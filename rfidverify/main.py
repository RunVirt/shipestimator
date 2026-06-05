#!/usr/bin/env python3
"""
RFID Verification Tool — EliteFeats + CAEN R1210IX Edition

Reads tags from a CAEN R1210IX Smart Tray Reader via CAENRFIDLib.dll
(SDK 5.0.0, 64-bit), looks up each EPC in the EliteFeats encoding CSV,
and flags bibs whose RSSI never exceeds the configured threshold.
"""

import csv
import ctypes
import glob
import json
import logging
import os
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from flask import Flask
from flask_socketio import SocketIO, emit

# ─── Settings ─────────────────────────────────────────────────────────────────

SETTINGS_FILE = Path(__file__).parent / "settings.json"

DEFAULT_SETTINGS = {
    "comPort":       "COM3",
    "baudRate":      115200,
    "readPower":     30,
    "dataDir":       "data",
    "filePrefix":    "rfid_reads",
    "encodingDb":    "EliteFeats_115000__Sheet1.csv",
    "rssiThreshold": -70,
    "webPort":       8765,
    "dllPath":       "",
    # "dll"    – use CAENRFIDLib.dll (crashes on RS232 without CAEN USB driver)
    # "serial" – pure-Python pyserial implementation (recommended)
    "readerBackend": "serial",
    "debug":         False,
}


def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE) as f:
            return {**DEFAULT_SETTINGS, **json.load(f)}
    return DEFAULT_SETTINGS.copy()


def save_settings(s: dict):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)


# ─── CAEN SDK ctypes structures ────────────────────────────────────────────────

class _TimeVal(ctypes.Structure):
    # struct timeval from <winsock2.h>; Windows long is always 4 bytes
    _fields_ = [
        ("tv_sec",  ctypes.c_int32),
        ("tv_usec", ctypes.c_int32),
    ]


class CAENRFIDTag(ctypes.Structure):
    """
    CAENRFIDTag from CAENRFIDTypes.h SDK 5.0.0, MSVC x64 layout.
    sizeof == 224 bytes on Windows x64.
    ctypes inserts padding automatically:
      +3 bytes before TimeStamp (alignment 4)
      +2 bytes before phaseBegin (alignment 4)
      +2 bytes before subCmdResultData (alignment 8)
    """
    _fields_ = [
        ("ID",                    ctypes.c_ubyte * 64),  # EPC bytes
        ("Length",                ctypes.c_int16),        # EPC byte count
        ("LogicalSource",         ctypes.c_char  * 30),
        ("ReadPoint",             ctypes.c_char  * 5),
        ("TimeStamp",             _TimeVal),              # +3 pad before this
        ("Type",                  ctypes.c_int32),        # CAENRFIDProtocol
        ("RSSI",                  ctypes.c_int16),        # signed dBm
        ("TID",                   ctypes.c_ubyte * 64),
        ("TIDLen",                ctypes.c_int16),
        ("XPC",                   ctypes.c_ubyte * 4),
        ("PC",                    ctypes.c_ubyte * 2),
        ("phaseBegin",            ctypes.c_float),        # +2 pad before this
        ("phaseEnd",              ctypes.c_float),
        ("frequency",             ctypes.c_int32),        # Windows long = 4 bytes
        ("subCmdCode",            ctypes.c_int32),
        ("subCmdResultCode",      ctypes.c_int32),
        ("subCmdResultDataCount", ctypes.c_int16),
        ("subCmdResultData",      ctypes.c_void_p),       # +2 pad before this
    ]


# ─── Encoding Database ────────────────────────────────────────────────────────

class EncodingDatabase:
    """Loads EliteFeats CSV (EPC, Bib #) for O(1) EPC → Bib lookup."""

    def __init__(self, csv_path: str):
        self._db: Dict[str, str] = {}
        p = Path(csv_path)
        if not p.is_absolute():
            p = Path(__file__).parent / csv_path
        with open(p, newline="") as f:
            for row in csv.DictReader(f):
                epc = row["EPC"].strip().upper()
                bib = row["Bib #"].strip()
                self._db[epc] = bib
                stripped = epc.lstrip("0") or "0"
                self._db[stripped] = bib
        logging.info("Encoding DB: %d tags loaded", len(self._db) // 2)

    def lookup(self, epc: str) -> Optional[str]:
        epc = epc.strip().upper()
        return self._db.get(epc) or self._db.get(epc.lstrip("0") or "0")

    def __len__(self):
        return len(self._db) // 2


# ─── Failed Bib Tracker ───────────────────────────────────────────────────────

class FailedBibTracker:
    def __init__(self):
        self._success: Set[str] = set()
        self._failed:  Set[str] = set()

    def add_success(self, bib: str):
        self._success.add(bib)
        self._failed.discard(bib)

    def add_failure(self, bib: str):
        if bib not in self._success:
            self._failed.add(bib)

    def bibs_needing_reprint(self) -> List[str]:
        return sorted(self._failed, key=lambda b: int(b) if b.isdigit() else b)

    def reset(self):
        self._success.clear()
        self._failed.clear()


# ─── CAEN R1210IX Reader ──────────────────────────────────────────────────────

class CaenReader:
    """
    CAEN R1210IX Smart Tray Reader via CAENRFIDLib.dll (easyReader API, x64).

    Uses the older CAENRFID_ API:
      CAENRFID_Init(connType, port, &handle)   — connect (RS232=0, USB=3)
      CAENRFID_End(handle)                      — disconnect
      CAENRFID_InventoryTag(handle, source, mask, maskLen, pos, &tags, &count)
      CAENRFID_FreeTagsMemory(tags)             — release DLL-allocated tag list

    Polls inventory in a background thread and calls
    tag_callback(epc: str, rssi_dbm: int, err: int) for every tag read.
    """

    _EOF = -13  # CAENRFID_EOF — no tags in this cycle

    def __init__(self, port: str, power: int, dll_path: str = "", debug: bool = False):
        self.port     = port
        self.power    = power
        self.dll_path = dll_path
        self.debug    = debug
        self._lib: Optional[ctypes.CDLL] = None
        self._handle  = ctypes.c_void_p(0)   # NULL / uninitialised
        self._running = False
        self._callback: Optional[Callable] = None

    @property
    def connected(self) -> bool:
        return self._lib is not None and bool(self._handle.value)

    def connect(self) -> bool:
        if not hasattr(ctypes, "WinDLL"):
            logging.error("CAENRFIDLib.dll requires Windows")
            return False

        dll = self._find_dll()
        if not dll:
            logging.error(
                "CAENRFIDLib.dll not found. Set \"dllPath\" in settings.json to "
                r'"C:\\Users\\tyler\\OneDrive\\Desktop\\caen-rfid-websocket\\CAENRFIDLib.dll"'
            )
            return False

        logging.info("Loading DLL: %s", dll)
        dll_dir = str(Path(dll).parent)
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(dll_dir)
        try:
            self._lib = ctypes.WinDLL(dll)
        except OSError as e:
            logging.error("Failed to load DLL: %s", e)
            return False

        # CAENRFID_Init(int connType, void* pParam, int* pHandle)
        # connType 0 = RS232 (use for USB virtual COM port like COM3)
        # connType 3 = USB  (direct USB, no COM port)
        try:
            self._lib.CAENRFID_Init.restype  = ctypes.c_int
            self._lib.CAENRFID_Init.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
        except AttributeError:
            logging.error("CAENRFID_Init not found in DLL")
            return False

        # R1210IX on USB shows as a virtual COM port → RS232 connection type
        port_bytes = ctypes.c_char_p(self.port.encode())
        ret = self._lib.CAENRFID_Init(0, port_bytes, ctypes.byref(self._handle))
        if ret != 0:
            logging.warning("CAENRFID_Init RS232(%s) returned %d, trying USB direct...", self.port, ret)
            self._handle = ctypes.c_void_p(0)
            ret = self._lib.CAENRFID_Init(3, None, ctypes.byref(self._handle))

        if ret != 0:
            logging.error("CAENRFID_Init failed (code %d)", ret)
            return False

        logging.info("Connected to reader on %s (handle=%d)", self.port, self._handle.value)
        self._try_set_power()
        return True

    def disconnect(self):
        self._running = False
        if self._lib and self._handle.value:
            try:
                self._lib.CAENRFID_End.restype  = ctypes.c_int
                self._lib.CAENRFID_End.argtypes = [ctypes.c_void_p]
                self._lib.CAENRFID_End(self._handle)
            except Exception:
                pass
        self._handle = ctypes.c_void_p(0)
        self._lib    = None

    def start_inventory(self, callback: Callable):
        self._callback = callback
        self._running  = True
        t = threading.Thread(target=self._poll_loop, daemon=True, name="caen-poll")
        t.start()

    def stop_inventory(self):
        self._running = False

    # ── Internal ──────────────────────────────────────────────────────────────

    def _find_dll(self) -> str:
        if self.dll_path and os.path.exists(self.dll_path):
            return self.dll_path

        patterns = [
            r"C:\Program Files\CAEN\**\CAENRFIDLib.dll",
            r"C:\Program Files (x86)\CAEN\**\CAENRFIDLib.dll",
            r"C:\CAEN\**\CAENRFIDLib.dll",
            r"C:\Windows\System32\CAENRFIDLib.dll",
        ]
        user = os.environ.get("USERNAME") or os.environ.get("USER", "")
        if user:
            patterns += [
                rf"C:\Users\{user}\Desktop\**\CAENRFIDLib.dll",
                rf"C:\Users\{user}\OneDrive\Desktop\**\CAENRFIDLib.dll",
                rf"C:\Users\{user}\OneDrive - *\Desktop\**\CAENRFIDLib.dll",
            ]

        candidates = []
        for pat in patterns:
            try:
                candidates.extend(glob.glob(pat, recursive=True))
            except Exception:
                pass
        script_dir = Path(__file__).parent
        for d in (script_dir, script_dir.parent):
            candidates.extend(str(f) for f in d.rglob("CAENRFIDLib.dll"))

        # Prefer x64 DLLs — skip 32-bit ones (they fail with WinError 193)
        from struct import unpack_from
        for path in candidates:
            try:
                data = Path(path).read_bytes()
                if data[:2] != b"MZ":
                    continue
                pe_off = unpack_from("<I", data, 0x3C)[0]
                machine = unpack_from("<H", data, pe_off + 4)[0]
                if machine == 0x8664:   # IMAGE_FILE_MACHINE_AMD64
                    logging.info("Auto-detected 64-bit DLL: %s", path)
                    return path
            except Exception:
                continue

        # Fall back to first loadable candidate
        for path in candidates:
            if os.path.exists(path):
                return path
        return ""

    def _try_set_power(self):
        try:
            fn = self._lib.CAENRFID_SetPower
            fn.restype  = ctypes.c_int
            fn.argtypes = [ctypes.c_void_p, ctypes.c_int]
            fn(self._handle, self.power)
            logging.info("RF power set to %d dBm", self.power)
        except AttributeError:
            pass

    def _poll_loop(self):
        try:
            self._lib.CAENRFID_InventoryTag.restype  = ctypes.c_int
            self._lib.CAENRFID_InventoryTag.argtypes = [
                ctypes.c_void_p,                     # Handle
                ctypes.c_char_p,                     # SourceName
                ctypes.c_char_p,                     # Mask (NULL = no filter)
                ctypes.c_ubyte,                      # MaskLength
                ctypes.c_ubyte,                      # MaskPosition
                ctypes.POINTER(ctypes.c_void_p),     # CAENRFIDTag** (DLL allocates)
                ctypes.POINTER(ctypes.c_uint16),     # TagCount*
            ]
        except AttributeError:
            logging.error("CAENRFID_InventoryTag not found in DLL")
            self._running = False
            return

        while self._running:
            tags_ptr = ctypes.c_void_p(0)
            count    = ctypes.c_uint16(0)

            ret = self._lib.CAENRFID_InventoryTag(
                self._handle,
                b"Source_0",   # default source name on CAEN readers
                None,          # no EPC mask filter
                0,             # MaskLength
                0,             # MaskPosition
                ctypes.byref(tags_ptr),
                ctypes.byref(count),
            )

            if ret == 0 and count.value > 0 and tags_ptr.value:
                self._process_tags(tags_ptr, count.value)
                try:
                    self._lib.CAENRFID_FreeTagsMemory.restype  = ctypes.c_int
                    self._lib.CAENRFID_FreeTagsMemory.argtypes = [ctypes.c_void_p]
                    self._lib.CAENRFID_FreeTagsMemory(tags_ptr)
                except AttributeError:
                    pass
            elif ret not in (0, self._EOF):
                if self.debug:
                    print(f"InventoryTag returned {ret}", flush=True)
                time.sleep(0.1)

            time.sleep(0.05)

    def _process_tags(self, tags_ptr: ctypes.c_void_p, count: int):
        array_type = CAENRFIDTag * count
        try:
            tags = ctypes.cast(tags_ptr, ctypes.POINTER(array_type)).contents
        except Exception as e:
            logging.error("Failed to cast tag array: %s", e)
            return

        for tag in tags:
            if tag.Length <= 0 or tag.Length > 64:
                continue
            epc  = bytes(tag.ID[:tag.Length]).hex().upper()
            rssi = int(tag.RSSI)
            if self.debug:
                print(f"TAG  EPC={epc}  RSSI={rssi} dBm", flush=True)
            if self._callback:
                self._callback(epc, rssi, 0)


# ─── Verification Runner ──────────────────────────────────────────────────────

def _make_reader(settings: dict):
    """Return the appropriate reader instance based on settings['readerBackend']."""
    backend = settings.get("readerBackend", "serial").lower()
    port    = settings["comPort"]
    power   = settings.get("readPower", 30)
    debug   = settings.get("debug", False)

    if backend == "dll":
        return CaenReader(port=port, power=power,
                          dll_path=settings.get("dllPath", ""), debug=debug)

    # "serial" (default) — pure-Python pyserial, no DLL needed
    from serial_reader import CaenSerialReader
    return CaenSerialReader(port=port, power=power, debug=debug)


class VerificationRunner:
    def __init__(self, settings: dict, db: EncodingDatabase, socketio: SocketIO):
        self._settings = settings
        self._db       = db
        self._sio      = socketio
        self._reader   = _make_reader(settings)
        self._tracker  = FailedBibTracker()
        self._running  = False
        self._paused   = False
        self._lock     = threading.Lock()
        self.total_tested     = 0
        self.successful_reads = 0
        self.failed_reads     = 0

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._paused  = False

        self._tracker.reset()
        self.total_tested = self.successful_reads = self.failed_reads = 0

        t = threading.Thread(target=self._run, daemon=True, name="verify-runner")
        t.start()

    def stop(self):
        with self._lock:
            self._running = False
        self._reader.stop_inventory()

    def pause(self):
        with self._lock:
            self._paused = True
        self._reader.stop_inventory()

    def resume(self):
        with self._lock:
            self._paused = False
        self._reader.start_inventory(self._on_tag)

    def is_running(self) -> bool:
        return self._running

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(self):
        self._broadcast("status", {"type": "status", "status": "connecting"})

        if not self._reader.connect():
            self._broadcast("status", {
                "type":  "error",
                "error": (
                    f"Failed to connect on {self._settings['comPort']}. "
                    "Make sure: (1) CAEN software is fully closed, "
                    "(2) the reader is plugged in, "
                    "(3) dllPath in settings points to the 64-bit CAENRFIDLib.dll."
                ),
            })
            self._running = False
            return

        self._broadcast("status", {"type": "status", "status": "running"})
        self._reader.start_inventory(self._on_tag)

        while self._running:
            time.sleep(0.2)

        self._reader.disconnect()
        self._finish()

    def _on_tag(self, epc: str, rssi: int, err: int):
        with self._lock:
            if not self._running or self._paused:
                return

        self.total_tested += 1
        bib   = self._db.lookup(epc)
        is_ok = err == 0 and bib is not None and rssi >= self._settings.get("rssiThreshold", -70)

        result = {
            "type":            "result",
            "tagData":         epc,
            "bib":             bib or "UNKNOWN",
            "readAttempt":     self.total_tested,
            "errorCode":       err,
            "errorDesc":       "OK" if err == 0 else f"ERR {err}",
            "rssi":            rssi,
            "success":         is_ok,
            "totalTagsTested": self.total_tested,
        }

        if is_ok:
            self.successful_reads += 1
            if bib:
                self._tracker.add_success(bib)
        else:
            self.failed_reads += 1
            if bib:
                self._tracker.add_failure(bib)

        self._broadcast("result", result)

    def _finish(self):
        bibs = self._tracker.bibs_needing_reprint()
        summary = {
            "type":               "summary",
            "totalTagsTested":    self.total_tested,
            "successfulReads":    self.successful_reads,
            "failedReads":        self.failed_reads,
            "bibsNeedingReprint": bibs,
            "success":            len(bibs) == 0,
        }

        if bibs:
            logging.warning("%d bib(s) need manual reprinting: %s",
                            len(bibs), ", ".join(bibs[:10]) + ("…" if len(bibs) > 10 else ""))
        else:
            logging.info("All bib numbers verified successfully!")

        self._write_csv(summary)
        self._broadcast("summary", summary)
        self._broadcast("status",  {"type": "status", "status": "stopped"})
        self._running = False

    def _write_csv(self, summary: dict):
        data_dir = Path(__file__).parent / self._settings["dataDir"]
        data_dir.mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = data_dir / f"{self._settings['filePrefix']}_{ts}.csv"

        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Total Tested", "Successful", "Failed",
                        "Bibs Needing Reprint"])
            w.writerow([ts, summary["totalTagsTested"], summary["successfulReads"],
                        summary["failedReads"],
                        "; ".join(summary["bibsNeedingReprint"])])
            if summary["bibsNeedingReprint"]:
                w.writerow([])
                w.writerow(["Bib Numbers Needing Manual Reprint"])
                for bib in summary["bibsNeedingReprint"]:
                    w.writerow([bib])

        logging.info("Report saved: %s", path)

    def _broadcast(self, event: str, data: dict):
        self._sio.emit(event, data)


# ─── Import / Analyze existing CSV ───────────────────────────────────────────

def import_csv_and_analyze(csv_path: str, db: EncodingDatabase,
                           rssi_threshold: int) -> dict:
    """Analyze a previously saved rfid_reads CSV against the encoding DB."""
    tracker = FailedBibTracker()
    total = ok = 0

    logging.info("Analyzing: %s", csv_path)
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            epc = row.get("EPC", row.get("tagData", "")).strip().upper()
            if not epc:
                continue
            total += 1
            try:
                rssi = int(row.get("RSSI", row.get("rssi", "0")).strip())
            except ValueError:
                rssi = 0
            bib = db.lookup(epc)
            if bib and rssi >= rssi_threshold:
                ok += 1
                tracker.add_success(bib)
            elif bib:
                tracker.add_failure(bib)

    bibs = tracker.bibs_needing_reprint()
    return {
        "type":               "summary",
        "totalTagsTested":    total,
        "successfulReads":    ok,
        "failedReads":        total - ok,
        "bibsNeedingReprint": bibs,
        "success":            len(bibs) == 0,
    }


# ─── Flask / SocketIO ─────────────────────────────────────────────────────────

app      = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = "rfidverify-elitefeats-caen"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

_settings: dict = {}
_db:       Optional[EncodingDatabase] = None
_runner:   Optional[VerificationRunner] = None


@app.route("/")
def index():
    return app.send_static_file("index.html")


@socketio.on("connect")
def on_connect():
    emit("settings", {
        "type": "settings",
        **{k: v for k, v in _settings.items() if k != "debug"},
        "dbTagCount": len(_db) if _db else 0,
    })
    status = "running" if (_runner and _runner.is_running()) else "stopped"
    emit("status", {"type": "status", "status": status})


@socketio.on("start")
def on_start(data=None):
    global _runner
    if _runner and _runner.is_running():
        return
    _runner = VerificationRunner(_settings, _db, socketio)
    _runner.start()


@socketio.on("stop")
def on_stop(data=None):
    if _runner:
        _runner.stop()


@socketio.on("pause")
def on_pause(data=None):
    if _runner:
        _runner.pause()
    emit("status", {"type": "status", "status": "paused"})


@socketio.on("resume")
def on_resume(data=None):
    if _runner:
        _runner.resume()
    emit("status", {"type": "status", "status": "running"})


@socketio.on("settings")
def on_settings(data: dict):
    global _settings, _db
    allowed = {"comPort", "baudRate", "readPower", "dataDir", "filePrefix",
               "encodingDb", "rssiThreshold", "webPort", "dllPath", "readerBackend"}
    for k, v in data.items():
        if k in allowed:
            _settings[k] = v
    save_settings(_settings)
    try:
        _db = EncodingDatabase(_settings["encodingDb"])
    except Exception as e:
        emit("status", {"type": "error", "error": f"Failed to load encoding DB: {e}"})
        return
    emit("settings", {
        "type": "settings",
        **{k: v for k, v in _settings.items() if k != "debug"},
        "dbTagCount": len(_db),
    })


@socketio.on("import")
def on_import(data: dict):
    path = data.get("path", "")
    if not path or not os.path.exists(path):
        emit("status", {"type": "error", "error": f"File not found: {path}"})
        return
    try:
        emit("summary", import_csv_and_analyze(
            path, _db, _settings.get("rssiThreshold", -70)
        ))
    except Exception as e:
        emit("status", {"type": "error", "error": str(e)})


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    global _settings, _db

    _settings = load_settings()
    if "--debug" in sys.argv:
        _settings["debug"] = True

    logging.basicConfig(
        level=logging.DEBUG if _settings.get("debug") else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    try:
        _db = EncodingDatabase(_settings["encodingDb"])
    except FileNotFoundError as e:
        print(f"ERROR: Encoding DB not found — {e}")
        sys.exit(1)

    port = _settings.get("webPort", 8765)
    logging.info("CAEN R1210IX  |  COM port: %s  |  Web UI: http://localhost:%d",
                 _settings["comPort"], port)

    def open_browser():
        time.sleep(1.2)
        webbrowser.open(f"http://localhost:{port}")

    threading.Thread(target=open_browser, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    main()
