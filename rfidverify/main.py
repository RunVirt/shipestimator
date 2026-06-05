#!/usr/bin/env python3
"""
RFID Verification Tool — EliteFeats + CAEN R1210IX Edition

Reads tags continuously from a CAEN R1210IX Smart Tray Reader over
USB/COM port, looks up each EPC in the EliteFeats encoding CSV, and
flags any bib with an RSSI below the configured threshold.

CAEN serial protocol (easyReader SDK):
  Frame: STX(0x02) + LEN(2 LE) + CMD(1) + DATA(N) + CRC16(2 LE) + ETX(0x03)
  Inventory response frames arrive continuously once inventory is started.
  Each tag frame contains: EPC length, EPC bytes, RSSI (signed, 1/10 dBm).
"""

import csv
import json
import logging
import os
import struct
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

import serial
from flask import Flask
from flask_socketio import SocketIO, emit

# ─── Settings ─────────────────────────────────────────────────────────────────

SETTINGS_FILE = Path(__file__).parent / "settings.json"

DEFAULT_SETTINGS = {
    "comPort":      "COM3",
    "baudRate":     115200,
    "readPower":    30,
    "dataDir":      "data",
    "filePrefix":   "rfid_reads",
    "encodingDb":   "EliteFeats_115000__Sheet1.csv",
    "rssiThreshold": -70,
    "webPort":      8765,
    "debug":        False,
}

def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE) as f:
            return {**DEFAULT_SETTINGS, **json.load(f)}
    return DEFAULT_SETTINGS.copy()

def save_settings(s: dict):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)

# ─── RFID Error descriptions ───────────────────────────────────────────────────

RFID_ERRORS: Dict[int, str] = {
    0x00: "OK",
    0x01: "NO TAG FOUND",
    0x02: "READ ERROR",
    0x03: "CRC ERROR",
    0x04: "PROTOCOL ERROR",
    0xFF: "UNKNOWN ERROR",
}

# ─── CAEN easyReader protocol constants ───────────────────────────────────────

STX = 0x02
ETX = 0x03

# Host → Reader commands
CMD_OPEN_READER    = 0x01   # Open/initialise reader
CMD_CLOSE_READER   = 0x02   # Close reader
CMD_SET_PROTOCOL   = 0x03   # Set tag protocol (0x00 = GEN2/ISO18000-6C)
CMD_SET_POWER      = 0x04   # Set RF power (uint16, dBm * 100)
CMD_START_INV      = 0x05   # Start continuous inventory
CMD_STOP_INV       = 0x06   # Stop inventory

# Reader → Host response commands
RESP_TAG           = 0x80   # Tag report: EPC + RSSI
RESP_ACK           = 0x81   # Command acknowledged
RESP_ERR           = 0x82   # Error response
RESP_INV_END       = 0x83   # Inventory session ended

MIN_FRAME = 7   # STX(1) + LEN(2) + CMD(1) + CRC(2) + ETX(1)

def _crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

def _build_frame(cmd: int, data: bytes = b"") -> bytes:
    payload = bytes([cmd]) + data
    length  = struct.pack("<H", len(payload))
    body    = length + payload
    crc     = struct.pack("<H", _crc16(body))
    return bytes([STX]) + body + crc + bytes([ETX])

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
    CAEN R1210IX Smart Tray Reader via USB/COM port.

    Uses CAEN's easyReader binary protocol (STX-framed packets).
    Runs continuous inventory in a background thread and calls
    tag_callback(epc: str, rssi_dbm: int, err: int) for every read.

    If debug=True, all raw bytes sent and received are printed so the
    protocol can be verified against the actual reader firmware.
    """

    def __init__(self, port: str, baud: int, power: int, debug: bool = False):
        self.port  = port
        self.baud  = baud
        self.power = power
        self.debug = debug
        self._ser:  Optional[serial.Serial] = None
        self._buf   = b""
        self._running = False
        self._callback: Optional[Callable] = None

    @property
    def connected(self) -> bool:
        return self._ser is not None and self._ser.is_open

    def connect(self) -> bool:
        try:
            self._ser = serial.Serial(
                port=self.port,
                baudrate=self.baud,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
            )
            self._buf = b""
            logging.info("Opened %s at %d baud", self.port, self.baud)

            # Initialise reader
            self._send(CMD_OPEN_READER)
            time.sleep(0.2)
            self._drain()

            # Set GEN2 protocol
            self._send(CMD_SET_PROTOCOL, bytes([0x00]))
            time.sleep(0.1)
            self._drain()

            # Set RF power (dBm * 100, e.g. 3000 = 30.00 dBm)
            power_raw = min(max(self.power, 0), 30) * 100
            self._send(CMD_SET_POWER, struct.pack("<H", power_raw))
            time.sleep(0.1)
            self._drain()

            return True
        except serial.SerialException as e:
            logging.error("CAEN connect failed: %s", e)
            return False

    def disconnect(self):
        self._running = False
        if self._ser and self._ser.is_open:
            try:
                self._send(CMD_STOP_INV)
                time.sleep(0.05)
                self._send(CMD_CLOSE_READER)
                time.sleep(0.05)
                self._ser.close()
            except Exception:
                pass
        self._ser = None

    def start_inventory(self, callback: Callable):
        self._callback = callback
        self._running  = True
        self._send(CMD_START_INV)
        t = threading.Thread(target=self._read_loop, daemon=True, name="caen-rx")
        t.start()

    def stop_inventory(self):
        self._running = False
        self._send(CMD_STOP_INV)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _send(self, cmd: int, data: bytes = b""):
        if not (self._ser and self._ser.is_open):
            return
        frame = _build_frame(cmd, data)
        if self.debug:
            print(f"TX: {frame.hex()}  ({frame!r})", flush=True)
        try:
            self._ser.write(frame)
        except serial.SerialException as e:
            logging.error("Serial write error: %s", e)

    def _drain(self):
        """Read and discard any pending bytes (e.g. ACKs after setup cmds)."""
        if not (self._ser and self._ser.is_open):
            return
        time.sleep(0.05)
        pending = self._ser.in_waiting
        if pending:
            data = self._ser.read(pending)
            if self.debug:
                print(f"DRAIN ({len(data)} bytes): {data.hex()}  {data!r}", flush=True)

    def _read_loop(self):
        while self._running and self._ser and self._ser.is_open:
            try:
                chunk = self._ser.read(256)
            except serial.SerialException as e:
                logging.error("Serial read error: %s", e)
                break
            if chunk:
                if self.debug:
                    print(f"RAW RX ({len(chunk)} bytes): {chunk.hex()}  {chunk!r}", flush=True)
                self._buf += chunk
                self._process_buf()

    def _process_buf(self):
        while len(self._buf) >= MIN_FRAME:
            # Find next STX
            stx = self._buf.find(STX)
            if stx < 0:
                self._buf = b""
                return
            if stx > 0:
                self._buf = self._buf[stx:]

            if len(self._buf) < MIN_FRAME:
                return

            # Parse length field
            length = struct.unpack_from("<H", self._buf, 1)[0]
            frame_total = 1 + 2 + length + 2 + 1  # STX+LEN+PAYLOAD+CRC+ETX

            if len(self._buf) < frame_total:
                return  # Wait for rest of frame

            frame = self._buf[:frame_total]
            self._buf = self._buf[frame_total:]

            if frame[-1] != ETX:
                if self.debug:
                    print(f"Bad ETX, skipping frame: {frame.hex()}", flush=True)
                continue

            # Verify CRC
            body     = frame[1:-3]   # LEN + PAYLOAD
            received = struct.unpack_from("<H", frame, frame_total - 3)[0]
            expected = _crc16(body)
            if received != expected:
                if self.debug:
                    print(f"CRC mismatch: got {received:04X} expected {expected:04X}", flush=True)
                continue

            cmd     = frame[3]
            payload = frame[4:4 + length - 1]

            if self.debug:
                print(f"FRAME cmd=0x{cmd:02X} payload({len(payload)}B)={payload.hex()}", flush=True)

            self._dispatch(cmd, payload)

    def _dispatch(self, cmd: int, payload: bytes):
        if cmd == RESP_TAG:
            self._handle_tag(payload)
        elif cmd == RESP_ERR:
            err = payload[0] if payload else 0xFF
            logging.warning("Reader error: %s", RFID_ERRORS.get(err, f"0x{err:02X}"))
        elif cmd == RESP_ACK:
            logging.debug("Reader ACK")
        elif cmd == RESP_INV_END:
            logging.info("Inventory session ended by reader")
        else:
            if self.debug:
                print(f"Unknown response cmd=0x{cmd:02X}: {payload.hex()}", flush=True)

    def _handle_tag(self, payload: bytes):
        """
        Tag payload: [epc_len:1][epc_bytes:epc_len][rssi:2 LE signed, 1/10 dBm]
        """
        if len(payload) < 3:
            if self.debug:
                print(f"Short tag payload: {payload.hex()}", flush=True)
            return

        epc_len = payload[0]
        if len(payload) < 1 + epc_len + 2:
            if self.debug:
                print(f"Incomplete tag payload: {payload.hex()}", flush=True)
            return

        epc_bytes = payload[1:1 + epc_len]
        epc = epc_bytes.hex().upper()

        rssi_raw = struct.unpack_from("<h", payload, 1 + epc_len)[0]
        rssi_dbm = rssi_raw // 10   # convert 1/10 dBm to dBm

        if self.debug:
            print(f"TAG  EPC={epc}  RSSI={rssi_dbm} dBm", flush=True)

        if self._callback:
            self._callback(epc, rssi_dbm, 0)

# ─── Verification Runner ──────────────────────────────────────────────────────

class VerificationRunner:
    def __init__(self, settings: dict, db: EncodingDatabase, socketio: SocketIO):
        self._settings = settings
        self._db       = db
        self._sio      = socketio
        self._reader   = CaenReader(
            port  = settings["comPort"],
            baud  = settings.get("baudRate", 115200),
            power = settings.get("readPower", 30),
            debug = settings.get("debug", False),
        )
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
                "error": f"Failed to open {self._settings['comPort']} — check the port and that the reader is plugged in",
            })
            self._running = False
            return

        self._broadcast("status", {"type": "status", "status": "running"})
        self._reader.start_inventory(self._on_tag)

        # Keep thread alive until stopped
        while self._running:
            time.sleep(0.2)

        self._reader.disconnect()
        self._finish()

    def _on_tag(self, epc: str, rssi: int, err: int):
        """Called from the CAEN reader thread for every tag read."""
        with self._lock:
            if not self._running or self._paused:
                return

        self.total_tested += 1
        bib   = self._db.lookup(epc)
        is_ok = err == 0 and bib is not None and rssi >= self._settings.get("rssiThreshold", -70)

        result = {
            "type":          "result",
            "tagData":       epc,
            "bib":           bib or "UNKNOWN",
            "readAttempt":   self.total_tested,
            "errorCode":     err,
            "errorDesc":     RFID_ERRORS.get(err, f"CODE 0x{err:02X}"),
            "rssi":          rssi,
            "success":       is_ok,
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
            "type":              "summary",
            "totalTagsTested":   self.total_tested,
            "successfulReads":   self.successful_reads,
            "failedReads":       self.failed_reads,
            "bibsNeedingReprint": bibs,
            "success":           len(bibs) == 0,
        }

        if bibs:
            logging.warning("%d bib(s) need manual reprinting: %s",
                            len(bibs), ", ".join(bibs[:10]) + ("…" if len(bibs) > 10 else ""))
        else:
            logging.info("All bib numbers verified successfully!")

        self._write_csv(summary)
        self._broadcast("summary",  summary)
        self._broadcast("status",   {"type": "status", "status": "stopped"})
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
    from collections import defaultdict
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
        "type":              "summary",
        "totalTagsTested":   total,
        "successfulReads":   ok,
        "failedReads":       total - ok,
        "bibsNeedingReprint": bibs,
        "success":           len(bibs) == 0,
    }

# ─── Flask / SocketIO ─────────────────────────────────────────────────────────

app     = Flask(__name__, static_folder="static")
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
               "encodingDb", "rssiThreshold", "webPort"}
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
