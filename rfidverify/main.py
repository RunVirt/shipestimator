#!/usr/bin/env python3
"""
RFID Verification Tool — EliteFeats Edition
Replaces IPICO RC5 tag decoding with a direct EPC→Bib CSV lookup.

Protocol note: The Zebra/IPICO printer on port 6101 uses a binary
framed protocol. Frames are:  [1-byte cmd][2-byte len LE][payload]
Response frames for tag reads include EPC bytes + RSSI byte per tag.
Adjust CMD_* constants and _parse_frame() if the printer responds
differently — enable debug=true in settings.json to log raw bytes.
"""

import csv
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from flask import Flask, request
from flask_socketio import SocketIO, emit, disconnect

# ─── Settings ─────────────────────────────────────────────────────────────────

SETTINGS_FILE = Path(__file__).parent / "settings.json"

DEFAULT_SETTINGS = {
    "ip": "192.168.50.169",
    "port": 6101,
    "readPower": 30,
    "tagPosition": "F0",
    "batchSize": 50,
    "timeout": 20,
    "dataDir": "data",
    "filePrefix": "rfid_reads",
    "encodingDb": "EliteFeats_115000__Sheet1.csv",
    "rssiThreshold": -70,
    "webPort": 8765,
    "debug": False,
}

def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        with open(SETTINGS_FILE) as f:
            s = json.load(f)
        merged = {**DEFAULT_SETTINGS, **s}
        return merged
    return DEFAULT_SETTINGS.copy()

def save_settings(s: dict):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(s, f, indent=2)

# ─── RFID Error Codes (matches Zebra/IPICO firmware strings) ─────────────────

RFID_ERRORS: Dict[int, str] = {
    0x00: "RFID OK",
    0x01: "NO TAG FOUND",
    0x02: "TAG ID BUFFER FULL",
    0x03: "BAD RFID DATA",
    0x04: "INVALID ADDRESS",
    0x05: "LOCK ERROR",
    0x06: "GENERAL TAG ERROR",
    0x07: "INVALID WRITE DATA",
    0x08: "DATA AMOUNT ERROR",
    0x09: "INVALID PARAMETER",
    0x0A: "INVALID PROTOCOL",
    0x0B: "INVALID FREQUENCY",
    0x0C: "PROTOCOL UNDEFINED",
    0x0D: "PROTOCOL BAD EPC",
    0x0E: "PROT BAD NUM DATA",
    0x0F: "GEN2 PROTOCOL ERR",
    0x10: "UNKNOWN OPCODE",
    0x11: "RDR COMM TIMEOUT",
    0x12: "TM ASSERT FAILED",
}

# ─── Printer command bytes (Zebra/IPICO port-6101 binary protocol) ────────────
# Each frame: [CMD:1][LEN:2 LE][PAYLOAD:LEN]
# Adjust these if your firmware version uses different opcodes.

CMD_SETUP   = 0x01   # Set power + position; no response expected
CMD_READ    = 0x02   # Trigger batch inventory read
CMD_CLEAR   = 0x03   # Clear tag buffer
CMD_PAUSE   = 0x04
CMD_RESUME  = 0x05

# Response frame types from printer
RESP_TAG    = 0x10   # One tag: [EPC:12][RSSI:1 signed][ERR:1]
RESP_DONE   = 0x11   # Batch complete: [count:2 LE]
RESP_ERROR  = 0x12   # [error_code:1]

TAG_POSITION_CODES = {
    "F0": 0x00, "F10": 0x01,
    "B0": 0x10, "B10": 0x11, "B20": 0x12, "B30": 0x13,
}

def _frame(cmd: int, payload: bytes = b"") -> bytes:
    return bytes([cmd]) + struct.pack("<H", len(payload)) + payload

def _setup_payload(power: int, position: str) -> bytes:
    pos_byte = TAG_POSITION_CODES.get(position, 0x00)
    return bytes([power & 0xFF, pos_byte])

def _read_payload(batch_size: int) -> bytes:
    return struct.pack("<H", batch_size)

# ─── Encoding Database ────────────────────────────────────────────────────────

class EncodingDatabase:
    """Loads EliteFeats CSV (EPC,Bib #) and provides O(1) EPC→Bib lookup."""

    def __init__(self, csv_path: str):
        self._db: Dict[str, str] = {}
        self._load(csv_path)

    def _load(self, path: str):
        p = Path(path)
        if not p.is_absolute():
            p = Path(__file__).parent / path
        with open(p, newline="") as f:
            for row in csv.DictReader(f):
                epc = row["EPC"].strip().upper().lstrip("0") or "0"
                # Store both zero-padded and stripped forms for resilience
                self._db[row["EPC"].strip().upper()] = row["Bib #"].strip()
                self._db[epc] = row["Bib #"].strip()
        logging.info("Encoding DB loaded: %d tags", len(self._db) // 2)

    def lookup(self, epc: str) -> Optional[str]:
        epc = epc.strip().upper()
        return self._db.get(epc) or self._db.get(epc.lstrip("0") or "0")

    def __len__(self):
        return len(self._db) // 2

# ─── Failed Bib Tracker ───────────────────────────────────────────────────────

class FailedBibTracker:
    def __init__(self):
        self._success: Set[str] = set()
        self._failed: Set[str] = set()

    def add_success(self, bib: str):
        self._success.add(bib)
        self._failed.discard(bib)

    def add_failure(self, bib: str):
        if bib not in self._success:
            self._failed.add(bib)

    def bibs_needing_reprint(self) -> List[str]:
        def sort_key(b):
            return int(b) if b.isdigit() else b
        return sorted(self._failed, key=sort_key)

    def reset(self):
        self._success.clear()
        self._failed.clear()

# ─── Printer Connection ───────────────────────────────────────────────────────

class PrinterConnection:
    """
    Manages the TCP socket to the Zebra/IPICO printer on port 6101.

    The binary framing (CMD/LEN/PAYLOAD) is described at the top of
    this file. If the actual printer uses a different wire format,
    override _send_frame() and _recv_frames() without touching the
    rest of the application.
    """

    def __init__(self, ip: str, port: int, timeout: int, debug: bool = False):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.debug = debug
        self._sock: Optional[socket.socket] = None

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, self.port))
            self._sock = s
            logging.info("Connected to printer at %s:%d", self.ip, self.port)
            return True
        except OSError as e:
            logging.error("Printer connect failed: %s", e)
            return False

    def disconnect(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def send_setup(self, power: int, position: str):
        frame = _frame(CMD_SETUP, _setup_payload(power, position))
        self._send_frame(frame)
        logging.info("RFID setup command sent (no response expected)")

    def clear_buffer(self):
        self._send_frame(_frame(CMD_CLEAR))

    def pause_printer(self):
        self._send_frame(_frame(CMD_PAUSE))

    def resume_printer(self):
        self._send_frame(_frame(CMD_RESUME))

    def read_batch(self, batch_size: int) -> List[Tuple[str, int, int]]:
        """
        Send a read command and collect tag responses.
        Returns list of (epc_hex_str, rssi_dBm, error_code).
        """
        self._send_frame(_frame(CMD_READ, _read_payload(batch_size)))
        return self._recv_batch(batch_size)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _send_frame(self, frame: bytes):
        if not self._sock:
            return
        if self.debug:
            print(f"TX: {frame.hex()}", flush=True)
        try:
            self._sock.sendall(frame)
        except OSError as e:
            logging.error("Send error: %s", e)
            self.disconnect()

    def _recv_exact(self, n: int) -> Optional[bytes]:
        buf = b""
        while len(buf) < n:
            try:
                chunk = self._sock.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _recv_raw(self, timeout: float) -> bytes:
        """Read whatever the printer sends back, raw, for debug purposes."""
        buf = b""
        self._sock.settimeout(timeout)
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        return buf

    def _recv_batch(self, expected: int) -> List[Tuple[str, int, int]]:
        tags: List[Tuple[str, int, int]] = []
        deadline = time.time() + self.timeout

        # In debug mode, dump raw bytes first so we can see the real protocol
        if self.debug:
            raw = self._recv_raw(min(3.0, self.timeout))
            if raw:
                print(f"RAW RX ({len(raw)} bytes): {raw.hex()}", flush=True)
                print(f"RAW RX (text): {raw!r}", flush=True)
            return tags

        while time.time() < deadline:
            hdr = self._recv_exact(3)  # [cmd:1][len:2]
            if not hdr:
                break
            cmd = hdr[0]
            length = struct.unpack_from("<H", hdr, 1)[0]
            payload = self._recv_exact(length) if length else b""
            if payload is None:
                break

            if self.debug:
                print(f"RX cmd=0x{cmd:02X} payload={payload.hex() if payload else ''}", flush=True)

            if cmd == RESP_TAG and payload and len(payload) >= 14:
                epc = payload[:12].hex().upper()
                rssi = struct.unpack_from("b", payload, 12)[0]  # signed byte
                err  = payload[13] if len(payload) > 13 else 0
                tags.append((epc, rssi, err))
                if len(tags) >= expected:
                    break

            elif cmd == RESP_DONE:
                break  # Batch finished before expected count

            elif cmd == RESP_ERROR:
                err_code = payload[0] if payload else 0xFF
                logging.warning("Printer error: %s", RFID_ERRORS.get(err_code, f"0x{err_code:02X}"))
                break

        return tags

# ─── Verification Runner ──────────────────────────────────────────────────────

class VerificationRunner:
    def __init__(self, settings: dict, db: EncodingDatabase, socketio: SocketIO):
        self._settings = settings
        self._db = db
        self._sio = socketio
        self._conn = PrinterConnection(
            settings["ip"], settings["port"],
            settings["timeout"], settings.get("debug", False),
        )
        self._tracker = FailedBibTracker()
        self._running = False
        self._paused = False
        self._lock = threading.Lock()

        self.total_tested = 0
        self.successful_reads = 0
        self.failed_reads = 0

    # ── Public control ────────────────────────────────────────────────────────

    def start(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._paused = False

        self._tracker.reset()
        self.total_tested = 0
        self.successful_reads = 0
        self.failed_reads = 0

        t = threading.Thread(target=self._run, daemon=True)
        t.start()

    def stop(self):
        with self._lock:
            self._running = False

    def pause(self):
        with self._lock:
            self._paused = True
        if self._conn.connected:
            self._conn.pause_printer()

    def resume(self):
        with self._lock:
            self._paused = False
        if self._conn.connected:
            self._conn.resume_printer()

    def is_running(self) -> bool:
        return self._running

    # ── Internal loop ─────────────────────────────────────────────────────────

    def _run(self):
        self._broadcast("status", {"type": "status", "status": "connecting"})

        if not self._conn.connect():
            self._broadcast("status", {
                "type": "error",
                "error": f"Failed to connect to {self._settings['ip']}:{self._settings['port']}",
            })
            self._running = False
            return

        self._broadcast("status", {"type": "status", "status": "connected"})
        self._conn.send_setup(
            self._settings["readPower"],
            self._settings["tagPosition"],
        )
        self._conn.clear_buffer()

        batch = self._settings["batchSize"]
        rssi_threshold = self._settings.get("rssiThreshold", -70)

        while self._running:
            if self._paused:
                import gevent
                gevent.sleep(0.2)
                continue

            try:
                tags = self._conn.read_batch(batch)
            except Exception as e:
                logging.error("Read error: %s", e)
                self._broadcast("status", {"type": "error", "error": str(e)})
                break

            for epc, rssi, err_code in tags:
                if not self._running:
                    break

                self.total_tested += 1
                bib = self._db.lookup(epc)
                is_ok = err_code == 0 and bib is not None and rssi >= rssi_threshold

                result = {
                    "type": "result",
                    "tagData": epc,
                    "bib": bib or "UNKNOWN",
                    "readAttempt": self.total_tested,
                    "errorCode": err_code,
                    "errorDesc": RFID_ERRORS.get(err_code, f"CODE 0x{err_code:02X}"),
                    "rssi": rssi,
                    "success": is_ok,
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

            if not tags:
                import gevent
                gevent.sleep(0.05)

        self._conn.disconnect()
        self._finish()

    def _finish(self):
        bibs = self._tracker.bibs_needing_reprint()
        summary = {
            "type": "summary",
            "totalTagsTested": self.total_tested,
            "successfulReads": self.successful_reads,
            "failedReads": self.failed_reads,
            "bibsNeedingReprint": bibs,
            "success": len(bibs) == 0,
        }

        if bibs:
            lines = [f" {b}" for b in bibs]
            logging.warning("%d bib numbers failed and need manual reprinting:\n%s",
                            len(bibs), "\n".join(lines))
        else:
            logging.info("All bib numbers were successfully printed!")

        self._write_csv(summary)
        self._broadcast("summary", summary)
        self._broadcast("status", {"type": "status", "status": "stopped"})
        self._running = False

    def _write_csv(self, summary: dict):
        data_dir = Path(__file__).parent / self._settings["dataDir"]
        data_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = data_dir / f"{self._settings['filePrefix']}_{ts}.csv"

        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["Timestamp", "Total Tested", "Successful", "Failed",
                        "Bibs Needing Reprint"])
            w.writerow([ts, summary["totalTagsTested"],
                        summary["successfulReads"], summary["failedReads"],
                        "; ".join(summary["bibsNeedingReprint"])])
            if summary["bibsNeedingReprint"]:
                w.writerow([])
                w.writerow(["IMPORT ANALYSIS: Bib Numbers Needing Manual Reprint"])
                for bib in summary["bibsNeedingReprint"]:
                    w.writerow([bib])

        logging.info("Summary saved: %s", path)

    def _broadcast(self, event: str, data: dict):
        self._sio.emit(event, data)

# ─── Import / Analyze existing CSV ───────────────────────────────────────────

def import_csv_and_analyze(csv_path: str, db: EncodingDatabase,
                           rssi_threshold: int) -> dict:
    """
    Analyze a previously saved rfid_reads CSV against the encoding DB.
    Expected columns: EPC, RSSI  (other columns ignored).
    Returns a summary dict matching the live-run format.
    """
    tracker = FailedBibTracker()
    total = 0
    ok = 0

    logging.info("Importing and analyzing CSV file: %s", csv_path)
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            epc = row.get("EPC", row.get("tagData", "")).strip().upper()
            if not epc:
                continue
            total += 1
            rssi_raw = row.get("RSSI", row.get("rssi", "0")).strip()
            try:
                rssi = int(rssi_raw)
            except ValueError:
                rssi = 0
            bib = db.lookup(epc)
            if bib and rssi >= rssi_threshold:
                ok += 1
                tracker.add_success(bib)
            elif bib:
                tracker.add_failure(bib)

    bibs = tracker.bibs_needing_reprint()
    logging.info("IMPORT ANALYSIS: Bib Numbers Needing Manual Reprint")
    for b in bibs:
        logging.info("  %s", b)

    return {
        "type": "summary",
        "totalTagsTested": total,
        "successfulReads": ok,
        "failedReads": total - ok,
        "bibsNeedingReprint": bibs,
        "success": len(bibs) == 0,
    }

# ─── Flask / SocketIO App ─────────────────────────────────────────────────────

app = Flask(__name__, static_folder="static")
app.config["SECRET_KEY"] = "rfidverify-elitefeats"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")

_settings: dict = {}
_db: Optional[EncodingDatabase] = None
_runner: Optional[VerificationRunner] = None

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/api/settings")
def api_settings():
    from flask import jsonify
    return jsonify(_settings)

# ── WebSocket handlers ────────────────────────────────────────────────────────

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
    allowed = {"ip", "port", "readPower", "tagPosition", "batchSize",
               "timeout", "dataDir", "filePrefix", "encodingDb",
               "rssiThreshold", "webPort"}
    for k, v in data.items():
        if k in allowed:
            _settings[k] = v
    save_settings(_settings)
    # Reload DB if encodingDb changed
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
        result = import_csv_and_analyze(
            path, _db, _settings.get("rssiThreshold", -70)
        )
        emit("summary", result)
    except Exception as e:
        emit("status", {"type": "error", "error": str(e)})

# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    global _settings, _db

    _settings = load_settings()
    if "--debug" in sys.argv:
        _settings["debug"] = True

    debug_on = _settings.get("debug", False) or "--debug" in sys.argv
    logging.basicConfig(
        level=logging.DEBUG if debug_on else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    db_path = _settings.get("encodingDb", "")
    try:
        _db = EncodingDatabase(db_path)
        logging.info("Encoding DB: %d tags loaded", len(_db))
    except FileNotFoundError:
        logging.error("Encoding DB not found: %s", db_path)
        sys.exit(1)

    port = _settings.get("webPort", 8765)
    url = f"http://localhost:{port}"
    logging.info("Starting web UI at %s", url)

    # Open browser after a short delay so the server is ready
    def open_browser():
        time.sleep(1.2)
        webbrowser.open(url)

    threading.Thread(target=open_browser, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=port, debug=False)

if __name__ == "__main__":
    main()
