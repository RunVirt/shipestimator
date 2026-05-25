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

# ─── ZPL command builders ─────────────────────────────────────────────────────
# Zebra printers speak ZPL (Zebra Programming Language) over TCP.
# ^XA / ^XZ  = start / end of format
# ^RS        = RFID Setup  (type, antenna, read-power, write-power, …)
# ^RFR,H,0,12= Read RFID field: hex, starting block 0, 12 bytes (EPC)
# ^PQ<n>     = Print/process Quantity
# ^HV<f>,<l> = Host Verify: send field data back over the comms port

def zpl_setup(power: int, position: str) -> bytes:
    """Configure RFID antenna and read power. No response expected."""
    # ^RS<type=A GEN2>,<position>,<read-power>
    return f"^XA^RSA,{position},{power}^XZ\n".encode()

def zpl_clear() -> bytes:
    return b"^XA^XZ\n"

def zpl_pause() -> bytes:
    return b"~PP\n"

def zpl_resume() -> bytes:
    return b"~PS\n"

def zpl_read_batch(batch_size: int) -> bytes:
    """
    ZPL format that reads the EPC from each label and sends it back to
    the host via ^HV. The printer processes <batch_size> labels.
    Response lines look like: <24-char hex EPC>\r\n
    """
    return (
        f"^XA"
        f"^PQ{batch_size}"
        f"^RS"
        f"^RFR,H,0,12"
        f"^FN1^FD^FS"
        f"^HV1,24"
        f"^XZ\n"
    ).encode()

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
    Manages the TCP socket to the Zebra printer on port 6101.
    Communicates using ZPL (Zebra Programming Language) text commands.
    Tag data is returned by the printer as plain text lines over the
    same socket, one EPC per line.
    """

    def __init__(self, ip: str, port: int, timeout: int, debug: bool = False):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.debug = debug
        self._sock: Optional[socket.socket] = None
        self._buf = b""

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def connect(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((self.ip, self.port))
            self._sock = s
            self._buf = b""
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
        cmd = zpl_setup(power, position)
        self._send(cmd)
        logging.info("RFID setup sent: power=%d pos=%s", power, position)

    def clear_buffer(self):
        self._send(zpl_clear())

    def pause_printer(self):
        self._send(zpl_pause())

    def resume_printer(self):
        self._send(zpl_resume())

    def read_batch(self, batch_size: int) -> List[Tuple[str, int, int]]:
        """
        Send ZPL to process a batch of labels, collect EPC responses.
        Returns list of (epc_hex_str, rssi_dBm, error_code).
        RSSI is 0 when the printer does not report it; error_code 0 = OK.
        """
        self._send(zpl_read_batch(batch_size))
        return self._recv_lines(batch_size)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _send(self, data: bytes):
        if not self._sock:
            return
        if self.debug:
            print(f"TX: {data!r}", flush=True)
        try:
            self._sock.sendall(data)
        except OSError as e:
            logging.error("Send error: %s", e)
            self.disconnect()

    def _recv_lines(self, expected: int) -> List[Tuple[str, int, int]]:
        """
        Read newline-delimited responses from the printer.
        In debug mode, also dumps the raw bytes so we can see the
        actual format and adjust the parser if needed.
        """
        tags: List[Tuple[str, int, int]] = []
        deadline = time.time() + self.timeout

        while len(tags) < expected and time.time() < deadline:
            remaining = max(0.5, deadline - time.time())
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                break
            except OSError as e:
                logging.error("Recv error: %s", e)
                break

            if not chunk:
                break

            if self.debug:
                print(f"RAW RX ({len(chunk)} bytes): {chunk.hex()}", flush=True)
                print(f"RAW RX (text): {chunk!r}", flush=True)

            self._buf += chunk

            # Parse complete lines
            while b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                line = line.rstrip(b"\r").decode(errors="replace").strip()
                if self.debug:
                    print(f"LINE: {line!r}", flush=True)
                parsed = self._parse_line(line)
                if parsed:
                    tags.append(parsed)
                    if len(tags) >= expected:
                        break

        return tags

    def _parse_line(self, line: str) -> Optional[Tuple[str, int, int]]:
        """
        Parse one response line from the printer.
        Handles several common Zebra RFID response formats:
          - Plain 24-char hex EPC:   000000015000...
          - Prefixed:                EPC:000000015000
          - Status with RSSI:        000000015000 RSSI=-55 ERR=0
          - RFID OK / error strings: RFID OK, NO TAG FOUND, etc.
        """
        line = line.strip().upper()
        if not line:
            return None

        # Map plain RFID status strings to error codes
        for code, msg in RFID_ERRORS.items():
            if line == msg:
                if code == 0x00:
                    return None  # "RFID OK" with no EPC — skip
                logging.debug("Printer status: %s", msg)
                return None

        # Strip common prefixes
        for prefix in ("EPC:", "RFID:", "TAG:", "DATA:"):
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
                break

        # Extract optional RSSI and ERR tokens first
        rssi = 0
        err  = 0
        parts = line.split()
        epc_candidate = parts[0] if parts else ""
        for token in parts[1:]:
            if token.startswith("RSSI="):
                try:
                    rssi = int(token[5:])
                except ValueError:
                    pass
            elif token.startswith("ERR="):
                try:
                    err = int(token[4:])
                except ValueError:
                    pass

        # Validate EPC: must be 12, 24, or 16 hex chars (96-bit or 64-bit EPC)
        epc = epc_candidate.replace(" ", "")
        if epc and all(c in "0123456789ABCDEF" for c in epc) and len(epc) in (12, 16, 24):
            # Normalise to 12 hex chars (6 bytes) used by EliteFeats CSV
            if len(epc) == 24:
                epc = epc[:12]   # first 6 bytes = EPC header + bib number
            return (epc, rssi, err)

        return None

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
