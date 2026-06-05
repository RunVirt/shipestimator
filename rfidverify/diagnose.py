#!/usr/bin/env python3
"""
CAEN R1210IX - Simple listen diagnostic.
Just opens the COM port and dumps whatever the reader sends.
No commands sent - safe to run without knowing the protocol.
"""

import json
import time
import sys
from pathlib import Path

import serial
import serial.tools.list_ports

# ── Show all available COM ports first ────────────────────────────────────────
print("=" * 60)
print("Available COM ports on this PC:")
ports = list(serial.tools.list_ports.comports())
if ports:
    for p in ports:
        print(f"  {p.device:10s}  {p.description}")
else:
    print("  (none found)")
print("=" * 60)

# ── Load settings ─────────────────────────────────────────────────────────────
s = json.loads((Path(__file__).parent / "settings.json").read_text())
PORT = s.get("comPort", "COM3")
BAUD = s.get("baudRate", 115200)

# ── Try opening the port ──────────────────────────────────────────────────────
print(f"\nTrying to open {PORT} at {BAUD} baud...")
try:
    ser = serial.Serial(PORT, BAUD, timeout=0.1)
    print(f"SUCCESS - {PORT} is open\n")
except serial.SerialException as e:
    print(f"\nFAILED: {e}")
    print("\nMost likely fix: close the CAEN software completely, then try again.")
    sys.exit(1)

# ── Listen for 10 seconds without sending anything ───────────────────────────
print("Listening for 10 seconds without sending any commands...")
print("(If the reader sends anything on startup, it will appear below)\n")

buf = b""
deadline = time.time() + 10
last_print = time.time()

while time.time() < deadline:
    chunk = ser.read(256)
    if chunk:
        buf += chunk
        print(f"  RECEIVED ({len(chunk)} bytes): {chunk.hex()}")
        print(f"  AS TEXT : {chunk!r}")
        print()

# ── Try baud rates if nothing received ───────────────────────────────────────
if not buf:
    print("Nothing received at 115200 baud.")
    print("\nTrying other common baud rates...\n")
    ser.close()

    for baud in [9600, 19200, 38400, 57600]:
        print(f"  Trying {baud} baud...")
        try:
            ser = serial.Serial(PORT, baud, timeout=0.1)
            time.sleep(0.5)
            chunk = ser.read(256)
            if chunk:
                print(f"  GOT DATA at {baud} baud: {chunk.hex()}")
                print(f"  AS TEXT: {chunk!r}")
            else:
                print(f"  Nothing at {baud} baud")
            ser.close()
        except serial.SerialException as e:
            print(f"  Error: {e}")
else:
    ser.close()

print("\n" + "=" * 60)
print("Done - paste this full output so the protocol can be identified.")
print("=" * 60)
