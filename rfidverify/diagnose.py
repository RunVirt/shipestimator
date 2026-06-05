#!/usr/bin/env python3
"""
CAEN R1210IX diagnostic tool.
Opens the COM port, sends each command, and dumps exactly what comes back.
Run this and paste the output so the protocol can be verified.
"""

import json
import struct
import time
from pathlib import Path

import serial

# ── Load settings ──────────────────────────────────────────────────────────────
s = json.loads((Path(__file__).parent / "settings.json").read_text())
PORT = s.get("comPort", "COM3")
BAUD = s.get("baudRate", 115200)

STX, ETX = 0x02, 0x03

def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

def frame(cmd: int, data: bytes = b"") -> bytes:
    payload = bytes([cmd]) + data
    body    = struct.pack("<H", len(payload)) + payload
    return bytes([STX]) + body + struct.pack("<H", crc16(body)) + bytes([ETX])

def recv(ser: serial.Serial, wait=1.5) -> bytes:
    buf = b""
    deadline = time.time() + wait
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            deadline = time.time() + 0.4   # keep reading if data arrives
    return buf

def show(label: str, data: bytes):
    if data:
        print(f"  ← {label} ({len(data)} bytes)")
        print(f"    HEX : {data.hex()}")
        print(f"    TEXT: {data!r}")
    else:
        print(f"  ← {label}: (nothing)")

print("=" * 60)
print(f"CAEN R1210IX Diagnostic  —  {PORT} @ {BAUD} baud")
print("=" * 60)

try:
    ser = serial.Serial(PORT, BAUD, timeout=0.1)
    print(f"Port opened OK\n")
except serial.SerialException as e:
    print(f"FAILED to open {PORT}: {e}")
    raise SystemExit(1)

steps = [
    ("Open Reader",      frame(0x01)),
    ("Set GEN2 proto",   frame(0x03, b"\x00")),
    ("Set power 30dBm",  frame(0x04, struct.pack("<H", 3000))),
    ("Start inventory",  frame(0x05)),
]

for label, cmd in steps:
    print(f"→ {label}:  {cmd.hex()}")
    ser.write(cmd)
    resp = recv(ser)
    show("response", resp)
    time.sleep(0.2)

print("\nListening for tag reads for 10 seconds — wave a tag over the reader now...")
tag_data = recv(ser, wait=10)
show("Tag reads", tag_data)

print("\n→ Stop inventory:", frame(0x06).hex())
ser.write(frame(0x06))
show("response", recv(ser))

ser.close()
print("\n" + "=" * 60)
print("Done — paste this entire output for protocol verification.")
print("=" * 60)
