#!/usr/bin/env python3
"""
CAEN R1210IX - Protocol probe diagnostic.
Tries many different command formats and captures every byte the reader
sends back. Paste the full output so the protocol can be identified.
"""

import json
import struct
import sys
import time
from pathlib import Path

import serial
import serial.tools.list_ports

# ── Settings ──────────────────────────────────────────────────────────────────
s    = json.loads((Path(__file__).parent / "settings.json").read_text())
PORT = s.get("comPort", "COM3")
BAUD = s.get("baudRate", 115200)

def recv(ser, wait=1.0):
    buf = b""
    deadline = time.time() + wait
    while time.time() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf += chunk
            deadline = time.time() + 0.4
    return buf

def probe(ser, label, data):
    ser.reset_input_buffer()
    print(f"\n  → {label}")
    print(f"    SENT: {data.hex()}  {data!r}")
    ser.write(data)
    resp = recv(ser, 1.5)
    if resp:
        print(f"    GOT ({len(resp)} bytes): {resp.hex()}")
        print(f"    TEXT: {resp!r}")
    else:
        print(f"    (no response)")
    return resp

def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc

def caen_frame(cmd, data=b""):
    payload = bytes([cmd]) + data
    body    = struct.pack("<H", len(payload)) + payload
    return b"\x02" + body + struct.pack("<H", crc16(body)) + b"\x03"

# ── List COM ports ────────────────────────────────────────────────────────────
print("=" * 60)
print("Available COM ports:")
for p in serial.tools.list_ports.comports():
    print(f"  {p.device:10s}  {p.description}")
print("=" * 60)

# ── Open port ────────────────────────────────────────────────────────────────
print(f"\nOpening {PORT} at {BAUD} baud...")
try:
    ser = serial.Serial(
        PORT, BAUD,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.1,
        dsrdtr=False,
        rtscts=False,
    )
    print("Port opened OK")
except serial.SerialException as e:
    print(f"FAILED: {e}")
    print("Make sure CAEN software is fully closed and try again.")
    sys.exit(1)

# ── Toggle DTR/RTS (wakes some USB-serial devices) ───────────────────────────
print("\nToggling DTR/RTS to wake device...")
ser.dtr = True;  ser.rts = True;  time.sleep(0.2)
ser.dtr = False; ser.rts = False; time.sleep(0.2)
startup = recv(ser, 1.0)
if startup:
    print(f"  Device sent on startup: {startup.hex()}  {startup!r}")
else:
    print("  Nothing on startup")

# ── Variant A: my current binary framing (cmd bytes 0x01-0x06) ───────────────
print("\n── Variant A: current binary frames ─────────────────────")
probe(ser, "A1 Open (0x01)",            caen_frame(0x01))
probe(ser, "A2 Set protocol GEN2",      caen_frame(0x03, b"\x00"))
probe(ser, "A3 Set power 30dBm",        caen_frame(0x04, struct.pack("<H", 3000)))
probe(ser, "A4 Start inventory (0x05)", caen_frame(0x05))
print("  Listening 5s for tags (wave a tag over reader now)...")
r = recv(ser, 5)
if r: print(f"  TAGS: {r.hex()}  {r!r}")
else: print("  (nothing)")
probe(ser, "A5 Stop inventory (0x06)",  caen_frame(0x06))

# ── Variant B: alternate CAEN command numbering ───────────────────────────────
print("\n── Variant B: alternate command bytes ────────────────────")
probe(ser, "B1 Init (0x00)",             caen_frame(0x00))
probe(ser, "B2 GetReaderInfo (0x02)",    caen_frame(0x02))
probe(ser, "B3 SetProtocol alt (0x04)",  caen_frame(0x04, b"\x00"))
probe(ser, "B4 Start inv (0x0D)",        caen_frame(0x0D))
print("  Listening 5s for tags...")
r = recv(ser, 5)
if r: print(f"  TAGS: {r.hex()}  {r!r}")
else: print("  (nothing)")
probe(ser, "B5 Stop inv (0x0E)",         caen_frame(0x0E))

# ── Variant C: raw single bytes ───────────────────────────────────────────────
print("\n── Variant C: raw single bytes ───────────────────────────")
for b in [0x00, 0x01, 0x02, 0x04, 0x05, 0x0D, 0xFF]:
    probe(ser, f"raw byte 0x{b:02X}", bytes([b]))

# ── Variant D: simple ASCII text commands ────────────────────────────────────
print("\n── Variant D: ASCII text commands ────────────────────────")
for cmd in [b"?\r\n", b"AT\r\n", b"INV\r\n", b"GET\r\n",
            b"START\r\n", b"INVENTORY\r\n", b"GET_TAG\r\n"]:
    probe(ser, f"text: {cmd!r}", cmd)

ser.close()
print("\n" + "=" * 60)
print("Done — paste the full output above.")
print("=" * 60)
