#!/usr/bin/env python3
"""
CAEN R1210IX — serial protocol probe / raw traffic dump.

Opens the COM port and tries every likely CAEN command byte, logging all raw
bytes the reader sends back.  Use this to verify the protocol is correct when
serial_reader.py does not produce tag reads.

Usage:
  python probe.py              # uses COM3 at 115200 baud
  python probe.py COM4
  python probe.py COM3 9600
"""

import struct
import sys
import time

import serial

# ─── Config from command line ─────────────────────────────────────────────────

PORT  = sys.argv[1] if len(sys.argv) > 1 else "COM3"
BAUD  = int(sys.argv[2]) if len(sys.argv) > 2 else 115200

SEP = "=" * 60

# ─── Protocol helpers (same as serial_reader.py) ─────────────────────────────

STX, ETX = 0x02, 0x03

def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
        crc &= 0xFFFF
    return crc

def frame(cmd, data=b""):
    payload = bytes([cmd]) + data
    inner   = struct.pack(">H", len(payload)) + payload
    return bytes([STX]) + inner + bytes([ETX]) + struct.pack(">H", crc16(inner))

def drain(ser, window=0.5):
    """Read all bytes available within window seconds."""
    buf = bytearray()
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        n = ser.in_waiting
        if n:
            buf.extend(ser.read(n))
        else:
            time.sleep(0.02)
    return bytes(buf)

# ─── Open port ────────────────────────────────────────────────────────────────

print(SEP)
print(f"CAEN R1210IX serial probe  |  {PORT}  @  {BAUD} baud")
print(SEP)

# Accept "COM3" or "\\\\.\\COM3"
port_arg = PORT if PORT.startswith("\\\\.\\") else "\\\\.\\" + PORT

try:
    ser = serial.Serial(
        port=port_arg, baudrate=BAUD,
        bytesize=8, parity="N", stopbits=1,
        timeout=0.3, write_timeout=2.0,
    )
    ser.reset_input_buffer()
    print(f"Port opened OK: {port_arg}\n")
except serial.SerialException as e:
    print(f"FAILED to open {port_arg}: {e}")
    sys.exit(1)

# Flush any stale data
leftover = drain(ser, 0.3)
if leftover:
    print(f"Stale data in buffer: {leftover.hex()}\n")

# ─── Probe sequence ───────────────────────────────────────────────────────────

probes = [
    # (description, frame_bytes)
    ("READER_INFO  cmd=0x01",        frame(0x01)),
    ("INVENTORY    cmd=0x03 noarg",  frame(0x03)),
    ("INVENTORY    cmd=0x03 src=0",  frame(0x03, b"\x00")),
    ("INVENTORY    cmd=0x03 Source_0",
     frame(0x03, b"\x08Source_0")),
    ("SET_POWER    cmd=0x07 p=30",   frame(0x07, b"\x1e")),
    ("GET_POWER    cmd=0x08",        frame(0x08)),
    # Try a few more plausible command codes
    ("CMD 0x00",                     frame(0x00)),
    ("CMD 0x02",                     frame(0x02)),
    ("CMD 0x04",                     frame(0x04)),
    ("CMD 0x05",                     frame(0x05)),
    ("CMD 0x06",                     frame(0x06)),
    ("CMD 0x09",                     frame(0x09)),
    ("CMD 0x0A",                     frame(0x0A)),
    ("CMD 0x10",                     frame(0x10)),
    ("CMD 0x11",                     frame(0x11)),
    ("CMD 0x20",                     frame(0x20)),
]

any_response = False
for desc, pkt in probes:
    ser.reset_input_buffer()
    print(f"  TX  {desc}")
    print(f"      bytes: {pkt.hex()}")
    ser.write(pkt)
    ser.flush()
    resp = drain(ser, 0.8)
    if resp:
        any_response = True
        print(f"  RX  [{len(resp)} bytes]: {resp.hex()}")
        # Try to decode as ASCII too
        try:
            text = resp.decode("ascii", errors="replace")
            if any(32 <= ord(c) < 127 for c in text):
                print(f"  ASCII: {repr(text)}")
        except Exception:
            pass
    else:
        print("  RX  (no response)")
    print()
    time.sleep(0.1)

ser.close()

print(SEP)
if any_response:
    print("Reader responded to at least one command!")
    print("Share the RX hex output above so we can decode the protocol.")
else:
    print("No response to any command.")
    print()
    print("Possible causes:")
    print("  1. Wrong baud rate — try: python probe.py COM3 9600")
    print("       then 19200, 38400, 57600, 115200, 921600")
    print("  2. Different protocol framing — reader may not use STX/ETX framing")
    print("  3. Reader is off or not fully enumerated — unplug/replug and retry")
    print("  4. Share the diagnose.py output so we can verify COM3 is really open")
print(SEP)
