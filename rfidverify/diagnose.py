#!/usr/bin/env python3
"""
Printer protocol diagnostic tool.
Connects to the printer and tries several approaches to figure out
what protocol it actually uses. Run this and paste the output here.
"""

import socket
import time
import json
from pathlib import Path

# Load IP/port from settings.json
settings_path = Path(__file__).parent / "settings.json"
with open(settings_path) as f:
    s = json.load(f)

IP   = s.get("ip",   "192.168.50.169")
PORT = s.get("port", 6101)

WAIT = 3.0  # seconds to wait for a response each time

def recv_all(sock, timeout=WAIT):
    buf = b""
    sock.settimeout(timeout)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            sock.settimeout(0.3)   # keep reading if more arrives quickly
        except socket.timeout:
            break
        except OSError:
            break
    return buf

def show(label, data):
    if data:
        print(f"\n>>> {label}")
        print(f"    HEX : {data.hex()}")
        print(f"    TEXT: {data!r}")
    else:
        print(f"\n>>> {label}: (nothing received)")

def try_send(sock, label, payload):
    print(f"\nSending [{label}]: {payload!r}  hex={payload.hex()}")
    try:
        sock.sendall(payload)
    except OSError as e:
        print(f"  Send failed: {e}")
        return
    resp = recv_all(sock)
    show(f"Response to [{label}]", resp)

print("=" * 60)
print(f"Connecting to {IP}:{PORT} ...")
print("=" * 60)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((IP, PORT))
    print("Connected.\n")
except OSError as e:
    print(f"FAILED to connect: {e}")
    raise SystemExit(1)

# 1. Listen first — does the printer say anything on its own?
print("Listening for unsolicited data (3 seconds)...")
first = recv_all(sock)
show("Unsolicited data", first)

# 2. Plain newline
try_send(sock, "CRLF",          b"\r\n")

# 3. Question mark (some devices send a help/menu)
try_send(sock, "?",             b"?\r\n")

# 4. ZPL host-status query
try_send(sock, "ZPL ~HS",       b"~HS\r\n")

# 5. SGD get all (Zebra Link-OS)
try_send(sock, "SGD get all",   b"! U1 getvar \"all\"\r\n")

# 6. Common RFID text commands
try_send(sock, "RFID SETUP",    b"RFID SETUP\r\n")
try_send(sock, "RFID READ",     b"RFID READ\r\n")
try_send(sock, "GET TAGS",      b"GET TAGS\r\n")
try_send(sock, "INVENTORY",     b"INVENTORY\r\n")

# 7. Single STX byte (start of many binary protocols)
try_send(sock, "STX=0x02",      b"\x02")

# 8. Common binary handshake patterns
try_send(sock, "0x01 0x00",     b"\x01\x00")
try_send(sock, "0xFF",          b"\xff")

sock.close()
print("\n" + "=" * 60)
print("Done. Paste the full output above back to Claude.")
print("=" * 60)
