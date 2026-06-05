#!/usr/bin/env python3
"""
CAEN R1210IX — network & process probe.

Checks whether:
  1. Any CAEN-related Windows processes are running (holds the USB device)
  2. A CAEN RFID middleware is listening on localhost (TCP connection mode)
  3. The DLL can connect when we use the newer CAENRFIDLib_Connect API

Run this with CAEN RFID Lab open AND with it closed to see the difference.

Usage:
  python netprobe.py
"""

import ctypes
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

SEP = "=" * 60

# ── 1. List running processes that look CAEN-related ────────────────────────
print(SEP)
print("1. Checking for running CAEN / RFID processes ...")
print(SEP)
try:
    out = subprocess.check_output(
        ["tasklist", "/fo", "csv", "/nh"],
        text=True, errors="replace"
    )
    caen_procs = []
    for line in out.splitlines():
        lower = line.lower()
        if any(k in lower for k in ("caen", "rfid", "rflab", "r2rf", "rfidlab")):
            caen_procs.append(line.strip().strip('"').split('","')[0])

    if caen_procs:
        print("  CAEN/RFID processes found (these may be holding the USB device):")
        for p in caen_procs:
            print(f"    {p}")
        print()
        print("  → Close ALL of them before running main.py or diagnose.py")
    else:
        print("  No CAEN/RFID processes detected.")
except Exception as e:
    print(f"  (tasklist failed: {e})")

# ── 2. TCP port scan — CAEN middleware / easyReader server ───────────────────
print()
print(SEP)
print("2. Scanning localhost for CAEN middleware TCP servers ...")
print("   (CAEN RFID Lab, R2RF, or easyReader SDK server)")
print(SEP)

CAEN_PORTS = [10001, 2000, 9090, 5555, 4001, 8080, 8000, 3000]

open_ports = []
for port in CAEN_PORTS:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        s.settimeout(1.0)
        banner = b""
        try:
            banner = s.recv(256)
        except Exception:
            pass
        s.close()
        open_ports.append((port, banner))
        hex_banner = banner.hex() if banner else "(no banner)"
        try:
            txt = banner.decode("latin-1", errors="replace").strip()
            printable = sum(32 <= ord(c) < 127 for c in txt) > len(txt) * 0.6
        except Exception:
            printable = False
        print(f"  *** OPEN port {port}: {hex_banner}")
        if printable and banner:
            print(f"      ASCII: {repr(txt[:80])}")
    except (ConnectionRefusedError, OSError):
        print(f"  port {port}: closed")

if open_ports:
    print()
    print("  → One of those open ports may be a CAEN easyReader TCP server.")
    print("  → To use it: set readerBackend=dll and let the DLL connect via")
    print("    connType=1 (TCP/IP). Run tcp_connect.py (created below) to test.")
else:
    print()
    print("  No CAEN TCP server found on localhost.")

# ── 3. Try new-style DLL API: CAENRFIDLib_Connect ───────────────────────────
print()
print(SEP)
print("3. Trying newer DLL API: CAENRFIDLib_Connect ...")
print(SEP)

import glob

def find_dll():
    patterns = [
        r"C:\Program Files\CAEN\**\CAENRFIDLib.dll",
        r"C:\Program Files (x86)\CAEN\**\CAENRFIDLib.dll",
        r"C:\CAEN\**\CAENRFIDLib.dll",
    ]
    user = os.environ.get("USERNAME") or ""
    if user:
        patterns += [
            rf"C:\Users\{user}\Desktop\**\CAENRFIDLib.dll",
            rf"C:\Users\{user}\OneDrive\Desktop\**\CAENRFIDLib.dll",
            rf"C:\Users\{user}\OneDrive - *\Desktop\**\CAENRFIDLib.dll",
        ]
    hits = []
    for pat in patterns:
        try:
            hits.extend(glob.glob(pat, recursive=True))
        except Exception:
            pass
    script_dir = Path(__file__).parent
    for d in (script_dir, script_dir.parent):
        hits.extend(str(f) for f in d.rglob("CAENRFIDLib.dll"))
    # Prefer x64
    for h in hits:
        try:
            data = Path(h).read_bytes()
            if data[:2] == b"MZ":
                pe_off = struct.unpack_from("<I", data, 0x3C)[0]
                if struct.unpack_from("<H", data, pe_off + 4)[0] == 0x8664:
                    return h
        except Exception:
            pass
    return hits[0] if hits else None

dll_path = find_dll()
if not dll_path:
    print("  No DLL found — skipping.")
else:
    print(f"  DLL: {dll_path}")
    try:
        dll_dir = str(Path(dll_path).parent)
        if hasattr(os, "add_dll_directory"):
            os.add_dll_directory(dll_dir)
        lib = ctypes.WinDLL(dll_path)

        # Check which connect function exists
        has_new = hasattr(lib, "CAENRFIDLib_Connect")
        has_old = hasattr(lib, "CAENRFID_Init")
        print(f"  CAENRFIDLib_Connect: {'YES' if has_new else 'no'}")
        print(f"  CAENRFID_Init      : {'YES' if has_old else 'no'}")

        if has_new:
            # New API: CAENRFIDLib_Connect(connType, pParams, pHandle)
            # where pHandle is a CAENRFIDReader* (pointer to a handle struct)
            lib.CAENRFIDLib_Connect.restype  = ctypes.c_int
            lib.CAENRFIDLib_Connect.argtypes = [
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            for conn_type, param, label in [
                (3, None,               "USB (connType=3, NULL)"),
                (3, ctypes.c_char_p(b"0"), "USB (connType=3, '0')"),
            ]:
                handle = ctypes.c_void_p(0)
                try:
                    ret = lib.CAENRFIDLib_Connect(conn_type, param, ctypes.byref(handle))
                    print(f"  CAENRFIDLib_Connect {label}: ret={ret}  handle={handle.value}")
                    if ret == 0 and handle.value:
                        print("  *** Connected with new API!")
                        try:
                            lib.CAENRFIDLib_Disconnect.restype  = ctypes.c_int
                            lib.CAENRFIDLib_Disconnect.argtypes = [ctypes.c_void_p]
                            lib.CAENRFIDLib_Disconnect(handle)
                            print("  Disconnected OK")
                        except Exception:
                            pass
                        break
                    elif ret == -11:
                        print("  → -11: device held by another process. Close CAEN software first.")
                        break
                except OSError as e:
                    print(f"  CAENRFIDLib_Connect crashed: {e}")
                    break
    except Exception as e:
        print(f"  Could not load DLL: {e}")

# ── 4. DLL connType=1 TCP test (if open port found above) ───────────────────
if open_ports and dll_path:
    print()
    print(SEP)
    print("4. Trying DLL TCP connection to open local ports ...")
    print(SEP)
    try:
        lib = ctypes.WinDLL(dll_path)
        lib.CAENRFID_Init.restype  = ctypes.c_int
        lib.CAENRFID_Init.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        for port, _ in open_ports:
            handle = ctypes.c_void_p(0)
            param  = ctypes.c_char_p(f"127.0.0.1:{port}".encode())
            print(f"  CAENRFID_Init TCP 127.0.0.1:{port} ...")
            try:
                ret = lib.CAENRFID_Init(1, param, ctypes.byref(handle))
                print(f"    ret={ret}  handle={handle.value}")
                if ret == 0 and handle.value:
                    print("  *** TCP connection worked!")
                    lib.CAENRFID_End.restype  = ctypes.c_int
                    lib.CAENRFID_End.argtypes = [ctypes.c_void_p]
                    lib.CAENRFID_End(handle)
            except OSError as e:
                print(f"    crashed: {e}")
    except Exception as e:
        print(f"  DLL load error: {e}")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print(SEP)
print("NEXT STEPS:")
print()
print("  Paste the full output above in chat so we can see exactly what's open")
print("  and which API calls succeed.")
print()
print("  Most useful info:")
print("    - Section 1: which CAEN processes are running right now")
print("    - Section 2: any open TCP ports (CAEN middleware server)")
print("    - Section 3: which DLL connect functions exist and their return codes")
print(SEP)
