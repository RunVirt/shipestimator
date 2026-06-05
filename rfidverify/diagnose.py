#!/usr/bin/env python3
"""
CAEN R1210IX — SDK 5.0.0 diagnostic.

Finds CAENRFIDLib.dll (64-bit), connects to the reader, runs one
inventory cycle, and prints any tags found.  Paste the full output
so we can confirm which DLL was used and whether reads work.

Usage:
  python diagnose.py
  python diagnose.py "C:\\full\\path\\to\\64bit\\CAENRFIDLib.dll"
"""

import ctypes
import ctypes.util
import glob
import os
import sys
import time
from pathlib import Path

import serial.tools.list_ports

SEP = "=" * 60

# ── COM ports ─────────────────────────────────────────────────────────────────
print(SEP)
print("Available COM ports:")
for p in serial.tools.list_ports.comports():
    print(f"  {p.device:10s}  {p.description}")
print(SEP)

# ── Find CAENRFIDLib.dll ──────────────────────────────────────────────────────
print("\nSearching for CAENRFIDLib.dll (64-bit)...")

dll_path = sys.argv[1] if len(sys.argv) > 1 else ""

if not dll_path:
    user = os.environ.get("USERNAME") or os.environ.get("USER", "")
    patterns = [
        r"C:\Program Files\CAEN\**\CAENRFIDLib.dll",
        r"C:\Program Files (x86)\CAEN\**\CAENRFIDLib.dll",
        r"C:\CAEN\**\CAENRFIDLib.dll",
        r"C:\Windows\System32\CAENRFIDLib.dll",
        r"C:\Windows\SysWOW64\CAENRFIDLib.dll",
    ]
    if user:
        patterns += [
            rf"C:\Users\{user}\Desktop\**\CAENRFIDLib.dll",
            rf"C:\Users\{user}\OneDrive\Desktop\**\CAENRFIDLib.dll",
            rf"C:\Users\{user}\OneDrive - *\Desktop\**\CAENRFIDLib.dll",
        ]
    found = []
    for pat in patterns:
        try:
            found.extend(glob.glob(pat, recursive=True))
        except Exception:
            pass
    # Also near this script
    for d in (Path(__file__).parent, Path(__file__).parent.parent):
        for f in d.rglob("CAENRFIDLib.dll"):
            found.append(str(f))

    found = list(dict.fromkeys(found))  # deduplicate, preserve order

    if found:
        print(f"  Found {len(found)} DLL(s):")
        for d in found:
            print(f"    {d}")
        dll_path = found[0]
        print(f"\n  Using: {dll_path}")
    else:
        print("  No CAENRFIDLib.dll found automatically.")
        dll_path = input("\n  Paste full path to 64-bit CAENRFIDLib.dll (or Enter to skip): ").strip()
        if not dll_path or not os.path.exists(dll_path):
            print("  Skipping DLL test.")
            dll_path = ""

# ── Load DLL ──────────────────────────────────────────────────────────────────
if not dll_path:
    print("\nNo DLL to test.")
    sys.exit(0)

print(f"\n{SEP}")
print(f"Loading: {dll_path}")

# Add the DLL's own directory to the search path so Windows can find
# any sibling DLLs that CAENRFIDLib.dll depends on (Python 3.8+).
dll_dir = str(Path(dll_path).parent)
if hasattr(os, "add_dll_directory"):
    os.add_dll_directory(dll_dir)
    print(f"  Added DLL search dir: {dll_dir}")

try:
    lib = ctypes.WinDLL(dll_path)
    print("  DLL loaded OK")
except AttributeError:
    print("  ERROR: ctypes.WinDLL not available — run this on Windows")
    sys.exit(1)
except OSError as e:
    print(f"  ERROR loading DLL: {e}")
    print("  Hint: make sure you are using the 64-bit DLL with 64-bit Python")
    sys.exit(1)

# ── List exported functions ───────────────────────────────────────────────────
print("\nLooking for CAEN functions...")
for name in ("CAENRFIDLib_Connect", "CAENRFIDLib_Disconnect",
             "CAENRFIDLib_InventoryTag", "CAENRFIDLib_EventInventoryTag"):
    try:
        _ = getattr(lib, name)
        print(f"  {name}  ✓ found")
    except AttributeError:
        print(f"  {name}  ✗ NOT found")

# ── Connect ───────────────────────────────────────────────────────────────────
COM_PORT = "COM3"
print(f"\nConnecting to {COM_PORT} via CAENRFIDLib_Connect...")

handle = ctypes.c_void_p(0)
try:
    lib.CAENRFIDLib_Connect.restype  = ctypes.c_int
    lib.CAENRFIDLib_Connect.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    ret = lib.CAENRFIDLib_Connect(COM_PORT.encode(), ctypes.byref(handle))
    print(f"  Return code: {ret}  Handle: {handle.value}")
    if ret == 0:
        print("  Connected OK!")
    else:
        print(f"  Connect failed (code {ret})")
        print("  Is CAEN software closed? Is the reader on COM3?")
        sys.exit(1)
except AttributeError:
    print("  CAENRFIDLib_Connect not available in this DLL")
    sys.exit(1)

# ── Inventory ─────────────────────────────────────────────────────────────────
print("\nRunning inventory (wave a tag over the reader)...")

# CAENRFIDTag struct layout from CAENRFIDTypes.h SDK 5.0.0
class _TimeVal(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_int32), ("tv_usec", ctypes.c_int32)]

class CAENRFIDTag(ctypes.Structure):
    _fields_ = [
        ("ID",                    ctypes.c_ubyte * 64),
        ("Length",                ctypes.c_int16),
        ("LogicalSource",         ctypes.c_char  * 30),
        ("ReadPoint",             ctypes.c_char  * 5),
        ("TimeStamp",             _TimeVal),
        ("Type",                  ctypes.c_int32),
        ("RSSI",                  ctypes.c_int16),
        ("TID",                   ctypes.c_ubyte * 64),
        ("TIDLen",                ctypes.c_int16),
        ("XPC",                   ctypes.c_ubyte * 4),
        ("PC",                    ctypes.c_ubyte * 2),
        ("phaseBegin",            ctypes.c_float),
        ("phaseEnd",              ctypes.c_float),
        ("frequency",             ctypes.c_int32),
        ("subCmdCode",            ctypes.c_int32),
        ("subCmdResultCode",      ctypes.c_int32),
        ("subCmdResultDataCount", ctypes.c_int16),
        ("subCmdResultData",      ctypes.c_void_p),
    ]

print(f"  CAENRFIDTag sizeof = {ctypes.sizeof(CAENRFIDTag)} bytes (expected 224)")

lib.CAENRFIDLib_InventoryTag.restype  = ctypes.c_int
lib.CAENRFIDLib_InventoryTag.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_uint16),
]

tags_found = 0
for attempt in range(10):
    tags_ptr = ctypes.c_void_p(0)
    count    = ctypes.c_uint16(0)
    ret      = lib.CAENRFIDLib_InventoryTag(handle, ctypes.byref(tags_ptr), ctypes.byref(count))
    print(f"  Attempt {attempt+1}: ret={ret}  count={count.value}", end="")

    if ret == 0 and count.value > 0 and tags_ptr.value:
        array_type = CAENRFIDTag * count.value
        tags = ctypes.cast(tags_ptr, ctypes.POINTER(array_type)).contents
        print()
        for tag in tags:
            if tag.Length > 0:
                epc = bytes(tag.ID[:tag.Length]).hex().upper()
                print(f"    TAG  EPC={epc}  RSSI={tag.RSSI} dBm")
                tags_found += 1
    else:
        print("  (no tags)" if ret in (0, -13) else f"  (error {ret})")

    time.sleep(0.5)

# ── Disconnect ────────────────────────────────────────────────────────────────
print("\nDisconnecting...")
try:
    lib.CAENRFIDLib_Disconnect.restype  = ctypes.c_int
    lib.CAENRFIDLib_Disconnect.argtypes = [ctypes.c_void_p]
    lib.CAENRFIDLib_Disconnect(handle)
    print("  Disconnected OK")
except AttributeError:
    pass

print(f"\n{SEP}")
print(f"Done — {tags_found} tag read(s) captured.")
print("Paste the full output above to confirm the setup works.")
print(SEP)
