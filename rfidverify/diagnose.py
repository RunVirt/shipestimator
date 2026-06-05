#!/usr/bin/env python3
"""
CAEN R1210IX - SDK diagnostic.
Searches for CAENrfid.dll (installed with CAEN software) and uses it
to connect to the reader. Paste the full output so we can confirm
which DLL was found and whether the connection works.
"""

import ctypes
import ctypes.util
import glob
import json
import os
import sys
import time
from pathlib import Path

import serial.tools.list_ports

# ── List COM ports ────────────────────────────────────────────────────────────
print("=" * 60)
print("Available COM ports:")
import serial
for p in serial.tools.list_ports.comports():
    print(f"  {p.device:10s}  {p.description}")
print("=" * 60)

# ── Search for CAENrfid.dll ───────────────────────────────────────────────────
print("\nSearching for CAENrfid.dll...")

search_paths = [
    r"C:\Program Files\CAEN\**\CAENrfid.dll",
    r"C:\Program Files (x86)\CAEN\**\CAENrfid.dll",
    r"C:\Program Files\CAEN\**\CAENrfid*.dll",
    r"C:\Program Files (x86)\CAEN\**\CAENrfid*.dll",
    r"C:\CAEN\**\CAENrfid.dll",
    r"C:\Windows\System32\CAENrfid.dll",
    r"C:\Windows\SysWOW64\CAENrfid.dll",
]

found_dlls = []
for pattern in search_paths:
    matches = glob.glob(pattern, recursive=True)
    found_dlls.extend(matches)

# Also search the current directory and parent
for extra in [Path(__file__).parent, Path(__file__).parent.parent]:
    for f in extra.glob("**/*.dll"):
        if "caen" in f.name.lower():
            found_dlls.append(str(f))

found_dlls = list(set(found_dlls))

if found_dlls:
    print(f"  Found {len(found_dlls)} CAEN DLL(s):")
    for d in found_dlls:
        print(f"    {d}")
else:
    print("  No CAENrfid.dll found in standard locations.")
    print("\n  To fix this:")
    print("  1. Find where your CAEN software is installed")
    print("  2. Look for CAENrfid.dll in that folder")
    print("  3. Copy the full path and paste it below")
    dll_path = input("\n  Paste the full path to CAENrfid.dll (or press Enter to skip): ").strip()
    if dll_path and os.path.exists(dll_path):
        found_dlls = [dll_path]
    else:
        print("\n  Skipping DLL test.")
        found_dlls = []

# ── Try loading and using the DLL ─────────────────────────────────────────────
for dll_path in found_dlls[:1]:   # try the first one found
    print(f"\nLoading: {dll_path}")
    try:
        lib = ctypes.WinDLL(dll_path)
        print("  DLL loaded OK")
    except OSError as e:
        print(f"  Failed to load: {e}")
        continue

    # ── Try connecting ─────────────────────────────────────────────────────
    # CAEN SDK connection types: 0=USB, 1=RS232, 2=TCP/IP
    # CAENRFID_Connect(int connType, void* connParam, int* handle)
    handle = ctypes.c_int32(-1)

    print("\n  Trying USB connection (type 0)...")
    try:
        lib.CAENRFID_Connect.restype  = ctypes.c_int
        lib.CAENRFID_Connect.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int32)
        ]
        ret = lib.CAENRFID_Connect(0, None, ctypes.byref(handle))
        print(f"  Return code: {ret}  Handle: {handle.value}")
        if ret == 0:
            print("  USB connection OK!")
        else:
            print(f"  USB failed (code {ret}), trying RS232/COM3...")
            com = ctypes.c_char_p(b"COM3")
            ret = lib.CAENRFID_Connect(1, com, ctypes.byref(handle))
            print(f"  RS232 return code: {ret}  Handle: {handle.value}")
            if ret == 0:
                print("  RS232 connection OK!")
    except AttributeError:
        print("  CAENRFID_Connect not found — trying alternate function names...")
        funcs = [name for name in dir(lib) if "connect" in name.lower() or "open" in name.lower()]
        print(f"  Available functions with 'connect'/'open': {funcs}")

    # ── If connected, try reading tags ──────────────────────────────────────
    if handle.value >= 0:
        print("\n  Connected! Trying to read tags...")
        print("  (Wave a bib tag over the reader now)")
        time.sleep(3)

        # Try GetTagData or similar
        try:
            buf = ctypes.create_string_buffer(256)
            ret2 = lib.CAENRFID_GetTagData(handle, buf)
            print(f"  GetTagData returned {ret2}, data: {buf.raw[:32].hex()}")
        except AttributeError:
            pass

        # Disconnect
        try:
            lib.CAENRFID_Disconnect(handle)
            print("  Disconnected OK")
        except AttributeError:
            pass

print("\n" + "=" * 60)
print("Done — paste the full output above.")
print("=" * 60)
