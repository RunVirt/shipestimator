#!/usr/bin/env python3
"""
CAEN R1210IX — comprehensive diagnostic.

Finds every CAENRFIDLib.dll it can, reads each one's export table to show
which functions it contains, then tries to connect on COM3 and read tags.

Usage:
  python diagnose.py
  python diagnose.py "C:\\full\\path\\to\\CAENRFIDLib.dll"
"""

import ctypes
import glob
import os
import struct
import sys
import time
from pathlib import Path

import serial.tools.list_ports

SEP = "=" * 60


# ── PE export reader (no external libraries needed) ───────────────────────────

def pe_info(path):
    """
    Returns (arch, [export_names], [import_dll_names]) by parsing PE headers.
    arch is 'x64', 'x86', or 'unknown'.
    """
    try:
        data = bytearray(Path(path).read_bytes())
    except OSError:
        return "unknown", [], []

    if data[:2] != b"MZ":
        return "unknown", [], []
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off : pe_off + 4] != b"PE\x00\x00":
        return "unknown", [], []

    machine  = struct.unpack_from("<H", data, pe_off + 4)[0]
    arch     = "x64" if machine == 0x8664 else "x86" if machine == 0x14C else f"0x{machine:04x}"
    num_secs = struct.unpack_from("<H", data, pe_off + 6)[0]
    opt_sz   = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off  = pe_off + 24
    magic    = struct.unpack_from("<H", data, opt_off)[0]
    secs_off = opt_off + opt_sz

    if magic == 0x10B:    # PE32
        exp_rva, imp_rva = (struct.unpack_from("<I", data, opt_off + 96)[0],
                            struct.unpack_from("<I", data, opt_off + 104)[0])
    elif magic == 0x20B:  # PE32+
        exp_rva, imp_rva = (struct.unpack_from("<I", data, opt_off + 112)[0],
                            struct.unpack_from("<I", data, opt_off + 120)[0])
    else:
        return arch, [], []

    def rva2off(rva):
        for i in range(num_secs):
            s = secs_off + i * 40
            va, vsz = struct.unpack_from("<I", data, s + 12)[0], struct.unpack_from("<I", data, s + 8)[0]
            ro, rsz = struct.unpack_from("<I", data, s + 20)[0], struct.unpack_from("<I", data, s + 16)[0]
            if va <= rva < va + max(vsz, rsz):
                return ro + (rva - va)
        return None

    def cstr(off):
        end = data.index(0, off)
        return data[off:end].decode("ascii", errors="replace")

    # Export names
    exports = []
    if exp_rva:
        eo = rva2off(exp_rva)
        if eo:
            nn  = struct.unpack_from("<I", data, eo + 24)[0]
            nrva = struct.unpack_from("<I", data, eo + 32)[0]
            no  = rva2off(nrva)
            if no:
                for i in range(nn):
                    nr = struct.unpack_from("<I", data, no + i * 4)[0]
                    noff = rva2off(nr)
                    if noff:
                        exports.append(cstr(noff))

    # Import DLL names
    imports = []
    if imp_rva:
        io = rva2off(imp_rva)
        if io:
            while True:
                name_rva = struct.unpack_from("<I", data, io + 12)[0]
                if name_rva == 0:
                    break
                noff = rva2off(name_rva)
                if noff:
                    imports.append(cstr(noff))
                io += 20

    return arch, exports, imports


# ── COM ports ─────────────────────────────────────────────────────────────────
print(SEP)
print("Available COM ports:")
for p in serial.tools.list_ports.comports():
    print(f"  {p.device:10s}  {p.description}")
print(SEP)

# ── Find DLLs ─────────────────────────────────────────────────────────────────
print("\nSearching for CAENRFIDLib.dll...")

if len(sys.argv) > 1:
    candidates = [sys.argv[1]]
else:
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
    candidates = []
    for pat in patterns:
        try:
            candidates.extend(glob.glob(pat, recursive=True))
        except Exception:
            pass
    for d in (Path(__file__).parent, Path(__file__).parent.parent):
        for f in d.rglob("CAENRFIDLib.dll"):
            candidates.append(str(f))
    candidates = list(dict.fromkeys(candidates))

if not candidates:
    print("  No DLLs found. Pass the path as an argument:")
    print(r'  python diagnose.py "C:\path\to\64bit\CAENRFIDLib.dll"')
    sys.exit(1)

# ── Inspect each DLL ──────────────────────────────────────────────────────────
print(f"\nFound {len(candidates)} DLL(s). Inspecting exports...\n")

WANTED = {
    "CAENRFIDLib_Connect",
    "CAENRFIDLib_Disconnect",
    "CAENRFIDLib_InventoryTag",
    "CAENRFIDLib_EventInventoryTag",
    "CAENRFID_Connect",          # older SDK API
    "CAENRFID_Disconnect",
    "CAENRFID_InventoryTag",
}

loadable = []  # (dll_path, lib_handle, api_style)

for dll_path in candidates:
    dll_path = str(dll_path)
    arch, exports, imports = pe_info(dll_path)
    print(f"  {dll_path}")
    print(f"    Architecture : {arch}")
    print(f"    Total exports: {len(exports)}")

    found_wanted = [e for e in exports if e in WANTED]
    if found_wanted:
        print(f"    CAEN functions: {', '.join(found_wanted)}")

    # Show every CAENRFID-prefixed export (case-insensitive)
    caen_exports = sorted(e for e in exports if e.upper().startswith("CAENRFID"))
    if caen_exports:
        print(f"    All CAENRFID exports ({len(caen_exports)}):")
        for name in caen_exports:
            print(f"      {name}")
    elif exports:
        print(f"    First 12 exports: {', '.join(exports[:12])}")
    else:
        print("    (no named exports found — may use ordinals)")

    # Determine API style
    has_new = "CAENRFIDLib_Connect" in exports
    has_old = "CAENRFID_Connect" in exports

    print(f"    Trying to load...")
    dll_dir  = str(Path(dll_path).parent)
    orig_cwd = os.getcwd()
    lib      = None
    load_err  = None

    for attempt in ("add_dll_dir", "chdir", "plain"):
        try:
            if attempt == "add_dll_dir" and hasattr(os, "add_dll_directory"):
                os.add_dll_directory(dll_dir)
                lib = ctypes.WinDLL(dll_path)
            elif attempt == "chdir":
                os.chdir(dll_dir)
                lib = ctypes.WinDLL(dll_path)
                os.chdir(orig_cwd)
            else:
                lib = ctypes.WinDLL(dll_path)
            print(f"    Load: OK ({attempt})")
            break
        except (OSError, AttributeError) as e:
            load_err = e
            if os.getcwd() != orig_cwd:
                os.chdir(orig_cwd)

    if lib is None:
        print(f"    Load: FAILED — {load_err}")
        if imports:
            print(f"    This DLL imports from: {', '.join(imports)}")
            print("    Check that those DLLs (especially VC++ runtime) are installed.")
            missing = []
            for imp in imports:
                try:
                    ctypes.WinDLL(imp)
                except OSError:
                    missing.append(imp)
            if missing:
                print(f"    MISSING on this system: {', '.join(missing)}")
                if any("msvcp" in m.lower() or "vcruntime" in m.lower() for m in missing):
                    print("    → Install 'Visual C++ 2015-2022 Redistributable (x64)'")
                    print("      from https://aka.ms/vs/17/release/vc_redist.x64.exe")
        print()
        continue

    api = "new" if has_new else ("old" if has_old else "unknown")
    loadable.append((dll_path, lib, api))

    # Verify the functions ctypes can actually resolve
    for fn in ["CAENRFIDLib_Connect", "CAENRFID_Connect"]:
        try:
            getattr(lib, fn)
            print(f"    GetProcAddress({fn}): OK")
        except AttributeError:
            print(f"    GetProcAddress({fn}): not found")
    print()

if not loadable:
    print(SEP)
    print("No loadable DLLs found. Fix the issues above and re-run.")
    sys.exit(1)

# ── Try to connect using the best available DLL ───────────────────────────────
COM_PORT = "COM3"
print(SEP)
print(f"Attempting connection on {COM_PORT}...\n")


# ── CAEN SDK ctypes structures ─────────────────────────────────────────────────
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

print(f"CAENRFIDTag sizeof = {ctypes.sizeof(CAENRFIDTag)} bytes (expected 224 on x64)")

connected = False
tags_found = 0

for dll_path, lib, api_style in loadable:
    print(f"\nTrying: {dll_path}  (API: {api_style})")

        # easyReader API: CAENRFID_Init(int connType, void* param, int* handle)
    # connType 0 = RS232 (use for USB virtual COM port like COM3)
    # connType 3 = USB direct
    handle = ctypes.c_int32(-1)
    try:
        lib.CAENRFID_Init.restype  = ctypes.c_int
        lib.CAENRFID_Init.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32)]

        print(f"  Trying CAENRFID_Init RS232 on {COM_PORT}...")
        com = ctypes.c_char_p(COM_PORT.encode())
        ret = lib.CAENRFID_Init(0, com, ctypes.byref(handle))
        print(f"    returned {ret}, handle={handle.value}")

        if ret != 0:
            print(f"  Trying CAENRFID_Init USB direct...")
            handle = ctypes.c_int32(-1)
            ret = lib.CAENRFID_Init(3, None, ctypes.byref(handle))
            print(f"    returned {ret}, handle={handle.value}")

        if ret == 0:
            connected = True
        else:
            print(f"  Could not connect (last code: {ret})")
    except AttributeError:
        print("  CAENRFID_Init not available in this DLL")

    if not connected:
        continue

    # ── Run inventory ──────────────────────────────────────────────────────────
    print("\n  Running inventory — wave a tag over the reader now...")
    try:
        lib.CAENRFID_InventoryTag.restype  = ctypes.c_int
        lib.CAENRFID_InventoryTag.argtypes = [
            ctypes.c_int32,                       # Handle
            ctypes.c_char_p,                      # SourceName
            ctypes.c_char_p,                      # Mask (NULL = no filter)
            ctypes.c_ubyte,                       # MaskLength
            ctypes.c_ubyte,                       # MaskPosition
            ctypes.POINTER(ctypes.c_void_p),      # CAENRFIDTag** (DLL allocates)
            ctypes.POINTER(ctypes.c_uint16),      # TagCount*
        ]
    except AttributeError:
        print("  CAENRFID_InventoryTag not found")
        break

    for attempt in range(10):
        tags_ptr = ctypes.c_void_p(0)
        count    = ctypes.c_uint16(0)
        ret = lib.CAENRFID_InventoryTag(
            handle, b"Source_0", None, 0, 0,
            ctypes.byref(tags_ptr), ctypes.byref(count)
        )
        print(f"  Attempt {attempt+1}: ret={ret}  count={count.value}", end="")

        if ret == 0 and count.value > 0 and tags_ptr.value:
            array_type = CAENRFIDTag * count.value
            tags = ctypes.cast(tags_ptr, ctypes.POINTER(array_type)).contents
            print()
            for tag in tags:
                if tag.Length > 0:
                    epc = bytes(tag.ID[:tag.Length]).hex().upper()
                    print(f"    ✓  EPC={epc}  RSSI={tag.RSSI} dBm")
                    tags_found += 1
        else:
            print("  (no tags)" if ret in (0, -13) else f"  (error {ret})")
        time.sleep(0.5)

    # Free last tag allocation and disconnect
    try:
        lib.CAENRFID_FreeTagsMemory.restype  = ctypes.c_int
        lib.CAENRFID_FreeTagsMemory.argtypes = [ctypes.c_void_p]
    except AttributeError:
        pass

    try:
        lib.CAENRFID_End.restype  = ctypes.c_int
        lib.CAENRFID_End.argtypes = [ctypes.c_int32]
        lib.CAENRFID_End(handle)
        print("\n  Disconnected OK")
    except AttributeError:
        pass
    break

print(f"\n{SEP}")
print(f"Done — {tags_found} tag read(s) captured.")
if connected:
    print("Connection worked! If you got tag reads above, main.py is ready to use.")
else:
    print("Could not connect. Review the DLL load errors above.")
print(SEP)
