#!/usr/bin/env python3
"""
Check what hardware signals the CAEN reader is asserting on COM3.
Complete silence to all probes often means CTS is low and the
Windows CDC driver is silently blocking our writes.

Usage:
  python modem_check.py              # COM3
  python modem_check.py COM4
"""

import ctypes
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM3"
SEP = "=" * 60

MS_CTS_ON  = 0x0010
MS_DSR_ON  = 0x0020
MS_RING_ON = 0x0040
MS_RLSD_ON = 0x0080   # DCD / Carrier Detect

k32 = ctypes.windll.kernel32


def read_modem_status(handle):
    status = ctypes.c_ulong(0)
    ok = k32.GetCommModemStatus(ctypes.c_void_p(handle), ctypes.byref(status))
    if not ok:
        return None
    v = status.value
    return {
        "CTS":  bool(v & MS_CTS_ON),
        "DSR":  bool(v & MS_DSR_ON),
        "RING": bool(v & MS_RING_ON),
        "DCD":  bool(v & MS_RLSD_ON),
        "raw":  f"0x{v:08X}",
    }


port_arg = PORT if PORT.startswith("\\\\.\\") else "\\\\.\\" + PORT

print(SEP)
print(f"CAEN modem status check  |  {PORT}")
print(SEP)

# ── Test 1: Default open (no RTS/DTR) ─────────────────────────────────────────
print("\n[1] Open with no RTS / no DTR:")
try:
    s = serial.Serial(port_arg, 115200, timeout=1)
    s.rts = False
    s.dtr = False
    time.sleep(0.3)
    ms = read_modem_status(s.fileno() if hasattr(s, 'fileno') else
                           ctypes.c_void_p(int(s._port_handle)).value)
    # pyserial on Windows stores handle differently
    h = s._port_handle if hasattr(s, '_port_handle') else None
    if h is None:
        import win32file
        h = s.hComPort
    ms = read_modem_status(int(h))
    print(f"  CTS={ms['CTS']}  DSR={ms['DSR']}  RING={ms['RING']}  DCD={ms['DCD']}  ({ms['raw']})")
    print(f"  in_waiting={s.in_waiting}")
    s.close()
except Exception as e:
    print(f"  Error: {e}")

# ── Test 2: RTS=True, DTR=True ─────────────────────────────────────────────────
print("\n[2] Open with RTS=True, DTR=True, wait 1s:")
try:
    s = serial.Serial(port_arg, 115200, timeout=1)
    s.rts = True
    s.dtr = True
    time.sleep(1.0)
    h = s._port_handle
    ms = read_modem_status(int(h))
    print(f"  CTS={ms['CTS']}  DSR={ms['DSR']}  RING={ms['RING']}  DCD={ms['DCD']}  ({ms['raw']})")
    print(f"  in_waiting={s.in_waiting}")
    if s.in_waiting:
        data = s.read(s.in_waiting)
        print(f"  Spontaneous data: {data.hex()}")
    s.close()
except Exception as e:
    print(f"  Error: {e}")

# ── Test 3: Monitor CTS changes for 5 seconds ─────────────────────────────────
print("\n[3] Monitoring CTS changes for 5s (RTS=True) ...")
try:
    s = serial.Serial(port_arg, 115200, timeout=0.1)
    s.rts = True
    s.dtr = True
    h = s._port_handle
    prev_cts = None
    deadline = time.monotonic() + 5.0
    samples = 0
    while time.monotonic() < deadline:
        ms = read_modem_status(int(h))
        cts = ms['CTS']
        if cts != prev_cts:
            t = 5.0 - (deadline - time.monotonic())
            print(f"  t={t:.2f}s  CTS changed: {prev_cts} → {cts}")
            prev_cts = cts
        if s.in_waiting:
            data = s.read(s.in_waiting)
            print(f"  t=?  data received: {data.hex()}")
        time.sleep(0.05)
        samples += 1
    print(f"  Final: CTS={ms['CTS']}  DSR={ms['DSR']}  (sampled {samples} times)")
    s.close()
except Exception as e:
    print(f"  Error: {e}")

# ── Test 4: Toggle RTS and watch CTS ──────────────────────────────────────────
print("\n[4] Toggling RTS and watching for CTS response:")
try:
    s = serial.Serial(port_arg, 115200, timeout=0.1)
    h = s._port_handle
    for rts_val in [False, True, False, True]:
        s.rts = rts_val
        time.sleep(0.5)
        ms = read_modem_status(int(h))
        print(f"  RTS={rts_val}  →  CTS={ms['CTS']}  DSR={ms['DSR']}  in_waiting={s.in_waiting}")
    s.close()
except Exception as e:
    print(f"  Error: {e}")

print()
print(SEP)
print("INTERPRETATION:")
print("  CTS=False always  → Reader isn't ready; CDC driver may block writes silently")
print("  CTS=True          → Driver allows writes; protocol or command code is wrong")
print("  CTS changes after RTS toggle → Reader responds to handshake signals")
print(SEP)
