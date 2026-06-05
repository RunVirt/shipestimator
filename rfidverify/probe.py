#!/usr/bin/env python3
"""
CAEN R1210IX — serial protocol probe / raw traffic dump  (v2).

Tests every likely protocol variant and hardware-handshaking combination
until the reader responds.  Paste the full output if nothing works.

Usage:
  python probe.py              # COM3, 115200 baud
  python probe.py COM4
  python probe.py COM3 9600
"""

import struct
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM3"
BAUD = int(sys.argv[2]) if len(sys.argv) > 2 else 115200

SEP = "=" * 60


# ─── helpers ──────────────────────────────────────────────────────────────────

def crc16(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
        crc &= 0xFFFF
    return crc

def frame_stx_etx(cmd, data=b""):
    """Standard CAEN frame: STX LEN_HI LEN_LO CMD DATA ETX CRC_HI CRC_LO"""
    payload = bytes([cmd]) + data
    inner   = struct.pack(">H", len(payload)) + payload
    return bytes([0x02]) + inner + bytes([0x03]) + struct.pack(">H", crc16(inner))

def frame_no_wrap(cmd, data=b""):
    """Alternative: LEN_HI LEN_LO CMD DATA CRC_HI CRC_LO  (no STX/ETX)"""
    payload = bytes([cmd]) + data
    inner   = struct.pack(">H", len(payload)) + payload
    return inner + struct.pack(">H", crc16(inner))

def frame_bare(cmd, data=b""):
    """Bare: CMD DATA (no length, no CRC — for detecting single-byte triggers)"""
    return bytes([cmd]) + data

def open_port(baud=None, rtscts=False, set_rts=None, set_dtr=None):
    port_arg = PORT if PORT.startswith("\\\\.\\") else "\\\\.\\" + PORT
    try:
        s = serial.Serial(
            port=port_arg, baudrate=(baud or BAUD),
            bytesize=8, parity="N", stopbits=1,
            timeout=0.3, write_timeout=2.0,
            rtscts=rtscts, dsrdtr=False,
            xonxoff=False,
        )
        if set_rts is not None:
            s.rts = set_rts
        if set_dtr is not None:
            s.dtr = set_dtr
        return s
    except serial.SerialException as e:
        print(f"  Cannot open {port_arg}: {e}")
        return None

def drain(ser, window=1.0):
    buf = bytearray()
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        waiting = ser.in_waiting
        if waiting:
            buf.extend(ser.read(waiting))
        else:
            time.sleep(0.02)
    return bytes(buf)

def try_cmd(ser, label, pkt, wait=1.5):
    ser.reset_input_buffer()
    ser.write(pkt)
    ser.flush()
    resp = drain(ser, wait)
    if resp:
        print(f"  *** RESPONSE to {label}: [{len(resp)}B] {resp.hex()}")
        try:
            txt = resp.decode("latin-1")
            if sum(32 <= ord(c) < 127 for c in txt) > len(txt) // 2:
                print(f"      ASCII: {repr(txt)}")
        except Exception:
            pass
        return True
    return False


print(SEP)
print(f"CAEN R1210IX serial probe v2  |  {PORT}  @  {BAUD} baud")
print(SEP)


# ── 1. Listen for spontaneous broadcast (no commands sent) ────────────────────
print("\n[1] Listening for spontaneous data from reader (5 s) ...")
s = open_port()
if s is None:
    sys.exit(1)

time.sleep(0.5)          # let CDC enumeration settle
beacon = drain(s, 5.0)
if beacon:
    print(f"  Beacon received [{len(beacon)}B]: {beacon.hex()}")
else:
    print("  (silence — reader does not self-announce)")
s.close()


# ── 2. Standard probe: no flow control, RTS not forced ────────────────────────
print(f"\n[2] Standard frames (STX/ETX/CRC16) — no explicit flow control ...")
s = open_port()
found = False
if s:
    for desc, pkt in [
        ("READER_INFO 0x01",      frame_stx_etx(0x01)),
        ("INVENTORY   0x03",      frame_stx_etx(0x03)),
        ("INVENTORY   0x03+src0", frame_stx_etx(0x03, b"\x00")),
        ("INVENTORY   0x03+src_name", frame_stx_etx(0x03, b"\x08Source_0")),
    ]:
        if try_cmd(s, desc, pkt):
            found = True
            break
    s.close()


# ── 3. Same commands with RTS=True ────────────────────────────────────────────
if not found:
    print(f"\n[3] Same frames with RTS asserted (ser.rts = True) ...")
    s = open_port(set_rts=True, set_dtr=True)
    if s:
        time.sleep(0.3)   # give reader time to see RTS go high
        for desc, pkt in [
            ("READER_INFO 0x01",      frame_stx_etx(0x01)),
            ("INVENTORY   0x03",      frame_stx_etx(0x03)),
            ("INVENTORY   0x03+src0", frame_stx_etx(0x03, b"\x00")),
        ]:
            if try_cmd(s, desc, pkt):
                found = True
                break
        s.close()


# ── 4. Hardware flow control (rtscts=True) ────────────────────────────────────
if not found:
    print(f"\n[4] Hardware flow control: rtscts=True ...")
    s = open_port(rtscts=True)
    if s:
        time.sleep(0.3)
        for desc, pkt in [
            ("READER_INFO 0x01",      frame_stx_etx(0x01)),
            ("INVENTORY   0x03",      frame_stx_etx(0x03)),
        ]:
            if try_cmd(s, desc, pkt):
                found = True
                break
        s.close()


# ── 5. Alternative frame format: no STX/ETX ──────────────────────────────────
if not found:
    print(f"\n[5] Alternative frame (no STX/ETX): LEN CMD CRC ...")
    s = open_port(set_rts=True)
    if s:
        time.sleep(0.2)
        for desc, pkt in [
            ("READER_INFO 0x01 (no wrap)", frame_no_wrap(0x01)),
            ("INVENTORY   0x03 (no wrap)", frame_no_wrap(0x03)),
        ]:
            if try_cmd(s, desc, pkt):
                found = True
                break
        s.close()


# ── 6. Bare single-byte commands ──────────────────────────────────────────────
if not found:
    print(f"\n[6] Bare single-byte commands (no framing at all) ...")
    s = open_port(set_rts=True)
    if s:
        time.sleep(0.2)
        for b in [0x01, 0x03, 0x00, 0x80, 0xFF, 0xAA, 0x0D, 0x0A]:
            if try_cmd(s, f"bare 0x{b:02x}", bytes([b]), wait=0.8):
                found = True
                break
        s.close()


# ── 7. Baud rate sweep (READER_INFO with RTS, STX/ETX frame) ─────────────────
if not found:
    print(f"\n[7] Baud rate sweep (READER_INFO cmd=0x01, RTS=True) ...")
    pkt = frame_stx_etx(0x01)
    for baud in [9600, 19200, 38400, 57600, 115200, 230400, 921600]:
        if baud == BAUD:
            continue
        s = open_port(baud=baud, set_rts=True)
        if s:
            time.sleep(0.2)
            resp = try_cmd(s, f"baud={baud}", pkt, wait=1.2)
            s.close()
            if resp:
                found = True
                print(f"  *** Reader responds at {baud} baud!")
                break
        print(f"  {baud}: no response")


# ── 8. Long listen with RTS=True and repeated pings ──────────────────────────
if not found:
    print(f"\n[8] Extended test: RTS=True, send READER_INFO every second for 10 s ...")
    s = open_port(set_rts=True)
    if s:
        pkt = frame_stx_etx(0x01)
        for i in range(10):
            s.reset_input_buffer()
            s.write(pkt)
            s.flush()
            time.sleep(1.0)
            waiting = s.in_waiting
            if waiting:
                raw = s.read(waiting)
                print(f"  t+{i+1}s: [{len(raw)}B] {raw.hex()}")
                found = True
                break
            else:
                print(f"  t+{i+1}s: (silent)")
        s.close()


# ── summary ───────────────────────────────────────────────────────────────────
print()
print(SEP)
if found:
    print("Reader responded!  Copy the RX hex lines above.")
else:
    print("Still no response after all tests.")
    print()
    print("Next steps:")
    print("  A) Download the LightCLib source from OneDrive:")
    print("     File Explorer → SDK_5_0_0\\LightCLib\\SRC\\")
    print("     Select all → right-click → 'Always keep on this device'")
    print("     Paste Protocol_Light.h content in chat.")
    print()
    print("  B) Install CAEN R2RF / RFID Lab from caen.it — this provides")
    print("     the CAEN USB driver (fixes -11 error) and a working DLL.")
    print()
    print("  C) Run Wireshark with USBPcap to capture USB traffic while")
    print("     CAEN RFID Lab talks to the reader, then share the capture.")
print(SEP)
