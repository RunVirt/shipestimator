#!/usr/bin/env python3
"""
CAEN R1210IX — CAEN LightCLib Protocol probe (corrected).

Protocol from SDK source: IO_Light.c, Protocol_Light.h

Frame format — NO STX/ETX/CRC — pure binary, all big-endian:
  Request:
    TxVer=0x8001(2) | CmdID_seq(2) | VendorID=21336(4) | TotalLen(2) | AVPs...
  Response:
    TxVer=0x0001(2) | CmdID_seq(2) | VendorID=21336(4) | TotalLen(2) | AVPs...

AVP format:
    Reserved=0(2) | TotalLen(2)=(6+n) | Type(2) | Value(n bytes)

Usage:
  python avp_probe.py              # COM3, 115200 baud
  python avp_probe.py COM4
  python avp_probe.py COM3 9600
"""

import struct
import sys
import time

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM3"
BAUD = int(sys.argv[2]) if len(sys.argv) > 2 else 115200

# Protocol constants (from Protocol_Light.h)
CAEN_VENDOR  = 21336       # 0x5358
HEADER_LEN   = 10
AVP_HEADLEN  = 6
UART_ABORT   = 0xAB

# AVP types
AVP_COMMAND        = 0x01
AVP_RESULT_CODE    = 0x02
AVP_TAGIDLEN       = 0x0F
AVP_TIMESTAMP      = 0x10
AVP_TAGID          = 0x11
AVP_TAGTYPE        = 0x12
AVP_READPOINT_NAME = 0x22
AVP_BITMASK        = 0x67
AVP_READERINFO     = 0x76
AVP_RFREGULATION   = 0x77
AVP_RSSI           = 0x7A
AVP_GETFWRELEASE   = 0x5C
AVP_SOURCE_NAME    = 0xFB
AVP_POWER_GET      = 0x52
AVP_POWER          = 0x96

# Command values (go inside AVP_COMMAND, uint16)
CMD_INVENTORY    = 0x13
CMD_GETFWRELEASE = 0x7C
CMD_GETRDRINFO   = 0x9E
CMD_GETPOWER     = 0x73
CMD_GETRFREGULATION = 0xA2

# Inventory flags (go inside AVP_BITMASK, uint16)
FLAG_RSSI      = 0x0001
FLAG_FRAMED    = 0x0002
FLAG_CONTINUOS = 0x0004
FLAG_COMPACT   = 0x0008

SEP = "=" * 62
_cmd_seq = 0

AVP_TYPE_NAMES = {
    0x01: "COMMAND",
    0x02: "RESULT_CODE",
    0x0F: "TAGIDLEN",
    0x10: "TIMESTAMP",
    0x11: "TAGID",
    0x12: "TAGTYPE",
    0x22: "READPOINT_NAME",
    0x52: "POWER_GET",
    0x5C: "GETFWRELEASE",
    0x67: "BITMASK",
    0x76: "READERINFO",
    0x77: "RFREGULATION",
    0x7A: "RSSI",
    0x96: "POWER",
    0xFB: "SOURCE_NAME",
}


# ─── Frame builders ──────────────────────────────────────────────────────────

def _u16(v): return struct.pack(">H", v & 0xFFFF)
def _u32(v): return struct.pack(">I", v & 0xFFFFFFFF)
def _gu16(b, off=0): return struct.unpack_from(">H", b, off)[0]
def _gu32(b, off=0): return struct.unpack_from(">I", b, off)[0]


def _avp_u16(avp_type, value):
    return _u16(0) + _u16(AVP_HEADLEN + 2) + _u16(avp_type) + _u16(value)


def _avp_str(avp_type, s):
    b = s.encode("ascii") + b"\x00"
    return _u16(0) + _u16(AVP_HEADLEN + len(b)) + _u16(avp_type) + b


def build_frame(avps: bytes) -> bytes:
    global _cmd_seq
    total = HEADER_LEN + len(avps)
    hdr = (_u16(0x8001) + _u16(_cmd_seq) + _u32(CAEN_VENDOR) + _u16(total))
    _cmd_seq = (_cmd_seq + 1) & 0xFFFF
    return hdr + avps


def frame_getrdrinfo() -> bytes:
    return build_frame(_avp_u16(AVP_COMMAND, CMD_GETRDRINFO))


def frame_getfwrelease() -> bytes:
    return build_frame(_avp_u16(AVP_COMMAND, CMD_GETFWRELEASE))


def frame_getpower() -> bytes:
    return build_frame(_avp_u16(AVP_COMMAND, CMD_GETPOWER))


def frame_getrfregulation() -> bytes:
    return build_frame(_avp_u16(AVP_COMMAND, CMD_GETRFREGULATION))


def frame_inventory(source="Source_0", flags=FLAG_RSSI) -> bytes:
    avps = _avp_u16(AVP_COMMAND, CMD_INVENTORY) + _avp_str(AVP_SOURCE_NAME, source)
    if flags:
        avps += _avp_u16(AVP_BITMASK, flags)
    return build_frame(avps)


# ─── Serial helpers ───────────────────────────────────────────────────────────

def open_port(baud=None, rts=True, dtr=True):
    arg = PORT if PORT.startswith("\\\\.\\") else "\\\\.\\" + PORT
    try:
        s = serial.Serial(arg, baudrate=(baud or BAUD),
                          bytesize=8, parity="N", stopbits=1,
                          timeout=0.1, write_timeout=2.0,
                          rtscts=False, dsrdtr=False, xonxoff=False)
        s.rts = rts
        s.dtr = dtr
        return s
    except serial.SerialException as e:
        print(f"  Cannot open {arg}: {e}")
        return None


def read_exactly(ser, n, deadline):
    buf = bytearray()
    while len(buf) < n:
        if time.monotonic() >= deadline:
            return None
        chunk = ser.read(n - len(buf))
        if chunk:
            buf.extend(chunk)
    return bytes(buf)


# ─── Response parser ──────────────────────────────────────────────────────────

def parse_avps(data: bytes):
    """Parse AVPs from raw bytes, return list of (type, value_bytes)."""
    result = []
    pos = 0
    while pos + AVP_HEADLEN <= len(data):
        reserved = _gu16(data, pos)
        total_len = _gu16(data, pos + 2)
        avp_type  = _gu16(data, pos + 4)
        val_len   = total_len - AVP_HEADLEN
        if reserved != 0 or val_len < 0 or pos + total_len > len(data):
            break
        val = data[pos + AVP_HEADLEN : pos + total_len]
        result.append((avp_type, val))
        pos += total_len
    return result


def decode_avp_val(avp_type, val):
    if len(val) == 2:
        u = _gu16(val)
        s = struct.unpack(">h", val)[0]
        name = AVP_TYPE_NAMES.get(avp_type, f"0x{avp_type:02X}")
        if avp_type == AVP_RSSI:
            return f"{s} dBm (raw 0x{u:04X})"
        if avp_type == AVP_RESULT_CODE:
            return f"{u} ({'OK' if u == 0 else 'ERROR'})"
        return f"0x{u:04X} ({u})"
    if len(val) == 4:
        u = _gu32(val)
        return f"0x{u:08X} ({u})"
    try:
        text = val.rstrip(b"\x00").decode("ascii")
        return repr(text)
    except Exception:
        return val.hex()


def print_avps(avps):
    for avp_type, val in avps:
        name = AVP_TYPE_NAMES.get(avp_type, f"type=0x{avp_type:02X}")
        decoded = decode_avp_val(avp_type, val)
        print(f"      AVP {name}: {decoded}")


def try_command(ser, label, frame, timeout=3.0):
    """Send frame, read CAEN Light response, print results. Returns response bytes or None."""
    sent_cmdid = _gu16(frame, 2)
    ser.reset_input_buffer()
    print(f"  TX [{len(frame)}B]: {frame.hex()}")
    ser.write(frame)
    ser.flush()

    deadline = time.monotonic() + timeout
    # Read 10-byte header
    hdr = read_exactly(ser, HEADER_LEN, deadline)
    if not hdr:
        print(f"  → No response (timeout waiting for header)")
        return None

    print(f"  RX header [{len(hdr)}B]: {hdr.hex()}")
    txver     = _gu16(hdr, 0)
    resp_cid  = _gu16(hdr, 2)
    vendor    = _gu32(hdr, 4)
    length    = _gu16(hdr, 8)

    print(f"     TxVer=0x{txver:04X}  CmdID={resp_cid}  VendorID=0x{vendor:08X}  TotalLen={length}")

    # Validate
    if txver != 0x0001:
        print(f"  ✗ Bad TxVer: expected 0x0001, got 0x{txver:04X}")
        return None
    if vendor != CAEN_VENDOR:
        print(f"  ✗ Bad VendorID: expected 0x{CAEN_VENDOR:08X}=21336, got 0x{vendor:08X}")
        return None
    if resp_cid != sent_cmdid:
        print(f"  ✗ CmdID mismatch: sent {sent_cmdid}, got {resp_cid}")
        return None
    if length < HEADER_LEN:
        print(f"  ✗ TotalLen {length} < {HEADER_LEN}")
        return None

    # Read rest of payload
    rest_len = length - HEADER_LEN
    if rest_len > 0:
        rest = read_exactly(ser, rest_len, deadline)
        if rest is None:
            print(f"  ✗ Truncated: needed {rest_len} more bytes but timed out")
            return None
        full = hdr + rest
    else:
        full = hdr

    print(f"  ✓ Valid response [{len(full)}B]: {full.hex()}")
    avps = parse_avps(full[HEADER_LEN:])
    print_avps(avps)
    return full


def listen_passively(ser, duration=5.0):
    buf = bytearray()
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        chunk = ser.read(256)
        if chunk:
            buf.extend(chunk)
    return bytes(buf)


# ─── Main probe ───────────────────────────────────────────────────────────────

print(SEP)
print(f"CAEN LightCLib Protocol probe  |  {PORT}  @  {BAUD} baud")
print(f"CAEN_VENDOR=21336=0x5358, HEADER=10B, NO STX/ETX/CRC")
print(SEP)
print()

# ── 1. Listen passively ───────────────────────────────────────────────────────
print("[1] Opening port + listening passively 3 s (RTS=1 DTR=1) ...")
s = open_port()
if s is None:
    sys.exit(1)
time.sleep(0.3)
s.reset_input_buffer()
beacon = listen_passively(s, 3.0)
if beacon:
    print(f"  Spontaneous data [{len(beacon)}B]: {beacon.hex()}")
    if len(beacon) >= HEADER_LEN:
        txv = _gu16(beacon, 0)
        vid = _gu32(beacon, 4)
        print(f"  TxVer=0x{txv:04X}  VendorID=0x{vid:08X}")
else:
    print("  (silence — expected, reader only responds to commands)")

# Send UART_ABORT byte first to cancel any pending framed inventory
print()
print("[1b] Sending UART_ABORT (0xAB) to cancel any pending inventory ...")
s.write(bytes([UART_ABORT]))
s.flush()
time.sleep(0.5)
s.reset_input_buffer()
print("  Done.")
s.close()

# ── 2. GetReaderInfo ──────────────────────────────────────────────────────────
print()
print("[2] CMD_GETRDRINFO (0x9E) — Reader model + serial number ...")
s = open_port()
if s:
    f = frame_getrdrinfo()
    result = try_command(s, "GETRDRINFO", f, timeout=5.0)
    s.close()
    if result:
        print("  *** GetReaderInfo succeeded — reader is communicating! ***")

# ── 3. GetFirmwareRelease ─────────────────────────────────────────────────────
print()
print("[3] CMD_GETFWRELEASE (0x7C) — Firmware version ...")
s = open_port()
if s:
    f = frame_getfwrelease()
    result = try_command(s, "GETFWRELEASE", f, timeout=5.0)
    s.close()

# ── 4. GetPower ───────────────────────────────────────────────────────────────
print()
print("[4] CMD_GETPOWER (0x73) — RF power in mW ...")
s = open_port()
if s:
    f = frame_getpower()
    result = try_command(s, "GETPOWER", f, timeout=5.0)
    s.close()

# ── 5. Inventory with RSSI ────────────────────────────────────────────────────
print()
print("[5] CMD_INVENTORY (0x13) on Source_0 with RSSI flag (10 s timeout) ...")
print("    Wave some RFID tags over the antenna now ...")
s = open_port()
if s:
    f = frame_inventory("Source_0", FLAG_RSSI)
    result = try_command(s, "INVENTORY", f, timeout=10.0)
    if result:
        avps = parse_avps(result[HEADER_LEN:])
        tags = []
        i = 0
        while i < len(avps):
            if avps[i][0] == AVP_TAGID:
                epc = avps[i][1].hex().upper()
                rssi = None
                if i + 1 < len(avps) and avps[i + 1][0] == AVP_RSSI:
                    rssi = struct.unpack(">h", avps[i + 1][1])[0]
                    i += 1
                tags.append((epc, rssi))
            i += 1
        print(f"  Tags found: {len(tags)}")
        for epc, rssi in tags:
            print(f"    EPC={epc}  RSSI={rssi} dBm")
    s.close()

# ── 6. Baud rate sweep if nothing worked ─────────────────────────────────────
print()
print("[6] Baud rate sweep for GetReaderInfo (in case default baud is not 115200) ...")
for baud in [9600, 19200, 38400, 57600, 230400, 460800]:
    print(f"  baud={baud}: ", end="", flush=True)
    s = open_port(baud=baud)
    if not s:
        continue
    time.sleep(0.2)
    f = frame_getrdrinfo()
    sent_cid = _gu16(f, 2)
    s.reset_input_buffer()
    s.write(f)
    s.flush()
    deadline = time.monotonic() + 2.0
    hdr = read_exactly(s, HEADER_LEN, deadline)
    s.close()
    if hdr:
        txv = _gu16(hdr, 0)
        vid = _gu32(hdr, 4)
        cid = _gu16(hdr, 2)
        if txv == 0x0001 and vid == CAEN_VENDOR and cid == sent_cid:
            print(f"RESPONSE! Valid header: {hdr.hex()}")
            print(f"  *** Correct baud rate is {baud} ***")
            break
        else:
            print(f"data but invalid ({hdr.hex()})")
    else:
        print("(silence)")

print()
print(SEP)
print("Probe complete.")
print(SEP)
