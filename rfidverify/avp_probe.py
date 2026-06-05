#!/usr/bin/env python3
"""
CAEN R1210IX — CAEN Light Protocol (AVP) probe.

The CAEN serial protocol uses a different frame format from the simple
1-byte command framing we tried before:

  STX(1) | LEN(2) | CMD(2) | RESULT(2) | AVPs... | ETX(1) | CRC(2)

  CMD    = 2-byte big-endian command code
  RESULT = 0x0000 for requests; non-zero in error responses
  LEN    = 2+2+len(AVPs)  (covers CMD+RESULT+AVP bytes)
  CRC    = CRC-16/CCITT-FALSE over LEN_HI..last_AVP_byte

AVP format:
  TYPE(2) | LENGTH(2) | VALUE[LENGTH bytes]

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

STX, ETX = 0x02, 0x03
SEP = "=" * 60


# ── helpers ───────────────────────────────────────────────────────────────────

def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
        crc &= 0xFFFF
    return crc


def build_frame(cmd: int, avps: bytes = b"") -> bytes:
    """CAEN Light Protocol frame: STX LEN(2) CMD(2) RESULT(2) AVPs ETX CRC(2)"""
    result = 0x0000      # always 0 for requests
    inner_payload = struct.pack(">HH", cmd, result) + avps
    len_field = struct.pack(">H", len(inner_payload))
    inner = len_field + inner_payload
    crc = struct.pack(">H", crc16(inner))
    return bytes([STX]) + inner + bytes([ETX]) + crc


def build_avp(avp_type: int, value: bytes) -> bytes:
    """AVP: TYPE(2) LENGTH(2) VALUE(n)"""
    return struct.pack(">HH", avp_type, len(value)) + value


def avp_string(s: str) -> bytes:
    return build_avp(0x0001, s.encode("ascii") + b"\x00")   # type 1 = string attribute


def open_port(baud=None, rtscts=False, set_rts=None, set_dtr=None):
    port_arg = PORT if PORT.startswith("\\\\.\\") else "\\\\.\\" + PORT
    try:
        s = serial.Serial(
            port=port_arg, baudrate=(baud or BAUD),
            bytesize=8, parity="N", stopbits=1,
            timeout=0.4, write_timeout=2.0,
            rtscts=rtscts, dsrdtr=False, xonxoff=False,
        )
        if set_rts is not None:
            s.rts = set_rts
        if set_dtr is not None:
            s.dtr = set_dtr
        return s
    except serial.SerialException as e:
        print(f"  Cannot open {port_arg}: {e}")
        return None


def drain(ser, window=1.5):
    buf = bytearray()
    deadline = time.monotonic() + window
    while time.monotonic() < deadline:
        w = ser.in_waiting
        if w:
            buf.extend(ser.read(w))
        else:
            time.sleep(0.03)
    return bytes(buf)


def try_cmd(ser, label, pkt, wait=1.5):
    ser.reset_input_buffer()
    ser.write(pkt)
    ser.flush()
    resp = drain(ser, wait)
    if resp:
        print(f"  *** RESPONSE to {label}: [{len(resp)}B] {resp.hex()}")
        # Try to parse as CAEN Light frame
        parse_response(resp, label)
        return True
    return False


def parse_response(data: bytes, label: str):
    """Try to parse a CAEN Light Protocol response frame."""
    i = 0
    while i < len(data):
        if data[i] != STX:
            i += 1
            continue
        if i + 6 >= len(data):
            break
        length = struct.unpack_from(">H", data, i + 1)[0]
        total = 1 + 2 + length + 1 + 2   # STX + LEN + payload + ETX + CRC
        if i + total > len(data):
            break
        etx_pos = i + 3 + length
        if data[etx_pos] != ETX:
            i += 1
            continue
        inner = data[i + 1 : etx_pos]   # LEN_HI LEN_LO CMD(2) RESULT(2) AVPs
        act_crc = struct.unpack_from(">H", data, etx_pos + 1)[0]
        exp_crc = crc16(inner)
        if act_crc != exp_crc:
            print(f"    [CRC mismatch: got {act_crc:04X} expected {exp_crc:04X}]")
            i += 1
            continue
        if length >= 4:
            cmd    = struct.unpack_from(">H", data, i + 3)[0]
            result = struct.unpack_from(">H", data, i + 5)[0]
            avp_data = data[i + 7 : etx_pos]
            print(f"    → cmd=0x{cmd:04X}  result=0x{result:04X}  avp_bytes={avp_data.hex()}")
            # Parse AVPs
            j = 0
            while j + 4 <= len(avp_data):
                a_type = struct.unpack_from(">H", avp_data, j)[0]
                a_len  = struct.unpack_from(">H", avp_data, j + 2)[0]
                a_val  = avp_data[j + 4 : j + 4 + a_len]
                print(f"      AVP type=0x{a_type:04X} len={a_len} val={a_val.hex()} "
                      f"({a_val[:20].decode('latin-1', errors='replace')!r})")
                j += 4 + a_len
        i += total


# ── command codes to probe ────────────────────────────────────────────────────
# CAEN Light Protocol command codes (from SDK headers and documentation).
# Trying a broad range to find which ones elicit a response.

CMDS = [
    # Most likely "ping" / info commands
    (0x0001, b"", "GetFirmwareRelease"),
    (0x0002, b"", "GetReaderInfo"),
    (0x0003, b"", "GetSources"),
    (0x0004, b"", "GetSourceConfiguration (no param)"),
    (0x0005, b"", "GetSourceNames"),
    (0x0006, b"", "InventoryTag (no param)"),
    (0x0007, b"", "SetPower / GetPower?"),
    (0x0008, b"", "cmd 0x0008"),
    (0x0009, b"", "cmd 0x0009"),
    (0x000A, b"", "cmd 0x000A"),
    (0x000B, b"", "cmd 0x000B"),
    (0x0010, b"", "cmd 0x0010"),
    (0x0020, b"", "cmd 0x0020"),
    (0x0100, b"", "cmd 0x0100"),
    (0x0101, b"", "cmd 0x0101"),
    (0x0200, b"", "cmd 0x0200"),
    (0x0201, b"", "cmd 0x0201"),
    (0x0300, b"", "cmd 0x0300"),
    # With Source_0 as first AVP string arg
    (0x0006,
     build_avp(0x0001, b"Source_0\x00"),
     "InventoryTag with Source_0 AVP"),
    # With source index 0 as uint16 AVP
    (0x0006,
     build_avp(0x0003, struct.pack(">H", 0)),
     "InventoryTag with source_idx=0 AVP"),
]


print(SEP)
print(f"CAEN Light Protocol (AVP) probe  |  {PORT}  @  {BAUD} baud")
print(SEP)
print()
print("Frame format: STX | LEN(2) | CMD(2) | RESULT(2) | AVPs | ETX | CRC(2)")
print("AVP format:   TYPE(2) | LENGTH(2) | VALUE")
print()

# ── 1. Listen for beacon (5 seconds) ─────────────────────────────────────────
print("[1] Listening for spontaneous data (5 s, RTS=True) ...")
s = open_port(set_rts=True, set_dtr=True)
if s is None:
    sys.exit(1)
time.sleep(0.4)
beacon = drain(s, 5.0)
if beacon:
    print(f"  Beacon received [{len(beacon)}B]: {beacon.hex()}")
    parse_response(beacon, "beacon")
else:
    print("  (silence)")
s.close()

# ── 2. Probe each command code ─────────────────────────────────────────────────
print()
print(f"[2] Probing {len(CMDS)} command codes (RTS=True, DTR=True) ...")
found = False
for cmd_code, avps, label in CMDS:
    frame = build_frame(cmd_code, avps)
    print(f"  cmd=0x{cmd_code:04X}  ({label})")
    print(f"    TX: {frame.hex()}")
    s = open_port(set_rts=True, set_dtr=True)
    if not s:
        continue
    time.sleep(0.3)
    if try_cmd(s, label, frame, wait=1.5):
        found = True
    s.close()
    if found:
        break

# ── 3. If nothing: try without RTS ────────────────────────────────────────────
if not found:
    print()
    print("[3] Retrying first 4 commands WITHOUT explicit RTS ...")
    for cmd_code, avps, label in CMDS[:4]:
        frame = build_frame(cmd_code, avps)
        s = open_port()
        if not s:
            continue
        time.sleep(0.2)
        if try_cmd(s, label, frame, wait=1.5):
            found = True
        s.close()
        if found:
            break

# ── 4. Baud sweep with cmd 0x0002 (GetReaderInfo) ─────────────────────────────
if not found:
    print()
    print("[4] Baud rate sweep with GetReaderInfo (0x0002), RTS=True ...")
    frame = build_frame(0x0002)
    for baud in [9600, 19200, 38400, 57600, 230400]:
        s = open_port(baud=baud, set_rts=True, set_dtr=True)
        if not s:
            continue
        time.sleep(0.2)
        print(f"  baud={baud}: TX {frame.hex()}")
        if try_cmd(s, f"0x0002 @{baud}", frame, wait=1.5):
            found = True
        s.close()
        if found:
            break
        print(f"    (no response at {baud})")

# ── summary ────────────────────────────────────────────────────────────────────
print()
print(SEP)
if found:
    print("Reader responded!  Paste the full output above.")
    print("We now know the correct command code and AVP encoding.")
else:
    print("No response to any CAEN Light Protocol frame.")
    print()
    print("This means one of:")
    print("  A) RTS handshake works but a different command code is needed.")
    print("     → Share SDK_5_0_0\\LightCLib\\SRC\\Protocol_Light.h (command codes).")
    print()
    print("  B) The reader needs specific hardware setup before accepting commands.")
    print("     → Run netprobe.py while tagstester is connected to see TCP ports.")
    print()
    print("  C) tagstester connects via TCP, not serial, to a CAEN middleware.")
    print("     → Check tagstester settings / config file for IP/port settings.")
print(SEP)
