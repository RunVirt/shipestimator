#!/usr/bin/env python3
"""
CAEN R1210IX Smart Tray — pure-Python serial reader using CAEN LightCLib protocol.

Implements the exact protocol from SDK source files:
  SDK_5_0_0/LightCLib/SRC/IO_Light.c + Protocol_Light.h

Frame format (all big-endian, NO STX/ETX/CRC):
  Request:  TxVer=0x8001(2) | CmdID_seq(2) | VendorID=21336(4) | TotalLen(2) | AVPs
  Response: TxVer=0x0001(2) | CmdID_seq(2) | VendorID=21336(4) | TotalLen(2) | AVPs

AVP: Reserved=0(2) | TotalLen=6+n(2) | Type(2) | Value(n)
"""

import logging
import struct
import threading
import time
from typing import Callable, Optional

import serial

logger = logging.getLogger(__name__)

# Protocol constants
CAEN_VENDOR  = 21336       # 0x00005358
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
AVP_RSSI           = 0x7A
AVP_GETFWRELEASE   = 0x5C
AVP_SOURCE_NAME    = 0xFB

# Command values (uint16 inside AVP_COMMAND)
CMD_INVENTORY    = 0x13
CMD_GETFWRELEASE = 0x7C
CMD_GETRDRINFO   = 0x9E

# Inventory flags (uint16 inside AVP_BITMASK)
FLAG_RSSI      = 0x0001
FLAG_FRAMED    = 0x0002
FLAG_CONTINUOS = 0x0004


def _u16(v): return struct.pack(">H", v & 0xFFFF)
def _u32(v): return struct.pack(">I", v & 0xFFFFFFFF)
def _gu16(b, off=0): return struct.unpack_from(">H", b, off)[0]
def _gu32(b, off=0): return struct.unpack_from(">I", b, off)[0]


# ─── Frame builders ───────────────────────────────────────────────────────────

def _avp_u16(avp_type, value):
    return _u16(0) + _u16(AVP_HEADLEN + 2) + _u16(avp_type) + _u16(value)


def _avp_str(avp_type, s):
    b = s.encode("ascii") + b"\x00"
    return _u16(0) + _u16(AVP_HEADLEN + len(b)) + _u16(avp_type) + b


class _Seq:
    def __init__(self): self.n = 0
    def next(self):
        v = self.n; self.n = (self.n + 1) & 0xFFFF; return v


def _build_frame(avps: bytes, seq: _Seq) -> bytes:
    total = HEADER_LEN + len(avps)
    cid = seq.next()
    hdr = _u16(0x8001) + _u16(cid) + _u32(CAEN_VENDOR) + _u16(total)
    return hdr + avps, cid


def make_getrdrinfo(seq): return _build_frame(_avp_u16(AVP_COMMAND, CMD_GETRDRINFO), seq)
def make_getfwrelease(seq): return _build_frame(_avp_u16(AVP_COMMAND, CMD_GETFWRELEASE), seq)


def make_inventory(seq, source="Source_0"):
    avps = (_avp_u16(AVP_COMMAND, CMD_INVENTORY) +
            _avp_str(AVP_SOURCE_NAME, source) +
            _avp_u16(AVP_BITMASK, FLAG_RSSI))
    return _build_frame(avps, seq)


# ─── Serial I/O helpers ───────────────────────────────────────────────────────

def _read_exactly(ser: serial.Serial, n: int, deadline: float) -> Optional[bytes]:
    buf = bytearray()
    while len(buf) < n:
        remaining = n - len(buf)
        if time.monotonic() >= deadline:
            return None
        chunk = ser.read(remaining)
        if chunk:
            buf.extend(chunk)
    return bytes(buf)


def _send_receive(ser: serial.Serial, frame: bytes, expected_cid: int,
                  timeout: float = 5.0) -> Optional[bytes]:
    """Send frame, read and validate response. Returns full response bytes or None."""
    deadline = time.monotonic() + timeout
    try:
        ser.reset_input_buffer()
        ser.write(frame)
        ser.flush()

        hdr = _read_exactly(ser, HEADER_LEN, deadline)
        if not hdr:
            return None

        txver  = _gu16(hdr, 0)
        cid    = _gu16(hdr, 2)
        vendor = _gu32(hdr, 4)
        length = _gu16(hdr, 8)

        if txver != 0x0001 or vendor != CAEN_VENDOR or cid != expected_cid:
            logger.debug("Bad response header: txver=0x%04X cid=%d vendor=0x%08X",
                         txver, cid, vendor)
            return None
        if length < HEADER_LEN:
            return None

        rest_n = length - HEADER_LEN
        if rest_n == 0:
            return hdr

        rest = _read_exactly(ser, rest_n, deadline)
        if rest is None:
            return None
        return hdr + rest

    except serial.SerialException as exc:
        logger.error("Serial error in send_receive: %s", exc)
        return None


# ─── AVP parser ───────────────────────────────────────────────────────────────

def _parse_avps(data: bytes):
    """Parse AVPs, return list of (type, value_bytes)."""
    result = []
    pos = 0
    while pos + AVP_HEADLEN <= len(data):
        reserved  = _gu16(data, pos)
        total_len = _gu16(data, pos + 2)
        avp_type  = _gu16(data, pos + 4)
        val_len   = total_len - AVP_HEADLEN
        if reserved != 0 or val_len < 0 or pos + total_len > len(data):
            break
        result.append((avp_type, data[pos + AVP_HEADLEN: pos + total_len]))
        pos += total_len
    return result


def _extract_tags(avps):
    """
    Yield (epc_hex_upper, rssi_int16) from a list of AVPs.

    Non-framed inventory AVP order per tag:
      SOURCE_NAME, READPOINT_NAME, TIMESTAMP, TAGTYPE, TAGIDLEN, TAGID [, RSSI]
    followed by RESULT_CODE at the end.
    """
    tags = []
    i = 0
    while i < len(avps):
        avp_type, val = avps[i]
        if avp_type == AVP_TAGID:
            epc = val.hex().upper()
            rssi = 0
            if i + 1 < len(avps) and avps[i + 1][0] == AVP_RSSI:
                rssi = struct.unpack(">h", avps[i + 1][1])[0]
                i += 1
            tags.append((epc, rssi))
        i += 1
    return tags


# ─── Main reader class ────────────────────────────────────────────────────────

class CaenSerialReader:
    """
    CAEN R1210IX reader over serial using the CAEN LightCLib protocol.

    Public API:
      connect() → bool
      disconnect()
      start_inventory(callback)   callback(epc: str, rssi: int, err: int)
      stop_inventory()
      connected  (property)
    """

    BAUD      = 115200
    POLL_GAP  = 0.05          # seconds between inventory polls
    INV_TIMEOUT = 8.0         # seconds to wait for inventory response

    def __init__(self, port: str, power: int = 30, debug: bool = False):
        self.port  = port
        self.power = power
        self.debug = debug
        self._ser: Optional[serial.Serial] = None
        self._seq = _Seq()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._cb: Optional[Callable] = None
        self._lock = threading.Lock()

    @property
    def connected(self) -> bool:
        return self._ser is not None and self._ser.is_open

    # ── connect / disconnect ─────────────────────────────────────────────────

    def connect(self) -> bool:
        port_arg = self.port
        if not port_arg.startswith("\\\\.\\") and port_arg.upper().startswith("COM"):
            port_arg = "\\\\.\\" + port_arg

        try:
            self._ser = serial.Serial(
                port=port_arg,
                baudrate=self.BAUD,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=0.1,
                write_timeout=2.0,
                xonxoff=False,
                rtscts=False,
            )
            self._ser.rts = True
            self._ser.dtr = True
            time.sleep(0.3)
            self._ser.reset_input_buffer()
            logger.info("Opened %s at %d baud", self.port, self.BAUD)
        except serial.SerialException as exc:
            logger.error("Cannot open %s: %s", self.port, exc)
            return False

        # Cancel any pending framed inventory from a previous session
        try:
            self._ser.write(bytes([UART_ABORT]))
            self._ser.flush()
            time.sleep(0.3)
            self._ser.reset_input_buffer()
        except Exception:
            pass

        # Probe reader
        frame, cid = make_getrdrinfo(self._seq)
        if self.debug:
            logger.debug("TX GetReaderInfo: %s", frame.hex())
        resp = _send_receive(self._ser, frame, cid, timeout=4.0)
        if resp is not None:
            avps = _parse_avps(resp[HEADER_LEN:])
            for atype, val in avps:
                if atype == AVP_READERINFO:
                    try:
                        info = val.rstrip(b"\x00").decode("ascii")
                        logger.info("Reader: %s", info)
                    except Exception:
                        pass
            logger.info("Reader connected (CAEN LightCLib protocol)")
            return True

        # Retry GetFirmwareRelease as fallback
        frame2, cid2 = make_getfwrelease(self._seq)
        resp2 = _send_receive(self._ser, frame2, cid2, timeout=4.0)
        if resp2 is not None:
            logger.info("Reader connected (firmware query OK)")
            return True

        logger.warning(
            "No response to GetReaderInfo on %s. "
            "Reader may be connected but not responding — "
            "inventory will still be attempted.",
            self.port
        )
        return True   # Keep open; inventory may still work

    def disconnect(self):
        self._running = False
        if self._ser and self._ser.is_open:
            try:
                self._ser.write(bytes([UART_ABORT]))
                self._ser.flush()
            except Exception:
                pass
            try:
                self._ser.close()
            except Exception:
                pass
        self._ser = None
        logger.info("Disconnected from %s", self.port)

    # ── inventory control ────────────────────────────────────────────────────

    def start_inventory(self, callback: Callable):
        self._cb = callback
        self._running = True
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="caen-light"
        )
        self._thread.start()
        logger.info("Inventory started on %s", self.port)

    def stop_inventory(self):
        self._running = False
        if self._ser and self._ser.is_open:
            try:
                self._ser.write(bytes([UART_ABORT]))
                self._ser.flush()
            except Exception:
                pass
        logger.info("Inventory stopped on %s", self.port)

    # ── poll loop ────────────────────────────────────────────────────────────

    def _poll_loop(self):
        consecutive_errors = 0

        while self._running:
            try:
                with self._lock:
                    frame, cid = make_inventory(self._seq)
                    if self.debug:
                        logger.debug("TX Inventory: %s", frame.hex())

                    resp = _send_receive(self._ser, frame, cid, self.INV_TIMEOUT)

                if resp is None:
                    consecutive_errors += 1
                    if consecutive_errors >= 5:
                        logger.error(
                            "5 consecutive inventory timeouts on %s — stopping",
                            self.port
                        )
                        break
                    if self.debug:
                        logger.debug("Inventory timeout #%d", consecutive_errors)
                    time.sleep(0.2)
                    continue

                consecutive_errors = 0
                if self.debug:
                    logger.debug("RX Inventory [%dB]: %s", len(resp), resp.hex())

                avps = _parse_avps(resp[HEADER_LEN:])
                tags = _extract_tags(avps)

                for epc, rssi in tags:
                    if self._cb:
                        try:
                            self._cb(epc, rssi, 0)
                        except Exception as exc:
                            logger.error("Callback error: %s", exc)

                if tags:
                    logger.debug("Inventory: %d tag(s)", len(tags))

            except serial.SerialException as exc:
                logger.error("Serial error in poll loop: %s", exc)
                break

            time.sleep(self.POLL_GAP)

        self._running = False
        logger.info("Poll loop exited for %s", self.port)
