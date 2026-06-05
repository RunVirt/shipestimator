#!/usr/bin/env python3
"""
CAEN R1210IX Smart Tray — pure-Python serial reader (no DLL needed).

Implements the CAEN easyReader binary serial protocol over a virtual COM port.
Use this as a drop-in replacement for the ctypes/DLL approach when the DLL
crashes (access violation on RS232 init) or the CAEN USB driver is not installed.

Frame format  (big-endian):
  [STX=0x02][LEN_HI][LEN_LO][CMD][DATA...][ETX=0x03][CRC_HI][CRC_LO]

  LEN  = number of bytes from CMD through last DATA byte (uint16 BE)
  CRC  = CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) over
         [LEN_HI, LEN_LO, CMD, DATA...]

Response frames have the same format; the response CMD = request CMD | 0x80.
"""

import logging
import struct
import threading
import time
from typing import Callable, Iterator, Optional, Tuple

import serial

logger = logging.getLogger(__name__)

# ─── Protocol constants ────────────────────────────────────────────────────────

STX = 0x02
ETX = 0x03

# Host → reader commands
CMD_READER_INFO   = 0x01   # No params; response: firmware/model string
CMD_INVENTORY     = 0x03   # Params: see _inv_frame(); response: tag list
CMD_SET_POWER     = 0x07   # Params: [power_dBm: uint8]; response: ACK

# Reader → host response = CMD | 0x80
RESP_READER_INFO  = CMD_READER_INFO  | 0x80   # 0x81
RESP_INVENTORY    = CMD_INVENTORY    | 0x80   # 0x83
RESP_SET_POWER    = CMD_SET_POWER    | 0x80   # 0x87
RESP_ERROR        = 0xFF


# ─── CRC ──────────────────────────────────────────────────────────────────────

def _crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: polynomial 0x1021, initial value 0xFFFF."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
        crc &= 0xFFFF
    return crc


# ─── Frame builder ─────────────────────────────────────────────────────────────

def build_frame(cmd: int, data: bytes = b"") -> bytes:
    payload = bytes([cmd]) + data
    inner   = struct.pack(">H", len(payload)) + payload   # LEN + CMD + DATA
    crc     = struct.pack(">H", _crc16(inner))
    return bytes([STX]) + inner + bytes([ETX]) + crc


# ─── Frame parser ──────────────────────────────────────────────────────────────

def _iter_frames(buf: bytearray) -> Iterator[Tuple[int, bytes]]:
    """
    Yield (cmd, data) for each complete, CRC-valid frame found in buf.
    Consumed bytes are deleted from buf in place.
    """
    while len(buf) >= 7:          # minimum: STX + 2 LEN + 1 CMD + ETX + 2 CRC
        if buf[0] != STX:
            del buf[0]
            continue
        n     = struct.unpack_from(">H", buf, 1)[0]   # payload length
        total = 6 + n                                   # full frame length
        if len(buf) < total:
            break
        etx_idx = 3 + n
        if buf[etx_idx] != ETX:
            del buf[0]
            continue
        inner   = bytes(buf[1 : 3 + n])               # LEN_HI LEN_LO CMD DATA
        exp_crc = _crc16(inner)
        act_crc = struct.unpack_from(">H", buf, etx_idx + 1)[0]
        if exp_crc != act_crc:
            del buf[0]
            continue
        cmd  = buf[3]
        data = bytes(buf[4 : 3 + n])                  # DATA only (may be empty)
        del buf[:total]
        yield cmd, data


# ─── Inventory frame variants ──────────────────────────────────────────────────
#
# The exact inventory command parameters differ slightly between firmware versions.
# We cycle through the three most likely encodings until one produces tag reads.

def _inv_frames():
    """Yield successive inventory frame candidates to probe."""
    # Variant A: no parameters (simplest, some firmware versions)
    yield build_frame(CMD_INVENTORY)
    # Variant B: source index 0 as single byte
    yield build_frame(CMD_INVENTORY, bytes([0x00]))
    # Variant C: source name "Source_0" as length-prefixed Pascal string
    src = b"Source_0"
    yield build_frame(CMD_INVENTORY, bytes([len(src)]) + src)
    # Variant D: source name + null mask (length 0)
    yield build_frame(CMD_INVENTORY, bytes([len(src)]) + src + b"\x00\x00")


# ─── Inventory tag parser ──────────────────────────────────────────────────────

def _parse_inv_data(data: bytes) -> Iterator[Tuple[str, int]]:
    """
    Yield (epc_hex_upper, rssi_dbm) for each tag in a RESP_INVENTORY payload.

    Expected payload layout:
      [tag_count: uint16 BE]
      for each tag:
        [epc_byte_len: uint8]
        [epc: epc_byte_len bytes]
        [rssi: int16 BE, in dBm]
        (remaining fields per-tag are skipped if present)
    """
    if len(data) < 2:
        return
    try:
        n_tags, offset = struct.unpack_from(">H", data)[0], 2
        for _ in range(n_tags):
            if offset >= len(data):
                break
            epc_len = data[offset]; offset += 1
            if offset + epc_len > len(data):
                break
            epc  = data[offset : offset + epc_len].hex().upper()
            offset += epc_len
            if offset + 2 > len(data):
                yield epc, 0
                continue
            rssi = struct.unpack_from(">h", data, offset)[0]
            offset += 2
            yield epc, rssi
    except Exception as exc:
        logger.debug("inv parse failed: %s  raw=%s", exc, data.hex())


# ─── Main reader class ────────────────────────────────────────────────────────

class CaenSerialReader:
    """
    CAEN R1210IX reader over direct serial connection (no DLL required).

    Public API matches CaenReader in main.py:
      connect() → bool
      disconnect()
      start_inventory(callback)   callback(epc: str, rssi: int, err: int)
      stop_inventory()
      connected  (property)
    """

    BAUD     = 115200
    TIMEOUT  = 0.25          # serial read timeout in seconds
    POLL_GAP = 0.05          # pause between inventory polls

    def __init__(self, port: str, power: int = 30, debug: bool = False):
        self.port    = port
        self.power   = power
        self.debug   = debug
        self._ser: Optional[serial.Serial] = None
        self._rx_buf = bytearray()
        self._running= False
        self._thread: Optional[threading.Thread] = None
        self._cb: Optional[Callable] = None
        self._lock   = threading.Lock()
        self._inv_variant = 0      # which inventory frame variant to use

    @property
    def connected(self) -> bool:
        return self._ser is not None and self._ser.is_open

    # ── connect / disconnect ─────────────────────────────────────────────────

    def connect(self) -> bool:
        port = self.port
        # Accept both "COM3" and "\\.\COM3"
        if not port.startswith("\\\\.\\") and port.upper().startswith("COM"):
            port = "\\\\.\\" + port

        try:
            self._ser = serial.Serial(
                port        = port,
                baudrate    = self.BAUD,
                bytesize    = serial.EIGHTBITS,
                parity      = serial.PARITY_NONE,
                stopbits    = serial.STOPBITS_ONE,
                timeout     = self.TIMEOUT,
                write_timeout= 2.0,
                xonxoff     = False,
                rtscts      = False,
            )
            self._ser.reset_input_buffer()
            logger.info("Opened %s at %d baud", self.port, self.BAUD)
        except serial.SerialException as exc:
            logger.error("Cannot open %s: %s", self.port, exc)
            return False

        # Ping the reader
        info = self._transact(CMD_READER_INFO, timeout=2.0)
        if info is not None:
            logger.info("Reader info response: %s", info.hex() if info else "(empty)")
        else:
            logger.warning(
                "No response to READER_INFO on %s — "
                "reader may use a different protocol or baud rate. "
                "Inventory will still be attempted.",
                self.port,
            )

        # Set RF power
        ack = self._transact(CMD_SET_POWER, bytes([max(0, min(30, self.power))]), timeout=1.0)
        if ack is not None:
            logger.info("RF power set to %d dBm (ack=%s)", self.power, ack.hex() if ack else "OK")

        return True

    def disconnect(self):
        self._running = False
        if self._ser and self._ser.is_open:
            try:
                self._ser.close()
            except Exception:
                pass
        self._ser = None

    # ── inventory control ────────────────────────────────────────────────────

    def start_inventory(self, callback: Callable):
        self._cb      = callback
        self._running = True
        self._thread  = threading.Thread(
            target=self._poll_loop, daemon=True, name="caen-serial"
        )
        self._thread.start()

    def stop_inventory(self):
        self._running = False

    # ── internal helpers ─────────────────────────────────────────────────────

    def _write(self, frame: bytes):
        if self.debug:
            logger.debug("TX [%d]: %s", len(frame), frame.hex())
        self._ser.write(frame)
        self._ser.flush()

    def _read_into_buf(self, window: float):
        """Read available bytes into _rx_buf for up to `window` seconds."""
        deadline = time.monotonic() + window
        while time.monotonic() < deadline:
            chunk = self._ser.read(self._ser.in_waiting or 256)
            if chunk:
                if self.debug:
                    logger.debug("RX [%d]: %s", len(chunk), chunk.hex())
                self._rx_buf.extend(chunk)

    def _transact(self, cmd: int, data: bytes = b"", timeout: float = 1.0) -> Optional[bytes]:
        """Send command and return the first matching response payload, or None."""
        frame    = build_frame(cmd, data)
        exp_resp = cmd | 0x80
        try:
            with self._lock:
                self._write(frame)
                deadline = time.monotonic() + timeout
                local_buf = bytearray()
                while time.monotonic() < deadline:
                    chunk = self._ser.read(self._ser.in_waiting or 128)
                    if chunk:
                        local_buf.extend(chunk)
                        for r_cmd, r_data in list(_iter_frames(local_buf)):
                            if r_cmd == exp_resp:
                                return r_data
                            if r_cmd == RESP_ERROR:
                                logger.warning("Reader error response: %s", r_data.hex())
        except serial.SerialException as exc:
            logger.error("Serial error in transact: %s", exc)
        return None

    def _poll_loop(self):
        """Background thread: continuously poll inventory and fire callbacks."""
        variants      = list(_inv_frames())
        variant_idx   = 0
        zero_streak   = 0              # consecutive polls with zero tags
        switch_after  = 10             # switch variant after this many empty polls

        while self._running:
            frame = variants[variant_idx % len(variants)]
            try:
                with self._lock:
                    self._write(frame)
                    self._read_into_buf(0.4)

                tags_this_cycle = 0
                for r_cmd, r_data in list(_iter_frames(self._rx_buf)):
                    if r_cmd == RESP_INVENTORY:
                        for epc, rssi in _parse_inv_data(r_data):
                            tags_this_cycle += 1
                            if self._cb:
                                self._cb(epc, rssi, 0)
                    elif r_cmd == RESP_ERROR:
                        logger.debug("Reader error frame: %s", r_data.hex())

                if tags_this_cycle == 0:
                    zero_streak += 1
                    if zero_streak >= switch_after:
                        # Protocol variant isn't producing tags — try the next one
                        variant_idx  = (variant_idx + 1) % len(variants)
                        zero_streak  = 0
                        logger.debug("Switching to inventory variant %d", variant_idx)
                else:
                    zero_streak = 0

            except serial.SerialException as exc:
                logger.error("Serial error in poll loop: %s", exc)
                break

            time.sleep(self.POLL_GAP)
