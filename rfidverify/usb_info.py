#!/usr/bin/env python3
"""
Show USB identity of every COM port, then attempt a pyusb device scan.
Run this so we know the exact VID:PID of the CAEN reader.

Usage:
  python usb_info.py
"""

import sys
import serial.tools.list_ports

SEP = "=" * 60

print(SEP)
print("COM port USB identities")
print(SEP)
for p in serial.tools.list_ports.comports():
    print(f"  {p.device:10s}  {p.description}")
    print(f"             hwid : {p.hwid}")
    if p.vid is not None:
        print(f"             VID  : 0x{p.vid:04X}  ({p.vid})")
        print(f"             PID  : 0x{p.pid:04X}  ({p.pid})")
    if p.serial_number:
        print(f"             S/N  : {p.serial_number}")
    if p.manufacturer:
        print(f"             Mfr  : {p.manufacturer}")
    print()

print(SEP)
print("pyusb device scan (all connected USB devices)")
print(SEP)

try:
    import usb.core
    import usb.util

    devices = list(usb.core.find(find_all=True))
    if not devices:
        print("  (no devices found — may need a backend like libusb-1.0)")
    for dev in devices:
        mfr = prd = ""
        try:
            if dev.iManufacturer:
                mfr = usb.util.get_string(dev, dev.iManufacturer)
        except Exception:
            pass
        try:
            if dev.iProduct:
                prd = usb.util.get_string(dev, dev.iProduct)
        except Exception:
            pass
        label = f"{mfr} / {prd}".strip(" /")
        print(f"  {dev.idVendor:04X}:{dev.idProduct:04X}  {label}")

        # Print interfaces / endpoints for CAEN-looking devices
        if "caen" in (mfr + prd).lower() or "rfid" in (mfr + prd).lower():
            print("    *** CAEN/RFID device — listing interfaces ***")
            try:
                for cfg in dev:
                    for intf in cfg:
                        print(f"    Interface {intf.bInterfaceNumber}: "
                              f"class=0x{intf.bInterfaceClass:02X} "
                              f"subclass=0x{intf.bInterfaceSubClass:02X} "
                              f"protocol=0x{intf.bInterfaceProtocol:02X} "
                              f"({_class_name(intf.bInterfaceClass)})")
                        for ep in intf:
                            direction = "IN " if usb.util.endpoint_direction(ep.bEndpointAddress) \
                                == usb.util.ENDPOINT_IN else "OUT"
                            ep_type = _ep_type(ep.bmAttributes & 0x03)
                            print(f"      EP 0x{ep.bEndpointAddress:02X}  {direction}  "
                                  f"{ep_type}  max={ep.wMaxPacketSize}")
            except Exception as e:
                print(f"    (cannot enumerate interfaces: {e})")

except ImportError:
    print("  pyusb not installed.")
    print("  Install it with:  pip install pyusb")
    print()
    print("  Without pyusb we can still get the VID:PID from the COM port")
    print("  hwid lines printed above (format: USB VID:PID=XXXX:YYYY).")

print()
print(SEP)
print("Next steps based on VID:PID:")
print()
print("  Option A — Install CAEN's official driver (simplest):")
print("    Download 'CAEN RFID Lab' from https://www.caen.it/products/caen-rfid-lab/")
print("    Install it.  The CAEN USB driver is bundled.  Re-run diagnose.py.")
print()
print("  Option B — Zadig + pyusb (no CAEN account needed):")
print("    1. Note the VID:PID from the lines above (e.g. 21A7:0002)")
print("    2. Download Zadig from https://zadig.akeo.ie/")
print("    3. Options > List All Devices")
print("    4. Find the CAEN device's VENDOR INTERFACE (NOT the CDC/COM one)")
print("    5. Install WinUSB driver on that interface")
print("    6. Run:  pip install pyusb")
print("    7. Re-run this script — the CAEN device section will list its endpoints")
print("    8. We write a pyusb reader using those endpoints")
print(SEP)


def _class_name(cls):
    return {0x00: "vendor", 0x02: "CDC", 0x03: "HID",
            0x08: "Mass Storage", 0x0A: "CDC Data",
            0xFF: "vendor-specific"}.get(cls, f"0x{cls:02X}")

def _ep_type(t):
    return {0: "Control", 1: "Isochronous", 2: "Bulk", 3: "Interrupt"}.get(t, "?")
