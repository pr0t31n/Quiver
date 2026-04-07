#!/usr/bin/env python3
"""
yardstick-ook-replay.py
Description : Replay a captured OOK sub-GHz signal with Yardstick One.
              Transmits binary data previously recorded by yardstick-ook-record.py.
Requires    : rfcat
Usage       : sudo python3 yardstick-ook-replay.py <freq_mhz> <binfile> [repeat] [delay_ms]
Example     : sudo python3 yardstick-ook-replay.py 433.92 ook_433.92MHz.bin 3 200
WARNING     : Only transmit on frequencies and in environments you are authorised to use.
"""

import sys
import time
import os

try:
    from rfcat import RfCat, MOD_ASK_OOK
except ImportError:
    print("[!] rfcat not found. Install with: pip install rfcat")
    sys.exit(1)

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <freq_mhz> <binfile> [repeat=1] [delay_ms=200]")
    sys.exit(1)

FREQ_MHZ = float(sys.argv[1])
BINFILE  = sys.argv[2]
REPEAT   = int(sys.argv[3]) if len(sys.argv) > 3 else 1
DELAY_MS = int(sys.argv[4]) if len(sys.argv) > 4 else 200

if not os.path.isfile(BINFILE):
    print(f"[!] File not found: {BINFILE}")
    sys.exit(1)

with open(BINFILE, 'rb') as f:
    payload = f.read()

print(f" ==================================================")
print(f"  Yardstick One — OOK Replay")
print(f"  Frequency : {FREQ_MHZ} MHz")
print(f"  File      : {BINFILE} ({len(payload)} bytes)")
print(f"  Repeat    : {REPEAT}x | Delay: {DELAY_MS}ms")
print(f" ==================================================")
print("[!] WARNING: Ensure you are authorised to transmit on this frequency.")

try:
    d = RfCat()
    d.setModeIDLE()
    d.setFreq(int(FREQ_MHZ * 1e6))
    d.setMdmModulation(MOD_ASK_OOK)
    d.setMdmDRate(4800)
    d.setMaxPower()

    for i in range(REPEAT):
        print(f"[*] Transmitting ({i+1}/{REPEAT})...")
        d.RFxmit(payload)
        if i < REPEAT - 1:
            time.sleep(DELAY_MS / 1000.0)

    print("[+] Replay complete.")

except KeyboardInterrupt:
    print("\n[*] Interrupted.")
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    try:
        d.setModeIDLE()
        d.cleanup()
    except Exception:
        pass
