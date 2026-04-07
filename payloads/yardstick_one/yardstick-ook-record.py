#!/usr/bin/env python3
"""
yardstick-ook-record.py
Description : Capture OOK-modulated sub-GHz signal with Yardstick One.
              Records raw bitstream and IQ-equivalent data to file.
              Common targets: garage openers, alarm sensors, key fobs,
              weather stations, RF thermostats.
Requires    : rfcat
Usage       : sudo python3 yardstick-ook-record.py <freq_mhz> [duration_s] [outfile]
Example     : sudo python3 yardstick-ook-record.py 433.92 5
"""

import sys
import time
import os
from datetime import datetime

try:
    from rfcat import RfCat, MOD_ASK_OOK
except ImportError:
    print("[!] rfcat not found. Install with: pip install rfcat")
    sys.exit(1)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <freq_mhz> [duration_s] [outfile]")
    sys.exit(1)

FREQ_MHZ  = float(sys.argv[1])
DURATION  = int(sys.argv[2]) if len(sys.argv) > 2 else 5
LOOT_DIR  = "./loot/ook-capture"
os.makedirs(LOOT_DIR, exist_ok=True)
OUTFILE   = sys.argv[3] if len(sys.argv) > 3 else \
    os.path.join(LOOT_DIR, f"ook_{FREQ_MHZ:.2f}MHz_{datetime.now().strftime('%H%M%S')}.bin")

print(f" ==================================================")
print(f"  Yardstick One — OOK Capture")
print(f"  Frequency : {FREQ_MHZ} MHz")
print(f"  Duration  : {DURATION}s")
print(f"  Output    : {OUTFILE}")
print(f" ==================================================")

try:
    d = RfCat()
    d.setModeIDLE()
    d.setFreq(int(FREQ_MHZ * 1e6))
    d.setMdmModulation(MOD_ASK_OOK)
    d.setMdmDRate(4800)        # 4800 baud — adjust per target
    d.setMdmSyncMode(0)        # No sync word (capture everything)
    d.setMaxPower()
    d.setModeRX()

    print(f"[*] Listening for {DURATION}s... (transmit your signal now)")
    captured = []
    end_time = time.time() + DURATION

    while time.time() < end_time:
        try:
            pkt, ts = d.RFrecv(timeout=1000)
            if pkt:
                captured.append(bytes(pkt))
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] Packet: {len(pkt)} bytes | RSSI: {d.getRSSI()} dBm")
        except Exception:
            pass

    d.setModeIDLE()

    if captured:
        with open(OUTFILE, 'wb') as f:
            for pkt in captured:
                f.write(pkt)
        print(f"\n[+] Captured {len(captured)} packet(s) → {OUTFILE}")
        print(f"    Replay with: yardstick-ook-replay.py {FREQ_MHZ} {OUTFILE}")
    else:
        print("[*] No packets captured. Try adjusting baud rate or frequency.")

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
