#!/usr/bin/env python3
"""
zigbee-pcap-capture.py
Description : Capture all Zigbee traffic on a specific channel to PCAP
              for Wireshark analysis. Supports any KillerBee-compatible device.
Requires    : killerbee
Usage       : python3 zigbee-pcap-capture.py <channel> [device] [duration_s]
Example     : python3 zigbee-pcap-capture.py 15 /dev/ttyUSB0 120
"""

import sys
import time
import os
from datetime import datetime

try:
    from killerbee import KillerBee
    from killerbee.pcapdump import PcapDump
except ImportError:
    print("[!] killerbee not found. Install with: pip install killerbee")
    sys.exit(1)

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <channel> [device] [duration_s]")
    sys.exit(1)

CHANNEL  = int(sys.argv[1])
DEVICE   = sys.argv[2] if len(sys.argv) > 2 else None
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 0

LOOT_DIR = f"./loot/zigbee-cap-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
PCAP = os.path.join(LOOT_DIR, f"zigbee_ch{CHANNEL}.pcap")

if CHANNEL < 11 or CHANNEL > 26:
    print("[!] Zigbee channels are 11-26")
    sys.exit(1)

FREQ_MHZ = 2405 + (CHANNEL - 11) * 5
print(f" ==================================================")
print(f"  Zigbee PCAP Capture — Channel {CHANNEL} ({FREQ_MHZ} MHz)")
print(f"  Duration: {'indefinite' if DURATION == 0 else str(DURATION)+'s'}")
print(f"  Output: {PCAP}")
print(f" ==================================================")
print("[*] Press Ctrl+C to stop")

try:
    kb = KillerBee(device=DEVICE)
    kb.set_channel(CHANNEL)
    pd = PcapDump(PCAP)

    start = time.time()
    count = 0

    while True:
        if DURATION > 0 and (time.time() - start) > DURATION:
            break
        pkt = kb.pnext(timeout=1)
        if pkt and pkt[1]:
            pd.write(pkt[1])
            count += 1
            if count % 100 == 0:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] {count} packets captured")

except KeyboardInterrupt:
    print(f"\n[+] Captured {count} packets → {PCAP}")
    print(f"    Analyze: wireshark {PCAP}")
    print(f"    Filter:  wpan || zbee_nwk || zbee_aps")
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    try:
        pd.close()
        kb.close()
    except Exception:
        pass
