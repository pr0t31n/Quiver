#!/usr/bin/env python3
"""
zigbee-channel-survey.py
Description : Passive Zigbee network survey using KillerBee + Sonoff ZBDongle-E
              (or compatible CC2531/CC2652 sniffer). Scans channels 11-26,
              identifies PAN IDs, coordinators, routers, and end devices.
Requires    : killerbee (pip install killerbee), KillerBee-compatible adapter
Usage       : python3 zigbee-channel-survey.py [device] [dwell_ms]
Example     : python3 zigbee-channel-survey.py /dev/ttyUSB0 500
"""

import sys
import time
import os
from datetime import datetime

try:
    from killerbee import KillerBee, PCAP_FILENAME
    import killerbee
except ImportError:
    print("[!] killerbee not found. Install with: pip install killerbee")
    sys.exit(1)

DEVICE   = sys.argv[1] if len(sys.argv) > 1 else None  # Auto-detect
DWELL_MS = int(sys.argv[2]) if len(sys.argv) > 2 else 500
CHANNELS = list(range(11, 27))  # Zigbee channels 11-26 (2405-2480 MHz)

LOOT_DIR = f"./loot/zigbee-survey-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
SURVEY_FILE = os.path.join(LOOT_DIR, "zigbee_networks.csv")

print(f" ==================================================")
print(f"  Zigbee Channel Survey (KillerBee)")
print(f"  Channels: 11-26 | Dwell: {DWELL_MS}ms per channel")
print(f"  Output: {SURVEY_FILE}")
print(f" ==================================================")
print("[*] Press Ctrl+C to stop")

try:
    kb = KillerBee(device=DEVICE)
    print(f"[+] Device: {kb.get_dev_info()}")

    networks = {}  # {pan_id: {channel, coordinator, devices}}

    with open(SURVEY_FILE, 'w') as f:
        f.write("timestamp,channel,pan_id,src_addr,dst_addr,frame_type,seq\n")

        while True:
            for ch in CHANNELS:
                kb.set_channel(ch)
                end_time = time.time() + (DWELL_MS / 1000.0)

                while time.time() < end_time:
                    pkt = kb.pnext()
                    if pkt and pkt[1]:
                        data = pkt[1]
                        ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

                        # Parse minimal 802.15.4 header
                        if len(data) >= 9:
                            fc = int.from_bytes(data[0:2], 'little')
                            seq = data[2]
                            dst_pan = int.from_bytes(data[3:5], 'little')
                            dst_addr = int.from_bytes(data[5:7], 'little')
                            src_addr = int.from_bytes(data[7:9], 'little') if len(data) >= 9 else 0
                            frame_type = fc & 0x7

                            type_name = {0: 'Beacon', 1: 'Data', 2: 'Ack', 3: 'MAC_CMD'}.get(frame_type, 'Unknown')
                            pan_hex = f"0x{dst_pan:04X}"

                            if pan_hex not in networks:
                                networks[pan_hex] = {'channel': ch, 'devices': set()}
                                print(f"  [{ts}] NEW NETWORK: PAN {pan_hex} on CH{ch}")
                            networks[pan_hex]['devices'].add(f"0x{src_addr:04X}")

                            if frame_type == 0:  # Beacon = coordinator
                                print(f"  [{ts}] Beacon CH{ch} PAN={pan_hex} coordinator=0x{src_addr:04X}")

                            f.write(f"{ts},{ch},{pan_hex},0x{src_addr:04X},0x{dst_addr:04X},{type_name},{seq}\n")
                            f.flush()

except KeyboardInterrupt:
    print(f"\n[+] Survey complete.")
    print(f"    Networks found: {len(networks)}")
    for pan, info in networks.items():
        print(f"    PAN {pan} | CH{info['channel']} | {len(info['devices'])} device(s)")
    print(f"[+] Data: {SURVEY_FILE}")
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    try:
        kb.close()
    except Exception:
        pass
