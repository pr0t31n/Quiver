#!/usr/bin/env python3
# ==============================================================================
#  deauth_monitor.py
#  Description : Passive 802.11 deauthentication and disassociation frame
#                monitor. Uses scapy on the host with a monitor-mode adapter.
#                Optionally reads from an ESP32 running custom monitor firmware
#                via serial.
#  Requires    : scapy, monitor-mode WiFi adapter
#  Install     : pip3 install scapy
#  Usage       : sudo python3 deauth_monitor.py -i wlan0mon
#                sudo python3 deauth_monitor.py -i wlan0mon --serial /dev/ttyUSB0
# ==============================================================================

import argparse
import sys
import os
import json
import time
from collections import defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas, RadioTap
    from scapy.layers.dot11 import Dot11
except ImportError:
    print("[!] scapy not installed. Run: pip3 install scapy")
    sys.exit(1)

# Track deauth/disassoc counts per BSSID
deauth_counts: dict = defaultdict(int)
disassoc_counts: dict = defaultdict(int)

# Sliding window for storm detection: {bssid: [timestamp, ...]}
recent_deauths: dict = defaultdict(list)

STORM_THRESHOLD = 10     # frames per window
STORM_WINDOW_SECS = 5    # sliding window seconds
alerted_bssids: set = set()

events: list = []


def format_mac(mac: str) -> str:
    if mac and len(mac) == 17:
        return mac.upper()
    return mac or "ff:ff:ff:ff:ff:ff"


def check_storm(bssid: str) -> bool:
    """Return True if a deauth storm is detected from this BSSID."""
    now = time.time()
    window = [t for t in recent_deauths[bssid] if now - t < STORM_WINDOW_SECS]
    recent_deauths[bssid] = window
    if len(window) >= STORM_THRESHOLD:
        return True
    return False


def process_frame(pkt):
    """Scapy packet handler — filters for deauth (subtype 12) and disassoc (subtype 10)."""
    if not pkt.haslayer(Dot11):
        return

    dot11 = pkt[Dot11]
    frame_type = dot11.type
    frame_subtype = dot11.subtype

    # type=0 Management, subtype=12 Deauth, subtype=10 Disassoc
    if frame_type != 0:
        return
    if frame_subtype not in (10, 12):
        return

    bssid = format_mac(dot11.addr3 or dot11.addr2)
    target = format_mac(dot11.addr1)
    ts = datetime.utcnow().isoformat() + "Z"

    rssi = None
    if pkt.haslayer(RadioTap):
        try:
            rssi = pkt[RadioTap].dBm_AntSignal
        except Exception:
            pass

    reason_code = None
    frame_name = "UNKNOWN"

    if frame_subtype == 12:
        frame_name = "DEAUTH"
        deauth_counts[bssid] += 1
        recent_deauths[bssid].append(time.time())
        if pkt.haslayer(Dot11Deauth):
            reason_code = pkt[Dot11Deauth].reason
    elif frame_subtype == 10:
        frame_name = "DISASSOC"
        disassoc_counts[bssid] += 1
        if pkt.haslayer(Dot11Disas):
            reason_code = pkt[Dot11Disas].reason

    event = {
        "type": frame_name.lower(),
        "bssid": bssid,
        "target": target,
        "reason": reason_code,
        "rssi": rssi,
        "timestamp": ts,
        "deauth_count": deauth_counts[bssid],
    }
    events.append(event)
    print_event(event)

    if frame_subtype == 12 and check_storm(bssid):
        if bssid not in alerted_bssids:
            alerted_bssids.add(bssid)
            print(f"\n  *** DEAUTH STORM ALERT ***")
            print(f"  BSSID: {bssid} sent >{STORM_THRESHOLD} deauths in {STORM_WINDOW_SECS}s")
            print(f"  Total deauth count from this BSSID: {deauth_counts[bssid]}\n")


def print_event(event: dict):
    reason_str = f" reason={event['reason']}" if event['reason'] is not None else ""
    rssi_str = f" rssi={event['rssi']}dBm" if event['rssi'] is not None else ""
    count_str = f" [total: {event['deauth_count']}]"
    ts = event["timestamp"]
    print(
        f"[{ts}] {event['type'].upper():8s} "
        f"BSSID={event['bssid']}  "
        f"TARGET={event['target']}"
        f"{reason_str}{rssi_str}{count_str}"
    )


def print_summary():
    print("\n" + "=" * 70)
    print("  DEAUTH/DISASSOC SUMMARY")
    print("=" * 70)
    print(f"  {'BSSID':<20}  {'DEAUTH':>8}  {'DISASSOC':>10}  {'STORM':>6}")
    print("  " + "-" * 60)

    all_bssids = set(list(deauth_counts.keys()) + list(disassoc_counts.keys()))
    for bssid in sorted(all_bssids, key=lambda b: deauth_counts[b] + disassoc_counts[b], reverse=True):
        storm = "YES" if bssid in alerted_bssids else "no"
        print(f"  {bssid:<20}  {deauth_counts[bssid]:>8}  {disassoc_counts[bssid]:>10}  {storm:>6}")
    print()


def save_events(output_file: str):
    with open(output_file, "w") as f:
        json.dump(events, f, indent=2)
    print(f"[+] Events saved to: {output_file}")


def read_serial_esp32(serial_port: str, iface: str):
    """
    Alternative input: read JSON events from ESP32 running custom monitor firmware
    via serial port. Falls back to scapy sniff if serial not available.
    """
    try:
        import serial
    except ImportError:
        print("[!] pyserial not installed. Run: pip3 install pyserial")
        sys.exit(1)

    print(f"[*] Reading deauth events from ESP32 on {serial_port} at 115200 baud...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        ser = serial.Serial(serial_port, 115200, timeout=1)
        while True:
            line = ser.readline().decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("type") in ("deauth", "disassoc"):
                    bssid = event.get("bssid", "ff:ff:ff:ff:ff:ff")
                    event.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
                    event.setdefault("deauth_count", deauth_counts[bssid])
                    if event["type"] == "deauth":
                        deauth_counts[bssid] += 1
                        recent_deauths[bssid].append(time.time())
                    else:
                        disassoc_counts[bssid] += 1
                    event["deauth_count"] = deauth_counts[bssid]
                    events.append(event)
                    print_event(event)

                    if event["type"] == "deauth" and check_storm(bssid):
                        if bssid not in alerted_bssids:
                            alerted_bssids.add(bssid)
                            print(f"\n  *** DEAUTH STORM ALERT *** BSSID: {bssid}\n")
            except (json.JSONDecodeError, KeyError):
                pass
    except serial.SerialException as e:
        print(f"[!] Serial error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Passive 802.11 deauthentication frame monitor"
    )
    parser.add_argument("-i", "--iface", default="wlan0mon",
                        help="Monitor-mode interface (default: wlan0mon)")
    parser.add_argument("--serial", default="",
                        help="Read from ESP32 serial port instead of scapy sniff (e.g. /dev/ttyUSB0)")
    parser.add_argument("--output", "-o", default="",
                        help="Save captured events to JSON file")
    parser.add_argument("--count", "-c", type=int, default=0,
                        help="Stop after N frames (0 = unlimited)")
    args = parser.parse_args()

    if os.geteuid() != 0 and not args.serial:
        print("[!] Root privileges required for raw packet sniffing. Run with sudo.")
        sys.exit(1)

    print("=" * 70)
    print("  802.11 Deauth / Disassoc Monitor")
    print(f"  Interface : {args.iface}")
    print(f"  Storm alert: >{STORM_THRESHOLD} deauths in {STORM_WINDOW_SECS}s from same BSSID")
    print("  Press Ctrl+C to stop")
    print("=" * 70)
    print(f"\n  {'TIMESTAMP':<27}  {'TYPE':<8}  {'BSSID':<20}  {'TARGET':<20}")
    print("  " + "-" * 85)

    try:
        if args.serial:
            read_serial_esp32(args.serial, args.iface)
        else:
            count = args.count if args.count > 0 else 0
            sniff(
                iface=args.iface,
                prn=process_frame,
                count=count,
                store=False,
            )
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.")

    print_summary()

    if args.output:
        save_events(args.output)
    elif events:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        save_events(f"deauth_events_{ts}.json")


if __name__ == "__main__":
    main()
