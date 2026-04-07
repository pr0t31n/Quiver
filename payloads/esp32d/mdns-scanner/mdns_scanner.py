#!/usr/bin/env python3
# ==============================================================================
#  mdns_scanner.py
#  Description : mDNS/Bonjour service discovery scanner. Discovers services
#                on the local network using the zeroconf library with a raw
#                multicast socket fallback.
#  Requires    : zeroconf (optional but recommended), socket (stdlib)
#  Install     : pip3 install zeroconf
#  Usage       : python3 mdns_scanner.py [--timeout 30] [--output results.json]
# ==============================================================================

import argparse
import json
import socket
import struct
import sys
import time
from datetime import datetime
from typing import List, Dict, Optional

# Service types to query
SERVICE_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_ftp._tcp.local.",
    "_smb._tcp.local.",
    "_ipp._tcp.local.",
    "_airplay._tcp.local.",
    "_googlecast._tcp.local.",
    "_homekit._tcp.local.",
    "_raop._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_nfs._tcp.local.",
    "_rfb._tcp.local.",
    "_daap._tcp.local.",
    "_mpd._tcp.local.",
    "_mqtt._tcp.local.",
    "_coap._udp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_workstation._tcp.local.",
]

discovered_services: List[Dict] = []


# ---------------------------------------------------------------------------
# Zeroconf-based discovery (primary method)
# ---------------------------------------------------------------------------

def scan_with_zeroconf(service_types: List[str], timeout: int = 30) -> List[Dict]:
    """Use the zeroconf library to browse for mDNS services."""
    try:
        from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo
    except ImportError:
        print("[!] zeroconf not installed. Falling back to raw socket method.")
        print("[!] Install: pip3 install zeroconf")
        return []

    results: List[Dict] = []
    zc = Zeroconf()

    class Listener:
        def __init__(self, stype: str):
            self.stype = stype

        def remove_service(self, zeroconf, type_, name):
            pass

        def update_service(self, zeroconf, type_, name):
            pass

        def add_service(self, zeroconf, type_, name):
            info: Optional[ServiceInfo] = zeroconf.get_service_info(type_, name)
            if not info:
                return
            addresses = []
            for addr in info.parsed_addresses():
                addresses.append(addr)

            txt_records = {}
            for k, v in info.properties.items():
                key = k.decode("utf-8", errors="replace") if isinstance(k, bytes) else k
                val = v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)
                txt_records[key] = val

            svc = {
                "name": name,
                "service_type": self.stype.rstrip("."),
                "hostname": info.server or "",
                "addresses": addresses,
                "port": info.port,
                "txt_records": txt_records,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            results.append(svc)
            print_service(svc)

    browsers = []
    for stype in service_types:
        browsers.append(ServiceBrowser(zc, stype, Listener(stype)))

    print(f"[*] Browsing for {len(service_types)} service types (timeout={timeout}s)...")
    time.sleep(timeout)

    zc.close()
    return results


# ---------------------------------------------------------------------------
# Raw multicast socket fallback (no zeroconf dependency)
# ---------------------------------------------------------------------------

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


def build_mdns_query(name: str) -> bytes:
    """Build a minimal mDNS PTR query packet for the given service type."""
    transaction_id = 0x0000
    flags = 0x0000
    questions = 1
    header = struct.pack(">HHHHHH", transaction_id, flags, questions, 0, 0, 0)

    labels = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("utf-8")
        labels += bytes([len(encoded)]) + encoded
    labels += b"\x00"

    qtype = 12   # PTR
    qclass = 1   # IN (unicast bit not set)
    question = labels + struct.pack(">HH", qtype, qclass)
    return header + question


def scan_with_raw_socket(service_types: List[str], timeout: int = 10) -> List[Dict]:
    """
    Send mDNS PTR queries via multicast socket and collect responses.
    This is a best-effort fallback — full mDNS parsing is complex.
    """
    results: List[Dict] = []
    raw_responses: List[bytes] = []

    print("[*] Sending mDNS queries via raw multicast socket...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.settimeout(2)
        sock.bind(("", MDNS_PORT))

        mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        for stype in service_types:
            query = build_mdns_query(stype)
            try:
                sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
            except OSError:
                pass

        end_time = time.time() + timeout
        seen: set = set()
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(4096)
                key = (addr[0], data[:12])
                if key not in seen:
                    seen.add(key)
                    raw_responses.append(data)
                    svc = {
                        "name": f"mDNS response from {addr[0]}",
                        "service_type": "raw",
                        "hostname": "",
                        "addresses": [addr[0]],
                        "port": None,
                        "txt_records": {"raw_len": str(len(data))},
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                    }
                    results.append(svc)
                    print(f"[+] mDNS response from {addr[0]} ({len(data)} bytes)")
            except socket.timeout:
                pass

    except PermissionError:
        print("[!] Permission denied. Raw socket scan may require root. Try: sudo python3 mdns_scanner.py")
    except Exception as e:
        print(f"[!] Socket error: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return results


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def print_service(svc: Dict):
    addrs = ", ".join(svc.get("addresses", []))
    port = svc.get("port") or ""
    host = svc.get("hostname", "").rstrip(".")
    name = svc.get("name", "").split(".")[0]
    stype = svc.get("service_type", "")
    txt = svc.get("txt_records", {})

    print(f"  [+] {name}")
    print(f"      Type    : {stype}")
    print(f"      Host    : {host}")
    print(f"      Address : {addrs}")
    print(f"      Port    : {port}")
    if txt:
        print(f"      TXT     : {json.dumps(txt)}")
    print()


def print_table(services: List[Dict]):
    if not services:
        print("[*] No services discovered.")
        return

    print("\n" + "=" * 80)
    print("  mDNS / Bonjour Service Discovery Results")
    print("=" * 80)
    print(f"  {'NAME':<30}  {'TYPE':<25}  {'ADDRESS':<18}  {'PORT':<6}")
    print("  " + "-" * 76)
    for svc in services:
        name = svc.get("name", "")[:28]
        stype = svc.get("service_type", "")[:23]
        addr = (svc.get("addresses") or [""])[0][:16]
        port = str(svc.get("port") or "")
        print(f"  {name:<30}  {stype:<25}  {addr:<18}  {port:<6}")
    print(f"\n  Total services discovered: {len(services)}\n")


def save_results(services: List[Dict], output_file: str):
    with open(output_file, "w") as f:
        json.dump(services, f, indent=2)
    print(f"[+] Results saved to: {output_file}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="mDNS/Bonjour service discovery scanner")
    parser.add_argument("--timeout", "-t", type=int, default=30,
                        help="Discovery timeout in seconds (default: 30)")
    parser.add_argument("--output", "-o", default="",
                        help="Save results to JSON file")
    parser.add_argument("--raw", action="store_true",
                        help="Force raw socket mode (skip zeroconf)")
    args = parser.parse_args()

    print("=" * 60)
    print("  mDNS / Bonjour Service Discovery Scanner")
    print(f"  Querying {len(SERVICE_TYPES)} service types")
    print(f"  Timeout: {args.timeout}s")
    print("=" * 60)
    print()

    all_services: List[Dict] = []

    if not args.raw:
        zc_results = scan_with_zeroconf(SERVICE_TYPES, timeout=args.timeout)
        all_services.extend(zc_results)

    if args.raw or not all_services:
        raw_results = scan_with_raw_socket(SERVICE_TYPES, timeout=min(args.timeout, 15))
        all_services.extend(raw_results)

    print_table(all_services)

    if args.output:
        save_results(all_services, args.output)
    elif all_services:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        save_results(all_services, f"mdns_scan_{ts}.json")


if __name__ == "__main__":
    main()
