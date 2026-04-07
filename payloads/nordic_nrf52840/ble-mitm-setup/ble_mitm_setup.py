#!/usr/bin/env python3
# ==============================================================================
#  ble_mitm_setup.py
#  Description : BLE MITM setup guide and automation. Checks for available
#                tools (bettercap, GATTacker, Wireshark), guides the operator
#                through a BLE MITM attack setup, and generates ready-to-run
#                commands. Includes nRF52840 sniffer firmware instructions.
#  Requires    : bleak (for GATT enumeration), optionally bettercap / GATTacker
#  Install     : pip3 install bleak
#                brew install bettercap  (macOS)
#                npm install -g gattacker (requires Node.js)
# ==============================================================================

import asyncio
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional

try:
    from bleak import BleakScanner, BleakClient
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# ---------------------------------------------------------------------------
# Tool detection
# ---------------------------------------------------------------------------

def check_tool(name: str, args: List[str] = ["--version"]) -> Optional[str]:
    """Return tool version string or None if not found."""
    path = shutil.which(name)
    if not path:
        return None
    try:
        result = subprocess.run([name] + args, capture_output=True, text=True, timeout=5)
        ver = (result.stdout + result.stderr).strip().split("\n")[0]
        return ver[:80]
    except Exception:
        return "found (version unknown)"


def detect_tools() -> Dict[str, Optional[str]]:
    tools = {
        "bleak": "installed" if BLEAK_AVAILABLE else None,
        "bettercap": check_tool("bettercap", ["-v"]),
        "gattacker": check_tool("gatt-server", ["--version"]),
        "wireshark": check_tool("wireshark", ["--version"]),
        "tshark": check_tool("tshark", ["--version"]),
        "hcitool": check_tool("hcitool"),
        "gatttool": check_tool("gatttool", ["--version"]),
        "btlejuice": check_tool("btlejuice"),
        "npm": check_tool("npm", ["--version"]),
        "node": check_tool("node", ["--version"]),
    }
    return tools


def print_tool_status(tools: Dict[str, Optional[str]]):
    print("\n[*] Tool availability:")
    for name, ver in tools.items():
        status = f"[OK] {ver}" if ver else "[--] not found"
        color = "\033[32m" if ver else "\033[31m"
        reset = "\033[0m"
        print(f"  {color}{status:40s}{reset} {name}")
    print()


# ---------------------------------------------------------------------------
# BLE target scanning
# ---------------------------------------------------------------------------

async def scan_targets(timeout: float = 10.0) -> List[Dict]:
    if not BLEAK_AVAILABLE:
        print("[!] bleak not installed. Cannot scan. Run: pip3 install bleak")
        return []

    devices_found: List[Dict] = []

    def cb(device: BLEDevice, adv_data: AdvertisementData):
        entry = {
            "address": device.address,
            "name": device.name or adv_data.local_name or "(unknown)",
            "rssi": adv_data.rssi,
            "service_uuids": list(adv_data.service_uuids or []),
        }
        for existing in devices_found:
            if existing["address"] == device.address:
                return
        devices_found.append(entry)

    print(f"[*] Scanning for BLE devices ({timeout}s)...")
    scanner = BleakScanner(detection_callback=cb)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()
    return devices_found


async def enumerate_gatt(target_mac: str) -> Dict:
    """Enumerate GATT services and characteristics of a target device."""
    if not BLEAK_AVAILABLE:
        return {}

    print(f"\n[*] Enumerating GATT for {target_mac}...")
    services_info = {}
    try:
        async with BleakClient(target_mac, timeout=15.0) as client:
            print(f"[+] Connected to {target_mac}")
            for service in client.services:
                svc_data = {
                    "uuid": str(service.uuid),
                    "description": service.description,
                    "characteristics": []
                }
                for char in service.characteristics:
                    char_data = {
                        "uuid": str(char.uuid),
                        "description": char.description,
                        "properties": char.properties,
                        "value": None,
                    }
                    if "read" in char.properties:
                        try:
                            val = await client.read_gatt_char(char.uuid)
                            char_data["value"] = list(val)
                        except Exception:
                            pass
                    svc_data["characteristics"].append(char_data)
                services_info[str(service.uuid)] = svc_data
    except Exception as e:
        print(f"[!] GATT enumeration failed: {e}")
    return services_info


# ---------------------------------------------------------------------------
# Command generators
# ---------------------------------------------------------------------------

def generate_bettercap_commands(target_mac: str) -> List[str]:
    return [
        "# --- bettercap BLE MITM commands ---",
        f"sudo bettercap -eval \"ble.recon on\"",
        f"sudo bettercap -eval \"ble.recon on; ble.enum {target_mac}\"",
        "# Interactive bettercap session:",
        "sudo bettercap",
        "# Then in bettercap REPL:",
        "ble.recon on",
        f"ble.enum {target_mac}",
        f"# Read characteristic:  ble.read {target_mac} <UUID>",
        f"# Write characteristic: ble.write {target_mac} <UUID> <hex_data>",
    ]


def generate_gattacker_commands(target_mac: str) -> List[str]:
    mac_safe = target_mac.replace(":", "-")
    return [
        "# --- GATTacker BLE MITM commands (Node.js) ---",
        "# Install: npm install -g gattacker",
        "# Step 1: Scan and clone target advertisement",
        f"gatt-server --target {target_mac} --scan",
        "# Step 2: Run cloned advertisement server",
        f"gatt-server --clone {mac_safe}.json",
        "# Step 3: Forward GATT requests to real device",
        f"gatt-client --target {target_mac}",
        "# Full proxy (advertisement clone + GATT forwarding):",
        f"gatt-mitm --target {target_mac}",
    ]


def generate_nrf52840_sniffer_instructions() -> List[str]:
    return [
        "=" * 60,
        "  nRF52840 BLE Sniffer Firmware Setup",
        "=" * 60,
        "",
        "1. Download nRF Sniffer firmware from Nordic Semiconductor:",
        "   https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE",
        "",
        "2. Flash the sniffer firmware to nRF52840 dongle:",
        "   nrfjprog --family NRF52 --program sniffer_nrf52840dongle_*.hex --chiperase",
        "   # OR via nRF Connect for Desktop -> Programmer",
        "",
        "3. Install Wireshark nRF Sniffer plugin:",
        "   - Copy 'nrf_sniffer_for_bluetooth_le.py' to Wireshark extcap directory:",
        "     macOS: ~/Library/Application Support/Wireshark/extcap/",
        "     Linux: ~/.config/wireshark/extcap/",
        "   - Make executable: chmod +x nrf_sniffer_for_bluetooth_le.py",
        "",
        "4. Launch Wireshark, select 'nRF Sniffer for Bluetooth LE' interface.",
        "   Filter for a specific device: enter its MAC in the 'Device to follow' field.",
        "",
        "5. Serial output from sniffer: 1000000 baud (1 Mbaud).",
        "   Wireshark plugin handles the pipe automatically.",
        "",
        "Useful Wireshark filters:",
        "  btle.advertising_header.pdu_type == 0x06  (ADV_IND)",
        "  btle.advertising_address == XX:XX:XX:XX:XX:XX",
        "  btatt                                      (GATT traffic)",
        "  btatt.opcode == 0x12                       (Write Request)",
        "  btatt.opcode == 0x1b                       (Handle Value Notification)",
    ]


def generate_bleak_proxy_concept(target_mac: str) -> List[str]:
    return [
        "=" * 60,
        "  bleak-based GATT Proxy Concept",
        "=" * 60,
        "",
        "# A GATT proxy intercepts and forwards GATT traffic.",
        "# Full implementation requires two BLE adapters:",
        "#   Adapter 1: Central role — connects to real device",
        "#   Adapter 2: Peripheral role — presents cloned device to victim",
        "",
        "# Step 1: Enumerate real device GATT structure",
        f"python3 ble_mitm_setup.py --enumerate {target_mac}",
        "",
        "# Step 2: Mirror services to a GATT server (requires bleak + bless)",
        "# pip3 install bless",
        "# See: https://github.com/kevincar/bless",
        "",
        "# Step 3: Forward all reads/writes to the real device via bleak",
        "# This requires a custom GATT server implementation.",
        "# Reference implementation: BtleJuice (Node.js, archived)",
        "#   https://github.com/DigitalSecurity/btlejuice",
    ]


# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------

async def run_workflow(args):
    print("=" * 64)
    print("  BLE MITM Setup and Automation")
    print("  For authorized security assessments only")
    print("=" * 64)

    tools = detect_tools()
    print_tool_status(tools)

    # Tool recommendations
    if not tools["bleak"]:
        print("[!] Install bleak for BLE scanning: pip3 install bleak")
    if not tools["bettercap"]:
        print("[!] bettercap not found. Install: brew install bettercap (macOS)")
        print("                                  apt install bettercap (Linux)")
    if not tools["npm"] and not tools["gattacker"]:
        print("[!] npm not found. GATTacker requires Node.js: https://nodejs.org")
    print()

    target_mac = args.target

    # Step 1: Scan for targets if no target specified
    if not target_mac:
        print("[STEP 1] Scanning for BLE devices...")
        devices = await scan_targets(args.scan_timeout)
        if not devices:
            print("[!] No devices found. Ensure BLE adapter is available.")
            return

        print(f"\n  Found {len(devices)} device(s):\n")
        for i, d in enumerate(devices):
            print(f"  [{i+1:2d}] {d['address']}  RSSI:{d['rssi']:>4}dBm  {d['name']}")

        print()
        choice = input("  Select target device number (or enter MAC directly): ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(devices):
            target_mac = devices[int(choice) - 1]["address"]
        elif ":" in choice:
            target_mac = choice
        else:
            print("[!] Invalid selection.")
            return

    print(f"\n[*] Target: {target_mac}")

    # Step 2: GATT enumeration
    if args.enumerate or not args.skip_enum:
        print("\n[STEP 2] Enumerating GATT structure...")
        gatt_data = await enumerate_gatt(target_mac)
        if gatt_data:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            out_file = f"gatt_enum_{target_mac.replace(':', '-')}_{ts}.json"
            with open(out_file, "w") as f:
                json.dump(gatt_data, f, indent=2)
            print(f"[+] GATT data saved to: {out_file}")

            print("\n  GATT Services:")
            for uuid, svc in gatt_data.items():
                print(f"    [{uuid}] {svc.get('description', '')}")
                for char in svc.get("characteristics", []):
                    props = ", ".join(char.get("properties", []))
                    print(f"      - {char['uuid']} ({props})")

    # Step 3: Generate attack commands
    print("\n[STEP 3] Generated attack commands:\n")

    if tools["bettercap"]:
        print("  --- bettercap ---")
        for cmd in generate_bettercap_commands(target_mac):
            print(f"  {cmd}")
        print()

    print("  --- GATTacker (Node.js) ---")
    for cmd in generate_gattacker_commands(target_mac):
        print(f"  {cmd}")
    print()

    print("  --- bleak GATT Proxy (concept) ---")
    for line in generate_bleak_proxy_concept(target_mac):
        print(f"  {line}")
    print()

    # Step 4: nRF52840 sniffer instructions
    print("\n[STEP 4] nRF52840 Sniffer Firmware Instructions:")
    for line in generate_nrf52840_sniffer_instructions():
        print(f"  {line}")


def main():
    parser = argparse.ArgumentParser(
        description="BLE MITM setup and automation with tool detection and command generation"
    )
    parser.add_argument("--target", "-t", default="",
                        help="Target BLE device MAC address (skip scan if provided)")
    parser.add_argument("--scan-timeout", type=float, default=10.0,
                        help="BLE scan duration in seconds (default: 10)")
    parser.add_argument("--enumerate", "-e", action="store_true",
                        help="Enumerate GATT services on target")
    parser.add_argument("--skip-enum", action="store_true",
                        help="Skip GATT enumeration step")
    args = parser.parse_args()

    asyncio.run(run_workflow(args))


if __name__ == "__main__":
    main()
