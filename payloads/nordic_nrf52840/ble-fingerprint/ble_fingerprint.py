#!/usr/bin/env python3
# ==============================================================================
#  ble_fingerprint.py
#  Description : Bluetooth LE device fingerprinting using the bleak library.
#                Collects MAC, RSSI, company ID (OUI), service UUIDs, device
#                name, TX power, and infers device type from service UUIDs.
#  Requires    : bleak
#  Install     : pip3 install bleak
#  Usage       : python3 ble_fingerprint.py [--timeout 15] [--output results.json]
# ==============================================================================

import asyncio
import argparse
import json
import sys
import os
from datetime import datetime
from typing import Dict, List, Optional

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
except ImportError:
    print("[!] bleak not installed. Run: pip3 install bleak")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Bluetooth SIG Company Identifiers (subset of common ones)
# Full list: https://www.bluetooth.com/specifications/assigned-numbers/
# ---------------------------------------------------------------------------
COMPANY_IDS: Dict[int, str] = {
    0x0000: "Ericsson Technology",
    0x0001: "Nokia Mobile Phones",
    0x0002: "Intel Corp",
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x0046: "Qualcomm",
    0x004C: "Apple",
    0x0059: "Nordic Semiconductor",
    0x0060: "ST Microelectronics",
    0x0075: "Samsung",
    0x00E0: "Google",
    0x00CD: "Plantronics",
    0x0117: "Huawei",
    0x0131: "Cypress Semiconductor",
    0x0171: "Silicon Laboratories",
    0x02FF: "Amazon",
    0x038F: "Amazon (Echo)",
    0x0499: "Ruuvi Innovations",
    0x04AA: "Bose",
    0x05AC: "Apple (AirPods variant)",
    0x006B: "Jawbone",
    0x0078: "Nike",
    0x00FF: "Stollmann E+V",
    0x0101: "Action Star Enterprise",
    0x010F: "Caterpillar",
    0x0154: "Polar Electro",
    0x01D7: "Fitbit",
    0x01D8: "Tile",
    0x0208: "Logitech",
    0x020D: "Lexmark",
    0x0213: "iRobot",
    0x0220: "Kohler",
    0x022B: "HP",
    0x0265: "Xiaomi",
    0x0310: "Garmin",
    0x0312: "Garmin (variant)",
    0x033B: "Texas Instruments",
}

# ---------------------------------------------------------------------------
# Service UUID fingerprinting
# Standard BLE GATT service UUIDs (16-bit, padded to full 128-bit form)
# ---------------------------------------------------------------------------
GATT_SERVICES: Dict[str, str] = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001812-0000-1000-8000-00805f9b34fb": "HID (Human Interface Device)",
    "0000181a-0000-1000-8000-00805f9b34fb": "Environmental Sensing",
    "0000181c-0000-1000-8000-00805f9b34fb": "User Data",
    "0000181e-0000-1000-8000-00805f9b34fb": "Bond Management",
    "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
    "00001808-0000-1000-8000-00805f9b34fb": "Glucose",
    "00001816-0000-1000-8000-00805f9b34fb": "Cycling Speed and Cadence",
    "00001818-0000-1000-8000-00805f9b34fb": "Cycling Power",
    "00001819-0000-1000-8000-00805f9b34fb": "Location and Navigation",
    "0000181b-0000-1000-8000-00805f9b34fb": "Body Composition",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "00001805-0000-1000-8000-00805f9b34fb": "Current Time",
    "00001806-0000-1000-8000-00805f9b34fb": "Reference Time Update",
    "00001807-0000-1000-8000-00805f9b34fb": "Next DST Change",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000fef3-0000-1000-8000-00805f9b34fb": "Google (Fast Pair)",
    "0000fe2c-0000-1000-8000-00805f9b34fb": "Google (?)  ",
    "0000fd6f-0000-1000-8000-00805f9b34fb": "COVID-19 Exposure Notifications",
    "0000180b-0000-1000-8000-00805f9b34fb": "Network Availability",
    "0000fe9f-0000-1000-8000-00805f9b34fb": "Google Eddystone",
}

# Device type heuristics based on service UUIDs
DEVICE_TYPE_HINTS: Dict[str, str] = {
    "Heart Rate":                "Fitness / Heart Rate Monitor",
    "HID (Human Interface Device)": "Keyboard / Mouse / HID Peripheral",
    "Battery Service":           "Battery-powered BLE Device",
    "Environmental Sensing":     "Environmental Sensor",
    "Cycling Speed and Cadence": "Cycling Sensor",
    "Cycling Power":             "Cycling Power Meter",
    "Location and Navigation":   "GPS / Navigation Device",
    "Body Composition":          "Smart Scale / Body Composition",
    "Glucose":                   "Glucose Meter",
    "Blood Pressure":            "Blood Pressure Monitor",
    "Health Thermometer":        "Thermometer",
    "COVID-19 Exposure Notifications": "Exposure Notification (COVID) Device",
    "Google (Fast Pair)":        "Google Fast Pair Device",
}

# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

discovered_devices: List[Dict] = []


def lookup_company(company_id: int) -> str:
    return COMPANY_IDS.get(company_id, f"Unknown (0x{company_id:04X})")


def identify_services(uuids: List[str]) -> List[str]:
    labels = []
    for uuid in uuids:
        norm = uuid.lower()
        label = GATT_SERVICES.get(norm)
        if not label:
            # Try 16-bit short UUID lookup
            if len(uuid) == 4:
                full = f"0000{uuid.lower()}-0000-1000-8000-00805f9b34fb"
                label = GATT_SERVICES.get(full)
        if label:
            labels.append(label)
        else:
            labels.append(uuid)
    return labels


def infer_device_type(service_labels: List[str]) -> str:
    for label in service_labels:
        hint = DEVICE_TYPE_HINTS.get(label)
        if hint:
            return hint
    return "Unknown"


def process_advertisement(device: BLEDevice, adv_data: AdvertisementData):
    company = None
    company_name = None
    if adv_data.manufacturer_data:
        company_id = list(adv_data.manufacturer_data.keys())[0]
        company = company_id
        company_name = lookup_company(company_id)

    service_uuids = list(adv_data.service_uuids or [])
    service_labels = identify_services(service_uuids)
    device_type = infer_device_type(service_labels)

    entry = {
        "address": device.address,
        "name": device.name or adv_data.local_name or "",
        "rssi": adv_data.rssi,
        "company_id": f"0x{company:04X}" if company is not None else None,
        "company_name": company_name,
        "service_uuids": service_uuids,
        "service_labels": service_labels,
        "device_type": device_type,
        "tx_power": adv_data.tx_power,
        "manufacturer_data": {
            f"0x{k:04X}": list(v) for k, v in (adv_data.manufacturer_data or {}).items()
        },
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    # Deduplicate by address
    for existing in discovered_devices:
        if existing["address"] == device.address:
            # Update RSSI and data if re-seen
            existing["rssi"] = entry["rssi"]
            if entry["name"]:
                existing["name"] = entry["name"]
            return

    discovered_devices.append(entry)
    print_device(entry)


def print_device(entry: Dict):
    name = entry["name"] or "(no name)"
    addr = entry["address"]
    rssi = entry["rssi"]
    company = entry["company_name"] or "Unknown"
    dtype = entry["device_type"]
    services = ", ".join(entry["service_labels"][:3]) if entry["service_labels"] else "(none)"
    txpwr = f", TX:{entry['tx_power']}dBm" if entry["tx_power"] is not None else ""

    print(f"  [{addr}]  {name:<25}  RSSI:{rssi:>4}dBm{txpwr}")
    print(f"    Company : {company}")
    print(f"    Type    : {dtype}")
    print(f"    Services: {services}")
    print()


def print_summary():
    print("\n" + "=" * 72)
    print("  BLE FINGERPRINT SUMMARY")
    print("=" * 72)
    print(f"  {'ADDRESS':<20}  {'NAME':<22}  {'RSSI':>5}  {'TYPE':<30}")
    print("  " + "-" * 70)
    for e in sorted(discovered_devices, key=lambda x: x["rssi"], reverse=True):
        name = (e["name"] or "(no name)")[:20]
        addr = e["address"]
        rssi = e["rssi"]
        dtype = e["device_type"][:28]
        print(f"  {addr:<20}  {name:<22}  {rssi:>5}  {dtype:<30}")
    print(f"\n  Total devices: {len(discovered_devices)}\n")


def save_results(output_file: str):
    with open(output_file, "w") as f:
        json.dump(discovered_devices, f, indent=2)
    print(f"[+] Results saved to: {output_file}")


# ---------------------------------------------------------------------------
# Main async scan
# ---------------------------------------------------------------------------

async def scan(timeout: float):
    print(f"[*] Starting BLE scan for {timeout}s...")
    print("[*] Press Ctrl+C to stop early.\n")
    print(f"  {'ADDRESS':<20}  {'NAME':<25}  {'RSSI':>5}  {'COMPANY'}")
    print("  " + "-" * 75)

    scanner = BleakScanner(detection_callback=process_advertisement)
    await scanner.start()
    try:
        await asyncio.sleep(timeout)
    except asyncio.CancelledError:
        pass
    finally:
        await scanner.stop()


def main():
    parser = argparse.ArgumentParser(description="BLE device fingerprinting via bleak")
    parser.add_argument("--timeout", "-t", type=float, default=15.0,
                        help="Scan duration in seconds (default: 15)")
    parser.add_argument("--output", "-o", default="",
                        help="Save results to JSON file")
    args = parser.parse_args()

    print("=" * 60)
    print("  BLE Device Fingerprinting Tool")
    print(f"  Scan timeout: {args.timeout}s")
    print("=" * 60)
    print()

    try:
        asyncio.run(scan(args.timeout))
    except KeyboardInterrupt:
        print("\n[*] Scan stopped by user.")

    print_summary()

    if args.output:
        save_results(args.output)
    elif discovered_devices:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        save_results(f"ble_fingerprint_{ts}.json")


if __name__ == "__main__":
    main()
