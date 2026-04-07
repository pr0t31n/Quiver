# BLE MITM Setup and Automation

BLE Man-in-the-Middle setup guide and command automation. Detects available tools (bettercap, GATTacker, Wireshark), enumerates GATT structure on target devices, and generates ready-to-run attack commands. Includes nRF52840 sniffer firmware setup instructions.

## Requirements
- Python 3.7+
- bleak: `pip3 install bleak`
- Optional: bettercap (`brew install bettercap` or `apt install bettercap`)
- Optional: GATTacker (`npm install -g gattacker`)
- Optional: Wireshark + nRF Sniffer plugin

## Usage
```bash
# Scan, select target, get commands:
python3 ble_mitm_setup.py

# Enumerate specific target:
python3 ble_mitm_setup.py --target AA:BB:CC:DD:EE:FF --enumerate

# Skip enumeration, just generate commands:
python3 ble_mitm_setup.py --target AA:BB:CC:DD:EE:FF --skip-enum
```

## Workflow
1. Tool availability check (bettercap, GATTacker, bleak, Wireshark)
2. BLE scan to select target device
3. GATT service/characteristic enumeration (saves to JSON)
4. Generate bettercap commands for the target
5. Generate GATTacker (Node.js) MITM proxy commands
6. Generate bleak-based GATT proxy concept code
7. nRF52840 sniffer firmware setup instructions for Wireshark capture

## nRF52840 Sniffer
Flash Nordic nRF Sniffer firmware to nRF52840 dongle for passive BLE traffic capture in Wireshark. Download from: https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE
