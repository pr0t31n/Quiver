# BLE Device Fingerprinting

Bluetooth LE device fingerprinting using the bleak Python library. Performs passive BLE advertisement scanning and identifies device characteristics from advertisement data.

## Requirements
- Python 3.7+
- bleak: `pip3 install bleak`
- BLE-capable host adapter (built-in or USB dongle)

## Usage
```bash
python3 ble_fingerprint.py
python3 ble_fingerprint.py --timeout 30
python3 ble_fingerprint.py --output fingerprint.json
```

## Collected Data per Device
- MAC address (address type: public / random)
- RSSI (signal strength)
- Device name / local name
- Company identifier (OUI lookup from Bluetooth SIG list)
- Service UUIDs with GATT service name labels
- Device type inference (Heart Rate Monitor, HID, Smart Scale, etc.)
- TX Power Level
- Manufacturer-specific advertisement data

## Output
- Live per-device display as devices are discovered
- Summary table sorted by RSSI
- JSON file: `ble_fingerprint_YYYYMMDD_HHMMSS.json`
