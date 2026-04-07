# ESP32-D BLE Scanner (MicroPython)
# Requires MicroPython with ubluetooth support (most ESP32 builds include it)
# Upload via: mpremote connect <port> cp ble_scan.py :/ble_scan.py
# Run via:    mpremote connect <port> run ble_scan.py

import bluetooth
import time
import struct

SCAN_DURATION_MS = 10000   # 10 second scan

devices = {}

def bt_irq(event, data):
    # IRQ_SCAN_RESULT = 5
    if event == 5:
        addr_type, addr, adv_type, rssi, adv_data = data
        addr_str = ":".join("{:02x}".format(b) for b in bytes(addr))
        name = _parse_name(bytes(adv_data)) or "(unknown)"
        if addr_str not in devices or devices[addr_str]["rssi"] < rssi:
            devices[addr_str] = {"addr": addr_str, "rssi": rssi, "name": name,
                                  "addr_type": addr_type, "adv_type": adv_type}

def _parse_name(adv):
    i = 0
    while i < len(adv):
        if i + 1 >= len(adv):
            break
        length = adv[i]
        if length == 0:
            break
        ad_type = adv[i + 1]
        # 0x08 = Shortened Local Name, 0x09 = Complete Local Name
        if ad_type in (0x08, 0x09):
            return adv[i + 2:i + 1 + length].decode("utf-8", "replace")
        i += 1 + length
    return None

ble = bluetooth.BLE()
ble.active(True)
ble.irq(bt_irq)

print("Starting BLE scan for {} ms...".format(SCAN_DURATION_MS))
ble.gap_scan(SCAN_DURATION_MS, 30000, 30000)  # window=30ms, interval=30ms

start = time.ticks_ms()
while time.ticks_diff(time.ticks_ms(), start) < SCAN_DURATION_MS + 500:
    time.sleep_ms(200)

ble.gap_scan(None)  # Stop scan
ble.active(False)

print("\n=== BLE Scan Results ===")
print("{:<18}  {:>5}  {:>9}  {}".format("Address", "RSSI", "AddrType", "Name"))
print("-" * 60)
for d in sorted(devices.values(), key=lambda x: x["rssi"], reverse=True):
    atype = "Public" if d["addr_type"] == 0 else "Random"
    print("{:<18}  {:>5}  {:>9}  {}".format(d["addr"], d["rssi"], atype, d["name"]))
print("\nTotal devices found: {}".format(len(devices)))
