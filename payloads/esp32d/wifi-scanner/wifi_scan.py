# ESP32-D WiFi Scanner (MicroPython)
# Upload via: mpremote connect <port> cp wifi_scan.py :/wifi_scan.py
# Run via:    mpremote connect <port> run wifi_scan.py
# Or from REPL: import wifi_scan

import network
import json
import time

def scan():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    time.sleep(0.5)

    print("Scanning for WiFi networks...")
    results = wlan.scan()  # Returns list of (ssid, bssid, channel, RSSI, authmode, hidden)

    AUTH_MODES = {0: "Open", 1: "WEP", 2: "WPA-PSK", 3: "WPA2-PSK",
                  4: "WPA/WPA2-PSK", 5: "WPA2-EAP", 6: "WPA3-PSK", 7: "WPA2/WPA3-PSK"}

    networks = []
    for ssid, bssid, channel, rssi, authmode, hidden in results:
        entry = {
            "ssid":   ssid.decode("utf-8", "replace") if ssid else "(hidden)",
            "bssid":  ":".join("{:02x}".format(b) for b in bssid),
            "channel": channel,
            "rssi":   rssi,
            "auth":   AUTH_MODES.get(authmode, "Unknown"),
            "hidden": bool(hidden),
        }
        networks.append(entry)
        print("  SSID: {:32s}  CH:{:3d}  RSSI:{:4d}  Auth: {}{}".format(
            entry["ssid"][:32], channel, rssi,
            entry["auth"], "  [hidden]" if hidden else ""))

    print("\nTotal networks found: {}".format(len(networks)))
    print("\nJSON output:")
    print(json.dumps(networks))
    return networks

scan()
