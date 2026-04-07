# LilyGo T-Deck WiFi Deauth Tool (MicroPython / ESP32-S3)
# NOTE: Requires custom MicroPython build with raw 802.11 frame injection support
#       Standard MicroPython does NOT include frame injection.
#       Use Marauder firmware or ESP32 Deauther firmware for production use.
#
# This script demonstrates the scanning portion using standard MicroPython.
# For frame injection, use: https://github.com/justcallmekoko/ESP32Marauder

import network
import time
import json

# T-Deck display setup (requires T-Deck MicroPython build with display support)
try:
    import st7789
    import vga2_bold_16x16 as font
    HAS_DISPLAY = True
except ImportError:
    HAS_DISPLAY = False

wlan = network.WLAN(network.STA_IF)
wlan.active(True)

print("=== T-Deck WiFi Scanner ===")
print("Scanning for networks...")

if HAS_DISPLAY:
    # Display init would go here with T-Deck specific pin config
    pass

results = wlan.scan()
AUTH = {0:"Open", 1:"WEP", 2:"WPA-PSK", 3:"WPA2-PSK", 4:"WPA/WPA2", 5:"WPA2-EAP"}

networks = []
for ssid, bssid, ch, rssi, auth, hidden in results:
    name = ssid.decode("utf-8","replace") if ssid else "(hidden)"
    entry = {"ssid": name, "bssid": ":".join("{:02x}".format(b) for b in bssid),
             "ch": ch, "rssi": rssi, "auth": AUTH.get(auth,"Unk")}
    networks.append(entry)

networks.sort(key=lambda x: x["rssi"], reverse=True)

print("\n{:<3}  {:<32}  {:<6}  {:<5}  {}".format("#", "SSID", "CH", "RSSI", "Auth"))
print("-" * 65)
for i, n in enumerate(networks, 1):
    print("{:<3}  {:<32}  {:<6}  {:<5}  {}".format(
        i, n["ssid"][:32], n["ch"], n["rssi"], n["auth"]))

print("\nTotal: {} networks".format(len(networks)))
print("\nNOTE: Deauthentication requires frame injection firmware.")
print("For full WiFi attack capabilities, flash ESP32 Marauder:")
print("  https://github.com/justcallmekoko/ESP32Marauder")
print("Or ESP32 Deauther:")
print("  https://github.com/SpacehuhnTech/esp8266_deauther")
