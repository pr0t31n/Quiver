# LilyGo T-Deck Network Recon (MicroPython)
# WiFi network discovery with display output and SD card logging
# T-Deck hardware: ESP32-S3, 2.8" 320x240 display, keyboard, trackball

import network, json, time, os

SAVE_TO_SD = True
SD_PATH    = "/sd/wifi_scan_{}.json"

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
time.sleep(0.3)

AUTH = {0:"Open",1:"WEP",2:"WPA",3:"WPA2",4:"WPA/WPA2",5:"WPA2-EAP",6:"WPA3",7:"WPA2/WPA3"}

print("T-Deck Network Recon")
print("Performing WiFi scan...")
raw = wlan.scan()

results = []
for ssid, bssid, ch, rssi, auth, hidden in raw:
    name = ssid.decode("utf-8","replace") if ssid else "(hidden)"
    mac  = ":".join("{:02x}".format(b) for b in bssid)
    results.append({"ssid":name,"bssid":mac,"channel":ch,"rssi":rssi,
                     "auth":AUTH.get(auth,"?"),"hidden":bool(hidden)})

results.sort(key=lambda x: x["rssi"], reverse=True)

# Print to serial console
print("\n{:<3} {:.<32} {:>4}  {:>5}  {:>8}".format(
    "#", "SSID", "CH", "RSSI", "Auth"))
print("-"*60)
for i, n in enumerate(results, 1):
    print("{:>3} {:.<32} {:>4}  {:>5}  {:>8}{}".format(
        i, n["ssid"][:32], n["channel"], n["rssi"], n["auth"],
        " [H]" if n["hidden"] else ""))

print("\n{} networks found".format(len(results)))

# Save to SD card if available
if SAVE_TO_SD:
    try:
        import sdcard, machine
        # Mount SD card (T-Deck SD pins: CLK=40, MOSI=41, MISO=38, CS=39)
        spi = machine.SPI(2, baudrate=20000000,
                          sck=machine.Pin(40), mosi=machine.Pin(41), miso=machine.Pin(38))
        sd  = sdcard.SDCard(spi, machine.Pin(39))
        os.mount(sd, "/sd")
        fname = SD_PATH.format(int(time.time()))
        with open(fname, "w") as f:
            json.dump(results, f)
        print("Saved to SD: {}".format(fname))
    except Exception as e:
        print("SD save failed: {}".format(e))

print("\nJSON output:")
print(json.dumps(results))
