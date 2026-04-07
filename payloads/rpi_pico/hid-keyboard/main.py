# Raspberry Pi Pico USB HID Keyboard Injector (MicroPython)
# Requires: adafruit_hid library
# Install: mpremote mip install adafruit-circuitpython-hid  (CircuitPython build)
# Or for MicroPython: use the micropython-lib hid module
#
# Upload as main.py to auto-run on boot:
#   mpremote connect <port> cp main.py :/main.py

# ── CONFIGURE THESE ───────────────────────────────────────────────────────────
PAYLOAD = "Hello, World!"        # String to type
DELAY_BEFORE_MS  = 2000          # Wait before typing (ms) — let OS settle
DELAY_BETWEEN_MS = 50            # Delay between keystrokes (ms)
# ─────────────────────────────────────────────────────────────────────────────

import time
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS
from adafruit_hid.keycode import Keycode

time.sleep(DELAY_BEFORE_MS / 1000)

kbd = Keyboard(usb_hid.devices)
layout = KeyboardLayoutUS(kbd)

layout.write(PAYLOAD)
time.sleep(DELAY_BETWEEN_MS / 1000)
kbd.press(Keycode.ENTER)
kbd.release_all()
