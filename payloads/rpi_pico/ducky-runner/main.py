# Raspberry Pi Pico DuckyScript Runner (MicroPython + adafruit_hid)
# Reads /payload.txt from the Pico filesystem and executes HID injection
#
# Upload files:
#   mpremote connect <port> cp main.py :/main.py
#   mpremote connect <port> cp payload.txt :/payload.txt

import time
import usb_hid
from adafruit_hid.keyboard import Keyboard
from adafruit_hid.keyboard_layout_us import KeyboardLayoutUS
from adafruit_hid.keycode import Keycode

# ── Keycode lookup table ──────────────────────────────────────────────────────
KEYCODES = {
    "ENTER": Keycode.ENTER, "RETURN": Keycode.ENTER,
    "TAB": Keycode.TAB, "SPACE": Keycode.SPACE,
    "BACKSPACE": Keycode.BACKSPACE, "DELETE": Keycode.DELETE,
    "ESCAPE": Keycode.ESCAPE, "ESC": Keycode.ESCAPE,
    "GUI": Keycode.GUI, "WINDOWS": Keycode.GUI, "COMMAND": Keycode.GUI,
    "CTRL": Keycode.CONTROL, "CONTROL": Keycode.CONTROL,
    "ALT": Keycode.ALT, "SHIFT": Keycode.SHIFT,
    "UP": Keycode.UP_ARROW, "DOWN": Keycode.DOWN_ARROW,
    "LEFT": Keycode.LEFT_ARROW, "RIGHT": Keycode.RIGHT_ARROW,
    "HOME": Keycode.HOME, "END": Keycode.END,
    "PAGEUP": Keycode.PAGE_UP, "PAGEDOWN": Keycode.PAGE_DOWN,
    "F1": Keycode.F1, "F2": Keycode.F2, "F3": Keycode.F3, "F4": Keycode.F4,
    "F5": Keycode.F5, "F6": Keycode.F6, "F7": Keycode.F7, "F8": Keycode.F8,
    "F9": Keycode.F9, "F10": Keycode.F10, "F11": Keycode.F11, "F12": Keycode.F12,
    "CAPSLOCK": Keycode.CAPS_LOCK,
    "PRINTSCREEN": Keycode.PRINT_SCREEN,
}

time.sleep(2.0)  # wait for host to enumerate HID device

kbd = Keyboard(usb_hid.devices)
layout = KeyboardLayoutUS(kbd)

def run_payload(path="/payload.txt"):
    try:
        with open(path, "r") as f:
            lines = f.readlines()
    except OSError:
        print("payload.txt not found")
        return

    for line in lines:
        line = line.strip()
        if not line or line.startswith("REM") or line.startswith("#"):
            continue

        if line.startswith("DELAY "):
            ms = int(line[6:].strip())
            time.sleep(ms / 1000)

        elif line.startswith("STRING "):
            layout.write(line[7:])

        elif line.startswith("STRINGLN "):
            layout.write(line[9:])
            kbd.press(Keycode.ENTER)
            kbd.release_all()

        else:
            # Key combination (e.g. "GUI r", "CTRL ALT DELETE")
            parts = line.split()
            keys = []
            for p in parts:
                kc = KEYCODES.get(p.upper())
                if kc:
                    keys.append(kc)
            if keys:
                kbd.press(*keys)
                time.sleep(0.05)
                kbd.release_all()
                time.sleep(0.05)

run_payload()
