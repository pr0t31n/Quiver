#!/usr/bin/env python3
"""
LilyGo T-Deck ESP32-S3 Tool Manager
Handles device info, firmware flashing, MicroPython installation,
and payload management for the LilyGo T-Deck.

Hardware overview:
  SoC:      ESP32-S3 (Xtensa LX7 dual-core 240MHz, 8MB PSRAM, 16MB Flash)
  Display:  2.8" TFT touchscreen 320x240 (SPI, ST7789 controller)
  Input:    QWERTY keyboard (I2C, similar to BlackBerry Q20 — LILYGO KB scan)
  Trackball: GPIO-based
  Radio:    LoRa SX1276 or SX1262 (433/868/915 MHz) depending on hardware revision
  Audio:    Speaker + microphone
  Power:    USB-C with charging, LiPo battery connector
  USB:      Native ESP32-S3 USB CDC (no external USB-serial chip in most revisions)

USB identifiers:
  VID:PID 303A:1001 — ESP32-S3 native USB CDC (most T-Deck units)
  VID:PID 10C4:EA60 — CP2102 variant (some older T-Deck revisions)
  VID:PID 1A86:55D4 — CH9102 variant

DFU / flash mode:
  Hold the keyboard 'T' key (or BOOT pin) while connecting USB to enter download mode.
  Alternatively, use esptool --after hard_reset to exit automatically.

Linux serial access:
  Native USB CDC appears as /dev/ttyACM0.
  CP2102 variant appears as /dev/ttyUSB0.
  Add user to dialout: sudo usermod -aG dialout $USER

Usage:
    python3 lilygo_tdeck.py
"""

import subprocess
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, ensure_pip_packages, ensure_system_tool,
    require_sudo, sudo_run, sudo_output,
    ensure_apt_packages, ensure_brew_packages,
    web_detect_loop, run_streaming,
    check_latest_github_release, announce_firmware_update,
)

TOOL_NAME   = "LilyGo T-Deck"
DESCRIPTION = "LilyGo T-Deck — ESP32-S3 with LoRa, QWERTY keyboard, 2.8\" TFT"

VID_PIDS = [
    (0x303A, 0x1001),   # ESP32-S3 native USB CDC (most revisions)
    (0x10C4, 0xEA60),   # CP2102 variant
    (0x1A86, 0x55D4),   # CH9102 variant
]

ESP_CHIP = "esp32s3"

CONNECT_INSTRUCTIONS = (
    "LilyGo T-Deck not detected.\n\n"
    "  1. Connect the T-Deck via USB-C cable\n"
    "  2. The device should appear as:\n"
    "       /dev/ttyACM0  (native USB CDC, most units — VID:PID 303A:1001)\n"
    "       /dev/ttyUSB0  (CP2102 variant — VID:PID 10C4:EA60)\n\n"
    "  3. To enter firmware flash mode:\n"
    "       Hold keyboard 'T' key (or BOOT pad) while connecting USB\n"
    "       Or: press BOOT + RST, release RST, release BOOT\n\n"
    "  4. Linux permission fix:\n"
    "       sudo usermod -aG dialout $USER  (then log out and back in)\n"
    "       Quick: sudo chmod 666 /dev/ttyACM0\n\n"
    "  5. macOS: native USB CDC needs no driver. CP2102 may need:\n"
    "       https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers\n\n"
    "  6. Debug: lsusb | grep -E '303a|10c4|1a86'"
)

UDEV_RULES_CONTENT = """\
# LilyGo T-Deck udev rules
# ESP32-S3 native USB CDC (VID:PID 303A:1001)
SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", MODE="0666", GROUP="dialout"
# CP2102 (VID:PID 10C4:EA60)
SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", MODE="0666", GROUP="dialout"
# CH9102 (VID:PID 1A86:55D4)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="55d4", MODE="0666", GROUP="dialout"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-lilygo-tdeck.rules"

MICROPYTHON_URL = "https://micropython.org/download/ESP32_GENERIC_S3/"


def detect_device():
    return find_serial_port_by_vidpid(VID_PIDS) is not None


def _check_udev_rules():
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for LilyGo T-Deck…")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH}")
        info("Unplug and replug the T-Deck to apply new permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual: sudo tee {UDEV_RULES_PATH}")
        info(UDEV_RULES_CONTENT)
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")

    # Load relevant kernel modules
    for mod in ("cp210x", "ch341"):
        out = run_output(f"lsmod 2>/dev/null | grep {mod}")
        if out:
            ok(f"Kernel module '{mod}' loaded.")
        else:
            info(f"Loading kernel module '{mod}'…")
            r2 = sudo_run(f"modprobe {mod} 2>/dev/null")
            if r2.returncode == 0:
                ok(f"Module '{mod}' loaded.")
            else:
                info(f"Module '{mod}' not available (normal for native USB variant).")


def _require_file(path_str, ext=None):
    if not path_str:
        warn("No file path provided.")
        return None
    p = Path(path_str)
    if not p.exists():
        err(f"File not found: {p}")
        info("Tip: use an absolute path, e.g. /home/user/firmware.bin")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


def _run_esptool(args, timeout=180):
    """Run esptool as a Python module with streaming output."""
    cmd = [sys.executable, "-m", "esptool"] + args
    info(f"Running: {' '.join(cmd)}")
    info("Troubleshooting:")
    info("  'Failed to connect' → Hold keyboard 'T' key, press RST, release 'T'")
    info("  'Wrong chip'        → Ensure esp32s3 chip type is specified")
    info("  'Permission denied' → sudo usermod -aG dialout $USER")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(f"  esptool: {l}"), timeout=timeout)
        return rc
    except FileNotFoundError:
        err("esptool not found.")
        info("Install: pip install esptool --break-system-packages")
        return 1
    except Exception as e:
        err(f"esptool execution error: {e}")
        return 1


def op_device_info(port):
    heading("Device Info")
    info(f"Serial port : {port}")
    info(f"Chip type   : {ESP_CHIP} (Xtensa LX7 dual-core, 240 MHz)")
    info("")
    info("T-Deck hardware summary:")
    info("  Display  : 2.8\" TFT 320x240, ST7789, SPI")
    info("  Keyboard : QWERTY I2C (LILYGO KB — address 0x55)")
    info("  Trackball: GPIO 0 (UP), 3 (DOWN), 15 (LEFT), 21 (RIGHT), 38 (CLICK)")
    info("  LoRa     : SX1276 or SX1262 depending on hardware revision")
    info("  Speaker  : GPIO 46 (I2S) or simple PWM depending on revision")
    info("  Battery  : 3.7V LiPo via IP5306 or axp2101 PMIC")
    info("")

    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.device == port:
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
                if p.vid == 0x303A:
                    info("  USB type    : Native ESP32-S3 USB CDC")
                elif p.vid == 0x10C4:
                    info("  USB type    : CP2102 UART bridge")
                elif p.vid == 0x1A86:
                    info("  USB type    : CH9102 UART bridge")
    except Exception as e:
        warn(f"Could not read serial metadata: {e}")

    info("")
    info("Running chip_id to identify ESP32-S3 variant…")
    rc = _run_esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "115200", "chip_id"])
    if rc == 0:
        ok("Device info retrieved successfully.")
    else:
        err("chip_id failed. Try holding BOOT key when entering the command.")


def op_flash_firmware(port):
    heading("Flash Application Firmware")
    info("Flash a compiled .bin firmware file to the T-Deck.")
    info("")
    info("ESP32-S3 flash layout (typical for T-Deck Arduino/ESP-IDF builds):")
    info("  0x0000  — bootloader.bin")
    info("  0x8000  — partitions.bin")
    info("  0xe000  — boot_app0.bin")
    info("  0x10000 — app.bin (your application)")
    info("")
    info("For merged firmware (single .bin): flash at offset 0x0")
    info("  This is common for pre-compiled T-Deck firmware releases.")
    info("")
    info("T-Deck Arduino library and firmware:")
    info("  https://github.com/Xinyuan-LilyGO/T-Deck")
    info("")
    info("Flash mode for T-Deck: qio (ESP32-S3 default)")
    info("Flash size: 16MB (detect works too)")
    info("")

    firmware_path = prompt("Path to .bin firmware file")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return

    offset = prompt("Flash offset (default: 0x0 for merged firmware, or 0x10000 for app-only)")
    if not offset:
        offset = "0x0"
    offset = offset.strip()

    if not confirm(f"Flash {fw.name} at offset {offset} on {port}?"):
        info("Cancelled.")
        return

    info(f"Flashing {fw.name} at {offset}…")
    info("If this fails: hold keyboard 'T', press RST on the T-Deck, release 'T'.")
    rc = _run_esptool([
        "--chip", ESP_CHIP, "--port", port, "--baud", "921600",
        "write_flash", "--flash_mode", "qio", "--flash_size", "detect",
        offset, str(fw),
    ], timeout=300)
    if rc == 0:
        ok("Firmware flashed successfully. T-Deck will reboot.")
    else:
        err("Flash failed. Try lowering baud rate or using a different USB cable.")
        info("Retry with: esptool --chip esp32s3 --port {port} --baud 460800 write_flash ...")


def op_flash_micropython(port):
    heading("Flash MicroPython for ESP32-S3")
    info("Flash MicroPython to the T-Deck's ESP32-S3.")
    info("")
    info("Download MicroPython for ESP32-S3 (GENERIC build):")
    info(f"  {MICROPYTHON_URL}")
    info("  File: ESP32_GENERIC_S3-YYYYMMDD-vX.Y.Z.bin")
    info("")
    info("IMPORTANT NOTES for T-Deck:")
    info("  - Standard MicroPython does NOT include T-Deck display drivers (ST7789)")
    info("  - Standard MicroPython does NOT include keyboard drivers")
    info("  - For full T-Deck support, use MicroPython + LVGL or a custom build")
    info("  - Basic GPIO, I2C, SPI, UART, WiFi, BLE work with standard MicroPython")
    info("  - LoRa requires SX127x/SX126x MicroPython driver library")
    info("")
    info("Custom MicroPython builds with display support:")
    info("  https://github.com/russhughes/st7789_mpy (ST7789 driver)")
    info("  https://github.com/lv-micropython/lvgl (MicroPython + LVGL UI)")
    info("")

    firmware_path = prompt(f"Path to MicroPython .bin file (download from {MICROPYTHON_URL})")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return

    if not confirm(f"Erase flash and install MicroPython from {fw.name} on {port}?"):
        info("Cancelled.")
        return

    info("Step 1/2: Erasing flash…")
    info("  If this hangs: hold keyboard 'T', press RST, release 'T'")
    rc_erase = _run_esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "921600", "erase_flash"], timeout=60)
    if rc_erase != 0:
        err("Erase failed. Cannot proceed.")
        return
    ok("Flash erased.")

    info("Step 2/2: Writing MicroPython firmware at offset 0x0…")
    rc_flash = _run_esptool([
        "--chip", ESP_CHIP, "--port", port, "--baud", "460800",
        "write_flash", "--flash_mode", "qio", "--flash_size", "detect",
        "0x0", str(fw),
    ], timeout=300)
    if rc_flash == 0:
        ok("MicroPython installed successfully.")
        info(f"Connect to REPL: mpremote connect {port} repl")
    else:
        err("MicroPython flash failed.")
        info("Try lowering baud to 115200.")


def op_upload_script(port):
    heading("Upload MicroPython Script")
    info("Upload a .py script to the T-Deck's MicroPython filesystem via mpremote.")
    info("")
    info("mpremote quick reference:")
    info(f"  mpremote connect {port} repl              — interactive REPL")
    info(f"  mpremote connect {port} ls :/             — list files")
    info(f"  mpremote connect {port} cp file.py :/     — upload to root")
    info("")

    local_path = prompt("Path to local .py file")
    local = _require_file(local_path, ".py")
    if not local:
        return
    remote_name = prompt(f"Remote filename (default: {local.name})")
    if not remote_name:
        remote_name = local.name

    info(f"Uploading {local.name} → :{remote_name} …")
    try:
        result = subprocess.run(
            ["mpremote", "connect", port, "cp", str(local), f":{remote_name}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            ok(f"Uploaded: {remote_name}")
        else:
            err(f"Upload failed (exit {result.returncode})")
            if result.stderr:
                err(f"  stderr: {result.stderr.strip()[:400]}")
    except FileNotFoundError:
        err("mpremote not found. Install: pip install mpremote --break-system-packages")
    except Exception as e:
        err(f"Upload error: {e}")


def op_wifi_scan_info():
    heading("WiFi Scan and Deauth Payload Info")
    info("The T-Deck's ESP32-S3 has built-in 802.11 b/g/n WiFi.")
    info("")
    info("Available payloads:")
    info("  payloads/lilygo_tdeck/wifi-deauth/main.py    — WiFi deauthentication scan/attack")
    info("  payloads/lilygo_tdeck/network-recon/main.py  — Network reconnaissance with display")
    info("")
    info("Deauthentication frames:")
    info("  Standard ESP-IDF WiFi stack does NOT expose deauth frame injection.")
    info("  To send deauth frames, you need:")
    info("    Option A: Custom firmware with esp_wifi_80211_tx() raw frame injection")
    info("    Option B: Flipper Zero-style deauth firmware (community builds)")
    info("    Option C: Arduino sketch using WiFi raw packet injection patch")
    info("  For ethical/authorized testing only!")
    info("")
    info("Network recon (no special firmware needed):")
    info("  - WiFi scan: list SSIDs, BSSIDs, channels, RSSI")
    info("  - Results can be shown on the T-Deck's 2.8\" display")
    info("  - Upload payloads/lilygo_tdeck/network-recon/main.py as main.py")
    info("")
    info("T-Deck display usage in MicroPython (with ST7789 driver):")
    info("  from machine import SPI, Pin")
    info("  import st7789")
    info("  spi = SPI(2, baudrate=40000000, polarity=0, phase=0,")
    info("            sck=Pin(40), mosi=Pin(41), miso=Pin(38))")
    info("  tft = st7789.ST7789(spi, 240, 320, reset=Pin(42), cs=Pin(12), dc=Pin(11))")
    info("  tft.fill(0x0000)  # clear screen black")
    info("  tft.text('Hello T-Deck!', 10, 10, 0xFFFF)")


def op_lora_info():
    heading("LoRa Radio Info")
    info("The T-Deck includes a LoRa radio module depending on hardware revision:")
    info("")
    info("Revision T-Deck (standard):")
    info("  LoRa chip : SX1276 (HopeRF RFM95W compatible)")
    info("  Frequency : 433 MHz / 868 MHz / 915 MHz (region-specific)")
    info("  Sensitivity: -148 dBm")
    info("  TX power  : up to +20 dBm")
    info("  SPI pins  : SCK=40, MOSI=41, MISO=38, CS=9, RST=17, DIO0=45")
    info("")
    info("Revision T-Deck Plus (newer):")
    info("  LoRa chip : SX1262")
    info("  Better sensitivity and power control than SX1276")
    info("  SPI pinout may differ — check LilyGo GitHub for exact pins")
    info("")
    info("Programming options:")
    info("")
    info("Arduino (recommended for LoRa):")
    info("  Library: https://github.com/sandeepmistry/arduino-LoRa")
    info("  Or: RadioLib (supports both SX1276 and SX1262)")
    info("  T-Deck example sketches: https://github.com/Xinyuan-LilyGO/T-Deck")
    info("")
    info("MicroPython (limited LoRa support):")
    info("  SX127x: https://github.com/wybiral/micropython-lora (community)")
    info("  SX126x: https://github.com/ehong-tl/micropySX126X")
    info("  Basic usage (SX1276):")
    info("    from machine import SPI, Pin")
    info("    from sx1276 import SX1276")
    info("    lora = SX1276(spi, cs=Pin(9), rst=Pin(17), dio0=Pin(45))")
    info("    lora.set_freq(915E6)  # 915 MHz")
    info("    lora.send(b'Hello LoRa!')")
    info("")
    info("LoRaWAN (internet connectivity):")
    info("  Library: uLoRaWAN or Arduino LMIC")
    info("  Requires TTN (The Things Network) or ChirpStack server")
    info("  See: https://www.thethingsnetwork.org/")
    info("")
    info("WARNING: LoRa transmission regulations vary by region.")
    info("  EU: 868 MHz, max 14 dBm, duty cycle limits apply")
    info("  US: 915 MHz, max 20 dBm, frequency hopping")
    info("  Always comply with local RF regulations!")


def op_repl_info():
    heading("MicroPython REPL Info")
    info("Access the T-Deck's MicroPython REPL.")
    info("")
    info("mpremote: mpremote connect /dev/ttyACM0 repl")
    info("  Ctrl+]  — exit | Ctrl+C — interrupt | Ctrl+D — soft reset")
    info("")
    info("minicom:  minicom -D /dev/ttyACM0 -b 115200")
    info("screen:   screen /dev/ttyACM0 115200")
    info("")
    info("T-Deck GPIO reference (MicroPython):")
    info("  from machine import Pin, I2C, SPI")
    info("  # Keyboard (I2C)")
    info("  i2c = I2C(0, sda=Pin(18), scl=Pin(8))")
    info("  # Display SPI")
    info("  spi = SPI(2, baudrate=40000000, sck=Pin(40), mosi=Pin(41))")
    info("  # Trackball buttons")
    info("  btn_up    = Pin(0,  Pin.IN, Pin.PULL_UP)")
    info("  btn_down  = Pin(3,  Pin.IN, Pin.PULL_UP)")
    info("  btn_left  = Pin(15, Pin.IN, Pin.PULL_UP)")
    info("  btn_right = Pin(21, Pin.IN, Pin.PULL_UP)")
    info("  btn_click = Pin(38, Pin.IN, Pin.PULL_UP)")


def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Checking MicroPython version (if installed)...")
    info("  Note: This only works if MicroPython is flashed on the T-Deck (ESP32-S3).")
    info("  For custom firmware, version checking requires the firmware to expose a version string.")
    current = None
    try:
        import subprocess as _sp
        r = _sp.run(
            ["mpremote", "connect", port, "exec",
             "import sys; print(sys.version.split()[0])"],
            capture_output=True, text=True, timeout=8,
        )
        if r.returncode == 0 and r.stdout.strip():
            import re
            m = re.search(r'MicroPython\s+v?([\d.]+)', r.stdout)
            if m:
                current = m.group(1)
    except Exception as e:
        info(f"  MicroPython version query failed: {e}")

    if current:
        ok(f"Installed MicroPython version: {current}")
        info("Checking latest MicroPython for ESP32-S3 on GitHub...")
        latest, url = check_latest_github_release("micropython", "micropython")
        if latest:
            announce_firmware_update(TOOL_NAME + " (MicroPython)", current, latest.lstrip("v"), url)
        else:
            warn("Could not reach GitHub for version check.")
    else:
        info("MicroPython not detected or not responding.")
        info("Install MicroPython via 'Flash MicroPython' menu option.")
        info(f"Latest MicroPython for ESP32-S3: {MICROPYTHON_URL}")


def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Dependency Check")
    flavor = get_os_flavor()

    info("Checking for esptool (required for firmware flashing)…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["esptool", "python3-serial"])
    elif flavor == "macos":
        ensure_brew_packages(["esptool"])
    ensure_pip_packages([("esptool", "esptool>=4.7"), ("serial", "pyserial")])

    info("Checking for mpremote (required for MicroPython script upload)…")
    ensure_pip_packages([("mpremote", "mpremote")])

    _check_udev_rules()

    heading("Device Detection")
    info("Scanning for LilyGo T-Deck via VID:PID 303A:1001 / 10C4:EA60 / 1A86:55D4…")
    info("Expected: /dev/ttyACM0 (native USB) or /dev/ttyUSB0 (CP2102/CH9102)")
    info("")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("LilyGo T-Deck not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Device appeared but serial port could not be resolved. Exiting.")
        info("Debug: dmesg | tail -20  or  ls /dev/ttyACM* /dev/ttyUSB*")
        sys.exit(1)

    ok(f"LilyGo T-Deck detected on {port}")
    check_firmware_version(port)

    MENU_OPTIONS = [
        "Device Info (chip_id, hardware info)",
        "FIRMWARE - Flash Application Firmware (.bin file)",
        "FIRMWARE - Flash MicroPython for ESP32-S3",
        "Upload MicroPython Script (mpremote cp)",
        "WiFi Scan and Deauth Payload Info",
        "LoRa Radio Info and Usage",
        "REPL Info (mpremote, minicom, GPIO reference)",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_firmware(port)
        elif choice == 2:
            op_flash_micropython(port)
        elif choice == 3:
            op_upload_script(port)
        elif choice == 4:
            op_wifi_scan_info()
        elif choice == 5:
            op_lora_info()
        elif choice == 6:
            op_repl_info()
        elif choice == 7:
            info("Goodbye.")
            break

        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
