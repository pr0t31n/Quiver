#!/usr/bin/env python3
"""
Heltec WiFi LoRa32 v3 Tool Manager
Handles device info, application firmware flashing, full partition flashing,
MicroPython flashing, and MicroPython script upload/run via mpremote.

ESP32-S3 chip, SX1262 LoRa radio, 8MB flash.
Merged firmware binary is flashed at 0x0 for ESP32-S3.

Usage:
    python3 heltec_lora32_v3.py
"""

import subprocess
import sys
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, ensure_apt_packages, ensure_pip_packages,
    ensure_system_tool, require_sudo, sudo_run,
    web_detect_loop, run_streaming,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Heltec WiFi LoRa32 v3"
DESCRIPTION = "ESP32-S3 + SX1262 LoRa development board, 8MB flash"

VID_PIDS = [
    (0x10C4, 0xEA60),  # CP2102
    (0x303A, 0x1001),  # ESP32-S3 native USB
]

CONNECT_INSTRUCTIONS = (
    "Heltec WiFi LoRa32 v3 not detected.\n\n"
    "  1. Connect via USB cable (CP2102 bridge or ESP32-S3 native USB)\n"
    "  2. Linux: ensure udev rules are in place (see below)\n"
    "     CP2102:   /etc/udev/rules.d/ with 10C4:EA60\n"
    "     S3 native: /etc/udev/rules.d/ with 303A:1001\n"
    "  3. If auto-reset fails during flash:\n"
    "     Hold PRG button → tap RST → release PRG\n\n"
    "  VID:PID: 10C4:EA60 (CP2102) or 303A:1001 (S3 native USB)\n\n"
    "  Board notes:\n"
    "    - ESP32-S3 dual-core Xtensa @ 240 MHz, 8 MB flash, 8 MB PSRAM\n"
    "    - SX1262 LoRa radio (frequency band depends on hardware variant)\n"
    "    - OLED display via I2C (SSD1306 128x64)\n"
    "    - Pin 36 = OLED SDA, Pin 37 = OLED SCL, Pin 38 = OLED RST\n"
    "    - LoRa: MOSI=10, MISO=11, SCK=9, NSS=8, RST=12, DIO1=14, BUSY=13"
)

BOOTLOADER_NOTE = (
    "If flashing fails:\n"
    "  1. Hold PRG button, tap RST button, release PRG (enters download mode)\n"
    "  2. Re-run the flash operation immediately\n"
    "  3. If still failing, check USB cable and try a lower baud rate (460800)\n"
    "  4. Ensure no other process (serial monitor) has the port open"
)

UDEV_NOTE = (
    "Linux udev rules for Heltec LoRa32 v3:\n"
    "  CP2102 (10C4:EA60):\n"
    "    echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"10c4\", ATTR{idProduct}==\"ea60\", MODE=\"0666\", GROUP=\"dialout\"' \\\n"
    "    | sudo tee /etc/udev/rules.d/99-cp210x.rules\n"
    "  ESP32-S3 native USB (303A:1001):\n"
    "    echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"303a\", ATTR{idProduct}==\"1001\", MODE=\"0666\", GROUP=\"dialout\"' \\\n"
    "    | sudo tee /etc/udev/rules.d/99-esp32s3.rules\n"
    "  Then: sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "  Also add your user to the dialout group: sudo usermod -aG dialout $USER"
)

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_file(file_path: str, ext: str = None) -> Path | None:
    if not file_path:
        warn("No file path provided. Aborting.")
        return None
    p = Path(file_path)
    if not p.exists():
        err(f"File not found: {p}")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


def _check_udev():
    """Warn about udev rules on Linux if not already set up."""
    if get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        import shutil
        if shutil.which("udevadm"):
            info("Tip: If device is not accessible, ensure udev rules are installed.")
            info(UDEV_NOTE)


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info(f"Serial port: {port}")
    info("Reading port metadata from pyserial...")
    from serial.tools import list_ports
    for p in list_ports.comports():
        if p.device == port:
            info(f"Description : {p.description}")
            info(f"Manufacturer: {p.manufacturer or 'N/A'}")
            vid = f"0x{p.vid:04X}" if p.vid else "N/A"
            pid = f"0x{p.pid:04X}" if p.pid else "N/A"
            info(f"VID:PID     : {vid}:{pid}")

    info("Running esptool chip_id and flash_id to read chip info from the ESP32-S3...")
    info("Expected: chip type 'ESP32-S3', flash size '8MB'")
    info("If this hangs, the board may need to be manually put in download mode.")
    info(BOOTLOADER_NOTE)
    for sub_cmd in ["chip_id", "flash_id"]:
        cmd = [
            sys.executable, "-m", "esptool",
            "--chip", "esp32s3",
            "--port", port,
            sub_cmd,
        ]
        try:
            run_streaming(cmd, on_line=lambda l: info(l), timeout=30)
        except Exception as e:
            warn(f"esptool {sub_cmd} failed: {e}")
    ok("Device info complete.")


def op_flash_app_firmware(port: str):
    heading("Flash Application Firmware")
    info("ESP32-S3 uses merged binaries — the entire flash image is written at address 0x0.")
    info("This is different from classic ESP32 which writes the app at 0x10000.")
    info("Expected duration: ~30-90 seconds depending on firmware size.")
    info(BOOTLOADER_NOTE)
    firmware_path = prompt("Path to merged .bin firmware file")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return
    if not confirm(f"Flash {fw.name} to 0x0 on {port}?"):
        info("Flash cancelled.")
        return

    info(f"Flashing application firmware: {fw.name}...")
    info("If you see 'Failed to connect': hold PRG, tap RST, release PRG, then retry.")
    cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32s3",
        "--port", port,
        "--baud", "921600",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_size", "8MB",
        "0x0", str(fw),
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=180)
        ok("Application firmware flash complete.")
    except Exception as e:
        err(f"Flash failed: {e}")
        info(BOOTLOADER_NOTE)


def op_flash_full_partition_set(port: str):
    heading("Flash Full Partition Set")
    info("Writing individual partition binaries at their respective addresses.")
    info("ESP32-S3 partition layout:")
    info("  bootloader.bin  → 0x0     (ESP32-S3 bootloader always at 0x0)")
    info("  partitions.bin  → 0x8000")
    info("  boot_app0.bin   → 0xe000")
    info("  app.bin         → 0x10000")
    info("All four files are required. Operation will abort if any file is missing.")
    info(BOOTLOADER_NOTE)

    bootloader_path = prompt("Path to bootloader.bin")
    bootloader = _require_file(bootloader_path, ".bin")
    if not bootloader:
        return

    partitions_path = prompt("Path to partitions.bin")
    partitions = _require_file(partitions_path, ".bin")
    if not partitions:
        return

    boot_app0_path = prompt("Path to boot_app0.bin")
    boot_app0 = _require_file(boot_app0_path, ".bin")
    if not boot_app0:
        return

    app_path = prompt("Path to app.bin")
    app = _require_file(app_path, ".bin")
    if not app:
        return

    if not confirm(f"Flash all four partitions to {port}?"):
        info("Flash cancelled.")
        return

    info("Flashing full partition set...")
    cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32s3",
        "--port", port,
        "--baud", "921600",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_size", "8MB",
        "0x0",     str(bootloader),
        "0x8000",  str(partitions),
        "0xe000",  str(boot_app0),
        "0x10000", str(app),
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=240)
        ok("Full partition flash complete.")
    except Exception as e:
        err(f"Full partition flash failed: {e}")
        info(BOOTLOADER_NOTE)


def op_flash_micropython(port: str):
    heading("Flash MicroPython")
    info("MicroPython for ESP32-S3 is a combined image flashed at address 0x0.")
    info("The flash will be fully erased first — all existing data will be lost.")
    info("Download ESP32-S3 MicroPython from: https://micropython.org/download/ESP32_GENERIC_S3/")
    info(BOOTLOADER_NOTE)
    firmware_path = prompt("Path to micropython-esp32s3.bin")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return
    if not confirm(f"Erase flash and install MicroPython from {fw.name} on {port}?"):
        info("Flash cancelled.")
        return

    info("Erasing flash (this takes ~10 seconds)...")
    erase_cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32s3",
        "--port", port,
        "--baud", "921600",
        "erase_flash",
    ]
    try:
        run_streaming(erase_cmd, on_line=lambda l: info(l), timeout=60)
    except Exception as e:
        err(f"Erase failed: {e}")
        info(BOOTLOADER_NOTE)
        return

    info(f"Flashing MicroPython: {fw.name}...")
    flash_cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32s3",
        "--port", port,
        "--baud", "921600",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_size", "8MB",
        "0x0", str(fw),
    ]
    try:
        run_streaming(flash_cmd, on_line=lambda l: info(l), timeout=180)
        ok("MicroPython flash complete.")
        info("After reset, connect with: mpremote connect " + port + " repl")
    except Exception as e:
        err(f"MicroPython flash failed: {e}")
        info(BOOTLOADER_NOTE)


def op_upload_micropython_script(port: str):
    heading("Upload MicroPython Script")
    info("Uses mpremote to copy a local .py file to the board's filesystem.")
    info("The board must be running MicroPython (not in download mode).")
    local_path = prompt("Path to local .py file")
    local = _require_file(local_path, ".py")
    if not local:
        return
    remote_name = prompt(f"Remote filename on device (default: {local.name})")
    if not remote_name:
        remote_name = local.name

    info(f"Uploading {local.name} → :{remote_name} via mpremote...")
    info("If this fails with 'could not enter raw repl', the board may not be running MicroPython.")
    try:
        subprocess.run(
            ["mpremote", "connect", port, "cp", str(local), f":{remote_name}"],
            check=True,
        )
        ok(f"Uploaded: {remote_name}")
    except subprocess.CalledProcessError as e:
        err(f"Upload failed: {e}")
        info("Ensure mpremote is installed: pip install mpremote --break-system-packages")
    except FileNotFoundError:
        err("mpremote not found. Install with: pip install mpremote --break-system-packages")


def op_run_micropython_script(port: str):
    heading("Run MicroPython Script")
    info("Uses mpremote to run a script already on the board's filesystem.")
    remote_name = prompt("Remote script name to run (e.g. main.py)")
    if not remote_name:
        warn("No script name provided. Aborting.")
        return
    info(f"Running {remote_name} on device via mpremote...")
    try:
        subprocess.run(
            ["mpremote", "connect", port, "run", remote_name],
            check=True,
        )
        ok("Script executed.")
    except subprocess.CalledProcessError as e:
        err(f"Run failed: {e}")
    except FileNotFoundError:
        err("mpremote not found. Install with: pip install mpremote --break-system-packages")


def op_micropython_repl():
    heading("MicroPython REPL")
    info("Use the Shell tab for MicroPython REPL access.")
    info("Suggested command:  mpremote connect <port> repl")
    info("In REPL, Ctrl-A / Ctrl-B to enter/exit raw REPL; Ctrl-C to interrupt; Ctrl-D to soft-reset.")
    info("OLED test snippet:")
    info("  from machine import Pin, SoftI2C")
    info("  import ssd1306")
    info("  i2c = SoftI2C(sda=Pin(36), scl=Pin(37))")
    info("  oled = ssd1306.SSD1306_I2C(128, 64, i2c)")
    info("  oled.text('Hello Heltec!', 0, 0); oled.show()")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    info("Checking and installing required packages...")
    info("APT packages: esptool (esptool CLI), python3-serial (pyserial for port detection)")
    ensure_apt_packages(["esptool", "python3-serial"])

    info("PIP package: mpremote (MicroPython remote tool, not available in apt)")
    ensure_pip_packages([
        ("mpremote", "mpremote"),
    ])

    ensure_system_tool(
        "esptool.py",
        "Install via apt: sudo apt install esptool\n  or pip: pip install esptool --break-system-packages",
        apt_pkg="esptool",
    )

    info("Checking Linux udev rules for USB access...")
    _check_udev()

    print_banner(TOOL_NAME, DESCRIPTION)

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Heltec WiFi LoRa32 v3 not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Connected on {port}")

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash Application Firmware",
        "FIRMWARE - Flash Full Partition Set",
        "FIRMWARE - Flash MicroPython",
        "Upload MicroPython Script",
        "Run MicroPython Script",
        "MicroPython REPL",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Heltec WiFi LoRa32 v3 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_app_firmware(port)
        elif choice == 2:
            op_flash_full_partition_set(port)
        elif choice == 3:
            op_flash_micropython(port)
        elif choice == 4:
            op_upload_micropython_script(port)
        elif choice == 5:
            op_run_micropython_script(port)
        elif choice == 6:
            op_micropython_repl()
        elif choice == 7:
            info("Goodbye.")
            break

        # Re-check port after flash operations
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
