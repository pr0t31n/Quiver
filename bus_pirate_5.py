#!/usr/bin/env python3
"""
Bus Pirate 5 Tool Manager
Handles device info, resets, voltage reads, mode setup, power control,
firmware updates via UF2, and script uploads over USB CDC serial.

Usage:
    python3 bus_pirate_5.py

Bus Pirate 5 REPL command reference:
    i       — Device info (hardware version, firmware version)
    v       — Voltage report (Vout, 3.3V rail, 5V rail, ADC readings)
    m       — Mode menu (UART, SPI, I2C, 1-Wire, LED, etc.) — use buttons on device
    W / w   — Enable / disable programmable power supply (Vout)
    #       — Reset the device (soft reboot)
    $       — Enter UF2 bootloader mode for firmware flashing
    ~       — Perform self-test
    ?       — Context-sensitive help

Linux serial permissions:
    The Bus Pirate 5 appears as /dev/ttyACM* (USB CDC ACM).
    If you get "Permission denied", add your user to the dialout group:
        sudo usermod -aG dialout $USER
    Then log out and back in (or run: newgrp dialout).
    Check current groups with: id
    Verify device presence: ls -la /dev/ttyACM*
    Check USB enumeration: dmesg | tail -20
"""

import os
import shutil
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, ensure_pip_packages, ensure_system_tool,
    web_detect_loop, run_streaming,
    find_mounted_drive,
    require_sudo, sudo_run, sudo_output, run_streaming_sudo,
    ensure_apt_packages, ensure_brew_packages, get_os_flavor,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Bus Pirate 5"
DESCRIPTION = "Universal open-source hacking tool — UART, SPI, I2C, and more"

VID_PID_CDC  = [(0x1209, 0x7331)]
VID_PID_UF2  = [(0x2E8A, 0x0003)]

BAUD_RATE    = 115200
FS_LABEL     = "BusPirate-FS"
UF2_LABEL    = "RPI-RP2"

CONNECT_INSTRUCTIONS = (
    "Bus Pirate 5 not detected.\n\n"
    "  1. Connect Bus Pirate 5 via USB-C cable\n"
    "  2. Wait for the device to enumerate\n"
    "  3. The green LED should illuminate\n\n"
    "  Driver notes:\n"
    "    Linux: built-in CDC ACM (automatic) — device appears as /dev/ttyACM*\n"
    "    macOS: built-in (no driver needed)\n"
    "    Windows: install CDC ACM driver from buspirate.com\n\n"
    "  Permission issues on Linux:\n"
    "    Check: ls -la /dev/ttyACM*\n"
    "    Fix:   sudo usermod -aG dialout $USER  (then log out/in)\n"
    "    Debug: dmesg | tail -20"
)

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_bp5() -> bool:
    return find_serial_port_by_vidpid(VID_PID_CDC) is not None


def detect_uf2() -> bool:
    return find_serial_port_by_vidpid(VID_PID_UF2) is not None or \
           find_mounted_drive(UF2_LABEL) is not None


# ── Serial helpers ────────────────────────────────────────────────────────────

def _open_serial(port: str):
    import serial
    ser = serial.Serial(
        port=port,
        baudrate=BAUD_RATE,
        timeout=2,
        bytesize=8,
        parity="N",
        stopbits=1,
    )
    time.sleep(0.2)
    ser.reset_input_buffer()
    return ser


def _send_command(ser, cmd: str, wait: float = 0.5) -> str:
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    time.sleep(wait)
    raw = b""
    while ser.in_waiting:
        raw += ser.read(ser.in_waiting)
        time.sleep(0.05)
    return raw.decode("utf-8", errors="replace").strip()


def _check_dialout(port: str):
    """
    Check if the current user can access the serial port.
    If not, offer to add them to the dialout group via sudo.
    """
    import grp
    import pwd
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    try:
        dialout_gid = grp.getgrnam("dialout").gr_gid
        user_gids = os.getgroups()
        if dialout_gid in user_gids:
            return  # Already in dialout
    except KeyError:
        return  # dialout group doesn't exist on this OS

    warn(f"User '{username}' may not be in the 'dialout' group.")
    info("This can cause 'Permission denied' errors on /dev/ttyACM* devices.")
    info(f"  Check groups:  id {username}")
    info(f"  Check device:  ls -la {port}")
    if confirm(f"Add '{username}' to the 'dialout' group now?", default=True):
        info(f"Running: sudo usermod -aG dialout {username}")
        rc = sudo_run(f"usermod -aG dialout {username}")
        if rc.returncode == 0:
            ok(f"Added '{username}' to dialout. You must log out and back in (or run: newgrp dialout).")
        else:
            err("Failed to add user to dialout group. Try manually: sudo usermod -aG dialout $USER")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Sending 'i' command to Bus Pirate 5 REPL.")
    info("Expected output: hardware version, firmware version, RP2040 chip info.")
    info("If no response is received, the device may not be at the REPL prompt.")
    info("  Try: disconnect and reconnect USB, then re-run this option.")
    info(f"  Verify port is correct: ls -la {port}")
    try:
        with _open_serial(port) as ser:
            output = _send_command(ser, "i", wait=1.0)
        if output:
            for line in output.splitlines():
                info(line)
            ok("Device info retrieved.")
        else:
            warn("No response — device may not be at the REPL prompt.")
            info("Tip: Open a terminal emulator (e.g. screen /dev/ttyACM0 115200) to check REPL state.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Device info failed: {e}")
        info(f"Debug: Check dmesg | tail -20 and ls -la {port}")


def op_reset_device(port: str):
    heading("Reset Device")
    info("Sending '#' to the Bus Pirate 5 REPL — this triggers a soft reset (reboot).")
    info("The device will briefly disconnect and re-enumerate on the same or a new /dev/ttyACM* port.")
    if not confirm("Send reset command (#) to Bus Pirate 5?"):
        info("Reset cancelled.")
        return
    try:
        with _open_serial(port) as ser:
            _send_command(ser, "#", wait=1.5)
        ok("Reset command sent. Device is rebooting.")
        info("Wait ~3 seconds for the device to re-enumerate before running other commands.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Reset failed: {e}")


def op_read_voltages(port: str):
    heading("Read Voltages")
    info("Sending 'v' command to Bus Pirate 5 REPL.")
    info("Expected output: Vout (programmable supply), 3.3V rail, 5V rail, and ADC pin readings.")
    info("  Vout = 0V if power supply is OFF (use Power Control → Turn ON to enable).")
    info("  If voltages seem wrong, check physical connections and power source.")
    try:
        with _open_serial(port) as ser:
            output = _send_command(ser, "v", wait=1.0)
        if output:
            for line in output.splitlines():
                info(line)
            ok("Voltage report complete.")
        else:
            warn("No voltage data returned.")
            info("Ensure the device is in REPL mode (not mid-command). Try resetting first.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Read voltages failed: {e}")


def op_mode_setup(port: str):
    heading("Mode Setup")
    info("Sending mode command 'm' — the mode menu is displayed on the Bus Pirate OLED.")
    info("Available modes (use hardware buttons on the device to select):")
    info("  UART  — TTL serial, connect TX/RX/GND")
    info("  SPI   — 4-wire (CLK, MOSI, MISO, CS), connect to SPI flash/sensors")
    info("  I2C   — 2-wire (SCL, SDA), connect to EEPROMs, sensors, displays")
    info("  1-Wire — single-pin protocol (e.g. DS18B20 temperature sensors)")
    info("  LED   — control addressable RGB LEDs (WS2812, APA102)")
    info("  UART + bridge — pass-through bridge mode")
    info("After selecting a mode, return here and operations use that mode's context.")
    pause("Press ENTER when you have finished selecting a mode on the device.")
    try:
        with _open_serial(port) as ser:
            _send_command(ser, "m", wait=0.5)
        ok("Mode command sent.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Mode setup failed: {e}")


def op_power_control(port: str):
    heading("Power Control")
    info("The Bus Pirate 5 has a programmable power supply (Vout) on the VOUT/GND pins.")
    info("  'W' (uppercase) — Enable Vout power supply")
    info("  'w' (lowercase) — Disable Vout power supply")
    info("Set voltage level via the mode menu before enabling power.")
    info("Default Vout is typically 3.3V. Check voltage with 'Read Voltages' after enabling.")
    choice = numbered_menu("Power Action", ["Turn ON (W)", "Turn OFF (w)", "Cancel"])
    if choice == 2:
        info("Cancelled.")
        return
    cmd = "W" if choice == 0 else "w"
    action = "ON" if choice == 0 else "OFF"
    try:
        with _open_serial(port) as ser:
            output = _send_command(ser, cmd, wait=0.5)
        for line in output.splitlines():
            info(line)
        ok(f"Power {action} command sent.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Power control failed: {e}")


def op_firmware_update(port: str):
    heading("Firmware Update")
    info("Firmware update uses UF2 bootloader — no special flashing tool required.")
    info("Process:")
    info("  1. Send '$' to enter UF2 bootloader mode (or hold BOOT + plug USB)")
    info("  2. Device remounts as 'RPI-RP2' mass storage volume")
    info("  3. Copy .uf2 file to the volume — device flashes and reboots automatically")
    info("Download firmware from: https://github.com/DangerousPrototypes/BusPirate5-firmware/releases")
    uf2_path = prompt("Path to .uf2 firmware file")
    if not uf2_path:
        warn("No file path provided. Aborting.")
        return
    uf2_file = Path(uf2_path)
    if not uf2_file.exists():
        err(f"File not found: {uf2_file}")
        return
    if uf2_file.suffix.lower() != ".uf2":
        warn(f"File does not have a .uf2 extension: {uf2_file.name}")
        if not confirm("Continue anyway?", default=False):
            return

    info("Sending '$' to enter bootloader mode…")
    try:
        with _open_serial(port) as ser:
            _send_command(ser, "$", wait=1.0)
    except Exception as e:
        warn(f"Could not send bootloader command: {e}")
        info("Alternative: hold the BOOT button on the PCB while plugging in USB to force UF2 mode.")

    info("Waiting for RPI-RP2 mass storage to mount…")
    info("Expected: a new drive named 'RPI-RP2' will appear (usually under /media/$USER/ on Linux).")
    info("If it does not appear, try: hold BOOT button while re-plugging USB.")
    wait_start(
        "Bus Pirate 5 entering bootloader (UF2) mode.\n\n"
        "  The device will remount as 'RPI-RP2' mass storage.\n"
        "  This may take up to 15 seconds."
    )

    deadline = time.time() + 60
    mount = None
    while time.time() < deadline:
        mount = find_mounted_drive(UF2_LABEL)
        if mount:
            break
        remaining = int(deadline - time.time())
        wait_status(f"Waiting for RPI-RP2 mount… ({remaining}s remaining)")
        time.sleep(2)

    if not mount:
        wait_timeout("RPI-RP2 volume did not mount within 60 seconds.")
        err("Firmware update aborted.")
        info("Troubleshooting:")
        info("  1. Hold BOOT button while plugging in USB (forces UF2 mode)")
        info("  2. Check: lsblk | grep -i rpi  or  ls /media/$USER/")
        info("  3. Check: dmesg | tail -30")
        return

    wait_done(f"RPI-RP2 mounted at {mount}")
    dest = mount / uf2_file.name
    info(f"Copying {uf2_file.name} → {dest}")
    info("No sudo needed — the volume is mounted as your user.")
    try:
        shutil.copy2(str(uf2_file), str(dest))
        ok("Firmware file copied. Device will flash and reboot automatically.")
        info("Wait for the device to reboot and re-enumerate as /dev/ttyACM* before using again.")
    except Exception as e:
        err(f"File copy failed: {e}")
        info("If permission denied, check mount options: mount | grep RPI-RP2")


def op_upload_script(port: str):
    heading("Upload Script")
    info("Bus Pirate 5 exposes a small FAT filesystem as 'BusPirate-FS' mass storage.")
    info("Scripts (.bps files) placed here can be run from the REPL with the script command.")
    info("Expected mount path on Linux: /media/$USER/BusPirate-FS/")
    info("If not mounted, disconnect and reconnect the Bus Pirate 5.")
    script_path = prompt("Path to .bps script file")
    if not script_path:
        warn("No file path provided. Aborting.")
        return
    script_file = Path(script_path)
    if not script_file.exists():
        err(f"File not found: {script_file}")
        return

    info(f"Looking for BusPirate-FS volume ({FS_LABEL})…")
    info(f"Check: ls /media/$USER/ or lsblk -o NAME,LABEL,MOUNTPOINT")
    mount = find_mounted_drive(FS_LABEL)
    if not mount:
        err(
            f"'{FS_LABEL}' volume not found. "
            "Ensure the Bus Pirate 5 is connected and the filesystem is mounted."
        )
        info("Troubleshooting:")
        info("  Check: lsblk -o NAME,LABEL,MOUNTPOINT")
        info("  Check: dmesg | tail -20")
        info("  Try unplugging and replugging the device.")
        return

    dest = mount / script_file.name
    info(f"Copying {script_file.name} → {dest}")
    try:
        shutil.copy2(str(script_file), str(dest))
        ok(f"Script uploaded: {script_file.name}")
        info("Run the script on the device REPL with: script <filename>")
    except Exception as e:
        err(f"Upload failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor == "linux":
        info("Ensuring required APT package: python3-serial")
        info("  This provides the 'serial' Python module for USB CDC communication.")
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Detecting Bus Pirate 5 via USB VID:PID 1209:7331 (CDC mode)…")
    info("Expected device: /dev/ttyACM* (Linux) or /dev/cu.usbmodem* (macOS)")
    info("If not found, check: dmesg | tail -20   and   ls /dev/ttyACM*")

    found = web_detect_loop(detect_bp5, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Bus Pirate 5 not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PID_CDC)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Connected on {port}")
    _check_dialout(port)

    MENU_OPTIONS = [
        "Device Info (i)",
        "Reset Device (#)",
        "Read Voltages (v)",
        "Mode Setup (m)",
        "Power Control (W/w)",
        "FIRMWARE - Firmware Update (.uf2)",
        "Upload Script (.bps)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Bus Pirate 5 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_reset_device(port)
        elif choice == 2:
            op_read_voltages(port)
        elif choice == 3:
            op_mode_setup(port)
        elif choice == 4:
            op_power_control(port)
        elif choice == 5:
            op_firmware_update(port)
        elif choice == 6:
            op_upload_script(port)
        elif choice == 7:
            info("Goodbye.")
            break

        # Re-check device presence after each operation (it may reboot)
        new_port = find_serial_port_by_vidpid(VID_PID_CDC)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
