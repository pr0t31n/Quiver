#!/usr/bin/env python3
"""
Sonoff ZBDongle-E Tool Manager
Handles device probing, firmware flashing, IEEE address writing,
Zigbee coordinator startup, permit join, and network channel info
using universal-silabs-flasher and bellows (asyncio).

EFR32MG21 radio SoC, EmberZNet NCP firmware, EZSP/ASH protocol.
Firmware source: https://github.com/NabuCasa/silabs-firmware-builder/releases

macOS note: CH9102F variant requires WCH driver.

Usage:
    python3 sonoff_zbdongle_e.py
"""

import asyncio
import shutil
import sys
import threading
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

TOOL_NAME   = "Sonoff ZBDongle-E"
DESCRIPTION = "EFR32MG21 Zigbee coordinator dongle — EmberZNet NCP firmware"

VID_PIDS = [
    (0x1A86, 0x55D4),  # CH9102F
    (0x10C4, 0xEA60),  # CP2102N
]

EZSP_BAUD    = 115200
BELLOWS_DB   = "/tmp/zbdongle_e.db"

CONNECT_INSTRUCTIONS = (
    "Sonoff ZBDongle-E not detected.\n\n"
    "  1. Insert ZBDongle-E into USB port\n"
    "  2. Check the variant:\n"
    "     Early batch (CH9102F): VID 1A86:55D4\n"
    "       macOS: install WCH driver from WCHSoftGroup/ch34xser_macos\n"
    "       Linux: ensure udev rule for 1A86:55D4 exists\n"
    "     Newer batch (CP2102N): VID 10C4:EA60\n"
    "       macOS: works natively (/dev/cu.SLAB_USBtoUART)\n"
    "       Linux: ensure udev rule for 10C4:EA60 exists\n\n"
    "  Linux udev setup (run once):\n"
    "    echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1a86\", ATTR{idProduct}==\"55d4\", MODE=\"0666\", GROUP=\"dialout\"' \\\n"
    "      | sudo tee /etc/udev/rules.d/99-ch9102f.rules\n"
    "    echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"10c4\", ATTR{idProduct}==\"ea60\", MODE=\"0666\", GROUP=\"dialout\"' \\\n"
    "      | sudo tee /etc/udev/rules.d/99-cp210x.rules\n"
    "    sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "    sudo usermod -aG dialout $USER  (then log out/in)\n\n"
    "  Firmware: https://github.com/NabuCasa/silabs-firmware-builder/releases"
)

WCH_DRIVER_NOTE = (
    "IMPORTANT — macOS CH9102F driver required:\n"
    "  The early Sonoff ZBDongle-E variant uses a CH9102F USB-UART chip (VID 1A86:55D4).\n"
    "  macOS does NOT include a driver for this chip by default.\n"
    "  Without the driver, the device will not enumerate as a serial port.\n\n"
    "  Install the WCH driver:\n"
    "    1. Download from: https://github.com/WCHSoftGroup/ch34xser_macos\n"
    "    2. Install the .pkg file and approve in System Preferences → Privacy & Security\n"
    "    3. Reboot, then reconnect the dongle\n"
    "    4. The port should appear as /dev/cu.wchusbserial*\n\n"
    "  The newer CP2102N variant (VID 10C4:EA60) works without any extra driver."
)

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_flasher() -> bool:
    """Check if universal-silabs-flasher is available as CLI or module."""
    if shutil.which("universal-silabs-flasher"):
        return True
    # Also try as a Python module
    try:
        import universal_silabs_flasher  # noqa: F401
        # If importable but no CLI, it might be run via python -m
        info("universal-silabs-flasher found as Python module (no CLI in PATH).")
        info("Try: python3 -m universal_silabs_flasher --help")
        return True
    except ImportError:
        pass
    err("universal-silabs-flasher not found.")
    info("Install with: pip install universal-silabs-flasher --break-system-packages")
    info("Or check if it was installed as a user package: pip show universal-silabs-flasher")
    return False


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


def _warn_macos_driver(port: str):
    """Warn about WCH driver if on macOS and CH9102F VID:PID is present."""
    if get_os() != "macos":
        return
    from serial.tools import list_ports
    for p in list_ports.comports():
        if p.device == port and p.vid == 0x1A86 and p.pid == 0x55D4:
            warn(WCH_DRIVER_NOTE)
            break


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info(f"Serial port: {port}")
    info("Checking variant (CH9102F vs CP2102N) from USB descriptor...")
    _warn_macos_driver(port)

    from serial.tools import list_ports
    for p in list_ports.comports():
        if p.device == port:
            info(f"Description : {p.description}")
            info(f"Manufacturer: {p.manufacturer or 'N/A'}")
            vid = f"0x{p.vid:04X}" if p.vid else "N/A"
            pid = f"0x{p.pid:04X}" if p.pid else "N/A"
            info(f"VID:PID     : {vid}:{pid}")

    if not _check_flasher():
        return
    info("Probing ZBDongle-E via universal-silabs-flasher (reads firmware version, IEEE, etc.)...")
    info("Expected: EFR32MG21 chip info and current firmware version.")
    info("If probe hangs: ensure no other app (e.g. Zigbee2MQTT) is using the port.")
    cmd = ["universal-silabs-flasher", "--device", port, "probe"]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=30)
        ok("Device probe complete.")
    except Exception as e:
        err(f"Probe failed: {e}")
        info("Troubleshooting: check that the port is not in use and udev rules allow access.")


def op_flash_firmware(port: str):
    heading("Flash Firmware")
    _warn_macos_driver(port)
    if not _check_flasher():
        return

    info("Firmware source: https://github.com/NabuCasa/silabs-firmware-builder/releases")
    info("Download the EmberZNet NCP firmware (.gbl) for your region (EU/US/AU).")
    info("Flashing will take ~30-60 seconds. The dongle enters bootloader mode automatically.")
    info("If auto-bootloader fails: unplug and replug the dongle, then retry.")
    gbl_path = prompt("Path to .gbl firmware file")
    gbl = _require_file(gbl_path, ".gbl")
    if not gbl:
        return
    if not confirm(f"Flash {gbl.name} to ZBDongle-E on {port}?"):
        info("Flash cancelled.")
        return

    info(f"Flashing firmware: {gbl.name}...")
    info("universal-silabs-flasher will reset the dongle into bootloader mode via RTS/DTR.")
    cmd = [
        "universal-silabs-flasher",
        "--device", port,
        "--bootloader-reset", "rts_dtr",
        "flash",
        "--firmware", str(gbl),
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=180)
        ok("Firmware flash complete.")
        info("After flashing, the dongle will reset. Wait a few seconds before probing.")
    except Exception as e:
        err(f"Firmware flash failed: {e}")
        info("Troubleshooting:")
        info("  - Check that the .gbl file is valid (correct variant for your hardware)")
        info("  - Try power-cycling the dongle")
        info("  - Ensure no other process is using the serial port")


def op_write_ieee_address(port: str):
    heading("Write IEEE Address")
    _warn_macos_driver(port)
    if not _check_flasher():
        return

    info("The IEEE address (EUI64) is the unique 64-bit Zigbee hardware address.")
    info("Changing it is normally not required unless restoring a backup or replacing hardware.")
    info("IEEE address format: XX:XX:XX:XX:XX:XX:XX:XX (8 bytes, hex, colon-separated)")
    ieee = prompt("EUI64 / IEEE address to write")
    if not ieee:
        warn("No address provided. Aborting.")
        return
    # Basic format validation
    parts = ieee.split(":")
    if len(parts) != 8:
        err(f"Invalid EUI64 format: expected 8 colon-separated hex bytes, got {len(parts)}.")
        return
    for part in parts:
        if len(part) not in (1, 2) or not all(c in "0123456789abcdefABCDEF" for c in part):
            err(f"Invalid byte value in EUI64: {part!r}")
            return

    ieee_norm = ":".join(p.zfill(2).upper() for p in parts)
    if not confirm(f"Write IEEE address {ieee_norm} to dongle on {port}?"):
        info("Write cancelled.")
        return

    info(f"Writing IEEE address {ieee_norm}...")
    cmd = [
        "universal-silabs-flasher",
        "--device", port,
        "write-ieee",
        "--ieee", ieee_norm,
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=60)
        ok(f"IEEE address written: {ieee_norm}")
    except Exception as e:
        err(f"Write IEEE failed: {e}")


def run_bellows_info(port: str):
    async def _inner():
        info("Importing bellows ControllerApplication...")
        info("Connecting to EZSP coordinator (this may take 5-15 seconds)...")
        info("If this hangs: check that the firmware is EmberZNet NCP (not OpenThread or Zigbee RCP).")
        from bellows.zigbee.application import ControllerApplication
        config = ControllerApplication.SCHEMA({
            "database": BELLOWS_DB,
            "device": {
                "path": port,
                "baudrate": EZSP_BAUD,
                "flow_control": None,
            },
        })
        app = await ControllerApplication.new(config, auto_form=False)
        info(f"EUI64       : {app.ieee}")
        try:
            info(f"NWK address : {app.nwk}")
        except Exception:
            pass
        try:
            info(f"PAN ID      : 0x{app.pan_id:04X}")
            info(f"Channel     : {app.channel}")
            info(f"Ext PAN ID  : {app.extended_pan_id}")
        except Exception:
            pass
        await app.shutdown()
        ok("Bellows coordinator info retrieved.")

    asyncio.run(_inner())


def op_start_coordinator(port: str):
    heading("Start Zigbee Coordinator")
    _warn_macos_driver(port)
    info(f"Connecting bellows to EZSP coordinator on {port} at {EZSP_BAUD} baud...")
    info("No hardware flow control is used (EZSP/ASH requirement).")
    info("Troubleshooting coordinator startup:")
    info("  - 'Protocol error': firmware may not be EmberZNet NCP — reflash correct .gbl")
    info("  - 'Timeout': increase EZSP_BAUD or check USB cable quality")
    info("  - 'Permission denied': add user to dialout group and reload udev rules")
    t = threading.Thread(target=run_bellows_info, args=(port,), daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        err("Timed out waiting for bellows coordinator response (30s).")
        info("The bellows thread is still running in background. Press Ctrl+C to abort.")


def run_bellows_permit_join(port: str, duration: int = 60):
    async def _inner():
        from bellows.zigbee.application import ControllerApplication
        config = ControllerApplication.SCHEMA({
            "database": BELLOWS_DB,
            "device": {
                "path": port,
                "baudrate": EZSP_BAUD,
                "flow_control": None,
            },
        })
        app = await ControllerApplication.new(config, auto_form=False)
        info(f"EUI64: {app.ieee}")
        await app.permit(time_s=duration)
        info(f"Permit join opened for {duration} seconds.")
        await asyncio.sleep(2)
        await app.shutdown()
        ok("Permit join command sent.")

    asyncio.run(_inner())


def op_open_network_permit_join(port: str):
    heading("Open Network (Permit Join)")
    _warn_macos_driver(port)
    info("Opening the Zigbee network for new device joins for 60 seconds.")
    info("During this window, pair Zigbee devices by putting them in pairing mode.")
    info("Sending permit join (60 seconds) via bellows...")
    t = threading.Thread(target=run_bellows_permit_join, args=(port, 60), daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        err("Timed out waiting for permit join response (30s).")


def run_bellows_channel_info(port: str):
    async def _inner():
        from bellows.zigbee.application import ControllerApplication
        config = ControllerApplication.SCHEMA({
            "database": BELLOWS_DB,
            "device": {
                "path": port,
                "baudrate": EZSP_BAUD,
                "flow_control": None,
            },
        })
        app = await ControllerApplication.new(config, auto_form=False)
        try:
            info(f"PAN ID          : 0x{app.pan_id:04X}")
            info(f"Channel         : {app.channel}")
            info(f"Extended PAN ID : {app.extended_pan_id}")
            info(f"EUI64           : {app.ieee}")
            info(f"NWK address     : {app.nwk}")
        except Exception as e:
            warn(f"Could not retrieve all network parameters: {e}")
        await app.shutdown()
        ok("Channel info retrieved.")

    asyncio.run(_inner())


def op_network_channel_info(port: str):
    heading("Network Channel Info")
    _warn_macos_driver(port)
    info("Reading coordinator PAN ID, channel, and extended PAN ID via bellows...")
    info("The coordinator must have a formed network. If channel shows 0, form a network first.")
    t = threading.Thread(target=run_bellows_channel_info, args=(port,), daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        err("Timed out waiting for network channel info (30s).")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    info("Checking and installing required packages...")
    info("APT packages: python3-serial (pyserial for port detection)")
    ensure_apt_packages(["python3-serial"])

    info("PIP packages: universal-silabs-flasher (firmware flashing CLI+library),")
    info("  bellows (Zigbee coordinator control), zigpy (Zigbee protocol stack)")
    info("Note: These are not in apt — installing via pip with --break-system-packages")
    ensure_pip_packages([
        ("serial", "pyserial"),
        ("bellows", "bellows"),
        ("zigpy", "zigpy"),
        ("universal_silabs_flasher", "universal-silabs-flasher"),
    ])

    print_banner(TOOL_NAME, DESCRIPTION)

    # macOS driver advisory shown before detection attempt
    if get_os() == "macos":
        info(WCH_DRIVER_NOTE)

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Sonoff ZBDongle-E not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Connected on {port}")
    _warn_macos_driver(port)

    MENU_OPTIONS = [
        "Device Info",
        "Flash Firmware",
        "Write IEEE Address",
        "Start Zigbee Coordinator",
        "Open Network (Permit Join)",
        "Network Channel Info",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Sonoff ZBDongle-E — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_firmware(port)
        elif choice == 2:
            op_write_ieee_address(port)
        elif choice == 3:
            op_start_coordinator(port)
        elif choice == 4:
            op_open_network_permit_join(port)
        elif choice == 5:
            op_network_channel_info(port)
        elif choice == 6:
            info("Goodbye.")
            break

        # Re-check port after operations (flashing may reassign)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
