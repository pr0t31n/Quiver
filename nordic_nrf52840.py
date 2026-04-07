#!/usr/bin/env python3
"""
Nordic nRF52840 Development Kit / USB Dongle Tool Manager
Handles device detection (dongle vs DK), BLE sniffing, Zigbee/Thread NCP info,
DFU firmware flashing (dongle), J-Link programming (DK), and firmware management.

Usage:
    python3 nordic_nrf52840.py

USB VID:PIDs:
    0x1915:0x521F — nRF52840 Dongle (DFU bootloader CDC, press RESET to enter)
    0x1915:0x520F — nRF52840 Dongle (application CDC UART)
    0x1366:0x1015 — nRF52840-DK (Segger J-Link JTAG debugger on-board)

Device variants:
    nRF52840 Dongle (PCA10059):
        - Small USB dongle form factor
        - Onboard RGB LED + green LED
        - Press side button briefly to reset, hold side button while inserting to enter DFU
        - DFU bootloader via CDC serial (nrfutil dfu usb-serial)
        - No J-Link — firmware flashing via nrfutil only

    nRF52840-DK (PCA10056):
        - Full development kit with Arduino headers
        - Onboard Segger J-Link JTAG debugger
        - Firmware programming via nrfjprog (J-Link) or DFU
        - CDC UART for debug output

Linux serial permissions:
    Devices appear as /dev/ttyACM* (USB CDC ACM).
    Add user to dialout: sudo usermod -aG dialout $USER (then re-login)
    Check: id  and  ls -la /dev/ttyACM*
    Debug: dmesg | tail -20

nrfutil DFU reference:
    nrfutil dfu usb-serial -pkg <package.zip> -p <port>
    Package creation:
        nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\
            --application <firmware.hex> <output.zip>

nrfjprog (J-Link) reference:
    nrfjprog --ids                              List connected J-Link devices
    nrfjprog --program <hex> --sectorerase      Flash firmware (erase sectors first)
    nrfjprog --reset                            Reset the device
    nrfjprog --eraseall                         Full chip erase
    nrfjprog --readregs                         Read CPU registers
"""

import os
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
    find_mounted_drive,
    check_latest_github_release, announce_firmware_update, get_firmware_dir,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Nordic nRF52840"
DESCRIPTION = "nRF52840 Dongle / Development Kit — BLE, Zigbee, Thread, IEEE 802.15.4"

VID_PIDS = [
    (0x1915, 0x521F),  # nRF52840 Dongle — DFU bootloader CDC
    (0x1915, 0x520F),  # nRF52840 Dongle — application CDC
    (0x1366, 0x1015),  # nRF52840-DK — J-Link JTAG
]

VID_PID_DONGLE_DFU = [(0x1915, 0x521F)]
VID_PID_DONGLE_APP = [(0x1915, 0x520F)]
VID_PID_DK_JLINK   = [(0x1366, 0x1015)]

BAUD_RATE = 115200

BLE_SNIFFER_API_URL = (
    "https://api.github.com/repos/NordicSemiconductor/pc-nrfconnect-ble/releases/latest"
)
SDK_NRF_API_URL = (
    "https://api.github.com/repos/NordicSemiconductor/sdk-nrf/releases/latest"
)

CONNECT_INSTRUCTIONS = (
    "Nordic nRF52840 not detected.\n\n"
    "  DONGLE (PCA10059) — VID:PID 1915:520F (app) or 1915:521F (DFU):\n"
    "    1. Insert nRF52840 dongle into USB port\n"
    "    2. Application mode: appears as /dev/ttyACM* (1915:520F)\n"
    "    3. DFU mode: press the side button briefly — LED blinks red\n"
    "       USB re-enumerates as 1915:521F\n"
    "    4. If dongle is not detected: try a different USB port or cable\n\n"
    "  DK (PCA10056) — VID:PID 1366:1015 (J-Link):\n"
    "    1. Connect nRF52840-DK via USB (J-Link USB port, NOT the nRF USB port)\n"
    "    2. Install SEGGER J-Link Software:\n"
    "       Linux: download .deb from https://www.segger.com/downloads/jlink/\n"
    "              sudo dpkg -i JLink_Linux_*.deb\n"
    "       macOS: brew install --cask segger-jlink\n"
    "    3. Install nRF Command Line Tools (nrfjprog):\n"
    "       From: https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools\n"
    "       Linux: download .tar.gz, extract, run install.sh\n"
    "       macOS: brew install --cask nordic-nrf-command-line-tools\n\n"
    "  Linux permissions:\n"
    "    sudo usermod -aG dialout $USER  (then re-login)\n"
    "    sudo usermod -aG plugdev $USER  (for J-Link access)\n"
    "    Check: dmesg | tail -20\n"
    "    Check: lsusb | grep -E '1915|1366'"
)

UDEV_RULES_CONTENT = (
    '# Nordic nRF52840 udev rules\n'
    '# nRF52840 Dongle DFU bootloader (VID:PID 1915:521F)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="521f", '
    'MODE="0666", GROUP="dialout"\n'
    '# nRF52840 Dongle application (VID:PID 1915:520F)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="520f", '
    'MODE="0666", GROUP="dialout"\n'
    '# nRF52840-DK J-Link (VID:PID 1366:1015)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="1366", MODE="0666", GROUP="plugdev"\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1366", MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-nordic-nrf52840.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_nrf52840() -> bool:
    info("Scanning USB for nRF52840 (VID:PIDs 1915:521F, 1915:520F, 1366:1015)…")
    return find_serial_port_by_vidpid(VID_PIDS) is not None


def _identify_variant() -> str:
    """Return 'dongle_dfu', 'dongle_app', 'dk', or 'unknown'."""
    if find_serial_port_by_vidpid(VID_PID_DONGLE_DFU):
        return "dongle_dfu"
    if find_serial_port_by_vidpid(VID_PID_DONGLE_APP):
        return "dongle_app"
    if find_serial_port_by_vidpid(VID_PID_DK_JLINK):
        return "dk"
    return "unknown"


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for nRF52840 on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Nordic nRF52840…")
    info(f"  Writing to: {UDEV_RULES_PATH}")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the device to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Tool checks ───────────────────────────────────────────────────────────────

def _check_nrfutil():
    """Check / install nrfutil."""
    info("Checking nrfutil (Nordic DFU tool for dongle flashing)…")
    path = run_output("which nrfutil 2>/dev/null || true")
    if path and path.strip():
        ok(f"nrfutil found: {path.strip()}")
        ver = run_output("nrfutil version 2>/dev/null || true")
        if ver:
            info(f"  nrfutil version: {ver.strip()}")
        return True
    warn("nrfutil not found. Installing via pip…")
    info("  nrfutil is Nordic's official DFU tool for the nRF52840 dongle.")
    info("  It handles DFU package creation and USB CDC serial flashing.")
    ensure_pip_packages([("nrfutil", "nrfutil")])
    path2 = run_output("which nrfutil 2>/dev/null || true")
    if path2 and path2.strip():
        ok("nrfutil installed successfully.")
        return True
    err("nrfutil still not found after pip install.")
    info("  Manual install: pip install nrfutil --break-system-packages")
    info("  Or: pip3 install nrfutil")
    return False


def _check_nrfjprog():
    """Check for nrfjprog (nRF Command Line Tools)."""
    info("Checking nrfjprog (nRF Command Line Tools for J-Link programming)…")
    path = run_output("which nrfjprog 2>/dev/null || true")
    if path and path.strip():
        ok(f"nrfjprog found: {path.strip()}")
        ver = run_output("nrfjprog --version 2>/dev/null || true")
        if ver:
            info(f"  nrfjprog version: {ver.strip()}")
        return True
    warn("nrfjprog not found.")
    info("  nrfjprog is part of the nRF Command Line Tools package from Nordic Semiconductor.")
    info("  Required for J-Link firmware programming on the nRF52840-DK.")
    info("  Download from: https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
    flavor = get_os_flavor()
    if flavor == "darwin":
        info("  macOS install: brew install --cask nordic-nrf-command-line-tools")
        info("  Or: download the macOS .pkg installer from the Nordic website")
        if confirm("Attempt to install via brew cask?", default=True):
            ensure_brew_packages(["nordic-nrf-command-line-tools"])
    else:
        info("  Linux install:")
        info("    1. Download the .tar.gz from https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
        info("    2. Extract: tar xzf nRF-Command-Line-Tools_*.tar.gz")
        info("    3. Run installer: sudo ./install.sh")
        info("    4. Or install the .deb package if available for your distro")
        info("  Kali note: The nRF Command Line Tools .deb may work directly.")
    return False


# ── GitHub version checks ─────────────────────────────────────────────────────

def _get_latest_version(url: str, label: str) -> str:
    info(f"Fetching latest {label} version from GitHub…")
    info(f"  URL: {url}")
    try:
        import requests
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name", "unknown")
        info(f"  Latest {label}: {tag}")
        return tag
    except Exception as e:
        warn(f"Could not fetch {label} version: {e}")
        return "unknown"


# ── Serial helpers ────────────────────────────────────────────────────────────

def _open_serial(port: str):
    import serial
    info(f"Opening serial port {port} at {BAUD_RATE} baud…")
    ser = serial.Serial(port=port, baudrate=BAUD_RATE, timeout=2)
    time.sleep(0.3)
    ser.reset_input_buffer()
    return ser


def _check_dialout(port: str):
    if get_os_flavor() == "darwin":
        return
    import grp
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    try:
        gid = grp.getgrnam("dialout").gr_gid
        if gid in os.getgroups():
            return
    except KeyError:
        return
    warn(f"User '{username}' may not be in the 'dialout' group.")
    info(f"  Fix: sudo usermod -aG dialout {username}  (then log out/in)")
    if confirm("Add to dialout group now?", default=True):
        sudo_run(f"usermod -aG dialout {username}")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Identifying connected nRF52840 variant and device details.")
    info("")

    variant = _identify_variant()
    if variant == "dongle_dfu":
        info("VARIANT DETECTED: nRF52840 Dongle — DFU bootloader mode (1915:521F)")
        info("  The dongle is ready for firmware flashing via nrfutil.")
        info("  LED behavior in DFU mode: blinking red")
        info("  To exit DFU mode: press RESET, or flash new firmware.")
    elif variant == "dongle_app":
        info("VARIANT DETECTED: nRF52840 Dongle — application mode (1915:520F)")
        info("  The dongle is running its application firmware.")
        info("  To enter DFU mode: press the side button briefly.")
        info("  LED behavior depends on firmware (BLE sniffer, Zigbee, etc.)")
    elif variant == "dk":
        info("VARIANT DETECTED: nRF52840-DK (J-Link, 1366:1015)")
        info("  The DK's onboard J-Link debugger is connected.")
        info("  Use nrfjprog for firmware programming and device info.")
        info("  CDC UART may be on a separate /dev/ttyACM* interface.")
    else:
        warn("Variant could not be identified — defaulting to generic info.")

    info("")
    info("USB port details:")
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.device == port:
                info(f"  Device      : {p.device}")
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
                info(f"  Serial No.  : {p.serial_number or 'N/A'}")
    except Exception as e:
        warn(f"Could not enumerate USB ports via pyserial: {e}")

    # If DK, run nrfjprog --ids
    if variant == "dk":
        info("")
        info("Running 'nrfjprog --ids' to list J-Link connected devices…")
        try:
            r = run("nrfjprog --ids")
            if r.returncode == 0:
                ok("nrfjprog device listing complete.")
            else:
                warn("nrfjprog --ids returned an error.")
                info("  Ensure J-Link Software is installed and device is connected.")
                info("  Install: https://www.segger.com/downloads/jlink/")
        except FileNotFoundError:
            warn("nrfjprog not found. Install nRF Command Line Tools.")
            info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
        except Exception as e:
            err(f"nrfjprog error: {e}")

    ok("Device info complete.")


def op_ble_sniff(port: str):
    heading("BLE Sniffer Setup")
    info("Configuring the nRF52840 as a Bluetooth Low Energy (BLE) sniffer.")
    info("")
    info("REQUIRED FIRMWARE: nRF Sniffer for Bluetooth LE")
    info("  Nordic's official BLE sniffer firmware for Wireshark integration.")
    info("  This firmware allows the nRF52840 to capture BLE advertising and data packets.")
    info("  Works with Wireshark via the nRF Sniffer plugin (extcap).")
    info("")
    info("DOWNLOAD:")
    info("  nRF Sniffer firmware and Wireshark plugin:")
    info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE")
    info("  Or via nRF Connect for Desktop > Bluetooth Low Energy Sniffer app")
    info("")
    info("VARIANT NOTES:")
    variant = _identify_variant()
    if variant in ("dongle_app", "dongle_dfu"):
        info("  Dongle detected — use nrfutil DFU to flash BLE sniffer firmware.")
        info("  Follow: op_flash_dongle() from this menu.")
    elif variant == "dk":
        info("  DK detected — use nrfjprog J-Link to flash BLE sniffer firmware.")
        info("  Follow: op_flash_dk() from this menu.")

    info("")
    info("Checking for latest BLE sniffer release…")
    latest = _get_latest_version(BLE_SNIFFER_API_URL, "BLE sniffer")
    if latest != "unknown":
        ok(f"Latest BLE sniffer version available: {latest}")

    info("")
    info("WIRESHARK INTEGRATION:")
    info("  After flashing, install the Wireshark extcap plugin:")
    info("    1. Locate the extcap/ folder from the nRF Sniffer download")
    info("    2. Copy nrf_sniffer_ble.py and nrf_sniffer_ble.bat (Windows) to:")
    info("       Linux:  ~/.config/wireshark/extcap/  or  /usr/lib/x86_64-linux-gnu/wireshark/extcap/")
    info("       macOS:  ~/.config/wireshark/extcap/  or  /Applications/Wireshark.app/.../extcap/")
    info("    3. Make executable: chmod +x nrf_sniffer_ble.py")
    info("    4. Restart Wireshark — 'nRF Sniffer for Bluetooth LE' appears as capture interface")
    info("")
    info("USAGE:")
    info("  Open Wireshark → select 'nRF Sniffer for Bluetooth LE' interface")
    info("  Or from CLI: wireshark -i nrf_sniffer_ble -k")
    info("  Filter: btle.advertising_header.pdu_type == 0x00  (ADV_IND packets)")
    info("")
    pause("Press ENTER to continue.")


def op_zigbee_info():
    heading("Zigbee / Thread NCP Info")
    info("The nRF52840 can act as a Zigbee or Thread Network Co-Processor (NCP).")
    info("")
    info("FIRMWARE OPTIONS:")
    info("  1. Zigbee NCP (Network Co-Processor)")
    info("     - Used with Home Assistant, Zigbee2MQTT, OpenHAB")
    info("     - Communicates with host over CDC UART (ZBOSS NCP protocol)")
    info("     - Firmware: sdk-nrf Zigbee NCP sample")
    info("")
    info("  2. OpenThread Border Router (OTBR)")
    info("     - Thread/Matter networking co-processor")
    info("     - Requires OpenThread Border Router on Linux host")
    info("")
    info("  3. Zigbee Sniffer (IEEE 802.15.4)")
    info("     - Wireshark integration via extcap plugin")
    info("     - Capture Zigbee, Thread, 6LoWPAN traffic")
    info("")
    info("LATEST SDK-NRF RELEASE:")
    latest = _get_latest_version(SDK_NRF_API_URL, "sdk-nrf (Zigbee/Thread)")
    if latest != "unknown":
        ok(f"Latest sdk-nrf version: {latest}")
    info("")
    info("FIRMWARE SOURCE:")
    info("  Nordic sdk-nrf: https://github.com/NordicSemiconductor/sdk-nrf")
    info("  Pre-built binaries: in sdk-nrf release assets or Nordic nRF Connect for Desktop")
    info("")
    info("ZIGBEE2MQTT INTEGRATION:")
    info("  Once NCP firmware is flashed and device is on /dev/ttyACM*:")
    info("  In zigbee2mqtt configuration.yaml:")
    info("    serial:")
    info("      port: /dev/ttyACM0")
    info("      adapter: zboss   # for Nordic NCP firmware")
    info("")
    pause("Press ENTER to continue.")


def op_flash_dongle(port: str):
    heading("Flash Dongle via nrfutil DFU")
    info("Flashing firmware to the nRF52840 dongle via USB CDC DFU.")
    info("This method uses nrfutil and the dongle's built-in DFU bootloader.")
    info("The dongle MUST be in DFU mode before flashing.")
    info("")
    info("HOW TO ENTER DFU MODE:")
    info("  Method 1 (from running firmware): press the small side button briefly")
    info("    - The LED will blink red/yellow — device is in DFU mode")
    info("    - USB re-enumerates as VID:PID 1915:521F")
    info("  Method 2 (cold boot DFU): hold side button while inserting into USB")
    info("    - Useful if firmware is bricked / not responding")
    info("")
    info("DFU PACKAGE FORMAT:")
    info("  nrfutil expects a .zip DFU package (not a raw .hex or .bin).")
    info("  To create a DFU package from a .hex file:")
    info("    nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\")
    info("        --application <firmware.hex> <output_package.zip>")
    info("  Note: --sd-req 0x00 means no SoftDevice requirement.")
    info("")

    # Verify DFU mode
    dfu_port = find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
    app_port  = find_serial_port_by_vidpid(VID_PID_DONGLE_APP)

    if dfu_port:
        info(f"Dongle is in DFU mode on {dfu_port}.")
        flash_port = dfu_port
    elif app_port:
        warn(f"Dongle is in application mode on {app_port}. DFU mode required.")
        warn("  Press the SIDE BUTTON on the dongle now to enter DFU mode.")
        pause("Press ENTER after the dongle LED is blinking (DFU mode active).")
        # Re-check
        dfu_port = find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
        if not dfu_port:
            err("Dongle still not in DFU mode. Cannot proceed.")
            info("  Troubleshooting:")
            info("    - The side button is the small button on the edge (not the USER button)")
            info("    - If device is unresponsive: remove and reinsert while holding the side button")
            return
        flash_port = dfu_port
        info(f"DFU mode confirmed on {flash_port}.")
    else:
        err("No nRF52840 dongle detected. Ensure the device is connected.")
        return

    pkg_path = prompt("Path to DFU .zip package file")
    if not pkg_path:
        warn("No package path provided. Aborting.")
        return
    pkg = Path(pkg_path)
    if not pkg.exists():
        err(f"File not found: {pkg}")
        return
    if pkg.suffix.lower() != ".zip":
        warn(f"Expected a .zip DFU package, got: {pkg.name}")
        info("  Create a package: nrfutil pkg generate --hw-version 52 --sd-req 0x00 --application <hex> <pkg.zip>")
        if not confirm("Continue anyway?", default=False):
            return

    if not confirm(f"Flash {pkg.name} to dongle on {flash_port}?", default=True):
        info("Flash cancelled.")
        return

    info(f"Running: nrfutil dfu usb-serial -pkg {pkg} -p {flash_port}")
    info("  Watch for progress output — the process takes ~10-30 seconds.")
    info("  Do NOT unplug the dongle during flashing.")
    try:
        r = run(f"nrfutil dfu usb-serial -pkg {pkg} -p {flash_port}")
        if r.returncode == 0:
            ok("Dongle firmware flashed successfully via nrfutil DFU.")
            info("  The dongle will reboot and run the new firmware.")
            info("  USB may re-enumerate as 1915:520F (application mode).")
        else:
            err("nrfutil DFU flash failed.")
            info("Troubleshooting:")
            info("  - Verify the dongle is in DFU mode (LED blinking, VID:PID 1915:521F)")
            info("  - Check: ls -la /dev/ttyACM* and dmesg | tail -20")
            info("  - Ensure the .zip package was created for nRF52840 (hw-version 52)")
            info("  - Try without --sd-req: some firmware may need --sd-req 0xXXXX")
            info("  - Check nrfutil version: nrfutil version (older versions may have issues)")
    except FileNotFoundError:
        err("nrfutil not found. Install with: pip install nrfutil --break-system-packages")
    except Exception as e:
        err(f"Flash error: {e}")
        info(f"  Debug: check dmesg | tail -20 and ls -la {flash_port}")


def op_flash_dk(port: str):
    heading("Flash DK via J-Link (nrfjprog)")
    info("Programming the nRF52840-DK via the onboard Segger J-Link debugger.")
    info("This method uses nrfjprog and provides direct flash/erase operations.")
    info("The DK must be connected via its J-Link USB port (NOT the nRF USB port).")
    info("")
    info("WHAT nrfjprog CAN FLASH:")
    info("  - .hex files (Intel HEX format, standard Nordic firmware format)")
    info("  - Merged HEX files (bootloader + application + SoftDevice combined)")
    info("")
    info("nrfjprog FLASH OPERATIONS:")
    info("  --sectorerase    Erase only flash sectors being written (default, safer)")
    info("  --eraseall       Erase full chip before programming (use for clean flash)")
    info("  --verify         Verify flash contents after write (recommended)")
    info("")

    # Verify DK is connected
    dk_port = find_serial_port_by_vidpid(VID_PID_DK_JLINK)
    if not dk_port:
        err("nRF52840-DK (J-Link, 1366:1015) not detected.")
        info("  Ensure the DK is connected via the J-Link USB port.")
        info("  The J-Link USB port is labeled 'J-LINK/OB' on the DK board.")
        info("  Install J-Link Software: https://www.segger.com/downloads/jlink/")
        return

    info(f"nRF52840-DK detected via J-Link on {dk_port}.")

    # List connected devices
    info("Running nrfjprog --ids to confirm J-Link connection…")
    try:
        r = run("nrfjprog --ids")
        if r.returncode != 0:
            warn("nrfjprog --ids failed. J-Link software may not be installed.")
            info("  Install from: https://www.segger.com/downloads/jlink/")
            info("  Kali/Debian: sudo dpkg -i JLink_Linux_*.deb")
            info("  macOS: brew install --cask segger-jlink")
    except FileNotFoundError:
        err("nrfjprog not found. Install nRF Command Line Tools.")
        info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
        return

    hex_path = prompt("Path to firmware .hex file")
    if not hex_path:
        warn("No file path provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return
    if hex_file.suffix.lower() not in (".hex", ".bin"):
        warn(f"Unexpected file extension: {hex_file.suffix}")
        info("  nrfjprog typically uses .hex (Intel HEX) format.")
        if not confirm("Continue?", default=False):
            return

    erase_mode = numbered_menu("Erase mode", [
        "--sectorerase (recommended — erase only written sectors)",
        "--eraseall (full chip erase — use for clean reflash)",
    ])
    erase_flag = "--sectorerase" if erase_mode == 0 else "--eraseall"

    if not confirm(f"Flash {hex_file.name} to nRF52840-DK with {erase_flag}?", default=True):
        info("Flash cancelled.")
        return

    info(f"Running: nrfjprog --program {hex_file} {erase_flag}")
    info("  This will flash the nRF52840 via J-Link SWD interface.")
    info("  The process takes a few seconds. Do NOT disconnect during flashing.")
    try:
        r = run(f"nrfjprog --program {hex_file} {erase_flag}")
        if r.returncode == 0:
            ok("Firmware flashed via nrfjprog.")
            info("Resetting the device…")
            r_reset = run("nrfjprog --reset")
            if r_reset.returncode == 0:
                ok("Device reset. New firmware is running.")
            else:
                warn("Reset command failed. Try pressing the RESET button on the DK.")
        else:
            err("nrfjprog flash failed.")
            info("Troubleshooting:")
            info("  - Check J-Link connection: nrfjprog --ids")
            info("  - Ensure the .hex file is compiled for nRF52840")
            info("  - If 'No emulator connected': re-seat the USB cable on the J-Link port")
            info("  - Check udev rules for J-Link access (plugdev group)")
            info("  - Try: sudo nrfjprog --program " + str(hex_file) + " " + erase_flag)
            info("  - J-Link firmware update may be needed: JLinkExe → connect → updatefw")
    except FileNotFoundError:
        err("nrfjprog not found. Install nRF Command Line Tools.")
    except Exception as e:
        err(f"nrfjprog flash error: {e}")


def op_create_dfu_package():
    heading("Create DFU Package")
    info("Creating a nrfutil DFU .zip package from a .hex firmware file.")
    info("This package is required for flashing the dongle via USB CDC DFU.")
    info("")
    info("nrfutil pkg generate parameters:")
    info("  --hw-version 52    Hardware version (always 52 for nRF52840)")
    info("  --sd-req 0x00      No SoftDevice requirement (for ZB/Thread/custom firmware)")
    info("  --sd-req 0x0101    Require SoftDevice S140 (for BLE firmware with S140)")
    info("  --application      Path to the .hex file to package")
    info("")
    info("Common SoftDevice requirement codes:")
    info("  0x0101 = S140 v7.x  (BLE)")
    info("  0x00   = No SoftDevice (Zigbee, Thread, custom)")
    info("")

    hex_path = prompt("Path to source .hex firmware file")
    if not hex_path:
        warn("No file provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return

    output_name = hex_file.stem + "_dfu_package.zip"
    output_path = prompt(f"Output .zip package path", default=str(hex_file.parent / output_name))
    output_zip = Path(output_path)

    sd_req = prompt("SoftDevice requirement code (0x00 for none, 0x0101 for S140)", default="0x00")

    if not confirm(f"Create DFU package: {output_zip.name}?", default=True):
        info("Package creation cancelled.")
        return

    cmd = (
        f"nrfutil pkg generate --hw-version 52 --sd-req {sd_req} "
        f"--application {hex_file} {output_zip}"
    )
    info(f"Running: {cmd}")
    try:
        r = run(cmd)
        if r.returncode == 0:
            ok(f"DFU package created: {output_zip}")
            info(f"  Use this .zip with 'Flash Dongle via nrfutil DFU'.")
        else:
            err("DFU package creation failed.")
            info("  Check: is the .hex file valid? (nrfjprog --program can verify)")
            info("  Check: is nrfutil installed? (pip install nrfutil)")
            info("  Try different --sd-req value if your firmware uses a SoftDevice")
    except FileNotFoundError:
        err("nrfutil not found. Install: pip install nrfutil --break-system-packages")
    except Exception as e:
        err(f"Package creation error: {e}")


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking nRF52840 firmware version...")
    info("  For DK boards: firmware version is shown in nrfjprog output")
    info("  For Dongle (BLE Sniffer): check via nrfutil")
    current = None
    try:
        r_info = run_output("nrfjprog --version 2>/dev/null")
        if r_info:
            import re
            m = re.search(r'nrfjprog\s+([\d.]+)', r_info)
            if m:
                info(f"  nrfjprog version: {m.group(1)}")
    except Exception as e:
        info(f"  nrfjprog check failed: {e}")

    info("Checking latest nRF BLE Sniffer release on GitHub...")
    latest, url = check_latest_github_release("NordicSemiconductor", "nRF-Sniffer-for-Bluetooth-LE")
    if latest:
        info(f"  Latest BLE Sniffer: {latest}")
        info(f"  Release: {url}")
        firmware_dir = get_firmware_dir("nordic_nrf52840") / "ble_sniffer"
        if not any(firmware_dir.iterdir()) if firmware_dir.exists() else True:
            if confirm("Download latest BLE Sniffer firmware?", default=False):
                from common import get_github_release_asset_url, download_firmware
                asset_url = get_github_release_asset_url(
                    "NordicSemiconductor", "nRF-Sniffer-for-Bluetooth-LE",
                    latest, r"nRF_Sniffer.*\.zip$"
                )
                if asset_url:
                    dest = firmware_dir / f"nRF_Sniffer_{latest}.zip"
                    download_firmware(asset_url, dest, "nRF BLE Sniffer")
    else:
        warn("Could not reach GitHub for version check.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial
    info("Ensuring pyserial for USB CDC serial communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    # requests for GitHub API
    info("Ensuring requests library for version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Checking udev rules for nRF52840 USB access…")
    _check_udev_rules()

    info("Checking nrfutil (DFU tool for dongle flashing)…")
    _check_nrfutil()

    info("Checking nrfjprog (J-Link tool for DK programming)…")
    _check_nrfjprog()

    info("Detecting nRF52840 device via USB VID:PIDs 1915:521F, 1915:520F, 1366:1015…")
    info("  Dongle DFU mode   : 1915:521F — press side button to activate")
    info("  Dongle app mode   : 1915:520F — normal operation")
    info("  DK J-Link         : 1366:1015 — J-Link USB port connected")

    found = web_detect_loop(detect_nrf52840, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Nordic nRF52840 not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"nRF52840 detected on {port}")
    check_firmware_version()

    variant = _identify_variant()
    if variant == "dongle_dfu":
        ok("Variant: nRF52840 Dongle — DFU bootloader mode (1915:521F)")
        info("  Device is ready for DFU firmware flashing via nrfutil.")
    elif variant == "dongle_app":
        ok("Variant: nRF52840 Dongle — application mode (1915:520F)")
        info("  Press side button to enter DFU mode for firmware flashing.")
    elif variant == "dk":
        ok("Variant: nRF52840-DK — J-Link JTAG debugger (1366:1015)")
        info("  Use nrfjprog for firmware programming.")
        info("  CDC UART debug output may be on a separate /dev/ttyACM* port.")
    else:
        warn("Could not identify specific variant.")

    _check_dialout(port)

    MENU_OPTIONS = [
        "Device Info",
        "BLE Sniffer Setup",
        "Zigbee / Thread NCP Info",
        "Flash Dongle (nrfutil DFU)",
        "Flash DK (J-Link / nrfjprog)",
        "Create DFU Package",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Nordic nRF52840 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_ble_sniff(port)
        elif choice == 2:
            op_zigbee_info()
        elif choice == 3:
            op_flash_dongle(port)
        elif choice == 4:
            op_flash_dk(port)
        elif choice == 5:
            op_create_dfu_package()
        elif choice == 6:
            info("Goodbye.")
            break

        # Re-check port after operations (dongle mode may change)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")
            variant = _identify_variant()
            if variant == "dongle_dfu":
                info("  Dongle is now in DFU mode.")
            elif variant == "dongle_app":
                info("  Dongle is now in application mode.")


if __name__ == "__main__":
    main()
