#!/usr/bin/env python3
"""
Qorvo/Decawave DWM3001CDK UWB Development Kit Tool Manager
Handles device detection, J-Link firmware programming, DFU flashing,
firmware option listing, and serial debug console for the DWM3001CDK
UWB (Ultra-Wideband) development kit.

Usage:
    python3 dwm3001cdk.py

Board overview:
    The DWM3001CDK is a UWB development kit from Qorvo (formerly Decawave) built around:
        - Nordic nRF52833 (ARM Cortex-M4 host MCU)
        - Decawave DW3110 UWB transceiver (IEEE 802.15.4z HRP UWB)
        - Onboard Segger J-Link JTAG debugger (1366:1015)
        - USB CDC serial for debug console (1915:521F via nRF52833)

USB VID:PIDs:
    0x1915:0x521F — Nordic nRF52833 CDC UART (debug console, DFU)
    0x1366:0x1015 — Segger J-Link JTAG (onboard debugger for firmware flashing)

NOTE: When connecting DWM3001CDK via USB, TWO USB devices appear:
    1. J-Link debugger  (1366:1015) — for firmware programming
    2. Nordic CDC serial (1915:521F) — for debug output and DFU

UWB capabilities of DW3110:
    - IEEE 802.15.4z HRP UWB (High Rate Pulse)
    - Two-Way Ranging (TWR) — precision distance measurement (±10cm typical)
    - Time Difference of Arrival (TDoA) — positioning with multiple anchors
    - Fine Ranging (FiRa) protocol — standard interoperable UWB ranging
    - Channel 5 (6.5 GHz) and Channel 9 (8.0 GHz) support
    - Blink rate: up to 6500 Hz burst, 500 Hz continuous

Security research applications:
    - UWB relay attacks — test relay attack mitigations (AES-128 STS)
    - Ranging manipulation — test distance spoofing scenarios
    - Protocol fuzzing — FiRa/CCC protocol testing
    - UWB traffic capture with custom firmware
    - Car access system testing (passive entry/start UWB)

Linux serial/J-Link permissions:
    CDC serial: add to dialout group — sudo usermod -aG dialout $USER
    J-Link:     add to plugdev group — sudo usermod -aG plugdev $USER
    Then re-login. Debug: dmesg | tail -20

J-Link flashing reference:
    nrfjprog --ids                                    List connected J-Link devices
    nrfjprog --program <hex> -f NRF52 --sectorerase  Flash nRF52833 via J-Link
    nrfjprog --reset -f NRF52                        Reset device via J-Link
    nrfjprog --eraseall -f NRF52                     Full chip erase

Firmware sources:
    Qorvo QMatter SDK: https://github.com/Qorvo/QMatter/releases
    Qorvo UWB SDK:     https://www.qorvo.com/products/d/da008577 (requires account)
    Nordic sdk-nrf:    For nRF52833 base firmware components
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
    check_latest_github_release,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Qorvo DWM3001CDK"
DESCRIPTION = "nRF52833 + DW3110 UWB development kit — IEEE 802.15.4z, FiRa, TWR, TDoA"

VID_PIDS = [
    (0x1915, 0x521F),  # Nordic nRF52833 CDC UART (DFU bootloader / debug)
    (0x1366, 0x1015),  # Segger J-Link onboard debugger
]

VID_PID_CDC   = [(0x1915, 0x521F)]
VID_PID_JLINK = [(0x1366, 0x1015)]

BAUD_RATE = 115200

QMATTER_API_URL = "https://api.github.com/repos/Qorvo/QMatter/releases/latest"
QORVO_SDK_URL   = "https://www.qorvo.com/products/d/da008577"

CONNECT_INSTRUCTIONS = (
    "Qorvo DWM3001CDK not detected.\n\n"
    "  Connect DWM3001CDK via USB. Two USB devices should appear:\n"
    "    1. J-Link debugger  — VID:PID 1366:1015 (for firmware programming)\n"
    "    2. Nordic CDC UART  — VID:PID 1915:521F (for debug output and DFU)\n\n"
    "  If only one device appears:\n"
    "    - J-Link only: check if nRF52833 firmware is running (CDC may not enumerate)\n"
    "    - CDC only: J-Link software may not be installed (affects detection, not CDC)\n\n"
    "  Install J-Link Software (required for nrfjprog firmware programming):\n"
    "    Linux (Kali/Debian): apt install jlink\n"
    "                         OR download .deb: https://www.segger.com/downloads/jlink/\n"
    "                         sudo dpkg -i JLink_Linux_*.deb\n"
    "    macOS: brew install --cask segger-jlink\n"
    "           OR download from: https://www.segger.com/downloads/jlink/\n\n"
    "  Install nRF Command Line Tools (nrfjprog):\n"
    "    https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools\n"
    "    Linux: download .tar.gz, extract, run sudo ./install.sh\n"
    "    macOS: brew install --cask nordic-nrf-command-line-tools\n\n"
    "  Linux permissions:\n"
    "    sudo usermod -aG dialout $USER   (for CDC serial)\n"
    "    sudo usermod -aG plugdev $USER   (for J-Link USB)\n"
    "    Then log out and back in.\n"
    "    Debug: dmesg | tail -20  |  lsusb | grep -E '1915|1366'"
)

UDEV_RULES_CONTENT = (
    '# Qorvo DWM3001CDK udev rules\n'
    '# Nordic nRF52833 CDC UART (VID:PID 1915:521F)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="521f", '
    'MODE="0666", GROUP="dialout"\n'
    '# Segger J-Link onboard debugger (VID 1366, all PIDs)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="1366", MODE="0666", GROUP="plugdev"\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1366", MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-dwm3001cdk.rules"

# Firmware options for DWM3001CDK
FIRMWARE_OPTIONS = [
    {
        "name": "MCPS API Demo",
        "description": "MAC Common Part Sublayer API demonstration firmware.",
        "detail": (
            "Demonstrates the Qorvo MCPS API for UWB ranging.\n"
            "  Provides a standardized MCPS API interface for distance measurement.\n"
            "  Communication: CDC UART debug console at 115200 baud.\n"
            "  Source: Qorvo QMatter SDK — samples/mcps_api_demo/"
        ),
    },
    {
        "name": "FiRa Demo",
        "description": "FiRa Consortium protocol ranging demonstration.",
        "detail": (
            "Implements FiRa interoperable UWB ranging standard.\n"
            "  FiRa = Fine Ranging — the standard for UWB in smartphones/access control.\n"
            "  Compatible with Apple U1, Samsung UWB, NXP UWB, and other FiRa devices.\n"
            "  Security: AES-128 STS (Scrambled Timestamp Sequence) for relay protection.\n"
            "  Source: Qorvo QMatter SDK — samples/fira_demo/"
        ),
    },
    {
        "name": "TWR Demo",
        "description": "Two-Way Ranging (TWR) demonstration firmware.",
        "detail": (
            "Classic Two-Way Ranging for precise distance measurement.\n"
            "  Uses SS-TWR (Single-Sided) or DS-TWR (Double-Sided) ranging.\n"
            "  DS-TWR eliminates clock drift error — accuracy to ±10cm typical.\n"
            "  Role: can be configured as Initiator (master) or Responder (slave).\n"
            "  Source: Qorvo QMatter SDK — samples/twr_demo/\n"
            "  Also available as standalone from Decawave TREK1000 examples."
        ),
    },
    {
        "name": "OpenThread Border Router NCP",
        "description": "Thread/Matter Network Co-Processor firmware for OTBR.",
        "detail": (
            "Run the nRF52833 as an OpenThread NCP for a Linux-based Border Router.\n"
            "  Requires OpenThread Border Router (OTBR) on the host (Raspberry Pi or Linux).\n"
            "  Enables Thread mesh networking alongside UWB ranging.\n"
            "  Firmware: sdk-nrf OpenThread NCP sample\n"
            "  Source: https://github.com/NordicSemiconductor/sdk-nrf"
        ),
    },
    {
        "name": "Custom firmware (.hex file)",
        "description": "Flash a custom .hex firmware file via J-Link or DFU.",
        "detail": (
            "Provide your own firmware compiled for nRF52833 target.\n"
            "  Use the Zephyr RTOS + sdk-nrf toolchain for nRF52833 development.\n"
            "  Toolchain: https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/getting_started.html\n"
            "  Target board: qorvo_dwm3001cdk (or nrf52833dk/nrf52833)\n"
            "  Build with west: west build -b qorvo_dwm3001cdk <application_dir>"
        ),
    },
]


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_dwm3001cdk() -> bool:
    info("Scanning USB for DWM3001CDK (VID:PIDs 1915:521F, 1366:1015)…")
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Qorvo DWM3001CDK…")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written and reloaded: {UDEV_RULES_PATH}")
        info("Unplug and replug the DWM3001CDK to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Tool checks ───────────────────────────────────────────────────────────────

def _check_nrfjprog() -> bool:
    info("Checking nrfjprog (nRF Command Line Tools for J-Link programming)…")
    path = run_output("which nrfjprog 2>/dev/null || true")
    if path and path.strip():
        ok(f"nrfjprog found: {path.strip()}")
        ver = run_output("nrfjprog --version 2>/dev/null || true")
        if ver:
            info(f"  nrfjprog version: {ver.strip()}")
        return True

    warn("nrfjprog not found. J-Link firmware programming will not be available.")
    info("  Install nRF Command Line Tools from:")
    info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
    flavor = get_os_flavor()
    if flavor == "darwin":
        info("  macOS: brew install --cask nordic-nrf-command-line-tools")
        if confirm("Attempt install via brew cask?", default=True):
            ensure_brew_packages(["nordic-nrf-command-line-tools"])
    else:
        info("  Linux (Kali/Debian/Ubuntu):")
        info("    1. Download .tar.gz from Nordic website")
        info("    2. tar xzf nRF-Command-Line-Tools_*.tar.gz")
        info("    3. sudo ./install.sh")
        info("    4. Verify: nrfjprog --version")
    return False


def _check_nrfutil() -> bool:
    info("Checking nrfutil (Nordic DFU tool for DFU firmware flashing)…")
    path = run_output("which nrfutil 2>/dev/null || true")
    if path and path.strip():
        ok(f"nrfutil found: {path.strip()}")
        return True
    warn("nrfutil not found. Installing via pip…")
    ensure_pip_packages([("nrfutil", "nrfutil")])
    path2 = run_output("which nrfutil 2>/dev/null || true")
    if path2 and path2.strip():
        ok("nrfutil installed.")
        return True
    err("nrfutil still not found after pip install.")
    info("  Manual: pip install nrfutil --break-system-packages")
    return False


def _check_jlink_software():
    """Check for Segger J-Link software (JLinkExe / JLink)."""
    info("Checking Segger J-Link software (JLinkExe)…")
    path = run_output("which JLinkExe 2>/dev/null || which JLink 2>/dev/null || true")
    if path and path.strip():
        ok(f"J-Link software found: {path.strip()}")
        return True
    warn("Segger J-Link software not found.")
    info("  The J-Link software provides the DLL required by nrfjprog.")
    info("  Install from: https://www.segger.com/downloads/jlink/")
    flavor = get_os_flavor()
    if flavor == "darwin":
        info("  macOS: brew install --cask segger-jlink")
        if confirm("Attempt install via brew cask?", default=True):
            ensure_brew_packages(["segger-jlink"])
    else:
        info("  Linux (Kali): apt install jlink  (if available in repo)")
        info("  Or: download .deb from https://www.segger.com/downloads/jlink/")
        info("       sudo dpkg -i JLink_Linux_*.deb")
        jlink_apt = run_output("apt-cache show jlink 2>/dev/null || true")
        if jlink_apt and "Package:" in jlink_apt:
            info("  'jlink' package found in apt cache.")
            if confirm("Install jlink via apt?", default=True):
                ensure_apt_packages(["jlink"])
        else:
            info("  'jlink' not in apt cache. Manual download required.")
    return False


# ── GitHub version check ──────────────────────────────────────────────────────

def _get_latest_firmware_version() -> str:
    info("Fetching latest Qorvo QMatter firmware version from GitHub…")
    info(f"  API URL: {QMATTER_API_URL}")
    try:
        import requests
        resp = requests.get(QMATTER_API_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name", "unknown")
        name = data.get("name", "unknown")
        info(f"  Latest QMatter release tag: {tag}")
        info(f"  Release name: {name}")
        assets = data.get("assets", [])
        hex_assets = [a["name"] for a in assets if a["name"].endswith((".hex", ".bin", ".zip"))]
        if hex_assets:
            info("  Available firmware assets:")
            for a in hex_assets[:10]:  # Limit to first 10
                info(f"    {a}")
        return tag
    except Exception as e:
        warn(f"Could not fetch QMatter version: {e}")
        info("  Check: curl " + QMATTER_API_URL)
        return "unknown"


# ── Serial helpers ────────────────────────────────────────────────────────────

def _open_serial(port: str):
    import serial
    info(f"Opening serial port {port} at {BAUD_RATE} baud…")
    info("  DWM3001CDK debug console settings: 115200 8N1, no flow control.")
    ser = serial.Serial(
        port=port,
        baudrate=BAUD_RATE,
        timeout=2,
        bytesize=8,
        parity="N",
        stopbits=1,
    )
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
            ok(f"User '{username}' is in the dialout group.")
            return
    except KeyError:
        return
    warn(f"User '{username}' is NOT in the 'dialout' group.")
    info(f"  Fix: sudo usermod -aG dialout {username}  (then log out/in)")
    info(f"  Check device permissions: ls -la {port}")
    if confirm("Add to dialout group now?", default=True):
        rc = sudo_run(f"usermod -aG dialout {username}")
        if rc.returncode == 0:
            ok("Added. Log out and back in, or run: newgrp dialout")
        else:
            err("Failed to add to dialout group.")


def _check_plugdev():
    """Ensure user is in plugdev group for J-Link USB access."""
    if get_os_flavor() == "darwin":
        return
    import grp
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    try:
        gid = grp.getgrnam("plugdev").gr_gid
        if gid in os.getgroups():
            ok(f"User '{username}' is in the plugdev group (J-Link access OK).")
            return
    except KeyError:
        info("plugdev group does not exist on this system (OK for some distros).")
        return
    warn(f"User '{username}' is NOT in the 'plugdev' group.")
    info("  J-Link USB access may require plugdev group membership.")
    info(f"  Fix: sudo usermod -aG plugdev {username}  (then log out/in)")
    if confirm("Add to plugdev group now?", default=True):
        sudo_run(f"usermod -aG plugdev {username}")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Gathering DWM3001CDK device information from all available interfaces.")
    info("")
    info("DWM3001CDK hardware summary:")
    info("  Host MCU   : Nordic nRF52833 (64MHz ARM Cortex-M4F, 512KB flash, 128KB RAM)")
    info("  UWB Radio  : Decawave DW3110 (IEEE 802.15.4z HRP UWB transceiver)")
    info("  Interface  : DW3110 connected to nRF52833 via SPI")
    info("  JTAG Debug : Segger J-Link (onboard, separate from nRF52833)")
    info("  Antenna    : Onboard PCB antenna for both UWB and BLE")
    info("  Power      : 5V via USB, 3.3V regulated onboard")
    info("")

    # USB port enumeration
    info("USB interfaces detected:")
    cdc_port  = find_serial_port_by_vidpid(VID_PID_CDC)
    jlink_port = find_serial_port_by_vidpid(VID_PID_JLINK)

    if cdc_port:
        ok(f"  CDC UART (nRF52833): {cdc_port} — VID:PID 1915:521F")
    else:
        warn("  CDC UART (1915:521F) not detected.")
        info("    The CDC interface requires the nRF52833 firmware to initialize USB.")
        info("    If J-Link is present but CDC is not: firmware may not have USB enabled.")

    if jlink_port:
        ok(f"  J-Link debugger:     {jlink_port} — VID:PID 1366:1015")
    else:
        warn("  J-Link (1366:1015) not detected.")
        info("    Install J-Link Software: https://www.segger.com/downloads/jlink/")
        info("    On Kali: apt install jlink  or  dpkg -i JLink_Linux_*.deb")

    # Show pyserial details
    info("")
    info("USB port details (pyserial):")
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
        warn(f"Could not read pyserial port info: {e}")

    # J-Link device query
    if jlink_port:
        info("")
        info("Querying J-Link connected devices via nrfjprog…")
        try:
            r = run("nrfjprog --ids")
            if r.returncode == 0:
                ok("J-Link device enumeration complete.")
            else:
                warn("nrfjprog --ids returned an error.")
                info("  Troubleshooting:")
                info("    - Is the J-Link Software installed? (JLinkExe or JLink in PATH)")
                info("    - Check: dmesg | tail -20 for J-Link USB events")
                info("    - Check plugdev group: id " + (os.environ.get("USER") or ""))
                info("    - Try: sudo nrfjprog --ids (to rule out permission issue)")
        except FileNotFoundError:
            warn("nrfjprog not found. Install nRF Command Line Tools.")
            info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
        except Exception as e:
            err(f"nrfjprog error: {e}")

    # Quick serial probe on CDC port
    if cdc_port:
        info("")
        info(f"Probing CDC debug UART on {cdc_port}…")
        info("  Reading initial boot messages (if any)…")
        try:
            with _open_serial(cdc_port) as ser:
                time.sleep(0.5)
                if ser.in_waiting:
                    data = ser.read(min(ser.in_waiting, 1024))
                    boot_msg = data.decode("utf-8", errors="replace").strip()
                    if boot_msg:
                        info("  Boot output from nRF52833:")
                        for line in boot_msg.splitlines():
                            info(f"    {line}")
                    else:
                        info("  No boot messages (device may already be past startup).")
                else:
                    info("  No serial data available right now.")
                    info("  The debug console output depends on the firmware running.")
        except PermissionError:
            err(f"Permission denied on {cdc_port}.")
            _check_dialout(cdc_port)
        except Exception as e:
            warn(f"CDC probe failed: {e}")

    ok("Device info gathering complete.")


def op_flash_jlink(port: str):
    heading("Flash via J-Link (nrfjprog)")
    info("Programming the DWM3001CDK nRF52833 via the onboard Segger J-Link debugger.")
    info("")
    info("This method uses nrfjprog to write firmware via the J-Link SWD interface.")
    info("It does NOT require USB CDC — the J-Link interface is used exclusively.")
    info("The -f NRF52 flag targets the nRF52 family (nRF52833 in DWM3001CDK).")
    info("")
    info("WHEN TO USE THIS METHOD:")
    info("  - Initial firmware programming on a blank device")
    info("  - Recovering from a bricked/corrupt firmware")
    info("  - When CDC DFU is not available")
    info("  - Faster than DFU for development/testing cycles")
    info("")

    # Verify J-Link is present
    jlink_port = find_serial_port_by_vidpid(VID_PID_JLINK)
    if not jlink_port:
        err("J-Link debugger (1366:1015) not detected.")
        info("  Connect the DWM3001CDK via its USB cable (provides J-Link).")
        info("  Install J-Link Software: https://www.segger.com/downloads/jlink/")
        info("  On Kali/Debian: sudo apt install jlink  or  sudo dpkg -i JLink_Linux_*.deb")
        info("  macOS: brew install --cask segger-jlink")
        info("  Check: lsusb | grep 1366  and  dmesg | tail -20")
        return

    info(f"J-Link detected on {jlink_port}.")

    # Confirm nrfjprog works
    info("Verifying nrfjprog connection to J-Link…")
    try:
        r = run("nrfjprog --ids")
        if r.returncode != 0:
            err("nrfjprog --ids failed. J-Link may not be accessible.")
            info("  Troubleshooting:")
            info("    - Is the J-Link Software installed? (JLinkExe in PATH)")
            info("    - Check plugdev group: sudo usermod -aG plugdev $USER")
            info("    - Check udev rules: ls -la /dev/bus/usb/...")
            info("    - Try: sudo nrfjprog --ids (to check if it's a permissions issue)")
            info("    - Reconnect the USB cable")
            if not confirm("Continue anyway?", default=False):
                return
    except FileNotFoundError:
        err("nrfjprog not found. Install nRF Command Line Tools.")
        return
    except Exception as e:
        warn(f"nrfjprog check error: {e}")

    hex_path = prompt("Path to firmware .hex file")
    if not hex_path:
        warn("No firmware file provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return
    if hex_file.suffix.lower() not in (".hex", ".bin"):
        warn(f"Unexpected file extension: {hex_file.suffix}")
        info("  nrfjprog typically uses .hex (Intel HEX) format for nRF52833.")
        if not confirm("Continue?", default=False):
            return

    erase_mode = numbered_menu("Erase mode before flashing", [
        "--sectorerase  (recommended — erase only sectors being written)",
        "--eraseall     (full chip erase — use for clean initial flash)",
    ])
    erase_flag = "--sectorerase" if erase_mode == 0 else "--eraseall"

    if not confirm(f"Flash {hex_file.name} to DWM3001CDK nRF52833 with {erase_flag}?", default=True):
        info("Flash cancelled.")
        return

    flash_cmd = f"nrfjprog --program {hex_file} -f NRF52 {erase_flag}"
    info(f"Running: {flash_cmd}")
    info("  Flashing via J-Link SWD. Do NOT disconnect during programming.")
    info("  Expected duration: 10-60 seconds depending on firmware size.")
    try:
        r = run(flash_cmd)
        if r.returncode == 0:
            ok("Firmware flashed successfully via J-Link.")
            info("Resetting nRF52833 via J-Link…")
            r_reset = run("nrfjprog --reset -f NRF52")
            if r_reset.returncode == 0:
                ok("Device reset. New firmware is running.")
                info("  The CDC UART may take a few seconds to re-enumerate.")
                info("  Check: ls /dev/ttyACM*  or  dmesg | tail -10")
            else:
                warn("Reset command failed. Try pressing the RESET button on the DWM3001CDK.")
        else:
            err("nrfjprog flash failed.")
            info("Troubleshooting J-Link programming failures:")
            info("  1. Check nrfjprog --ids — can the J-Link enumerate?")
            info("  2. Is the DWM3001CDK powered? USB connected?")
            info("  3. For 'No emulator connected': try re-seating the USB cable")
            info("  4. For 'Could not erase': try --eraseall flag")
            info("  5. For permission errors: check plugdev group")
            info("     sudo usermod -aG plugdev $USER && newgrp plugdev")
            info("  6. J-Link firmware may need updating: JLinkExe → connect → updatefw")
            info("  7. Try: sudo " + flash_cmd)
    except FileNotFoundError:
        err("nrfjprog not found. Install nRF Command Line Tools.")
        info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
    except Exception as e:
        err(f"J-Link flash error: {e}")
        info("  Debug: check dmesg | tail -20 for J-Link USB errors")


def op_flash_dfu(port: str):
    heading("Flash via DFU (nrfutil)")
    info("Programming the DWM3001CDK nRF52833 via USB CDC DFU bootloader.")
    info("This method uses nrfutil and the nRF52833 DFU bootloader over CDC serial.")
    info("")
    info("REQUIREMENTS:")
    info("  - The DWM3001CDK must have a DFU-capable bootloader installed on the nRF52833.")
    info("  - The CDC serial port must be enumerated (VID:PID 1915:521F).")
    info("  - nrfutil must be installed (pip install nrfutil).")
    info("")
    info("DFU MODE ENTRY:")
    info("  Method 1: Reset with DFU pin held — check board schematic for DFU pin")
    info("  Method 2: Software reset into DFU from running firmware (if supported)")
    info("  Method 3: Via existing serial console command (firmware-dependent)")
    info("")
    info("DFU PACKAGE FORMAT:")
    info("  nrfutil expects a .zip DFU package.")
    info("  Create from .hex: nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\")
    info("                        --application <firmware.hex> <output.zip>")
    info("")

    cdc_port = find_serial_port_by_vidpid(VID_PID_CDC)
    if not cdc_port:
        err("Nordic CDC UART (1915:521F) not detected.")
        info("  The CDC interface is required for DFU flashing.")
        info("  If only J-Link is present: use 'Flash via J-Link' instead.")
        return

    info(f"CDC UART detected on {cdc_port}.")

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
        info("  Create: nrfutil pkg generate --hw-version 52 --sd-req 0x00 --application <hex> <pkg.zip>")
        if not confirm("Continue anyway?", default=False):
            return

    if not confirm(f"Flash {pkg.name} to DWM3001CDK via DFU on {cdc_port}?", default=True):
        info("DFU flash cancelled.")
        return

    cmd = f"nrfutil dfu usb-serial -pkg {pkg} -p {cdc_port}"
    info(f"Running: {cmd}")
    info("  Do NOT disconnect the device during DFU flashing.")
    info("  The process takes ~15-45 seconds.")
    try:
        r = run(cmd)
        if r.returncode == 0:
            ok("DFU flash completed successfully.")
            info("  Device will reboot and run new firmware.")
            info("  CDC may re-enumerate — check: ls /dev/ttyACM*")
        else:
            err("nrfutil DFU flash failed.")
            info("Troubleshooting DFU failures:")
            info("  - Ensure the device is in DFU bootloader mode, not application mode")
            info("  - Verify the .zip was built for nRF52833 (hw-version 52)")
            info("  - Check: nrfutil version (older nrfutil may have compatibility issues)")
            info("  - Try: dmesg | tail -20 for USB errors")
            info("  - Check: ls -la " + cdc_port + " for permission issues")
            info("  - If bootloader is not present, use J-Link to flash one first:")
            info("    Flash a DFU bootloader .hex via 'Flash via J-Link'")
    except FileNotFoundError:
        err("nrfutil not found. Install: pip install nrfutil --break-system-packages")
    except Exception as e:
        err(f"DFU flash error: {e}")


def op_list_firmware_options():
    heading("Firmware Options for DWM3001CDK")
    info("The DWM3001CDK supports several firmware configurations.")
    info("Each option targets a different UWB/wireless use case.")
    info("")

    info("Checking latest available firmware version from Qorvo GitHub…")
    latest = _get_latest_firmware_version()
    if latest != "unknown":
        ok(f"Latest QMatter release: {latest}")
    info("")
    info("NOTE: The primary Qorvo UWB SDK requires account registration:")
    info(f"  {QORVO_SDK_URL}")
    info("  Create a free account at: https://www.qorvo.com/account/sign-up")
    info("  The QMatter GitHub repo has open-source examples and some pre-built binaries.")
    info("")

    for i, opt in enumerate(FIRMWARE_OPTIONS):
        info(f"  [{i+1}] {opt['name']}")
        info(f"       {opt['description']}")

    info("")
    choice = numbered_menu("Show detailed info for a firmware option?", [
        o["name"] for o in FIRMWARE_OPTIONS
    ] + ["Back to main menu"])

    if choice < len(FIRMWARE_OPTIONS):
        selected = FIRMWARE_OPTIONS[choice]
        info("")
        heading(f"Firmware: {selected['name']}")
        for line in selected["detail"].splitlines():
            info(f"  {line}")
        info("")
        info("FLASHING THIS FIRMWARE:")
        info("  1. Obtain the .hex file from the Qorvo SDK or GitHub releases")
        info("  2. Use 'Flash via J-Link' → provide the .hex file path")
        info("  3. Or create a DFU .zip and use 'Flash via DFU'")
        info("")
        info("BUILD FROM SOURCE:")
        info("  git clone https://github.com/Qorvo/QMatter")
        info("  Follow the QMatter README for build environment setup (Zephyr/ncs)")
        ok(f"Firmware option '{selected['name']}' described.")
    else:
        info("Returning to main menu.")


def op_serial_monitor(port: str):
    heading("Serial Monitor (CDC UART Debug Console)")
    info("Opening serial monitor on the DWM3001CDK debug UART.")
    info("The nRF52833 firmware outputs debug logs, ranging data, and status to this port.")
    info("")
    info(f"CDC serial port: {port}")
    info(f"Baud rate: {BAUD_RATE}")
    info("")
    info("What to expect in the serial output (firmware-dependent):")
    info("  MCPS API Demo : UWB ranging results, timestamps, distance measurements")
    info("  FiRa Demo     : FiRa session status, initiator/responder roles, distances")
    info("  TWR Demo      : Two-way ranging initiator/responder exchange logs")
    info("  Custom        : Application-specific output")
    info("")
    info("TYPICAL RANGING OUTPUT FORMAT (TWR Demo):")
    info("  [RANGING] Distance: 1.234 m  |  RxPower: -85 dBm  |  FP: -91 dBm")
    info("  [RANGING] Seq: 001  |  Nlos: 0  |  Q: 100")
    info("")
    info("Serial monitor options:")
    info("  1. Python fallback (reads/prints raw serial bytes)")
    info("  2. screen:  screen " + port + " " + str(BAUD_RATE))
    info("  3. minicom: minicom -D " + port + " -b " + str(BAUD_RATE))
    info("  4. picocom: picocom -b " + str(BAUD_RATE) + " " + port)
    info("")

    method = numbered_menu("Choose serial monitor method", [
        "Python raw serial (built-in fallback)",
        "screen",
        "minicom",
        "picocom",
        "Cancel",
    ])

    if method == 0:
        info(f"Opening {port} at {BAUD_RATE} baud. Press Ctrl+C to stop.")
        try:
            with _open_serial(port) as ser:
                ok("Serial port open. Displaying output (Ctrl+C to stop):")
                while True:
                    if ser.in_waiting:
                        data = ser.read(min(ser.in_waiting, 4096))
                        print(data.decode("utf-8", errors="replace"), end="", flush=True)
                    time.sleep(0.02)
        except KeyboardInterrupt:
            info("Serial monitor stopped.")
        except PermissionError:
            err(f"Permission denied on {port}.")
            _check_dialout(port)
        except Exception as e:
            err(f"Serial read error: {e}")
            info(f"  Debug: ls -la {port}  and  dmesg | tail -20")
    elif method == 1:
        info(f"Running: screen {port} {BAUD_RATE}")
        info("  Exit: Ctrl+A then K  (or Ctrl+A then \\)")
        try:
            run(f"screen {port} {BAUD_RATE}")
        except Exception as e:
            err(f"screen error: {e}")
            info("Install: apt install screen  or  brew install screen")
    elif method == 2:
        info(f"Running: minicom -D {port} -b {BAUD_RATE}")
        info("  Exit: Ctrl+A then X")
        try:
            run(f"minicom -D {port} -b {BAUD_RATE}")
        except Exception as e:
            err(f"minicom error: {e}")
            info("Install: apt install minicom  or  brew install minicom")
    elif method == 3:
        info(f"Running: picocom -b {BAUD_RATE} {port}")
        info("  Exit: Ctrl+A then Ctrl+Q")
        try:
            run(f"picocom -b {BAUD_RATE} {port}")
        except Exception as e:
            err(f"picocom error: {e}")
            info("Install: apt install picocom  or  brew install picocom")
    else:
        info("Serial monitor cancelled.")


# ── Firmware Version Check ────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("DWM3001CDK firmware check...")
    info("")
    info("The DWM3001CDK uses Qorvo QMatter SDK firmware.")
    info("Firmware download requires registration at:")
    info("  https://www.qorvo.com/products/p/DWM3001CDK")
    info("")
    info("To check current firmware version:")
    info("  1. Connect via J-Link and run: nrfjprog --memrd 0x10001010 --n 4")
    info("     (reads FICR.INFO.PART register — identifies the nRF chip variant)")
    info("  2. Flash the TWR demo and open serial terminal at 115200 baud")
    info("     The boot message includes the firmware version string")
    info("  3. Via nrfutil: nrfutil device info --serial-number <SN>")
    info("")

    # Try to get version via nrfjprog
    try:
        out = run_output("nrfjprog --version 2>/dev/null")
        if out:
            info(f"  nrfjprog available: {out.strip()[:100]}")
        else:
            info("  nrfjprog not found — install for J-Link flashing support")
    except Exception:
        pass

    info("")
    info("Checking QMatter GitHub for release information...")
    latest, url = check_latest_github_release("Qorvo", "QMatter")
    if latest:
        info(f"  Latest QMatter release: {latest}")
        info(f"  Release page: {url}")
        info("  Note: Download still requires Qorvo website registration.")
    else:
        info("  QMatter repository may not be public. Check: https://www.qorvo.com/products/p/DWM3001CDK")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial
    info("Ensuring pyserial for CDC UART communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    # requests for GitHub/Qorvo API
    info("Ensuring requests library for firmware version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("UWB (Ultra-Wideband) capabilities of this kit:")
    info("  - IEEE 802.15.4z HRP UWB — indoor ranging and positioning")
    info("  - FiRa protocol — interoperable with Apple, Samsung, NXP UWB devices")
    info("  - TWR (Two-Way Ranging) — precision distance measurement ±10cm")
    info("  - TDoA — Time Difference of Arrival positioning with multiple anchors")
    info("  - Security research: relay attacks, ranging spoofing, protocol fuzzing")
    info("")

    info("Checking udev rules for DWM3001CDK USB access…")
    _check_udev_rules()

    info("Checking J-Link software…")
    _check_jlink_software()

    info("Checking nrfjprog (J-Link programming tool)…")
    _check_nrfjprog()

    info("Checking nrfutil (DFU programming tool)…")
    _check_nrfutil()

    info("Checking user group memberships…")
    _check_plugdev()

    info("Detecting DWM3001CDK via USB VID:PIDs 1915:521F and 1366:1015…")
    info("  Expecting TWO USB devices:")
    info("    1915:521F — Nordic CDC UART (debug console + DFU)")
    info("    1366:1015 — Segger J-Link onboard debugger")

    found = web_detect_loop(detect_dwm3001cdk, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Qorvo DWM3001CDK not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"DWM3001CDK detected on {port}")

    cdc_present   = find_serial_port_by_vidpid(VID_PID_CDC) is not None
    jlink_present = find_serial_port_by_vidpid(VID_PID_JLINK) is not None

    if cdc_present and jlink_present:
        ok("Both J-Link and CDC UART interfaces detected — full functionality available.")
    elif jlink_present and not cdc_present:
        warn("Only J-Link detected. CDC UART not enumerated.")
        warn("  This is normal if the nRF52833 firmware does not initialize USB CDC.")
        info("  J-Link flash is available. Serial monitor will not work until CDC firmware is flashed.")
    elif cdc_present and not jlink_present:
        warn("Only CDC UART detected. J-Link not enumerated.")
        warn("  J-Link requires J-Link Software to be installed.")
        info("  Install: https://www.segger.com/downloads/jlink/")

    if cdc_present:
        cdc_p = find_serial_port_by_vidpid(VID_PID_CDC)
        _check_dialout(cdc_p)

    check_firmware_version()

    MENU_OPTIONS = [
        "Device Info",
        "Flash via J-Link (nrfjprog)",
        "Flash via DFU (nrfutil)",
        "List Firmware Options",
        "Serial Monitor (CDC UART)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Qorvo DWM3001CDK — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_jlink(port)
        elif choice == 2:
            op_flash_dfu(port)
        elif choice == 3:
            op_list_firmware_options()
        elif choice == 4:
            cdc_p = find_serial_port_by_vidpid(VID_PID_CDC)
            if cdc_p:
                op_serial_monitor(cdc_p)
            else:
                err("CDC UART (1915:521F) not available. Cannot open serial monitor.")
                info("  Flash firmware with USB CDC support via J-Link first.")
        elif choice == 5:
            info("Goodbye.")
            break

        # Re-check ports after each operation (flashing may cause re-enumeration)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")
        elif not new_port:
            warn("DWM3001CDK not detected after operation. It may be rebooting.")
            info("  Waiting up to 10 seconds for re-enumeration…")
            deadline = time.time() + 10
            while time.time() < deadline:
                time.sleep(2)
                new_port = find_serial_port_by_vidpid(VID_PIDS)
                if new_port:
                    port = new_port
                    ok(f"Device re-enumerated on {port}")
                    break
            else:
                warn("Device did not re-enumerate. Check USB connection.")


if __name__ == "__main__":
    main()
