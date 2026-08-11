#!/usr/bin/env python3
"""
Particle Photon 2 Tool Manager
Handles device info, cloud authentication, Device OS updates via OTA,
DFU firmware flashing, and serial monitoring for the Particle Photon 2
(RTL8721DM WiFi/BLE SoC).

Usage:
    python3 photon_2.py

Particle Photon 2 LED status reference:
    Breathing cyan       — Connected to Particle cloud (normal operation)
    Blinking blue        — Listening mode / DFU (hold MODE 3s or send via serial)
    Blinking green       — Connecting to WiFi
    Blinking cyan        — Connecting to Particle cloud
    Blinking magenta     — DFU mode (firmware update in progress)
    Solid magenta        — Entering DFU mode (hold MODE ~3 seconds)
    Blinking red (SOS)   — Panic / firmware crash (check firmware)
    White breathing      — Safe mode (holds cloud but does not run user app)

USB VID:PIDs:
    2B04:C305 — Photon 2 running application (normal CDC ACM)
    2B04:D305 — Photon 2 in DFU / listening mode

Linux serial permissions:
    Device appears as /dev/ttyACM* (USB CDC ACM).
    If you get "Permission denied", add your user to the dialout group:
        sudo usermod -aG dialout $USER
    Then log out and back in (or run: newgrp dialout).
    Check current groups: id
    Verify device presence: ls -la /dev/ttyACM*
    Check USB enumeration: dmesg | tail -20

Particle CLI reference:
    particle login                     — Authenticate with Particle cloud
    particle identify                  — Read device ID, Device OS version
    particle serial inspect --port <p> — Inspect device over serial
    particle update                    — OTA Device OS update (requires login)
    particle flash --usb <bin>         — DFU flash firmware (.bin)
    particle device-os-update          — Update Device OS to latest
    particle serial monitor --port <p> — Serial monitor (115200 baud)
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
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload, get_firmware_dir,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Particle Photon 2"
DESCRIPTION = "RTL8721DM WiFi/BLE SoC — Particle cloud-connected development board"

VID_PID_NORMAL = [(0x2B04, 0xC305)]   # Photon 2 running application
VID_PID_DFU    = [(0x2B04, 0xD305)]   # Photon 2 in DFU / listening mode
VID_PID_ALL    = VID_PID_NORMAL + VID_PID_DFU

BAUD_RATE = 115200

PARTICLE_CLOUD_URL  = "https://console.particle.io"
DEVICE_OS_API_URL   = "https://api.github.com/repos/particle-iot/device-os/releases/latest"

CONNECT_INSTRUCTIONS = (
    "Particle Photon 2 not detected.\n\n"
    "  1. Connect Photon 2 via USB cable\n"
    "  2. VID:PID 2B04:C305 (running application) or 2B04:D305 (DFU/listening)\n"
    "  3. Ensure Particle CLI is installed:\n"
    "       npm install -g particle-cli\n"
    "  4. The device should show BREATHING CYAN if cloud-connected.\n"
    "     If BLINKING BLUE, the device is in listening mode (also detected).\n\n"
    "  Driver notes:\n"
    "    Linux: built-in CDC ACM (automatic) — device appears as /dev/ttyACM*\n"
    "    macOS: built-in (no driver needed) — device appears as /dev/cu.usbmodem*\n\n"
    "  Permission issues on Linux:\n"
    "    Check: ls -la /dev/ttyACM*\n"
    "    Fix:   sudo usermod -aG dialout $USER  (then log out/in)\n"
    "    Debug: dmesg | tail -20\n\n"
    "  If the device is not appearing at all:\n"
    "    - Try a different USB cable (data cable, not charge-only)\n"
    "    - Try a different USB port (avoid USB hubs if possible)\n"
    "    - Hold the MODE button for 3 seconds to enter listening mode\n"
    "    - Check: lsusb | grep 2B04"
)

# udev rules for Particle Photon 2
UDEV_RULES_CONTENT = (
    '# Particle Photon 2 udev rules\n'
    '# Photon 2 running application (VID:PID 2B04:C305)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="2b04", ATTRS{idProduct}=="c305", '
    'MODE="0666", GROUP="dialout"\n'
    '# Photon 2 DFU / listening mode (VID:PID 2B04:D305)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="2b04", ATTRS{idProduct}=="d305", '
    'MODE="0666", GROUP="dialout"\n'
    '# Particle DFU USB device rule\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="2b04", MODE="0666", GROUP="plugdev"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-particle-photon2.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_photon2() -> bool:
    info("Scanning USB for Particle Photon 2 (VID:PID 2B04:C305 or 2B04:D305)…")
    return find_serial_port_by_vidpid(VID_PID_ALL) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for the Photon 2 on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping on this platform.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Particle Photon 2…")
    info(f"  Rules file: {UDEV_RULES_PATH}")
    info("  This grants /dev/ttyACM* access without root for dialout group members.")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the Photon 2 to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual fix: sudo nano {UDEV_RULES_PATH}")
        info("Paste the following content:")
        for line in UDEV_RULES_CONTENT.splitlines():
            info(f"  {line}")
        info("Then run: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Particle CLI check ────────────────────────────────────────────────────────

def _check_particle_cli():
    """Check that the Particle CLI is installed and offer to install it."""
    info("Checking Particle CLI ('particle' command)…")
    info("  Particle CLI is required for device identification, OTA updates, and DFU flashing.")

    cli_path = run_output("which particle 2>/dev/null || true")
    if cli_path and cli_path.strip():
        ok(f"Particle CLI found: {cli_path.strip()}")
        # Show version
        ver = run_output("particle version 2>/dev/null || particle --version 2>/dev/null || true")
        if ver and ver.strip():
            info(f"  Particle CLI version: {ver.strip()}")
        return True

    warn("Particle CLI ('particle') not found in PATH.")
    info("  The Particle CLI is a Node.js tool installed via npm.")
    info("  It is required for: device identification, OTA updates, DFU flashing, serial monitor.")
    info("  Install instructions:")
    flavor = get_os_flavor()
    if flavor == "darwin":
        info("    macOS: brew install node && npm install -g particle-cli")
        info("    Or: nvm install node && npm install -g particle-cli")
    else:
        info("    Linux (Kali/Debian/Ubuntu): sudo apt install nodejs npm")
        info("    Then: sudo npm install -g particle-cli")
        info("    Or use nvm: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash")
        info("                nvm install node && npm install -g particle-cli")
    info("  After install, verify with: particle --version")

    if not confirm("Attempt to install Particle CLI now?", default=True):
        warn("Particle CLI not installed. Some operations will not work.")
        return False

    flavor = get_os_flavor()
    if flavor == "darwin":
        info("Checking for Node.js via brew…")
        ensure_brew_packages(["node"])
        info("Installing Particle CLI via npm…")
        r = run("npm install -g particle-cli")
        if r.returncode == 0:
            ok("Particle CLI installed via npm.")
            return True
        else:
            err("npm install failed. Try manually: npm install -g particle-cli")
            return False
    else:
        info("Installing Node.js and npm via apt…")
        ensure_apt_packages(["nodejs", "npm"])
        info("Installing Particle CLI globally via npm…")
        r = run("npm install -g particle-cli")
        if r.returncode == 0:
            ok("Particle CLI installed via npm.")
            return True
        else:
            err("npm install failed.")
            info("Troubleshooting:")
            info("  If npm errors about permissions, try: sudo npm install -g particle-cli")
            info("  Or install nvm and use it to manage Node.js:")
            info("    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash")
            info("    source ~/.bashrc && nvm install node && npm install -g particle-cli")
            return False


# ── Serial helpers ────────────────────────────────────────────────────────────

def _open_serial(port: str):
    import serial
    info(f"Opening serial port {port} at {BAUD_RATE} baud…")
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


def _send_at(ser, cmd: str, wait: float = 1.0) -> str:
    """Send an AT command and return the response."""
    info(f"Sending command: {cmd!r}")
    ser.reset_input_buffer()
    ser.write((cmd + "\r\n").encode())
    time.sleep(wait)
    raw = b""
    deadline = time.time() + wait + 1.0
    while time.time() < deadline:
        if ser.in_waiting:
            raw += ser.read(ser.in_waiting)
        time.sleep(0.05)
    return raw.decode("utf-8", errors="replace").strip()


def _check_dialout(port: str):
    """Check if the current user is in the dialout group."""
    if get_os_flavor() == "darwin":
        return  # macOS does not use dialout group
    import grp
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    try:
        dialout_gid = grp.getgrnam("dialout").gr_gid
        user_gids = os.getgroups()
        if dialout_gid in user_gids:
            ok(f"User '{username}' is in the dialout group.")
            return
    except KeyError:
        return  # dialout group doesn't exist
    warn(f"User '{username}' is NOT in the 'dialout' group.")
    info("This can cause 'Permission denied' errors on /dev/ttyACM* devices.")
    info(f"  Check groups:  id {username}")
    info(f"  Check device:  ls -la {port}")
    if confirm(f"Add '{username}' to the 'dialout' group now?", default=True):
        info(f"Running: sudo usermod -aG dialout {username}")
        rc = sudo_run(f"usermod -aG dialout {username}")
        if rc.returncode == 0:
            ok(f"Added '{username}' to dialout. You must log out and back in (or run: newgrp dialout).")
        else:
            err("Failed to add user to dialout group.")
            info("Try manually: sudo usermod -aG dialout $USER")


# ── GitHub version check ──────────────────────────────────────────────────────

def _get_latest_device_os_version() -> str:
    """Fetch the latest Device OS version from GitHub API."""
    info("Fetching latest Device OS version from GitHub API…")
    info(f"  API URL: {DEVICE_OS_API_URL}")
    try:
        import requests
        resp = requests.get(DEVICE_OS_API_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name", "unknown")
        name = data.get("name", "unknown")
        info(f"  Latest Device OS tag: {tag}")
        info(f"  Release name: {name}")
        return tag
    except Exception as e:
        warn(f"Could not fetch latest Device OS version: {e}")
        info("  Check: curl " + DEVICE_OS_API_URL)
        info("  Network may be unavailable, or GitHub rate limit reached.")
        return "unknown"


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Gathering Particle Photon 2 device information.")
    info("This uses the Particle CLI 'particle identify' command.")
    info("  'particle identify' queries the device over serial and returns:")
    info("    - Device ID (24-character hex string unique to each device)")
    info("    - Device OS version currently installed")
    info("    - Device type / platform (should be Photon 2 / P2)")
    info(f"  Serial port: {port}")
    info("  The device must be in normal running mode (breathing cyan or solid color).")
    info("  If the device is in DFU mode (blinking magenta), 'particle identify' still works.")

    # Method 1: particle identify
    info("Method 1: Running 'particle identify'…")
    info("  This command communicates with the device over the serial port.")
    try:
        r = run(f"particle identify --port {port}")
        if r.returncode == 0:
            ok("Device info retrieved via 'particle identify'.")
        else:
            warn("'particle identify' returned non-zero exit code.")
            info("  This may happen if the device is in an unexpected state.")
            info("  Trying fallback: AT+INFO command over raw serial…")
            _op_device_info_serial_fallback(port)
    except FileNotFoundError:
        err("'particle' command not found. Please install Particle CLI.")
        info("  Install: npm install -g particle-cli")
        info("  Then retry this operation.")
        info("  Fallback: querying device over raw serial with AT+INFO…")
        _op_device_info_serial_fallback(port)
    except Exception as e:
        err(f"Unexpected error running 'particle identify': {e}")
        info("  Falling back to raw serial AT command…")
        _op_device_info_serial_fallback(port)

    # Show USB port info from pyserial
    info("USB port details (from pyserial):")
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
                if pid == "0xC305":
                    info("  Mode        : Normal application mode")
                elif pid == "0xD305":
                    info("  Mode        : DFU / Listening mode")
    except Exception as e:
        warn(f"Could not enumerate USB ports: {e}")

    ok("Device info complete.")


def _op_device_info_serial_fallback(port: str):
    """Fallback: attempt to get device info over raw serial."""
    info("Attempting raw serial AT+INFO query…")
    info("  This is a fallback for when Particle CLI is unavailable.")
    info("  Sending AT+INFO command at 115200 baud…")
    try:
        with _open_serial(port) as ser:
            response = _send_at(ser, "AT+INFO", wait=1.5)
            if response:
                info("  AT+INFO response:")
                for line in response.splitlines():
                    info(f"    {line}")
                ok("Serial AT+INFO fallback succeeded.")
            else:
                warn("  No response to AT+INFO. The device may not respond to raw AT commands.")
                info("  The Photon 2 primarily uses Particle CLI for device info.")
                info("  Ensure Particle CLI is installed: npm install -g particle-cli")
    except PermissionError:
        err(f"Permission denied on {port}. Check dialout group membership.")
        _check_dialout(port)
    except Exception as e:
        err(f"Serial fallback failed: {e}")
        info(f"  Debug: check dmesg | tail -20 and ls -la {port}")


def op_check_device_os_version(port: str):
    heading("Check Device OS Version")
    info("Checking the installed Device OS version on the Photon 2.")
    info("Device OS is Particle's real-time operating system running on the device.")
    info("It provides WiFi, BLE, cloud connectivity, and hardware abstraction.")
    info("Keeping Device OS up to date ensures compatibility and security fixes.")
    info("")
    info("Method: 'particle serial inspect' reads version info over serial.")
    info(f"  Port: {port}")

    # Method 1: particle serial inspect
    info("Running 'particle serial inspect'…")
    try:
        r = run(f"particle serial inspect --port {port}")
        if r.returncode == 0:
            ok("Device OS version check complete.")
        else:
            warn("'particle serial inspect' failed.")
            info("  Trying 'particle identify' as fallback…")
            r2 = run(f"particle identify --port {port}")
            if r2.returncode != 0:
                err("Both inspection methods failed.")
                info("  Check: is the device in normal mode (not mid-update)?")
                info("  Check: is the port correct? (ls /dev/ttyACM* or ls /dev/cu.usbmodem*)")
    except FileNotFoundError:
        err("Particle CLI not found. Cannot check Device OS version without it.")
        info("  Install: npm install -g particle-cli")
        return
    except Exception as e:
        err(f"Device OS version check error: {e}")

    # Also check latest available version
    info("")
    info("Checking latest available Device OS version from Particle/GitHub…")
    latest = _get_latest_device_os_version()
    if latest != "unknown":
        ok(f"Latest Device OS version available: {latest}")
        info(f"  Compare with the installed version shown above.")
        info(f"  If outdated, use 'Update Device OS (OTA)' to upgrade.")
    info("")
    info("Device OS update channel: https://github.com/particle-iot/device-os/releases")
    info("Particle management console: " + PARTICLE_CLOUD_URL)


def op_update_device_os_ota(port: str):
    heading("Update Device OS (OTA)")
    info("Over-the-air (OTA) Device OS update via Particle cloud.")
    info("This is the recommended update method for the Photon 2.")
    info("")
    info("REQUIREMENTS:")
    info("  1. Device must be CONNECTED TO PARTICLE CLOUD (breathing cyan LED).")
    info("  2. You must be logged in to Particle CLI ('particle login').")
    info("  3. Active internet connection required.")
    info("  4. The device must be claimed to your Particle account.")
    info("")
    info("What 'particle device-os-update' does:")
    info("  - Checks the current Device OS version on the device")
    info("  - Downloads the appropriate Device OS binaries from Particle cloud")
    info("  - Flashes them to the device over the air (OTA)")
    info("  - The device will reboot multiple times during this process (normal)")
    info("  - Total time: typically 2-5 minutes")
    warn("")
    warn("Do NOT unplug or power off the device during the update process!")
    warn("Interrupting an OTA update can leave the device in an unrecoverable state.")
    warn("If that happens, use 'Flash Firmware (DFU)' to recover.")
    info("")

    # Check login status
    info("Checking Particle CLI login status…")
    login_check = run_output("particle whoami 2>/dev/null || true")
    if login_check and "Not logged in" not in login_check and login_check.strip():
        ok(f"Logged in as: {login_check.strip()}")
    else:
        warn("You do not appear to be logged in to Particle CLI.")
        info("  Run 'Particle Login' from the main menu first.")
        if not confirm("Continue anyway (will fail if not logged in)?", default=False):
            info("Update cancelled. Please log in first.")
            return

    if not confirm("Start OTA Device OS update now?", default=True):
        info("Update cancelled.")
        return

    info("Running 'particle device-os-update'…")
    info("  Watch for LED patterns on the device:")
    info("    Blinking magenta = downloading/flashing")
    info("    Blinking cyan = rebooting after flash")
    info("    Breathing cyan = update complete")
    try:
        r = run("particle device-os-update")
        if r.returncode == 0:
            ok("Device OS OTA update completed successfully.")
            info("  The device should now be breathing cyan (connected to cloud).")
        else:
            err("Device OS update failed.")
            info("Troubleshooting:")
            info("  - Ensure the device is connected to Particle cloud (breathing cyan)")
            info("  - Ensure you are logged in: particle whoami")
            info("  - Ensure the device is claimed: particle list")
            info("  - Try the DFU method instead: select 'Flash Firmware (DFU)' from menu")
            info("  - Check Particle status page: https://status.particle.io")
    except FileNotFoundError:
        err("Particle CLI not found. Install with: npm install -g particle-cli")
    except Exception as e:
        err(f"OTA update error: {e}")


def op_flash_firmware_dfu(port: str):
    heading("Flash Firmware (DFU)")
    info("Flashing firmware to the Photon 2 via USB DFU (Device Firmware Upgrade).")
    info("DFU flashing does NOT require Particle cloud connectivity or internet access.")
    info("This is the preferred recovery method if OTA updates are not possible.")
    info("")
    info("DFU mode LED indicator: BLINKING MAGENTA")
    info("  To enter DFU mode manually:")
    info("    1. While powered on, hold the MODE button")
    info("    2. After ~3 seconds the LED turns SOLID MAGENTA, then BLINKING MAGENTA")
    info("    3. Release the MODE button — device is now in DFU mode")
    info("    4. USB VID:PID changes from 2B04:C305 to 2B04:D305")
    info("")
    info("Firmware file: must be a .bin file compiled for the Photon 2 / P2 platform.")
    info("  Download firmware: https://github.com/particle-iot/device-os/releases")
    info("  Or compile via Particle Workbench / particle compile")
    info("")

    # Check current mode
    normal_port = find_serial_port_by_vidpid(VID_PID_NORMAL)
    dfu_port    = find_serial_port_by_vidpid(VID_PID_DFU)

    if dfu_port:
        info(f"Device is already in DFU mode on {dfu_port}.")
        flash_port = dfu_port
    elif normal_port:
        info(f"Device is in normal mode on {normal_port}.")
        info("Will attempt to enter DFU mode automatically via serial command.")
        flash_port = normal_port
    else:
        warn("No Photon 2 detected. Please connect the device.")
        return

    firmware_path = prompt("Path to .bin firmware file")
    if not firmware_path:
        warn("No firmware file provided. Aborting.")
        return
    fw = Path(firmware_path)
    if not fw.exists():
        err(f"File not found: {fw}")
        return
    if fw.suffix.lower() != ".bin":
        warn(f"File does not have a .bin extension: {fw.name}")
        info("  Photon 2 DFU expects .bin files. Make sure this is correct.")
        if not confirm("Continue with non-.bin file?", default=False):
            return

    if not confirm(f"Flash {fw.name} to Photon 2 via DFU?", default=True):
        info("Flash cancelled.")
        return

    info(f"Flashing {fw.name} using 'particle flash --usb'…")
    info("  The Particle CLI will handle DFU mode entry automatically.")
    info("  Watch the device LED: blinking magenta = flashing in progress.")
    try:
        r = run(f"particle flash --usb {fw} --port {flash_port}")
        if r.returncode == 0:
            ok("DFU firmware flash completed successfully.")
            info("  The device will now reboot and run the new firmware.")
            info("  After reboot, LED should return to normal operation (breathing cyan if connected).")
        else:
            err("DFU flash failed.")
            info("Troubleshooting:")
            info("  - Ensure the device is in DFU mode (blinking magenta LED)")
            info("    To force: hold MODE button ~3 seconds until LED blinks magenta")
            info("  - Check USB connection: dmesg | tail -20")
            info("  - Check udev rules: ls -la /dev/ttyACM*")
            info("  - Try: particle flash --usb " + str(fw) + " (without --port)")
            info("  - On Linux, ensure dfu-util is installed: apt install dfu-util")
    except FileNotFoundError:
        err("Particle CLI not found. Install with: npm install -g particle-cli")
    except Exception as e:
        err(f"DFU flash error: {e}")
        info(f"  Debug: check dmesg | tail -20 and ls -la {flash_port}")


def op_serial_monitor(port: str):
    heading("Serial Monitor")
    info("Opening a serial monitor to view Particle Photon 2 serial output.")
    info("The Photon 2 exposes a Serial.print() / Serial1 UART over USB CDC at 115200 baud.")
    info("")
    info("Serial monitor options:")
    info("  1. Particle CLI: particle serial monitor --port <port>")
    info("     - Ctrl+C to exit")
    info("  2. screen: screen <port> 115200")
    info("     - Ctrl+A then K to kill session")
    info("  3. minicom: minicom -D <port> -b 115200")
    info("     - Ctrl+A then X to exit")
    info("  4. picocom: picocom -b 115200 <port>")
    info("     - Ctrl+A then Ctrl+Q to exit")
    info("")
    info(f"Current port: {port}")
    info("Note: Some serial monitor tools may conflict with Particle CLI when the device")
    info("  is also connected to the cloud. Close other terminal sessions first.")
    info("")

    method = numbered_menu("Choose serial monitor method", [
        "Particle CLI (particle serial monitor)",
        "screen",
        "minicom",
        "Print raw bytes (Python fallback)",
        "Cancel",
    ])

    if method == 0:
        info(f"Running: particle serial monitor --port {port}")
        info("  Press Ctrl+C to stop.")
        try:
            run(f"particle serial monitor --port {port}")
        except KeyboardInterrupt:
            info("Serial monitor stopped by user.")
        except FileNotFoundError:
            err("Particle CLI not found. Install: npm install -g particle-cli")
        except Exception as e:
            err(f"Serial monitor error: {e}")
    elif method == 1:
        info(f"Running: screen {port} {BAUD_RATE}")
        info("  Exit with: Ctrl+A then K  (or Ctrl+A then \\)")
        try:
            run(f"screen {port} {BAUD_RATE}")
        except Exception as e:
            err(f"screen failed: {e}")
            info("Install screen: apt install screen  or  brew install screen")
    elif method == 2:
        info(f"Running: minicom -D {port} -b {BAUD_RATE}")
        info("  Exit with: Ctrl+A then X")
        try:
            run(f"minicom -D {port} -b {BAUD_RATE}")
        except Exception as e:
            err(f"minicom failed: {e}")
            info("Install minicom: apt install minicom  or  brew install minicom")
    elif method == 3:
        info(f"Opening raw serial on {port} at {BAUD_RATE} baud…")
        info("  Press Ctrl+C to stop.")
        try:
            with _open_serial(port) as ser:
                ok("Serial port open. Reading data (Ctrl+C to stop):")
                while True:
                    if ser.in_waiting:
                        data = ser.read(ser.in_waiting)
                        print(data.decode("utf-8", errors="replace"), end="", flush=True)
                    time.sleep(0.05)
        except KeyboardInterrupt:
            info("Serial monitor stopped.")
        except PermissionError:
            err(f"Permission denied on {port}.")
            _check_dialout(port)
        except Exception as e:
            err(f"Serial read error: {e}")
    else:
        info("Serial monitor cancelled.")


def op_particle_login():
    heading("Particle Login")
    info("Authenticating with the Particle cloud using the Particle CLI.")
    info("")
    info("Particle account is required for:")
    info("  - OTA firmware updates")
    info("  - Device OS updates via cloud")
    info("  - Accessing the Particle console: " + PARTICLE_CLOUD_URL)
    info("  - Claiming and managing devices")
    info("  - Particle Functions, Variables, and Events")
    info("")
    info("If you do not have a Particle account, create one at:")
    info("  https://login.particle.io/signup")
    info("")

    # Check if already logged in
    info("Checking current login status…")
    whoami = run_output("particle whoami 2>/dev/null || true")
    if whoami and "Not logged in" not in whoami and whoami.strip():
        ok(f"Already logged in as: {whoami.strip()}")
        if not confirm("Log in again with a different account?", default=False):
            info("Login skipped — already authenticated.")
            return

    info("Running 'particle login'…")
    info("  You will be prompted for your Particle account email and password.")
    info("  Two-factor authentication (2FA) is supported — check your authenticator app.")
    info("  After successful login, your credentials are stored in ~/.particle/")
    info("")
    try:
        r = run("particle login")
        if r.returncode == 0:
            ok("Successfully logged in to Particle cloud.")
            # Verify
            whoami_after = run_output("particle whoami 2>/dev/null || true")
            if whoami_after and whoami_after.strip():
                ok(f"Logged in as: {whoami_after.strip()}")
        else:
            err("Particle login failed.")
            info("Troubleshooting:")
            info("  - Verify your email and password at https://login.particle.io")
            info("  - Check internet connectivity: curl -s https://api.particle.io/v1/build_targets | head -c 100")
            info("  - If using 2FA, ensure your authenticator app is synced")
            info("  - Try browser login at: " + PARTICLE_CLOUD_URL)
    except FileNotFoundError:
        err("Particle CLI not found. Install with: npm install -g particle-cli")
    except Exception as e:
        err(f"Login error: {e}")


# ── Firmware Version Check ────────────────────────────────────────────────────

def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Checking Particle Photon 2 Device OS version...")
    info("  Using 'particle identify' to query the device...")
    current = None

    try:
        import subprocess as _sp, re
        r = _sp.run(["particle", "identify", "--port", port],
                    capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            # Output: "Your device firmware version is: 6.2.0"
            m = re.search(r'firmware version.*?(\d+\.\d+\.\d+)', r.stdout, re.IGNORECASE)
            if m:
                current = m.group(1)
                ok(f"Device OS version: {current}")
            else:
                info(f"  particle identify output: {r.stdout.strip()[:200]}")
    except FileNotFoundError:
        warn("particle CLI not found. Install: npm install -g particle-cli")
    except Exception as e:
        warn(f"Could not query firmware version: {e}")

    if not current:
        info("Could not auto-detect Device OS version.")
        info("  Check manually: particle identify --port {port}")
        info("  Or: particle serial inspect")

    info("Checking latest Particle Device OS on GitHub...")
    latest, url = check_latest_github_release("particle-iot", "device-os")
    if latest:
        if current:
            announce_firmware_update("Photon 2 Device OS", current, latest.lstrip("v"), url)
        else:
            info(f"  Latest Device OS: {latest}")
            info(f"  Update via: particle update  (over-the-air if cloud connected)")
            info(f"  Or via DFU: particle flash --usb system-part1.bin")
    else:
        warn("Could not reach GitHub for version check.")


# ── Firmware payload (main-page "FIRMWARE - ") ────────────────────────────────

def _fw_user_dir() -> Path:
    d = get_firmware_dir("photon_2") / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _run_dfu_payload(fw, port):
    state = {}

    def prep():
        if not _check_particle_cli():
            err("  Particle CLI not available — DFU flashing requires it.")
            return False
        d = _fw_user_dir()
        bins = sorted(d.glob("*.bin"))
        f = bins[0] if bins else None
        if not f:
            err("  No firmware .bin found. Compile a Photon 2 (platform 'p2') image via")
            err("  Particle Workbench / 'particle compile', or download a Device OS user")
            err(f"  application .bin, and drop it into: {d}")
            return False
        state["fw"] = f
        # Prefer the DFU-mode port if the device is already in DFU.
        state["port"] = find_serial_port_by_vidpid(VID_PID_DFU) or port
        ok(f"  Firmware ready: {f}")
        return True

    def flash():
        fw_path = state["fw"]
        flash_port = state["port"]
        info(f"Flashing {Path(fw_path).name} using 'particle flash --usb'…")
        try:
            r = run(f"particle flash --usb {fw_path} --port {flash_port}")
            if r.returncode == 0:
                ok("DFU firmware flash completed successfully.")
            else:
                err("DFU flash failed. Ensure the device is in DFU mode (blinking magenta):")
                err("  hold MODE ~3s until the LED blinks magenta, then re-run.")
        except FileNotFoundError:
            err("Particle CLI not found. Install with: npm install -g particle-cli")

    run_firmware_payload(
        fw.get("label", "Flash firmware (DFU)"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            "Firmware : operator-supplied Photon 2 (.bin) via Particle DFU",
            f"Port     : {port}",
        ],
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial is available
    info("Ensuring pyserial is available for USB CDC serial communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  Preferred: apt-get install python3-serial")
        ensure_apt_packages(["python3-serial"])
    else:
        info("  Using pip to install pyserial…")
        ensure_pip_packages([("serial", "pyserial")])

    # Ensure requests is available for GitHub API calls
    info("Ensuring requests library is available for version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Checking udev rules for Particle Photon 2 USB CDC access…")
    _check_udev_rules()

    info("Checking Particle CLI installation…")
    _check_particle_cli()

    info("Detecting Particle Photon 2 via USB VID:PID 2B04:C305 or 2B04:D305…")
    info("  Normal mode (running): VID:PID 2B04:C305 → /dev/ttyACM* or /dev/cu.usbmodem*")
    info("  DFU/listening mode:    VID:PID 2B04:D305")
    info("  LED breathing cyan = cloud connected (normal mode)")
    info("  LED blinking blue  = listening / DFU mode")

    found = web_detect_loop(detect_photon2, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Particle Photon 2 not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PID_ALL)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Particle Photon 2 connected on {port}")

    # Identify current mode
    if find_serial_port_by_vidpid(VID_PID_DFU):
        warn("Device is in DFU / listening mode (VID:PID 2B04:D305).")
        warn("  LED should be BLINKING BLUE. OTA operations require normal mode.")
        info("  To exit DFU/listening mode: press the RESET button once.")
    else:
        ok("Device is in normal application mode (VID:PID 2B04:C305).")
        info("  LED breathing cyan = cloud connected. Breathing green = WiFi only.")

    _check_dialout(port)

    check_firmware_version(port)

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _run_dfu_payload(fw, port)
        return

    MENU_OPTIONS = [
        "Device Info (particle identify)",
        "Check Device OS Version",
        "Update Device OS (OTA)",
        "FIRMWARE - Flash Firmware (DFU)",
        "Serial Monitor",
        "Particle Login",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Particle Photon 2 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_check_device_os_version(port)
        elif choice == 2:
            op_update_device_os_ota(port)
        elif choice == 3:
            op_flash_firmware_dfu(port)
        elif choice == 4:
            op_serial_monitor(port)
        elif choice == 5:
            op_particle_login()
        elif choice == 6:
            info("Goodbye.")
            break

        # Re-check port after each operation (device may reboot / change mode)
        new_port = find_serial_port_by_vidpid(VID_PID_ALL)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")
        elif not new_port:
            warn("Photon 2 no longer detected on USB. It may be rebooting.")
            info("  Waiting up to 15 seconds for re-enumeration…")
            deadline = time.time() + 15
            while time.time() < deadline:
                time.sleep(2)
                new_port = find_serial_port_by_vidpid(VID_PID_ALL)
                if new_port:
                    port = new_port
                    ok(f"Device re-enumerated on {port}")
                    break
            else:
                warn("Device did not re-enumerate. Check USB connection.")


if __name__ == "__main__":
    main()
