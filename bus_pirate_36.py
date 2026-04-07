#!/usr/bin/env python3
"""
Bus Pirate v3.6 Tool Manager
Handles device info, voltage reads, mode setup, power control, self-test,
bootloader entry, and firmware updates via pirate-loader.

Usage:
    python3 bus_pirate_36.py

Bus Pirate 3.6 REPL command reference:
    i       — Device info (firmware version, board type, PIC chip info)
    v       — Measure voltages (3.3V rail, 5V rail, Vpu pull-up voltage)
    m       — Mode select menu (HiZ, 1-Wire, UART, I2C, SPI, 2-Wire, 3-Wire, LCD, DIO, JTAG)
    W / w   — PSU ON / PSU OFF (external power supply on VOUT pin)
    #       — Reset the device (soft reboot back to REPL)
    $       — Jump to bootloader (PIC24 bootloader for firmware updates)
    ~       — Run self-test (tests all pins, voltage references, pull-ups)
    ?       — Help menu (context-sensitive)

IMPORTANT: Bus Pirate 3.x uses 5V logic levels on I/O pins!
    - The Bus Pirate 3.6 I/O pins are 5V tolerant and output 5V signals.
    - If targeting a 3.3V device, you MUST use the on-board voltage translator or level shifter.
    - Connecting a 5V Bus Pirate pin directly to a 3.3V device INPUT can damage the target.
    - Use Vpu (pull-up voltage) to set open-drain bus voltage for I2C/SPI pull-ups.
    - The internal 3.3V and 5V regulators power the bus pull-ups and Vout.
    - Always check: What voltage does your target expect?

USB CDC device:
    - VID:PID 04D8:FB00 — Bus Pirate 3.x running application (Microchip PIC CDC)
    - VID:PID 04D8:FB01 — Bus Pirate 3.x bootloader mode (enter with '$' command)
    - Some 3.6 clones use FTDI FT232RL: VID:PID 0403:6001

Linux serial permissions:
    Device appears as /dev/ttyUSB* (FTDI clones) or /dev/ttyACM* (Microchip CDC).
    Check: ls -la /dev/ttyUSB*  and  ls -la /dev/ttyACM*
    Add user to dialout: sudo usermod -aG dialout $USER  (then re-login)
    Debug: dmesg | tail -20

Firmware update with pirate-loader:
    Source: https://github.com/BusPirate/Bus_Pirate/tree/master/package/BPv3-firmware
    Build:  git clone https://github.com/BusPirate/Bus_Pirate && cd Bus_Pirate/scripts && make
    Usage:  pirate-loader -p /dev/ttyUSB0 --hex firmware.hex

Comparison with Bus Pirate 5:
    BP 3.6:  PIC24FJ256GB106 MCU, 5V I/O, serial REPL, pirate-loader for updates
    BP 5:    RP2040 MCU, 3.3V I/O, USB CDC REPL, UF2 bootloader, scripting support
    BP 3.6 does NOT support BP5-style scripting or the BusPirate-FS filesystem.
    BP 3.6 firmware updates require pirate-loader or the PIC24 bootloader tool.
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
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Bus Pirate v3.6"
DESCRIPTION = "PIC24FJ256GB106 universal bus hacking tool — UART, SPI, I2C, JTAG, and more"

VID_PID_CDC  = [(0x04D8, 0xFB00)]   # Microchip USB CDC — Bus Pirate 3.x application
VID_PID_FT232 = [(0x0403, 0x6001)]  # FTDI FT232RL — clone Bus Pirates
VID_PID_BOOT  = [(0x04D8, 0xFB01)]  # Bus Pirate 3.x bootloader mode
VID_PID_ALL   = VID_PID_CDC + VID_PID_FT232 + VID_PID_BOOT

BAUD_RATE = 115200

FIRMWARE_API_URL = "https://api.github.com/repos/BusPirate/Bus_Pirate/releases/latest"
PIRATE_LOADER_REPO = "https://github.com/BusPirate/Bus_Pirate"

CONNECT_INSTRUCTIONS = (
    "Bus Pirate v3.6 not detected.\n\n"
    "  1. Connect Bus Pirate 3.6 via mini-USB cable\n"
    "  2. Expected VID:PID: 04D8:FB00 (Microchip CDC)\n"
    "     FTDI clone variant: 0403:6001 (FT232RL)\n"
    "     Bootloader mode:    04D8:FB01\n\n"
    "  Device paths:\n"
    "    Linux (Microchip CDC): /dev/ttyACM*\n"
    "    Linux (FTDI clone):    /dev/ttyUSB*\n"
    "    macOS (Microchip CDC): /dev/cu.usbmodemFD*\n"
    "    macOS (FTDI clone):    /dev/cu.usbserial-*\n\n"
    "  Kernel modules (Linux):\n"
    "    Microchip CDC: cdc_acm (built-in, auto-loaded)\n"
    "    FTDI FT232RL:  ftdi_sio (built-in, auto-loaded)\n"
    "    If not loading: sudo modprobe cdc_acm   or   sudo modprobe ftdi_sio\n\n"
    "  Permission fix:\n"
    "    sudo usermod -aG dialout $USER  (then log out/in)\n"
    "    Check: ls -la /dev/ttyACM*  or  ls -la /dev/ttyUSB*\n\n"
    "  Troubleshooting:\n"
    "    - If device appears then disappears: power issue — try powered USB hub\n"
    "    - If FTDI clone not detected: check 'dmesg | tail -20' for ftdi_sio\n"
    "    - Verify USB cable (must be data cable, not charge-only)\n"
    "    - Check: lsusb | grep -E '04D8|0403'"
)

UDEV_RULES_CONTENT = (
    '# Bus Pirate v3.6 udev rules\n'
    '# Microchip USB CDC — Bus Pirate 3.x application (VID:PID 04D8:FB00)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="04d8", ATTRS{idProduct}=="fb00", '
    'MODE="0666", GROUP="dialout"\n'
    '# Microchip USB CDC — Bus Pirate 3.x bootloader (VID:PID 04D8:FB01)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="04d8", ATTRS{idProduct}=="fb01", '
    'MODE="0666", GROUP="dialout"\n'
    '# FTDI FT232RL — Bus Pirate clone variant (VID:PID 0403:6001)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6001", '
    'MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-bus-pirate-36.rules"

# Mode descriptions shown during mode setup
MODE_TABLE = {
    "0": "HiZ       — All pins high-impedance (safe default)",
    "1": "1-Wire    — Dallas 1-Wire protocol (DS18B20 temp sensors, iButton)",
    "2": "UART      — Async serial TTL (connect to microcontroller UART, GPS, etc.)",
    "3": "I2C       — 2-wire serial (EEPROM, sensors, accelerometers, real-time clocks)",
    "4": "SPI       — 4-wire serial (flash chips, SD cards, ADC/DAC chips)",
    "5": "2-Wire    — Bare 2-wire, clock + data, no protocol overhead",
    "6": "3-Wire    — Bare 3-wire (CS/CLK/DATA, generic SPI-like)",
    "7": "LCD       — Hitachi HD44780 LCD controller (4-bit mode)",
    "8": "DIO       — Raw digital I/O (bit-bang any pattern)",
    "9": "JTAG      — JTAG (via OpenOCD or bit-bang; limited but functional)",
}


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_bp36() -> bool:
    info("Scanning USB for Bus Pirate v3.6 (VID:PIDs 04D8:FB00, 0403:6001, 04D8:FB01)…")
    return find_serial_port_by_vidpid(VID_PID_ALL) is not None


def _is_bootloader_mode() -> bool:
    return find_serial_port_by_vidpid(VID_PID_BOOT) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Bus Pirate v3.6…")
    info(f"  Writing to: {UDEV_RULES_PATH}")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written and reloaded: {UDEV_RULES_PATH}")
        info("Unplug and replug the Bus Pirate to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Serial helpers ────────────────────────────────────────────────────────────

def _open_serial(port: str):
    import serial
    info(f"Opening serial port {port} at {BAUD_RATE} baud…")
    info("  Bus Pirate 3.6 REPL settings: 115200 8N1, no flow control.")
    ser = serial.Serial(
        port=port,
        baudrate=BAUD_RATE,
        timeout=2,
        bytesize=8,
        parity="N",
        stopbits=1,
        xonxoff=False,
        rtscts=False,
    )
    time.sleep(0.3)
    ser.reset_input_buffer()
    return ser


def _send_command(ser, cmd: str, wait: float = 0.8) -> str:
    """Send a single REPL command and return the response."""
    info(f"Sending REPL command: {cmd!r}")
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
            ok(f"Added. Log out and back in, or run: newgrp dialout")
        else:
            err("Failed to add to dialout group.")


# ── pirate-loader check ───────────────────────────────────────────────────────

def _find_pirate_loader() -> str:
    """Return path to pirate-loader binary, or empty string if not found."""
    info("Searching for pirate-loader binary…")
    # Check system PATH first
    path = run_output("which pirate-loader 2>/dev/null || true")
    if path and path.strip():
        ok(f"pirate-loader found in PATH: {path.strip()}")
        return path.strip()
    # Check common local build locations
    script_dir = Path(__file__).parent
    candidates = [
        script_dir / "pirate-loader",
        script_dir / "Bus_Pirate" / "scripts" / "pirate-loader",
        Path.home() / "pirate-loader",
        Path("/usr/local/bin/pirate-loader"),
    ]
    for candidate in candidates:
        if candidate.exists():
            ok(f"pirate-loader found at: {candidate}")
            return str(candidate)
    warn("pirate-loader not found.")
    return ""


def _install_pirate_loader():
    """Offer to build pirate-loader from source."""
    info("pirate-loader is required for Bus Pirate 3.6 firmware updates.")
    info("  It communicates with the PIC24 bootloader to flash firmware .hex files.")
    info("  Source: " + PIRATE_LOADER_REPO)
    info("")
    info("Build instructions:")
    info("  1. git clone " + PIRATE_LOADER_REPO)
    info("  2. cd Bus_Pirate/scripts")
    info("  3. make")
    info("  4. Copy pirate-loader to /usr/local/bin/ or keep it in the cloned directory")
    info("")

    flavor = get_os_flavor()
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  Linux build deps: gcc, make, git")
        info("  Install: sudo apt-get install -y gcc make git")
    elif flavor == "darwin":
        info("  macOS build deps: Xcode Command Line Tools and git")
        info("  Install: xcode-select --install && brew install git")
    else:
        info("  Windows: use WSL or download a pre-compiled binary from GitHub releases.")

    if not confirm("Clone Bus_Pirate repository and build pirate-loader now?", default=True):
        warn("pirate-loader not installed. Firmware update will not be available.")
        return ""

    script_dir = Path(__file__).parent
    repo_dir = script_dir / "Bus_Pirate"
    if repo_dir.exists():
        info(f"Repository already exists at {repo_dir}. Pulling latest…")
        r = run(f"git -C {repo_dir} pull")
    else:
        info(f"Cloning Bus_Pirate repository to {repo_dir}…")
        r = run(f"git clone {PIRATE_LOADER_REPO} {repo_dir}")
        if r.returncode != 0:
            err("git clone failed. Ensure git is installed and internet is available.")
            info("  Install git: apt-get install git  or  brew install git")
            return ""

    scripts_dir = repo_dir / "scripts"
    if not scripts_dir.exists():
        warn("'scripts' directory not found in cloned repo. Checking for pirate-loader source…")
        # Try root of repo
        scripts_dir = repo_dir
    info(f"Building pirate-loader in {scripts_dir}…")
    ensure_apt_packages(["gcc", "make"])
    r = run(f"make -C {scripts_dir}")
    if r.returncode != 0:
        err("make failed.")
        info("  Check: does the Makefile exist? (ls " + str(scripts_dir) + ")")
        info("  Check: is gcc installed? (gcc --version)")
        return ""

    loader_bin = scripts_dir / "pirate-loader"
    if loader_bin.exists():
        ok(f"pirate-loader built at: {loader_bin}")
        return str(loader_bin)
    else:
        err("Build appeared to succeed but pirate-loader binary not found.")
        info(f"  Check contents of: {scripts_dir}")
        return ""


# ── GitHub version check ──────────────────────────────────────────────────────

def _get_latest_firmware_version() -> str:
    info("Fetching latest Bus Pirate firmware version from GitHub…")
    info(f"  API URL: {FIRMWARE_API_URL}")
    try:
        import requests
        resp = requests.get(FIRMWARE_API_URL, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name", "unknown")
        name = data.get("name", "unknown")
        info(f"  Latest release tag : {tag}")
        info(f"  Release name       : {name}")
        assets = data.get("assets", [])
        hex_assets = [a["name"] for a in assets if a["name"].endswith(".hex")]
        if hex_assets:
            info("  Available .hex firmware files in this release:")
            for a in hex_assets:
                info(f"    {a}")
        return tag
    except Exception as e:
        warn(f"Could not fetch firmware version: {e}")
        info("  Check: curl " + FIRMWARE_API_URL)
        return "unknown"


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info (i)")
    info("Sending the 'i' command to the Bus Pirate 3.6 REPL.")
    info("Expected output format:")
    info("  Bus Pirate v3.6, firmware v6.1-beta1 (r2151)  DEVID:0x0447 REVID:0x3046")
    info("  http://dangerousprototypes.com")
    info("")
    info("Fields in the output:")
    info("  Firmware version — e.g. v6.1-beta1 (r2151) — compare with latest on GitHub")
    info("  DEVID — PIC24FJ microcontroller device ID")
    info("  REVID — Silicon revision ID")
    info("")
    info("Troubleshooting 'no response':")
    info("  - Check baud rate is 115200 (NOT 9600 or any other rate)")
    info("  - The Bus Pirate 3.6 only responds at exactly 115200 8N1")
    info("  - Ensure the device is not in mid-command state")
    info("  - Try pressing ENTER once to get back to the REPL prompt")
    info("  - If still no response: send '#' to reset, then retry 'i'")
    info("  - Verify port is correct: dmesg | tail -20  and  ls /dev/ttyACM*  or  ls /dev/ttyUSB*")
    info(f"  - Current port: {port}")

    try:
        with _open_serial(port) as ser:
            # Send a bare Enter first to clear any pending state
            info("Sending Enter to clear REPL state…")
            ser.write(b"\r\n")
            time.sleep(0.3)
            ser.reset_input_buffer()

            info("Sending 'i' command…")
            output = _send_command(ser, "i", wait=1.0)

        if output:
            info("REPL response:")
            for line in output.splitlines():
                info(f"  {line}")
            ok("Device info retrieved successfully.")
            # Try to parse firmware version
            for line in output.splitlines():
                if "firmware" in line.lower() or "Bus Pirate" in line:
                    info(f"Parsed firmware info: {line.strip()}")
        else:
            warn("No response received from Bus Pirate.")
            info("Troubleshooting checklist:")
            info("  1. Is the baud rate correct? Bus Pirate 3.6 uses exactly 115200")
            info("  2. Is the device in REPL mode? (not paused waiting for input)")
            info("  3. Try: echo -e 'i\\r' > " + port + "  and observe response")
            info("  4. Try a terminal emulator: screen " + port + " 115200")
            info("  5. Check device power: ls -la " + port)
            info("  6. Reset device physically: unplug and replug USB")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Device info failed: {e}")
        info(f"  Check: dmesg | tail -20  and  ls -la {port}")

    # Also check latest firmware version
    info("")
    info("Checking latest available firmware version…")
    latest = _get_latest_firmware_version()
    if latest != "unknown":
        ok(f"Latest Bus Pirate firmware version: {latest}")
        info("  Compare with the firmware version shown in the 'i' output above.")
        info("  Download firmware .hex from: https://github.com/BusPirate/Bus_Pirate/releases")


def op_read_voltages(port: str):
    heading("Read Voltages (v)")
    info("Sending the 'v' command to the Bus Pirate 3.6 REPL.")
    info("Expected output:")
    info("  Vcc measured voltages:")
    info("  5V: X.XX  |  3.3V: X.XX  |  Vpu: X.XX")
    info("")
    info("Voltage rail descriptions:")
    info("  5V    — On-board 5V regulator output (powers I/O logic level, pins, etc.)")
    info("  3.3V  — On-board 3.3V regulator output (low-voltage rail for 3.3V targets)")
    info("  Vpu   — Pull-up voltage (set by jumper or mode; used for I2C/SPI open-drain)")
    info("")
    info("If any voltage reads 0V or significantly lower than expected:")
    info("  - Check USB power supply (USB 2.0 port may not supply enough current)")
    info("  - Try a powered USB hub")
    info("  - Check for short circuits on the Bus Pirate probe wires")
    info("  - The on-board 3.3V regulator can be damaged by ESD or over-voltage")
    info("")

    try:
        with _open_serial(port) as ser:
            ser.write(b"\r\n")
            time.sleep(0.3)
            ser.reset_input_buffer()
            output = _send_command(ser, "v", wait=1.0)
        if output:
            info("Voltage reading:")
            for line in output.splitlines():
                info(f"  {line}")
            ok("Voltage read complete.")
        else:
            warn("No voltage data returned.")
            info("  Ensure the device is at the REPL prompt (press Enter first).")
            info("  Try resetting the device with '#' command, then retry 'v'.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Read voltages failed: {e}")
        info(f"  Debug: ls -la {port}  and  dmesg | tail -20")


def op_mode_setup(port: str):
    heading("Mode Setup (m)")
    info("Sending the 'm' command to enter Bus Pirate mode selection.")
    info("")
    info("IMPORTANT — Bus Pirate 3.6 mode selection is TEXT-MENU based via REPL.")
    info("Type the mode number and press ENTER in your terminal when prompted.")
    info("")
    info("Available modes:")
    for num, desc in MODE_TABLE.items():
        info(f"  {num}: {desc}")
    info("")
    warn("REMEMBER: Bus Pirate 3.6 I/O pins are 5V logic!")
    warn("  If your target is 3.3V, use a level shifter or the 3.3V Vpu setting.")
    warn("  Directly connecting 5V Bus Pirate pins to a 3.3V CMOS input can damage it.")
    info("")
    info("Mode-specific wiring notes:")
    info("  UART:  MOSI=TX, MISO=RX, GND=GND. Set baud in mode menu.")
    info("  I2C:   CLK=SCL, MOSI=SDA, Vpu=pull-up. Set Vpu jumper to target voltage.")
    info("  SPI:   CLK=SCLK, MOSI=MOSI, MISO=MISO, CS=CS. 3.3V or 5V mode selectable.")
    info("  1-Wire: MOSI=DQ. Connect pull-up resistor (4.7kΩ) from DQ to Vcc.")
    info("  JTAG:  TDO=MISO, TDI=MOSI, TCK=CLK, TMS=CS. Not all targets work.")
    info("")
    pause("Press ENTER when ready to send the 'm' command.")
    try:
        with _open_serial(port) as ser:
            ser.write(b"\r\n")
            time.sleep(0.3)
            ser.reset_input_buffer()
            output = _send_command(ser, "m", wait=1.0)
        if output:
            for line in output.splitlines():
                info(f"  {line}")
        info("")
        info("The device is now showing the mode selection menu on the REPL.")
        info("Open a terminal (screen /dev/ttyUSB0 115200) to complete mode selection.")
        ok("Mode command sent.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Mode setup failed: {e}")


def op_power_control(port: str):
    heading("Power Control (W/w)")
    info("Controlling the Bus Pirate 3.6 on-board PSU (power supply output).")
    info("")
    info("  'W' (uppercase) — Enable external PSU (VOUT pin outputs set voltage)")
    info("  'w' (lowercase) — Disable external PSU (VOUT pin goes to high-Z)")
    info("")
    info("The Bus Pirate 3.6 PSU outputs are:")
    info("  +3.3V — from on-board 3.3V regulator (also powers internal 3.3V rail)")
    info("  +5V   — from USB VBUS (limited to what your USB port can supply)")
    info("")
    warn("The Bus Pirate 3.6 PSU is NOT adjustable — it provides only 3.3V or 5V.")
    warn("Do NOT connect the Bus Pirate PSU output to a circuit that already has power.")
    warn("Maximum current: ~150mA from 3.3V, ~500mA from 5V (USB limited).")
    info("")

    choice = numbered_menu("Power Action", [
        "Turn PSU ON  (W) — enable VOUT",
        "Turn PSU OFF (w) — disable VOUT",
        "Cancel",
    ])
    if choice == 2:
        info("Power control cancelled.")
        return

    cmd = "W" if choice == 0 else "w"
    action = "ON" if choice == 0 else "OFF"
    try:
        with _open_serial(port) as ser:
            ser.write(b"\r\n")
            time.sleep(0.3)
            ser.reset_input_buffer()
            output = _send_command(ser, cmd, wait=0.8)
        if output:
            for line in output.splitlines():
                info(f"  {line}")
        ok(f"PSU turned {action}.")
        if choice == 0:
            info("Verify output voltage using 'Read Voltages (v)' option.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Power control failed: {e}")


def op_self_test(port: str):
    heading("Self-Test (~)")
    info("Running the Bus Pirate 3.6 hardware self-test.")
    info("The '~' command tests:")
    info("  - All I/O pins (MOSI, MISO, CLK, CS, AUX, ADC)")
    info("  - Internal voltage references (3.3V, 5V)")
    info("  - Pull-up resistors (Vpu circuit)")
    info("  - I/O direction control")
    info("")
    warn("IMPORTANT: Disconnect all external wires before running self-test!")
    warn("  External connections will interfere with the self-test results.")
    warn("  The test will report failures if any pin is externally held high or low.")
    info("")
    info("Interpreting self-test results:")
    info("  PASS — the tested component is working correctly")
    info("  FAIL — the component may be damaged or a wire is connected")
    info("  If voltage readings are wrong, check the USB power supply quality")
    info("")

    if not confirm("Run self-test now? (Ensure all external wires are disconnected.)", default=True):
        info("Self-test cancelled.")
        return

    info("Sending '~' command…")
    info("This may take a few seconds while the device tests all pins.")
    try:
        with _open_serial(port) as ser:
            ser.write(b"\r\n")
            time.sleep(0.3)
            ser.reset_input_buffer()
            # Self-test needs more time
            output = _send_command(ser, "~", wait=3.0)
        if output:
            info("Self-test results:")
            for line in output.splitlines():
                lvl = "ok" if "PASS" in line.upper() else ("err" if "FAIL" in line.upper() else "info")
                if lvl == "ok":
                    ok(f"  {line}")
                elif lvl == "err":
                    err(f"  {line}")
                else:
                    info(f"  {line}")
            if "FAIL" in output.upper():
                warn("One or more self-test failures detected.")
                info("  Ensure all probes are disconnected and retry.")
                info("  Persistent failures may indicate hardware damage.")
            else:
                ok("All self-tests passed.")
        else:
            warn("No response from self-test. Device may not be in REPL mode.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Self-test failed: {e}")


def op_reset(port: str):
    heading("Reset Device (#)")
    info("Sending '#' to the Bus Pirate 3.6 REPL — triggers a soft reset.")
    info("After reset, the device returns to the REPL in HiZ mode.")
    info("Any mode settings, PSU state, and pin configurations are cleared.")
    info("")
    info("If the device becomes unresponsive:")
    info("  1. Try this soft reset first")
    info("  2. If that fails, physically unplug and replug the USB cable")
    info("  3. If still unresponsive, the firmware may be corrupted — use 'Enter Bootloader'")

    if not confirm("Send reset command (#) to Bus Pirate 3.6?", default=True):
        info("Reset cancelled.")
        return

    try:
        with _open_serial(port) as ser:
            info("Sending '#'…")
            _send_command(ser, "#", wait=1.5)
        ok("Reset command sent. Device is rebooting.")
        info("Wait ~2 seconds for the device to return to the REPL prompt.")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Reset failed: {e}")
        info("Try physically unplugging and replugging the USB cable.")


def op_enter_bootloader(port: str):
    heading("Enter Bootloader ($)")
    info("Sending '$' to the Bus Pirate 3.6 REPL — jumps to PIC24 bootloader.")
    info("")
    info("In bootloader mode:")
    info("  - The USB VID:PID changes to 04D8:FB01")
    info("  - The device waits for firmware from pirate-loader or a PIC programmer")
    info("  - A new /dev/ttyACM* or /dev/ttyUSB* port appears for the bootloader")
    info("")
    info("WHEN TO USE:")
    info("  - Before using pirate-loader for firmware updates")
    info("  - Bootloader mode is required for '$' + pirate-loader workflow")
    info("")
    warn("If the device hangs after entering bootloader and you need to recover:")
    warn("  Unplug USB, re-plug while holding the PGC/PGD pins low (hardware override)")
    warn("  Or use a PICkit programmer to directly program the PIC24FJ256GB106")
    info("")

    if not confirm("Send bootloader jump command ($)?", default=True):
        info("Bootloader entry cancelled.")
        return

    try:
        with _open_serial(port) as ser:
            info("Sending '$' command…")
            _send_command(ser, "$", wait=1.5)
        ok("Bootloader jump command sent.")
        info("Waiting for bootloader USB device to appear…")
        info("  Expected VID:PID: 04D8:FB01")
        info("  Check: lsusb | grep 04D8  or  dmesg | tail -20")
        time.sleep(2)
        boot_port = find_serial_port_by_vidpid(VID_PID_BOOT)
        if boot_port:
            ok(f"Bootloader detected on {boot_port}. Ready for firmware update.")
        else:
            warn("Bootloader not detected via VID:PID scan.")
            info("  It may take a few more seconds. Check: ls /dev/ttyACM* or ls /dev/ttyUSB*")
            info("  Also check: dmesg | tail -20 for new USB device messages")
    except PermissionError:
        err(f"Permission denied on {port}.")
        _check_dialout(port)
    except Exception as e:
        err(f"Bootloader entry failed: {e}")


def op_firmware_update(port: str):
    heading("Firmware Update (pirate-loader)")
    info("Updating Bus Pirate 3.6 firmware using pirate-loader.")
    info("")
    info("Bus Pirate 3.6 firmware update process:")
    info("  1. Device enters PIC24 bootloader mode (via '$' command or manually)")
    info("  2. pirate-loader communicates with the PIC24 bootloader over serial")
    info("  3. The .hex firmware file is transmitted and written to flash")
    info("  4. Device reboots into new firmware")
    info("")
    info("NOTE: Bus Pirate 3.x uses .hex files (Intel HEX), NOT .uf2 like Bus Pirate 5.")
    info("  The firmware files are named like: BPv3-firmware-v6.1-r2xxx.hex")
    info("  Download from: https://github.com/BusPirate/Bus_Pirate/releases")
    info("")
    info("Checking latest available firmware version…")
    latest = _get_latest_firmware_version()
    if latest != "unknown":
        ok(f"Latest firmware release: {latest}")
        info("  Download the .hex file for Bus Pirate v3.x from this release.")
    info("")

    # Find or install pirate-loader
    loader = _find_pirate_loader()
    if not loader:
        info("pirate-loader not found. Attempting to build from source…")
        loader = _install_pirate_loader()
        if not loader:
            err("pirate-loader unavailable. Cannot perform firmware update.")
            info("Manual option: https://github.com/BusPirate/Bus_Pirate")
            return

    hex_path = prompt("Path to firmware .hex file")
    if not hex_path:
        warn("No file path provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return
    if hex_file.suffix.lower() != ".hex":
        warn(f"File does not have a .hex extension: {hex_file.name}")
        info("  Bus Pirate 3.6 firmware must be in Intel HEX format (.hex).")
        if not confirm("Continue with non-.hex file?", default=False):
            return

    # Check current mode — enter bootloader if needed
    boot_port_str = ""
    if _is_bootloader_mode():
        boot_port = find_serial_port_by_vidpid(VID_PID_BOOT)
        boot_port_str = boot_port if boot_port else port
        ok(f"Device already in bootloader mode on {boot_port_str}.")
    else:
        info("Device is in application mode. Entering bootloader via '$' command…")
        try:
            with _open_serial(port) as ser:
                _send_command(ser, "$", wait=1.5)
            info("Waiting for bootloader enumeration…")
            time.sleep(3)
        except Exception as e:
            warn(f"Could not send bootloader command: {e}")
            info("  Manual method: unplug Bus Pirate, hold PGC low, re-plug USB")

        boot_dev = find_serial_port_by_vidpid(VID_PID_BOOT)
        if boot_dev:
            boot_port_str = boot_dev
            ok(f"Bootloader on {boot_port_str}.")
        else:
            warn("Bootloader not auto-detected. Using current port as fallback.")
            boot_port_str = port
            info("  If pirate-loader fails, manually enter bootloader: unplug, hold reset, replug")

    if not confirm(f"Flash {hex_file.name} to Bus Pirate 3.6 via pirate-loader?", default=True):
        info("Firmware update cancelled.")
        return

    cmd = f"{loader} -p {boot_port_str} --hex {hex_file}"
    info(f"Running: {cmd}")
    info("  This process typically takes 15-60 seconds.")
    info("  Do NOT unplug the Bus Pirate during flashing.")
    try:
        r = run(cmd)
        if r.returncode == 0:
            ok("Firmware update complete! Bus Pirate 3.6 is rebooting.")
            info("  Wait ~3 seconds for the device to re-enumerate.")
            info("  Verify with 'Device Info (i)' — check firmware version string.")
        else:
            err("pirate-loader returned an error.")
            info("Troubleshooting:")
            info("  - Is the device in bootloader mode? (VID:PID 04D8:FB01)")
            info("  - Check: dmesg | tail -20 for USB events")
            info("  - Try specifying port manually: " + loader + " -p /dev/ttyACM0 --hex " + str(hex_file))
            info("  - Ensure the .hex file is for Bus Pirate v3.x (PIC24FJ256GB106)")
            info("  - pirate-loader source: " + PIRATE_LOADER_REPO)
    except FileNotFoundError:
        err(f"pirate-loader not found at: {loader}")
    except Exception as e:
        err(f"Firmware update error: {e}")
        info(f"  Debug: dmesg | tail -20  and  ls -la {boot_port_str}")


def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Querying Bus Pirate firmware version via serial 'v' command...")
    current = None
    try:
        import serial, time
        with serial.Serial(port, 115200, timeout=3) as ser:
            time.sleep(0.5)
            ser.write(b'\n')
            time.sleep(0.3)
            ser.reset_input_buffer()
            ser.write(b'v\n')
            time.sleep(0.5)
            response = ser.read(512).decode('ascii', errors='replace')
            import re
            m = re.search(r'Bus Pirate\s+v(\S+)', response, re.IGNORECASE)
            if m:
                current = m.group(1)
                ok(f"Bus Pirate firmware: v{current}")
    except Exception as e:
        warn(f"Could not query firmware version: {e}")
        info("  Ensure Bus Pirate is not busy and try again.")

    info("Checking latest Bus Pirate firmware on GitHub...")
    latest, url = check_latest_github_release("BusPirate", "Bus_Pirate")
    if latest:
        if current:
            announce_firmware_update(TOOL_NAME, current, latest.lstrip("v"), url)
        else:
            info(f"  Latest firmware: {latest}  ({url})")
    else:
        warn("Could not check GitHub for latest version.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial
    info("Ensuring pyserial for serial communication with Bus Pirate 3.6…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    # requests for GitHub API
    info("Ensuring requests library for firmware version checks…")
    ensure_pip_packages([("requests", "requests")])

    # git for pirate-loader build
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Ensuring git and build tools for pirate-loader compilation…")
        ensure_apt_packages(["git", "gcc", "make"])

    print_banner(TOOL_NAME, DESCRIPTION)

    warn("IMPORTANT: Bus Pirate 3.6 I/O pins operate at 5V logic level!")
    warn("  Always verify your target device voltage before connecting.")
    warn("  3.3V targets may require level shifting to avoid damage.")
    info("")

    info("Checking udev rules for Bus Pirate 3.6 (Microchip CDC + FTDI)…")
    _check_udev_rules()

    info("Detecting Bus Pirate v3.6 via USB VID:PIDs…")
    info("  Normal mode (Microchip CDC): 04D8:FB00 → /dev/ttyACM*")
    info("  FTDI clone variant:          0403:6001 → /dev/ttyUSB*")
    info("  Bootloader mode:             04D8:FB01")

    found = web_detect_loop(detect_bp36, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Bus Pirate v3.6 not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PID_ALL)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Bus Pirate v3.6 detected on {port}")
    check_firmware_version(port)

    if _is_bootloader_mode():
        warn("Device is in BOOTLOADER mode (04D8:FB01).")
        warn("  Most operations require normal application mode.")
        warn("  Use 'Firmware Update' to flash firmware and return to normal mode.")
        warn("  Or physically unplug and replug to attempt auto-recovery.")
    else:
        ok("Device is in normal application mode (REPL available).")

    _check_dialout(port)

    MENU_OPTIONS = [
        "Device Info (i)",
        "Read Voltages (v)",
        "Mode Setup (m)",
        "Power Control (W/w)",
        "Self-Test (~)",
        "Reset (#)",
        "Enter Bootloader ($)",
        "Firmware Update (pirate-loader)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Bus Pirate v3.6 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_read_voltages(port)
        elif choice == 2:
            op_mode_setup(port)
        elif choice == 3:
            op_power_control(port)
        elif choice == 4:
            op_self_test(port)
        elif choice == 5:
            op_reset(port)
        elif choice == 6:
            op_enter_bootloader(port)
        elif choice == 7:
            op_firmware_update(port)
        elif choice == 8:
            info("Goodbye.")
            break

        # Re-check device after each operation (device may reboot or change mode)
        new_port = find_serial_port_by_vidpid(VID_PID_ALL)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")
            if _is_bootloader_mode():
                info("  Device is now in bootloader mode.")
        elif not new_port:
            warn("Bus Pirate not detected after operation. It may be rebooting.")
            time.sleep(3)
            new_port = find_serial_port_by_vidpid(VID_PID_ALL)
            if new_port:
                port = new_port
                ok(f"Device re-enumerated on {port}")


if __name__ == "__main__":
    main()
