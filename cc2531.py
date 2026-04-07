#!/usr/bin/env python3
"""
CC2531 Tool Manager
Handles device info, firmware flashing, Zigbee2MQTT setup, Zigbee survey,
and serial monitoring for the Texas Instruments CC2531 Zigbee USB dongle.

The CC2531 is a USB-capable 802.15.4 / Zigbee SoC commonly used as:
  - Zigbee coordinator (with Z-Stack firmware + Zigbee2MQTT)
  - Zigbee packet sniffer (with sniffer firmware + Wireshark)

USB identity (when running CDC UART firmware):
  CC2531 CDC UART — VID:PID 0451:16AE  (Texas Instruments)

IMPORTANT — Flashing notes:
  The CC2531 CANNOT be flashed via its own USB port.  Firmware must be
  written through the 10-pin debug header on the PCB using a CC Debugger
  (VID:PID 0451:16A6) or a compatible JTAG/debug programmer.

  CC Debugger -> CC2531 pin mapping:
    CC Debugger pin 3  (DC / Debug Clock)  ->  CC2531 P2.1
    CC Debugger pin 4  (DD / Debug Data)   ->  CC2531 P2.0
    CC Debugger pin 7  (RST)               ->  CC2531 RESET pin
    CC Debugger pin 1  (GND)               ->  CC2531 GND
    CC Debugger pin 9  (3.3 V target)      ->  CC2531 VCC  (or use external 3.3 V)

Linux serial access:
  With CDC UART firmware the dongle appears as /dev/ttyACM*.
  If you get 'Permission denied': sudo usermod -aG dialout $USER
  then log out and back in.

Usage:
    python3 cc2531.py
"""

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
    check_latest_github_release, announce_firmware_update, get_firmware_dir,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "CC-2531"
DESCRIPTION = "Texas Instruments CC2531 Zigbee USB dongle"

# The CC2531 exposes a CDC UART interface when running coordinator/sniffer firmware.
VID_PIDS = [
    (0x0451, 0x16AE),   # TI CC2531 CDC UART
]

# The CC Debugger programmer is a separate USB device used for flashing.
CC_DEBUGGER_VID = "0451"
CC_DEBUGGER_PID = "16a6"

CONNECT_INSTRUCTIONS = (
    "CC2531 not detected.\n\n"
    "  1. Connect the CC2531 dongle via a USB-A port.\n"
    "  2. The dongle appears as a CDC UART device only when it is running\n"
    "     coordinator or sniffer firmware that enables the USB serial interface.\n"
    "     A freshly unprogrammed dongle will NOT enumerate here.\n\n"
    "  3. Expected device paths:\n"
    "       Linux : /dev/ttyACM0 (or ttyACM1, ttyACM2...)\n"
    "       macOS : /dev/cu.usbmodem*\n\n"
    "  4. If the port is not accessible:\n"
    "       Check: ls -la /dev/ttyACM*\n"
    "       Fix:   sudo usermod -aG dialout $USER  (then log out/in)\n"
    "       Quick: sudo chmod 666 /dev/ttyACM0\n\n"
    "  5. FLASHING REQUIREMENT:\n"
    "       To flash firmware you need a CC Debugger (VID:PID 0451:16A6)\n"
    "       connected to the 10-pin debug header on the CC2531 PCB.\n"
    "       The CC2531 CANNOT be flashed through its own USB port.\n\n"
    "  6. macOS users: cc-tool is Linux-only. Use a Linux VM or Raspberry Pi\n"
    "       to flash firmware, then bring the dongle back to macOS."
)

UDEV_RULES_CONTENT = """\
# CC2531 Zigbee USB dongle udev rules
# CC2531 CDC UART interface (VID:PID 0451:16AE)
SUBSYSTEM=="tty", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="16ae", MODE="0666", GROUP="dialout"
# CC Debugger programmer (VID:PID 0451:16A6) -- needed for firmware flashing
SUBSYSTEM=="usb", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="16a6", MODE="0666", GROUP="dialout"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-cc2531.rules"

# Zigbee2MQTT default installation path
Z2M_PATH   = Path("/opt/zigbee2mqtt")
Z2M_CONFIG = Z2M_PATH / "data" / "configuration.yaml"

# Zigbee channel range for 2.4 GHz 802.15.4 (channels 11-26)
ZIGBEE_CHANNELS = list(range(11, 27))


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    """Return True if a CC2531 CDC UART serial port is found via VID:PID."""
    return find_serial_port_by_vidpid(VID_PIDS) is not None


def _detect_cc_debugger() -> bool:
    """
    Return True if a CC Debugger USB device is visible via lsusb.
    The CC Debugger is a raw USB device (not a serial port), so we check lsusb.
    """
    try:
        out = run_output("lsusb 2>/dev/null")
        if out and f"{CC_DEBUGGER_VID}:{CC_DEBUGGER_PID}" in out.lower():
            return True
    except Exception:
        pass
    return False


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """
    Install udev rules on Linux so non-root users can access the CC2531
    CDC port and the CC Debugger USB device without sudo.
    """
    flavor = get_os_flavor()
    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules are a Linux-only concern -- skipping on this OS.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for CC2531 and CC Debugger...")
    info("  This grants non-root access to /dev/ttyACM* and the CC Debugger USB device.")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the CC2531 (and CC Debugger if connected) to apply permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual fix: sudo tee {UDEV_RULES_PATH} << 'EOF'")
        info(UDEV_RULES_CONTENT)
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_file(path_str: str, ext: str = None) -> Path:
    """
    Validate a user-supplied file path.  Returns a Path object on success,
    or None if the file is missing or the user cancels.
    """
    if not path_str:
        warn("No file path provided. Aborting.")
        return None
    p = Path(path_str)
    if not p.exists():
        err(f"File not found: {p}")
        info("Tip: use an absolute path, e.g. /home/user/CC2531ZNP-Pro-Secure_LinkKeyJoin.hex")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


def _lsusb_ti() -> str:
    """
    Run lsusb and return lines that mention Texas Instruments or VID 0451.
    Returns an empty string on non-Linux systems or if lsusb is unavailable.
    """
    try:
        out = run_output("lsusb 2>/dev/null")
        if not out:
            return ""
        lines = [l for l in out.splitlines()
                 if "0451" in l.lower() or "texas instruments" in l.lower()]
        return "\n".join(lines)
    except Exception as e:
        warn(f"lsusb query failed: {e}")
        return ""


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    """
    Show USB device information for the CC2531 dongle.

    Reads serial port metadata via pyserial, runs lsusb to list TI USB devices,
    and attempts a brief serial open to check whether firmware is responding on
    the CDC port (Z-Stack coordinator firmware enables CDC; a sniffer or empty
    dongle typically will not produce human-readable serial output).
    """
    heading("Device Info")
    info(f"Serial port detected : {port}")
    info(f"Tool                 : {TOOL_NAME} -- {DESCRIPTION}")
    info("")
    info("The CC2531 is a Texas Instruments IEEE 802.15.4 / Zigbee SoC.")
    info("It can run different firmware types:")
    info("  Z-Stack Coordinator  -- acts as a Zigbee coordinator for Zigbee2MQTT")
    info("  Zigbee Sniffer       -- captures raw 802.15.4 frames for Wireshark")
    info("")

    # ── pyserial metadata ──
    info("Reading serial port metadata via pyserial...")
    try:
        from serial.tools import list_ports
        matched = False
        for p in list_ports.comports():
            if p.device == port:
                matched = True
                info(f"  Device      : {p.device}")
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}  (expected: 0x0451:0x16AE for CC2531)")
                info(f"  Serial #    : {p.serial_number or 'N/A'}")
                info(f"  Location    : {p.location or 'N/A'}")
        if not matched:
            warn(f"pyserial did not find metadata for {port} -- port may have re-enumerated.")
    except ImportError:
        warn("pyserial not available -- cannot read port metadata.")
        info("Install: pip install pyserial --break-system-packages")
    except Exception as e:
        warn(f"pyserial metadata read error: {e}")

    # ── lsusb TI devices ──
    info("")
    info("Scanning lsusb for Texas Instruments USB devices (VID 0451)...")
    ti_lines = _lsusb_ti()
    if ti_lines:
        ok("TI devices found via lsusb:")
        for line in ti_lines.splitlines():
            info(f"  {line}")
    else:
        warn("No TI devices found in lsusb output (normal on macOS or if lsusb is absent).")

    # ── CC Debugger presence check ──
    info("")
    info("Checking for CC Debugger (VID:PID 0451:16A6) -- needed for flashing...")
    if _detect_cc_debugger():
        ok("CC Debugger is connected and visible in lsusb.")
        info("You can use 'Flash Firmware' to program the CC2531 through the debug header.")
    else:
        warn("CC Debugger not detected.")
        info("To flash firmware you will need a CC Debugger or compatible programmer.")
        info("Connect it to the CC2531 debug header (10-pin connector on the PCB).")

    # ── Probe CDC serial port ──
    info("")
    info("Probing CDC serial port to check firmware responsiveness...")
    info(f"Opening {port} at 115200 baud for 2 seconds to capture any output...")
    byte_count = 0
    try:
        import serial
        with serial.Serial(port, baudrate=115200, timeout=2) as ser:
            time.sleep(0.3)
            data = ser.read(256)
        byte_count = len(data)
        if data:
            ok(f"Received {byte_count} bytes from serial port -- firmware appears active.")
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in data[:80])
            info(f"  First 80 bytes (printable): {printable}")
        else:
            info("No data received -- this is normal for coordinator/sniffer firmware.")
            info("The CC2531 CDC port does not stream data unless queried by Zigbee2MQTT or a sniffer app.")
    except ImportError:
        warn("pyserial not installed -- cannot probe serial port.")
    except Exception as e:
        warn(f"Serial probe error: {e}")
        info("This does not necessarily indicate a problem -- the port may be in use by Zigbee2MQTT.")

    info("")
    ok("Device info complete.")
    pause()


def op_flash_firmware():
    """
    Flash firmware to the CC2531 using cc-tool.

    IMPORTANT: Flashing requires:
      1. A CC Debugger (VID:PID 0451:16A6) or compatible programmer
      2. The CC Debugger connected to the 10-pin debug header on the CC2531 PCB
      3. cc-tool installed (Linux only; not available on macOS)

    CC Debugger -> CC2531 debug header pin mapping:
      CC Debugger connector (10-pin 2x5, 1.27mm or 2.54mm):
        Pin 1  -- GND            -> CC2531 GND
        Pin 3  -- DC (Debug Clk) -> CC2531 P2.1  (debug clock)
        Pin 4  -- DD (Debug Data)-> CC2531 P2.0  (debug data)
        Pin 7  -- RST            -> CC2531 RESET pin
        Pin 9  -- 3.3V target    -> CC2531 VCC  (if powering via debugger)

    The debug header on the CC2531 PCB is labeled "DEBUG" or "P2" near the USB
    connector.  Consult the CC2531 hardware user guide (SWRU191) for the exact
    silkscreen layout.
    """
    heading("Flash Firmware (via CC Debugger)")
    flavor = get_os_flavor()

    # ── macOS guard ──
    if flavor == "macos":
        err("cc-tool is a Linux-only utility and is not available on macOS.")
        info("Options:")
        info("  1. Use a Linux machine, Raspberry Pi, or VM to flash the CC2531.")
        info("  2. Use a pre-flashed CC2531 from the Zigbee2MQTT project shop.")
        info("  3. Build cc-tool from source on macOS (unsupported, non-trivial).")
        pause()
        return

    # ── Check cc-tool availability ──
    info("Checking for cc-tool (Texas Instruments CC debugger flash tool)...")
    cc_tool_path = run_output("which cc-tool 2>/dev/null")
    if not cc_tool_path:
        info("cc-tool not found in PATH.  Attempting to install via apt...")
        ensure_apt_packages(["cc-tool"])
        cc_tool_path = run_output("which cc-tool 2>/dev/null")
        if not cc_tool_path:
            err("cc-tool could not be installed automatically.")
            info("Manual install: sudo apt-get install cc-tool")
            info("Or build from source: https://github.com/dashesy/cc-tool")
            pause()
            return
    ok(f"cc-tool found: {cc_tool_path.strip()}")

    # ── Check CC Debugger ──
    info("")
    info("Checking for CC Debugger (VID:PID 0451:16A6)...")
    if not _detect_cc_debugger():
        warn("CC Debugger not detected in lsusb.")
        info("Make sure the CC Debugger is:")
        info("  1. Plugged into a USB port on THIS machine (not a hub if possible)")
        info("  2. Connected to the CC2531 debug header via the 10-pin ribbon cable")
        info("  3. Has the CC2531 powered on (either via USB or 3.3V from debugger pin 9)")
        if not confirm("CC Debugger might still be present (lsusb check skipped). Continue?", default=False):
            info("Cancelled.  Connect the CC Debugger and try again.")
            pause()
            return
    else:
        ok("CC Debugger detected in lsusb.")

    # ── Physical connection reminder ──
    info("")
    info("PHYSICAL CONNECTION REMINDER:")
    info("  CC Debugger pin 1 (GND)             -> CC2531 GND")
    info("  CC Debugger pin 3 (DC / Debug Clock) -> CC2531 P2.1")
    info("  CC Debugger pin 4 (DD / Debug Data)  -> CC2531 P2.0")
    info("  CC Debugger pin 7 (RST)              -> CC2531 RESET")
    info("  CC Debugger pin 9 (3.3V target out)  -> CC2531 VCC  (optional, if not USB-powered)")
    info("")
    info("The debug header on the CC2531 is a 2x5 pin header near the USB connector.")
    info("Pin 1 is usually marked with a triangle or dot on the PCB silkscreen.")
    info("Consult SWRU191 (CC2531 hardware user guide) for the exact pin layout.")
    info("")

    # ── Firmware selection menu ──
    info("Select the firmware to flash:")
    fw_options = [
        "Z-Stack Coordinator (Zigbee2MQTT) -- coordinator firmware",
        "Zigbee Sniffer firmware -- for use with Wireshark",
        "Custom .hex file -- provide your own firmware path",
        "Cancel",
    ]
    fw_choice = numbered_menu("Firmware Selection", fw_options)

    firmware_path = None

    if fw_choice == 0:
        info("")
        info("Z-Stack Coordinator firmware (Zigbee2MQTT):")
        info("  Repository: https://github.com/Koenkk/Z-Stack-firmware")
        info("  Path in repo: coordinator/Z-Stack_Home_1.2/bin/default/")
        info("  Recommended file: CC2531ZNP-Pro-Secure_LinkKeyJoin.hex")
        info("")
        info("Download the latest coordinator hex from:")
        info("  https://github.com/Koenkk/Z-Stack-firmware/tree/master/coordinator/Z-Stack_Home_1.2/bin/default")
        info("")
        fw_path_str = prompt("Path to coordinator .hex file (e.g. /home/user/CC2531ZNP-Pro-Secure_LinkKeyJoin.hex)")
        firmware_path = _require_file(fw_path_str, ".hex")

    elif fw_choice == 1:
        info("")
        info("Zigbee Sniffer firmware:")
        info("  Repository: https://github.com/Koenkk/Z-Stack-firmware")
        info("  Path in repo: sniffer/bin/")
        info("  Recommended file: CC2531ZNP-sniffer.hex  (or CC2531_sniffer.hex)")
        info("")
        info("Download the latest sniffer hex from:")
        info("  https://github.com/Koenkk/Z-Stack-firmware/tree/master/sniffer/bin")
        info("")
        fw_path_str = prompt("Path to sniffer .hex file (e.g. /home/user/CC2531ZNP-sniffer.hex)")
        firmware_path = _require_file(fw_path_str, ".hex")

    elif fw_choice == 2:
        info("")
        info("Custom firmware: provide the full path to any valid CC2531 .hex file.")
        info("The file must be in Intel HEX format (.hex extension).")
        fw_path_str = prompt("Path to custom .hex firmware file")
        firmware_path = _require_file(fw_path_str, ".hex")

    else:
        info("Cancelled.")
        return

    if not firmware_path:
        err("No valid firmware file selected. Aborting.")
        return

    # ── Confirm and flash ──
    info("")
    info(f"Firmware file : {firmware_path}")
    info("Flash command : cc-tool -e -w <firmware.hex> -v")
    info("  -e  erase the CC2531 flash before writing")
    info("  -w  write the firmware hex file")
    info("  -v  verify the written flash by reading back and comparing")
    info("")
    warn("This will ERASE all existing firmware on the CC2531.")
    if not confirm(f"Flash {firmware_path.name} to CC2531 via CC Debugger?"):
        info("Cancelled.")
        return

    info("Starting flash (this typically takes 30-90 seconds)...")
    info("Do NOT unplug the CC Debugger or CC2531 during this operation.")
    info("")

    cmd = ["cc-tool", "-e", "-w", str(firmware_path), "-v"]
    info(f"Running: {' '.join(cmd)}")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(f"  cc-tool: {l}"), timeout=180)
        if rc == 0:
            ok("Firmware flashed and verified successfully!")
            info("Unplug and replug the CC2531 USB dongle to boot the new firmware.")
            info("The dongle should now enumerate as a CDC UART device (/dev/ttyACM*).")
        else:
            err(f"cc-tool exited with code {rc}. Flashing failed.")
            info("Troubleshooting:")
            info("  'No USB device found' -> CC Debugger not recognised; check udev rules")
            info("  'Timeout'             -> Check debug header cable connections (DC/DD/RST)")
            info("  'Verify failed'       -> Try a fresh erase-only first: cc-tool -e")
            info("  LED on CC Debugger should turn GREEN when connected to a live target")
    except FileNotFoundError:
        err("cc-tool binary not found even after install attempt.")
        info("Manual install: sudo apt-get install cc-tool")
        info("Build from source: https://github.com/dashesy/cc-tool")
    except Exception as e:
        err(f"cc-tool execution error: {e}")

    pause()


def op_setup_zigbee2mqtt(port: str):
    """
    Guide the user through installing and configuring Zigbee2MQTT.

    Zigbee2MQTT bridges Zigbee devices to MQTT, allowing integration with
    Home Assistant, Node-RED, and other home automation platforms.

    Prerequisites:
      - CC2531 with Z-Stack Coordinator firmware flashed
      - Node.js >= 16 and npm
      - An MQTT broker (mosquitto recommended)
    """
    heading("Zigbee2MQTT Setup")
    info("Zigbee2MQTT bridges Zigbee devices to an MQTT broker.")
    info("  Project: https://www.zigbee2mqtt.io/")
    info("  GitHub : https://github.com/Koenkk/zigbee2mqtt")
    info("")
    info(f"CC2531 serial port : {port}")
    info(f"Z2M install path   : {Z2M_PATH}")
    info(f"Z2M config file    : {Z2M_CONFIG}")
    info("")

    # ── Check if Zigbee2MQTT is installed ──
    info("Checking for existing Zigbee2MQTT installation...")
    z2m_installed = (Z2M_PATH / "node_modules").exists() or (Z2M_PATH / "package.json").exists()

    if not z2m_installed:
        info(f"Zigbee2MQTT is NOT installed at {Z2M_PATH}.")
        info("")
        info("Installation steps (run as root or with sudo):")
        info("  1. Install Node.js >= 16:")
        info("       curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -")
        info("       sudo apt-get install -y nodejs")
        info("")
        info("  2. Install and start the Mosquitto MQTT broker:")
        info("       sudo apt-get install -y mosquitto mosquitto-clients")
        info("       sudo systemctl enable --now mosquitto")
        info("       # Test: mosquitto_pub -t test -m hello && mosquitto_sub -t test -C 1")
        info("")
        info("  3. Run the automated setup script (if present):")
        info("       bash payloads/cc2531/zigbee2mqtt-setup/setup.sh")
        info("")
        info("  4. Or manual install:")
        info("       sudo mkdir -p /opt/zigbee2mqtt")
        info("       sudo chown -R $(id -u):$(id -g) /opt/zigbee2mqtt")
        info("       git clone --depth 1 https://github.com/Koenkk/zigbee2mqtt.git /opt/zigbee2mqtt")
        info("       cd /opt/zigbee2mqtt && npm ci")
        info("")
        info("  5. Edit the config file before first run:")
        info(f"       {Z2M_CONFIG}")
        info("       Key settings:")
        info(f"         serial.port: {port}")
        info("         mqtt.server: mqtt://localhost")
        info("         homeassistant: true  # if using Home Assistant")
        info("")

        # Check for payload script
        setup_script = Path("payloads/cc2531/zigbee2mqtt-setup/setup.sh")
        if setup_script.exists():
            ok(f"Setup script found: {setup_script}")
            if confirm("Run the automated setup script now?"):
                try:
                    rc = run_streaming(
                        ["bash", str(setup_script)],
                        on_line=lambda l: info(f"  setup: {l}"),
                        timeout=600,
                    )
                    if rc == 0:
                        ok("Setup script completed successfully.")
                    else:
                        err(f"Setup script exited with code {rc}.")
                except Exception as e:
                    err(f"Setup script error: {e}")
        else:
            info(f"Setup script not found at {setup_script} -- follow manual steps above.")
    else:
        ok(f"Zigbee2MQTT is installed at {Z2M_PATH}.")
        info("")

        # ── Show config location ──
        info(f"Configuration file: {Z2M_CONFIG}")
        if Z2M_CONFIG.exists():
            ok("Configuration file exists.")
            if confirm("Show configuration file contents?", default=False):
                try:
                    content = Z2M_CONFIG.read_text()
                    for line in content.splitlines():
                        info(f"  {line}")
                except Exception as e:
                    warn(f"Could not read config: {e}")
        else:
            warn(f"Configuration file not found at {Z2M_CONFIG}.")
            info("Copy the example config and edit it:")
            info(f"  cp {Z2M_PATH}/data/configuration.yaml.example {Z2M_CONFIG}")

        # ── Check systemd service ──
        info("")
        info("Checking Zigbee2MQTT systemd service status...")
        try:
            out = run_output("systemctl is-active zigbee2mqtt 2>/dev/null")
            if out and "active" in out.lower():
                ok("zigbee2mqtt service is ACTIVE (running).")
            elif out and "inactive" in out.lower():
                warn("zigbee2mqtt service is INACTIVE (stopped).")
                info("Start it: sudo systemctl start zigbee2mqtt")
            elif out and "failed" in out.lower():
                err("zigbee2mqtt service is in FAILED state.")
                info("Check logs: journalctl -u zigbee2mqtt -n 50")
            else:
                info("zigbee2mqtt service not configured as a systemd unit.")
                info(f"Manual start: cd {Z2M_PATH} && npm start")
        except Exception as e:
            warn(f"systemctl check failed: {e}")

        # ── How to start ──
        info("")
        info("How to start Zigbee2MQTT:")
        info("  Systemd : sudo systemctl start zigbee2mqtt")
        info(f"  Manual  : cd {Z2M_PATH} && npm start")
        info(f"  With log: cd {Z2M_PATH} && npm start 2>&1 | tee /tmp/z2m.log")
        info("")
        info("How to monitor Zigbee MQTT messages:")
        info("  mosquitto_sub -t 'zigbee2mqtt/#' -v")
        info("  mosquitto_sub -t 'zigbee2mqtt/bridge/devices' -v  # list paired devices")
        info("  mosquitto_sub -t 'zigbee2mqtt/bridge/log' -v       # bridge log stream")
        info("")
        info("Pairing a new Zigbee device:")
        info("  mosquitto_pub -t 'zigbee2mqtt/bridge/request/permit_join' -m '{\"value\":true}'")
        info("  Then trigger the device's pairing mode (usually hold a button).")

        # ── Mosquitto check ──
        info("")
        info("Checking Mosquitto MQTT broker...")
        try:
            out = run_output("systemctl is-active mosquitto 2>/dev/null")
            if out and "active" in out.lower():
                ok("Mosquitto broker is running.")
            else:
                warn("Mosquitto does not appear to be running.")
                info("Install & start: sudo apt-get install mosquitto && sudo systemctl enable --now mosquitto")
        except Exception as e:
            warn(f"Mosquitto status check failed: {e}")

    pause()


def op_zigbee_survey(port: str):
    """
    Guide the user through using the CC2531 as a Zigbee sniffer with Wireshark.

    This requires the CC2531 to be flashed with the Zigbee sniffer firmware.
    The sniffer firmware communicates with the host via a custom protocol over
    the USB CDC port, and a Python-based extcap plugin feeds frames to Wireshark.

    Zigbee uses 16 channels in the 2.4 GHz band (channels 11-26).
    """
    heading("Zigbee Survey / Packet Sniffing")
    info("Use the CC2531 as a Zigbee packet sniffer with Wireshark.")
    info("")
    info("PREREQUISITE: The CC2531 must be flashed with the SNIFFER firmware,")
    info("  NOT the coordinator firmware.  Coordinator firmware does NOT support")
    info("  raw packet capture mode.")
    info("")
    info(f"CC2531 serial port : {port}")
    info("Zigbee frequency   : 2.4 GHz ISM band")
    info("Zigbee channels    : 11 - 26  (each channel is 5 MHz wide)")
    info("Channel 11 = 2405 MHz, Channel 26 = 2480 MHz")
    info("")

    # ── Check for Wireshark / tshark ──
    info("Checking for Wireshark / tshark...")
    wireshark_path = run_output("which wireshark 2>/dev/null")
    tshark_path    = run_output("which tshark 2>/dev/null")

    if wireshark_path:
        ok(f"wireshark found: {wireshark_path.strip()}")
    else:
        warn("wireshark not found.")
        info("Install: sudo apt-get install wireshark  (Linux)")
        info("         brew install --cask wireshark   (macOS)")

    if tshark_path:
        ok(f"tshark found: {tshark_path.strip()}")
    else:
        warn("tshark not found.")
        info("Install: sudo apt-get install tshark  (Linux, included with Wireshark)")

    if not wireshark_path and not tshark_path:
        warn("Neither wireshark nor tshark found -- packet capture will not be possible.")
        flavor = get_os_flavor()
        if flavor in ("kali", "debian", "ubuntu", "linux"):
            if confirm("Install wireshark and tshark now?"):
                try:
                    ensure_apt_packages(["wireshark", "tshark"])
                except Exception as e:
                    err(f"apt install failed: {e}")

    # ── Payload script check ──
    info("")
    info("Checking for Zigbee survey payload script...")
    survey_script = Path("payloads/cc2531/zigbee-survey/setup.sh")
    if survey_script.exists():
        ok(f"Survey setup script found: {survey_script}")
        info("Run it to install and configure the sniffer extcap plugin.")
        if confirm("Run the zigbee-survey setup script now?", default=False):
            try:
                rc = run_streaming(
                    ["bash", str(survey_script)],
                    on_line=lambda l: info(f"  setup: {l}"),
                    timeout=300,
                )
                if rc == 0:
                    ok("Zigbee survey setup completed.")
                else:
                    err(f"Setup script exited with code {rc}.")
            except Exception as e:
                err(f"Setup script error: {e}")
    else:
        info(f"Survey script not found at {survey_script} -- following manual steps below.")

    # ── Sniffer setup instructions ──
    info("")
    info("MANUAL SNIFFER SETUP:")
    info("  The CC2531 sniffer firmware exposes a raw USB protocol.")
    info("  You need a Python extcap plugin (whsniff or cc2531-sniffer) to bridge it")
    info("  to Wireshark's extcap pipe interface.")
    info("")
    info("  Option 1 -- whsniff:")
    info("    https://github.com/homewsn/whsniff")
    info("    Build: git clone https://github.com/homewsn/whsniff && cd whsniff && make")
    info("    Run:   whsniff -c <channel> | wireshark -k -i -")
    info("")
    info("  Option 2 -- cc2531-sniffer extcap:")
    info("    https://github.com/Koenkk/zigbee-herdsman")
    info("    (See Zigbee2MQTT sniffer documentation for extcap integration)")
    info("")
    info("  Option 3 -- Texas Instruments Packet Sniffer 2:")
    info("    https://www.ti.com/tool/PACKET-SNIFFER  (Windows only)")
    info("")

    # ── Channel scanning reference ──
    info("ZIGBEE CHANNEL SCANNING:")
    info("  Scan each channel to identify active Zigbee networks.")
    info(f"  Channels to scan: {ZIGBEE_CHANNELS}")
    info("")
    info("  With whsniff -- capture 10 seconds per channel:")
    for ch in ZIGBEE_CHANNELS:
        info(f"    whsniff -c {ch} | timeout 10 tshark -r - -q -z io,stat,0 2>/dev/null")
    info("")
    info("  Capture to pcap file for later analysis:")
    info("    whsniff -c 11 | tshark -r - -w /tmp/zigbee-ch11.pcap")
    info("")

    # ── Wireshark display filters ──
    info("WIRESHARK DISPLAY FILTERS for Zigbee traffic:")
    info("  wpan            -- all IEEE 802.15.4 frames (MAC layer)")
    info("  zbee_nwk        -- Zigbee Network layer frames")
    info("  zbee_aps        -- Zigbee Application Support Sub-layer")
    info("  zbee_zcl        -- Zigbee Cluster Library (device commands)")
    info("  zbee_zdp        -- Zigbee Device Profile (discovery/management)")
    info("")
    info("  Combined filter : wpan || zbee_nwk || zbee_aps")
    info("  Beacon frames   : wpan.frame_type == 0")
    info("  Data frames     : wpan.frame_type == 1")
    info("  Filter by PAN ID: wpan.dst_pan == 0x1234")
    info("")

    # ── Wi-Fi channel overlap advisory ──
    info("COMMON ZIGBEE CHANNEL USAGE (2.4 GHz):")
    info("  Channel 11 -- often used by Philips Hue")
    info("  Channel 15 -- used by SmartThings, Ikea Tradfri")
    info("  Channel 25 -- Zigbee2MQTT default")
    info("  Channel 26 -- maximum (may have reduced TX power in some regions)")
    info("")
    info("  Wi-Fi / Zigbee 2.4 GHz overlap:")
    info("  Wi-Fi ch 1  overlaps Zigbee ch 11-14")
    info("  Wi-Fi ch 6  overlaps Zigbee ch 16-21")
    info("  Wi-Fi ch 11 overlaps Zigbee ch 21-25")
    info("  Best Zigbee channels to avoid Wi-Fi: 15, 20, 25, 26")

    pause()


def op_serial_monitor(port: str):
    """
    Open a raw serial monitor to the CC2531 CDC UART port.

    Useful for debugging Z-Stack firmware responses, AT command interfaces,
    or any raw output from custom CC2531 firmware.  The CDC port does not
    stream data unless queried, so this is mostly useful with firmware that
    outputs log messages or responds to commands.
    """
    heading("Serial Monitor")
    info(f"Opening serial monitor on {port} at 115200 baud.")
    info("")
    info("This connects to the CC2531 CDC UART interface directly.")
    info("Useful for:")
    info("  - Debugging Z-Stack coordinator/sniffer firmware log output")
    info("  - Testing custom CC2531 firmware serial communication")
    info("  - Sending raw commands to experimental firmware builds")
    info("")
    info("NOTE: If Zigbee2MQTT is currently using this port, you must stop it first.")
    info("  sudo systemctl stop zigbee2mqtt")
    info("")
    info("Press Ctrl+C to exit the serial monitor.")
    info("")

    # ── Terminal emulator alternatives ──
    info("Alternatively, use a terminal emulator directly:")
    info(f"  minicom  : minicom -D {port} -b 115200")
    info(f"           : Ctrl+A then X to exit minicom")
    info(f"  screen   : screen {port} 115200")
    info(f"           : Ctrl+A then K to kill screen session")
    info(f"  picocom  : picocom {port} -b 115200")
    info(f"           : Ctrl+A then Ctrl+X to exit picocom")
    info(f"  tio      : tio {port}")
    info(f"           : Ctrl+T then Q to exit tio")
    info("")

    if not confirm(f"Open pyserial monitor on {port} now?"):
        info("Cancelled.  Use one of the terminal emulators listed above instead.")
        return

    info(f"Starting serial monitor on {port} at 115200 baud...  (Ctrl+C to stop)")
    info("")

    byte_count = 0
    try:
        import serial
        with serial.Serial(port, baudrate=115200, timeout=1) as ser:
            info(f"Connected to {port}.  Waiting for data...")
            line_buf = b""
            while True:
                try:
                    chunk = ser.read(64)
                    if chunk:
                        byte_count += len(chunk)
                        line_buf += chunk
                        # Print complete lines, buffer partial ones
                        while b"\n" in line_buf:
                            line, line_buf = line_buf.split(b"\n", 1)
                            decoded = line.rstrip(b"\r").decode("utf-8", errors="replace")
                            info(f"  >> {decoded}")
                except Exception as inner_e:
                    err(f"Serial read error: {inner_e}")
                    break
    except KeyboardInterrupt:
        info("")
        info("Serial monitor stopped by user (Ctrl+C).")
        info(f"Total bytes received: {byte_count}")
    except ImportError:
        err("pyserial not installed.")
        info("Install: pip install pyserial --break-system-packages")
        info(f"Then use: minicom -D {port} -b 115200")
    except Exception as e:
        err(f"Could not open {port}: {e}")
        info("Possible causes:")
        info("  - Port is already in use (Zigbee2MQTT, another terminal, etc.)")
        info("  - Insufficient permissions -- try: sudo chmod 666 " + port)
        info("  - Device was unplugged")

    pause()


# ── Firmware Version Check ────────────────────────────────────────────────────

def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Querying CC2531 firmware via Z-Stack ZNP SYS_VERSION command...")
    info("  This only works if the CC2531 is running Z-Stack coordinator/sniffer firmware.")
    current = None

    try:
        import serial, time
        with serial.Serial(port, 115200, timeout=3) as ser:
            time.sleep(0.5)
            # ZNP SYS_PING: FE 00 21 01 20
            ser.write(bytes([0xFE, 0x00, 0x21, 0x01, 0x20]))
            time.sleep(0.3)
            resp = ser.read(10)
            if len(resp) >= 5 and resp[0] == 0xFE:
                info("  ZNP SYS_PING successful — Z-Stack firmware detected")
                # ZNP SYS_VERSION: FE 00 21 02 23
                ser.write(bytes([0xFE, 0x00, 0x21, 0x02, 0x23]))
                time.sleep(0.3)
                ver_resp = ser.read(16)
                if len(ver_resp) >= 8:
                    transport_rev = ver_resp[4] if len(ver_resp) > 4 else 0
                    product_id = ver_resp[5] if len(ver_resp) > 5 else 0
                    major = ver_resp[6] if len(ver_resp) > 6 else 0
                    minor = ver_resp[7] if len(ver_resp) > 7 else 0
                    current = f"Z-Stack {major}.{minor} (product {product_id})"
                    ok(f"Firmware: {current}")
            else:
                info("  No ZNP response — may be running sniffer firmware or different stack")
    except Exception as e:
        warn(f"Could not query Z-Stack version: {e}")
        info("  This is normal if the CC2531 has sniffer firmware or CDC isn't active")

    info("Checking latest Z-Stack coordinator firmware on GitHub...")
    latest, url = check_latest_github_release("Koenkk", "Z-Stack-firmware")
    if latest:
        info(f"  Latest Z-Stack firmware release: {latest}")
        info(f"  Release URL: {url}")
        fw_dir = get_firmware_dir("cc2531") / "coordinator"
        if fw_dir.exists() and not any(fw_dir.iterdir()):
            if confirm("Download latest CC2531 coordinator firmware?", default=False):
                from common import get_github_release_asset_url, download_firmware
                asset_url = get_github_release_asset_url(
                    "Koenkk", "Z-Stack-firmware", latest,
                    r"CC2531.*coordinator.*\.hex$|CC2531.*coordinator.*\.zip$"
                )
                if asset_url:
                    dest = fw_dir / f"CC2531_coordinator_{latest}.hex"
                    download_firmware(asset_url, dest, "CC2531 Coordinator")
                else:
                    warn("No CC2531 coordinator asset found in release.")
                    info(f"Manual download from: {url}")
    else:
        warn("Could not check GitHub for firmware updates.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")
    info("")

    info("Checking for pyserial (required for serial port detection and monitoring)...")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  Trying apt: apt-get install python3-serial")
        ensure_apt_packages(["python3-serial"])
    info("  Checking pip for pyserial...")
    ensure_pip_packages([("serial", "pyserial")])
    info("")

    info("Checking for cc-tool (required for firmware flashing, Linux only)...")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  cc-tool is available via apt on Debian/Ubuntu/Kali.")
        info("  It will be installed on-demand when 'Flash Firmware' is selected.")
        info("  Manual install now: sudo apt-get install cc-tool")
    elif flavor == "macos":
        warn("cc-tool is NOT available on macOS.  Firmware flashing requires Linux.")
        info("  Use a Linux VM, Raspberry Pi, or a second machine to flash the CC2531.")
    else:
        info("  cc-tool availability unknown for this OS.  Linux recommended for flashing.")
    info("")

    info("Checking for Wireshark / tshark (optional, for Zigbee sniffing)...")
    wireshark_found = bool(run_output("which wireshark 2>/dev/null"))
    tshark_found    = bool(run_output("which tshark 2>/dev/null"))
    if wireshark_found:
        ok("  wireshark is installed.")
    else:
        info("  wireshark not found (optional -- needed for Zigbee survey).")
        info("  Install: sudo apt-get install wireshark")
    if tshark_found:
        ok("  tshark is installed.")
    else:
        info("  tshark not found (optional -- needed for command-line packet capture).")
        info("  Install: sudo apt-get install tshark")
    info("")

    info("Checking for mosquitto_sub (optional, for monitoring Zigbee2MQTT messages)...")
    if run_output("which mosquitto_sub 2>/dev/null"):
        ok("  mosquitto-clients (mosquitto_sub / mosquitto_pub) are installed.")
    else:
        info("  mosquitto_sub not found (optional).")
        info("  Install: sudo apt-get install mosquitto-clients")
    info("")

    # ── Linux udev rules ──────────────────────────────────────────────────────
    _check_udev_rules()

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    info("Scanning for CC2531 CDC UART device via VID:PID 0451:16AE...")
    info("The CC2531 only enumerates as a serial port when running firmware that")
    info("enables the USB CDC interface (coordinator or sniffer firmware).")
    info("")
    info("Expected device paths:")
    info("  Linux : /dev/ttyACM*  (check with: ls /dev/ttyACM*)")
    info("  macOS : /dev/cu.usbmodem*")
    info("")
    info("If the dongle is connected but not detected, it may need firmware flashed first.")
    info("In that case, connect the CC Debugger to the debug header and use the")
    info("'Flash Firmware' option after the menu loads.")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("CC2531 not detected within timeout. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Device appeared but serial port could not be resolved. Exiting.")
        info("Debug: check 'dmesg | tail -20' or 'ls /dev/ttyACM*'")
        sys.exit(1)

    ok(f"CC2531 detected on {port}")
    info(f"Serial port: {port}")
    info("")

    check_firmware_version(port)

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Device Info (USB details, firmware probe)",
        "Flash Firmware (requires CC Debugger + debug header)",
        "Zigbee2MQTT Setup (coordinator mode)",
        "Zigbee Survey / Packet Sniffing (sniffer mode)",
        "Serial Monitor (raw CDC UART output)",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} -- Main Menu", MENU_OPTIONS)

        if choice == 0:
            try:
                op_device_info(port)
            except Exception as e:
                err(f"Device info error: {e}")

        elif choice == 1:
            try:
                op_flash_firmware()
            except Exception as e:
                err(f"Flash firmware error: {e}")

        elif choice == 2:
            try:
                op_setup_zigbee2mqtt(port)
            except Exception as e:
                err(f"Zigbee2MQTT setup error: {e}")

        elif choice == 3:
            try:
                op_zigbee_survey(port)
            except Exception as e:
                err(f"Zigbee survey error: {e}")

        elif choice == 4:
            try:
                op_serial_monitor(port)
            except Exception as e:
                err(f"Serial monitor error: {e}")

        elif choice == 5:
            info("Goodbye.")
            break

        # Re-check port after operations (device may re-enumerate after flash)
        try:
            new_port = find_serial_port_by_vidpid(VID_PIDS)
            if new_port and new_port != port:
                info(f"Serial port changed from {port} to {new_port} (device re-enumerated).")
                port = new_port
                ok(f"Now using port: {port}")
        except Exception as e:
            warn(f"Port re-check failed: {e}")


if __name__ == "__main__":
    main()
