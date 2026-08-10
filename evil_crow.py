#!/usr/bin/env python3
"""
Evil Crow RF V2 Tool Manager
Manages the Evil Crow RF V2 sub-GHz / 2.4 GHz RF attack platform.
Built around ESP32 + CC1101 (sub-GHz) + nRF24L01+ (2.4 GHz).

Usage:
    python3 evil_crow.py

Evil Crow RF V2 connection methods:
    USB:  VID:PID 10C4:EA60 (CP2102) — primarily for firmware flashing
    WiFi: Connect to SSID "EvilCrowRF" (password: EvilCrowRF)
          then access http://192.168.4.1

Project: https://github.com/joelsernamoreno/EvilCrowRF-V2

Hardware overview:
    CC1101  — Sub-GHz transceiver (300-348 MHz, 387-464 MHz, 779-928 MHz)
    nRF24L01+ — 2.4 GHz (mouse/keyboard attacks, Bluetooth-like)
    ESP32   — Main MCU + WiFi AP for web interface

Web API endpoints:
    GET  /api/status  — device status and current config
    GET  /api/scan    — start RF scan
    POST /api/replay  — replay captured signal
"""

import socket
import sys
import time
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

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
    detect_usb_libusb_any,
    check_latest_github_release, announce_firmware_update,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Evil Crow RF V2"
DESCRIPTION = "ESP32 + CC1101 + nRF24L01+ sub-GHz / 2.4 GHz RF attack platform"

VID_PIDS = [
    (0x10C4, 0xEA60),  # Silicon Labs CP2102 USB-UART bridge (primary)
    (0x303A, 0x0002),  # ESP32-S2 native USB
]

BAUD_RATE   = 115200
WEB_HOST    = "192.168.4.1"
WEB_PORT    = 80
WEB_BASE    = f"http://{WEB_HOST}"
WIFI_SSID   = "EvilCrowRF"
WIFI_PASS   = "EvilCrowRF"

GITHUB_API  = "https://api.github.com/repos/joelsernamoreno/EvilCrowRF-V2/releases/latest"
GITHUB_REPO = "https://github.com/joelsernamoreno/EvilCrowRF-V2"

CONNECT_INSTRUCTIONS = (
    "Evil Crow RF V2 not detected.\n\n"
    "  Evil Crow RF can connect via:\n\n"
    "  (1) USB: VID:PID 10C4:EA60 (CP2102 USB-UART bridge)\n"
    "      Connect via Micro-USB or USB-C cable.\n"
    "      The USB connection is primarily for firmware flashing.\n"
    "      Linux: device appears as /dev/ttyUSB* (cp210x driver)\n"
    "      macOS: device appears as /dev/cu.SLAB_USBtoUART\n"
    "      Check: ls /dev/ttyUSB* or dmesg | tail -20\n\n"
    "  (2) WiFi: Connect your computer to WiFi SSID 'EvilCrowRF'\n"
    "      Password: EvilCrowRF\n"
    "      Then access: http://192.168.4.1\n"
    "      The WiFi interface is the primary management UI.\n\n"
    "  Troubleshooting USB:\n"
    "    Linux CP2102 driver: sudo modprobe cp210x\n"
    "    udev rules: ls /etc/udev/rules.d/ | grep evil\n"
    "    Permission: sudo usermod -aG dialout $USER\n"
    "    Debug: dmesg | tail -20"
)

UDEV_RULES_CONTENT = (
    '# Evil Crow RF V2 udev rules\n'
    '# CP2102 USB-UART (VID:PID 10C4:EA60)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", '
    'MODE="0666", GROUP="dialout"\n'
    '# ESP32-S2 native USB (VID:PID 303A:0002)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="0002", '
    'MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-evil-crow-rf.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device_usb() -> bool:
    """Detect Evil Crow RF via USB VID:PID using serial port or libusb."""
    info("Checking USB serial port for CP2102 (10C4:EA60) or ESP32-S2 (303A:0002)…")
    port = find_serial_port_by_vidpid(VID_PIDS)
    if port:
        info(f"  Found serial port: {port}")
        return True
    info("  Serial port not found. Trying libusb direct scan…")
    return detect_usb_libusb_any(VID_PIDS)


def detect_device_wifi() -> bool:
    """Detect Evil Crow RF via TCP connect to 192.168.4.1:80."""
    info(f"Checking WiFi reachability: TCP connect to {WEB_HOST}:{WEB_PORT}…")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        result = s.connect_ex((WEB_HOST, WEB_PORT))
        s.close()
        if result == 0:
            info(f"  TCP connection to {WEB_HOST}:{WEB_PORT} succeeded.")
            return True
        else:
            info(f"  TCP connection failed (code {result}). WiFi not connected?")
            return False
    except Exception as e:
        info(f"  TCP check exception: {e}")
        return False


def detect_device() -> bool:
    """Detect via USB first, then WiFi."""
    if detect_device_usb():
        return True
    if detect_device_wifi():
        return True
    return False


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for CP2102 on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("Skipping udev rule check (not Linux).")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("udev rules not found — installing Evil Crow RF rules…")
    info(f"  Target: {UDEV_RULES_PATH}")
    info("  Enables non-root access to CP2102 USB-UART bridge.")
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
        info("  Add: SUBSYSTEM==\"tty\", ATTRS{{idVendor}}==\"10c4\", ATTRS{{idProduct}}==\"ea60\", MODE=\"0666\", GROUP=\"dialout\"")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")

    # Check cp210x kernel module
    info("Checking cp210x kernel module…")
    mod_out = run_output("lsmod 2>/dev/null | grep cp210x")
    if mod_out:
        ok("Kernel module 'cp210x' is loaded.")
    else:
        info("cp210x module not loaded — attempting modprobe…")
        r = sudo_run("modprobe cp210x")
        if r.returncode == 0:
            ok("cp210x module loaded.")
        else:
            warn("Could not load cp210x module. CP2102 may still work via built-in driver.")


# ── Web API helpers ────────────────────────────────────────────────────────────

def _web_get(endpoint: str, timeout: int = 10):
    """Perform GET request to Evil Crow RF web API. Returns response or None."""
    if not HAS_REQUESTS:
        warn("'requests' library not available. Cannot make HTTP requests.")
        info("Install: pip install requests --break-system-packages")
        return None
    url = f"{WEB_BASE}{endpoint}"
    info(f"HTTP GET {url}")
    try:
        resp = requests.get(url, timeout=timeout)
        info(f"  HTTP {resp.status_code} {resp.reason}")
        return resp
    except requests.exceptions.ConnectionError as e:
        err(f"Connection error to {WEB_HOST}: {e}")
        info("Troubleshooting:")
        info(f"  - Are you connected to WiFi SSID '{WIFI_SSID}' (password: {WIFI_PASS})?")
        info(f"  - Is {WEB_HOST} reachable? Try: ping {WEB_HOST}")
        info(f"  - Is the Evil Crow RF powered on?")
        return None
    except requests.exceptions.Timeout:
        err(f"HTTP request timed out ({timeout}s).")
        info(f"  Check WiFi connection to '{WIFI_SSID}' and device power state.")
        return None
    except Exception as e:
        err(f"HTTP request failed: {e}")
        return None


def _web_post(endpoint: str, data: dict, timeout: int = 10):
    """Perform POST request to Evil Crow RF web API. Returns response or None."""
    if not HAS_REQUESTS:
        warn("'requests' library not available.")
        return None
    url = f"{WEB_BASE}{endpoint}"
    info(f"HTTP POST {url} data={data}")
    try:
        resp = requests.post(url, json=data, timeout=timeout)
        info(f"  HTTP {resp.status_code} {resp.reason}")
        return resp
    except requests.exceptions.ConnectionError as e:
        err(f"Connection error to {WEB_HOST}: {e}")
        info(f"  Ensure you are connected to WiFi SSID '{WIFI_SSID}'.")
        return None
    except Exception as e:
        err(f"HTTP POST failed: {e}")
        return None


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    """Show USB info and connect to web API for device status."""
    heading("Device Info")
    info("Evil Crow RF V2 hardware overview:")
    info("  ESP32       — Main MCU (dual-core Xtensa LX6, WiFi/BT capable)")
    info("  CC1101      — Sub-GHz transceiver: 300-348 MHz, 387-464 MHz, 779-928 MHz")
    info("  nRF24L01+   — 2.4 GHz transceiver (mouse jacking, keyboard attacks)")
    info("  USB-UART    — CP2102 bridge for serial debug / firmware flashing")
    info("")

    # USB info
    os_flavor = get_os_flavor()
    info("Checking USB connection (CP2102 VID:PID 10C4:EA60)…")
    port = find_serial_port_by_vidpid(VID_PIDS)
    if port:
        ok(f"USB serial port detected: {port}")
        info("  The USB connection is used for:")
        info("    - Firmware flashing via esptool")
        info("    - Serial debug output (115200 baud)")
        try:
            from serial.tools import list_ports
            for p in list_ports.comports():
                if p.device == port:
                    info(f"  Description : {p.description}")
                    info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                    vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                    pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                    info(f"  VID:PID     : {vid}:{pid}")
                    info(f"  Serial No.  : {p.serial_number or 'N/A'}")
        except Exception as e:
            info(f"  (Could not enumerate port details: {e})")
    else:
        warn("USB serial port not detected.")
        info("  Device may be in WiFi-only mode, or CP2102 driver not loaded.")
        if os_flavor in ("kali", "debian", "ubuntu", "linux"):
            info("  Check: lsusb | grep -i '10c4:ea60'")
            info("  Check: dmesg | tail -20 (look for 'cp210x' or 'ttyUSB')")
            info("  Fix:   sudo modprobe cp210x")

    info("")
    info("Checking WiFi web interface (http://192.168.4.1)…")
    info(f"  Ensure you are connected to WiFi SSID: {WIFI_SSID}")
    info(f"  WiFi password: {WIFI_PASS}")

    resp = _web_get("/api/status")
    if resp and resp.status_code == 200:
        ok("Web API /api/status reachable!")
        try:
            import json
            data = resp.json()
            info("  Device status from API:")
            for k, v in data.items():
                info(f"    {k}: {v}")
        except Exception:
            info(f"  Response body: {resp.text[:500]}")
    elif resp:
        warn(f"Web API returned HTTP {resp.status_code}")
        info("  Device is reachable but API endpoint may differ in your firmware version.")
        info("  Try accessing http://192.168.4.1 in a web browser.")
    else:
        warn("Web API not reachable.")
        info(f"  Are you connected to WiFi '{WIFI_SSID}'? Check network settings.")

    ok("Device info complete.")


def op_check_wifi_connection():
    """Check if 192.168.4.1 is reachable via WiFi."""
    heading("Check WiFi Connection")
    info(f"Checking connectivity to Evil Crow RF V2 web interface…")
    info(f"  AP SSID    : {WIFI_SSID}")
    info(f"  AP Password: {WIFI_PASS}")
    info(f"  AP IP      : {WEB_HOST}")
    info(f"  Web UI     : {WEB_BASE}")
    info("")
    info(f"Step 1: TCP connect check to {WEB_HOST}:{WEB_PORT}…")

    tcp_ok = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((WEB_HOST, WEB_PORT))
        s.close()
        if result == 0:
            ok(f"TCP connection to {WEB_HOST}:{WEB_PORT} succeeded.")
            tcp_ok = True
        else:
            err(f"TCP connection to {WEB_HOST}:{WEB_PORT} failed (error code {result}).")
            info("  Possible causes:")
            info(f"    - Not connected to WiFi SSID '{WIFI_SSID}'")
            info(f"    - Evil Crow RF V2 not powered on")
            info(f"    - IP address conflict on your network")
    except socket.timeout:
        err(f"TCP connection timed out after 5 seconds.")
        info(f"  Ensure you are connected to WiFi '{WIFI_SSID}' and device is powered.")
    except Exception as e:
        err(f"TCP check failed: {e}")

    info("")
    info(f"Step 2: HTTP GET {WEB_BASE} …")
    if not tcp_ok:
        warn("Skipping HTTP check since TCP connection failed.")
        info(f"To connect manually:")
        info(f"  1. Open WiFi settings on your computer")
        info(f"  2. Connect to SSID: {WIFI_SSID}")
        info(f"  3. Password: {WIFI_PASS}")
        info(f"  4. Open browser: {WEB_BASE}")
        return

    resp = _web_get("/", timeout=10)
    if resp and resp.status_code == 200:
        ok(f"HTTP {resp.status_code} — Evil Crow RF web interface is UP!")
        info(f"  Content-Type: {resp.headers.get('Content-Type', 'unknown')}")
        info(f"  Content-Length: {len(resp.content)} bytes")
        info(f"  Open in browser: {WEB_BASE}")
    elif resp:
        warn(f"HTTP {resp.status_code} — web interface responded but returned non-200.")
        info(f"  Try opening {WEB_BASE} in a browser directly.")
    else:
        warn("HTTP request to web interface failed.")

    info("")
    info(f"Step 3: API status check at {WEB_BASE}/api/status …")
    resp = _web_get("/api/status", timeout=10)
    if resp and resp.status_code == 200:
        ok("API /api/status is reachable!")
    elif resp:
        info(f"  /api/status returned HTTP {resp.status_code}")
        info("  The API endpoint may not be available in all firmware versions.")
    else:
        info("  /api/status not reachable.")

    ok("WiFi connection check complete.")


def op_check_firmware():
    """Check firmware version via web API, fall back to USB serial."""
    heading("Check Firmware Version")
    info("Attempting to retrieve firmware version information…")
    info("  Method 1: Web API (preferred) — GET http://192.168.4.1/api/status")
    info("  Method 2: USB serial fallback — connect at 115200 baud")
    info("")

    # Method 1: Web API
    info("Method 1: Querying web API for firmware version…")
    resp = _web_get("/api/status", timeout=10)
    if resp and resp.status_code == 200:
        ok("Web API reachable. Parsing firmware info…")
        try:
            import json
            data = resp.json()
            # Look for common firmware version fields
            for key in ("version", "firmware", "fw_version", "Version", "firmware_version"):
                if key in data:
                    ok(f"  Firmware version: {data[key]}")
                    break
            else:
                info("  No 'version' field found in API response.")
                info(f"  Full response: {data}")
        except Exception:
            info(f"  API response (raw): {resp.text[:500]}")
    else:
        warn("Web API not reachable. Trying USB serial fallback…")
        info("")
        info("Method 2: USB serial at 115200 baud…")
        port = find_serial_port_by_vidpid(VID_PIDS)
        if not port:
            warn("USB serial port not found either.")
            info("  Ensure the device is connected via USB and CP2102 driver is loaded.")
            info("  Linux: sudo modprobe cp210x && dmesg | tail -10")
        else:
            ok(f"USB serial port found: {port}")
            info(f"  Opening {port} at {BAUD_RATE} baud to read serial output…")
            try:
                import serial
                with serial.Serial(port, BAUD_RATE, timeout=5) as ser:
                    time.sleep(0.5)
                    ser.reset_input_buffer()
                    # Send newline to trigger any debug output
                    ser.write(b"\r\n")
                    time.sleep(1)
                    raw = b""
                    deadline = time.time() + 5
                    while time.time() < deadline:
                        if ser.in_waiting:
                            raw += ser.read(ser.in_waiting)
                        time.sleep(0.1)
                output = raw.decode("utf-8", errors="replace").strip()
                if output:
                    info("  Serial output received:")
                    for line in output.splitlines():
                        info(f"    {line}")
                else:
                    warn("  No serial output received.")
                    info("  The device may be running in WiFi mode with no serial debug output.")
            except Exception as e:
                err(f"  Serial read failed: {e}")
                info("  Check: dialout group membership and port permissions.")

    info("")
    info("Checking latest release on GitHub…")
    if HAS_REQUESTS:
        try:
            resp = requests.get(GITHUB_API, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                tag = data.get("tag_name", "unknown")
                name = data.get("name", "unknown")
                pub = data.get("published_at", "unknown")
                ok(f"Latest GitHub release: {tag} ({name})")
                info(f"  Published: {pub}")
                info(f"  Release URL: {data.get('html_url', GITHUB_REPO)}")
                assets = data.get("assets", [])
                if assets:
                    info(f"  Release assets ({len(assets)}):")
                    for a in assets:
                        info(f"    {a['name']} ({a.get('size', '?')} bytes)")
            else:
                warn(f"GitHub API returned HTTP {resp.status_code}")
        except Exception as e:
            warn(f"Could not reach GitHub API: {e}")
            info(f"  Check manually: {GITHUB_REPO}/releases")
    else:
        warn("'requests' not available. Cannot check GitHub release.")
        info(f"  Check manually: {GITHUB_REPO}/releases")

    ok("Firmware version check complete.")


def op_update_firmware():
    """Download firmware from GitHub and flash via esptool."""
    heading("Update Firmware")
    info("Evil Crow RF V2 firmware flashing via esptool (USB, ESP32).")
    info("Project firmware source: https://github.com/joelsernamoreno/EvilCrowRF-V2")
    info("")
    info("Firmware flashing requires:")
    info("  1. USB connection (CP2102 VID:PID 10C4:EA60)")
    info("  2. esptool installed")
    info("  3. Device in download/flash mode")
    info("")
    info("Entering ESP32 download mode:")
    info("  Method 1 (auto): esptool tries auto-reset via DTR/RTS lines")
    info("  Method 2 (manual): Hold BOOT/FLASH button, press RESET, release BOOT")
    info("  Method 3 (manual): Hold BOOT while plugging in USB")
    info("")

    # Check esptool
    info("Checking for 'esptool' or 'esptool.py' in PATH…")
    esptool_cmd = None
    for candidate in ["esptool.py", "esptool"]:
        if run_output(f"which {candidate} 2>/dev/null"):
            esptool_cmd = candidate
            ok(f"Found esptool: {candidate}")
            break

    if not esptool_cmd:
        warn("esptool not found. Attempting installation…")
        os_flavor = get_os_flavor()
        if os_flavor in ("kali", "debian", "ubuntu", "linux"):
            info("Trying: apt-get install esptool")
            ensure_apt_packages(["esptool"])
        elif os_flavor == "macos":
            info("Trying: brew install esptool")
            ensure_brew_packages(["esptool"])
        # Also try pip
        info("Trying: pip install esptool")
        ensure_pip_packages([("esptool", "esptool")])
        for candidate in ["esptool.py", "esptool"]:
            if run_output(f"which {candidate} 2>/dev/null"):
                esptool_cmd = candidate
                ok(f"Found esptool after install: {candidate}")
                break
        if not esptool_cmd:
            esptool_cmd = f"{sys.executable} -m esptool"
            info(f"Using Python module: {esptool_cmd}")

    # Find USB port
    info("")
    info("Looking for Evil Crow RF serial port…")
    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        warn("USB serial port not detected automatically.")
        info("  Check: lsusb | grep '10c4:ea60'")
        info("  Check: dmesg | tail -20 (look for cp210x or ttyUSB)")
        port = prompt("Enter serial port manually (e.g. /dev/ttyUSB0)", "/dev/ttyUSB0")
        if not port:
            err("No port specified. Cannot flash firmware.")
            return
    else:
        ok(f"Serial port: {port}")

    # Firmware file
    info("")
    info("Specify the firmware .bin file to flash.")
    info("  Download from: https://github.com/joelsernamoreno/EvilCrowRF-V2/releases")
    info("  Look for a file named 'firmware.bin' or 'EvilCrowRF*.bin'")

    fw_path_str = prompt("Path to firmware .bin file")
    if not fw_path_str:
        warn("No firmware file specified. Aborting.")
        return
    fw_path = Path(fw_path_str)
    if not fw_path.exists():
        err(f"File not found: {fw_path}")
        return
    if fw_path.suffix.lower() not in (".bin",):
        warn(f"File does not have .bin extension: {fw_path.name}")
        if not confirm("Continue anyway?", default=False):
            return

    info("")
    warn("Flashing firmware will OVERWRITE the current firmware on the device.")
    info(f"  Port    : {port}")
    info(f"  Firmware: {fw_path.name} ({fw_path.stat().st_size} bytes)")
    info(f"  Chip    : ESP32")
    info(f"  Address : 0x0 (merged binary — bootloader + partitions + app)")
    if not confirm("Proceed with firmware flash?", default=False):
        info("Flash cancelled.")
        return

    info("")
    info("Starting firmware flash via esptool…")
    info("Troubleshooting esptool failures:")
    info("  'Failed to connect' → hold BOOT button while pressing RESET, then release BOOT")
    info("  'Wrong boot mode'   → device did not enter download mode; retry boot sequence")
    info("  'MD5 mismatch'      → USB cable quality issue; try different cable or port")
    info("  'Chip not detected' → check USB connection and port permissions")
    info("  'Permission denied' → check dialout group membership")

    # Build esptool command
    if " " in esptool_cmd:
        # python -m esptool form
        cmd = esptool_cmd.split() + [
            "--chip", "esp32",
            "--port", port,
            "--baud", "460800",
            "--before", "default_reset",
            "--after", "hard_reset",
            "write_flash",
            "--flash_size", "detect",
            "0x0", str(fw_path),
        ]
    else:
        cmd = [
            esptool_cmd,
            "--chip", "esp32",
            "--port", port,
            "--baud", "460800",
            "--before", "default_reset",
            "--after", "hard_reset",
            "write_flash",
            "--flash_size", "detect",
            "0x0", str(fw_path),
        ]

    info(f"Command: {' '.join(cmd)}")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=180)
        if rc == 0:
            ok("Firmware flashed successfully!")
            info("The Evil Crow RF V2 will reboot and start the new firmware.")
            info(f"  Reconnect to WiFi SSID '{WIFI_SSID}' after device reboots.")
            info(f"  Access web interface at: {WEB_BASE}")
        else:
            warn(f"esptool exited with code {rc}")
            info("Flash may have failed. Check the output above for error details.")
    except Exception as e:
        err(f"Firmware flash failed: {e}")
        info("Ensure esptool is correctly installed and the device is in download mode.")


def op_rf_scan():
    """Start RF scan via web API."""
    heading("RF Scan (Sub-GHz)")
    info("Evil Crow RF V2 CC1101 sub-GHz RF scan via web API.")
    info("  CC1101 frequency ranges:")
    info("    300–348 MHz — EU/US low-band (various remotes)")
    info("    387–464 MHz — 433.92 MHz ISM (most common garage/remote band)")
    info("    779–928 MHz — 868 MHz (EU) and 915 MHz (US) ISM bands")
    info("")
    info("Ensure you are connected to WiFi SSID '{}' before scanning.".format(WIFI_SSID))
    info("")

    if not detect_device_wifi():
        warn(f"Cannot reach {WEB_HOST}. Not connected to '{WIFI_SSID}' WiFi?")
        info(f"  Connect to SSID: {WIFI_SSID}")
        info(f"  Password: {WIFI_PASS}")
        info(f"  Then re-run this option.")
        return

    info("Sending scan request to /api/scan…")
    resp = _web_get("/api/scan", timeout=30)
    if resp and resp.status_code == 200:
        ok("RF scan started successfully.")
        info(f"  View scan results at: {WEB_BASE}")
        try:
            import json
            data = resp.json()
            info("  Scan response:")
            for k, v in data.items():
                info(f"    {k}: {v}")
        except Exception:
            info(f"  Response: {resp.text[:500]}")
    elif resp:
        warn(f"Scan endpoint returned HTTP {resp.status_code}")
        info(f"  Try accessing {WEB_BASE} in a browser for the scan interface.")
    else:
        err("Scan request failed. Check WiFi connection.")

    ok("RF scan operation complete.")


def op_signal_replay():
    """Replay captured signal via web API."""
    heading("Signal Replay")
    info("Replay a previously captured RF signal via the Evil Crow RF V2 web API.")
    info("  POST /api/replay — send a captured signal for replay")
    info("")
    warn("Signal replay sends RF transmissions on the configured frequency.")
    warn("Ensure you have authorization to transmit on the target frequency.")
    warn("Comply with local RF transmission regulations.")
    info("")

    if not detect_device_wifi():
        warn(f"Cannot reach {WEB_HOST}. Not connected to '{WIFI_SSID}' WiFi?")
        info(f"  Connect to SSID: {WIFI_SSID} (password: {WIFI_PASS})")
        return

    info("The web interface provides the full replay workflow:")
    info(f"  1. Open {WEB_BASE} in your browser")
    info("  2. Capture a signal using the CC1101 receive function")
    info("  3. Select the captured signal for replay")
    info("  4. Click 'Replay' to retransmit")
    info("")
    info("For API-based replay, enter the signal data to replay.")
    signal_data = prompt("Signal data to replay (hex, leave blank to skip API replay)")
    if not signal_data:
        info("No signal data entered. Use the web interface for replay.")
        info(f"  Web interface: {WEB_BASE}")
        return

    info(f"Sending replay request with signal data: {signal_data[:40]}…")
    payload = {"signal": signal_data}
    resp = _web_post("/api/replay", payload, timeout=30)
    if resp and resp.status_code == 200:
        ok("Replay request sent successfully.")
        try:
            import json
            data = resp.json()
            info(f"  API response: {data}")
        except Exception:
            info(f"  Response: {resp.text[:200]}")
    elif resp:
        warn(f"Replay API returned HTTP {resp.status_code}")
        info(f"  Use the web interface for reliable replay: {WEB_BASE}")
    else:
        err("Replay request failed.")

    ok("Signal replay operation complete.")


def op_web_interface_instructions():
    """Show detailed instructions for using the Evil Crow RF V2 web interface."""
    heading("Web Interface Instructions")
    info("The Evil Crow RF V2 primary management interface is a web application.")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("CONNECTION SETUP")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info(f"  1. Power on the Evil Crow RF V2 (via USB)")
    info(f"  2. On your computer/phone, connect to WiFi:")
    info(f"       SSID:     {WIFI_SSID}")
    info(f"       Password: {WIFI_PASS}")
    info(f"  3. Open web browser and navigate to: {WEB_BASE}")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("WEB INTERFACE FEATURES")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("  CC1101 Sub-GHz (300–928 MHz):")
    info("    - Raw signal capture and display")
    info("    - Signal replay (retransmit captured signals)")
    info("    - Rolling code brute force (garage doors, car key fobs)")
    info("    - Frequency scanner")
    info("    - Common targets: 315 MHz, 433.92 MHz, 868 MHz, 915 MHz")
    info("    - Protocols: OOK, FSK, ASK")
    info("")
    info("  nRF24L01+ (2.4 GHz):")
    info("    - MouseJack attack (inject clicks/keystrokes via 2.4 GHz mouse dongle)")
    info("    - KeyJack attack (inject keystrokes via 2.4 GHz keyboard dongle)")
    info("    - Channel scanner")
    info("    - Target: Microsoft, Logitech wireless mice and keyboards")
    info("")
    info("  Configuration:")
    info("    - Frequency, modulation, bandwidth, data rate, sync word")
    info("    - Save/load signal profiles")
    info("    - OTA firmware update interface")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("API ENDPOINTS (for programmatic control)")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info(f"  GET  {WEB_BASE}/api/status  — device status and config")
    info(f"  GET  {WEB_BASE}/api/scan    — start sub-GHz scan")
    info(f"  POST {WEB_BASE}/api/replay  — replay captured signal (JSON body)")
    info("")
    info("  Example with curl:")
    info(f"    curl http://{WEB_HOST}/api/status")
    info(f"    curl http://{WEB_HOST}/api/scan")
    info(f"    curl -X POST http://{WEB_HOST}/api/replay -H 'Content-Type: application/json' -d '{{\"signal\":\"...\"}}'")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("TROUBLESHOOTING WEB INTERFACE")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info(f"  'Site not reachable' → Check WiFi is connected to '{WIFI_SSID}'")
    info(f"  'No WiFi AP visible' → Device not powered on or in USB flash mode")
    info(f"  'Wrong password'     → Default password is '{WIFI_PASS}'")
    info(f"  'Blank web page'     → Try hard refresh (Ctrl+Shift+R) in browser")
    info(f"  'API returns 404'    → Firmware version may not support that endpoint")
    info("")
    info(f"  Project documentation: {GITHUB_REPO}")
    ok("Web interface instructions complete.")


# ── Firmware Version Check ────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("Attempting to read Evil Crow RF V2 firmware version...")
    current = None

    # Try WiFi API first
    try:
        import requests as _req
        resp = _req.get("http://192.168.4.1/api/info", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            current = data.get("firmware", data.get("version", data.get("fw_version")))
    except Exception:
        pass

    if not current:
        # Try /api/status
        try:
            import requests as _req
            resp = _req.get("http://192.168.4.1/api/status", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                current = data.get("firmware", data.get("version"))
        except Exception:
            pass

    if current:
        ok(f"Evil Crow RF V2 firmware version: {current}")
    else:
        info("Could not determine firmware version via WiFi API.")
        info("  Ensure you are connected to EvilCrowRF WiFi (192.168.4.1)")

    info("Checking latest Evil Crow RF V2 firmware on GitHub...")
    latest, url = check_latest_github_release("joelsernamoreno", "EvilCrowRF-V2")
    if latest:
        if current:
            announce_firmware_update(TOOL_NAME, current, latest.lstrip("v"), url)
        else:
            info(f"  Latest release: {latest}  ({url})")
            info("  Download and flash via 'Update Firmware' menu option.")
    else:
        warn("Could not check GitHub.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    os_flavor = get_os_flavor()
    info(f"Detected OS: {os_flavor}")
    info("")

    # Install system tools
    info("Checking required system tools…")
    if os_flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking apt packages: python3-serial…")
        ensure_apt_packages(["python3-serial"])
        info("Note: esptool may be available as 'esptool' in apt on newer Kali/Debian.")
        ensure_apt_packages(["esptool"])
    elif os_flavor == "macos":
        info("Checking brew packages: esptool…")
        ensure_brew_packages(["esptool"])

    # pip packages
    info("Checking Python packages: pyserial, requests…")
    ensure_pip_packages([
        ("serial", "pyserial"),
        ("requests", "requests"),
    ])

    # Reload requests module if it was just installed
    global HAS_REQUESTS
    try:
        import requests as _req
        HAS_REQUESTS = True
    except ImportError:
        HAS_REQUESTS = False

    # udev rules (Linux)
    if os_flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking udev rules for CP2102 (10C4:EA60)…")
        _check_udev_rules()

    info("")
    info("Detecting Evil Crow RF V2…")
    info("  Checking USB VID:PID: 10C4:EA60 (CP2102), 303A:0002 (ESP32-S2)")
    info("  Checking WiFi: TCP connect to 192.168.4.1:80")
    info("")
    info("If using WiFi: connect your computer to SSID 'EvilCrowRF' before continuing.")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        warn("Evil Crow RF V2 not detected via USB or WiFi.")
        info("You can still view web interface instructions and firmware info.")
        if not confirm("Continue without detected device?", default=True):
            err("Exiting.")
            sys.exit(1)

    if found:
        ok("Evil Crow RF V2 detected.")

    check_firmware_version()

    MENU_OPTIONS = [
        "Device Info",
        "Check WiFi Connection",
        "Check Firmware Version",
        "FIRMWARE - Update Firmware (esptool via USB)",
        "RF Scan (sub-GHz via web API)",
        "Signal Replay (via web API)",
        "Web Interface Instructions",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Evil Crow RF V2 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_check_wifi_connection()
        elif choice == 2:
            op_check_firmware()
        elif choice == 3:
            op_update_firmware()
        elif choice == 4:
            op_rf_scan()
        elif choice == 5:
            op_signal_replay()
        elif choice == 6:
            op_web_interface_instructions()
        elif choice == 7:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
