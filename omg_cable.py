#!/usr/bin/env python3
"""
O.MG Cable / Elite Tool Manager
Handles detection, payload deployment, and management of the O.MG Cable
USB HID implant device by Hak5. The O.MG Cable looks like a standard USB
cable but contains a hidden WiFi-enabled microcontroller that executes
DuckyScript payloads delivered over WiFi.

Device modes:
  AP mode  — creates a WiFi AP named "O.MG-XXXX"; device IP is 192.168.4.1
  STA mode — joins an existing WiFi network; IP assigned by DHCP

USB presence (when emulating keyboard):
  VID:PID 05AC:8102  (spoofs Apple Keyboard)

Web interface: http://<device-ip>/
  /info            GET  — JSON with version, config
  /list            GET  — JSON list of payloads
  /upload          POST — upload a payload file
  /execute         GET  — execute a payload (?payload=name)
  /update          POST — firmware update (requires .bin)

Firmware updates require a hak5.org account — cannot be automated.
Payload reference: https://github.com/hak5/omg-payloads

Usage:
    python3 omg_cable.py
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
import urllib.parse
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

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "O.MG Cable / Elite"
DESCRIPTION = "WiFi-enabled USB HID implant cable by Hak5"

# VID:PID when spoofing an Apple Keyboard (deployed / attack mode)
VID_PIDS = [
    (0x05AC, 0x8102),   # Apple Keyboard spoof
]

DEFAULT_AP_IP   = "192.168.4.1"
DEFAULT_TIMEOUT = 5  # seconds for HTTP requests

GITHUB_OWNER = "hak5"
GITHUB_REPO  = "omg-payloads"

CONNECT_INSTRUCTIONS = (
    "O.MG Cable not detected.\n\n"
    "  1. Plug the O.MG Cable into a USB port on this machine (or a power source).\n\n"
    "  2. Connect to the O.MG WiFi access point:\n"
    "       WiFi SSID: O.MG-XXXX  (XXXX = last 4 of MAC)\n"
    "       Default password: 'opensesame'\n\n"
    "  3. Device IP in AP mode: 192.168.4.1\n"
    "       In STA mode: check your router DHCP table.\n\n"
    "  4. If using STA mode, provide the device IP when prompted.\n\n"
    "  5. USB HID VID:PID when active: 05AC:8102 (Apple Keyboard spoof)\n\n"
    "  6. Firmware / payload docs: https://github.com/hak5/omg-payloads\n"
    "     Web UI: http://192.168.4.1"
)

UDEV_RULES_CONTENT = """\
# O.MG Cable udev rules
# Apple Keyboard spoof (VID:PID 05AC:8102)
SUBSYSTEM=="usb", ATTRS{idVendor}=="05ac", ATTRS{idProduct}=="8102", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="05ac", ATTRS{idProduct}=="8102", MODE="0666", GROUP="plugdev"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-omg-cable.rules"


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _http_get(base_ip: str, path: str, timeout: int = DEFAULT_TIMEOUT):
    """
    Perform an HTTP GET to http://<base_ip><path>.
    Returns (status_code, body_text) or raises on network error.
    """
    url = f"http://{base_ip}{path}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        raise ConnectionError(f"Cannot reach {url}: {e.reason}") from e


def _http_post_file(base_ip: str, path: str, field: str, filename: str,
                    data: bytes, timeout: int = 30):
    """
    Multipart POST a file to http://<base_ip><path>.
    Returns (status_code, body_text).
    """
    import email.mime.multipart
    boundary = "----QuiverBoundary7H3x9"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

    url = f"http://{base_ip}{path}"
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        raise ConnectionError(f"POST failed to {url}: {e.reason}") from e


# ── Detection ─────────────────────────────────────────────────────────────────

def _probe_device(ip: str) -> dict | None:
    """
    Try GET /info on the device at the given IP.
    Returns parsed JSON dict on success, None on failure.
    """
    try:
        status, body = _http_get(ip, "/info")
        if status == 200:
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                return {"raw": body}
        else:
            return None
    except ConnectionError:
        return None
    except Exception:
        return None


def detect_device() -> bool:
    """Quick probe of default AP IP — used by web_detect_loop."""
    return _probe_device(DEFAULT_AP_IP) is not None


def _resolve_device_ip() -> str | None:
    """
    Try default IP first; if that fails, ask the user for the IP.
    Returns the reachable IP string or None.
    """
    info(f"Probing default AP address ({DEFAULT_AP_IP})…")
    if _probe_device(DEFAULT_AP_IP):
        ok(f"Device responded at {DEFAULT_AP_IP}")
        return DEFAULT_AP_IP

    warn(f"No response from {DEFAULT_AP_IP}.")
    info("The device may be in STA mode (joined an existing WiFi network).")
    custom_ip = prompt("Enter device IP address (leave blank to abort)", default="")
    if not custom_ip:
        return None
    if _probe_device(custom_ip):
        ok(f"Device responded at {custom_ip}")
        return custom_ip
    err(f"No response from {custom_ip}. Check the IP and WiFi connection.")
    return None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    flavor = get_os_flavor()
    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for O.MG Cable HID device…")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the O.MG Cable to apply new permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual fix: sudo tee {UDEV_RULES_PATH} << 'EOF'")
        info(UDEV_RULES_CONTENT)
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Firmware version check ────────────────────────────────────────────────────

def check_firmware_version(ip: str):
    heading("Firmware Version Check")
    info("Querying device /info endpoint for firmware version…")
    try:
        data = _probe_device(ip)
        if not data:
            err("Could not retrieve device info. Is the device reachable?")
            return

        current = None
        # The /info endpoint may return version under various keys
        for key in ("version", "fw_version", "firmware", "ver"):
            if key in data:
                current = str(data[key]).lstrip("v")
                break

        if current:
            ok(f"Device firmware version: {current}")
        else:
            warn("Version field not found in /info response.")
            info(f"Raw /info response: {json.dumps(data, indent=2)[:500]}")
            info("Check manually at: http://{ip}/info")

        info("Checking latest O.MG payload scripts on GitHub (hak5/omg-payloads)…")
        latest_tag, release_url = check_latest_github_release(GITHUB_OWNER, GITHUB_REPO)
        if latest_tag:
            info(f"Latest omg-payloads release tag: {latest_tag}")
            info(f"Release URL: {release_url}")
        else:
            warn("Could not retrieve GitHub release info.")

        info("")
        info("NOTE: O.MG Cable firmware updates require a hak5.org account.")
        info("  Firmware cannot be downloaded or applied automatically.")
        info("  See 'Firmware Update Walkthrough' option in the menu.")

    except Exception as e:
        err(f"Firmware version check error: {e}")


# ── Operations ────────────────────────────────────────────────────────────────

def op_detect_and_info(ip: str):
    heading("Detect Device & Check Version")
    info(f"Connecting to device at {ip}…")
    try:
        status, body = _http_get(ip, "/info")
        if status == 200:
            ok("Device is online and responding.")
            try:
                data = json.loads(body)
                info("Device info:")
                for k, v in data.items():
                    info(f"  {k}: {v}")
            except json.JSONDecodeError:
                info(f"Raw response: {body[:800]}")
        else:
            err(f"Device returned HTTP {status}")
            info(f"Body: {body[:400]}")
    except ConnectionError as e:
        err(str(e))
        info("Troubleshooting:")
        info("  - Ensure you are connected to the O.MG WiFi AP (SSID: O.MG-XXXX)")
        info("  - Default AP IP: 192.168.4.1  |  Default password: opensesame")
        info("  - In STA mode: check router for assigned DHCP IP")
    except Exception as e:
        err(f"Unexpected error during device detection: {e}")


def op_open_web_interface(ip: str):
    heading("Open Web Interface")
    url = f"http://{ip}"
    info(f"O.MG Cable web UI: {url}")
    info("Open this URL in your browser while connected to the device WiFi.")
    info("")
    info("Web interface features:")
    info("  /         — Main dashboard")
    info("  /info     — Device info JSON")
    info("  /list     — List uploaded payloads")
    info("  /update   — Firmware update page (requires hak5.org account)")
    info("")
    flavor = get_os_flavor()
    try:
        if flavor == "macos":
            run(f"open {url}")
            ok(f"Opened {url} in default browser.")
        elif flavor in ("kali", "debian", "ubuntu", "linux"):
            run(f"xdg-open {url} 2>/dev/null || sensible-browser {url} 2>/dev/null")
            ok(f"Attempted to open {url} in browser.")
        else:
            info(f"Navigate manually to: {url}")
    except Exception as e:
        warn(f"Could not auto-open browser: {e}")
        info(f"Open manually: {url}")


def op_deploy_payload(ip: str):
    heading("Deploy DuckyScript Payload")
    info("Upload a DuckyScript payload file to the O.MG Cable via HTTP POST.")
    info("The device stores payloads in its internal flash filesystem.")
    info("")
    info("DuckyScript 1.0 is supported by O.MG Cable.")
    info("Payload examples: https://github.com/hak5/omg-payloads/tree/master/payloads")
    info("")
    payload_path = prompt("Path to DuckyScript payload file (.txt or .duck)")
    if not payload_path:
        warn("No file path provided. Aborting.")
        return
    p = Path(payload_path)
    if not p.exists():
        err(f"File not found: {p}")
        info("Tip: use an absolute path, e.g. /home/user/payload.txt")
        return
    remote_name = prompt(f"Remote filename on device (default: {p.name})", default=p.name)
    if not remote_name:
        remote_name = p.name

    info(f"Uploading '{p.name}' as '{remote_name}' to device at {ip}…")
    try:
        data = p.read_bytes()
        status, body = _http_post_file(ip, "/upload", "payload", remote_name, data)
        if status in (200, 201):
            ok(f"Payload '{remote_name}' uploaded successfully.")
            info(f"Execute it with option 5 (Execute Payload), name: {remote_name}")
        else:
            err(f"Upload failed — HTTP {status}")
            info(f"Response: {body[:400]}")
    except ConnectionError as e:
        err(f"Upload error: {e}")
    except Exception as e:
        err(f"Unexpected upload error: {e}")


def op_list_payloads(ip: str):
    heading("List Payloads on Device")
    info(f"Requesting payload list from {ip}/list…")
    try:
        status, body = _http_get(ip, "/list")
        if status == 200:
            try:
                data = json.loads(body)
                if isinstance(data, list):
                    if data:
                        ok(f"Found {len(data)} payload(s):")
                        for i, item in enumerate(data, 1):
                            info(f"  {i}. {item}")
                    else:
                        info("No payloads currently stored on device.")
                else:
                    info(f"Response: {json.dumps(data, indent=2)[:800]}")
            except json.JSONDecodeError:
                info(f"Raw response: {body[:800]}")
        else:
            err(f"HTTP {status} from /list")
            info(f"Response: {body[:400]}")
    except ConnectionError as e:
        err(f"Cannot reach device: {e}")
    except Exception as e:
        err(f"List payloads error: {e}")


def op_execute_payload(ip: str):
    heading("Execute Payload Remotely")
    info("Trigger execution of a stored payload by name via HTTP GET /execute.")
    info("WARNING: This will immediately execute the DuckyScript payload on the target!")
    info("")
    info("Tip: Use 'List Payloads' (option 4) to see available payload names first.")
    payload_name = prompt("Payload name to execute")
    if not payload_name:
        warn("No payload name provided. Aborting.")
        return
    if not confirm(f"Execute payload '{payload_name}' on connected HID target?", default=False):
        info("Cancelled.")
        return
    encoded = urllib.parse.quote(payload_name)
    info(f"Sending execute command for '{payload_name}'…")
    try:
        status, body = _http_get(ip, f"/execute?payload={encoded}")
        if status == 200:
            ok(f"Payload '{payload_name}' execution triggered.")
            info(f"Response: {body[:400]}")
        else:
            err(f"Execute returned HTTP {status}")
            info(f"Response: {body[:400]}")
    except ConnectionError as e:
        err(f"Cannot reach device: {e}")
    except Exception as e:
        err(f"Execute payload error: {e}")


def op_device_info_dump(ip: str):
    heading("Device Info Dump")
    info(f"Requesting full device info from {ip}/info…")
    try:
        status, body = _http_get(ip, "/info")
        if status == 200:
            ok("Device info retrieved:")
            try:
                data = json.loads(body)
                info(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                info(f"Raw response:\n{body[:2000]}")
        else:
            err(f"HTTP {status} from /info")
            info(f"Response: {body[:400]}")
    except ConnectionError as e:
        err(f"Cannot reach device: {e}")
    except Exception as e:
        err(f"Device info dump error: {e}")


def op_factory_reset_warning(ip: str):
    heading("Factory Reset")
    warn("WARNING: Factory reset will erase ALL payloads and settings on the device!")
    warn("This action cannot be undone.")
    info("")
    info("Factory reset procedure for O.MG Cable:")
    info("  1. Connect to the O.MG WiFi AP (SSID: O.MG-XXXX)")
    info("  2. Navigate to http://192.168.4.1 in your browser")
    info("  3. Go to Settings → Factory Reset")
    info("  4. Confirm the reset in the web UI")
    info("")
    info("Alternative method (hardware reset):")
    info("  1. While the cable is plugged in, hold the setup button (if present)")
    info("  2. Refer to the O.MG Cable documentation for your specific model")
    info("  3. Cable Elite models may have different reset procedures")
    info("")
    info("After reset:")
    info("  - Default WiFi SSID:     O.MG-XXXX")
    info("  - Default WiFi password: opensesame")
    info("  - Default IP (AP mode):  192.168.4.1")
    if not confirm("Do you want to attempt a factory reset via web API?", default=False):
        info("Factory reset aborted. No changes made.")
        return
    info("Attempting factory reset via web API…")
    try:
        status, body = _http_get(ip, "/reset")
        if status in (200, 204):
            ok("Factory reset command sent.")
            info("Device may be rebooting. Reconnect to O.MG WiFi AP in 30 seconds.")
        else:
            warn(f"Unexpected HTTP {status} from /reset")
            info(f"Response: {body[:400]}")
            info("Perform the reset manually via the web UI as described above.")
    except ConnectionError as e:
        warn(f"Could not reach reset endpoint: {e}")
        info("Perform the reset manually via the web UI as described above.")
    except Exception as e:
        err(f"Factory reset error: {e}")


def op_firmware_update_walkthrough(ip: str):
    heading("Firmware Update Walkthrough")
    warn("O.MG Cable firmware CANNOT be downloaded or applied automatically.")
    warn("Firmware is only available to registered hak5.org users.")
    info("")
    info("Step-by-step firmware update procedure:")
    info("")
    info("  Step 1 — Get firmware:")
    info("    1a. Go to https://hak5.org/downloads")
    info("    1b. Log in with your hak5.org account (purchase required)")
    info("    1c. Find 'O.MG Cable' firmware under your registered products")
    info("    1d. Download the latest .bin firmware file")
    info("")
    info("  Step 2 — Connect to device:")
    info(f"    2a. Ensure you are connected to the O.MG WiFi AP")
    info(f"    2b. Device web UI: http://{ip}")
    info("")
    info("  Step 3 — Upload firmware:")
    info("    3a. In the web UI, navigate to Settings → Firmware Update")
    info("    3b. Click 'Choose File' and select the .bin file you downloaded")
    info("    3c. Click 'Upload' and wait for the update to complete (~60 seconds)")
    info("    3d. Do NOT unplug the cable during the update")
    info("")
    info("  Step 4 — Verify:")
    info("    4a. Reconnect to the O.MG WiFi AP after the device reboots")
    info(f"    4b. Check /info endpoint: http://{ip}/info")
    info("    4c. Confirm the new version is shown")
    info("")
    info("Payload repository (DuckyScripts for O.MG):")
    info("  https://github.com/hak5/omg-payloads")
    pause("Press ENTER when you have read the update instructions…")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    flavor = get_os_flavor()
    info("O.MG Cable communicates over HTTP/WiFi — no special host-side packages required.")
    info("Checking for optional utilities…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["curl", "wget"])
    elif flavor == "macos":
        info("  macOS — curl is built-in, no additional packages needed.")
    ensure_pip_packages([("requests", "requests")])

    # ── Linux udev rules ──────────────────────────────────────────────────────
    _check_udev_rules()

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    info("The O.MG Cable communicates over WiFi, not a serial port.")
    info("Connect to the O.MG Cable WiFi AP (SSID: O.MG-XXXX) first.")
    info(f"Default AP IP: {DEFAULT_AP_IP}  |  Default password: opensesame")
    info("")

    # In web mode, use the standard detection loop
    if WEB_MODE:
        found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=300)
        if not found:
            err("O.MG Cable not detected within timeout. Exiting.")
            sys.exit(1)
        device_ip = DEFAULT_AP_IP
    else:
        device_ip = _resolve_device_ip()
        if not device_ip:
            err("Could not reach O.MG Cable. Ensure WiFi is connected and try again.")
            sys.exit(1)

    ok(f"O.MG Cable detected at {device_ip}")
    check_firmware_version(device_ip)

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Detect Device & Check Version",
        "Open Web Interface (print URL)",
        "Deploy DuckyScript Payload (upload via HTTP POST)",
        "List Payloads on Device",
        "Execute Payload Remotely",
        "Device Info Dump",
        "Factory Reset (warning + instructions)",
        "Firmware Update Walkthrough (manual — requires hak5.org)",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_detect_and_info(device_ip)
        elif choice == 1:
            op_open_web_interface(device_ip)
        elif choice == 2:
            op_deploy_payload(device_ip)
        elif choice == 3:
            op_list_payloads(device_ip)
        elif choice == 4:
            op_execute_payload(device_ip)
        elif choice == 5:
            op_device_info_dump(device_ip)
        elif choice == 6:
            op_factory_reset_warning(device_ip)
        elif choice == 7:
            op_firmware_update_walkthrough(device_ip)
        elif choice == 8:
            info("Goodbye.")
            break

        # Allow the user to switch device IP between operations
        new_ip = _resolve_device_ip() if not WEB_MODE else device_ip
        if new_ip and new_ip != device_ip:
            device_ip = new_ip
            info(f"Device IP updated to {device_ip}")


if __name__ == "__main__":
    main()
