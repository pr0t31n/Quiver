#!/usr/bin/env python3
"""
WiFi Duck Tool Manager
Controls the WiFi Duck (ATmega32U4 + ESP8266) via WebSocket CLI at ws://192.168.4.1/ws.
Supports payload upload, execution, file management, memory stats, and OTA firmware updates.

Usage:
    python3 wifi_duck.py

Connection setup:
    1. Plug in the WiFi Duck (USB to target or USB power bank)
    2. On your computer, connect to the WiFi AP:
       SSID:     wifiduck
       Password: wifiduck
    3. The ESP8266 hosts a WebSocket server at ws://192.168.4.1/ws
    4. HTTP interface at http://192.168.4.1

WebSocket protocol:
    The WiFi Duck uses a simple text-based WebSocket CLI protocol.
    Commands are sent as plain text strings, responses are returned as text.
    File upload uses a chunked streaming protocol:
        1. 'create <filename>'   — creates the file on the ESP8266 SPIFFS
        2. 'stream <filename>'   — opens the file for streaming writes
        3. send raw content chunks (max ~220 bytes each, ~50ms delay between)
        4. 'close'               — finalizes the file write
    The ATmega32U4 fetches files from the ESP8266 to execute them as HID.

Available WebSocket commands:
    version    — firmware version string
    status     — current execution status (running/idle)
    mem        — SPIFFS memory usage
    ls         — list files on ESP8266 SPIFFS
    run <f>    — execute a DuckyScript file
    stop       — abort current execution
    create <f> — create a new file
    stream <f> — open file for streaming write (followed by data chunks)
    close      — finalize streaming write
    remove <f> — delete a file
    settings   — show current settings (SSID, password, layout, etc.)

Troubleshooting WiFi connection:
    - Ensure you are connected to the 'wifiduck' AP, NOT your regular WiFi
    - Check: ip route  — the 192.168.4.0/24 route should be via your WiFi interface
    - Check: ping 192.168.4.1  — should respond
    - If not responding, try: nmcli dev wifi list  to verify AP is visible
    - Some systems auto-reconnect to known networks — disable auto-reconnect temporarily

Troubleshooting WebSocket connection:
    - If ws:// connection fails, verify HTTP first: curl http://192.168.4.1
    - Firewall: sudo ufw allow out to 192.168.4.1  (if ufw is active)
    - WebSocket port is 80 (ws://host/ws, not a custom port)
"""

import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, detect_usb_libusb,
    ensure_pip_packages,
    web_detect_loop,
    require_sudo, sudo_run, sudo_output, run_streaming_sudo,
    ensure_apt_packages, ensure_brew_packages, get_os_flavor,
    get_selected_payload, verify_device_connection,
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    download_firmware, get_firmware_dir, get_github_release_asset_url,
    run_streaming,
)

# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME   = "WiFi Duck"
DESCRIPTION = "USB HID injection via WiFi WebSocket (ESP8266 + ATmega32U4)"

DUCK_IP     = "192.168.4.1"
DUCK_WS_URL = f"ws://{DUCK_IP}/ws"
DUCK_HTTP   = f"http://{DUCK_IP}"

VIDPIDS = [
    (0x2341, 0x8037),   # ATmega32U4 (Arduino Micro)
    (0x1B4F, 0x9206),   # SparkFun Pro Micro
]

CONNECT_INSTRUCTIONS = (
    "WiFi Duck not detected.\n\n"
    "  1. Power on WiFi Duck (connect USB to target or power source)\n"
    "  2. On your computer, connect to WiFi:\n"
    "     SSID: wifiduck\n"
    "     Password: wifiduck\n"
    "  3. Default IP: 192.168.4.1\n\n"
    "  Verify connectivity:\n"
    "    ping 192.168.4.1\n"
    "    curl http://192.168.4.1\n\n"
    "  Note: Your computer must be connected to the wifiduck AP\n"
    "  Note: ATmega32U4 or ESP32-S2 variant both use the same AP\n\n"
    "  If AP not visible: check WiFi Duck has power and LED is on"
)


# ── Firmware version check ────────────────────────────────────────────────────

def check_firmware_version(ws=None):
    heading("Firmware Version Check")
    info("Querying WiFi Duck firmware version…")
    current = None
    # Try HTTP GET /info or /version first
    try:
        import requests as _req
        for endpoint in [f"{DUCK_HTTP}/info", f"{DUCK_HTTP}/version"]:
            try:
                r = _req.get(endpoint, timeout=3)
                if r.status_code == 200 and r.text.strip():
                    current = r.text.strip()[:80]
                    break
            except Exception:
                pass
    except ImportError:
        pass

    # Fall back to WebSocket 'version' command if ws is available
    if not current and ws:
        try:
            resp = _ws_cmd(ws, "version")
            if resp.strip():
                current = resp.strip()
        except Exception:
            pass

    if current:
        ok(f"Firmware version: {current}")
    else:
        info("Could not auto-detect WiFi Duck firmware version.")

    latest, url = check_latest_github_release("spacehuhn", "esp8266_wifi_duck")
    if latest:
        announce_firmware_update(TOOL_NAME, current, latest, url)


# ── Detection ──────────────────────────────────────────────────────────────────

def detect_wifi_duck() -> bool:
    """Detect WiFi Duck via HTTP; fall back to USB serial VID:PID check."""
    info("Attempting HTTP detection at http://192.168.4.1 …")
    try:
        import requests
        r = requests.get(DUCK_HTTP, timeout=3)
        if r.status_code == 200:
            return True
    except Exception:
        pass
    # Secondary: USB presence (serial port)
    info("HTTP detection failed — trying USB VID:PID fallback…")
    port = find_serial_port_by_vidpid(VIDPIDS)
    return port is not None


# ── WebSocket helpers ──────────────────────────────────────────────────────────

def _ws_connect():
    """
    Open and return a WebSocket connection to the WiFi Duck.

    Troubleshooting if this fails:
      - Verify you are on the wifiduck WiFi AP
      - Test HTTP: curl http://192.168.4.1
      - Test ping: ping 192.168.4.1
      - Check firewall: sudo ufw status
      - The WebSocket endpoint is ws://192.168.4.1/ws (port 80, path /ws)
    """
    info(f"Opening WebSocket connection to {DUCK_WS_URL} …")
    import websocket
    ws = websocket.WebSocket()
    ws.connect(DUCK_WS_URL, timeout=10)
    return ws


def _ws_recv(ws, timeout: float = 2.0) -> str:
    """Receive a response with timeout; return empty string on timeout."""
    import websocket
    ws.settimeout(timeout)
    try:
        return ws.recv()
    except websocket.WebSocketTimeoutException:
        return ""
    except Exception:
        return ""


def _ws_cmd(ws, cmd: str, recv_timeout: float = 2.0) -> str:
    """Send a command and return the response."""
    ws.send(cmd)
    return _ws_recv(ws, recv_timeout)


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(ws):
    heading("Device Info")
    info("Querying version, status, and memory via WebSocket commands.")
    info("Expected: firmware version string, execution status (idle/running), SPIFFS memory usage.")
    for cmd, label in [("version", "Version"), ("status", "Status"), ("mem", "Memory")]:
        ws.send(cmd)
        resp = _ws_recv(ws)
        info(f"{label}: {resp.strip() if resp else '(no response)'}")
    info("If any field shows '(no response)', the device may be busy or the connection dropped.")


def op_list_files(ws):
    heading("List Files")
    info("Lists files stored on the ESP8266 SPIFFS filesystem.")
    info("Files are DuckyScript payloads (.txt) stored on the WiFi Duck.")
    info("Maximum SPIFFS size is typically 1-2 MB depending on firmware build.")
    ws.send("ls")
    resp = _ws_recv(ws, timeout=3.0)
    if resp.strip():
        for line in resp.strip().splitlines():
            info(line)
        ok("File list retrieved.")
    else:
        info("(no files or no response)")
        info("If no files appear, the SPIFFS may be empty — upload a payload first.")


def op_upload_payload(ws):
    heading("Upload DuckyScript Payload")
    info("Uploads a DuckyScript (.txt) payload to the WiFi Duck SPIFFS over WebSocket.")
    info("")
    info("Chunked streaming protocol:")
    info("  1. 'create <filename>'  — creates the file entry on SPIFFS")
    info("  2. 'stream <filename>'  — opens file for chunked write")
    info("  3. Send raw text chunks (220 bytes max each, ~50ms between chunks)")
    info("  4. 'close'              — finalizes the write operation")
    info("")
    info("Chunk size (220 bytes) is chosen to avoid ESP8266 WebSocket buffer overflow.")
    info("The 50ms delay between chunks prevents the ESP8266 from dropping data.")
    info("For large scripts (>5 KB), expect upload to take several seconds.")
    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        p = Path(preselected).expanduser()
    else:
        local_path = prompt("Local file path")
        if not local_path:
            warn("No path entered.")
            return
        p = Path(local_path).expanduser()
    if not p.exists():
        err(f"File not found: {p}")
        return

    remote_name = prompt("Remote filename on device", p.name)
    if not remote_name:
        remote_name = p.name

    try:
        content = p.read_text(encoding="utf-8")
    except Exception as e:
        err(f"Cannot read file: {e}")
        return

    total = len(content)
    info(f"Uploading '{remote_name}' ({total} bytes) in 220-byte chunks…")
    ws.send(f"create {remote_name}")
    time.sleep(0.1)
    ws.send(f"stream {remote_name}")
    chunk_size = 220
    chunks = range(0, total, chunk_size)
    for i, offset in enumerate(chunks):
        ws.send(content[offset:offset + chunk_size])
        time.sleep(0.05)
        if (i + 1) % 20 == 0:
            info(f"  Sent {min(offset + chunk_size, total)}/{total} bytes…")
    ws.send("close")
    time.sleep(0.2)
    ok(f"Upload complete: {remote_name}")
    info(f"Verify with 'List Files' — '{remote_name}' should appear in the listing.")


def op_run_payload(ws):
    heading("Run Payload")
    info("Instructs the WiFi Duck to execute a previously uploaded DuckyScript file.")
    info("The ATmega32U4 fetches the file from SPIFFS and injects it as USB HID keystrokes.")
    info("Ensure the WiFi Duck is plugged into the target machine's USB port.")
    info("Execution speed is controlled by the DELAY commands in the DuckyScript.")
    info("Check status with 'Device Info → Status' — shows 'running' or 'idle'.")
    filename = prompt("Filename to run")
    if not filename:
        warn("No filename entered.")
        return
    info(f"Sending: run {filename}")
    resp = _ws_cmd(ws, f"run {filename}")
    ok(f"Run command sent for '{filename}'. Response: {resp.strip() or '(none)'}")
    info("Use 'Stop Execution' to abort if needed.")


def op_stop_execution(ws):
    heading("Stop Execution")
    info("Sends a 'stop' command to immediately halt any running DuckyScript execution.")
    info("Useful if a payload is running too long or has an infinite loop.")
    resp = _ws_cmd(ws, "stop")
    ok(f"Stop sent. Response: {resp.strip() or '(none)'}")


def op_delete_file(ws):
    heading("Delete File")
    info("Deletes a file from the ESP8266 SPIFFS filesystem.")
    info("Use 'List Files' to see current files before deleting.")
    filename = prompt("Filename to delete")
    if not filename:
        warn("No filename entered.")
        return
    if not confirm(f"Delete '{filename}' from device?", default=False):
        info("Cancelled.")
        return
    info(f"Sending: remove {filename}")
    resp = _ws_cmd(ws, f"remove {filename}")
    ok(f"Delete sent for '{filename}'. Response: {resp.strip() or '(none)'}")
    info("Verify deletion with 'List Files'.")


def op_memory_stats(ws):
    heading("Memory Stats")
    info("Queries SPIFFS memory usage from the ESP8266.")
    info("Expected output: total bytes, used bytes, free bytes.")
    info("If free space is low, delete unused payloads before uploading new ones.")
    resp = _ws_cmd(ws, "mem")
    info(f"Memory: {resp.strip() or '(no response)'}")


def op_settings(ws):
    heading("Settings")
    info("Retrieves current WiFi Duck settings from the ESP8266.")
    info("Settings include: SSID, password, keyboard layout, LED behavior, etc.")
    info("To change settings, use the web UI at http://192.168.4.1 or send set commands.")
    resp = _ws_cmd(ws, "settings")
    if resp.strip():
        for line in resp.strip().splitlines():
            info(line)
    else:
        info("(no response)")


def op_firmware_update_ota():
    heading("Firmware Update — ESP8266 OTA")
    info("Performs an over-the-air (OTA) firmware update on the ESP8266 via HTTP POST.")
    info(f"Endpoint: POST {DUCK_HTTP}/update  (multipart/form-data, field: 'firmware')")
    info("")
    info("Firmware binary (.bin) download sources:")
    info("  https://github.com/spacehuhn/wifi-duck/releases")
    info("")
    info("OTA process:")
    info("  1. The .bin file is POSTed to the ESP8266 HTTP update endpoint")
    info("  2. ESP8266 flashes itself in-place and reboots (~30 seconds)")
    info("  3. Reconnect to the 'wifiduck' AP after reboot")
    info("")
    info("Troubleshooting:")
    info("  - Ensure you remain connected to the wifiduck AP during upload")
    info("  - HTTP 200 = success, any other status = failure")
    info("  - If the ESP8266 doesn't reboot after 60s, power cycle the device")
    info("  - Wrong firmware (e.g. ATmega firmware) will brick the ESP8266")
    fw_path = prompt("Path to firmware .bin file")
    if not fw_path:
        warn("No path entered.")
        return
    p = Path(fw_path).expanduser()
    if not p.exists():
        err(f"File not found: {p}")
        return

    try:
        import requests
    except ImportError:
        err("'requests' library not available.")
        info("Install: pip install requests --break-system-packages")
        info("Or: sudo apt install python3-requests")
        return

    info(f"Uploading firmware: {p.name} ({p.stat().st_size} bytes)…")
    info("This may take 30-60 seconds. Do not disconnect from the wifiduck AP.")
    try:
        with open(p, "rb") as fh:
            resp = requests.post(
                f"{DUCK_HTTP}/update",
                files={"firmware": (p.name, fh, "application/octet-stream")},
                timeout=120,
            )
        if resp.status_code == 200:
            ok("Firmware uploaded successfully. Device will reboot.")
            info("Wait ~30 seconds, then reconnect to the 'wifiduck' WiFi AP.")
        else:
            warn(f"Unexpected HTTP {resp.status_code}: {resp.text[:200]}")
            info("Check that the .bin file is the correct ESP8266 firmware build.")
    except Exception as e:
        err(f"OTA upload failed: {e}")
        info("Troubleshooting:")
        info("  - Verify you are still connected to the wifiduck AP")
        info("  - Test: curl http://192.168.4.1")
        info("  - Check if the device is still responding (ping 192.168.4.1)")


# ── Firmware payloads (main-page "FIRMWARE - ..." auto-flash) ─────────────────
# Adds the official WiFi Duck firmware (SpacehuhnTech/WiFiDuck) as no-menu
# payloads. The ESP8266 half is flashed two ways:
#   ESP8266 (esptool) — wired serial flash of the release .bin via esptool
#   ESP8266 (OTA)      — reuses the module's existing HTTP /update OTA path
# Source repo/releases: https://github.com/SpacehuhnTech/WiFiDuck
# (ESP8266 firmware asset: dstike_wifi_duck_esp8266_*.bin)

WIFIDUCK_OWNER = "SpacehuhnTech"
WIFIDUCK_REPO  = "WiFiDuck"
ESP_UART_VID_PIDS = [(0x10C4, 0xEA60), (0x1A86, 0x7523), (0x0403, 0x6001),
                     (0x1A86, 0x55D4)]


def _fw_dir() -> Path:
    d = get_firmware_dir("wifi_duck")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _fetch_esp8266_bin():
    url = get_github_release_asset_url(WIFIDUCK_OWNER, WIFIDUCK_REPO, "",
                                       r"dstike_wifi_duck_esp8266.*\.bin")
    if not url:
        warn("  Could not resolve the WiFi Duck ESP8266 .bin from GitHub releases.")
        existing = sorted(_fw_dir().glob("*esp8266*.bin"))
        if existing:
            ok(f"  Using operator-supplied image: {existing[-1].name}")
            return existing[-1]
        return None
    dest = _fw_dir() / url.rsplit("/", 1)[-1]
    if dest.exists() and dest.stat().st_size > 0:
        ok(f"  ESP8266 firmware already downloaded: {dest.name}")
        return dest
    return dest if download_firmware(url, dest, "WiFi Duck ESP8266 firmware") else None


def _fw_device_info():
    heading("Device Info")
    info(f"Board : {TOOL_NAME} (ESP8266 + ATmega32U4)")
    info("ESP8266 half hosts the AP/WebSocket UI; this payload updates its firmware.")


def _prep_esptool(staged) -> bool:
    binf = _fetch_esp8266_bin()
    if not binf:
        err("  Could not obtain the ESP8266 firmware .bin — aborting before the flash.")
        return False
    info("  Ensuring esptool is available…")
    ensure_pip_packages([("esptool", "esptool")])
    port = find_serial_port_by_vidpid(ESP_UART_VID_PIDS)
    if not port:
        port = prompt("ESP8266 USB-serial port (e.g. /dev/ttyUSB0) — blank to abort")
    if not port:
        err("  No ESP8266 serial port available — aborting before the flash.")
        info("  Connect the WiFi Duck's ESP8266 USB-UART and re-run the payload.")
        return False
    staged["bin"] = binf
    staged["port"] = port
    ok(f"  Ready: esptool + {Path(binf).name}  (port {port})")
    return True


def _prep_ota(staged) -> bool:
    binf = _fetch_esp8266_bin()
    if not binf:
        err("  Could not obtain the ESP8266 firmware .bin — aborting before the flash.")
        return False
    try:
        import requests as _req
        r = _req.get(DUCK_HTTP, timeout=4)
        reachable = r.status_code == 200
    except Exception:
        reachable = False
    if not reachable:
        err(f"  WiFi Duck HTTP endpoint {DUCK_HTTP} not reachable — aborting before the flash.")
        info("  Connect to the 'wifiduck' AP first (OTA uploads over HTTP).")
        return False
    staged["bin"] = binf
    ok(f"  Ready: OTA upload of {Path(binf).name} to {DUCK_HTTP}/update")
    return True


def _flash_esptool(staged):
    port = staged["port"]
    binf = staged["bin"]
    cmd = [sys.executable, "-m", "esptool", "--chip", "esp8266",
           "--port", port, "--baud", "460800", "write_flash", "0x0", str(binf)]
    info(f"Running: {' '.join(cmd)}")
    rc = run_streaming(cmd, on_line=lambda l: info(f"  esptool: {l}"), timeout=300)
    if rc == 0:
        ok("  ESP8266 flashed — reconnect to the 'wifiduck' AP after it reboots.")
    else:
        warn(f"  esptool exited with code {rc}. If it stalled, hold the ESP FLASH button")
        warn("  during connect, or retry at --baud 115200.")


def _flash_ota(staged):
    binf = staged["bin"]
    try:
        import requests
    except ImportError:
        err("  'requests' not available — cannot OTA. Install: pip install requests")
        return
    info(f"  Uploading {Path(binf).name} to {DUCK_HTTP}/update … (~30-60s, stay on the AP)")
    try:
        with open(binf, "rb") as fh:
            resp = requests.post(
                f"{DUCK_HTTP}/update",
                files={"firmware": (Path(binf).name, fh, "application/octet-stream")},
                timeout=120,
            )
        if resp.status_code == 200:
            ok("  Firmware uploaded — the ESP8266 will reboot. Reconnect to the AP.")
        else:
            warn(f"  Unexpected HTTP {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        err(f"  OTA upload failed: {e}")


def _dispatch_firmware_payload(fw: dict):
    fw_name = fw.get("firmware", "")
    label = fw.get("label", f"Flash {fw_name}")
    staged: dict = {}
    if fw_name == "WiFi Duck ESP8266 (esptool)":
        run_firmware_payload(
            label,
            info_fn=_fw_device_info,
            prepare_fn=lambda: _prep_esptool(staged),
            flash_fn=lambda: _flash_esptool(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME} — ESP8266 half",
                "Firmware : WiFi Duck (SpacehuhnTech/WiFiDuck) esp8266 .bin",
                "Flasher  : esptool write_flash 0x0 (wired USB-UART)",
            ],
        )
    elif fw_name == "WiFi Duck ESP8266 (OTA)":
        run_firmware_payload(
            label,
            info_fn=_fw_device_info,
            prepare_fn=lambda: _prep_ota(staged),
            flash_fn=lambda: _flash_ota(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME} — ESP8266 half",
                "Firmware : WiFi Duck (SpacehuhnTech/WiFiDuck) esp8266 .bin",
                f"Flasher  : HTTP OTA POST to {DUCK_HTTP}/update",
            ],
        )
    else:
        err(f"Unknown firmware payload: {fw_name!r}")
        info("  Supported: WiFi Duck ESP8266 (esptool), WiFi Duck ESP8266 (OTA)")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor == "linux":
        info("Ensuring required APT packages: python3-requests, python3-websocket")
        info("  python3-requests   — HTTP detection and OTA firmware upload")
        info("  python3-websocket  — WebSocket CLI communication with WiFi Duck")
        apt_ok = ensure_apt_packages(["python3-requests", "python3-websocket"])
        if not apt_ok:
            info("APT websocket package unavailable — falling back to pip: websocket-client")
            ensure_pip_packages([("websocket", "websocket-client")])
    else:
        ensure_pip_packages([
            ("websocket", "websocket-client"),
            ("requests", "requests"),
        ])

    print_banner(TOOL_NAME, DESCRIPTION)

    # Firmware payload selected on the main page → auto-flash (no menu).
    # Handled before detection: esptool flashing uses a wired UART (not the AP),
    # and the OTA prepare step verifies HTTP reachability itself.
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    info("Detecting WiFi Duck…")
    info("Primary: HTTP request to http://192.168.4.1")
    info("Fallback: USB VID:PID check (2341:8037 or 1b4f:9206)")
    info("Ensure your computer is connected to the 'wifiduck' WiFi AP before continuing.")

    # Detection
    detected = verify_device_connection(
        detect_wifi_duck, TOOL_NAME, CONNECT_INSTRUCTIONS, max_retries=3
    )
    if not detected:
        err("WiFi Duck not detected. Exiting.")
        sys.exit(1)

    ok(f"WiFi Duck detected at {DUCK_IP}")

    check_firmware_version()

    # Connect WebSocket
    info(f"Connecting WebSocket to {DUCK_WS_URL}…")
    info("If this fails, ensure you are on the wifiduck AP and can ping 192.168.4.1")
    try:
        ws = _ws_connect()
    except Exception as e:
        err(f"WebSocket connection failed: {e}")
        info("Troubleshooting:")
        info("  1. Verify WiFi: iwconfig  or  ip link  — check which interface is connected")
        info("  2. Verify IP: ip route  — 192.168.4.0/24 should be routed")
        info("  3. Test HTTP: curl http://192.168.4.1")
        info("  4. Test ping: ping -c 3 192.168.4.1")
        info("  5. Check firewall: sudo ufw status")
        info("  6. The WebSocket is at ws://192.168.4.1/ws (port 80, not a custom port)")
        sys.exit(1)
    ok("WebSocket connected.")

    MENU_OPTIONS = [
        "Device Info (version + status + mem)",
        "List Files (ls)",
        "Upload DuckyScript Payload",
        "Run Payload",
        "Stop Execution",
        "Delete File",
        "Memory Stats",
        "Settings",
        "FIRMWARE - Firmware Update ESP8266 (OTA)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("WiFi Duck — Select Operation", MENU_OPTIONS)

        try:
            if choice == 0:
                op_device_info(ws)
            elif choice == 1:
                op_list_files(ws)
            elif choice == 2:
                op_upload_payload(ws)
            elif choice == 3:
                op_run_payload(ws)
            elif choice == 4:
                op_stop_execution(ws)
            elif choice == 5:
                op_delete_file(ws)
            elif choice == 6:
                op_memory_stats(ws)
            elif choice == 7:
                op_settings(ws)
            elif choice == 8:
                # OTA update doesn't need the open WebSocket
                op_firmware_update_ota()
            elif choice == 9:
                info("Closing WebSocket…")
                try:
                    ws.close()
                except Exception:
                    pass
                ok("Goodbye.")
                sys.exit(0)
        except Exception as e:
            err(f"Operation failed: {e}")
            info("Attempting to reconnect WebSocket…")
            info("Verify WiFi connection: ping 192.168.4.1")
            try:
                ws.close()
            except Exception:
                pass
            try:
                ws = _ws_connect()
                ok("Reconnected.")
            except Exception as e2:
                err(f"Reconnect failed: {e2}")
                info("Check WiFi connection and ensure the wifiduck AP is active.")
                sys.exit(1)


if __name__ == "__main__":
    main()
