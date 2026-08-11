#!/usr/bin/env python3
"""
Raspberry Pi Pico W Tool Manager
Handles device info, UF2 firmware flashing, MicroPython installation,
and script upload for the Raspberry Pi Pico W (RP2040 + CYW43439 WiFi/BT).

IMPORTANT: Pico W requires a DIFFERENT MicroPython build from regular Pico.
  Regular Pico build: rp2-pico-*.uf2
  Pico W build:      rp2-pico-w-*.uf2  ← MUST use this for WiFi to work

USB identifiers:
  VID:PID 2E8A:0005 — Pico W running MicroPython (CDC UART)
  VID:PID 2E8A:000A — Pico W running Arduino/TinyUSB firmware
  VID:PID 2E8A:0003 — Pico W in BOOTSEL / mass-storage (UF2) mode

WiFi chip: Infineon CYW43439 (802.11 b/g/n, Bluetooth 5.2 LE)
  Accessed in MicroPython via: import network; wlan = network.WLAN(network.STA_IF)
  LED: machine.Pin("LED") — NOT Pin(25) like regular Pico

Usage:
    python3 rpi_pico_w.py
"""

import subprocess
import sys
import shutil
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
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    download_firmware, get_firmware_dir, get_github_release_asset_url,
)

TOOL_NAME   = "Raspberry Pi Pico W"
DESCRIPTION = "Raspberry Pi Pico W — RP2040 with CYW43439 WiFi/BT (802.11 b/g/n + BLE 5.2)"

VID_PIDS = [
    (0x2E8A, 0x0005),
    (0x2E8A, 0x000A),
]
UF2_VID_PID      = (0x2E8A, 0x0003)
UF2_DRIVE_NAMES  = ["RPI-RP2"]
MICROPYTHON_URL  = "https://micropython.org/download/rp2-pico-w/"

CONNECT_INSTRUCTIONS = (
    "Raspberry Pi Pico W not detected.\n\n"
    "  For REPL / serial access (MicroPython running):\n"
    "    1. Connect the Pico W to USB — it should appear as /dev/ttyACM*\n"
    "    2. Ensure MicroPython (Pico W build) is already flashed\n\n"
    "  For UF2 firmware flashing (BOOTSEL mode):\n"
    "    1. Hold the BOOTSEL button on the Pico W\n"
    "    2. While holding BOOTSEL, connect the USB cable\n"
    "    3. Release BOOTSEL — a drive called 'RPI-RP2' will mount\n"
    "    4. Copy your .uf2 file onto that drive\n\n"
    "  IMPORTANT: Pico W needs its OWN MicroPython build!\n"
    "    Download from: https://micropython.org/download/rp2-pico-w/\n"
    "    File: rp2-pico-w-YYYYMMDD-vX.Y.Z.uf2\n"
    "    Do NOT use the regular rp2-pico-*.uf2 — WiFi will NOT work!\n\n"
    "  Linux permission fix:\n"
    "    sudo usermod -aG dialout $USER   (then log out and back in)\n\n"
    "  Debug: lsusb | grep 2e8a   or   ls /dev/ttyACM*"
)

UDEV_RULES_CONTENT = """\
# Raspberry Pi Pico W udev rules
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0005", MODE="0666", GROUP="dialout"
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000a", MODE="0666", GROUP="dialout"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0003", MODE="0666", GROUP="dialout"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-rpi-pico-w.rules"

WIFI_EXAMPLE_CODE = '''\
import network, time

SSID     = "YourNetwork"
PASSWORD = "YourPassword"

wlan = network.WLAN(network.STA_IF)
wlan.active(True)
wlan.connect(SSID, PASSWORD)

# Wait for connection
for _ in range(20):
    if wlan.isconnected():
        break
    time.sleep(0.5)

if wlan.isconnected():
    print("Connected! IP:", wlan.ifconfig()[0])
else:
    print("Failed to connect")
    print("Status code:", wlan.status())
    # Status codes:
    # 0 = LINK_DOWN (not connected)
    # 1 = LINK_JOIN (connecting)
    # 2 = LINK_NOIP (no IP yet)
    # 3 = LINK_UP   (connected)
    # -1 = LINK_FAIL
    # -2 = LINK_NONET (SSID not found)
    # -3 = LINK_BADAUTH (wrong password)
'''


def _find_uf2_drive():
    os_name = get_os()
    candidates = []
    if os_name == "linux":
        import getpass
        user = getpass.getuser()
        for base in [Path("/media") / user, Path("/run/media") / user, Path("/media")]:
            if base.exists():
                for name in UF2_DRIVE_NAMES:
                    p = base / name
                    if p.is_dir():
                        candidates.append(p)
    elif os_name == "macos":
        for name in UF2_DRIVE_NAMES:
            p = Path("/Volumes") / name
            if p.is_dir():
                candidates.append(p)
    return candidates[0] if candidates else None


def detect_device():
    if find_serial_port_by_vidpid(VID_PIDS) is not None:
        return True
    if _find_uf2_drive() is not None:
        return True
    try:
        import usb.core
        dev = usb.core.find(idVendor=UF2_VID_PID[0], idProduct=UF2_VID_PID[1])
        if dev is not None:
            return True
    except Exception:
        pass
    return False


def _check_udev_rules():
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Raspberry Pi Pico W…")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH}")
        info("Unplug and replug the Pico W to apply new permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual fix: sudo tee {UDEV_RULES_PATH}")
        info(UDEV_RULES_CONTENT)


def _require_file(path_str, ext=None):
    if not path_str:
        warn("No file path provided.")
        return None
    p = Path(path_str)
    if not p.exists():
        err(f"File not found: {p}")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


def _wait_for_uf2_drive(timeout=30):
    info(f"Waiting up to {timeout}s for RPI-RP2 drive to mount…")
    for i in range(timeout):
        drive = _find_uf2_drive()
        if drive:
            ok(f"RPI-RP2 drive found at: {drive}")
            return drive
        if WEB_MODE:
            wait_status(f"Waiting for RPI-RP2… ({i+1}/{timeout}s)")
        time.sleep(1)
    return None


def op_device_info(port):
    heading("Device Info")
    info(f"Serial port: {port}")
    info("Querying MicroPython version and system info via mpremote…")
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.device == port:
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
    except Exception as e:
        warn(f"Could not read serial port metadata: {e}")

    info("")
    info("Note: Pico W LED is on machine.Pin('LED'), NOT Pin(25) like the regular Pico.")
    info("WiFi chip: Infineon CYW43439 — accessed via network.WLAN() in MicroPython")
    info("")

    try:
        result = subprocess.run(
            ["mpremote", "connect", port, "exec",
             "import sys; print('MicroPython:', sys.version); import os; print('uname:', os.uname())"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                ok(f"  {line}")
        else:
            warn("No response — board may not be running MicroPython.")
            info("Flash the Pico W-specific MicroPython build if needed.")
    except FileNotFoundError:
        err("mpremote not found. Install: pip install mpremote --break-system-packages")
    except Exception as e:
        err(f"Device info error: {e}")

    # Check if WiFi network module is available
    info("")
    info("Checking WiFi availability…")
    try:
        result = subprocess.run(
            ["mpremote", "connect", port, "exec",
             "import network; wlan = network.WLAN(network.STA_IF); print('WiFi available, MAC:', ':'.join('%02x'%b for b in wlan.config('mac')))"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            ok(f"  {result.stdout.strip()}")
        else:
            warn("WiFi not available — are you using the Pico W MicroPython build?")
            info(f"  Download Pico W build: {MICROPYTHON_URL}")
    except Exception as e:
        warn(f"WiFi check failed: {e}")


def op_flash_uf2(uf2_path_str=None):
    heading("Flash UF2 Firmware")
    info("The Pico W must be in BOOTSEL mode (hold button while plugging USB).")
    info("")
    info("WARNING: Regular Pico and Pico W use DIFFERENT firmware!")
    info(f"  Pico W MicroPython: {MICROPYTHON_URL}")
    info("  File: rp2-pico-w-YYYYMMDD-vX.Y.Z.uf2")
    info("  Using wrong firmware will prevent WiFi from working!")
    info("")

    if uf2_path_str is None:
        uf2_path_str = prompt("Path to .uf2 firmware file")
    fw = _require_file(uf2_path_str, ".uf2")
    if not fw:
        return

    # Warn if file looks like regular Pico firmware
    if "pico-w" not in fw.name.lower() and "picow" not in fw.name.lower():
        warn(f"Filename '{fw.name}' does not contain 'pico-w' or 'picow'.")
        warn("Ensure this is the Pico W build — regular Pico firmware won't enable WiFi!")
        if not confirm("Continue with this file?", default=False):
            info("Cancelled. Download Pico W firmware from:")
            info(f"  {MICROPYTHON_URL}")
            return

    info("Looking for RPI-RP2 drive…")
    drive = _find_uf2_drive()
    if not drive:
        info("RPI-RP2 not found. Waiting for BOOTSEL mode…")
        info("  → Hold BOOTSEL, unplug, replug, release BOOTSEL")
        drive = _wait_for_uf2_drive(timeout=60)
    if not drive:
        err("RPI-RP2 drive did not appear within 60 seconds.")
        info("Troubleshooting:")
        info("  - Hold BOOTSEL BEFORE plugging in USB")
        info("  - Use a data USB cable, not a charge-only cable")
        info("  - Try a different USB port (avoid hubs)")
        return

    if not confirm(f"Copy {fw.name} to {drive}?"):
        info("Cancelled.")
        return

    info(f"Copying {fw.name} → {drive} …")
    try:
        shutil.copy2(str(fw), str(drive / fw.name))
        ok(f"Copied — Pico W is rebooting…")
        info("Wait a few seconds, then check: ls /dev/ttyACM*")
    except PermissionError as e:
        err(f"Permission denied: {e}")
        sudo_run(f"cp {fw} {drive / fw.name}")
    except Exception as e:
        err(f"Copy failed: {e}")


def op_flash_micropython_w():
    heading("Flash MicroPython for Pico W")
    info("MicroPython for Pico W is a SEPARATE build from regular Pico.")
    info("")
    info("Download from:")
    info(f"  {MICROPYTHON_URL}")
    info("")
    info("File to download: rp2-pico-w-YYYYMMDD-vX.Y.Z.uf2")
    info("  (NOT rp2-pico-YYYYMMDD-vX.Y.Z.uf2 — that's for regular Pico)")
    info("  (NOT rp2-pico2-w-*.uf2 — that's for Pico 2W with RP2350)")
    info("")
    info("Why does it matter?")
    info("  - Regular Pico build has no CYW43439 WiFi driver")
    info("  - Pico W build includes the WiFi stack and network module")
    info("  - The LED is also different: Pin('LED') vs Pin(25)")
    info("")
    fw_path = prompt(f"Path to Pico W MicroPython .uf2 (download from {MICROPYTHON_URL})")
    op_flash_uf2(fw_path)


def op_wifi_info(port):
    heading("WiFi Setup Info")
    info("Pico W WiFi uses the Infineon CYW43439 chip via the 'network' module in MicroPython.")
    info("")
    info("Key differences from regular Pico:")
    info("  - LED: use machine.Pin('LED') instead of machine.Pin(25)")
    info("  - WiFi: import network; wlan = network.WLAN(network.STA_IF)")
    info("  - Bluetooth: import bluetooth (BLE only)")
    info("")
    info("WiFi connection example code:")
    for line in WIFI_EXAMPLE_CODE.strip().splitlines():
        info(f"  {line}")
    info("")
    info("Access Point mode (make Pico W a hotspot):")
    info("  ap = network.WLAN(network.AP_IF)")
    info("  ap.config(essid='PicoW-AP', password='password123')")
    info("  ap.active(True)")
    info("")
    info("Scan for networks:")
    info("  wlan.active(True)")
    info("  for net in wlan.scan():")
    info("      print(net[0].decode(), 'RSSI:', net[3])")
    info("")
    if port:
        info("Testing WiFi scan on device…")
        try:
            result = subprocess.run(
                ["mpremote", "connect", port, "exec",
                 "import network; w=network.WLAN(network.STA_IF); w.active(True); nets=w.scan();"
                 "print(f'Found {len(nets)} networks'); [print(' ', n[0].decode(), 'ch', n[2], 'rssi', n[3]) for n in nets[:5]]"],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().splitlines():
                    ok(f"  {line}")
            else:
                warn("WiFi scan failed or returned no results.")
        except Exception as e:
            warn(f"WiFi scan error: {e}")


def op_upload_payload(port):
    heading("Upload Payload")
    info("Upload a MicroPython payload script to the Pico W.")
    info("")
    info("Available Pico W payloads:")
    info("  payloads/rpi_pico_w/wifi-exfil/main.py       — WiFi-based data exfiltration HID")
    info("  payloads/rpi_pico_w/wireless-sysaudit/main.py — Wireless system audit")
    info("")
    info("Usage: upload as 'main.py' to run on boot, or with a different name to run manually.")
    info("")

    local_path = prompt("Path to .py payload file")
    local = _require_file(local_path, ".py")
    if not local:
        return
    remote_name = prompt(f"Remote filename on device (default: {local.name})")
    if not remote_name:
        remote_name = local.name

    info(f"Uploading {local.name} → :{remote_name} …")
    try:
        result = subprocess.run(
            ["mpremote", "connect", port, "cp", str(local), f":{remote_name}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            ok(f"Uploaded: {remote_name}")
            if remote_name == "main.py":
                info("main.py will execute automatically on the next boot/reset.")
        else:
            err(f"Upload failed (exit {result.returncode})")
            if result.stderr:
                err(f"  stderr: {result.stderr.strip()[:400]}")
    except FileNotFoundError:
        err("mpremote not found. Install: pip install mpremote --break-system-packages")
    except Exception as e:
        err(f"Upload error: {e}")


def op_repl_info():
    heading("MicroPython REPL Info")
    info("Access the Pico W's interactive MicroPython REPL.")
    info("")
    info("mpremote: mpremote connect /dev/ttyACM0 repl")
    info("  Ctrl+]  — exit | Ctrl+C — interrupt | Ctrl+D — soft reset")
    info("")
    info("minicom:  minicom -D /dev/ttyACM0 -b 115200")
    info("screen:   screen /dev/ttyACM0 115200")
    info("picocom:  picocom /dev/ttyACM0 -b 115200")
    info("")
    info("Pico W-specific MicroPython snippets:")
    info("  from machine import Pin; Pin('LED').toggle()   # blink LED (NOT Pin(25)!)")
    info("  import network; print(network.country())       # WiFi country code")
    info("  import bluetooth; print('BLE available')       # Bluetooth LE")
    info("  import gc; gc.collect(); print(gc.mem_free())  # free memory")


def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Checking MicroPython version on Raspberry Pi Pico W...")
    current = None
    try:
        import subprocess as _sp, re
        r = _sp.run(
            ["mpremote", "connect", port, "exec",
             "import sys; v=sys.version; print(v)"],
            capture_output=True, text=True, timeout=8,
        )
        if r.returncode == 0 and r.stdout.strip():
            m = re.search(r'MicroPython\s+v?([\d.]+)', r.stdout)
            if m:
                current = m.group(1)
    except Exception as e:
        info(f"  Version query failed: {e}")

    if current:
        ok(f"Installed MicroPython: {current}")
        latest, url = check_latest_github_release("micropython", "micropython")
        if latest:
            announce_firmware_update("Pico W MicroPython", current, latest.lstrip("v"), url)
        else:
            warn("Could not check GitHub for latest version.")
    else:
        info("MicroPython not detected. If it's installed, the REPL may not be responding.")
        info("Download latest Pico W MicroPython: https://micropython.org/download/rp2-pico-w/")


# ── Firmware payloads (main-page "FIRMWARE - ..." auto-flash) ─────────────────
# In-the-wild firmwares wired as no-menu payloads. Sources:
#   MicroPython UF2 (Pico W build) — https://micropython.org/download/RPI_PICO_W/
#   CircuitPython UF2 — https://circuitpython.org/board/raspberry_pi_pico_w/
#   Pico Ducky (CircuitPython USB Rubber Ducky) — https://github.com/dbisu/pico-ducky
# RP2040 firmware is written by copying a .uf2 onto the RPI-RP2 BOOTSEL drive.

import re as _re
import urllib.request as _urlreq
import zipfile as _zipfile

FW_TOOL_ID       = "rpi_pico_w"
MICROPY_BOARD    = "RPI_PICO_W"
CIRCUITPY_BOARD  = "raspberry_pi_pico_w"
PICO_DUCKY_OWNER = "dbisu"
PICO_DUCKY_REPO  = "pico-ducky"
_FW_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _fw_dir() -> Path:
    d = get_firmware_dir(FW_TOOL_ID)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _http_get_text(url: str, timeout: int = 20) -> str:
    req = _urlreq.Request(url, headers={"User-Agent": _FW_UA})
    with _urlreq.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _scrape_first(url: str, pattern: str) -> str:
    try:
        html = _http_get_text(url)
    except Exception as e:
        warn(f"  Could not fetch {url}: {e}")
        return ""
    m = _re.search(pattern, html)
    return m.group(0) if m else ""


def _fetch_micropython_uf2():
    page = f"https://micropython.org/download/{MICROPY_BOARD}/"
    info(f"  Locating the latest MicroPython UF2 on {page} …")
    rel = _scrape_first(page, r"/resources/firmware/" + _re.escape(MICROPY_BOARD)
                        + r"-\d{8}-v[0-9.]+\.uf2")
    if not rel:
        warn("  No MicroPython UF2 link found on the download page.")
        return None
    url = "https://micropython.org" + rel
    dest = _fw_dir() / rel.rsplit("/", 1)[-1]
    if dest.exists() and dest.stat().st_size > 0:
        ok(f"  MicroPython UF2 already downloaded: {dest.name}")
        return dest
    return dest if download_firmware(url, dest, "MicroPython UF2") else None


def _fetch_circuitpython_uf2():
    page = f"https://circuitpython.org/board/{CIRCUITPY_BOARD}/"
    info(f"  Locating the latest CircuitPython UF2 on {page} …")
    url = _scrape_first(
        page,
        r"https://downloads\.circuitpython\.org/bin/" + _re.escape(CIRCUITPY_BOARD)
        + r"/en_US/adafruit-circuitpython-" + _re.escape(CIRCUITPY_BOARD)
        + r"-en_US-[0-9.]+\.uf2")
    if not url:
        warn("  No CircuitPython UF2 link found on the board page.")
        return None
    dest = _fw_dir() / url.rsplit("/", 1)[-1]
    if dest.exists() and dest.stat().st_size > 0:
        ok(f"  CircuitPython UF2 already downloaded: {dest.name}")
        return dest
    return dest if download_firmware(url, dest, "CircuitPython UF2") else None


def _fetch_pico_ducky():
    """Download + extract the pico-ducky release package; return the dir holding
    code.py + the lib/ folder (copied to CIRCUITPY after CircuitPython is flashed)."""
    info("  Fetching the pico-ducky payload package (dbisu/pico-ducky, US layout) …")
    url = get_github_release_asset_url(PICO_DUCKY_OWNER, PICO_DUCKY_REPO, "",
                                       r"pico-ducky-.*-US\.zip")
    if not url:
        warn("  Could not resolve a pico-ducky release asset from GitHub.")
        return None
    zip_dest = _fw_dir() / url.rsplit("/", 1)[-1]
    if not (zip_dest.exists() and zip_dest.stat().st_size > 0):
        if not download_firmware(url, zip_dest, "pico-ducky package"):
            return None
    extract_dir = _fw_dir() / "pico-ducky"
    try:
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        with _zipfile.ZipFile(zip_dest) as zf:
            zf.extractall(extract_dir)
    except Exception as e:
        err(f"  Failed to extract pico-ducky package: {e}")
        return None
    for cand in [extract_dir, *extract_dir.rglob("*")]:
        if cand.is_dir() and (cand / "code.py").exists():
            ok(f"  pico-ducky files ready: {cand}")
            return cand
    warn("  Extracted the pico-ducky package but code.py was not found inside.")
    return None


def _copy_uf2_to_bootsel(uf2: Path) -> bool:
    """Wait for the RPI-RP2 BOOTSEL drive and copy the UF2 onto it (the write)."""
    info("  Enter BOOTSEL mode now: hold the BOOTSEL button and (re)connect USB.")
    drive = _find_uf2_drive() or _wait_for_uf2_drive(timeout=60)
    if not drive:
        err("  RPI-RP2 BOOTSEL drive did not appear — cannot flash.")
        return False
    ok(f"  RPI-RP2 drive: {drive}")
    try:
        shutil.copy2(str(uf2), str(drive / uf2.name))
    except PermissionError:
        sudo_run(f"cp {uf2} {drive / uf2.name}")
    except Exception as e:
        err(f"  Copy to RPI-RP2 failed: {e}")
        return False
    ok(f"  Copied {uf2.name} → {drive} — the board will reboot into the new firmware.")
    return True


def _find_circuitpy_drive():
    import os as _os
    vol = Path("/Volumes/CIRCUITPY")
    if vol.exists():
        return vol
    user = _os.environ.get("USER", "")
    for base in [Path(f"/media/{user}"), Path(f"/run/media/{user}"), Path("/media")]:
        c = base / "CIRCUITPY"
        if c.is_dir():
            return c
    return None


def _fw_device_info(port):
    heading("Device Info")
    info(f"Board : {TOOL_NAME}")
    if port:
        info(f"Serial port : {port}")
    else:
        info("Mode : BOOTSEL / mass-storage (ready for UF2 flashing)")


def _prep_micropython(staged) -> bool:
    uf2 = _fetch_micropython_uf2()
    if not uf2:
        err("  Could not obtain the MicroPython UF2 — aborting before the flash.")
        return False
    staged["uf2"] = uf2
    ok(f"  Ready to flash MicroPython: {Path(uf2).name}")
    return True


def _prep_circuitpython(staged) -> bool:
    uf2 = _fetch_circuitpython_uf2()
    if not uf2:
        err("  Could not obtain the CircuitPython UF2 — aborting before the flash.")
        return False
    staged["uf2"] = uf2
    ok(f"  Ready to flash CircuitPython: {Path(uf2).name}")
    return True


def _prep_pico_ducky(staged) -> bool:
    uf2 = _fetch_circuitpython_uf2()
    if not uf2:
        err("  Could not obtain the CircuitPython UF2 (pico-ducky base) — aborting.")
        return False
    pd = _fetch_pico_ducky()
    if not pd:
        err("  Could not obtain the pico-ducky payload set — aborting before the flash.")
        return False
    staged["uf2"] = uf2
    staged["pd_dir"] = pd
    ok("  Ready to flash CircuitPython + copy the pico-ducky files.")
    return True


def _flash_uf2_only(staged):
    uf2 = staged.get("uf2")
    if not uf2 or not Path(uf2).exists():
        err("UF2 image missing at flash time — aborting.")
        return
    _copy_uf2_to_bootsel(Path(uf2))


def _flash_pico_ducky(staged):
    uf2 = staged.get("uf2")
    pd = staged.get("pd_dir")
    if not uf2 or not Path(uf2).exists() or not pd:
        err("pico-ducky assets missing at flash time — aborting.")
        return
    if not _copy_uf2_to_bootsel(Path(uf2)):
        return
    info("  Waiting for the CIRCUITPY drive to appear after CircuitPython boots…")
    drv = None
    for _ in range(90):
        drv = _find_circuitpy_drive()
        if drv:
            break
        wait_status("  Waiting for CIRCUITPY…")
        time.sleep(1)
    wait_done()
    if not drv:
        err("  CIRCUITPY drive not found — copy the pico-ducky files manually from:")
        info(f"    {pd}")
        return
    ok(f"  CIRCUITPY drive: {drv}")
    for item in Path(pd).iterdir():
        dest = drv / item.name
        try:
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)
        except Exception as e:
            warn(f"  Could not copy {item.name}: {e}")
    ok("  pico-ducky files copied to CIRCUITPY — the Pico W now runs as a USB Rubber Ducky.")
    info("  Edit payload.dd on the CIRCUITPY drive to set your DuckyScript payload.")


def _dispatch_firmware_payload(fw: dict, port: str):
    """Route a selected .qfw firmware payload to the right prepare/flash pair."""
    fw_name = fw.get("firmware", "")
    label = fw.get("label", f"Flash {fw_name}")
    staged: dict = {}
    if fw_name == "MicroPython":
        run_firmware_payload(
            label,
            info_fn=lambda: _fw_device_info(port),
            prepare_fn=lambda: _prep_micropython(staged),
            flash_fn=lambda: _flash_uf2_only(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : MicroPython (Pico W build, micropython.org UF2)",
                "Flasher  : copy UF2 to the RPI-RP2 BOOTSEL drive",
            ],
        )
    elif fw_name == "CircuitPython":
        run_firmware_payload(
            label,
            info_fn=lambda: _fw_device_info(port),
            prepare_fn=lambda: _prep_circuitpython(staged),
            flash_fn=lambda: _flash_uf2_only(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : CircuitPython (Pico W build, circuitpython.org UF2, Adafruit)",
                "Flasher  : copy UF2 to the RPI-RP2 BOOTSEL drive",
            ],
        )
    elif fw_name == "Pico Ducky":
        run_firmware_payload(
            label,
            info_fn=lambda: _fw_device_info(port),
            prepare_fn=lambda: _prep_pico_ducky(staged),
            flash_fn=lambda: _flash_pico_ducky(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : Pico Ducky (dbisu/pico-ducky, CircuitPython USB Rubber Ducky)",
                "Flasher  : flash CircuitPython UF2, then copy pico-ducky files to CIRCUITPY",
            ],
        )
    else:
        err(f"Unknown firmware payload: {fw_name!r}")
        info("  Supported: MicroPython, CircuitPython, Pico Ducky")


def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Dependency Check")
    flavor = get_os_flavor()
    info("Checking for pyserial…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    ensure_pip_packages([("serial", "pyserial")])

    info("Checking for mpremote…")
    ensure_pip_packages([("mpremote", "mpremote")])

    _check_udev_rules()

    heading("Device Detection")
    info("Scanning for Raspberry Pi Pico W via VID:PID 2E8A:0005/000A…")
    info("Also checking for BOOTSEL mode (RPI-RP2 drive)…")
    info("")
    info("KEY REMINDER: Pico W requires a Pico W-specific MicroPython build!")
    info(f"  Download: {MICROPYTHON_URL}")
    info("")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Raspberry Pi Pico W not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    uf2_drive = _find_uf2_drive()

    if port:
        ok(f"Pico W detected on serial port: {port}")
        check_firmware_version(port)
    elif uf2_drive:
        ok(f"Pico W in BOOTSEL mode — UF2 drive at: {uf2_drive}")
        port = None
    else:
        ok("Pico W detected via USB.")
        port = None

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw, port)
        return

    MENU_OPTIONS = [
        "Device Info (MicroPython version, WiFi MAC)",
        "FIRMWARE - Flash UF2 Firmware (custom .uf2 file)",
        "FIRMWARE - Flash MicroPython for Pico W (download guide + UF2 flash)",
        "WiFi Setup Info (scan networks, connection example)",
        "Upload Payload (wifi-exfil, wireless-sysaudit)",
        "REPL Info (mpremote, minicom, screen)",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)

        if choice == 0:
            if not port:
                port = find_serial_port_by_vidpid(VID_PIDS)
            if port:
                op_device_info(port)
            else:
                warn("No serial port found. Flash MicroPython (Pico W build) first.")
        elif choice == 1:
            op_flash_uf2()
        elif choice == 2:
            op_flash_micropython_w()
        elif choice == 3:
            op_wifi_info(port)
        elif choice == 4:
            if not port:
                port = find_serial_port_by_vidpid(VID_PIDS)
            if port:
                op_upload_payload(port)
            else:
                warn("No serial port found. Flash MicroPython first.")
        elif choice == 5:
            op_repl_info()
        elif choice == 6:
            info("Goodbye.")
            break

        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
