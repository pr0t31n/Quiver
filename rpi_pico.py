#!/usr/bin/env python3
"""
Raspberry Pi Pico (RP2040) Tool Manager
Handles device detection, MicroPython flashing, script upload, and REPL access
for the Raspberry Pi Pico RP2040 microcontroller board.

USB identifiers:
  MicroPython REPL mode:
    VID:PID 2E8A:0005  — Raspberry Pi Pico MicroPython CDC
    VID:PID 2E8A:000A  — Raspberry Pi Pico Arduino-compatible CDC

  BOOTSEL / mass storage mode (for UF2 flashing):
    VID:PID 2E8A:0003  — RPI-RP2 mass storage device

Linux serial access:
  The Pico appears as /dev/ttyACM* in MicroPython mode.
  If you get 'Permission denied', run:
    sudo usermod -aG dialout $USER
  then log out and back in.

BOOTSEL mode (for UF2 flashing):
  Hold the BOOTSEL button on the board, then connect USB (or press RUN/RST
  while holding BOOTSEL). The board mounts as a USB mass storage device
  named RPI-RP2. Drop a .uf2 file onto it to flash.

Usage:
    python3 rpi_pico.py
"""

import shutil
import subprocess
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
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    download_firmware, get_firmware_dir, get_github_release_asset_url,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Raspberry Pi Pico"
DESCRIPTION = "Raspberry Pi Pico RP2040 microcontroller board"

# VID:PID pairs for the Pico running MicroPython or Arduino firmware
VID_PIDS = [
    (0x2E8A, 0x0005),   # Raspberry Pi Pico — MicroPython CDC
    (0x2E8A, 0x000A),   # Raspberry Pi Pico — Arduino-compatible CDC
]

# VID:PID for BOOTSEL / mass storage mode (UF2 flashing)
UF2_VID_PID = (0x2E8A, 0x0003)

CONNECT_INSTRUCTIONS = (
    "Raspberry Pi Pico not detected.\n\n"
    "  1. Connect the Pico via a USB data cable (not a charge-only cable)\n"
    "     The board should appear as /dev/ttyACM* (Linux) or /dev/cu.usbmodem* (macOS)\n\n"
    "  2. To enter MicroPython REPL mode:\n"
    "       Just connect normally — if MicroPython is installed it will enumerate\n\n"
    "  3. To enter BOOTSEL / UF2 flash mode:\n"
    "       Hold the BOOTSEL button on the board while connecting USB\n"
    "       OR: hold BOOTSEL, press the RUN button, then release BOOTSEL\n"
    "       The board will mount as a drive named 'RPI-RP2'\n\n"
    "  4. Linux permission fix:\n"
    "       sudo usermod -aG dialout $USER  (then log out and back in)\n"
    "       Quick fix: sudo chmod 666 /dev/ttyACM0\n\n"
    "  5. macOS: The Pico should be recognized natively without extra drivers\n"
    "       In MicroPython mode it appears under /dev/cu.usbmodem*\n\n"
    "  6. Still not detected? Try a different USB port or cable\n"
    "       Check Linux: dmesg | tail -20\n"
    "       Check macOS: system_profiler SPUSBDataType | grep -A5 'Pico'"
)

# udev rules for non-root serial port access on Linux
UDEV_RULES_CONTENT = """\
# Raspberry Pi Pico udev rules
# MicroPython CDC (VID:PID 2E8A:0005)
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0005", MODE="0666", GROUP="dialout"
# Arduino-compatible CDC (VID:PID 2E8A:000A)
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000a", MODE="0666", GROUP="dialout"
# BOOTSEL / mass storage mode (VID:PID 2E8A:0003)
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0003", MODE="0666", GROUP="dialout"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-rpi-pico.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    """Return True if a Pico is found in either REPL or BOOTSEL mode."""
    if find_serial_port_by_vidpid(VID_PIDS) is not None:
        return True
    # Also check for BOOTSEL mass storage mode
    if _find_uf2_drive() is not None:
        return True
    return False


def _find_uf2_drive() -> Path | None:
    """Return the path to the RPI-RP2 mass storage drive, or None."""
    import os
    flavor = get_os_flavor()
    # macOS
    vol = Path("/Volumes/RPI-RP2")
    if vol.exists():
        return vol
    # Linux — /media/$USER/RPI-RP2 or /run/media/$USER/RPI-RP2
    user = os.environ.get("USER", "")
    for base in [Path(f"/media/{user}"), Path(f"/run/media/{user}"), Path("/media")]:
        candidate = base / "RPI-RP2"
        if candidate.exists():
            return candidate
    return None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules on Linux so non-root users can access the Pico."""
    flavor = get_os_flavor()
    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules are Linux-only — skipping on this OS.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Raspberry Pi Pico…")
    info("  This allows non-root access to /dev/ttyACM* and the BOOTSEL drive.")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the Pico to apply new permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual fix — run as root:")
        info(f"  sudo tee {UDEV_RULES_PATH} << 'EOF'")
        info(UDEV_RULES_CONTENT)
        info("  sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_file(path_str: str, ext: str = None) -> Path | None:
    """Validate a file path and optionally check its extension."""
    if not path_str:
        warn("No file path provided. Aborting.")
        return None
    p = Path(path_str.strip())
    if not p.exists():
        err(f"File not found: {p}")
        info("Tip: use an absolute path, e.g. /home/user/firmware.uf2")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


def _run_mpremote(args: list, timeout: int = 30):
    """Run an mpremote command and return (returncode, stdout, stderr)."""
    cmd = ["mpremote"] + args
    info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        err("mpremote not found.")
        info("Install: pip install mpremote --break-system-packages")
        return 1, "", "mpremote not found"
    except subprocess.TimeoutExpired:
        err(f"mpremote timed out after {timeout}s.")
        return 1, "", "timeout"
    except Exception as e:
        err(f"mpremote execution error: {e}")
        return 1, "", str(e)


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    """Show serial port metadata and query the MicroPython version via mpremote."""
    heading("Device Info")
    info(f"Serial port : {port}")
    info(f"Board       : Raspberry Pi Pico (RP2040)")
    info("")
    info("Reading serial port metadata from pyserial…")
    try:
        from serial.tools import list_ports
        found_port_info = False
        for p in list_ports.comports():
            if p.device == port:
                found_port_info = True
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
                info(f"  Serial No.  : {p.serial_number or 'N/A'}")
        if not found_port_info:
            warn(f"Port {port} not found in comports() — metadata unavailable.")
    except Exception as e:
        warn(f"Could not read serial port metadata: {e}")

    info("")
    info("Querying MicroPython version via mpremote…")
    info("  (Board must be running MicroPython — not in BOOTSEL mode)")
    rc, stdout, stderr = _run_mpremote(
        ["connect", port, "exec", "import sys; print(sys.version)"],
        timeout=15,
    )
    if rc == 0 and stdout.strip():
        ok(f"MicroPython version: {stdout.strip()}")
    else:
        warn("Could not retrieve MicroPython version.")
        if stderr.strip():
            info(f"  mpremote stderr: {stderr.strip()[:300]}")
        info("  Is MicroPython installed? Flash it via option 3 in the menu.")
        info("  Is the board in BOOTSEL mode? If so, disconnect and reconnect normally.")

    info("")
    info("Additional info:")
    info("  RP2040 chip: dual-core ARM Cortex-M0+ @ 133 MHz")
    info("  Flash: 2 MB (standard Pico), SRAM: 264 KB")
    info("  USB: native USB 1.1 device/host controller")
    info("  GPIO: 26 multi-function pins (3.3V logic)")


def op_flash_uf2(port: str = None):
    """Flash a .uf2 firmware image to the Pico via BOOTSEL mass storage mode."""
    heading("Flash UF2 Firmware")
    info("This flashes any .uf2 file (MicroPython, Arduino, CircuitPython, etc.)")
    info("to the Pico by copying it to the RPI-RP2 mass storage drive.")
    info("")
    info("Step 1: Enter BOOTSEL mode")
    info("  Method A: Hold BOOTSEL button, then connect USB cable")
    info("  Method B: Hold BOOTSEL, press the RUN button, release BOOTSEL")
    info("  The board will appear as a USB drive named 'RPI-RP2'")
    info("")

    uf2_path_str = prompt("Path to .uf2 firmware file")
    uf2 = _require_file(uf2_path_str, ".uf2")
    if not uf2:
        return

    info("Waiting for RPI-RP2 mass storage drive to appear…")
    info("(Make sure the Pico is in BOOTSEL mode — see instructions above)")

    drive = None
    for attempt in range(30):
        drive = _find_uf2_drive()
        if drive:
            break
        if attempt == 0:
            info("  Scanning for RPI-RP2 drive every 2 seconds (up to 60s)…")
        wait_status(f"  Attempt {attempt + 1}/30 — RPI-RP2 not found yet…")
        time.sleep(2)
    wait_done()

    if not drive:
        err("RPI-RP2 drive not found after 60 seconds.")
        info("Troubleshooting:")
        info("  1. Make sure you are holding BOOTSEL while connecting/resetting")
        info("  2. Try a different USB cable (must be data cable, not charge-only)")
        info("  3. Linux: check 'dmesg | tail -20' for mount errors")
        info("  4. Linux: you may need to add yourself to the 'plugdev' group:")
        info("       sudo usermod -aG plugdev $USER")
        return

    ok(f"RPI-RP2 drive found at: {drive}")
    dest = drive / uf2.name

    if not confirm(f"Copy {uf2.name} to {drive}?"):
        info("Cancelled.")
        return

    info(f"Copying {uf2.name} ({uf2.stat().st_size:,} bytes) to {drive}…")
    try:
        shutil.copy2(str(uf2), str(dest))
    except Exception as e:
        err(f"Copy failed: {e}")
        info("  Try running with sudo, or check filesystem permissions on the drive.")
        return

    ok(f"UF2 file copied to {dest}")
    info("The Pico will now reboot automatically and apply the new firmware.")
    info("The RPI-RP2 drive will disappear — this is normal and expected.")
    info("After reboot, the board will re-enumerate on a new serial port.")


def op_flash_micropython():
    """Guide the user through downloading and flashing MicroPython for RP2040."""
    heading("Flash MicroPython (RP2040)")
    info("This installs MicroPython on the Raspberry Pi Pico (RP2040).")
    info("")
    info("IMPORTANT: Download the correct MicroPython build for the STANDARD Pico.")
    info("  The Pico and Pico W use DIFFERENT MicroPython builds!")
    info("  Using the wrong build will cause errors or missing modules.")
    info("")
    info("Download the latest MicroPython .uf2 for the standard Pico:")
    info("  https://micropython.org/download/rp2-pico/")
    info("")
    info("  Look for: rp2-pico-YYYYMMDD-vX.Y.Z.uf2  (e.g. rp2-pico-20241129-v1.24.1.uf2)")
    info("  Download the most recent stable release.")
    info("")
    info("After downloading, come back here and provide the path to the .uf2 file.")
    info("Then put your Pico into BOOTSEL mode (hold BOOTSEL, connect USB).")
    info("")

    if not confirm("Proceed to UF2 flash?"):
        info("Cancelled. Download the firmware first, then re-run this option.")
        return

    op_flash_uf2()


def op_upload_script(port: str):
    """Upload a local .py script to the Pico's MicroPython filesystem via mpremote cp."""
    heading("Upload Python Script")
    info("Uploads a .py file from your computer to the Pico's MicroPython filesystem.")
    info("Uses mpremote cp to transfer the file over the serial connection.")
    info("")
    info("mpremote quick reference:")
    info(f"  mpremote connect {port} ls :/              — list files on device")
    info(f"  mpremote connect {port} cp file.py :/      — upload file to root")
    info(f"  mpremote connect {port} cp file.py :/main.py  — upload as main.py (runs on boot)")
    info(f"  mpremote connect {port} rm :/file.py       — delete file from device")
    info("")
    info("Troubleshooting:")
    info("  'Could not enter raw repl' — Board is not running MicroPython; flash it first")
    info("  'serial.SerialException'  — Wrong port, or another program has it open (close Thonny etc.)")
    info("  'mpremote: not found'     — Install: pip install mpremote --break-system-packages")
    info("")

    local_path_str = prompt("Path to local .py script")
    local = _require_file(local_path_str, ".py")
    if not local:
        return

    remote_name = prompt(f"Remote filename on device (default: {local.name})")
    if not remote_name or not remote_name.strip():
        remote_name = local.name
    remote_name = remote_name.strip()

    if not remote_name.startswith(":"):
        remote_dest = f":/{remote_name}"
    else:
        remote_dest = remote_name

    info(f"Uploading {local.name} → {remote_dest} on {port}…")

    rc, stdout, stderr = _run_mpremote(
        ["connect", port, "cp", str(local), remote_dest],
        timeout=30,
    )

    if rc == 0:
        ok(f"Uploaded: {remote_dest}")
        info(f"To run immediately: mpremote connect {port} run {local.name}")
        info(f"To run on boot:     rename/upload the file as main.py")
    else:
        err(f"Upload failed (exit code {rc})")
        if stderr.strip():
            err(f"  stderr: {stderr.strip()[:400]}")
        if stdout.strip():
            info(f"  stdout: {stdout.strip()[:400]}")


def op_run_script(port: str):
    """Execute a local .py script on the Pico via mpremote run (without storing it)."""
    heading("Run Python Script")
    info("Runs a script on the Pico via mpremote run.")
    info("The script is executed but NOT stored on the device filesystem.")
    info("To run a script on every boot: upload it as main.py instead.")
    info("")
    info("Execution notes:")
    info("  Output from print() on the Pico will appear here in real-time")
    info("  Ctrl+C sends KeyboardInterrupt to the running script")
    info("  The script runs in the global MicroPython namespace")
    info("")

    local_path_str = prompt("Path to local .py script to run")
    local = _require_file(local_path_str, ".py")
    if not local:
        return

    info(f"Running {local.name} on {port}…  (Ctrl+C to interrupt)")
    info("")

    try:
        result = subprocess.run(
            ["mpremote", "connect", port, "run", str(local)],
            timeout=300,
        )
        if result.returncode == 0:
            ok("Script completed successfully.")
        else:
            warn(f"Script exited with code {result.returncode}.")
    except FileNotFoundError:
        err("mpremote not found.")
        info("Install: pip install mpremote --break-system-packages")
    except subprocess.TimeoutExpired:
        warn("Script timed out after 5 minutes.")
    except KeyboardInterrupt:
        info("Interrupted by user.")
    except Exception as e:
        err(f"Run error: {e}")


def op_repl_info():
    """Print detailed instructions for connecting to the MicroPython REPL."""
    heading("MicroPython REPL — Connection Guide")
    info("The Raspberry Pi Pico REPL runs at 115200 baud on its USB CDC port.")
    info("")
    info("Option 1 — mpremote (recommended, pip install mpremote):")
    info("  mpremote connect <port> repl")
    info("  Ctrl+]         — exit mpremote REPL")
    info("  Ctrl+C         — send KeyboardInterrupt (stop running code)")
    info("  Ctrl+D         — soft reset the board")
    info("  Ctrl+E         — enter paste mode")
    info("")
    info("Option 2 — minicom:")
    info("  minicom -D <port> -b 115200")
    info("  Ctrl+A then X  — exit minicom")
    info("  Ctrl+A then W  — toggle line wrap")
    info("")
    info("Option 3 — screen:")
    info("  screen <port> 115200")
    info("  Ctrl+A then K  — kill session and exit")
    info("  Ctrl+A then D  — detach (leave running in background)")
    info("")
    info("Option 4 — picocom:")
    info("  picocom <port> -b 115200")
    info("  Ctrl+A Ctrl+X  — exit picocom")
    info("  Ctrl+A Ctrl+C  — toggle local echo")
    info("")
    info("Useful MicroPython one-liners:")
    info("  import os; os.listdir('/')                 # list filesystem")
    info("  import machine; machine.reset()            # hard reset")
    info("  import sys; print(sys.version)             # MicroPython version")
    info("  import machine; print(machine.freq())      # CPU frequency (Hz)")
    info("  from machine import Pin; Pin(25, Pin.OUT).toggle()  # blink LED")
    info("  import gc; gc.collect(); print(gc.mem_free())       # free RAM")
    info("")
    info("Linux port is typically: /dev/ttyACM0  (check with: ls /dev/ttyACM*)")
    info("macOS port is typically: /dev/cu.usbmodem*  (check: ls /dev/cu.usb*)")


def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Checking MicroPython version on Raspberry Pi Pico...")
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
            announce_firmware_update("Pico MicroPython", current, latest.lstrip("v"), url)
        else:
            warn("Could not check GitHub for latest version.")
    else:
        info("MicroPython not detected. If it's installed, the REPL may not be responding.")
        info("Download latest Pico MicroPython: https://micropython.org/download/rp2-pico/")


# ── Firmware payloads (main-page "FIRMWARE - ..." auto-flash) ─────────────────
# In-the-wild firmwares wired as no-menu payloads. Sources:
#   MicroPython UF2 — https://micropython.org/download/RPI_PICO/
#   CircuitPython UF2 — https://circuitpython.org/board/raspberry_pi_pico/
#   Pico Ducky (CircuitPython USB Rubber Ducky) — https://github.com/dbisu/pico-ducky
# All RP2040 firmware is written by copying a .uf2 onto the RPI-RP2 BOOTSEL
# mass-storage drive (the module's existing UF2 flow).

import re as _re
import urllib.request as _urlreq
import zipfile as _zipfile

FW_TOOL_ID       = "rpi_pico"
MICROPY_BOARD    = "RPI_PICO"
CIRCUITPY_BOARD  = "raspberry_pi_pico"
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
    drive = None
    for _ in range(60):
        drive = _find_uf2_drive()
        if drive:
            break
        wait_status("  Waiting for the RPI-RP2 drive to mount…")
        time.sleep(1)
    wait_done()
    if not drive:
        err("  RPI-RP2 BOOTSEL drive did not appear — cannot flash.")
        return False
    ok(f"  RPI-RP2 drive: {drive}")
    try:
        shutil.copy2(str(uf2), str(drive / uf2.name))
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
    if port and port != "BOOTSEL":
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
    ok("  pico-ducky files copied to CIRCUITPY — the Pico now runs as a USB Rubber Ducky.")
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
                "Firmware : MicroPython (micropython.org UF2)",
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
                "Firmware : CircuitPython (circuitpython.org UF2, Adafruit)",
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


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")
    info("")

    info("Checking for pyserial (required for serial port scanning and REPL access)…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  Trying apt: python3-serial")
        ensure_apt_packages(["python3-serial"])
    info("  Checking pip fallback for pyserial…")
    ensure_pip_packages([("serial", "pyserial")])
    ok("pyserial ready.")

    info("")
    info("Checking for mpremote (required for script upload, REPL, and device query)…")
    info("  mpremote is pip-only (no apt/brew package available).")
    ensure_pip_packages([("mpremote", "mpremote")])
    ok("mpremote ready.")

    # ── Linux udev rules ──────────────────────────────────────────────────────
    info("")
    info("Checking udev rules (Linux only)…")
    _check_udev_rules()

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    info("Scanning for Raspberry Pi Pico via USB VID:PID matching…")
    info("  Checking for MicroPython CDC mode  (VID:PID 2E8A:0005 or 2E8A:000A)")
    info("  Checking for BOOTSEL mass storage  (VID:PID 2E8A:0003 or RPI-RP2 drive)")
    info("")
    info("Expected serial ports:")
    info("  Linux : /dev/ttyACM0  (or /dev/ttyACM1, etc.)")
    info("  macOS : /dev/cu.usbmodem*")
    info("")
    info("Verify manually: ls /dev/ttyACM* 2>/dev/null")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Raspberry Pi Pico not detected within timeout. Exiting.")
        sys.exit(1)

    # Check which mode the Pico was detected in
    port = find_serial_port_by_vidpid(VID_PIDS)
    uf2_drive = _find_uf2_drive()

    if port:
        ok(f"Pico detected in MicroPython/REPL mode on {port}")
        check_firmware_version(port)
    elif uf2_drive:
        ok(f"Pico detected in BOOTSEL mode — mass storage at {uf2_drive}")
        info("The Pico is in BOOTSEL mode (firmware flash mode).")
        info("  To use REPL/script operations: disconnect, then reconnect WITHOUT holding BOOTSEL")
        info("  To flash firmware: use 'Flash UF2 Firmware' from the menu")
        port = "BOOTSEL"
    else:
        err("Device appeared but could not be resolved. Exiting.")
        info("Debug: check 'dmesg | tail -20' or 'ls /dev/ttyACM*'")
        sys.exit(1)

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw, port)
        return

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Device Info (serial port metadata + MicroPython version)",
        "FIRMWARE - Flash UF2 Firmware (copy .uf2 to RPI-RP2 drive)",
        "FIRMWARE - Flash MicroPython (guided download + UF2 flash)",
        "Upload Python Script (mpremote cp)",
        "Run Python Script (mpremote run, no storage)",
        "REPL Connection Info (mpremote, minicom, screen, picocom)",
        "Exit",
    ]

    while True:
        heading(f"{TOOL_NAME} — Main Menu")
        if port and port != "BOOTSEL":
            info(f"Active port: {port}")
        elif uf2_drive:
            info(f"Active mode: BOOTSEL  (drive: {uf2_drive})")
        info("")

        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)

        if choice == 0:
            if port and port != "BOOTSEL":
                op_device_info(port)
            else:
                warn("Device is in BOOTSEL mode — REPL operations unavailable.")
                info("Reconnect without holding BOOTSEL to enter MicroPython mode.")
        elif choice == 1:
            op_flash_uf2(port if port != "BOOTSEL" else None)
        elif choice == 2:
            op_flash_micropython()
        elif choice == 3:
            if port and port != "BOOTSEL":
                op_upload_script(port)
            else:
                warn("Device is in BOOTSEL mode — REPL operations unavailable.")
                info("Reconnect without holding BOOTSEL to enter MicroPython mode.")
        elif choice == 4:
            if port and port != "BOOTSEL":
                op_run_script(port)
            else:
                warn("Device is in BOOTSEL mode — REPL operations unavailable.")
                info("Reconnect without holding BOOTSEL to enter MicroPython mode.")
        elif choice == 5:
            op_repl_info()
        elif choice == 6:
            info("Goodbye.")
            break

        # Re-check port after operations (device may re-enumerate after a flash)
        info("")
        info("Re-scanning for device after operation…")
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        new_drive = _find_uf2_drive()
        if new_port and new_port != port:
            port = new_port
            ok(f"Serial port updated to {port}")
        elif new_drive and new_drive != uf2_drive:
            uf2_drive = new_drive
            port = "BOOTSEL"
            ok(f"Pico re-detected in BOOTSEL mode at {uf2_drive}")
        elif new_port:
            info(f"Port unchanged: {port}")


if __name__ == "__main__":
    main()
