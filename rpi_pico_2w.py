#!/usr/bin/env python3
"""
Raspberry Pi Pico 2W Tool Manager
Handles device info, UF2 flashing, MicroPython installation, WiFi setup, and
script upload for the Raspberry Pi Pico 2W (RP2350, dual Cortex-M33 + RISC-V).

Key differences from original Pico / Pico W:
  - RP2350 chip (2024), NOT RP2040.  Firmware is NOT cross-compatible.
  - BOOTSEL volume appears as RPI-RP2350 (not RPI-RP2 as on Pico/Pico W).
  - Dual-architecture: Cortex-M33 cores + RISC-V hazard3 cores (selectable at build time).
  - MicroPython build: rp2-pico2-w  (https://micropython.org/download/rp2-pico2-w/)
  - WiFi/BT: Infineon CYW43439 (same chip as Pico W).

USB-serial identifiers:
  Pico 2W running MicroPython CDC  — VID:PID 2E8A:0005
  Pico 2W running Arduino CDC      — VID:PID 2E8A:000A
  Pico 2W CDC (specific variant)   — VID:PID 2E8A:000F
  BOOTSEL / Mass-Storage mode      — VID:PID 2E8A:000F (also used as UF2 drive)

Linux serial access:
  The Pico 2W CDC device appears as /dev/ttyACM*.
  If you get 'Permission denied': sudo usermod -aG dialout $USER
  then log out and back in.

Usage:
    python3 rpi_pico_2w.py
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
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Raspberry Pi Pico 2W"
DESCRIPTION = "Raspberry Pi Pico 2W — RP2350 with WiFi/BT (dual Cortex-M33 + RISC-V)"

# Running-mode VID:PID combinations (CDC serial)
VID_PIDS = [
    (0x2E8A, 0x0005),   # Pico 2W MicroPython CDC
    (0x2E8A, 0x000A),   # Pico 2W Arduino CDC
    (0x2E8A, 0x000F),   # Pico 2W specific CDC / BOOTSEL
]

# BOOTSEL (UF2 mass-storage) mode identifier
UF2_VID_PID = (0x2E8A, 0x000F)

# RP2350-specific BOOTSEL volume name (NOT RPI-RP2 — that is RP2040 only!)
BOOTSEL_VOLUME_NAME = "RPI-RP2350"
BOOTSEL_VOLUME_FALLBACK = "RPI-RP2"   # fallback for some older Pico W boards, not Pico 2W

CONNECT_INSTRUCTIONS = (
    "Raspberry Pi Pico 2W (RP2350) not detected.\n\n"
    "  1. Connect the board via USB-C cable.\n"
    "     The Pico 2W uses the RP2350 chip (2024 revision).\n\n"
    "  2. The device will appear as /dev/ttyACM* when running MicroPython or\n"
    "     Arduino firmware (USB CDC serial).\n\n"
    "  3. VID:PID combinations recognised:\n"
    "       2E8A:0005 — MicroPython CDC\n"
    "       2E8A:000A — Arduino CDC\n"
    "       2E8A:000F — Specific CDC / BOOTSEL mode\n\n"
    "  4. BOOTSEL procedure (for firmware flashing):\n"
    "       a. Unplug USB.\n"
    "       b. Hold the BOOTSEL button on the board.\n"
    "       c. Plug USB back in while still holding BOOTSEL.\n"
    "       d. Release BOOTSEL. The board mounts as a USB mass-storage drive.\n"
    "       e. The drive is named RPI-RP2350 (RP2350 chip, NOT RPI-RP2).\n\n"
    "  5. IMPORTANT — RP2350 firmware is NOT compatible with RP2040:\n"
    "       Do NOT flash Pico W (RP2040) firmware onto the Pico 2W.\n"
    "       Always download rp2-pico2-w builds from micropython.org.\n\n"
    "  6. Permission issues (Linux):\n"
    "       Check:  ls -la /dev/ttyACM*\n"
    "       Fix:    sudo usermod -aG dialout $USER  (then log out/in)\n"
    "       Quick:  sudo chmod 666 /dev/ttyACM0\n\n"
    "  7. macOS: no driver needed for built-in USB CDC.\n"
    "       Device appears as /dev/cu.usbmodem*"
)

UDEV_RULES_CONTENT = """\
# Raspberry Pi Pico 2W (RP2350) udev rules
# MicroPython CDC (VID:PID 2E8A:0005)
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0005", MODE="0666", GROUP="dialout"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0005", MODE="0666", GROUP="dialout"
# Arduino CDC (VID:PID 2E8A:000A)
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000a", MODE="0666", GROUP="dialout"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000a", MODE="0666", GROUP="dialout"
# Pico 2W specific CDC / BOOTSEL (VID:PID 2E8A:000F)
SUBSYSTEM=="tty", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000f", MODE="0666", GROUP="dialout"
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="000f", MODE="0666", GROUP="dialout"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-rpi-pico-2w.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    """Return True if any known Pico 2W VID:PID is present on a serial port."""
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for the Pico 2W on Linux systems."""
    flavor = get_os_flavor()
    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only apply to Linux — skipping on this OS.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Raspberry Pi Pico 2W (2E8A vendor)…")
    info("These rules grant non-root users access to /dev/ttyACM* devices.")
    info(f"Target file: {UDEV_RULES_PATH}")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    try:
        tmp.write_text(UDEV_RULES_CONTENT)
        r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
        tmp.unlink(missing_ok=True)
        if r.returncode == 0:
            sudo_run("udevadm control --reload-rules 2>/dev/null")
            sudo_run("udevadm trigger 2>/dev/null")
            ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
            info("Unplug and replug the Pico 2W to apply new permissions.")
        else:
            warn("Could not write udev rules automatically.")
            info(f"Manual fix: sudo tee {UDEV_RULES_PATH} with the following content:")
            info(UDEV_RULES_CONTENT)
            info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")
    except Exception as e:
        err(f"Error writing udev rules: {e}")
        tmp.unlink(missing_ok=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_file(path_str: str, ext: str = None) -> Path | None:
    """Validate that a file path exists and optionally check the extension."""
    if not path_str:
        warn("No file path provided. Aborting.")
        return None
    p = Path(path_str)
    if not p.exists():
        err(f"File not found: {p}")
        info("Tip: use an absolute path, e.g. /home/user/firmware.uf2")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


def _find_bootsel_volume() -> Path | None:
    """Locate the RPI-RP2350 BOOTSEL mass-storage volume on the host."""
    info("Searching for BOOTSEL mass-storage volume…")
    os_name = get_os()

    # Linux: look under /media for the volume
    if os_name == "linux":
        info("  Checking /media/*/RPI-RP2350 (Linux mount points)…")
        for candidate in Path("/media").glob("*/RPI-RP2350"):
            if candidate.is_dir():
                ok(f"  Found RP2350 BOOTSEL volume: {candidate}")
                return candidate
        # Fallback: some older Linux automounters may use /run/media or /mnt
        for base in ["/run/media", "/mnt"]:
            for candidate in Path(base).glob("*/RPI-RP2350"):
                if candidate.is_dir():
                    ok(f"  Found RP2350 BOOTSEL volume: {candidate}")
                    return candidate
        # Fallback: check for RPI-RP2 (Pico W / Pico — warn the user)
        info("  RPI-RP2350 not found. Checking fallback RPI-RP2 volume…")
        for candidate in Path("/media").glob("*/RPI-RP2"):
            if candidate.is_dir():
                warn(f"  Found RPI-RP2 volume (RP2040 Pico/Pico W): {candidate}")
                warn("  This is the WRONG volume for the Pico 2W (RP2350).")
                warn("  If this is intentional (flashing a Pico W), use rpi_pico_w.py instead.")
                if confirm("Use this volume anyway?", default=False):
                    return candidate
        return None

    # macOS: look under /Volumes
    elif os_name == "macos":
        info("  Checking /Volumes/RPI-RP2350 (macOS mount point)…")
        candidate = Path("/Volumes/RPI-RP2350")
        if candidate.is_dir():
            ok(f"  Found RP2350 BOOTSEL volume: {candidate}")
            return candidate
        # Fallback: RPI-RP2
        info("  RPI-RP2350 not found. Checking fallback /Volumes/RPI-RP2…")
        fallback = Path("/Volumes/RPI-RP2")
        if fallback.is_dir():
            warn(f"  Found RPI-RP2 volume (RP2040 board): {fallback}")
            warn("  This is the WRONG volume for the Pico 2W (RP2350).")
            warn("  If you meant to flash a Pico/Pico W, use rpi_pico_w.py instead.")
            if confirm("Use this volume anyway?", default=False):
                return fallback
        return None

    else:
        warn(f"Unsupported OS for BOOTSEL volume detection: {os_name}")
        return None


def _run_mpremote(args: list, timeout: int = 30) -> int:
    """Run mpremote with the given arguments, streaming output."""
    cmd = ["mpremote"] + args
    info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.stdout:
            for line in result.stdout.splitlines():
                info(f"  mpremote: {line}")
        if result.returncode != 0 and result.stderr:
            for line in result.stderr.splitlines():
                warn(f"  mpremote stderr: {line}")
        return result.returncode
    except FileNotFoundError:
        err("mpremote not found. Install: pip install mpremote --break-system-packages")
        return 1
    except subprocess.TimeoutExpired:
        err(f"mpremote timed out after {timeout}s.")
        return 1
    except Exception as e:
        err(f"mpremote error: {e}")
        return 1


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    """Display serial port metadata and query MicroPython version via mpremote."""
    heading("Device Info")
    info(f"Serial port  : {port}")
    info(f"Chip family  : RP2350 (Raspberry Pi Pico 2W)")
    info(f"Chip note    : RP2350 is the 2024-generation chip — NOT RP2040.")
    info(f"               Dual Cortex-M33 cores + optional RISC-V hazard3 cores.")
    info(f"WiFi chip    : Infineon CYW43439 (same as Pico W)")
    info("")
    info("Reading serial port metadata…")
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.device == port:
                info(f"  Description  : {p.description}")
                info(f"  Manufacturer : {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID      : {vid}:{pid}")
                info(f"  Serial num   : {p.serial_number or 'N/A'}")
    except Exception as e:
        warn(f"Could not read serial port metadata: {e}")

    info("")
    info("Querying MicroPython version via mpremote…")
    info("  (This will fail if the board is running Arduino firmware — that is normal.)")
    try:
        result = subprocess.run(
            ["mpremote", "connect", port, "exec",
             "import sys; print('MicroPython:', sys.version); "
             "import os; inf = os.uname(); "
             "print('sysname:', inf.sysname); "
             "print('machine:', inf.machine); "
             "print('release:', inf.release)"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                ok(f"  {line}")
        else:
            warn("  MicroPython version query failed — board may not be running MicroPython.")
            if result.stderr:
                info(f"  stderr: {result.stderr.strip()[:200]}")
    except FileNotFoundError:
        warn("mpremote not installed — cannot query MicroPython version.")
        info("Install: pip install mpremote --break-system-packages")
    except subprocess.TimeoutExpired:
        warn("MicroPython version query timed out (10s). Board may be busy or not running MicroPython.")
    except Exception as e:
        warn(f"Version query error: {e}")

    info("")
    info("Troubleshooting:")
    info("  'Permission denied' → sudo usermod -aG dialout $USER  then log out/in")
    info("  'No module named ...' → board is not running MicroPython; flash MicroPython first")
    info("  Blank output → try: screen {port} 115200  or  minicom -D {port} -b 115200")


def op_flash_uf2(port: str = None):
    """Flash a .uf2 file by copying it to the BOOTSEL mass-storage volume."""
    heading("Flash UF2 Firmware")
    info("UF2 flashing is the simplest way to program the Pico 2W.")
    info("The board must be in BOOTSEL mode (mass-storage drive) to proceed.")
    info("")
    info("BOOTSEL procedure for Pico 2W (RP2350):")
    info("  1. Unplug the USB cable.")
    info("  2. Hold the BOOTSEL button on the board.")
    info("  3. Plug the USB cable back in while still holding BOOTSEL.")
    info("  4. Release BOOTSEL. The board mounts as a drive named RPI-RP2350.")
    info("     (RP2040 boards mount as RPI-RP2 — different name!)")
    info("  5. Copy your .uf2 file to that drive — the board reboots automatically.")
    info("")
    info("Where to get .uf2 files:")
    info("  MicroPython for Pico 2W : https://micropython.org/download/rp2-pico2-w/")
    info("  CircuitPython           : https://circuitpython.org/board/raspberry_pi_pico2_w/")
    info("  Custom firmware         : build with Pico SDK (RP2350 target)")
    info("")
    warn("Do NOT flash RP2040 .uf2 files onto the Pico 2W — incompatible chip!")
    info("")

    fw_path = prompt("Path to .uf2 firmware file")
    fw = _require_file(fw_path, ".uf2")
    if not fw:
        return

    info("Searching for BOOTSEL volume…")
    vol = _find_bootsel_volume()
    if not vol:
        err("BOOTSEL volume not found.")
        info("Ensure you held BOOTSEL while connecting USB.")
        info("Linux: check 'lsblk' or 'ls /media/$USER/' for the RPI-RP2350 mount.")
        info("macOS: check Finder or 'ls /Volumes/' for the RPI-RP2350 volume.")
        return

    dest = vol / fw.name
    info(f"Volume found  : {vol}")
    info(f"Source file   : {fw}  ({fw.stat().st_size // 1024} KB)")
    info(f"Destination   : {dest}")
    if not confirm(f"Copy {fw.name} to {vol}?"):
        info("Cancelled.")
        return

    info("Copying .uf2 file…  The board will reboot automatically when done.")
    try:
        shutil.copy2(str(fw), str(dest))
        ok("UF2 file copied successfully.")
        ok("The Pico 2W is now rebooting and running the new firmware.")
        info("Wait ~3 seconds, then check for the device on a serial port (/dev/ttyACM*).")
    except PermissionError as e:
        err(f"Permission error copying to BOOTSEL volume: {e}")
        info("Try: sudo cp {fw} {dest}")
    except Exception as e:
        err(f"Copy failed: {e}")
        info("Troubleshooting: ensure the volume is still mounted and the .uf2 file is valid.")


def op_flash_micropython_2w():
    """Flash the RP2350-specific MicroPython build for the Pico 2W via BOOTSEL."""
    heading("Flash MicroPython for Pico 2W (RP2350)")
    info("This operation installs the official MicroPython build for the Pico 2W.")
    info("")
    warn("CRITICAL — RP2350 firmware compatibility:")
    warn("  The Pico 2W uses the RP2350 chip (2024).")
    warn("  The original Pico and Pico W use the RP2040 chip.")
    warn("  RP2350 firmware is NOT compatible with RP2040 and vice versa.")
    warn("  Flashing RP2040 MicroPython onto a Pico 2W will NOT work.")
    info("")
    info("Correct MicroPython download URL for Pico 2W:")
    info("  https://micropython.org/download/rp2-pico2-w/")
    info("  Build name: RPI_PICO2_W-<version>.uf2")
    info("  Look for builds tagged 'rp2-pico2-w' or 'RP2350' — NOT 'rp2-pico-w'.")
    info("")
    info("WRONG builds (do NOT use on Pico 2W):")
    info("  rp2-pico-w  — for Pico W (RP2040)")
    info("  rp2-pico    — for original Pico (RP2040)")
    info("  ESP32 .bin  — completely different architecture")
    info("")
    info("After flashing, the Pico 2W will run MicroPython with WiFi support.")
    info("Access the REPL: mpremote connect /dev/ttyACM0 repl")
    info("")
    info("Proceeding to UF2 flash (BOOTSEL method)…")
    # Delegate to UF2 flash operation since MicroPython for Pico uses the same UF2 method
    op_flash_uf2()


def op_wifi_info(port: str):
    """Display WiFi setup information for the Pico 2W under MicroPython."""
    heading("WiFi Setup (Pico 2W MicroPython)")
    info("The Pico 2W uses the Infineon CYW43439 combo chip for WiFi + Bluetooth.")
    info("This is the same chip as the original Pico W — driver API is identical.")
    info("")
    info("MicroPython network module quick reference:")
    info("")
    info("  import network")
    info("  wlan = network.WLAN(network.STA_IF)")
    info("  wlan.active(True)")
    info("  wlan.connect('SSID', 'password')")
    info("  while not wlan.isconnected():")
    info("      pass")
    info("  print('IP:', wlan.ifconfig()[0])")
    info("")
    info("Scan for networks:")
    info("  wlan.scan()  # returns list of (ssid, bssid, channel, RSSI, security, hidden)")
    info("")
    info("Access Point mode:")
    info("  ap = network.WLAN(network.AP_IF)")
    info("  ap.config(essid='PicoAP', password='test1234', authmode=3)  # 3=WPA2")
    info("  ap.active(True)")
    info("")
    info("WiFi country code (important for regulatory compliance):")
    info("  import rp2")
    info("  rp2.country('US')   # or 'GB', 'DE', etc.")
    info("")
    info("Bluetooth (via bluetooth module):")
    info("  import bluetooth")
    info("  ble = bluetooth.BLE()")
    info("  ble.active(True)")
    info("  # See MicroPython BLE examples for advertising / scanning")
    info("")
    info("Testing WiFi connectivity on device now via mpremote…")
    try:
        result = subprocess.run(
            ["mpremote", "connect", port, "exec",
             "import network; w = network.WLAN(network.STA_IF); w.active(True); "
             "print('WiFi active:', w.active()); print('Connected:', w.isconnected()); "
             "nets = w.scan(); print('Networks found:', len(nets)); "
             "[print(' ', n[0].decode() if isinstance(n[0], bytes) else n[0], "
             "       'ch:', n[2], 'RSSI:', n[3]) for n in nets[:8]]"],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode == 0 and result.stdout.strip():
            ok("WiFi scan results:")
            for line in result.stdout.splitlines():
                info(f"  {line}")
        else:
            warn("WiFi scan failed — board may not be running MicroPython or WiFi driver issue.")
            if result.stderr:
                info(f"  stderr: {result.stderr.strip()[:200]}")
    except FileNotFoundError:
        warn("mpremote not installed — cannot run WiFi scan.")
    except subprocess.TimeoutExpired:
        warn("WiFi scan timed out (20s).")
    except Exception as e:
        warn(f"WiFi scan error: {e}")


def op_upload_script(port: str):
    """Upload a Python script to the Pico 2W filesystem via mpremote."""
    heading("Upload MicroPython Script")
    info("Transfers a local .py file to the Pico 2W's MicroPython filesystem.")
    info("")
    info("mpremote quick reference:")
    info(f"  mpremote connect {port} repl              — interactive REPL (Ctrl+] to exit)")
    info(f"  mpremote connect {port} ls :/              — list filesystem root")
    info(f"  mpremote connect {port} cp file.py :/      — upload file to root")
    info(f"  mpremote connect {port} rm :/file.py       — delete file from device")
    info(f"  mpremote connect {port} run file.py        — run without storing")
    info("")
    info("Boot-time scripts:")
    info("  main.py  — runs automatically on every boot")
    info("  boot.py  — runs before main.py (hardware init)")
    info("")
    info("Troubleshooting:")
    info("  'Could not enter raw repl' → Board not running MicroPython; flash MicroPython first.")
    info("  'serial.SerialException'   → Wrong port, or another terminal has it open.")
    info("  'mpremote: not found'      → pip install mpremote --break-system-packages")
    info("")

    local_path = prompt("Path to local .py file")
    local = _require_file(local_path, ".py")
    if not local:
        return

    remote_name = prompt(f"Remote filename on device (default: {local.name})")
    if not remote_name:
        remote_name = local.name

    if not remote_name.startswith(":"):
        remote_dest = f":/{remote_name}"
    else:
        remote_dest = remote_name

    info(f"Uploading {local} → {remote_dest} on {port}…")
    rc = _run_mpremote(["connect", port, "cp", str(local), remote_dest], timeout=30)
    if rc == 0:
        ok(f"Uploaded: {remote_dest}")
        info(f"To run:   mpremote connect {port} run {local.name}")
        info(f"  Or REPL: mpremote connect {port} repl  (then exec(open('{local.name}').read()))")
    else:
        err("Upload failed. See output above.")
        info("Retry: ensure the board is in MicroPython mode and no other process holds the port.")


def op_repl_info():
    """Print REPL connection instructions for the Pico 2W."""
    heading("MicroPython REPL — Pico 2W")
    info("Access the interactive MicroPython prompt on the Pico 2W.")
    info("")
    info("Option 1 — mpremote (recommended):")
    info("  mpremote connect /dev/ttyACM0 repl")
    info("  Ctrl+]  — exit mpremote REPL")
    info("  Ctrl+C  — KeyboardInterrupt (stop running code)")
    info("  Ctrl+D  — soft reset (restart interpreter)")
    info("")
    info("Option 2 — minicom:")
    info("  minicom -D /dev/ttyACM0 -b 115200")
    info("  Ctrl+A then X — exit minicom")
    info("")
    info("Option 3 — screen:")
    info("  screen /dev/ttyACM0 115200")
    info("  Ctrl+A then K — kill session")
    info("")
    info("Option 4 — picocom:")
    info("  picocom /dev/ttyACM0 -b 115200")
    info("  Ctrl+A Ctrl+X — exit")
    info("")
    info("macOS port names:")
    info("  ls /dev/cu.usbmodem*  — find the Pico 2W port")
    info("  mpremote connect /dev/cu.usbmodem1101 repl")
    info("")
    info("Useful RP2350 MicroPython one-liners:")
    info("  import os; os.listdir('/')              # list files on device")
    info("  import machine; machine.reset()         # hard reset")
    info("  import rp2; rp2.country('US')           # set WiFi country code")
    info("  import network; n = network.WLAN(network.STA_IF); n.active(True); n.scan()")
    info("  import sys; print(sys.implementation)  # MicroPython version info")
    info("  import gc; gc.collect(); gc.mem_free()  # free heap memory")


def op_run_ducky_payload():
    """Describe the DuckyScript runner payload for the Pico 2W."""
    heading("DuckyScript Runner Payload")
    info("The Pico 2W can act as a USB HID keyboard to execute DuckyScript payloads.")
    info("")
    info("Payload location:")
    info("  payloads/rpi_pico_2w/ducky-runner/")
    info("    main.py     — DuckyScript interpreter that runs on boot")
    info("    payload.dd  — your DuckyScript payload file")
    info("")
    info("How it works:")
    info("  1. main.py implements a DuckyScript parser using the 'adafruit_hid' library.")
    info("  2. On boot, it reads payload.dd and replays the keystrokes to the host.")
    info("  3. The Pico 2W presents as a standard USB HID keyboard — no driver needed.")
    info("")
    info("Setup instructions:")
    info("  Step 1: Flash MicroPython for Pico 2W (rp2-pico2-w .uf2).")
    info("          URL: https://micropython.org/download/rp2-pico2-w/")
    info("")
    info("  Step 2: Install adafruit_hid library via mpremote:")
    info("          mpremote connect <port> mip install adafruit-circuitpython-hid")
    info("          (or copy manually: mpremote connect <port> cp adafruit_hid/ :/adafruit_hid/)")
    info("")
    info("  Step 3: Upload main.py:")
    info("          mpremote connect <port> cp payloads/rpi_pico_2w/ducky-runner/main.py :/main.py")
    info("")
    info("  Step 4: Write your DuckyScript payload (payload.dd).")
    info("          Example payload.dd:")
    info("            DELAY 2000")
    info("            GUI r")
    info("            DELAY 500")
    info("            STRING cmd")
    info("            ENTER")
    info("")
    info("  Step 5: Upload payload.dd:")
    info("          mpremote connect <port> cp payloads/rpi_pico_2w/ducky-runner/payload.dd :/payload.dd")
    info("")
    info("  Step 6: Unplug and replug the Pico 2W into the target machine.")
    info("          main.py runs automatically on boot and replays the DuckyScript.")
    info("")
    info("Supported DuckyScript commands:")
    info("  REM, DELAY, STRING, ENTER, GUI, CTRL, ALT, SHIFT, TAB, ESCAPE, DELETE, etc.")
    info("")
    info("WiFi exfil variant:")
    info("  payloads/rpi_pico_2w/ may also contain WiFi exfil payloads (if present).")
    info("  These use the CYW43439 WiFi to send captured data to a remote server.")
    info("")
    warn("For educational/authorised testing only. Ensure you have permission before use.")


def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Checking MicroPython version on Raspberry Pi Pico 2W...")
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
            announce_firmware_update("Pico 2W MicroPython", current, latest.lstrip("v"), url)
        else:
            warn("Could not check GitHub for latest version.")
    else:
        info("MicroPython not detected. If it's installed, the REPL may not be responding.")
        info("Download latest Pico 2W MicroPython: https://micropython.org/download/rp2-pico2-w/")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    flavor = get_os_flavor()

    info("Checking for pyserial (required for serial port enumeration)…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  Trying apt: python3-serial")
        ensure_apt_packages(["python3-serial"])
    info("  Checking pip for pyserial…")
    ensure_pip_packages([("serial", "pyserial")])

    info("Checking for mpremote (required for MicroPython file/REPL access)…")
    ensure_pip_packages([("mpremote", "mpremote")])

    info("Dependency check complete.")

    # ── Linux udev rules ──────────────────────────────────────────────────────
    _check_udev_rules()

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    info("Scanning for Raspberry Pi Pico 2W via VID:PID matching…")
    info("Expected VID:PID values: 2E8A:0005, 2E8A:000A, 2E8A:000F")
    info("Expected port: /dev/ttyACM* (Linux) or /dev/cu.usbmodem* (macOS)")
    info("")
    info("If you want to flash via BOOTSEL (UF2), connect in BOOTSEL mode and")
    info("skip detection — the board will appear as a mass-storage drive only.")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Pico 2W not detected within timeout. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Device appeared but serial port could not be resolved.")
        info("Debug: check 'dmesg | tail -20' or 'ls /dev/ttyACM*'")
        sys.exit(1)

    ok(f"Raspberry Pi Pico 2W detected on {port}")
    if port:
        check_firmware_version(port)

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Device Info (serial metadata + MicroPython version)",
        "Flash UF2 Firmware (BOOTSEL mass-storage copy)",
        "Flash MicroPython for Pico 2W (RP2350-specific build)",
        "WiFi Setup Info + Live Scan (MicroPython CYW43439)",
        "Upload MicroPython Script (mpremote cp)",
        "REPL Connection Info",
        "DuckyScript Runner Payload Info",
        "Exit",
    ]

    while True:
        try:
            choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)
        except (KeyboardInterrupt, EOFError):
            info("\nInterrupted. Goodbye.")
            break

        try:
            if choice == 0:
                op_device_info(port)
            elif choice == 1:
                op_flash_uf2(port)
            elif choice == 2:
                op_flash_micropython_2w()
            elif choice == 3:
                op_wifi_info(port)
            elif choice == 4:
                op_upload_script(port)
            elif choice == 5:
                op_repl_info()
            elif choice == 6:
                op_run_ducky_payload()
            elif choice == 7:
                info("Goodbye.")
                break
        except KeyboardInterrupt:
            info("\nOperation interrupted. Returning to menu.")
            continue
        except Exception as e:
            err(f"Unexpected error in operation: {e}")
            info("Returning to menu.")
            continue

        # Re-check port after operations (device may re-enumerate after flash)
        try:
            new_port = find_serial_port_by_vidpid(VID_PIDS)
            if new_port and new_port != port:
                port = new_port
                info(f"Serial port updated to {port} (device re-enumerated).")
        except Exception as e:
            warn(f"Could not re-check serial port: {e}")


if __name__ == "__main__":
    main()
