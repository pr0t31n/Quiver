#!/usr/bin/env python3
"""
Chameleon Ultra Tool Manager
Handles slot management, card scanning, auth logging, cloning, and firmware
updates via the official ChameleonUltra CLI subprocess.

Usage:
    python3 chameleon_ultra.py

Prerequisites:
    Clone the official ChameleonUltra repository into the quiver directory:

        git clone https://github.com/RfidResearchGroup/ChameleonUltra.git

    Install the CLI's Python dependencies:

        pip install -r ChameleonUltra/software/script/requirements.txt --break-system-packages

    nrfutil for DFU firmware update:

        pip install nrfutil --break-system-packages
        nrfutil install device

Slot type descriptions:
    MIFARE_Mini   — 320 bytes, 5 sectors (rare, some old Philips/NXP systems)
    MIFARE_1024   — MIFARE Classic 1K, 16 sectors, 1024 bytes (most common)
    MIFARE_2048   — MIFARE Classic 2K (rare variant)
    MIFARE_4096   — MIFARE Classic 4K, 40 sectors (transit cards, high capacity)
    MIFARE_UL     — MIFARE Ultralight (48 bytes, NFC tags, small tickets)
    MIFARE_UL_C   — MIFARE Ultralight C (3DES authentication)
    NTAG_213      — NXP NTAG213 (144 bytes, URL/text NFC tags)
    NTAG_215      — NXP NTAG215 (504 bytes, Amiibo compatible)
    NTAG_216      — NXP NTAG216 (888 bytes, max capacity NTAG)
    EM410X        — EM4100 / EM4102 LF 125 kHz proximity (most common LF)
    HID_26        — HID Prox 26-bit Wiegand LF (corporate access cards)

DFU mode:
    Hold button B while plugging in USB-C to enter DFU (firmware update) mode.
    DFU mode VID:PID is 1915:521F. Solid LED indicates DFU mode.

Linux serial permissions:
    Device appears as /dev/ttyACM* in normal mode.
    Add user to dialout group: sudo usermod -aG dialout $USER
"""

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, ensure_pip_packages, ensure_system_tool,
    web_detect_loop, run_streaming,
    require_sudo, sudo_run, sudo_output, run_streaming_sudo,
    ensure_apt_packages, ensure_brew_packages, get_os_flavor,
    check_latest_github_release, compare_versions, announce_firmware_update,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Chameleon Ultra"
DESCRIPTION = "Advanced RFID emulator and reader — HF + LF dual-band"

SCRIPT_DIR  = Path(__file__).parent.resolve()
CLI_REL     = Path("ChameleonUltra") / "software" / "script" / "chameleon_cli_main.py"
CLI_PATH    = SCRIPT_DIR / CLI_REL

VID_PID_CDC = [(0x6868, None)]    # Nordic nRF52840, any PID
VID_PID_DFU = [(0x1915, 0x521F)]  # DFU mode

BAUD_RATE   = 115200

CONNECT_INSTRUCTIONS = (
    "Chameleon Ultra not detected.\n\n"
    "  1. Connect Chameleon Ultra via USB-C cable\n"
    "  2. Wait for the LED to indicate connection\n\n"
    "  Prerequisite — clone the official repo:\n"
    "    cd /path/to/quiver\n"
    "    git clone https://github.com/RfidResearchGroup/ChameleonUltra.git\n"
    "    pip install -r ChameleonUltra/software/script/requirements.txt --break-system-packages\n\n"
    "  Linux permission fix:\n"
    "    sudo usermod -aG dialout $USER  (then log out/in)\n"
    "    Verify: ls -la /dev/ttyACM*\n"
    "    Debug:  dmesg | tail -20\n\n"
    "  DFU mode (firmware update): hold button B while plugging in USB"
)

SLOT_TYPES = [
    "MIFARE_Mini",
    "MIFARE_1024",
    "MIFARE_2048",
    "MIFARE_4096",
    "MIFARE_UL",
    "MIFARE_UL_C",
    "NTAG_213",
    "NTAG_215",
    "NTAG_216",
    "EM410X",
    "HID_26",
]

# ── Firmware version check ────────────────────────────────────────────────────

def _get_current_version(port: str) -> str:
    """
    Return the firmware version from the Chameleon Ultra via the CLI 'hw info'
    command, or '' on failure.
    """
    try:
        if not CLI_PATH.exists():
            return ""
        proc = subprocess.Popen(
            [sys.executable, str(CLI_PATH)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env={**os.environ, "CHAMELEON_PORT": port},
        )
        proc.stdin.write("hw info\n")
        proc.stdin.write("exit\n")
        proc.stdin.flush()
        proc.stdin.close()
        output, _ = proc.communicate(timeout=15)
        for line in output.splitlines():
            stripped = line.strip()
            # CLI output includes lines like "Firmware version: x.y.z"
            if "firmware" in stripped.lower() and "version" in stripped.lower():
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip().split()[0]
        return ""
    except Exception:
        return ""


def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Checking installed firmware version...")
    current = _get_current_version(port)
    if not current:
        warn("Could not determine installed firmware version.")
        info("Continuing without version check.")
        return
    ok(f"Installed firmware: {current}")

    info("Checking latest available version on GitHub...")
    latest, release_url = check_latest_github_release("RfidResearchGroup", "ChameleonUltra")
    if not latest:
        warn("Could not reach GitHub. Skipping version check.")
        return

    wants_update = announce_firmware_update(TOOL_NAME, current, latest, release_url)
    if wants_update:
        op_firmware_update(port)


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_chameleon() -> bool:
    return find_serial_port_by_vidpid(VID_PID_CDC) is not None


def detect_chameleon_dfu() -> bool:
    return find_serial_port_by_vidpid(VID_PID_DFU) is not None


# ── dialout group check ───────────────────────────────────────────────────────

def _check_dialout(port: str):
    """Check dialout group membership; offer to add user if missing."""
    import grp
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    try:
        dialout_gid = grp.getgrnam("dialout").gr_gid
        if dialout_gid in os.getgroups():
            return
    except KeyError:
        return

    warn(f"User '{username}' may not be in the 'dialout' group.")
    info("This causes 'Permission denied' on /dev/ttyACM* serial devices.")
    info(f"  Verify: id {username}   and   ls -la {port}")
    if confirm(f"Add '{username}' to the 'dialout' group now?", default=True):
        rc = sudo_run(f"usermod -aG dialout {username}")
        if rc.returncode == 0:
            ok(f"Added '{username}' to dialout. Log out/in or run: newgrp dialout")
        else:
            err("Failed. Try manually: sudo usermod -aG dialout $USER")


# ── CLI helpers ───────────────────────────────────────────────────────────────

def _check_cli() -> bool:
    if CLI_PATH.exists():
        return True
    err(f"Chameleon CLI not found at: {CLI_PATH}")
    info("You must clone the ChameleonUltra repository first:")
    info(f"  cd {SCRIPT_DIR}")
    info("  git clone https://github.com/RfidResearchGroup/ChameleonUltra.git")
    info("  pip install -r ChameleonUltra/software/script/requirements.txt --break-system-packages")
    info("")
    info("After cloning, the expected CLI path will be:")
    info(f"  {CLI_PATH}")
    info("")
    info("If you cloned to a different location, create a symlink:")
    info(f"  ln -s /path/to/ChameleonUltra {SCRIPT_DIR / 'ChameleonUltra'}")
    return False


def _cli_command(port: str, command: str, timeout: int = 30) -> tuple:
    """
    Run a single command through the Chameleon CLI using Popen with stdin/stdout pipe.
    Sends the command string followed by newline, then 'exit', and collects output.
    Returns (returncode, output_lines).
    """
    if not _check_cli():
        return 1, []

    cmd = [sys.executable, str(CLI_PATH)]
    lines_out = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env={**os.environ, "CHAMELEON_PORT": port},
        )

        # Send command then exit
        proc.stdin.write(command + "\n")
        proc.stdin.write("exit\n")
        proc.stdin.flush()
        proc.stdin.close()

        deadline = time.time() + timeout
        for line in proc.stdout:
            stripped = line.rstrip()
            if stripped:
                lines_out.append(stripped)
        proc.wait(timeout=max(1, int(deadline - time.time())))
        return proc.returncode or 0, lines_out

    except subprocess.TimeoutExpired:
        proc.kill()
        warn(f"CLI command timed out after {timeout}s.")
        info("If commands consistently time out, check that the device is responsive:")
        info("  Try: screen /dev/ttyACM0 115200  to verify REPL is responding")
        return 1, lines_out
    except Exception as e:
        err(f"CLI execution error: {e}")
        info("Ensure the CLI script and its dependencies are installed correctly.")
        return 1, lines_out


def _run_cli_op(port: str, command: str, timeout: int = 30):
    """Run a CLI command and stream output via info()."""
    info(f"Running: {command}")
    rc, lines = _cli_command(port, command, timeout=timeout)
    for line in lines:
        info(line)
    if rc == 0:
        ok(f"Command completed: {command}")
    else:
        warn(f"Command returned non-zero exit code: {rc}")
        info("Check output above for error details.")
        info(f"  Device port: {port}")
        info("  Try reconnecting the Chameleon Ultra.")
    return rc, lines


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Queries hardware info from the Chameleon Ultra via CLI: 'hw info'")
    info("Expected output: firmware version, hardware version, chip ID.")
    info("If no output, ensure the device is connected and not in DFU mode.")
    _run_cli_op(port, "hw info")


def op_slot_status(port: str):
    heading("Slot Status")
    info("Lists all 8 emulation slots and their current configuration.")
    info("Each slot can independently emulate a different card type.")
    info("Output shows: slot number, HF type, LF type, enabled/disabled state.")
    _run_cli_op(port, "hw slot list")


def op_set_slot_type(port: str):
    heading("Set Slot Type")
    info("Configures a slot to emulate a specific RFID card protocol.")
    info("Slot types:")
    for st in SLOT_TYPES:
        info(f"  {st}")
    info("")
    info("HF (13.56 MHz): MIFARE_*, NTAG_*  — for NFC/MIFARE readers")
    info("LF (125 kHz):   EM410X, HID_26    — for proximity card readers")
    slot_str = prompt("Slot number (1-8)")
    if not slot_str.isdigit() or not (1 <= int(slot_str) <= 8):
        err("Invalid slot number. Must be 1-8.")
        return
    slot = int(slot_str)

    type_choice = numbered_menu("Select Card Type", SLOT_TYPES)
    card_type = SLOT_TYPES[type_choice]

    band_choice = numbered_menu("Frequency Band", ["HF (13.56 MHz)", "LF (125 kHz)"])
    freq_flag = "--hf" if band_choice == 0 else "--lf"

    info(f"Setting slot {slot} to {card_type} ({freq_flag})…")
    info(f"CLI command: hw slot type -s {slot} -t {card_type} {freq_flag}")
    _run_cli_op(port, f"hw slot type -s {slot} -t {card_type} {freq_flag}")


def op_enable_disable_slot(port: str):
    heading("Enable / Disable Slot")
    info("Enables or disables a slot. Disabled slots are skipped during emulation cycling.")
    info("Useful to hide unused slots or isolate a specific card for emulation.")
    slot_str = prompt("Slot number (1-8)")
    if not slot_str.isdigit() or not (1 <= int(slot_str) <= 8):
        err("Invalid slot number. Must be 1-8.")
        return
    slot = int(slot_str)

    action_choice = numbered_menu("Action", ["Enable", "Disable"])
    action = "enable" if action_choice == 0 else "disable"

    band_choice = numbered_menu("Frequency Band", ["HF (13.56 MHz)", "LF (125 kHz)"])
    freq_flag = "--hf" if band_choice == 0 else "--lf"

    info(f"CLI command: hw slot {action} -s {slot} {freq_flag}")
    _run_cli_op(port, f"hw slot {action} -s {slot} {freq_flag}")


def op_scan_hf(port: str):
    heading("Scan HF Cards (ISO 14443-A)")
    info("Activates the Chameleon Ultra HF reader to scan for ISO 14443-A cards.")
    info("Supported: MIFARE Classic, MIFARE Ultralight, NTAG, DESFire, EMV cards.")
    info("Place the card flat on the top of the Chameleon Ultra (HF antenna).")
    info("Expected output: UID, SAK, ATQA, card type.")
    info("Troubleshooting:")
    info("  - Hold card still for at least 2 seconds")
    info("  - Remove metal cases or wallets that block RF")
    info("  - If card type is unknown, try 'hf search' from the CLI directly")
    info("Place a card on the Chameleon Ultra HF antenna…")
    _run_cli_op(port, "hf 14a scan", timeout=20)


def op_scan_lf(port: str):
    heading("Scan LF Cards (EM410x)")
    info("Activates the Chameleon Ultra LF reader to scan for EM410x cards.")
    info("EM4100/EM4102 are the most common 125 kHz proximity cards.")
    info("Place the card flat on the bottom of the Chameleon Ultra (LF antenna).")
    info("Expected output: EM410x card ID (10 hex digits).")
    info("Troubleshooting:")
    info("  - LF reads require the card to be within ~3 cm")
    info("  - Hold still for 3-5 seconds — LF is slower than HF")
    info("  - HID Prox cards use a different protocol — use 'lf hid read' for those")
    info("  - Not all 125 kHz cards are EM410x — see 'lf search' for auto-detect")
    info("Place a card on the Chameleon Ultra LF antenna…")
    _run_cli_op(port, "lf em 410x scan", timeout=20)


def op_enable_auth_logging(port: str):
    heading("Enable Authentication Logging")
    info("Enables logging of MIFARE Classic authentication attempts.")
    info("When the Chameleon emulates a MIFARE card, any reader authentication")
    info("attempts will be logged — useful for capturing nonces for offline attacks.")
    info("After enabling, present the emulated card to a target reader.")
    info("Then use 'View Auth Log' to retrieve captured nonces.")
    info("Note: emulation slot must be configured as MIFARE_1024 or similar first.")
    _run_cli_op(port, "hf mf econfig --enable-log")


def op_view_auth_log(port: str):
    heading("View Authentication Log")
    info("Retrieves captured MIFARE authentication nonces from device memory.")
    info("Output format: tag nonce, reader nonce, encrypted response — suitable")
    info("for offline key recovery tools like mfkey32v2 or Proxmark3 autopwn.")
    info("If log is empty, ensure auth logging was enabled before card presentation.")
    _run_cli_op(port, "hf mf elog")


def op_clone_card(port: str):
    heading("Clone Card")
    info("Card cloning workflow overview:")
    info("  1. Scan the source card into a slot (HF/LF scan reads card data).")
    info("  2. Configure destination slot type to match the source card.")
    info("  3. Use dump/restore CLI commands to copy data between slots.")
    info("")
    info("Full MIFARE clone workflow via CLI:")
    info("  Step 1: hf mf dump -s <src>  → dumps slot data to a local .bin file")
    info("  Step 2: hf mf restore -s <dst>  → restores .bin file to destination slot")
    info("  Step 3: hw slot enable -s <dst> --hf  → enable the destination slot")
    info("")
    info("Note: Block 0 (UID block) may be locked on some cards. Use 'magic' cards for full UID clone.")

    src_str = prompt("Source slot number (1-8, where original card was scanned)")
    if not src_str.isdigit() or not (1 <= int(src_str) <= 8):
        err("Invalid source slot.")
        return
    dst_str = prompt("Destination slot number (1-8, to clone into)")
    if not dst_str.isdigit() or not (1 <= int(dst_str) <= 8):
        err("Invalid destination slot.")
        return

    src = int(src_str)
    dst = int(dst_str)

    if src == dst:
        warn("Source and destination slots are the same. Nothing to clone.")
        return

    info(f"Cloning slot {src} → slot {dst}…")
    info("Note: Use the CLI's dump/restore commands for a full card clone workflow.")
    info("  Step 1: hf mf dump -s {src}  → save to file")
    info(f"  Step 2: hf mf restore -s {dst}  → restore to destination slot")

    if confirm(f"Run 'hw slot list' to confirm slot {dst} configuration?"):
        _run_cli_op(port, "hw slot list")


def op_firmware_update(port: str):
    heading("Firmware Update")
    warn("Firmware update requires DFU mode.")
    info("DFU mode entry:")
    info("  1. Hold button B while plugging in USB-C")
    info("  2. The device will enumerate as VID:PID 1915:521F (Nordic DFU)")
    info("  3. Solid LED indicates DFU mode is active")
    info("")
    info("nrfutil is required for firmware flashing.")
    info("If not installed, install it with:")
    info("  pip install nrfutil --break-system-packages")
    info("  nrfutil install device")
    info("")
    info("Firmware .zip packages are available at:")
    info("  https://github.com/RfidResearchGroup/ChameleonUltra/releases")

    if not ensure_system_tool(
        "nrfutil",
        "pip install nrfutil --break-system-packages && nrfutil install device",
    ):
        warn("nrfutil not available. Cannot proceed with firmware update.")
        info("Install with: pip install nrfutil --break-system-packages")
        info("Then run: nrfutil install device")
        pause("Install nrfutil, then press ENTER to retry.")
        if not ensure_system_tool(
            "nrfutil",
            "pip install nrfutil --break-system-packages && nrfutil install device",
        ):
            return

    zip_path = prompt("Path to firmware .zip file")
    if not zip_path:
        warn("No file path provided.")
        return
    zip_file = Path(zip_path)
    if not zip_file.exists():
        err(f"File not found: {zip_file}")
        return
    if zip_file.suffix.lower() != ".zip":
        warn(f"File does not have a .zip extension: {zip_file.name}")
        if not confirm("Continue anyway?", default=False):
            return

    info("Connect device in DFU mode (hold B + plug USB) then wait…")
    info("Expected: lsusb should show 1915:521f Nordic Semiconductor ASA")
    info("Check: lsusb | grep -i nordic  or  dmesg | tail -10")
    wait_start(
        "Waiting for Chameleon Ultra in DFU mode.\n\n"
        "  Hold button B while plugging in USB-C cable.\n"
        "  DFU mode indicator: solid LED.\n"
        "  Verify with: lsusb | grep 1915"
    )

    deadline = time.time() + 120
    while time.time() < deadline:
        if detect_chameleon_dfu():
            break
        wait_status(f"Waiting for DFU device… ({int(deadline - time.time())}s remaining)")
        time.sleep(2)
    else:
        wait_timeout("DFU device not detected. Aborting firmware update.")
        info("Troubleshooting:")
        info("  - Hold button B BEFORE plugging in USB (not after)")
        info("  - Try a different USB port or cable")
        info("  - Check: dmesg | tail -20  after plugging in")
        info("  - Verify DFU VID:PID: lsusb | grep 1915")
        return

    wait_done("DFU device detected.")
    info("Running nrfutil device program to flash firmware…")
    info("This will take 30-120 seconds. Do not disconnect USB.")

    nrfutil_bin = shutil.which("nrfutil") or "nrfutil"
    cmd = [nrfutil_bin, "device", "program", "--firmware", str(zip_file), "--traits", "nordicDfu"]

    info(f"Running: {' '.join(cmd)}")
    rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=300)
    if rc == 0:
        ok("Firmware update complete. Device will reboot automatically.")
        info("Wait for the device to re-enumerate as /dev/ttyACM* before using again.")
    else:
        err(f"nrfutil exited with code {rc}. Check output above for details.")
        info("Common failures:")
        info("  - 'No device found': ensure DFU mode is active (solid LED)")
        info("  - 'Invalid firmware': ensure you downloaded the correct .zip for ChameleonUltra")
        info("  - Permission error: check udev rules or run with sudo")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor == "linux":
        info("Ensuring required APT package: python3-serial")
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    info("Checking for nrfutil (needed for DFU firmware updates)…")
    info("nrfutil is not in apt — installing via pip if missing.")
    ensure_pip_packages([("nrfutil", "nrfutil")])

    print_banner(TOOL_NAME, DESCRIPTION)

    if not CLI_PATH.exists():
        warn(f"ChameleonUltra CLI not found at: {CLI_PATH}")
        info("Clone the repo before using this tool:")
        info(f"  git clone https://github.com/RfidResearchGroup/ChameleonUltra.git {SCRIPT_DIR / 'ChameleonUltra'}")
        info("  pip install -r ChameleonUltra/software/script/requirements.txt --break-system-packages")
        info("")
        info("You can still proceed if the device is connected — CLI is only needed for commands.")

    info("Detecting Chameleon Ultra via USB VID:PID 6868:* (nRF52840 CDC)…")
    info("Expected device: /dev/ttyACM* (Linux) or /dev/cu.usbmodem* (macOS)")

    found = web_detect_loop(detect_chameleon, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Chameleon Ultra not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PID_CDC)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Chameleon Ultra found on {port}")
    _check_dialout(port)

    check_firmware_version(port)

    MENU_OPTIONS = [
        "Device Info",
        "Slot Status",
        "Set Slot Type",
        "Enable / Disable Slot",
        "Scan HF Cards (14a)",
        "Scan LF Cards (EM410x)",
        "Enable Auth Logging",
        "View Auth Log",
        "Clone Card",
        "Firmware Update",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Chameleon Ultra — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_slot_status(port)
        elif choice == 2:
            op_set_slot_type(port)
        elif choice == 3:
            op_enable_disable_slot(port)
        elif choice == 4:
            op_scan_hf(port)
        elif choice == 5:
            op_scan_lf(port)
        elif choice == 6:
            op_enable_auth_logging(port)
        elif choice == 7:
            op_view_auth_log(port)
        elif choice == 8:
            op_clone_card(port)
        elif choice == 9:
            op_firmware_update(port)
        elif choice == 10:
            info("Goodbye.")
            break

        # Refresh port in case device re-enumerated
        new_port = find_serial_port_by_vidpid(VID_PID_CDC)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
