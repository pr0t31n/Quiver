#!/usr/bin/env python3
"""
Proxmark3 Iceman Tool Manager
Handles LF/HF card scanning, MIFARE operations, EM410x and HID reads,
dictionary attacks, and firmware updates via the pm3 binary.

Usage:
    python3 proxmark3.py

Installation on Kali Linux:
    sudo apt install proxmark3
    This provides: pm3, pm3-flash-all, pm3-flash-bootrom, pm3-flash-fullimage

    udev rules are required for non-root access. The apt package may install
    them automatically; if not, they are added by this script.

pm3 command reference:
    pm3 [port] --flush -c '<command>'   — run a single command non-interactively
    pm3 [port]                          — interactive REPL

    hw status          — hardware info (firmware, FPGA, antenna tuning)
    lf search          — auto-detect LF card type and read data
    hf search          — auto-detect HF card type and read data
    hf 14a scan        — ISO 14443-A card scan (UID, SAK, ATQA)
    hf mf autopwn      — fully automated MIFARE Classic key recovery
    hf mf dump --1k    — dump all sectors of MIFARE 1K
    hf mf sim --1k -u  — simulate MIFARE 1K with given UID
    hf mf chk --1k -f  — dictionary attack on MIFARE 1K
    lf em 410x read    — read EM4100/EM4102 LF card
    lf em 410x clone   — clone EM410x ID to a T55xx writable card
    lf hid read        — read HID Prox 26-bit card

Proxmark3 USB permissions:
    VID:PID 9ac4:4b8f (RDV4 Iceman) — requires udev rules for non-root access.
    udev rule: SUBSYSTEM=="usb", IDVENDOR=="9ac4", MODE="0666", GROUP="plugdev"
    Also add user to plugdev group: sudo usermod -aG plugdev $USER

    The device appears as /dev/ttyACM* (serial over USB).
    Add user to dialout group too: sudo usermod -aG dialout $USER
"""

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

TOOL_NAME   = "Proxmark3 (Iceman)"
DESCRIPTION = "Industry-standard RFID research and cloning platform"

VID_PID_LIST = [
    (0x9AC4, 0x4B8F),  # Iceman / RDV4
    (0x2D2D, 0x504D),  # Older firmware
    (0x502D, 0x502D),  # Clone / generic
]

UDEV_RULE_FILE = Path("/etc/udev/rules.d/77-proxmark3.rules")
UDEV_RULE_CONTENT = (
    '# Proxmark3 RDV4 Iceman firmware\n'
    'SUBSYSTEM=="usb", IDVENDOR=="9ac4", MODE="0666", GROUP="plugdev"\n'
    '# Proxmark3 older firmware / clones\n'
    'SUBSYSTEM=="usb", IDVENDOR=="2d2d", MODE="0666", GROUP="plugdev"\n'
    'SUBSYSTEM=="usb", IDVENDOR=="502d", MODE="0666", GROUP="plugdev"\n'
)

CONNECT_INSTRUCTIONS = (
    "Proxmark3 not detected.\n\n"
    "  1. Connect Proxmark3 via USB cable\n"
    "  2. Ensure Iceman firmware is installed\n\n"
    "  On Kali Linux:\n"
    "    sudo apt install proxmark3\n\n"
    "  udev rules for non-root access:\n"
    "    This script can install them automatically.\n\n"
    "  RDV4 VID:PID 9AC4:4B8F  |  Easy/clone: 502D:502D\n"
    "  Check: lsusb | grep -i proxmark   and   dmesg | tail -20"
)

# ── Firmware version check ────────────────────────────────────────────────────

def _get_current_version(port: str = None) -> str:
    """Return the firmware version from pm3 hw version output, or ''."""
    try:
        pm3_bin = shutil.which("pm3") or "/usr/bin/pm3"
        if not shutil.which("pm3") and not Path("/usr/bin/pm3").exists():
            return ""
        cmd = [pm3_bin]
        if port:
            cmd.append(port)
        cmd += ["--flush", "-c", "hw version"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20,
        )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("firmware:"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip().split()[0]
        return ""
    except Exception:
        return ""


def check_firmware_version(port: str = None):
    heading("Firmware Version Check")
    info("Checking installed firmware version...")
    current = _get_current_version(port)
    if not current:
        warn("Could not determine installed firmware version.")
        info("Continuing without version check.")
        return
    ok(f"Installed firmware: {current}")

    info("Checking latest available version on GitHub...")
    latest, release_url = check_latest_github_release("RfidResearchGroup", "proxmark3")
    if not latest:
        warn("Could not reach GitHub. Skipping version check.")
        return

    wants_update = announce_firmware_update(TOOL_NAME, current, latest, release_url)
    if wants_update:
        op_firmware_update(port)


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_pm3() -> bool:
    return find_serial_port_by_vidpid(VID_PID_LIST) is not None


# ── udev rule management ──────────────────────────────────────────────────────

def _ensure_udev_rules():
    """
    Check if udev rules are installed for Proxmark3.
    If not, install them via sudo_run and reload udev.
    """
    info("Checking Proxmark3 udev rules…")
    info(f"Expected rule file: {UDEV_RULE_FILE}")
    info("udev rules allow non-root access to the Proxmark3 USB device.")
    info("Without them, pm3 will require sudo for every run.")

    if UDEV_RULE_FILE.exists():
        ok(f"udev rules already installed at {UDEV_RULE_FILE}")
        return

    warn(f"udev rule file not found: {UDEV_RULE_FILE}")
    info("Installing udev rules for Proxmark3…")

    rule_content_escaped = UDEV_RULE_CONTENT.replace("'", "'\"'\"'")
    write_cmd = f"bash -c 'cat > {UDEV_RULE_FILE} << '\"'\"'EOF'\"'\"'\\n{UDEV_RULE_CONTENT}EOF'"

    # Use tee via sudo for reliable write
    import subprocess, tempfile, os
    with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as tf:
        tf.write(UDEV_RULE_CONTENT)
        tmp_path = tf.name

    try:
        rc = sudo_run(f"cp {tmp_path} {UDEV_RULE_FILE}")
        if rc.returncode != 0:
            err(f"Failed to install udev rules to {UDEV_RULE_FILE}")
            info(f"Install manually: sudo tee {UDEV_RULE_FILE} << 'EOF'")
            info(UDEV_RULE_CONTENT)
            info("EOF")
            return
        ok(f"udev rules written to {UDEV_RULE_FILE}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    info("Reloading udev rules…")
    sudo_run("udevadm control --reload-rules")
    sudo_run("udevadm trigger")
    ok("udev rules reloaded. Unplug and replug the Proxmark3 for rules to take effect.")

    # Also ensure user is in plugdev group
    import os as _os
    username = _os.environ.get("USER") or _os.environ.get("LOGNAME") or ""
    if username:
        info(f"Adding '{username}' to plugdev group for device access…")
        rc2 = sudo_run(f"usermod -aG plugdev {username}")
        if rc2.returncode == 0:
            ok(f"Added '{username}' to plugdev. Log out/in for group to take effect.")
        else:
            warn("Could not add to plugdev. Try: sudo usermod -aG plugdev $USER")


def _check_dialout():
    """Ensure user is in dialout group for /dev/ttyACM* access."""
    import grp, os as _os
    username = _os.environ.get("USER") or _os.environ.get("LOGNAME") or ""
    try:
        dialout_gid = grp.getgrnam("dialout").gr_gid
        if dialout_gid in _os.getgroups():
            return
    except KeyError:
        return
    warn(f"User '{username}' may not be in 'dialout' group.")
    info("This can cause 'Permission denied' on /dev/ttyACM* devices.")
    if confirm(f"Add '{username}' to 'dialout' now?", default=True):
        rc = sudo_run(f"usermod -aG dialout {username}")
        if rc.returncode == 0:
            ok("Added to dialout. Log out/in or run: newgrp dialout")
        else:
            err("Failed. Try: sudo usermod -aG dialout $USER")


# ── pm3 runner ────────────────────────────────────────────────────────────────

def pm3_run(command: str, port: str = None, timeout: int = 60) -> tuple:
    """
    Run a single Proxmark3 command via the pm3 binary with --flush -c flags.
    Streams output line-by-line via info().
    Returns (returncode, joined_output_str).

    pm3 command syntax:
        pm3 [device_port] --flush -c '<command>'
        --flush  : disable output buffering for real-time display
        -c       : run this command non-interactively and exit

    Common failure reasons:
        - pm3 not in PATH: install with 'sudo apt install proxmark3' (Kali)
        - Permission denied: install udev rules, add user to plugdev/dialout
        - Device not found: check USB connection, dmesg, lsusb
        - Firmware mismatch: update Proxmark3 firmware to match pm3 client version
    """
    pm3_bin = shutil.which("pm3") or "/usr/bin/pm3"
    if not shutil.which("pm3") and not Path("/usr/bin/pm3").exists():
        err("pm3 binary not found in PATH.")
        info("Install on Kali: sudo apt install proxmark3")
        info("Check PATH: echo $PATH")
        info("Check binary: which pm3  or  ls /usr/bin/pm3")
        return 1, ""

    cmd = [pm3_bin]
    if port:
        cmd += [port]
    cmd += ["--flush", "-c", command]

    lines = []

    def _handle_line(line: str):
        lines.append(line)
        info(line)

    info(f"pm3 command: {command}")
    info(f"Full invocation: {' '.join(cmd)}")
    rc = run_streaming(cmd, on_line=_handle_line, timeout=timeout)
    return rc, "\n".join(lines)


# ── Operations ────────────────────────────────────────────────────────────────

def op_hw_status(port: str):
    heading("Hardware Status")
    info("Queries Proxmark3 hardware status via 'hw status'.")
    info("Expected output:")
    info("  - Client version and library info")
    info("  - FPGA version and image")
    info("  - Antenna tuning results (LF/HF voltage, frequency)")
    info("  - Detected device type")
    info("If antenna tuning shows 0V, check the antenna connectors are seated properly.")
    rc, _ = pm3_run("hw status", port=port, timeout=30)
    if rc == 0:
        ok("Hardware status retrieved.")
    else:
        warn(f"pm3 exited with code {rc}.")
        info("Troubleshooting:")
        info("  - Check USB connection: lsusb | grep 9ac4")
        info("  - Check serial port: ls -la /dev/ttyACM*")
        info("  - Check udev rules: cat /etc/udev/rules.d/77-proxmark3.rules")
        info("  - Firmware mismatch: update firmware with 'Firmware Update' option")


def op_lf_search(port: str):
    heading("LF Auto-Search")
    info("Automatically detects and reads the LF (125 kHz) card type on the antenna.")
    info("Supported protocols: EM4100, HID Prox, Indala, ioProx, Paradox, AWID, Viking, etc.")
    info("Place card on the LF antenna (flat against the device).")
    info("Expected output: card type identification, raw bit data, and decoded fields.")
    info("Troubleshooting:")
    info("  - Hold card flat and still for 5+ seconds")
    info("  - LF antenna must be connected (check 'hw status' for LF voltage)")
    info("  - Unknown cards may show raw bits but no decoded type")
    info("Searching for LF cards — place card on antenna…")
    rc, _ = pm3_run("lf search", port=port, timeout=60)
    if rc == 0:
        ok("LF search complete.")
    else:
        warn(f"LF search returned code {rc}.")


def op_hf_search(port: str):
    heading("HF Auto-Search")
    info("Automatically detects and reads the HF (13.56 MHz) card type on the antenna.")
    info("Supported protocols: ISO 14443-A/B, ISO 15693, MIFARE, DESFire, iCLASS, etc.")
    info("Place card on or near the HF antenna (within 2-3 cm).")
    info("Expected output: card type, UID, protocol details.")
    info("Troubleshooting:")
    info("  - HF antenna must be connected (check 'hw status' for HF voltage)")
    info("  - Some cards (e.g. DESFire) are detected but may not be fully read")
    info("  - If UID is 0s or garbled, check for RF interference nearby")
    info("Searching for HF cards — place card on antenna…")
    rc, _ = pm3_run("hf search", port=port, timeout=60)
    if rc == 0:
        ok("HF search complete.")
    else:
        warn(f"HF search returned code {rc}.")


def op_hf14a_scan(port: str):
    heading("HF 14A Scan (ISO 14443-A)")
    info("Scans for ISO 14443-A cards (the most common HF standard).")
    info("Expected output: UID (4, 7, or 10 bytes), SAK byte, ATQA, card type guess.")
    info("SAK byte meanings (common):")
    info("  SAK=0x08 → MIFARE Classic 1K")
    info("  SAK=0x18 → MIFARE Classic 4K")
    info("  SAK=0x00 → MIFARE Ultralight / NTAG")
    info("  SAK=0x20 → ISO 14443-4 compliant (DESFire, EMV)")
    info("  SAK=0x28 → MIFARE Classic + ISO 14443-4")
    info("Scanning for ISO 14443-A cards…")
    rc, _ = pm3_run("hf 14a scan", port=port, timeout=30)
    if rc == 0:
        ok("HF 14A scan complete.")
    else:
        warn(f"Scan returned code {rc}.")


def op_mf_autopwn(port: str):
    heading("MIFARE Autopwn")
    info("Attempts to fully recover all sector keys from a MIFARE Classic card.")
    info("Method: combines darkside attack, nested attack, and hardnested attack.")
    info("Required: card must be on the antenna for the entire duration (3-15+ minutes).")
    info("Expected output: recovered keys per sector, final dump to .bin and .json files.")
    info("Troubleshooting:")
    info("  - Keep card perfectly still — movement breaks the RF coupling")
    info("  - Some MIFARE clones or hardened cards may be immune to these attacks")
    info("  - 'No tag found': reposition card on the HF antenna")
    info("  - Output files saved in current directory as hf-mf-<UID>-dump.bin/.json")
    warn("This operation attempts to recover all keys from a MIFARE Classic card.")
    warn("It may take several minutes. Place target card on antenna.")
    if not confirm("Start MIFARE Autopwn?"):
        info("Cancelled.")
        return
    rc, _ = pm3_run("hf mf autopwn", port=port, timeout=600)
    if rc == 0:
        ok("Autopwn complete.")
    else:
        warn(f"Autopwn exited with code {rc}. Check output for partial results.")
        info("Even with non-zero exit, some keys may have been recovered.")
        info("Look for hf-mf-*-dump.bin in the current directory.")


def op_mf_dump(port: str):
    heading("MIFARE Dump")
    info("Dumps all blocks from a MIFARE Classic 1K card to local files.")
    info("Requires that all sector keys are known (run Autopwn first if needed).")
    info("Output files:")
    info("  <filename>.bin  — raw binary dump (512 bytes for 1K)")
    info("  <filename>.json — human-readable JSON with sector/block breakdown")
    info("The dump can be used to restore/clone a card, or analyze the data offline.")
    default_name = "mifare_dump"
    filename = prompt("Output filename (no extension)", default=default_name)
    if not filename:
        filename = default_name
    # Remove any extension the user might have added
    filename = Path(filename).stem
    info(f"Dumping MIFARE Classic 1K to {filename}…")
    info(f"pm3 command: hf mf dump --1k -f {filename}")
    rc, _ = pm3_run(f"hf mf dump --1k -f {filename}", port=port, timeout=120)
    if rc == 0:
        ok(f"Dump saved as {filename}.bin / {filename}.json")
    else:
        warn(f"Dump exited with code {rc}.")
        info("If keys are unknown, run 'MIFARE Autopwn' first to recover all sector keys.")


def op_mf_simulate(port: str):
    heading("MIFARE Simulate")
    info("Simulates a MIFARE Classic 1K card using the Proxmark3 as an emulator.")
    info("The Proxmark3 will respond to reader queries as if it were the specified UID.")
    info("Note: simulation uses default (all-zero) sector keys unless a dump is loaded.")
    info("For full simulation with real card data, use 'hf mf eload' to load a dump first.")
    info("Stop simulation by pressing any key in the pm3 console.")
    uid = prompt("UID to simulate (8 hex chars, e.g. DEADBEEF)")
    if not uid:
        warn("No UID provided.")
        return
    uid = uid.strip().upper().replace(" ", "").replace(":", "")
    if len(uid) != 8 or not all(c in "0123456789ABCDEF" for c in uid):
        err(f"Invalid UID format: '{uid}' — must be exactly 8 hex characters.")
        return
    info(f"Simulating MIFARE Classic 1K with UID {uid}…")
    info("Press Ctrl-C or any key in pm3 console to stop simulation.")
    rc, _ = pm3_run(f"hf mf sim --1k -u {uid}", port=port, timeout=120)
    if rc == 0:
        ok("Simulation ended.")
    else:
        warn(f"Simulation exited with code {rc}.")


def op_em410x_read(port: str):
    heading("EM410x Read (LF 125 kHz)")
    info("Reads an EM4100 or EM4102 125 kHz proximity card.")
    info("EM410x is the most common LF card type used in building access systems.")
    info("Expected output: 10-digit hex card ID (e.g. 1234567890).")
    info("Place card on the LF antenna (flat against the Proxmark3).")
    info("Troubleshooting:")
    info("  - Hold card still for 3-5 seconds")
    info("  - LF antenna voltage should be >10V (check with 'hw status')")
    info("  - Non-EM cards won't be read — use 'LF Auto-Search' for unknown cards")
    info("Place EM410x card on LF antenna…")
    rc, _ = pm3_run("lf em 410x read", port=port, timeout=30)
    if rc == 0:
        ok("EM410x read complete.")
    else:
        warn(f"EM410x read returned code {rc}.")


def op_em410x_clone(port: str):
    heading("EM410x Clone")
    info("Writes an EM410x ID to a writable T55xx card (e.g. T5577).")
    info("T55xx cards are blank rewritable LF cards available from RFID suppliers.")
    info("The cloned card will respond identically to the original in most readers.")
    info("Place the WRITABLE T55xx card on the LF antenna for cloning.")
    info("Warning: some advanced readers detect cloned cards via timing analysis.")
    target_id = prompt("Target EM410x ID to write (10 hex chars, e.g. 1122334455)")
    if not target_id:
        warn("No ID provided.")
        return
    target_id = target_id.strip().upper().replace(" ", "")
    if len(target_id) != 10 or not all(c in "0123456789ABCDEF" for c in target_id):
        err(f"Invalid ID: '{target_id}' — must be 10 hex characters.")
        return
    warn("Place a writable T55xx card on the LF antenna for cloning.")
    info("Do not use a real card — it will be overwritten if writable.")
    if not confirm(f"Clone ID {target_id} to card?"):
        info("Cancelled.")
        return
    info(f"pm3 command: lf em 410x clone --id {target_id}")
    rc, _ = pm3_run(f"lf em 410x clone --id {target_id}", port=port, timeout=60)
    if rc == 0:
        ok(f"EM410x clone written with ID {target_id}.")
        info("Verify the clone with 'EM410x Read' — place cloned card on antenna.")
    else:
        warn(f"Clone exited with code {rc}.")
        info("Ensure the card is a writable T55xx blank card, not a read-only EM card.")


def op_hid_read(port: str):
    heading("HID Prox Read (LF)")
    info("Reads HID Prox 26-bit Wiegand LF cards (common in corporate access control).")
    info("HID Prox cards operate at 125 kHz and encode a facility code + card number.")
    info("Expected output: facility code, card number, full raw bit string.")
    info("Place HID card on LF antenna (flat against the Proxmark3).")
    info("Troubleshooting:")
    info("  - HID cards require longer read time than EM cards — hold steady 5+ seconds")
    info("  - Some HID iCLASS cards are HF (13.56 MHz) — use 'HF Auto-Search' for those")
    info("  - Some HID formats (35-bit, 37-bit) may not decode — raw bits are still output")
    info("Place HID card on LF antenna…")
    rc, _ = pm3_run("lf hid read", port=port, timeout=30)
    if rc == 0:
        ok("HID read complete.")
    else:
        warn(f"HID read returned code {rc}.")


def op_dict_attack(port: str):
    heading("MIFARE Dictionary Attack")
    info("Tries known default keys against all sectors of a MIFARE Classic card.")
    info("Faster than Autopwn if the card uses common/default keys.")
    info("pm3 ships with a default key dictionary — or provide your own.")
    info("Common default key files (Kali/pm3 install):")
    info("  /usr/share/proxmark3/dictionaries/mfc_default_keys.dic")
    info("  /usr/share/proxmark3/dictionaries/mfc_default_keys_user.dic")
    info("Expected output: recovered keys per sector; sectors with unknown keys listed.")
    info("After recovery, use 'MIFARE Dump' to extract all card data.")
    dict_path = prompt("Path to dictionary file (e.g. /usr/share/proxmark3/dictionaries/mfc_default_keys.dic)")
    if not dict_path:
        warn("No dictionary file provided.")
        return
    dict_file = Path(dict_path)
    if not dict_file.exists():
        err(f"Dictionary file not found: {dict_file}")
        info("Default key files are in /usr/share/proxmark3/dictionaries/ on Kali.")
        return
    info(f"Running dictionary attack with {dict_file.name}…")
    info(f"pm3 command: hf mf chk --1k -f {dict_file}")
    rc, _ = pm3_run(f"hf mf chk --1k -f {dict_file}", port=port, timeout=300)
    if rc == 0:
        ok("Dictionary attack complete. Check output for recovered keys.")
    else:
        warn(f"Attack exited with code {rc}.")
        info("If no keys found, try Autopwn for cryptographic key recovery.")


def op_firmware_update(port: str):
    heading("Firmware Update")
    info("Flashes Iceman firmware to the Proxmark3 using pm3-flash-* utilities.")
    info("On Kali Linux (apt install proxmark3), firmware binaries are bundled.")
    info("")
    warn("Firmware update will erase and reflash the Proxmark3.")
    warn("The device must be in bootloader mode for flashing.")
    info("")
    info("Bootloader mode entry:")
    info("  RDV4: hold the button on the device while plugging in USB")
    info("  Easy/clone: some boards enter bootloader automatically via pm3-flash-all")
    info("")
    info("Flash utilities (installed by apt install proxmark3):")
    info("  pm3-flash-bootrom   — flashes the bootloader ROM")
    info("  pm3-flash-fullimage — flashes the main firmware image")
    info("  pm3-flash-all       — flashes both bootrom + fullimage (recommended)")
    info("")
    info("After flashing, unplug and replug the Proxmark3.")
    info("Then verify with: pm3 -- hw version")

    choice = numbered_menu(
        "Firmware Flash Target",
        [
            "Flash All (bootrom + fullimage) — recommended",
            "Flash Bootrom only",
            "Flash Full Image only",
            "Cancel",
        ],
    )

    if choice == 3:
        info("Firmware update cancelled.")
        return

    flash_cmds = {
        0: "pm3-flash-all",
        1: "pm3-flash-bootrom",
        2: "pm3-flash-fullimage",
    }
    flash_bin = flash_cmds[choice]

    if not shutil.which(flash_bin):
        err(f"'{flash_bin}' not found in PATH.")
        info("On Kali Linux, install with: sudo apt install proxmark3")
        info("Check PATH: echo $PATH  and  which pm3-flash-all")
        return

    cmd = [flash_bin]
    if port:
        cmd += [port]

    warn(f"Running: {' '.join(cmd)}")
    warn("Do NOT disconnect USB during flashing.")
    info("Flashing takes 30-90 seconds. Watch for progress output.")
    info("Troubleshooting if flash fails:")
    info("  - Ensure bootloader mode is active (button held during USB plug-in)")
    info("  - Check USB connection: dmesg | tail -10")
    info("  - Try a different USB port or cable")
    info("  - Verify device is recognized: lsusb | grep 9ac4")
    if not confirm("Proceed with firmware flash?", default=False):
        info("Cancelled.")
        return

    info(f"Running: {flash_bin}")
    rc = run_streaming_sudo(cmd, on_line=lambda l: info(l), timeout=300)
    if rc == 0:
        ok("Firmware flash complete. Unplug and replug the Proxmark3.")
        info("Verify firmware version after reconnecting: hw version")
    else:
        err(f"Flash tool exited with code {rc}. Check output above.")
        info("If the device is bricked, try entering bootloader mode manually and re-running.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor == "linux":
        info("Ensuring proxmark3 is installed via apt…")
        info("The 'proxmark3' apt package provides: pm3, pm3-flash-all, pm3-flash-bootrom,")
        info("pm3-flash-fullimage, and firmware binaries.")
        ensure_apt_packages(["proxmark3"])
        _ensure_udev_rules()
        _check_dialout()
    else:
        ensure_system_tool(
            "pm3",
            "brew install proxmark3",
            brew_pkg="proxmark3",
        )

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Detecting Proxmark3 via USB VID:PID 9AC4:4B8F (RDV4) or 502D:502D (clone)…")
    info("Check: lsusb | grep -iE '9ac4|502d|2d2d'")
    info("Check: dmesg | tail -20")

    found = web_detect_loop(detect_pm3, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Proxmark3 not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PID_LIST)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Proxmark3 found on {port}")

    check_firmware_version(port)

    MENU_OPTIONS = [
        "Hardware Status",
        "LF Auto-Search",
        "HF Auto-Search",
        "HF 14A Scan",
        "MIFARE Autopwn",
        "MIFARE Dump",
        "MIFARE Simulate",
        "EM410x Read",
        "EM410x Clone",
        "HID Read",
        "Dictionary Attack",
        "Firmware Update",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Proxmark3 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_hw_status(port)
        elif choice == 1:
            op_lf_search(port)
        elif choice == 2:
            op_hf_search(port)
        elif choice == 3:
            op_hf14a_scan(port)
        elif choice == 4:
            op_mf_autopwn(port)
        elif choice == 5:
            op_mf_dump(port)
        elif choice == 6:
            op_mf_simulate(port)
        elif choice == 7:
            op_em410x_read(port)
        elif choice == 8:
            op_em410x_clone(port)
        elif choice == 9:
            op_hid_read(port)
        elif choice == 10:
            op_dict_attack(port)
        elif choice == 11:
            op_firmware_update(port)
        elif choice == 12:
            info("Goodbye.")
            break

        # Refresh port — device may re-enumerate after some operations
        new_port = find_serial_port_by_vidpid(VID_PID_LIST)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
