#!/usr/bin/env python3
"""
USB Rubber Ducky Tool Manager
Handles detection of the 2022 USB Rubber Ducky (DuckyScript 3.0), payload
validation, and deployment.

Note: The Rubber Ducky has NO SSH/network access. All management is through
the DUCKY mass-storage drive. Firmware updates are not required (and NOT
supported — flashing bricks the device). Payload compilation requires
PayloadStudio: https://payloadstudio.hak5.org

Usage:
    python3 usb_rubber_ducky.py
"""

import re
import sys
import shutil
import textwrap
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    sudo_run,
    require_sudo,
    detect_usb_device, find_mounted_drive,
    detection_loop, get_filesystem_type,
    get_selected_payload, verify_device_connection,
)


def check_firmware_version():
    heading("Firmware Version Check")
    info("The USB Rubber Ducky (2022 model, DuckyScript 3.0) has no user-readable firmware version.")
    info("Firmware updates are NOT supported — flashing any firmware permanently bricks the device.")
    info("")
    info("  *** Do NOT attempt to update or flash the USB Rubber Ducky firmware ***")
    info("")
    info("If you have the original v1 Rubber Ducky (2010), firmware may be checked via the MicroSD card.")
    info("For the 2022 model: no firmware action is needed or possible.")
    info("More info: https://docs.hak5.org/usb-rubber-ducky/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "USB Rubber Ducky (2022, DuckyScript 3.0)"
DESCRIPTION = "HID keystroke injection device — USB storage management"
VID_NEW     = "05AC"   # Spoofed Apple VID (default for new ducky in HID mode)
VID_OLD     = "03EB"   # Atmel (original v1 ducky)
DRIVE_LABEL = "DUCKY"

PAYLOAD_STUDIO_URL = "https://payloadstudio.hak5.org"
FIRMWARE_NOTE = """
  *** IMPORTANT: Do NOT flash firmware on the USB Rubber Ducky (2022 model) ***
  Flashing third-party or legacy firmware PERMANENTLY BRICKS the device.
  The 2022 Ducky is designed to never need firmware updates.
"""

# DuckyScript 3.0 keywords
DS3_KEYWORDS = {
    # Flow control
    "REM", "REM_BLOCK", "END_REM", "DEFINE", "VAR", "IF", "ELSE", "END_IF",
    "WHILE", "END_WHILE", "FUNCTION", "END_FUNCTION", "RETURN",
    # Device control
    "ATTACKMODE", "DELAY", "RESET", "STOP_PAYLOAD", "RESTART_PAYLOAD",
    "HIDE_PAYLOAD", "RESTORE_PAYLOAD", "SAVE_ATTACKMODE", "RESTORE_ATTACKMODE",
    # String output
    "STRING", "STRINGLN", "STRINGLN_BLOCK", "END_STRINGLN",
    # Button
    "WAIT_FOR_BUTTON_PRESS", "BUTTON_DEF",
    # LED
    "LED_R", "LED_G", "LED_OFF",
    # Key names
    "ENTER", "BACKSPACE", "TAB", "SPACE", "DELETE", "HOME", "END",
    "INSERT", "PAGEUP", "PAGEDOWN", "UP", "DOWN", "LEFT", "RIGHT",
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10", "F11", "F12",
    "CTRL", "SHIFT", "ALT", "GUI", "WINDOWS", "CAPSLOCK", "NUMLOCK", "SCROLLLOCK",
    "ESCAPE", "PRINTSCREEN", "PAUSE",
    # Modifier combos (common forms)
    "CTRL-ALT-DELETE", "CTRL-ALT-END", "CTRL-SHIFT-ESCAPE",
    "GUI", "ALT-F4", "CTRL-C", "CTRL-V", "CTRL-Z",
}

ATTACKMODES_DS3 = {"HID", "STORAGE", "OFF"}

MODE_INSTRUCTIONS = """
The USB Rubber Ducky was not detected.

  For the 2022 USB Rubber Ducky (DuckyScript 3.0):
    1. Make sure you're plugging into a USB-A port (or USB-A adapter for USB-C).
    2. If the device has already run a payload, it may be in HID mode (not
       storage mode). To get back to storage mode:
       a. If your payload includes ATTACKMODE STORAGE, activate it via the
          squeeze button (hidden inside the case — use spacer stickers or a pin).
       b. Or add BUTTON_DEF ATTACKMODE STORAGE at the top of your payload.
    3. The drive should appear as "DUCKY" when in storage mode.

  For the original USB Rubber Ducky (v1, 2010):
    1. Remove the plastic case to access the MicroSD card slot.
    2. Remove the MicroSD card and insert it into a card reader on this computer.
    3. The card should mount as a drive.
    4. The inject.bin file must be compiled with the legacy encoder.
"""

RESET_INSTRUCTIONS = """
The USB Rubber Ducky does not have a traditional factory reset.

  If the device is unresponsive or stuck:
    1. For the 2022 Ducky: unplug, wait 5 seconds, replug.
    2. If the device is in HID mode and you can't reach storage mode,
       use the squeeze button (bend the case slightly inward on the sides).
    3. If inject.bin is corrupt: get to storage mode, delete inject.bin,
       replace with a working one.
    4. Do NOT attempt to flash firmware — this will permanently brick the device.
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_ducky() -> bool:
    """Detect Rubber Ducky by mounted drive label or USB VID."""
    if find_mounted_drive(DRIVE_LABEL):
        return True
    if detect_usb_device(VID_NEW):
        return True
    if detect_usb_device(VID_OLD):
        return True
    return False


# ── Payload Validation ────────────────────────────────────────────────────────

def validate_ds3_payload(path: Path) -> list[str]:
    """
    Validate a DuckyScript 3.0 source file (.txt).
    Returns list of issue strings.
    """
    issues = []
    try:
        content = path.read_text()
    except Exception as e:
        return [f"Cannot read file: {e}"]

    lines = content.splitlines()

    # Check for REM_BLOCK header
    has_header = any(ln.strip() == "REM_BLOCK" for ln in lines)
    if not has_header:
        issues.append("INFO: No REM_BLOCK header found (recommended for PayloadStudio metadata)")

    # Check balanced REM_BLOCK / END_REM
    rem_depth = 0
    for i, ln in enumerate(lines, 1):
        tok = ln.strip().split()[0] if ln.strip() else ""
        if tok == "REM_BLOCK":
            rem_depth += 1
        elif tok == "END_REM":
            rem_depth -= 1
            if rem_depth < 0:
                issues.append(f"ERROR: Line {i}: END_REM without matching REM_BLOCK")
                rem_depth = 0
    if rem_depth > 0:
        issues.append("ERROR: Unclosed REM_BLOCK (missing END_REM)")

    # Check balanced IF/END_IF
    if_depth = 0
    for i, ln in enumerate(lines, 1):
        tok = ln.strip().split()[0].upper() if ln.strip() else ""
        if tok == "IF":
            if_depth += 1
        elif tok == "END_IF":
            if_depth -= 1
            if if_depth < 0:
                issues.append(f"ERROR: Line {i}: END_IF without matching IF")
                if_depth = 0
    if if_depth > 0:
        issues.append(f"ERROR: {if_depth} unclosed IF block(s)")

    # Check balanced WHILE/END_WHILE
    while_depth = 0
    for i, ln in enumerate(lines, 1):
        tok = ln.strip().split()[0].upper() if ln.strip() else ""
        if tok == "WHILE":
            while_depth += 1
        elif tok == "END_WHILE":
            while_depth -= 1
            if while_depth < 0:
                issues.append(f"ERROR: Line {i}: END_WHILE without matching WHILE")
                while_depth = 0
    if while_depth > 0:
        issues.append(f"ERROR: {while_depth} unclosed WHILE block(s)")

    # Check balanced FUNCTION/END_FUNCTION
    func_depth = 0
    for i, ln in enumerate(lines, 1):
        tok = ln.strip().split()[0].upper() if ln.strip() else ""
        if tok == "FUNCTION":
            func_depth += 1
        elif tok == "END_FUNCTION":
            func_depth -= 1
            if func_depth < 0:
                issues.append(f"ERROR: Line {i}: END_FUNCTION without matching FUNCTION")
                func_depth = 0
    if func_depth > 0:
        issues.append(f"ERROR: {func_depth} unclosed FUNCTION block(s)")

    # ATTACKMODE validation
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*ATTACKMODE\s+(.*)", ln, re.IGNORECASE)
        if m:
            parts = m.group(1).upper().split()
            for part in parts:
                if re.match(r"(VID|PID|MAN|PROD|SERIAL)_", part):
                    continue
                if part not in ATTACKMODES_DS3:
                    issues.append(f"WARNING: Line {i}: Unknown ATTACKMODE argument: {part}  (valid: HID, STORAGE, OFF)")

    # STRING with no argument
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*(STRING|STRINGLN)\s*$", ln, re.IGNORECASE)
        if m:
            issues.append(f"WARNING: Line {i}: {m.group(1)} with no argument")

    # DELAY values
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*DELAY\s+(\S+)", ln, re.IGNORECASE)
        if m:
            try:
                val = int(m.group(1))
                if val < 0:
                    issues.append(f"WARNING: Line {i}: Negative DELAY value: {val}")
                elif val > 60000:
                    issues.append(f"INFO: Line {i}: Large DELAY ({val} ms ≈ {val//1000}s) — intentional?")
            except ValueError:
                # Could be a variable reference like $DELAY_VAR
                if not m.group(1).startswith("$"):
                    issues.append(f"WARNING: Line {i}: Non-numeric DELAY value: {m.group(1)}")

    # VAR declaration format
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*VAR\s+(\S+)\s*=", ln, re.IGNORECASE)
        if m:
            var_name = m.group(1)
            if not re.match(r"^\$[A-Z_][A-Z0-9_]*$", var_name):
                issues.append(f"WARNING: Line {i}: Variable name '{var_name}' should start with $ and use uppercase")

    return issues


def check_inject_bin(drive: Path) -> bool:
    """Check if inject.bin exists on the DUCKY drive."""
    return (drive / "inject.bin").exists()


def check_drive_health(drive: Path):
    """Check drive filesystem and inject.bin integrity; emit warnings."""
    fstype = get_filesystem_type(str(drive))
    if fstype:
        info(f"Drive filesystem: {fstype}")
        if "FAT" in fstype or "MSDOS" in fstype:
            ok(f"{fstype} filesystem — compatible with USB Rubber Ducky.")
        elif fstype in ("NTFS",) or fstype.startswith("EXT"):
            warn(f"'{fstype}' filesystem detected — Rubber Ducky expects FAT32. Reformat the card.")
        else:
            info(f"Filesystem '{fstype}' — verify the drive is FAT32.")

    inject = drive / "inject.bin"
    if inject.exists():
        size = inject.stat().st_size
        if size == 0:
            warn("inject.bin is 0 bytes — file is empty/corrupt. Delete and re-deploy.")
        elif size < 16:
            warn(f"inject.bin is only {size} bytes — likely corrupt. Re-compile in PayloadStudio.")
        else:
            info(f"inject.bin present: {size} bytes")
    else:
        info("No inject.bin on drive (will be created when you deploy a payload).")


# ── Payload Deployment ────────────────────────────────────────────────────────

def deploy_payload(drive: Path) -> bool:
    heading("Step 9/10 — Payload Upload & Review")

    print("""
  Deployment options:
    A) Upload a pre-compiled inject.bin  (compiled via PayloadStudio)
    B) Upload a DuckyScript 3.0 source (.txt) — review only; manual compilation required
    C) Open PayloadStudio in browser to compile
    """)

    choice = numbered_menu("Select deployment option:", [
        "Upload compiled inject.bin",
        "Review DuckyScript 3.0 source (.txt)",
        "Open PayloadStudio website (compile manually)",
    ])

    if choice == 2:
        import webbrowser
        webbrowser.open(PAYLOAD_STUDIO_URL)
        info(f"Opened {PAYLOAD_STUDIO_URL}")
        info("Compile your payload there, download inject.bin, then run this script again.")
        return True

    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        payload_path = Path(preselected).expanduser()
    else:
        payload_path = Path(prompt("Path to file")).expanduser()
    if not payload_path.exists():
        err(f"File not found: {payload_path}")
        return False

    if choice == 1:
        # Upload inject.bin
        if payload_path.suffix.lower() not in (".bin", ""):
            warn(f"Expected a .bin file, got '{payload_path.name}'. Continue?")
            if not confirm("Upload anyway?"):
                return False

        dest = drive / "inject.bin"
        info(f"Copying {payload_path.name} → {dest}")
        shutil.copy2(payload_path, dest)
        ok("inject.bin deployed to DUCKY drive.")
        info("Eject the drive safely. The payload will run automatically on next plug-in.")
        return True

    else:
        # Review .txt source
        if payload_path.suffix.lower() != ".txt":
            warn("Expected a .txt DuckyScript source file.")

        info("Validating DuckyScript 3.0 syntax…")
        issues = validate_ds3_payload(payload_path)

        if issues:
            error_count = sum(1 for i in issues if i.startswith("ERROR"))
            warn_count  = sum(1 for i in issues if i.startswith("WARNING"))
            info_count  = sum(1 for i in issues if i.startswith("INFO"))
            print(f"\n  Results: {error_count} errors, {warn_count} warnings, {info_count} info notes\n")
            for issue in issues:
                prefix = "    ✘ " if issue.startswith("ERROR") else "    ! " if issue.startswith("WARNING") else "    · "
                print(f"{prefix}{issue}")
        else:
            ok("DuckyScript 3.0 source looks good — no issues found.")

        if issues:
            err_issues = [i for i in issues if i.startswith("ERROR")]
            if err_issues:
                warn("Errors found. Fix them before compiling in PayloadStudio.")
            else:
                info("No blocking errors found.")

        print(f"""
  To compile and deploy:
    1. Go to {PAYLOAD_STUDIO_URL}
    2. Open or paste your .txt payload
    3. Click 'Compile' then 'Download inject.bin'
    4. Copy inject.bin to the root of the DUCKY drive
    5. Eject the drive safely
        """)
        return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    # Firmware warning
    print(FIRMWARE_NOTE)

    # Step 1
    heading("Step 1 — Connect the USB Rubber Ducky")
    _CONNECT_INSTRUCTIONS = (
        "Insert the USB Rubber Ducky into a USB-A port on this computer.\n\n"
        "Expected LED states (2022 model):\n"
        "  ● Solid GREEN       — Storage mode — 'DUCKY' drive mounted ✓  ← wait for this\n"
        "  ● No LED (dark)     — HID/Attack mode — drive NOT mounted\n"
        "  ● Rapid GREEN blink — Payload executing\n\n"
        "If the Ducky is in HID mode (no drive mounted):\n"
        "  1. Gently squeeze both sides of the case inward to trigger the hidden side button.\n"
        "     This switches to storage mode — the 'DUCKY' drive should appear.\n"
        "  2. Or: replug while squeezing the button.\n\n"
        "The Rubber Ducky 2022 has NO dedicated arming switch — the squeeze button\n"
        "is the only hardware control. Handle gently (flexible PCB inside)."
    )
    detected = verify_device_connection(
        detect_ducky, TOOL_NAME, _CONNECT_INSTRUCTIONS, max_retries=3
    )
    if not detected:
        err("USB Rubber Ducky not detected. Exiting.")
        sys.exit(1)

    # Step 4 — Confirm interface
    heading("Step 4 — Interface Confirmation")
    info("Looking for a drive labelled 'DUCKY'…")
    info("On Kali/Linux the drive typically mounts at /media/<user>/DUCKY — check your file manager.")
    drive = find_mounted_drive(DRIVE_LABEL)
    if drive:
        ok(f"DUCKY drive mounted at: {drive}")
    else:
        warn("Drive not found. USB device was detected but DUCKY drive is not mounted.")
        info("If the Ducky is in HID mode, it won't mount a drive.")
        info("On Kali, if the drive doesn't auto-mount, try: udisksctl mount -b /dev/sdX1")
        info("Or open Files (Nautilus) and click the DUCKY volume in the left panel.")
        print("""
  To switch to storage mode:
    • Gently squeeze the sides of the Rubber Ducky case — the squeeze button
      is hidden inside and is activated by flexing the case inward.
    • Or insert the Ducky while pressing the squeeze button.
    • If your payload has BUTTON_DEF ATTACKMODE STORAGE, that also works.
    • On Kali: check 'lsblk' to see if a new block device appeared (e.g. /dev/sdb).
        """)
        drive_path = prompt("Enter mount path for DUCKY drive (blank to abort)", "")
        if not drive_path:
            sys.exit(0)
        drive = Path(drive_path)

    # Run drive health check
    check_drive_health(drive)

    # Check for existing inject.bin
    if check_inject_bin(drive):
        info("An existing inject.bin is present on the drive.")
        if confirm("Remove existing inject.bin before uploading new payload?"):
            (drive / "inject.bin").unlink()
            ok("Existing inject.bin removed.")

    check_firmware_version()

    # Steps 7/8 — Not applicable (no SSH/network on the Rubber Ducky)
    heading("Steps 7 & 8 — Not Applicable")
    info("The USB Rubber Ducky has no network interface or SSH access.")
    info("Firmware updates are NOT supported on the 2022 model — no action needed.")

    # Steps 9-10 — Payload
    info("DuckyScript 3.0 source files (.txt) must be compiled to inject.bin via PayloadStudio.")
    info(f"PayloadStudio URL: {PAYLOAD_STUDIO_URL}")
    info("There is no command-line compiler for DuckyScript 3.0 — the web compiler is the only official method.")
    if confirm("\nDeploy a payload?"):
        deploy_payload(drive)

    # Step 11 — Cleanup
    heading("Step 11 — Cleanup")
    info("No network settings to revert (no ICS used).")
    ok("USB Rubber Ducky is ready.")
    print("""
  Next steps:
    • Eject the DUCKY drive safely before running the payload.
    • The payload (inject.bin) executes automatically when plugged into a target.
    • Loot/output from payloads using STORAGE mode appears on the drive.
    """)


if __name__ == "__main__":
    main()
