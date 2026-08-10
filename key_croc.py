#!/usr/bin/env python3
"""
Key Croc Tool Manager
Handles detection, WiFi configuration, firmware updates, and payload upload
for the Key Croc.

The Key Croc is an inline keylogger/HID injector that sits between a keyboard
and target PC. It runs Debian Linux and uses WiFi for remote SSH access.
In arming mode it presents as USB serial (ACM) + USB storage.

Usage:
    python3 key_croc.py
"""

import re
import sys
import time
import glob
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    sudo_run, sudo_output,
    require_sudo, ensure_apt_packages,
    detect_usb_device, find_usb_serial, find_mounted_drive,
    wait_for_ssh, SSHClient,
    get_interface_for_ip, ping, wait_for_ping,
    check_bash_syntax, extract_required_commands,
    check_packages_debian, install_debian_package,
    detection_loop,
    clear_ssh_known_hosts,
    get_selected_payload, verify_device_connection,
)


def check_firmware_version(ssh=None):
    heading("Firmware Version Check")
    info("Checking Key Croc firmware version…")
    current = None
    if ssh:
        try:
            _, ver_out, _ = ssh.run("cat /etc/key_croc/version 2>/dev/null || cat /etc/os-release 2>/dev/null | grep VERSION=")
            for ln in ver_out.splitlines():
                if ln.strip():
                    current = ln.split("=", 1)[-1].strip().strip('"') if "=" in ln else ln.strip()
                    break
        except Exception as e:
            warn(f"Could not read firmware version: {e}")

    if current:
        ok(f"Key Croc firmware: {current}")
    else:
        info("Could not auto-detect Key Croc firmware version.")

    info("")
    info("Key Croc firmware updates require a Hak5 account:")
    info("  1. Download firmware from: https://downloads.hak5.org/key-croc")
    info("  2. In arming mode, copy the .tar.gz to the root of the KeyCroc drive")
    info("  3. Safely eject and replug — firmware flashes automatically")
    info("  4. Check Hak5 docs: https://docs.hak5.org/key-croc/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME    = "Key Croc"
DESCRIPTION  = "Inline keyboard implant — keystroke logging + HID injection (Debian)"

# In arming mode the Key Croc presents as USB CDC-ACM (serial) + mass storage
# These VID:PIDs are generic; arming mode can also present as vendor-specific
VID_ARMING   = "0F0D"   # Hori (placeholder; actual varies by firmware)
DRIVE_LABEL  = "KeyCroc"
SSH_USER     = "root"
SSH_PASS     = "hak5croc"

FIRMWARE_URL = "https://downloads.hak5.org/key-croc"

# DuckyScript 2.x / Key Croc payload keywords
CROC_KEYWORDS = {
    "REM", "DELAY", "STRING", "GUI", "ALT", "CTRL", "SHIFT", "ENTER", "BACKSPACE",
    "TAB", "ESCAPE", "DELETE", "HOME", "END", "INSERT", "PAGEUP", "PAGEDOWN",
    "UP", "DOWN", "LEFT", "RIGHT", "F1", "F2", "F3", "F4", "F5", "F6",
    "F7", "F8", "F9", "F10", "F11", "F12", "CAPSLOCK", "NUMLOCK", "SCROLLLOCK",
    "QUACK", "LED", "ATTACKMODE", "NETMODE",
    # Key Croc specific
    "MATCH", "WAIT_FOR_CAPS_ON", "WAIT_FOR_CAPS_OFF",
    "WAIT_FOR_NUM_ON", "WAIT_FOR_NUM_OFF",
}

MODE_INSTRUCTIONS = """
Key Croc not detected in arming mode.

  Arming Mode:
    1. Locate the small arming button on the BOTTOM of the Key Croc device
       (requires a paperclip or pin — it's a recessed button).
    2. Hold the arming button while plugging the Key Croc into THIS computer's
       USB port.
    3. Release after 2 seconds. LED should blink BLUE.
    4. The device will appear as:
       - USB serial port (ACM)
       - USB mass storage drive labeled "KeyCroc"

  If the Key Croc is already plugged in (in attack mode):
    1. Unplug from the current computer.
    2. Hold the arming button and replug into THIS computer.

  Alternative — via WiFi (if previously configured):
    - The Key Croc may already be accessible via SSH on its WiFi IP.
    - Find the IP: check your router DHCP table for "KeyCroc" hostname.
"""

RESET_INSTRUCTIONS = """
Key Croc Factory Reset:

  Method 1 — Via arming mode (config.txt):
    1. Enter arming mode (arming button + plug in).
    2. Open the KeyCroc drive.
    3. Delete or edit config.txt — remove or clear WIFI_SSID and WIFI_PASS entries.
    4. To fully reset: delete all files in the payloads/ directory.
    5. Safely eject and re-insert (still in arming mode) to apply.

  Method 2 — Full reflash:
    1. Download firmware from: https://downloads.hak5.org/key-croc
    2. In arming mode, copy the upgrade .tar.gz to the ROOT of the KeyCroc drive.
    3. Safely eject, then unplug and replug (still holding arming button).
    4. Wait 5-10 minutes. LED blinks during flash.
    5. Do NOT unplug during flash.

  WARNING: Enabling ARMING_PASS in config.txt without noting it down can lock
  you out. If locked out, a factory reset will be required.
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_key_croc() -> bool:
    """Detect Key Croc in arming mode (drive + serial) or via WiFi SSH."""
    # Check for KeyCroc drive
    if find_mounted_drive(DRIVE_LABEL):
        return True
    # Check serial (arming mode presents ACM serial)
    os_name = get_os()
    if os_name == "linux":
        acm_devs = glob.glob("/dev/ttyACM*")
        if acm_devs:
            return True
    elif os_name == "macos":
        serial_devs = glob.glob("/dev/tty.usbmodem*")
        if serial_devs:
            return True
    # Check WiFi (if previously configured)
    # We don't know the IP, but let's see if there's a croc-related hostname
    return False


def find_croc_wifi_ip() -> str:
    """Try to find the Key Croc's WiFi IP from the KeyCroc drive's loot."""
    drive = find_mounted_drive(DRIVE_LABEL)
    if drive:
        # Check for any IP hints in loot directory
        croc_info = drive / "loot" / "croc_info.txt"
        if croc_info.exists():
            content = croc_info.read_text()
            m = re.search(r"addr:(\d+\.\d+\.\d+\.\d+)", content)
            if m:
                return m.group(1)
    return ""


# ── WiFi Configuration ────────────────────────────────────────────────────────

def _check_config_lockout(config_text: str):
    """Warn if ARMING_PASS is set in config.txt — could lock out arming mode."""
    if re.search(r"^\s*ARMING_PASS\s+\S+", config_text, re.MULTILINE):
        warn("ARMING_PASS is set in config.txt!")
        warn("If you forget this password you will be locked out of arming mode.")
        warn("Ensure you have noted it down. Recovery requires a factory reset.")


def configure_wifi(drive: Path) -> bool:
    """Configure WiFi in config.txt on the KeyCroc drive."""
    heading("WiFi Configuration")

    config_path = drive / "config.txt"
    if not config_path.exists():
        config_path.write_text("")

    current = config_path.read_text()

    # Check for ARMING_PASS lockout risk
    _check_config_lockout(current)

    # Show current WiFi settings (masked)
    ssid_m = re.search(r"^WIFI_SSID\s+(.+)$", current, re.MULTILINE)
    if ssid_m:
        info(f"Current WIFI_SSID: {ssid_m.group(1)}")

    if not confirm("Configure or update WiFi credentials?"):
        return True

    ssid = prompt("WiFi SSID")
    password = prompt("WiFi Password")
    lang = prompt("Keyboard language (e.g. us, de, fr, gb)", "us")
    ssh_enable = confirm("Enable SSH?", default=True)

    # Build new config
    new_config = []
    for line in current.splitlines():
        # Remove existing WiFi/SSH/language lines to replace them
        if re.match(r"^(WIFI_SSID|WIFI_PASS|SSH|DUCKY_LANG)\b", line.strip()):
            continue
        new_config.append(line)

    new_config.extend([
        f"DUCKY_LANG {lang}",
        f"WIFI_SSID {ssid}",
        f"WIFI_PASS {password}",
    ])
    if ssh_enable:
        new_config.append("SSH ENABLE")

    config_path.write_text("\n".join(new_config) + "\n")
    ok("config.txt updated.")
    info("Eject and re-insert the Key Croc to apply WiFi config.")
    info("Once connected to WiFi, find its IP via your router's DHCP table.")

    wifi_ip = prompt("Enter the Key Croc's WiFi IP address (after it connects)", "")
    return wifi_ip


# ── Firmware Update ───────────────────────────────────────────────────────────

def firmware_update_drive(drive: Path) -> bool:
    """Update firmware by copying .tar.gz to the KeyCroc drive root."""
    heading("Step 8 — Firmware Update (Drive Method)")
    print(f"\n  Download firmware from: {FIRMWARE_URL}")
    fw_path = prompt("Path to firmware .tar.gz (leave blank to skip)")
    if not fw_path:
        info("Skipping firmware update.")
        return True

    fw_path = Path(fw_path).expanduser()
    if not fw_path.exists():
        err(f"Not found: {fw_path}")
        return False

    import shutil
    dest = drive / fw_path.name
    info(f"Copying firmware to {dest}…")
    shutil.copy2(fw_path, dest)
    ok("Firmware copied.")
    print("""
  To complete the update:
    1. Safely eject the KeyCroc drive.
    2. Unplug and replug while holding the arming button.
    3. Wait 5-10 minutes. LED blinks during flash. Do NOT unplug.
    4. When complete, the drive will remount.
    """)
    pause("Press ENTER after the update is complete…")
    return True


def firmware_update_ssh(ssh: SSHClient) -> bool:
    """Update firmware via SSH SCP + apt."""
    heading("Step 8 — Firmware Update (SSH Method)")

    rc, ver_out, _ = ssh.run("cat /etc/os-release 2>/dev/null | grep VERSION")
    info(f"Current OS info: {ver_out.strip()}")

    update_method = numbered_menu("Update method:", [
        "apt-get update && apt-get upgrade (Debian package updates)",
        "FIRMWARE - Full firmware upgrade via .tar.gz",
        "Skip",
    ])

    if update_method == 0:
        info("Running apt-get update && apt-get upgrade…")
        rc, out, _ = ssh.run("apt-get update 2>&1", timeout=120)
        rc2, out2, _ = ssh.run(
            "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1", timeout=300
        )
        if rc2 == 0:
            ok("Packages updated.")
        else:
            warn(f"Some packages may have failed: {out2[-200:]}")
        return True

    elif update_method == 1:
        print(f"\n  Download from: {FIRMWARE_URL}")
        fw_path = prompt("Path to firmware .tar.gz")
        if not fw_path:
            return True
        fw_path = Path(fw_path).expanduser()
        if not fw_path.exists():
            err(f"Not found: {fw_path}")
            return False
        remote_path = f"/tmp/{fw_path.name}"
        info("Uploading firmware…")
        if not ssh.upload(str(fw_path), remote_path):
            err("Upload failed.")
            return False
        ok(f"Uploaded to {remote_path}")
        info("Extracting and running upgrade script…")
        ssh.run(f"cd /tmp && tar xzf {fw_path.name} 2>&1")
        rc3, out3, _ = ssh.run("cd /tmp && ./upgrade.sh 2>&1", timeout=30)
        info("Device will reboot after upgrade completes.")
        return True

    else:
        info("Skipping firmware update.")
        return True


# ── Payload Validation ────────────────────────────────────────────────────────

def validate_croc_payload(path: Path) -> list[str]:
    """Validate a Key Croc payload (bash + DuckyScript via QUACK)."""
    issues = []
    try:
        content = path.read_text()
    except Exception as e:
        return [f"Cannot read: {e}"]

    lines = content.splitlines()

    if lines and not lines[0].startswith("#!") and not lines[0].startswith("REM"):
        issues.append("INFO: No shebang or REM header at start")

    # Check for MATCH trigger (Key Croc specific)
    has_match = any(re.match(r"^\s*MATCH\b", ln, re.IGNORECASE) for ln in lines)
    if not has_match:
        issues.append("INFO: No MATCH trigger — payload won't auto-trigger on keyword. Is this intentional?")
    else:
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*MATCH\s+(.+)", ln, re.IGNORECASE)
            if m:
                pattern = m.group(1).strip()
                if not pattern:
                    issues.append(f"WARNING: Line {i}: Empty MATCH pattern")
                elif pattern.startswith("/") and not pattern.endswith("/"):
                    issues.append(f"WARNING: Line {i}: MATCH regex may be malformed: {pattern}")

    # Check QUACK syntax within bash payload
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*QUACK\s+(.*)", ln)
        if m:
            quack_arg = m.group(1).strip()
            if not quack_arg:
                issues.append(f"WARNING: Line {i}: Empty QUACK command")

    # Bash syntax check
    bash_errors = check_bash_syntax(str(path))
    issues.extend(f"BASH SYNTAX: {e}" for e in bash_errors)

    # Check for loot path references
    if "loot" in content.lower() and "/root/udisk/loot" not in content.lower():
        if "/loot" in content:
            issues.append("INFO: Loot path may need to be /root/udisk/loot/ on Key Croc")

    return issues


# ── Payload Upload ────────────────────────────────────────────────────────────

def upload_payload_drive(drive: Path) -> bool:
    """Upload payload to KeyCroc drive (arming mode)."""
    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        payload_path = Path(preselected).expanduser()
    else:
        payload_path = Path(prompt("Path to payload file")).expanduser()
    if not payload_path.exists():
        err(f"Not found: {payload_path}")
        return False

    # Validate
    issues = validate_croc_payload(payload_path)
    if issues:
        warn(f"{len(issues)} issue(s):")
        for issue in issues:
            print(f"    {issue}")
        if not confirm("Continue uploading?"):
            return False

    payloads_dir = drive / "payloads"
    payloads_dir.mkdir(exist_ok=True)

    dest = payloads_dir / payload_path.name
    import shutil
    shutil.copy2(payload_path, dest)
    ok(f"Payload copied to {dest}")
    info("Safely eject the KeyCroc drive to return to attack mode.")
    return True


def upload_payload_ssh(ssh: SSHClient) -> bool:
    """Upload payload via SSH."""
    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        payload_path = Path(preselected).expanduser()
    else:
        payload_path = Path(prompt("Path to payload file")).expanduser()
    if not payload_path.exists():
        err(f"Not found: {payload_path}")
        return False

    issues = validate_croc_payload(payload_path)
    if issues:
        warn(f"{len(issues)} issue(s):")
        for issue in issues:
            print(f"    {issue}")
        if not confirm("Continue?"):
            return False

    # Check dependencies
    cmds = extract_required_commands(str(payload_path), CROC_KEYWORDS)
    if cmds:
        avail = check_packages_debian(ssh, cmds)
        missing = [c for c, a in avail.items() if not a]
        if missing:
            warn(f"Missing: {', '.join(missing)}")
            for cmd in missing:
                if confirm(f"Install '{cmd}'?"):
                    install_debian_package(ssh, cmd)

    remote_path = f"/root/udisk/payloads/{payload_path.name}"
    ssh.run("mkdir -p /root/udisk/payloads")
    if not ssh.upload(str(payload_path), remote_path):
        err("Upload failed.")
        return False
    ssh.run(f"chmod +x {remote_path}")
    ok(f"Payload uploaded to {remote_path}")
    return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking required apt packages (python3-paramiko, python3-requests, python3-serial)…")
        ensure_apt_packages(["python3-paramiko", "python3-requests", "python3-serial"])

    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Step 1 — Connect the Device")
    print("""
  The Key Croc can be accessed in two ways:
    A) ARMING MODE — plug into THIS computer with arming button held
       • Presents as USB serial + "KeyCroc" drive
    B) VIA WiFi — SSH over WiFi (requires prior WiFi configuration)

  For initial setup or firmware update: use ARMING MODE (Option A).

  To enter arming mode:
    1. Hold the arming button (paperclip hole on the bottom of the device).
    2. While holding, plug the Key Croc into a USB port on THIS computer.
    3. Release after 2 seconds. LED blinks BLUE.
    4. "KeyCroc" drive will appear on your desktop.

  Expected LED boot sequence (~20 s):
    ● Solid RED            — Booting / OS loading
    ● Solid YELLOW/AMBER   — Setup / init stage
    ● Blinking BLUE        — ARMING MODE ready — "KeyCroc" drive mounted ✓

  Other LED states to know:
    ● MAGENTA solid        — Caps Lock active (device is in pass-through mode)
    ● GREEN solid          — Payload FINISH stage (attack completed successfully)
    ● RED solid            — Payload FAIL stage
    ● YELLOW → payload LEDs — Attack mode: payload-controlled color sequence
    ● RED/BLUE alternating — Firmware flashing in progress (DO NOT unplug)
    ● No LED               — Not in arming mode, or device not powered
    """)

    conn_method = numbered_menu("How to connect?", [
        "Arming mode (USB — physical access to device)",
        "WiFi SSH (device already on your network)",
    ])

    ssh = None
    drive = None
    wifi_ip = ""

    if conn_method == 1:
        # WiFi SSH path
        wifi_ip = prompt("Key Croc WiFi IP address")
        if not wifi_ip:
            err("IP address required for WiFi connection.")
            sys.exit(1)
        pause(f"Press ENTER once Key Croc is powered and connected to WiFi…")
        info(f"Connecting via SSH to {wifi_ip}…")
        ssh = wait_for_ssh(wifi_ip, SSH_USER, SSH_PASS, timeout=60)
        if not ssh:
            # --- Troubleshoot WiFi SSH failure ---
            warn("SSH failed with default credentials.")

            # Known-hosts conflict (after firmware update the host key changes)
            from pathlib import Path as _Path
            kh_file = _Path.home() / ".ssh" / "known_hosts"
            if kh_file.exists() and wifi_ip in kh_file.read_text(errors="replace"):
                warn(f"Stale known_hosts entry found for {wifi_ip}.")
                if confirm("Clear known_hosts entry and retry?", default=True):
                    clear_ssh_known_hosts(wifi_ip)
                    ssh = wait_for_ssh(wifi_ip, SSH_USER, SSH_PASS, timeout=30)

            if not ssh:
                custom_pass = prompt("Enter custom SSH password if changed (blank to abort)", "")
                if custom_pass:
                    ssh = wait_for_ssh(wifi_ip, SSH_USER, custom_pass, timeout=30)

            if not ssh:
                err("SSH connection failed.")
                print(f"""
  Troubleshooting:
    • Verify the Key Croc is connected to your WiFi (check router DHCP table for 'KeyCroc').
    • Default password: {SSH_PASS}
    • Ensure SSH is enabled in config.txt: SSH ENABLE
    • If ARMING_PASS is set, enter arming mode with that password.
    • Try: ssh-keygen -R {wifi_ip}
                """)
                sys.exit(1)
        ok("SSH connected via WiFi.")
    else:
        # Arming mode path
        _ARMING_INSTRUCTIONS = (
            "Arming Mode steps:\n"
            "  1. Locate the recessed arming button on the BOTTOM of the Key Croc\n"
            "     (use a paperclip or pin).\n"
            "  2. Hold the arming button while plugging the Key Croc into this computer's USB port.\n"
            "  3. Release after 2 seconds.\n\n"
            "What to look for:\n"
            "  ● LED blinks BLUE — arming mode active ✓\n"
            "  ● A 'KeyCroc' drive appears on your desktop / file manager ✓\n"
            "  ● A USB serial (ACM) port becomes available ✓\n\n"
            "If already plugged in (attack mode): unplug, hold the arming button, then replug."
        )
        detected = verify_device_connection(
            detect_key_croc, TOOL_NAME, _ARMING_INSTRUCTIONS, max_retries=3
        )
        if not detected:
            err("Key Croc not detected. Exiting.")
            sys.exit(1)

        drive = find_mounted_drive(DRIVE_LABEL)
        if drive:
            ok(f"KeyCroc drive mounted at: {drive}")
            # Check config.txt for lockout risks immediately when drive is accessible
            cfg_path = drive / "config.txt"
            if cfg_path.exists():
                _check_config_lockout(cfg_path.read_text(errors="replace"))

    # Step 4 — Interface confirmation
    heading("Step 4 — Interface Confirmation")
    if ssh:
        ok(f"Connected via WiFi SSH to {wifi_ip}")
        rc, ifout, _ = ssh.run("ifconfig wlan0 2>/dev/null || ip addr show wlan0 2>/dev/null")
        for ln in ifout.splitlines():
            if "inet " in ln and "127.0.0.1" not in ln:
                info(f"Key Croc WiFi IP: {ln.strip()}")
    elif drive:
        ok(f"Drive: {drive}")
        serial = find_usb_serial(None, None)
        if serial:
            info(f"Serial port: {serial}  (115200 baud)")

    # Step 5/6 — Not needed if detected

    # Step 7 — Internet sharing
    heading("Step 7 — Internet Sharing")
    if conn_method == 0 and drive:
        print("""
  For firmware updates, the Key Croc needs WiFi internet access.
  Configure WiFi credentials in config.txt, then reconnect via WiFi SSH.
        """)
        if confirm("Configure WiFi credentials in config.txt now?"):
            wifi_ip = configure_wifi(drive)
            if wifi_ip:
                info(f"Attempting WiFi SSH to {wifi_ip}…")
                time.sleep(5)
                ssh = wait_for_ssh(wifi_ip, SSH_USER, SSH_PASS, timeout=90)
                if ssh:
                    ok("Connected via WiFi SSH.")

    # Step 8 — Firmware update
    check_firmware_version(ssh)
    if ssh:
        firmware_update_ssh(ssh)
    elif drive:
        if confirm("Update firmware via drive method?"):
            firmware_update_drive(drive)
    else:
        warn("No firmware update path available.")

    # Steps 9-10 — Payload
    heading("Steps 9-10 — Payload Upload")
    if get_selected_payload() or confirm("Upload a payload?"):
        if ssh:
            upload_payload_ssh(ssh)
        elif drive:
            upload_payload_drive(drive)

    # Step 11 — Cleanup
    heading("Step 11 — Cleanup")
    if ssh:
        ssh.close()
    ok("Key Croc is ready.")
    print("""
  Deployment:
    • Connect keyboard → [Keyboard USB plug] → [Key Croc] → [Target USB port]
    • The Key Croc logs all keystrokes and triggers payloads on MATCH patterns.
    • Loot is stored in /root/udisk/loot/ (visible on KeyCroc drive in arming mode).
    • To retrieve loot: enter arming mode and open the KeyCroc drive.

  Note: The Key Croc clones the VID:PID of the connected keyboard by default.
    """)


if __name__ == "__main__":
    main()
