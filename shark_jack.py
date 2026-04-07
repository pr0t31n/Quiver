#!/usr/bin/env python3
"""
Shark Jack Tool Manager
Handles detection, internet sharing, firmware updates, and payload upload
for the Shark Jack (original) and Shark Jack Cable.

The Shark Jack connects via Ethernet only (original) or CP2102 serial + Ethernet
(Cable variant). It runs OpenWRT.

Usage:
    python3 shark_jack.py
"""

import re
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    sudo_run, sudo_output, run_streaming_sudo,
    detect_usb_device, find_usb_serial,
    enable_ics, disable_ics,
    ensure_apt_packages, ensure_brew_packages,
    wait_for_ssh, SSHClient,
    get_interface_for_ip, ping, wait_for_ping,
    check_bash_syntax, extract_required_commands,
    check_packages_openwrt, install_openwrt_package,
    detection_loop,
    assign_static_ip_macos, get_macos_service_for_iface,
    clear_ssh_known_hosts,
    require_sudo,
    get_selected_payload, verify_device_connection,
)


def check_firmware_version(ssh=None):
    heading("Firmware Version Check")
    info("Checking Shark Jack firmware version…")
    current = None
    if ssh:
        try:
            _, ver_out, _ = ssh.run(
                "cat /etc/shark_jack/version 2>/dev/null || "
                "cat /etc/openwrt_release 2>/dev/null | grep DISTRIB_RELEASE"
            )
            for ln in ver_out.splitlines():
                if ln.strip():
                    current = ln.split("=", 1)[-1].strip().strip('"') if "=" in ln else ln.strip()
                    break
        except Exception as e:
            warn(f"Could not read firmware version: {e}")

    if current:
        ok(f"Shark Jack firmware: {current}")
    else:
        info("Could not auto-detect Shark Jack firmware version.")

    info("")
    info("Shark Jack firmware updates require a Hak5 account:")
    info("  1. Download firmware from: https://downloads.hak5.org/shark")
    info("  2. Upload via SCP + sysupgrade, or use recovery mode")
    info("  3. Check Hak5 docs: https://docs.hak5.org/shark-jack/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME    = "Shark Jack (Original & Cable)"
DESCRIPTION  = "Compact OpenWRT network pentest platform with RJ45"
VID_CP2102   = "10C4"   # Silicon Laboratories
PID_CP2102   = "EA60"   # CP210x (Shark Jack Cable serial)

SHARK_IP     = "172.16.24.1"
HOST_IP      = "172.16.24.2"
HOST_MASK    = "255.255.255.0"
SSH_USER     = "root"
SSH_PASS     = "hak5shark"

FIRMWARE_URL = "https://downloads.hak5.org/shark"

NETMODES = {"DHCP_CLIENT", "DHCP_SERVER", "TRANSPARENT"}

MODE_INSTRUCTIONS = """
Shark Jack not detected.

  Shark Jack (original) — Ethernet only:
    1. Flip the physical switch to ARMING MODE (middle position).
       OFF/Charging = fully back | Arming = middle | Attack = forward (toward RJ45)
    2. Plug an Ethernet cable from your computer to the Shark Jack's RJ45 port.
    3. Wait ~30 seconds for the device to boot.
    4. Manually assign your Ethernet interface:
         172.16.24.2 / 255.255.255.0

  Shark Jack Cable — USB serial + Ethernet:
    1. Plug the USB-C cable into the Shark Jack Cable and into this computer.
    2. Flip the switch to ARMING MODE.
    3. A serial port (CP2102) and Ethernet should both appear.
    4. Baud: 57600, 8N1, no flow control.
    5. Also plug Ethernet cable into your computer if using SSH.

  LED behaviour in arming mode: solid BLUE.
"""

RESET_INSTRUCTIONS = """
Shark Jack Factory Recovery:

  1. Fully charge the Shark Jack first (original only).
  2. Set switch to OFF position.
  3. Hold the reset button (paperclip hole on the bottom of the device).
  4. While holding reset, flip switch to ARMING MODE.
  5. Hold for 7 seconds — LED: solid GREEN with flashes.
  6. Assign host static IP: 192.168.1.2 / 255.255.255.0
     (different from the normal 172.16.24.x!)
  7. Browse to: http://192.168.1.1  (recovery web interface)
  8. Upload the recovery firmware .bin from:
     https://downloads.hak5.org/shark
  9. Wait 5-10 minutes. Do NOT disconnect power.
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_shark() -> bool:
    """Detect Shark Jack via Ethernet ping or CP2102 USB serial."""
    if ping(SHARK_IP):
        return True
    if detect_usb_device(VID_CP2102, PID_CP2102):
        return True
    return False


# ── Interface Setup ───────────────────────────────────────────────────────────

def configure_host_interface() -> bool:
    """Assign static IP to host Ethernet interface for Shark Jack."""
    os_name = get_os()
    device_if = get_interface_for_ip(SHARK_IP)

    if ping(SHARK_IP):
        ok(f"Shark Jack reachable at {SHARK_IP}")
        return True

    if os_name == "macos":
        if not device_if:
            device_if = prompt("Enter your Ethernet interface (e.g. en0, en3)", "en0")
        service = get_macos_service_for_iface(device_if)
        if service:
            info(f"Assigning {HOST_IP} to {service} ({device_if})…")
            assign_static_ip_macos(service, HOST_IP, HOST_MASK)
        else:
            warn(f"Set {device_if} to {HOST_IP}/{HOST_MASK} in System Settings → Network.")
            pause("Press ENTER after setting…")

    elif os_name == "linux":
        if not device_if:
            device_if = prompt("Enter your Ethernet interface", "eth0")
        info(f"Flushing existing addresses and assigning {HOST_IP}/24 to {device_if}…")
        info("  Why: Shark Jack DHCP server expects the host at 172.16.24.2.")
        info("  Expected: commands return silently on success.")
        info("  If 'Cannot find device': run 'ip link show' to list active interfaces.")
        info("  If 'RTNETLINK File exists': address already assigned — safe to ignore.")
        sudo_run(f"ip addr flush dev {device_if} 2>/dev/null")
        sudo_run(f"ip addr add {HOST_IP}/24 dev {device_if}")
        sudo_run(f"ip link set {device_if} up")
    else:
        warn(f"Set your Ethernet adapter to {HOST_IP}/{HOST_MASK} manually.")
        pause("Press ENTER after setting…")

    time.sleep(2)
    if ping(SHARK_IP):
        ok(f"Shark Jack reachable at {SHARK_IP}")
        return True

    # --- Troubleshoot interface failure ---
    warn("Still cannot reach Shark Jack.")
    print(f"""
  Troubleshooting checklist:
    • Ensure switch is in ARMING mode (middle position), not ATTACK (forward) or OFF (back).
    • In arming mode the LED should be solid BLUE; YELLOW/AMBER = attack mode.
    • Use an Ethernet cable, not USB — the Shark Jack has no USB-to-host connection.
    • If using Shark Jack Cable (USB-C variant), also plug Ethernet for SSH.
    • Try a different cable or port.
    • Assign host IP manually: {HOST_IP} / {HOST_MASK}

  Recovery mode (if Shark Jack won't boot normally):
    • Assign host IP: 192.168.1.2 / 255.255.255.0
    • Browse to: http://192.168.1.1 (recovery web interface)
    • Shark Jack IP in recovery mode is 192.168.1.1, not {SHARK_IP}
    """)

    # Check if recovery mode is active
    if ping("192.168.1.1"):
        warn("Detected Shark Jack in RECOVERY mode at 192.168.1.1!")
        warn("Follow the recovery procedure above to flash firmware.")
    return False


# ── Internet Sharing ──────────────────────────────────────────────────────────

def setup_internet_sharing() -> bool:
    heading("Step 7 — Internet Sharing Setup")

    print("""
  The Shark Jack needs internet access to run sysupgrade.
  Connect the Shark Jack's Ethernet OUT port (if available) to an internet-
  connected network, or share internet from this computer.
    """)

    method = numbered_menu("Internet method:", [
        "Share from this computer via NAT/ICS",
        "Connect Shark Jack Ethernet to internet directly",
        "Skip — device already has internet",
    ])

    if method == 0:
        return enable_ics(SHARK_IP)
    elif method == 1:
        info("Plug Shark Jack into a network with DHCP. It will get internet via DHCP_CLIENT.")
        pause("Press ENTER once connected…")
        # Verify
        rc, out, _ = (lambda s: s.run("ping -c1 8.8.8.8 2>&1"))(
            wait_for_ssh(SHARK_IP, SSH_USER, SSH_PASS, timeout=30) or type('', (), {'run': lambda *a: (1, '', '')})()
        )
        return True
    else:
        return True


# ── Firmware Update ───────────────────────────────────────────────────────────

def firmware_update(ssh: SSHClient) -> bool:
    heading("Step 8 — Firmware Update")

    rc, ver_out, _ = ssh.run("cat /etc/openwrt_release 2>/dev/null")
    current_ver = "unknown"
    for ln in ver_out.splitlines():
        if "DISTRIB_RELEASE" in ln:
            current_ver = ln.split("=", 1)[-1].strip().strip('"')
            break
    info(f"Current firmware: {current_ver}")

    print(f"\n  Download firmware from: {FIRMWARE_URL}")
    fw_path = prompt("Path to firmware .bin (leave blank to skip)")
    if not fw_path:
        info("Skipping firmware update.")
        return True

    fw_path = Path(fw_path).expanduser()
    if not fw_path.exists():
        err(f"Not found: {fw_path}")
        return False

    info("Uploading firmware…")
    remote_path = f"/tmp/{fw_path.name}"
    if not ssh.upload(str(fw_path), remote_path):
        err("Upload failed.")
        return False
    ok(f"Uploaded to {remote_path}")

    info("Running sysupgrade -n (device will reboot — do NOT disconnect power)…")
    ssh.run(f"sysupgrade -n {remote_path} &", timeout=5)

    info("Waiting for reboot…")
    time.sleep(20)
    if wait_for_ping(SHARK_IP, timeout=180):
        ok("Shark Jack is back online.")
    else:
        warn("Device did not respond within 3 minutes. Check LED and switch position.")
    return True


# ── Payload Validation ────────────────────────────────────────────────────────

SHARK_BUILTINS = {
    "NETMODE", "LED", "SERIAL_WRITE", "BUTTON", "ACTIVATE", "LIST",
    "UPDATE_PAYLOADS", "UPDATE_FIRMWARE",
}

def validate_shark_payload(path: Path) -> list[str]:
    issues = []
    try:
        content = path.read_text()
    except Exception as e:
        return [f"Cannot read file: {e}"]

    lines = content.splitlines()

    # Check shebang
    if lines and not lines[0].startswith("#!"):
        issues.append("WARNING: No shebang line (#!/bin/bash or #!/bin/sh recommended)")

    # Check NETMODE usage
    netmode_found = False
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*NETMODE\s+(\S+)", ln)
        if m:
            netmode_found = True
            mode = m.group(1).upper()
            if mode not in NETMODES:
                issues.append(f"WARNING: Line {i}: Unknown NETMODE: {mode}  (valid: {', '.join(NETMODES)})")

    if not netmode_found:
        issues.append("WARNING: No NETMODE command found — network mode will not be configured")

    # Check LED calls
    led_states = {"SETUP", "ATTACK", "FINISH", "FAIL", "STAGE1", "STAGE2", "R", "G", "B", "Y", "M"}
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*LED\s+(.+)", ln)
        if m:
            parts = m.group(1).upper().split()
            if parts and parts[0] not in led_states and not re.match(r"^#?[0-9A-F]{3,6}$", parts[0]):
                issues.append(f"INFO: Line {i}: Unrecognised LED state: {parts[0]}")

    # Bash syntax check
    bash_errors = check_bash_syntax(str(path))
    issues.extend(f"BASH SYNTAX: {e}" for e in bash_errors)

    # Check sync before exit
    content_lower = content.lower()
    if "sync" not in content_lower:
        issues.append("INFO: No 'sync' before exit — loot data may not be flushed to storage")

    return issues


# ── Payload Upload ────────────────────────────────────────────────────────────

def upload_payload(ssh: SSHClient) -> bool:
    heading("Step 9 — Payload Upload")

    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        payload_path = Path(preselected).expanduser()
    else:
        payload_path = Path(prompt("Path to payload file (payload.sh or payload)")).expanduser()
    if not payload_path.exists():
        err(f"Not found: {payload_path}")
        return False

    # Validate
    heading("Step 10 — Payload Review")
    info("Validating payload…")
    issues = validate_shark_payload(payload_path)
    if issues:
        warn(f"{len(issues)} issue(s) found:")
        for issue in issues:
            print(f"    {issue}")
        if not confirm("Continue uploading despite issues?"):
            return False
    else:
        ok("Payload looks good.")

    # Check package dependencies
    info("Checking external command dependencies…")
    cmds = extract_required_commands(str(payload_path), SHARK_BUILTINS)
    if cmds:
        info(f"Commands used: {', '.join(cmds)}")
        availability = check_packages_openwrt(ssh, cmds)
        missing = [c for c, a in availability.items() if not a]
        if missing:
            warn(f"Missing: {', '.join(missing)}")
            for cmd in missing:
                if confirm(f"Install package for '{cmd}' via opkg?"):
                    install_openwrt_package(ssh, cmd)
        else:
            ok("All dependencies available.")

    # Upload
    remote_path = "/root/payload/payload.sh"
    info(f"Uploading to {remote_path}…")
    ssh.run("mkdir -p /root/payload")
    if not ssh.upload(str(payload_path), remote_path):
        err("Upload failed.")
        return False
    ssh.run(f"chmod +x {remote_path}")
    ok("Payload uploaded.")
    return True


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(ssh: SSHClient, ics_enabled: bool):
    heading("Step 11 — Cleanup")
    ssh.close()
    if ics_enabled:
        disable_ics()
    ok("Shark Jack is ready.")
    print("""
  Next steps:
    • Flip the switch to ATTACK MODE (toward the RJ45 port) to run the payload.
    • Plug into target network. The payload executes automatically.
    • Flip back to ARMING MODE to retrieve loot from /root/loot/ via SSH.
    • LED: SETUP → ATTACK → FINISH
    """)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    # Ensure apt packages are installed on Kali/Debian before anything else.
    # paramiko → SSH to the Shark Jack; pyserial → serial console on Cable variant.
    info("Checking required system packages (Kali/Debian)…")
    info("  Why: python3-paramiko (SSH) and python3-serial (serial) are needed.")
    info("  If apt-get fails: run manually: sudo apt-get install -y python3-paramiko python3-serial")
    ensure_apt_packages(["python3-paramiko", "python3-serial"])

    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Step 1 — Connect the Shark Jack in Arming Mode")
    _CONNECT_INSTRUCTIONS = (
        "Switch positions:\n"
        "  ■ OFF / Charging — fully toward body (away from RJ45)\n"
        "  ■ ARMING MODE    — middle position  ← required\n"
        "  ■ ATTACK MODE    — fully toward RJ45 port\n\n"
        "Shark Jack (original):\n"
        "  1. Flip switch to ARMING MODE (middle position).\n"
        "  2. Connect an Ethernet cable from your computer to the Shark Jack RJ45 port.\n"
        "  3. Ensure your host interface is set to 172.16.24.2 / 255.255.255.0.\n\n"
        "Shark Jack Cable:\n"
        "  1. Flip switch to ARMING MODE.\n"
        "  2. Connect the USB-C cable to this computer.\n"
        "  3. Connect an Ethernet cable to the RJ45 port.\n\n"
        "Expected LED boot sequence (~30 s):\n"
        "  ● AMBER/YELLOW      — Booting\n"
        "  ● Solid BLUE        — ARMING MODE ready ✓  ← wait for this"
    )
    detected = verify_device_connection(
        detect_shark, TOOL_NAME, _CONNECT_INSTRUCTIONS, max_retries=3
    )
    if not detected:
        err("Shark Jack not detected. Exiting.")
        sys.exit(1)

    # Step 4 — Interface
    heading("Step 4 — Interface Configuration")
    configure_host_interface()

    # Step 7 — ICS
    ics_enabled = setup_internet_sharing()

    # Step 8 — SSH + firmware
    info(f"Connecting via SSH to {SHARK_IP}…")
    info("  Why: SSH is used for firmware upload, payload deployment and package checks.")
    info(f"  Expected: SSH connects within 60 s. Default credentials: {SSH_USER} / {SSH_PASS}")
    info("  If SSH fails: ensure switch is in ARMING mode (solid BLUE LED).")
    info("  Shark Jack Cable serial: CP2102 appears as /dev/ttyUSB0. Baud: 57600 8N1.")
    info("  If no serial port appears: run 'lsusb' and confirm 10C4:EA60 is listed.")
    ssh = wait_for_ssh(SHARK_IP, SSH_USER, SSH_PASS, timeout=60)
    if not ssh:
        # --- Troubleshoot SSH failure ---
        warn("SSH failed with default credentials.")

        # 1. Known-hosts conflict — common after firmware reflash
        kh_file = Path.home() / ".ssh" / "known_hosts"
        if kh_file.exists() and SHARK_IP in kh_file.read_text(errors="replace"):
            warn(f"Stale known_hosts entry found for {SHARK_IP}.")
            if confirm("Clear known_hosts entry and retry?", default=True):
                clear_ssh_known_hosts(SHARK_IP)
                ssh = wait_for_ssh(SHARK_IP, SSH_USER, SSH_PASS, timeout=30)

        # 2. Custom password
        if not ssh:
            custom_pass = prompt("Enter custom SSH password if changed (blank to abort)", "")
            if custom_pass:
                ssh = wait_for_ssh(SHARK_IP, SSH_USER, custom_pass, timeout=30)

        if not ssh:
            err("SSH connection failed.")
            print(f"""
  Troubleshooting:
    • Ensure switch is in ARMING mode (middle position, solid BLUE LED).
    • Host IP must be {HOST_IP} / {HOST_MASK}.
    • Default password: {SSH_PASS}
    • Shark Jack (original): check battery charge — device won't boot if drained.
    • opkg failures: the Shark Jack may need internet access for package install.
            """)
            if ics_enabled:
                disable_ics()
            sys.exit(1)
    ok("SSH connected.")
    check_firmware_version(ssh)

    firmware_update(ssh)

    # Steps 9-10
    if get_selected_payload() or confirm("\nUpload a payload?"):
        upload_payload(ssh)

    cleanup(ssh, ics_enabled)


if __name__ == "__main__":
    main()
