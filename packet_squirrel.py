#!/usr/bin/env python3
"""
Packet Squirrel Tool Manager
Handles detection, internet sharing, firmware updates, and payload upload
for the Packet Squirrel Mark I and Mark II.

The Packet Squirrel is an inline Ethernet MITM device. It connects to the host
via the Ethernet IN port — there is NO USB-to-host connection (only USB power
and USB-A for flash drives). Runs OpenWRT.

Usage:
    python3 packet_squirrel.py
"""

import re
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    sudo_run, sudo_output,
    require_sudo, ensure_apt_packages,
    enable_ics, disable_ics,
    wait_for_ssh, SSHClient,
    get_interface_for_ip, ping, wait_for_ping,
    check_bash_syntax, extract_required_commands,
    check_packages_openwrt, install_openwrt_package,
    detection_loop,
    assign_static_ip_macos, get_macos_service_for_iface,
    clear_ssh_known_hosts, get_filesystem_type,
    get_selected_payload, verify_device_connection,
)


def check_firmware_version(ssh=None):
    heading("Firmware Version Check")
    info("Checking Packet Squirrel firmware version…")
    current = None
    if ssh:
        try:
            _, ver_out, _ = ssh.run("cat /etc/openwrt_release 2>/dev/null")
            for ln in ver_out.splitlines():
                if "DISTRIB_RELEASE" in ln:
                    current = ln.split("=", 1)[-1].strip().strip('"')
                    break
        except Exception as e:
            warn(f"Could not read firmware version: {e}")

    if current:
        ok(f"Packet Squirrel firmware: {current}")
    else:
        info("Could not auto-detect Packet Squirrel firmware version.")

    info("")
    info("Packet Squirrel firmware updates require a Hak5 account:")
    info("  1. Download firmware from: https://downloads.hak5.org/squirrel")
    info("  2. Upload via SCP + sysupgrade, or use USB flash drive method")
    info("  3. Check Hak5 docs: https://docs.hak5.org/packet-squirrel/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Packet Squirrel (Mark I / Mark II)"
DESCRIPTION = "Inline Ethernet MITM platform — covert network implant (OpenWRT)"

SQUIRREL_IP  = "172.16.32.1"
SSH_USER     = "root"
SSH_PASS     = "hak5squirrel"

FIRMWARE_URL = "https://downloads.hak5.org/squirrel"

NETMODES = {"BRIDGE", "TRANSPARENT", "NAT", "VPN", "CLONE"}

MODE_INSTRUCTIONS = """
Packet Squirrel not detected.

IMPORTANT: The Packet Squirrel does NOT connect to the host via USB.
It uses Ethernet — you must connect an Ethernet cable to the Ethernet IN port.

  Setup:
    1. Set the switch to position 4 (ARMING MODE).
    2. Connect an Ethernet cable from this computer to the Packet Squirrel's
       ETHERNET IN port  (left-side RJ45, above the power connector).
    3. Power the Squirrel via:
       - Mark I: Micro-USB cable
       - Mark II: USB-C cable
    4. Wait ~30 seconds. The Squirrel will assign your computer an IP via DHCP
       in the 172.16.32.0/24 range.
    5. LED: Blue blinking = arming mode ready.

  If DHCP doesn't work, manually set your Ethernet interface:
    IP: 172.16.32.10 / Mask: 255.255.255.0 / Gateway: 172.16.32.1

  The Ethernet OUT port (right side) is for connecting to the network/internet.
  Do NOT confuse IN and OUT ports.
"""

RESET_INSTRUCTIONS = """
Packet Squirrel Factory Reset:

  From a fully booted Packet Squirrel (any mode):
    1. Hold the push button for approximately 7 seconds.
    2. Device reboots.
    3. All settings, password, and payloads are reset to defaults.

  If device won't boot (firmware update via USB flash drive):
    1. Download upgrade-X.X.bin from: https://downloads.hak5.org/squirrel
    2. Format a USB flash drive as NTFS or EXT4.
    3. Copy the .bin to the root of the drive (do NOT rename or unpack).
    4. Plug USB drive into the Squirrel's USB-A port.
    5. Set switch to position 4 (arming mode).
    6. Power on — firmware auto-flashes (5-10 min).
    7. LED progression: Green blink → Red/Blue alt → Solid → Green blink → Blue blink (done).
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_squirrel() -> bool:
    """Detect Packet Squirrel via ping (Ethernet only device)."""
    return ping(SQUIRREL_IP)


# ── Interface Setup ───────────────────────────────────────────────────────────

def configure_host_interface() -> bool:
    """Ensure host can reach the Packet Squirrel."""
    if ping(SQUIRREL_IP):
        ok(f"Packet Squirrel reachable at {SQUIRREL_IP}")
        return True

    os_name = get_os()
    device_if = get_interface_for_ip(SQUIRREL_IP)

    print(f"""
  The Squirrel serves DHCP, so your interface should get an IP automatically.
  If not, assign manually: 172.16.32.10 / 255.255.255.0
    """)

    if os_name == "macos":
        if not device_if:
            device_if = prompt("Enter Ethernet interface name (e.g. en0, en3)", "en0")
        service = get_macos_service_for_iface(device_if)
        if service:
            # Try DHCP first
            info(f"Setting {service} to DHCP…")
            sudo_run(f"networksetup -setdhcp '{service}'")
            time.sleep(5)
            if ping(SQUIRREL_IP):
                ok("Got IP via DHCP.")
                return True
            # Fall back to static
            info("DHCP failed; assigning static 172.16.32.10…")
            assign_static_ip_macos(service, "172.16.32.10", "255.255.255.0")
        else:
            warn(f"Set {device_if} to DHCP or 172.16.32.10/24 in System Settings.")
            pause("Press ENTER after setting…")

    elif os_name == "linux":
        if not device_if:
            device_if = prompt("Enter Ethernet interface", "eth0")
        info(f"Requesting DHCP lease on {device_if} — this may take up to 15 seconds…")
        sudo_run(f"dhclient {device_if} 2>/dev/null &")
        time.sleep(5)
        if ping(SQUIRREL_IP):
            ok("Got IP via DHCP.")
            return True
        info(f"DHCP failed; flushing and assigning static 172.16.32.10/24 on {device_if}…")
        sudo_run(f"ip addr flush dev {device_if} 2>/dev/null")
        sudo_run(f"ip addr add 172.16.32.10/24 dev {device_if}")
        sudo_run(f"ip link set {device_if} up")
    else:
        warn("Set Ethernet adapter to DHCP or 172.16.32.10/255.255.255.0 manually.")
        pause("Press ENTER after setting…")

    time.sleep(2)
    if ping(SQUIRREL_IP):
        ok(f"Packet Squirrel reachable at {SQUIRREL_IP}")
        return True

    # --- Troubleshoot unreachable Squirrel ---
    warn("Packet Squirrel still unreachable.")
    print(f"""
  Common causes and fixes:
    • PORT CONFUSION: The IN port (left, labeled IN or above USB power) must connect
      to THIS computer. The OUT port connects to the router/target network.
      Swapping IN/OUT is the #1 cause of detection failure.
    • Switch must be in position 4 (ARMING MODE). Positions 1-3 run payloads.
    • LED: BLUE blinking = arming mode ready. If no LED, check USB power cable.
    • DHCP lease may take 10-15 seconds — wait and retry.

  If DHCP consistently fails:
    • Manually assign: 172.16.32.10 / 255.255.255.0 / gateway 172.16.32.1
    • Check: the Squirrel's DHCP server may be disabled if firmware is corrupt.
      In that case use the USB flash drive firmware update method.
    """)
    return False


# ── Internet Sharing ──────────────────────────────────────────────────────────

def setup_internet_sharing() -> bool:
    heading("Step 7 — Internet Sharing Setup")

    print("""
  To update firmware, the Squirrel needs internet access.
  Preferred: Connect the Ethernet OUT port to an internet-connected network
  (router or switch). The Squirrel will get internet via the OUT port.

  Alternative: Share internet from this computer through the Squirrel.
  Note: Both methods require the Squirrel's Ethernet IN to remain connected
  to this computer for SSH access.
    """)

    method = numbered_menu("Internet method:", [
        "Connect OUT port to internet (recommended)",
        "Share from this computer via NAT",
        "Skip — device already has internet",
    ])

    if method == 0:
        pause("Connect OUT port to internet-connected network, then press ENTER…")
        # Test internet on squirrel
        ssh = wait_for_ssh(SQUIRREL_IP, SSH_USER, SSH_PASS, timeout=30)
        if ssh:
            rc, out, _ = ssh.run("ping -c1 8.8.8.8 2>&1")
            ssh.close()
            if rc == 0:
                ok("Squirrel has internet access via OUT port.")
                return True
            warn("Squirrel cannot reach the internet via OUT port. Try NAT sharing.")
        return method == 0

    elif method == 1:
        return enable_ics(SQUIRREL_IP)

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

    update_method = numbered_menu("Firmware update method:", [
        "Upload .bin via SCP + sysupgrade (SSH)",
        "USB flash drive (requires USB drive)",
        "Skip",
    ])

    if update_method == 0:
        print(f"\n  Download from: {FIRMWARE_URL}")
        fw_path = prompt("Path to upgrade-X.X.bin")
        if not fw_path:
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
        info("Running sysupgrade -n (do NOT disconnect power or Ethernet IN)…")
        ssh.run(f"sysupgrade -n {remote_path} &", timeout=5)
        info("Waiting for reboot (up to 3 min)…")
        time.sleep(20)
        if wait_for_ping(SQUIRREL_IP, timeout=180):
            ok("Packet Squirrel is back online.")
        else:
            warn("No response within 3 minutes — check LED.")
        return True

    elif update_method == 1:
        print(f"""
  USB Flash Drive Update:
    1. Format a USB flash drive as NTFS or EXT4 (NOT FAT32 — file size limit).
    2. Download upgrade-X.X.bin from {FIRMWARE_URL}
    3. Copy the .bin to the ROOT of the drive (do not rename or unpack).
    4. Plug the USB drive into the Squirrel's USB-A port.
    5. Ensure switch is in position 4 (arming mode).
    6. Power cycle the Squirrel.
    7. LED: Green blink → Red/Blue alt → solid → Green blink → Blue blink = done.
    8. Wait the full 5-10 minutes.
        """)
        # Check filesystem type if a USB drive path is provided
        usb_path = prompt("Enter path to USB flash drive (to verify filesystem), or leave blank", "")
        if usb_path:
            fstype = get_filesystem_type(usb_path)
            if fstype:
                info(f"USB drive filesystem: {fstype}")
                if "FAT" in fstype and "32" in fstype:
                    warn("FAT32 has a 4 GB file size limit — this is usually fine for firmware .bin files.")
                elif "FAT" in fstype and "16" in fstype:
                    warn("FAT16 detected — format as NTFS or EXT4 for best compatibility.")
                elif fstype in ("NTFS", "EXT4", "EXT3", "EXT2"):
                    ok(f"{fstype} filesystem confirmed — compatible.")
                else:
                    warn(f"Filesystem '{fstype}' may not be supported — use NTFS or EXT4.")
        pause("Press ENTER after update is complete…")
        return True

    else:
        info("Skipping firmware update.")
        return True


# ── Payload Validation ────────────────────────────────────────────────────────

SQUIRREL_BUILTINS = {
    "NETMODE", "LED", "BUTTON", "USB_WAIT", "USB_FREE",
    "NO_LED", "SWITCH",
}


def validate_squirrel_payload(path: Path) -> list[str]:
    issues = []
    try:
        content = path.read_text()
    except Exception as e:
        return [f"Cannot read file: {e}"]

    lines = content.splitlines()

    if lines and not lines[0].startswith("#!"):
        issues.append("WARNING: No shebang line")

    # Check NETMODE
    netmode_found = False
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*NETMODE\s+(\S+)", ln)
        if m:
            netmode_found = True
            mode = m.group(1).upper()
            if mode not in NETMODES:
                issues.append(f"WARNING: Line {i}: Unknown NETMODE: {mode}  (valid: {', '.join(NETMODES)})")
    if not netmode_found:
        issues.append("WARNING: No NETMODE command — network mode not configured")

    # Check sync / halt
    if "sync" not in content.lower():
        issues.append("INFO: No 'sync' before exit — data may not be flushed")

    # If USB storage used, check USB_WAIT
    if "/usb/" in content and "USB_WAIT" not in content:
        issues.append("WARNING: Using /usb/ path but no USB_WAIT command — USB drive may not be ready")

    # Bash syntax
    bash_errors = check_bash_syntax(str(path))
    issues.extend(f"BASH SYNTAX: {e}" for e in bash_errors)

    return issues


# ── Payload Upload ────────────────────────────────────────────────────────────

def upload_payload(ssh: SSHClient) -> bool:
    heading("Step 9 — Payload Upload")

    switch = numbered_menu(
        "Which switch position should receive the payload?",
        ["Switch 1", "Switch 2", "Switch 3"]
    ) + 1

    remote_dir = f"/root/payloads/switch{switch}"

    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        payload_path = Path(preselected).expanduser()
    else:
        payload_path = Path(prompt("Path to payload file (payload, payload.sh, or payload.py)")).expanduser()
    if not payload_path.exists():
        err(f"Not found: {payload_path}")
        return False

    # Determine remote filename
    suffix = payload_path.suffix.lower()
    if suffix in (".sh", ""):
        remote_name = "payload"   # Mark II prefers no extension
    elif suffix == ".py":
        remote_name = "payload.py"
    elif suffix == ".php":
        remote_name = "payload.php"
    else:
        remote_name = "payload"

    # Validate
    heading("Step 10 — Payload Review")
    issues = validate_squirrel_payload(payload_path)
    if issues:
        warn(f"{len(issues)} issue(s):")
        for issue in issues:
            print(f"    {issue}")
        if not confirm("Continue?"):
            return False
    else:
        ok("Payload looks good.")

    # Check dependencies
    cmds = extract_required_commands(str(payload_path), SQUIRREL_BUILTINS)
    if cmds:
        availability = check_packages_openwrt(ssh, cmds)
        missing = [c for c, a in availability.items() if not a]
        if missing:
            warn(f"Missing commands: {', '.join(missing)}")
            for cmd in missing:
                if confirm(f"Install package for '{cmd}'?"):
                    install_openwrt_package(ssh, cmd)

    # Upload
    ssh.run(f"mkdir -p {remote_dir}")
    remote_path = f"{remote_dir}/{remote_name}"
    if not ssh.upload(str(payload_path), remote_path):
        err("Upload failed.")
        return False
    ssh.run(f"chmod +x {remote_path}")
    ok(f"Payload uploaded to switch{switch}.")

    # Upload companion files if payload is in a directory
    if payload_path.parent != payload_path:
        companion_dir = payload_path.parent
        companions = [f for f in companion_dir.iterdir()
                      if f.is_file() and f != payload_path]
        if companions:
            info(f"Found {len(companions)} companion file(s) in the same directory.")
            if confirm("Upload companion files too?"):
                try:
                    sftp = ssh._client.open_sftp()
                    for comp in companions:
                        sftp.put(str(comp), f"{remote_dir}/{comp.name}")
                        ok(f"  Uploaded: {comp.name}")
                    sftp.close()
                except Exception as e:
                    warn(f"Companion upload error: {e}")

    return True


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(ssh: SSHClient, ics_enabled: bool):
    heading("Step 11 — Cleanup")
    ssh.close()
    if ics_enabled:
        disable_ics()
    ok("Packet Squirrel is ready.")
    print("""
  Deployment:
    • Set switch to position 1, 2, or 3 to run your payload.
    • Insert the Squirrel INLINE between the target device and the network:
        [Target Device] → [Ethernet IN] → [Squirrel] → [Ethernet OUT] → [Router/LAN]
    • Or use as a covert implant: power via USB bank, connect inline.
    • Loot is saved to /root/loot/ (or /usb/loot/ if USB drive is attached).
    """)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking required apt packages (python3-paramiko, python3-requests)…")
        ensure_apt_packages(["python3-paramiko", "python3-requests"])

    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Step 1 — Connect the Packet Squirrel in Arming Mode")
    _CONNECT_INSTRUCTIONS = (
        "The Packet Squirrel uses ETHERNET only — no USB-to-host connection.\n\n"
        "Switch positions:\n"
        "  ■ Position 1-3 — Runs the payload in that switch slot\n"
        "  ■ Position 4   — ARMING MODE (required)  ←\n\n"
        "Setup:\n"
        "  1. Set the physical switch to position 4 (ARMING MODE).\n"
        "  2. Connect an Ethernet cable from this computer to the Squirrel's\n"
        "     ETHERNET IN port (left side, above the power connector).\n"
        "  3. Power the Squirrel via Micro-USB (Mark I) or USB-C (Mark II).\n"
        "  4. Wait ~30 seconds for the device to boot.\n"
        "     Your computer should receive a DHCP address in 172.16.32.0/24.\n\n"
        "Expected LED boot sequence:\n"
        "  ● Multi-colour flash  — Booting\n"
        "  ● Slow BLUE blink     — ARMING MODE ready ✓  ← wait for this\n\n"
        "NOTE: ETHERNET IN (left) = this computer.\n"
        "      ETHERNET OUT (right) = upstream router/network.\n"
        "      Swapping IN/OUT is the most common setup mistake."
    )
    detected = verify_device_connection(
        detect_squirrel, TOOL_NAME, _CONNECT_INSTRUCTIONS, max_retries=3
    )
    if not detected:
        err("Packet Squirrel not detected. Exiting.")
        sys.exit(1)

    # Step 4 — Interface
    heading("Step 4 — Interface Confirmation")
    configure_host_interface()

    # Step 7 — ICS
    ics_enabled = setup_internet_sharing()

    # Step 8 — SSH + firmware
    info(f"Connecting via SSH to {SQUIRREL_IP}…")
    ssh = wait_for_ssh(SQUIRREL_IP, SSH_USER, SSH_PASS, timeout=60)
    if not ssh:
        # --- Troubleshoot SSH failure ---
        warn("SSH failed with default credentials.")

        # Known-hosts conflict after firmware update
        from pathlib import Path
        kh_file = Path.home() / ".ssh" / "known_hosts"
        if kh_file.exists() and SQUIRREL_IP in kh_file.read_text(errors="replace"):
            warn(f"Stale known_hosts entry found for {SQUIRREL_IP}.")
            if confirm("Clear known_hosts entry and retry?", default=True):
                clear_ssh_known_hosts(SQUIRREL_IP)
                ssh = wait_for_ssh(SQUIRREL_IP, SSH_USER, SSH_PASS, timeout=30)

        if not ssh:
            custom_pass = prompt("Enter custom SSH password if changed (blank to abort)", "")
            if custom_pass:
                ssh = wait_for_ssh(SQUIRREL_IP, SSH_USER, custom_pass, timeout=30)

        if not ssh:
            err("SSH connection failed.")
            print(f"""
  Troubleshooting:
    • Verify IN port connects to this computer and IP is 172.16.32.10.
    • Default password: {SSH_PASS}
    • Check the switch is in position 4 (not 1-3 which run payloads).
    • If firmware is corrupt, use the USB flash drive method (see above).
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
