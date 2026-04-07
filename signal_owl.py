#!/usr/bin/env python3
"""
Signal Owl Tool Manager
Handles arming mode detection, WiFi SSH access, firmware updates, and payload
upload for the Signal Owl.

The Signal Owl is a passive WiFi monitoring / signal intelligence device.
It does NOT enumerate as a USB device to the host — it is accessed via its
own WiFi AP (SSID: Owl_xxxx) in arming mode. Runs OpenWRT.

Pre-installed tools: Aircrack-ng, Kismet, Nmap, MDK4, Python 3.

Usage:
    python3 signal_owl.py
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
    wait_for_ssh, SSHClient,
    ping, wait_for_ping,
    check_bash_syntax, extract_required_commands,
    check_packages_openwrt, install_openwrt_package,
    detection_loop,
    clear_ssh_known_hosts,
    get_selected_payload, verify_device_connection,
)


def check_firmware_version(ssh=None):
    heading("Firmware Version Check")
    info("Checking Signal Owl firmware version…")
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
        ok(f"Signal Owl firmware: {current}")
    else:
        info("Could not auto-detect Signal Owl firmware version.")

    info("")
    info("Signal Owl firmware updates require a Hak5 account:")
    info("  1. Download firmware from: https://downloads.hak5.org/owl")
    info("  2. Upload via SCP + sysupgrade, or use USB flash drive method")
    info("  3. Check Hak5 docs: https://docs.hak5.org/signal-owl/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME    = "Signal Owl"
DESCRIPTION  = "Passive WiFi monitoring & signal intelligence device (OpenWRT)"

OWL_IP       = "172.16.56.1"
OWL_SSID_PREFIX = "Owl_"
SSH_USER     = "root"
SSH_PASS     = "hak5owl"

FIRMWARE_URL = "https://downloads.hak5.org/owl"

# Commands provided by Signal Owl payload runtime
OWL_BUILTINS = {
    "LED", "C2CONNECT", "C2DISCONNECT", "C2EXFIL",
    "WIFI_CONNECT", "WIFI_DISCONNECT",
}

LED_STATES = {
    "SETUP", "ATTACK", "CLEANUP", "FINISH", "FAIL",
    "STAGE1", "STAGE2", "STAGE3", "STAGE4", "STAGE5",
    "SPECIAL1", "SPECIAL2", "SPECIAL3", "SPECIAL4", "SPECIAL5",
    "SOLID", "SLOW", "FAST", "VERYFAST",
    "SINGLE", "DOUBLE", "TRIPLE", "QUAD", "QUIN",
    "ISINGLE", "IDOUBLE", "ITRIPLE", "IQUAD", "IQUIN",
}

MODE_INSTRUCTIONS = """
Signal Owl not detected.

The Signal Owl does NOT appear as a USB device to the host computer.
It is accessed via its own WiFi access point in Arming Mode.

  To enter Arming Mode:
    Firmware 1.0.1 and later (recommended):
      1. Power on by plugging the USB-A end into any USB power source (or host USB).
      2. Wait ~1 minute for the device to fully boot into Attack Mode.
         LED: slow single blink (attack mode running).
      3. Press the recessed arming button on the bottom of the device
         (use a paperclip). LED changes to double-blink red = Arming Mode.

    Firmware 1.0.0 only:
      1. Power on — LED blinks RAPIDLY for ~3 seconds.
      2. Press the arming button DURING this rapid blink window (3 sec max).

    *** WARNING: Do NOT press the button during very early boot (before LED
    patterns stabilize) — this risks bricking the device. ***

  In Arming Mode:
    - LED: double-blink red
    - WiFi AP: Owl_XXXX (open, no password)
    - Connect your computer to this WiFi network.
    - SSH available at: 172.16.56.1

  To detect: connect to the Owl_XXXX WiFi network and ping 172.16.56.1.
"""

RESET_INSTRUCTIONS = """
Signal Owl Firmware Recovery (no traditional button-reset):

  There is no button-hold factory reset for the Signal Owl.
  Recovery is done via USB flash drive firmware reflash:

  1. Download latest firmware from: https://downloads.hak5.org/owl
  2. Verify SHA-256 checksum.
  3. Format a USB flash drive as FAT32 or EXT4.
  4. Copy the upgrade-x.x.x.bin file to the ROOT of the drive (do NOT rename it).
  5. Power OFF the Signal Owl completely.
  6. Insert the USB flash drive into the Signal Owl's USB pass-through port.
  7. Power ON the Signal Owl.
  8. The device detects the upgrade file and reflashes automatically (5-10 min).
  9. When complete, the device reboots with a clean configuration.
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_owl() -> bool:
    """Detect Signal Owl by pinging its management IP (must be on Owl WiFi)."""
    return ping(OWL_IP, timeout=2)


def check_owl_wifi_connected() -> bool:
    """Check if we are currently connected to an Owl_xxxx WiFi network."""
    os_name = get_os()
    if os_name == "macos":
        out = run_output("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null")
        ssid_m = re.search(r"SSID:\s+(\S+)", out)
        if ssid_m and ssid_m.group(1).startswith(OWL_SSID_PREFIX):
            return True
        # Also try networksetup
        out2 = run_output("networksetup -getairportnetwork en0 2>/dev/null || networksetup -getairportnetwork en1 2>/dev/null")
        if OWL_SSID_PREFIX in out2:
            return True
    elif os_name == "linux":
        out = run_output("iwgetid -r 2>/dev/null || nmcli -t -f active,ssid dev wifi 2>/dev/null | grep '^yes:'")
        if OWL_SSID_PREFIX in out:
            return True
    return False


def connect_to_owl_wifi() -> bool:
    """Instruct user to connect to Owl_xxxx WiFi, or try automatically."""
    os_name = get_os()
    print(f"""
  The Signal Owl broadcasts an open WiFi AP when in Arming Mode.
  SSID: Owl_xxxx  (xxxx = last 2 octets of the device's MAC address)
  No password required.

  Connect your computer to this WiFi network, then return here.
    """)

    if os_name == "macos":
        # Scan for Owl_xxxx on multiple interfaces
        airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        for wifi_iface in ["en0", "en1", "en2"]:
            out = run_output(f"{airport} -s 2>/dev/null | grep -i Owl_")
            if not out:
                # Try networksetup scan
                out = run_output(f"networksetup -listpreferredwirelessnetworks {wifi_iface} 2>/dev/null | grep -i Owl_")
            if out:
                ssid_m = re.search(r"(Owl_\w+)", out)
                if ssid_m:
                    ssid = ssid_m.group(1)
                    info(f"Found Signal Owl AP: {ssid} (on {wifi_iface})")
                    if confirm(f"Auto-connect to {ssid}?"):
                        r = run(f"networksetup -setairportnetwork {wifi_iface} '{ssid}' 2>/dev/null")
                        if r.returncode == 0:
                            time.sleep(5)
                            if check_owl_wifi_connected():
                                return True
                            warn("Auto-connect may not have worked; verify WiFi manually.")
                    break

    elif os_name == "linux":
        out = run_output("nmcli dev wifi list 2>/dev/null | grep -i Owl_")
        if out:
            ssid_m = re.search(r"(Owl_\w+)", out)
            if ssid_m:
                ssid = ssid_m.group(1)
                info(f"Found Signal Owl AP: {ssid}")
                if confirm(f"Connect to {ssid} via nmcli?"):
                    r = run(f"nmcli dev wifi connect '{ssid}' 2>&1")
                    if r.returncode == 0:
                        time.sleep(5)
                        return check_owl_wifi_connected()
                    warn(f"nmcli connect failed: {(r.stdout + r.stderr).strip()[:200]}")

    pause("Connect to the Owl_XXXX WiFi network, then press ENTER…")
    return True


# ── Internet Sharing ──────────────────────────────────────────────────────────

def setup_internet_sharing(ssh: SSHClient) -> bool:
    heading("Step 7 — Internet Sharing Setup")

    print("""
  To update firmware, the Signal Owl needs internet access.
  Options:
    A) Configure the Owl to connect to your router's WiFi (as a client)
       via /etc/config/wireless on the device.
    B) Use IP masquerading on the host to route traffic from the Owl through
       the host's internet connection.

  Note: The Signal Owl only has WiFi — no Ethernet WAN port.
    """)

    method = numbered_menu("Internet method:", [
        "Configure Owl WiFi client mode (connect to router)",
        "Host NAT via iptables (Linux) / pfctl (macOS)",
        "Skip — device already has internet",
    ])

    if method == 0:
        ssid = prompt("WiFi SSID for the Owl to connect to")
        password = prompt("WiFi Password")
        if not ssid:
            warn("No SSID entered.")
            return False

        info("Configuring Owl to connect to WiFi…")
        # Write wireless client config
        wifi_config = f"""
config wifi-iface 'sta0'
    option device 'radio0'
    option mode 'sta'
    option ssid '{ssid}'
    option encryption 'psk2'
    option key '{password}'
    option disabled '0'
"""
        # Apply via uci
        rc, out, _ = ssh.run(f"uci set wireless.sta0.ssid='{ssid}' 2>/dev/null; "
                             f"uci set wireless.sta0.key='{password}' 2>/dev/null; "
                             f"uci commit wireless; wifi reload 2>&1")
        if rc != 0:
            # Try direct config file approach
            ssh.run(f"echo '{ssid}' > /tmp/owl_ssid")
            ssh.run(f"echo '{password}' > /tmp/owl_pass")
            warn("Direct UCI approach uncertain; check /etc/config/wireless manually.")

        time.sleep(5)
        rc2, out2, _ = ssh.run("ping -c1 8.8.8.8 2>&1")
        if rc2 == 0:
            ok("Owl has internet access.")
            return True
        warn("Internet not confirmed. May need manual wireless config.")
        return False

    elif method == 1:
        os_name = get_os()
        if os_name == "linux":
            from common import get_internet_interface, enable_ics_linux
            internet_if = get_internet_interface()
            owl_if = run_output("ip route get 172.16.56.1 2>/dev/null | grep -oP 'dev \\K\\S+'")
            if not owl_if:
                owl_if = prompt("Enter the interface connected to the Owl WiFi", "wlan0")
            if internet_if:
                enable_ics_linux(internet_if, owl_if)
                return True
        elif os_name == "macos":
            from common import enable_ics_macos
            return enable_ics_macos("Airport")
        return False

    else:
        rc, out, _ = ssh.run("ping -c1 8.8.8.8 2>&1")
        if rc == 0:
            ok("Owl has internet.")
        else:
            warn("Owl cannot reach internet — firmware download will fail.")
        return False


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

    update_method = numbered_menu("Update method:", [
        "SCP + sysupgrade (SSH — recommended)",
        "USB flash drive (physical access required)",
        "Skip",
    ])

    if update_method == 0:
        print(f"\n  Download from: {FIRMWARE_URL}")
        fw_path = prompt("Path to firmware .bin file")
        if not fw_path:
            return True
        fw_path = Path(fw_path).expanduser()
        if not fw_path.exists():
            err(f"Not found: {fw_path}")
            return False

        remote_path = f"/tmp/{fw_path.name}"
        info("Uploading firmware via SFTP…")
        if not ssh.upload(str(fw_path), remote_path):
            err("Upload failed.")
            return False
        ok(f"Uploaded to {remote_path}")

        info("Running sysupgrade -v -n -F (device will reboot — WiFi AP will drop)…")
        ssh.run(f"sysupgrade -v -n -F {remote_path} &", timeout=5)

        info("WiFi connection will drop during reboot. Reconnect to Owl_xxxx after ~2 min.")
        pause("After reconnecting to Owl WiFi, press ENTER…")

        if wait_for_ping(OWL_IP, timeout=180):
            ok("Signal Owl is back online.")
        else:
            warn("No response. Try reconnecting to the Owl WiFi AP.")
        return True

    elif update_method == 1:
        print(f"""
  USB Flash Drive Update:
    1. Download upgrade-x.x.x.bin from {FIRMWARE_URL}
    2. Format a USB flash drive as FAT32 or EXT4.
    3. Copy upgrade-x.x.x.bin to the ROOT of the drive (do NOT rename).
    4. Power OFF the Signal Owl.
    5. Insert the USB drive into the Owl's USB pass-through port.
    6. Power ON. The Owl detects upgrade.bin and reflashes (5-10 min).
    7. When complete, Owl reboots with clean config.
    8. Reconnect to the Owl_xxxx WiFi AP.
        """)
        pause("Press ENTER after the update is complete and Owl has rebooted…")
        return True

    else:
        info("Skipping firmware update.")
        return True


# ── Payload Validation ────────────────────────────────────────────────────────

def validate_owl_payload(path: Path) -> list[str]:
    issues = []
    try:
        content = path.read_text()
    except Exception as e:
        return [f"Cannot read: {e}"]

    lines = content.splitlines()

    if not lines or not lines[0].startswith("#!/"):
        issues.append("WARNING: No shebang line (#!/bin/bash recommended)")

    # Check LED usage
    led_found = any(re.match(r"^\s*LED\s+", ln) for ln in lines)
    if not led_found:
        issues.append("INFO: No LED commands found (recommended for status indication)")
    else:
        for i, ln in enumerate(lines, 1):
            m = re.match(r"^\s*LED\s+(\S+)", ln)
            if m:
                state = m.group(1).upper()
                if state not in LED_STATES and not re.match(r"^\d+$", state):
                    issues.append(f"INFO: Line {i}: Unrecognised LED state: {state}")

    # Check for WIFI_CONNECT if network access used
    net_cmds = ["curl", "wget", "nmap", "aircrack", "kismet", "mdkk4"]
    content_lower = content.lower()
    uses_network = any(cmd in content_lower for cmd in net_cmds)
    if uses_network and "WIFI_CONNECT" not in content:
        issues.append("WARNING: Network commands used but no WIFI_CONNECT — device may not have internet")

    # Check C2EXFIL syntax
    for i, ln in enumerate(lines, 1):
        m = re.match(r"^\s*C2EXFIL\s+(.*)", ln)
        if m:
            args = m.group(1).strip()
            if not args:
                issues.append(f"WARNING: Line {i}: C2EXFIL with no arguments")

    # Bash syntax
    bash_errors = check_bash_syntax(str(path))
    issues.extend(f"BASH SYNTAX: {e}" for e in bash_errors)

    return issues


# ── Payload Upload ────────────────────────────────────────────────────────────

def upload_payload(ssh: SSHClient) -> bool:
    heading("Step 9 — Payload Upload")

    print("""
  Payload deployment options:
    A) Internal storage: /root/payload/payload.sh
    B) USB flash drive: plug a drive into the Owl; USB takes priority over internal.
    """)

    storage = numbered_menu("Where to deploy the payload?", [
        "Internal storage (/root/payload/)",
        "USB flash drive (physical)",
    ])

    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        payload_path = Path(preselected).expanduser()
    else:
        payload_path = Path(prompt("Path to payload.sh (or payload directory)")).expanduser()
    if not payload_path.exists():
        err(f"Not found: {payload_path}")
        return False

    if payload_path.is_dir():
        payload_file = payload_path / "payload.sh"
        if not payload_file.exists():
            payload_file = payload_path / "payload.txt"
        if not payload_file.exists():
            err("No payload.sh or payload.txt found in directory.")
            return False
        payload_dir = payload_path
    else:
        payload_file = payload_path
        payload_dir = None

    # Validate
    heading("Step 10 — Payload Review")
    issues = validate_owl_payload(payload_file)
    if issues:
        warn(f"{len(issues)} issue(s):")
        for issue in issues:
            print(f"    {issue}")
        if not confirm("Continue?"):
            return False
    else:
        ok("Payload looks good.")

    # Check dependencies
    cmds = extract_required_commands(str(payload_file), OWL_BUILTINS)
    if cmds:
        info(f"Commands referenced: {', '.join(cmds)}")
        # Pre-installed: aircrack-ng, kismet, nmap, mdk4, python3
        preinstalled = {"aircrack-ng", "airmon-ng", "airodump-ng", "kismet", "nmap", "mdk4", "python3", "python"}
        truly_missing_check = [c for c in cmds if c.lower() not in preinstalled]
        if truly_missing_check:
            availability = check_packages_openwrt(ssh, truly_missing_check)
            missing = [c for c, a in availability.items() if not a]
            if missing:
                warn(f"Possibly missing: {', '.join(missing)}")
                for cmd in missing:
                    if confirm(f"Install package for '{cmd}' via opkg?"):
                        install_openwrt_package(ssh, cmd)
        else:
            ok("All referenced commands are pre-installed on Signal Owl.")

    # Upload
    if storage == 0:
        # Internal storage
        remote_dir = "/root/payload"
        ssh.run(f"mkdir -p {remote_dir}/extensions")

        if payload_dir:
            try:
                sftp = ssh._client.open_sftp()
                for item in payload_dir.rglob("*"):
                    if item.is_file():
                        rel = item.relative_to(payload_dir)
                        remote_file = f"{remote_dir}/{rel}"
                        ssh.run(f"mkdir -p {str(Path(remote_file).parent)}")
                        sftp.put(str(item), remote_file)
                        ok(f"  Uploaded: {rel}")
                sftp.close()
            except Exception as e:
                err(f"Upload error: {e}")
                return False
        else:
            remote_name = "payload.sh" if payload_file.suffix == ".sh" else "payload.txt"
            if not ssh.upload(str(payload_file), f"{remote_dir}/{remote_name}"):
                err("Upload failed.")
                return False
            ssh.run(f"chmod +x {remote_dir}/{remote_name}")
        ok(f"Payload uploaded to {remote_dir}")

    else:
        print("""
  USB Flash Drive payload deployment:
    1. Format a USB flash drive and copy payload.sh to the root.
    2. Optionally create an extensions/ folder with extension scripts.
    3. Plug the drive into the Signal Owl BEFORE powering on.
    4. The USB payload takes priority over internal storage automatically.
        """)
        # Offer to copy to a mounted USB drive
        usb_path = prompt("Path to mounted USB drive (leave blank to skip)", "")
        if usb_path:
            usb_drive = Path(usb_path)
            import shutil
            dest = usb_drive / payload_file.name
            shutil.copy2(payload_file, dest)
            ok(f"Payload copied to {dest}")

    return True


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(ssh: SSHClient):
    heading("Step 11 — Cleanup")
    ssh.close()
    ok("Signal Owl is ready.")
    print("""
  Deployment:
    • To run the payload: press the arming button ONCE to exit arming mode.
    • Or unplug and replug without pressing the button (starts in Attack Mode).
    • LED: SLOW single blink = Attack Mode running.
    • LED: DOUBLE blink red = Arming Mode.

  Included tools: Aircrack-ng, Kismet, Nmap, MDK4, Python 3.
  Pre-installed for passive WiFi monitoring and signal intelligence ops.

  Note: The Signal Owl plugs into any USB-A port for power.
  It is covert — does not enumerate as a USB device to the host.
    """)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking required apt packages (python3-paramiko, python3-requests)…")
        ensure_apt_packages(["python3-paramiko", "python3-requests"])

    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Step 1 — Connect and Enter Arming Mode")
    _CONNECT_INSTRUCTIONS = (
        "The Signal Owl does NOT appear as a USB device — access it via its WiFi AP.\n\n"
        "Steps:\n"
        "  1. Plug the Signal Owl's USB-A end into any USB power source (or this computer).\n"
        "  2. Wait ~1 minute for full boot.\n"
        "     *** Do NOT press the button during early boot (before LED stabilizes). ***\n"
        "  3. Press the recessed arming button on the bottom (use a paperclip).\n"
        "  4. Connect YOUR COMPUTER to the open WiFi network: Owl_XXXX (no password).\n\n"
        "Expected LED sequence (~60 s):\n"
        "  ● Rapid blink        — Kernel loading / filesystem initializing\n"
        "  ● Slow single blink  — Attack Mode ready\n"
        "  ● Double-blink RED   — Arming Mode active — WiFi AP 'Owl_XXXX' visible ✓  ← wait for this\n\n"
        "Once connected to the Owl_XXXX WiFi, click Continue."
    )
    detected = verify_device_connection(
        detect_owl, TOOL_NAME, _CONNECT_INSTRUCTIONS, max_retries=3
    )
    if not detected:
        # Fall back: try to connect to Owl WiFi automatically
        if not check_owl_wifi_connected():
            warn("Not connected to Owl WiFi AP.")
            connect_to_owl_wifi()
            if not ping(OWL_IP):
                err("Cannot reach Signal Owl. Exiting.")
                sys.exit(1)
        else:
            err("Signal Owl not responding. Exiting.")
            sys.exit(1)

    # Step 4 — Interface confirmation
    heading("Step 4 — Interface Confirmation")
    ok(f"Connected to Signal Owl at {OWL_IP} via WiFi")
    # Show WiFi interface info on the Owl
    info("WiFi connection method: 802.11b/g/n, 2.4GHz, open AP")

    # Step 8 — SSH connect
    info(f"Connecting via SSH to {OWL_IP}…")
    ssh = wait_for_ssh(OWL_IP, SSH_USER, SSH_PASS, timeout=30)
    if not ssh:
        # --- Troubleshoot SSH failure ---
        warn("SSH failed with default credentials.")

        # Known-hosts conflict — host key changes after firmware update
        from pathlib import Path as _Path
        kh_file = _Path.home() / ".ssh" / "known_hosts"
        if kh_file.exists() and OWL_IP in kh_file.read_text(errors="replace"):
            warn(f"Stale known_hosts entry for {OWL_IP} — firmware update changes SSH host key.")
            if confirm("Clear known_hosts entry and retry?", default=True):
                clear_ssh_known_hosts(OWL_IP)
                ssh = wait_for_ssh(OWL_IP, SSH_USER, SSH_PASS, timeout=30)

        if not ssh:
            err("SSH failed. Check WiFi connection and password.")
            print(f"""
  Troubleshooting:
    • Verify you are connected to the Owl_XXXX WiFi (open, no password).
    • Default SSH password: {SSH_PASS}
    • Confirm arming mode: LED should DOUBLE-BLINK RED.
    • Run: ssh-keygen -R {OWL_IP}  then retry.
    • If arming mode was entered during early boot, power cycle and try again.
            """)
            sys.exit(1)
    ok("SSH connected.")

    check_firmware_version(ssh)

    # Step 7 — Internet sharing
    setup_internet_sharing(ssh)

    # Step 8 — Firmware
    firmware_update(ssh)

    # Steps 9-10
    if get_selected_payload() or confirm("\nUpload a payload?"):
        upload_payload(ssh)

    cleanup(ssh)


if __name__ == "__main__":
    main()
