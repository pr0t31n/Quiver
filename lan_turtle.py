#!/usr/bin/env python3
"""
LAN Turtle Tool Manager
Handles detection, internet sharing, firmware updates, and module management
for the LAN Turtle (original) and LAN Turtle 3G.

The LAN Turtle presents as a USB Ethernet adapter (RTL8152 chipset). It
provides an RJ45 port for LAN connection and a USB-A plug for host connection.
Managed via SSH through the Turtle Shell text menu. Runs OpenWRT.

Usage:
    python3 lan_turtle.py
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
    detect_usb_device,
    enable_ics, disable_ics,
    ensure_apt_packages, ensure_brew_packages,
    wait_for_ssh, SSHClient,
    get_interface_for_ip, ping, wait_for_ping,
    check_bash_syntax, extract_required_commands,
    check_packages_openwrt, install_openwrt_package,
    detection_loop,
    clear_ssh_known_hosts, check_kernel_module, load_kernel_module,
    require_sudo,
)


def check_firmware_version(ssh=None):
    heading("Firmware Version Check")
    info("Checking LAN Turtle firmware version…")
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
        ok(f"LAN Turtle firmware: {current}")
    else:
        info("Could not auto-detect LAN Turtle firmware version.")

    info("")
    info("LAN Turtle firmware updates require a Hak5 account:")
    info("  1. Download firmware from: https://downloads.hak5.org/turtle")
    info("  2. Use the Turtle Shell menu: Config → Check for Updates")
    info("  3. Or upload via SCP + sysupgrade")
    info("  4. Check Hak5 docs: https://docs.hak5.org/lan-turtle/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "LAN Turtle (Original & 3G)"
DESCRIPTION = "Covert USB Ethernet implant — network pivot & remote access (OpenWRT)"
VID_RTL     = "0BDA"   # Realtek
PID_8152    = "8152"   # RTL8152
PID_8153    = "8153"   # RTL8153

TURTLE_IP   = "172.16.84.1"
SSH_USER    = "root"
SSH_PASS    = "sh3llz"   # Default; user is forced to change on first login

FIRMWARE_URL = "https://downloads.hak5.org/turtle"

MODE_INSTRUCTIONS = """
LAN Turtle not detected.

  1. Plug the LAN Turtle (USB-A end) into a USB port on this computer.
  2. Wait ~30 seconds for the RTL8152 driver to load and the device to boot.
  3. The host will receive a DHCP address in the 172.16.84.0/24 range.
  4. If DHCP doesn't work, manually assign: 172.16.84.10 / 255.255.255.0

  Platform notes:
    macOS: Shows as "USB 10/100 LAN" in System Settings → Network.
    Linux: Appears as usb0 or eth1 (run: ip link show)
    Windows: Appears as "Realtek USB Ethernet" in Device Manager.

  If no interface appears at all:
    • Try a different USB port (USB 2.0 preferred; some USB 3.0 ports are picky)
    • Check USB current — use a powered hub if on a weak USB port
"""

RESET_INSTRUCTIONS = """
LAN Turtle Factory Recovery:

  WARNING: The reset button is INSIDE the LAN Turtle case.

  1. Download the RECOVERY IMAGE (different from regular firmware!) from:
     https://downloads.hak5.org/turtle
  2. Hold the reset button (inside case — requires opening) while plugging
     the Turtle into USB.
  3. Hold for the first 5 seconds of boot, then release.
  4. Wait 30-180 seconds for the Turtle to broadcast an IP.
  5. If no IP after 1 minute, statically assign host: 192.168.1.2 / 255.255.255.0
  6. Browse to: http://192.168.1.1 → upload the RECOVERY .bin (not regular firmware)
  7. Wait 5-10 minutes → device reboots.
  8. After recovery: accessible at 172.16.84.1, password: sh3llz
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_turtle() -> bool:
    """Detect LAN Turtle via RTL8152 USB VID:PID or IP ping."""
    if detect_usb_device(VID_RTL, PID_8152):
        return True
    if detect_usb_device(VID_RTL, PID_8153):
        return True
    if ping(TURTLE_IP):
        return True
    return False


# ── Interface Setup ───────────────────────────────────────────────────────────

def configure_host_interface() -> bool:
    """Ensure host can reach the LAN Turtle (DHCP or static)."""
    if ping(TURTLE_IP):
        ok(f"LAN Turtle reachable at {TURTLE_IP}")
        return True

    os_name = get_os()

    # Check/load RTL8152 driver on Linux
    if os_name == "linux":
        for mod in ("r8152", "cdc_ether"):
            if check_kernel_module(mod):
                info(f"USB Ethernet module '{mod}' is loaded.")
                break
        else:
            warn("RTL8152/CDC Ethernet module not detected. Attempting to load r8152…")
            if not load_kernel_module("r8152"):
                load_kernel_module("cdc_ether")
            time.sleep(2)

    device_if = get_interface_for_ip(TURTLE_IP)

    if not device_if:
        if os_name == "macos":
            out = run_output("networksetup -listallhardwareports")
            for line in out.splitlines():
                if "USB" in line.upper() or "REALTEK" in line.upper() or "10/100" in line.upper():
                    m = re.search(r"Device:\s+(\w+)", out[out.find(line):out.find(line)+200])
                    if m:
                        device_if = m.group(1)
                        break
        if not device_if:
            device_if = prompt("Enter the LAN Turtle interface name (e.g. usb0, eth1, en3)", "usb0")

    info(f"Interface detected: {device_if}. Attempting DHCP…")

    if os_name == "linux":
        info(f"Running dhclient on {device_if} to request DHCP from the LAN Turtle…")
        info("  Why: The LAN Turtle runs a DHCP server in the 172.16.84.0/24 range.")
        info("  Expected: DHCP lease obtained within a few seconds.")
        info("  If dhclient hangs: the interface may not be up — check 'ip link show'.")
        sudo_run(f"dhclient {device_if} 2>/dev/null")
        time.sleep(5)
    # macOS/Windows usually auto-DHCP, just wait
    time.sleep(5)

    if ping(TURTLE_IP):
        ok(f"Got DHCP address, LAN Turtle reachable at {TURTLE_IP}")
        return True

    # Fall back to static assignment
    warn("DHCP failed; assigning static IP 172.16.84.10…")
    info("  Why: Static fallback so SSH can reach the Turtle at 172.16.84.1.")
    info("  Expected: 'ip addr add' returns silently on success.")
    info("  If 'File exists': address already set — safe to ignore.")
    if os_name == "linux":
        sudo_run(f"ip addr flush dev {device_if} 2>/dev/null")
        sudo_run(f"ip addr add 172.16.84.10/24 dev {device_if}")
        sudo_run(f"ip link set {device_if} up")
    elif os_name == "macos":
        from common import assign_static_ip_macos, get_macos_service_for_iface
        service = get_macos_service_for_iface(device_if)
        if service:
            assign_static_ip_macos(service, "172.16.84.10", "255.255.255.0")
        else:
            warn("Could not find service name. Set manually in System Settings → Network.")
            pause("Press ENTER after setting IP…")

    time.sleep(2)
    if ping(TURTLE_IP):
        ok(f"LAN Turtle reachable at {TURTLE_IP}")
        return True

    # --- Troubleshoot unreachable Turtle ---
    warn("LAN Turtle still unreachable.")
    print(f"""
  Troubleshooting:
    • Try a different USB port — USB 3.0 (blue) ports can cause RTL8152 issues on some hosts.
      Prefer USB 2.0 (black) ports for the LAN Turtle.
    • On Linux: check 'ip link show' for a new interface after plugging in.
      If missing, run: sudo modprobe r8152 && sudo modprobe cdc_ether
    • Ensure the RJ45 port (if used) is not connected to a network with DHCP
      that conflicts with the 172.16.84.0/24 range.
    • USB current: if on a low-power port (laptop bus-powered), try a powered hub.
    • If no interface appears at all: the RTL8152 driver may need reinstalling.
      macOS: check System Settings → General → Login Items & Extensions.
    """)
    return False


# ── Internet Sharing ──────────────────────────────────────────────────────────

def setup_internet_sharing() -> bool:
    heading("Step 7 — Internet Sharing Setup")

    print("""
  To update firmware OTA, the LAN Turtle needs internet access.
  Connect the Turtle's RJ45 port to an internet-connected network (router/switch),
  OR share internet from this computer via NAT.

  The Turtle checks for updates via Config → Check for Updates in Turtle Shell.
    """)

    method = numbered_menu("Internet method:", [
        "Connect RJ45 to internet network",
        "Share from this computer via NAT/ICS",
        "Skip — use manual firmware upload",
    ])

    if method == 0:
        pause("Connect the RJ45 to your router/switch, then press ENTER…")
        ssh_test = wait_for_ssh(TURTLE_IP, SSH_USER, SSH_PASS, timeout=15)
        if ssh_test:
            rc, out, _ = ssh_test.run("ping -c1 8.8.8.8 2>&1")
            ssh_test.close()
            if rc == 0:
                ok("Turtle has internet via RJ45.")
                return True
            warn("Cannot reach internet via RJ45 — check the upstream network.")
        return True
    elif method == 1:
        return enable_ics(TURTLE_IP)
    else:
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
        "OTA via Turtle Shell (Config → Check for Updates)",
        "Manual upload via SCP + sysupgrade",
        "Skip",
    ])

    if update_method == 0:
        print("""
  OTA Update via Turtle Shell:
    1. In the SSH session, you'll be dropped into a bash prompt.
    2. Type: turtle
       (to enter the Turtle Shell text menu)
    3. Navigate: Config → Check for Updates
    4. Wait ~10 min. SSH session will close during flash.
    5. SSH key resets to default (sh3llz) after update.
    6. Update known_hosts: ssh-keygen -R 172.16.84.1
        """)
        info("Exiting Turtle Shell if active, then checking updates…")
        # Exit turtle shell if running, then run turtle update check
        ssh.run("exit 2>/dev/null; true")
        rc2, out2, _ = ssh.run("turtle update 2>&1 || echo 'MANUAL'", timeout=30)
        if "MANUAL" in out2:
            warn("Automated OTA update not available via command line on this firmware.")
            warn("Use the Turtle Shell menu: Config → Check for Updates")
            pause("Run the update manually in the SSH terminal, then press ENTER…")
        else:
            info("Update command sent. Waiting for device to finish updating…")
            time.sleep(15)
            if wait_for_ping(TURTLE_IP, timeout=300):
                ok("LAN Turtle is back online.")
            else:
                warn("Turtle did not respond within 5 minutes.")
        return True

    elif update_method == 1:
        print(f"\n  Download firmware from: {FIRMWARE_URL}")
        fw_path = prompt("Path to firmware .bin file")
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
        warn("Note: After sysupgrade, SSH key resets. Remove old key:")
        warn(f"  ssh-keygen -R {TURTLE_IP}")
        info("Running sysupgrade -n (device will reboot)…")
        ssh.run(f"sysupgrade -n {remote_path} &", timeout=5)
        time.sleep(20)
        if wait_for_ping(TURTLE_IP, timeout=300):
            ok("LAN Turtle is back online.")
        else:
            warn("Turtle did not respond within 5 minutes.")
        return True

    else:
        info("Skipping firmware update.")
        return True


# ── Module Management ─────────────────────────────────────────────────────────

def manage_modules(ssh: SSHClient) -> bool:
    heading("Steps 9-10 — Module Management")

    print("""
  The LAN Turtle uses a module system for functionality:
    - autossh        — reverse SSH tunnel
    - nmap           — network scanner
    - openvpn        — VPN client
    - URLSnarf       — passive URL capture
    - DNSSpoof       — DNS spoofing
    - netcat-revshell — reverse shell

  Modules are stored in /etc/turtle/modules/
    """)

    action = numbered_menu("What would you like to do?", [
        "Install a module via opkg",
        "List installed modules",
        "Upload a custom module",
        "Configure a module (via Turtle Shell)",
        "Skip — manage via Turtle Shell interactively",
    ])

    if action == 0:
        pkg = prompt("Package/module name to install (e.g. nmap, autossh)")
        if pkg:
            info("Running opkg update…")
            ssh.run("opkg update 2>&1", timeout=60)
            rc, out, _ = ssh.run(f"opkg install {pkg} 2>&1", timeout=120)
            if rc == 0:
                ok(f"Installed: {pkg}")
            else:
                err(f"Installation failed. Try: opkg search {pkg}")
        return True

    elif action == 1:
        rc, out, _ = ssh.run("ls /etc/turtle/modules/ 2>/dev/null")
        if out.strip():
            print("\n  Installed modules:")
            for mod in out.strip().splitlines():
                print(f"    • {mod}")
        else:
            info("No modules in /etc/turtle/modules/")
        return True

    elif action == 2:
        mod_path = prompt("Path to module directory on this computer")
        mod_path = Path(mod_path).expanduser()
        if not mod_path.is_dir():
            err("Not a directory.")
            return False
        remote_dir = f"/etc/turtle/modules/{mod_path.name}"
        ssh.run(f"mkdir -p {remote_dir}")
        try:
            sftp = ssh._client.open_sftp()
            for item in mod_path.rglob("*"):
                if item.is_file():
                    rel = item.relative_to(mod_path)
                    remote_file = f"{remote_dir}/{rel}"
                    ssh.run(f"mkdir -p {str(Path(remote_file).parent)}")
                    sftp.put(str(item), remote_file)
            sftp.close()
            ok(f"Module uploaded to {remote_dir}")
        except Exception as e:
            err(f"Upload error: {e}")
        return True

    elif action == 3:
        mod_name = prompt("Module name to configure")
        if mod_name:
            info(f"Running module configure: /etc/turtle/modules {mod_name} configure")
            ssh.run(f"/etc/turtle/modules {mod_name} configure 2>&1", timeout=30)
        return True

    else:
        info("Use the Turtle Shell (type 'turtle' in SSH) to manage modules interactively.")
        return True


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(ssh: SSHClient, ics_enabled: bool):
    heading("Step 11 — Cleanup")
    ssh.close()
    if ics_enabled:
        disable_ics()
    ok("LAN Turtle is ready.")
    print(f"""
  Deployment:
    • Unplug from this computer.
    • Plug the USB-A end into the target computer's USB port.
    • Connect the RJ45 to the target's network.
    • The Turtle presents as a USB Ethernet adapter to the target host.
    • SSH back in when needed: ssh {SSH_USER}@{TURTLE_IP}
      (requires your computer to be on the 172.16.84.0/24 network or connected
       via the Turtle's USB)

  LAN Turtle 3G: additional 3G modem provides out-of-band access.
    """)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    # Ensure apt packages are installed on Kali/Debian before anything else.
    # paramiko → SSH to the Turtle; requests → optional API calls.
    info("Checking required system packages (Kali/Debian)…")
    info("  Why: python3-paramiko (SSH) must be installed before any SSH connection attempt.")
    info("  If apt-get fails: run manually: sudo apt-get install -y python3-paramiko python3-requests")
    ensure_apt_packages(["python3-paramiko", "python3-requests"])

    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Step 1 — Connect the Device")
    print("""
  The LAN Turtle plugs directly into a USB-A port on this computer.
  It presents as a USB Ethernet adapter (Realtek RTL8152).

    1. Plug the LAN Turtle (USB-A end) into a USB port on this computer.
    2. Wait ~30 seconds for the RTL8152 driver to load and device to boot.
    3. The Turtle will serve DHCP in the 172.16.84.0/24 range.
    4. On first connection, you'll be prompted to change the default password.
       Default password: sh3llz

  Expected LED boot sequence (~30 s):
    ● Rapid GREEN blink    — Booting / kernel loading
    ● Solid GREEN          — Ready — SSH accessible at 172.16.84.1 ✓

  Other LED states to know:
    ● Rapid blink → solid  — Normal boot (allow 30 s before declaring a failure)
    ● No LED at all        — USB port may not be supplying power; try a different port
    ● Continuous rapid blinking (>60 s) — Possible kernel panic; unplug and retry
    ● LED off after solid  — Module exited or device went idle (normal after payload)
    """)
    pause("Press ENTER once plugged in…")

    # Steps 2-6
    detected = detection_loop(
        detect_fn=detect_turtle,
        mode_instructions=MODE_INSTRUCTIONS,
        reset_instructions=RESET_INSTRUCTIONS,
    )
    if not detected:
        sys.exit(1)

    # Step 4 — Interface
    heading("Step 4 — Interface Confirmation")
    configure_host_interface()

    # Step 7 — ICS
    ics_enabled = setup_internet_sharing()

    # Step 8 — SSH + firmware
    info(f"Connecting via SSH to {TURTLE_IP}…")
    info("  Why: SSH is used to manage firmware, modules and configuration.")
    info(f"  Expected: connection within 60 s. Default credentials: {SSH_USER} / {SSH_PASS}")
    info("  If SSH fails: the Turtle forces a password change on first interactive login.")
    info("  After logging in once via terminal (ssh root@172.16.84.1), the default password is gone.")
    info("  Module management troubleshooting: if 'opkg update' fails, ensure internet is shared.")
    ssh = wait_for_ssh(TURTLE_IP, SSH_USER, SSH_PASS, timeout=60)
    if not ssh:
        # --- Troubleshoot SSH failure ---
        warn("SSH failed with default password.")

        # 1. Known-hosts conflict after firmware update
        from pathlib import Path as _Path
        kh_file = _Path.home() / ".ssh" / "known_hosts"
        if kh_file.exists() and TURTLE_IP in kh_file.read_text(errors="replace"):
            warn(f"Stale known_hosts entry found for {TURTLE_IP}.")
            if confirm("Clear known_hosts entry and retry?", default=True):
                clear_ssh_known_hosts(TURTLE_IP)
                ssh = wait_for_ssh(TURTLE_IP, SSH_USER, SSH_PASS, timeout=30)

        # 2. Password was changed on first login
        if not ssh:
            warn("Note: The LAN Turtle forces a password change on first interactive login.")
            warn("If you logged in via the Turtle Shell before, the password is no longer 'sh3llz'.")
            custom_pass = prompt("Enter custom SSH password (blank to abort)", "")
            if custom_pass:
                ssh = wait_for_ssh(TURTLE_IP, SSH_USER, custom_pass, timeout=30)

        if not ssh:
            err("SSH connection failed.")
            print(f"""
  Troubleshooting:
    • Default password: {SSH_PASS} (may have been changed on first login)
    • Try: ssh-keygen -R {TURTLE_IP}
    • Check USB port (prefer USB 2.0; USB 3.0 can cause enumeration issues)
    • LAN Turtle 3G: modem may need initialisation; try disconnecting/reconnecting.
    • Recovery: hold reset button inside case while plugging in (see reset instructions).
            """)
            if ics_enabled:
                disable_ics()
            sys.exit(1)
    ok("SSH connected.")
    check_firmware_version(ssh)

    # Handle first-login password change
    rc, banner, _ = ssh.run("cat /etc/turtle_version 2>/dev/null || echo 'connected'")
    if "sh3llz" in SSH_PASS:
        info("Note: Default password is in use. The Turtle Shell will prompt you to change it on first interactive login.")
        info("After changing password, update it in this script's SSH_PASS constant or enter when prompted.")

    firmware_update(ssh)

    # Steps 9-10
    if confirm("\nManage modules?"):
        manage_modules(ssh)

    cleanup(ssh, ics_enabled)


if __name__ == "__main__":
    main()
