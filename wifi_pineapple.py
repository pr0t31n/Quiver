#!/usr/bin/env python3
"""
WiFi Pineapple Mark VII Tool Manager
Handles detection, internet sharing, firmware updates, and module management
for the WiFi Pineapple MK7.

Usage:
    python3 wifi_pineapple.py
"""

import re
import sys
import time
import textwrap
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    sudo_run, sudo_output, run_streaming_sudo,
    detect_usb_device, find_mounted_drive,
    enable_ics, disable_ics,
    ensure_apt_packages, ensure_brew_packages,
    wait_for_ssh, SSHClient,
    get_interface_for_ip, get_internet_interface, ping, wait_for_ping,
    check_bash_syntax,
    detection_loop,
    assign_static_ip_macos, get_macos_service_for_iface,
    clear_ssh_known_hosts, check_kernel_module, load_kernel_module,
    require_sudo,
)


def check_firmware_version(ssh=None):
    heading("Firmware Version Check")
    info("Checking WiFi Pineapple firmware version...")
    current = None
    if ssh:
        try:
            _, ver_out, _ = ssh.run(
                "cat /etc/pineapple/version 2>/dev/null || "
                "cat /etc/openwrt_release 2>/dev/null | grep DISTRIB_REVISION"
            )
            current = ver_out.strip()
        except Exception as e:
            warn(f"Could not read firmware version: {e}")

    if current:
        ok(f"Firmware version: {current}")
    else:
        info("Could not auto-detect firmware version.")

    info("")
    info("WiFi Pineapple firmware updates require a Hak5 account:")
    info("  1. Visit: https://downloads.hak5.org/")
    info("  2. Log in and download the latest firmware for your Pineapple model")
    info("  3. Flash via the Pineapple web UI (Settings → Advanced → Firmware Update)")
    info("  4. Or: scp firmware.bin root@172.16.42.1:/tmp/ && ssh root@172.16.42.1 'sysupgrade /tmp/firmware.bin'")
    info("")
    info("Check for updates via Pineapple web UI:")
    info("  Navigate to http://172.16.42.1:1471/ → Settings → Firmware Update")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "WiFi Pineapple Mark VII"
DESCRIPTION = "Dedicated WiFi penetration testing platform (OpenWRT)"
# ASIX AX88772A/B/C (the USB Ethernet adapter chipset)
VID_ASIX    = "0B95"
PID_7720    = "7720"    # AX88772A
PID_772B    = "772B"    # AX88772B/C

PINEAPPLE_IP     = "172.16.42.1"
HOST_STATIC_IP   = "172.16.42.42"
HOST_MASK        = "255.255.255.0"
WEB_UI_PORT      = 1471
SSH_USER         = "root"
SSH_PASS         = "hak5pineapple"

FIRMWARE_URL     = "https://downloads.hak5.org/wifi-pineapple-7"

MACOS_ASIX_NOTE = """
  *** macOS Big Sur (11) and later ASIX Driver Issue ***
  The ASIX AX88772 USB Ethernet driver is broken in macOS 11+.
  Options:
    A) Download the ASIX driver from: https://www.asix.com.tw/en/support/download
       Install it and reboot, then retry.
    B) Use a Linux machine (driver built-in).
    C) Connect to the Pineapple's management WiFi AP instead:
       SSID: Pineapple_XXXX (XXXX = last 4 of MAC)
       Then configure networking manually.
"""

MODE_INSTRUCTIONS = """
The WiFi Pineapple MK7 was not detected.

  1. Connect the antennas BEFORE powering on.
  2. Use the included USB-C cable to connect the Pineapple to this computer.
     (USB-C to USB-A adapter may be needed.)
  3. Power on via the USB-C connection or DC barrel jack.
  4. Wait ~30-45 seconds for the device to fully boot.
  5. You may need to manually assign a static IP to the interface:

     macOS:
       System Settings → Network → USB Ethernet adapter → Manual
       IP: 172.16.42.42 / Mask: 255.255.255.0 / Router: blank

     Linux:
       sudo ip addr add 172.16.42.42/24 dev <interface>
       sudo ip link set <interface> up

  6. Test connectivity: ping 172.16.42.1

  If nothing appears:
"""

RESET_INSTRUCTIONS = """
Factory Reset / Recovery Procedure:

  1. Hold the RESET button (small button near the antenna connectors) while
     applying power to the Pineapple.
  2. Continue holding for about 5 seconds until the LED blinks RED rapidly.
  3. Release the button — LED goes solid RED.
  4. Assign static IP to host: 172.16.42.42 / 255.255.255.0
  5. Browse to:  http://172.16.42.1  (NO port number — this is recovery mode)
  6. Upload the recovery .bin from: https://downloads.hak5.org/wifi-pineapple-7
  7. Wait 5-10 minutes. Do NOT unplug.
  8. After reboot, go through initial setup at http://172.16.42.1:1471

  Password Reset Only (firmware 1.1.0+):
    - Boot normally, then hold reset button for 10+ seconds.
    - LED flashes rainbow → device reboots.
    - Default password restored to: hak5pineapple
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_pineapple() -> bool:
    """Detect Pineapple via ASIX USB or IP ping."""
    if detect_usb_device(VID_ASIX, PID_7720):
        return True
    if detect_usb_device(VID_ASIX, PID_772B):
        return True
    if ping(PINEAPPLE_IP):
        return True
    return False


# ── Network Setup ─────────────────────────────────────────────────────────────

def _check_asix_driver() -> bool:
    """Check ASIX driver status; guide installation on macOS 11+ or Linux if missing."""
    os_name = get_os()
    if os_name == "linux":
        if not check_kernel_module("asix"):
            warn("ASIX USB Ethernet kernel module not loaded.")
            load_kernel_module("asix")
        return True
    elif os_name == "macos":
        # On macOS 11+ (Big Sur and later) the ASIX driver is not bundled
        import platform
        ver = platform.mac_ver()[0]
        try:
            major = int(ver.split(".")[0])
        except (ValueError, IndexError):
            major = 0
        if major >= 11 and not detect_usb_device(VID_ASIX):
            warn(f"macOS {ver} detected — built-in ASIX driver may be missing.")
            print(MACOS_ASIX_NOTE)
    return True


def configure_host_interface() -> bool:
    """Assign static IP to the host interface for the Pineapple."""
    os_name = get_os()
    device_if = get_interface_for_ip(PINEAPPLE_IP)

    if ping(PINEAPPLE_IP):
        ok(f"Pineapple already reachable at {PINEAPPLE_IP}")
        return True

    # Check/load driver before trying to configure interface
    _check_asix_driver()

    if os_name == "macos":
        if not device_if:
            # Try to find the ASIX interface
            out = run_output("networksetup -listallhardwareports")
            # Look for USB 10/100 LAN or ASIX in the output
            for line in out.splitlines():
                if "USB" in line.upper() or "ASIX" in line.upper():
                    m = re.search(r"Device:\s+(\w+)", out[out.find(line):])
                    if m:
                        device_if = m.group(1)
                        break
        if not device_if:
            device_if = prompt("Enter the USB Ethernet interface name (e.g. en3, en4)", "en3")
        service = get_macos_service_for_iface(device_if)
        if service:
            info(f"Assigning {HOST_STATIC_IP} to {service} ({device_if})…")
            assign_static_ip_macos(service, HOST_STATIC_IP, HOST_MASK)
        else:
            warn(f"Could not find Network service for {device_if}.")
            warn(f"Please manually set {device_if} to {HOST_STATIC_IP}/{HOST_MASK} in System Settings → Network.")
            pause("Press ENTER after setting the IP…")

    elif os_name == "linux":
        if not device_if:
            device_if = prompt("Enter the USB Ethernet interface name (e.g. eth1, usb0)", "eth1")
        info(f"Assigning {HOST_STATIC_IP}/24 to {device_if}…")
        info("  Why: The Pineapple expects the host at 172.16.42.42/24.")
        info("  Expected: commands return silently on success.")
        info("  If 'RTNETLINK answers: File exists': the address is already set (safe to ignore).")
        info("  If 'Cannot find device': wrong interface name — check 'ip link show'.")
        sudo_run(f"ip addr flush dev {device_if} 2>/dev/null")
        sudo_run(f"ip addr add {HOST_STATIC_IP}/24 dev {device_if}")
        sudo_run(f"ip link set {device_if} up")
    else:
        warn(f"Windows: manually set IP {HOST_STATIC_IP}/{HOST_MASK} on the USB Ethernet adapter.")
        pause("Press ENTER after setting the IP…")

    # Verify
    time.sleep(2)
    if ping(PINEAPPLE_IP):
        ok(f"Pineapple reachable at {PINEAPPLE_IP}")
        return True
    warn("Cannot reach Pineapple. Check cable and interface configuration.")
    return False


# ── Internet Sharing ──────────────────────────────────────────────────────────

def setup_internet_sharing() -> bool:
    heading("Step 7 — Internet Sharing Setup")
    os_name = get_os()
    internet_if = get_internet_interface()

    if os_name == "macos":
        # Check for macOS ASIX driver issue
        if not detect_usb_device(VID_ASIX):
            warn("ASIX USB Ethernet adapter not detected at USB level.")
            print(MACOS_ASIX_NOTE)

        device_if = get_interface_for_ip(PINEAPPLE_IP)
        print(f"""
  To share internet to the WiFi Pineapple on macOS:

  RECOMMENDED: Via WiFi Client Mode on the Pineapple itself:
    1. Open {PINEAPPLE_IP}:{WEB_UI_PORT} in your browser.
    2. Navigate to Settings → Networking → Wireless Client Mode.
    3. Scan for your router, select it, and connect.
    4. Dedicated client interface: wlan2 (preferred).

  Alternative: System Settings ICS:
    1. System Settings → General → Sharing → Internet Sharing
    2. Share from: {internet_if or 'Wi-Fi'}
    3. To computers using: USB Ethernet / ASIX adapter
        """)
        choice = numbered_menu("How would you like to share internet?", [
            "Via WiFi Client Mode on the Pineapple (recommended)",
            "Via macOS Internet Sharing (ICS)",
            "Via PF NAT rules (automated, requires sudo)",
            "Skip — device already has internet",
        ])
        if choice == 0:
            pause("Configure WiFi client mode in the web UI, then press ENTER…")
            return True
        elif choice == 1:
            pause("Configure macOS ICS manually, then press ENTER…")
            return True
        elif choice == 2:
            return enable_ics(PINEAPPLE_IP)
        else:
            return True

    elif os_name == "linux":
        device_if = get_interface_for_ip(PINEAPPLE_IP)
        if not device_if:
            device_if = prompt("Enter Pineapple interface name", "eth1")
        if not internet_if:
            internet_if = prompt("Enter your internet-facing interface", "wlan0")
        info(f"Sharing {internet_if} → {device_if} via iptables NAT…")
        return enable_ics(PINEAPPLE_IP)

    else:
        print("""
  Windows Manual ICS:
    1. Control Panel → Network Connections
    2. Right-click your internet adapter → Properties → Sharing
    3. Check "Allow other network users..." → select USB Ethernet adapter
    4. Set USB Ethernet adapter: IP 172.16.42.42, Mask 255.255.255.0
        """)
        pause("Press ENTER after configuring ICS…")
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

    update_method = numbered_menu("Choose firmware update method:", [
        "Web UI (recommended) — Settings → General → Software Update",
        "Manual upload via SCP + sysupgrade (SSH)",
        "Skip firmware update",
    ])

    if update_method == 0:
        print(f"""
  Update via Web UI:
    1. Open http://{PINEAPPLE_IP}:{WEB_UI_PORT} in your browser.
    2. Navigate to Settings → General → Software Update.
    3. Click 'Check for Updates' then 'Install'.
    4. Wait 5-10 minutes. LED alternates red/blue during update.
    5. Do NOT unplug during update.

  Note: Firmware update acts as a factory reset (loses recon data).
  Backup any scans before updating.
        """)
        pause("Press ENTER after the update completes and device reboots…")
        return True

    elif update_method == 1:
        print(f"\n  Download firmware from: {FIRMWARE_URL}")
        fw_path = prompt("Path to firmware .bin file")
        fw_path = Path(fw_path).expanduser()
        if not fw_path.exists():
            err(f"File not found: {fw_path}")
            return False

        info("Uploading firmware via SFTP…")
        remote_path = f"/tmp/{fw_path.name}"
        if not ssh.upload(str(fw_path), remote_path):
            err("Upload failed.")
            return False
        ok(f"Uploaded to {remote_path}")

        info("Running sysupgrade (device will reboot — SSH session will drop)…")
        ssh.run(f"sysupgrade -n {remote_path} &", timeout=5)
        info("Waiting for device to reboot…")
        time.sleep(15)
        if wait_for_ping(PINEAPPLE_IP, timeout=180):
            ok("Device is back online after firmware update.")
        else:
            warn("Device did not respond within 3 minutes. Check it manually.")
        return True

    else:
        info("Skipping firmware update.")
        return True


# ── Payload / Module Management ───────────────────────────────────────────────

def manage_modules(ssh: SSHClient) -> bool:
    heading("Steps 9-10 — Module / Payload Management")

    print("""
  The WiFi Pineapple uses modules (rather than standalone payload scripts).
  Modules can be installed via:
    • Web UI: Settings → Modules → Module Manager
    • Manually via SSH (opkg install or custom module placement)

  Common modules: PineAP, Evil Portal, Recon, Site Survey, DNSMasq Spoof
    """)

    action = numbered_menu("What would you like to do?", [
        "Install a module via opkg (SSH)",
        "Upload a custom module directory",
        "List installed modules",
        "Skip — manage via web UI",
    ])

    if action == 0:
        pkg = prompt("Module/package name to install")
        if pkg:
            # Update opkg first
            info("Running opkg update…")
            rc, out, _ = ssh.run("opkg update 2>&1", timeout=60)
            rc2, out2, _ = ssh.run(f"opkg install {pkg} 2>&1", timeout=120)
            if rc2 == 0:
                ok(f"Installed: {pkg}")
            else:
                err(f"Installation failed: {out2[:300]}")
        return True

    elif action == 1:
        mod_path = prompt("Path to module directory on this computer")
        mod_path = Path(mod_path).expanduser()
        if not mod_path.is_dir():
            err("Not a directory.")
            return False
        remote_dir = f"/pineapple/modules/{mod_path.name}"
        info(f"Uploading module to {remote_dir}…")
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
            ok("Module uploaded.")
        except Exception as e:
            err(f"Upload failed: {e}")
            return False
        return True

    elif action == 2:
        rc, out, _ = ssh.run("ls /pineapple/modules/ 2>/dev/null")
        if out.strip():
            print("\n  Installed modules:")
            for mod in out.strip().splitlines():
                print(f"    • {mod}")
        else:
            info("No modules found in /pineapple/modules/")
        return True

    else:
        info(f"Manage modules via web UI at http://{PINEAPPLE_IP}:{WEB_UI_PORT}")
        return True


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(ssh: SSHClient, ics_enabled: bool, device_if_configured: bool):
    heading("Step 11 — Cleanup")
    ssh.close()
    if ics_enabled:
        disable_ics()
    if device_if_configured:
        os_name = get_os()
        if os_name == "linux":
            device_if = get_interface_for_ip(PINEAPPLE_IP)
            if device_if:
                info(f"Flushing static IP from {device_if}…")
                info("  Why: Remove the static IP assigned during setup to restore DHCP behaviour.")
                sudo_run(f"ip addr flush dev {device_if} 2>/dev/null")
    ok("WiFi Pineapple MK7 is ready.")
    print(f"""
  Access the Pineapple:
    • Web UI:  http://{PINEAPPLE_IP}:{WEB_UI_PORT}
    • SSH:     ssh {SSH_USER}@{PINEAPPLE_IP}

  Remember to update your SSH known_hosts after firmware updates:
    ssh-keygen -R {PINEAPPLE_IP}
    """)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    # Ensure apt packages are installed on Kali/Debian before anything else.
    # paramiko provides SSH connectivity to the Pineapple; requests enables API calls.
    info("Checking required system packages (Kali/Debian)…")
    info("  Why: python3-paramiko is required for SSH. Install once, then this step is instant.")
    info("  If apt-get fails: run manually: sudo apt-get install -y python3-paramiko python3-requests")
    ensure_apt_packages(["python3-paramiko", "python3-requests"])

    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Step 1 — Connect the Device")
    print("""
  1. Attach BOTH antennas BEFORE powering on (required — do not skip).
  2. Connect the USB-C cable from the Pineapple to this computer.
     (Use a USB-C to USB-A adapter if needed.)
  3. Wait 30-45 seconds for the device to fully boot.

  Expected LED boot sequence:
    ● Solid WHITE/BLUE — Booting (OS loading, 30-45 s)
    ● Solid BLUE       — Management interface ready ✓
                         Accessible at 172.16.42.1:1471

  Other LED states to know:
    ● Solid RED               — Recovery mode (hold reset while powering on)
    ● Rapid RED blink → RED   — Reset button held: password reset in progress
    ● RED/BLUE alternating    — Firmware update in progress (DO NOT unplug)
    ● LED OFF after 60 s      — Boot failure; try power cycling

  You may need to set your host interface IP to 172.16.42.42 / 255.255.255.0.
    """)
    pause("Press ENTER once the device is connected and booting…")

    # Steps 2-6
    detected = detection_loop(
        detect_fn=detect_pineapple,
        mode_instructions=MODE_INSTRUCTIONS,
        reset_instructions=RESET_INSTRUCTIONS,
    )
    if not detected:
        sys.exit(1)

    # Step 4 — Interface confirmation + IP config
    heading("Step 4 — Interface Configuration")
    device_if_configured = configure_host_interface()
    if not device_if_configured:
        warn("Could not configure host interface. Proceeding with best effort.")

    # Step 7 — Internet sharing
    ics_enabled = setup_internet_sharing()

    # Step 8 — SSH + firmware
    info(f"Connecting via SSH to {PINEAPPLE_IP}…")
    ssh = wait_for_ssh(PINEAPPLE_IP, SSH_USER, SSH_PASS, timeout=90)
    if not ssh:
        # Try with default password after reset
        warn("SSH with default password failed; trying common alternative…")
        ssh = wait_for_ssh(PINEAPPLE_IP, SSH_USER, "hak5pineapple", timeout=30)

    if not ssh:
        # --- Troubleshoot SSH failure ---
        warn("SSH connection failed with default credentials.")

        # 1. Known-hosts conflict (very common after firmware update)
        info("Checking for SSH known_hosts conflict…")
        kh_file = Path.home() / ".ssh" / "known_hosts"
        kh_conflict = False
        if kh_file.exists():
            kh_content = kh_file.read_text(errors="replace")
            if PINEAPPLE_IP in kh_content:
                warn(f"Existing known_hosts entry for {PINEAPPLE_IP} may conflict after firmware update.")
                if confirm("Clear known_hosts entry and retry SSH?", default=True):
                    clear_ssh_known_hosts(PINEAPPLE_IP)
                    kh_conflict = True
                    ssh = wait_for_ssh(PINEAPPLE_IP, SSH_USER, SSH_PASS, timeout=30)

        # 2. Password may have been changed via web UI
        if not ssh:
            custom_pass = prompt("SSH failed. Enter custom password if you changed it (blank to skip)", "")
            if custom_pass:
                ssh = wait_for_ssh(PINEAPPLE_IP, SSH_USER, custom_pass, timeout=30)

        # 3. Web UI reachability test
        if not ssh:
            import urllib.request
            web_ok = False
            try:
                urllib.request.urlopen(f"http://{PINEAPPLE_IP}:{WEB_UI_PORT}", timeout=5)
                web_ok = True
            except Exception:
                pass
            if web_ok:
                ok(f"Pineapple web UI is reachable at http://{PINEAPPLE_IP}:{WEB_UI_PORT}")
                warn("SSH is not responding but the web UI works.")
                print(f"""
  SSH recovery options:
    • In web UI: Settings → SSH → ensure SSH is enabled.
    • Reset SSH host key: Settings → Advanced → Reset SSH host key.
    • Or use web UI for module management instead of SSH.
                """)
            else:
                err(f"Pineapple web UI also unreachable. Check host IP is {HOST_STATIC_IP}.")

            print(f"""
  Full troubleshooting checklist:
    • Host IP must be {HOST_STATIC_IP} on the USB Ethernet adapter.
    • Try:  ssh-keygen -R {PINEAPPLE_IP}  then reconnect.
    • Default SSH password: {SSH_PASS}
    • Pineapple web UI: http://{PINEAPPLE_IP}:{WEB_UI_PORT}
    • If using macOS 11+, ensure ASIX driver is installed (see note above).
            """)
            if ics_enabled:
                disable_ics()
            sys.exit(1)

    ok("SSH connected.")
    check_firmware_version(ssh)
    firmware_update(ssh)

    # Steps 9-10
    if confirm("\nManage modules or upload payloads?"):
        manage_modules(ssh)

    cleanup(ssh, ics_enabled, device_if_configured)


if __name__ == "__main__":
    main()
