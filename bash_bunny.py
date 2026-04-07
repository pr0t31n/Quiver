#!/usr/bin/env python3
"""
Bash Bunny Tool Manager
Handles arming-mode detection, internet sharing, firmware updates, payload
upload with syntax validation, and package installation for the Bash Bunny
Mark I and Mark II.

Usage:
    python3 bash_bunny.py
"""

import glob
import json
import os
import re
import sys
import time
import shutil
import tempfile
import textwrap
import urllib.request
from pathlib import Path
from typing import Optional

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    sudo_run, sudo_output, run_streaming_sudo,
    detect_usb_device, find_mounted_drive,
    enable_ics, disable_ics,
    ensure_apt_packages, ensure_brew_packages,
    wait_for_ssh, SSHClient,
    get_interface_for_ip, get_internet_interface,
    get_macos_service_for_iface,
    ping, wait_for_ping,
    check_packages_debian, install_debian_package,
    check_bash_syntax, extract_required_commands,
    detection_loop, SerialConsole,
    clear_ssh_known_hosts,
    require_sudo,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    get_selected_payload, verify_device_connection,
)


def check_firmware_version(ssh_client=None):
    heading("Firmware Version Check")
    current = None
    if ssh_client:
        try:
            _, stdout, _ = ssh_client.exec_command("cat /etc/bunny_version 2>/dev/null || bunny_version 2>/dev/null")
            current = stdout.read().decode().strip()
        except Exception as e:
            warn(f"Could not read firmware version: {e}")

    if current:
        ok(f"Bash Bunny firmware: {current}")
    else:
        info("Could not auto-detect Bash Bunny firmware version.")

    info("")
    info("Bash Bunny firmware updates require a Hak5 account:")
    info("  1. Download firmware from: https://downloads.hak5.org/")
    info("  2. Copy to Bash Bunny storage root as /upgrade/upgrade.sh or similar")
    info("  3. Check Hak5 docs: https://docs.hak5.org/bash-bunny/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Bash Bunny (Mark I / Mark II)"
DESCRIPTION = "Full Linux USB attack platform — HID, Ethernet, Serial, Storage"
VID         = "F000"   # Bash Bunny USB vendor ID (all PIDs)
BUNNY_IP    = "172.16.64.1"
SSH_USER    = "root"
SSH_PASS    = "hak5bunny"
DRIVE_LABEL = "BashBunny"

FIRMWARE_URL     = "https://downloads.hak5.org/bunny"
FIRMWARE_API_URL = "https://downloads.hak5.org/api/devices/bunny/firmware"

# Commands provided by the Bash Bunny payload runtime (not standard binaries)
BB_BUILTINS = {
    "ATTACKMODE", "LED", "QUACK", "GET", "WAIT_FOR_PRESENT",
    "WAIT_FOR_NOT_PRESENT", "RUN", "LOOT_DIR",
}

# LED states recognised in payload.txt
LED_STATES = {
    "SETUP", "ATTACK", "STAGE1", "STAGE2", "STAGE3",
    "SPECIAL", "FAIL", "CLEANUP", "FINISH",
    "R", "G", "B", "Y", "M", "C", "W",
    "SUCCESS", "BLINK",
}

ATTACKMODES = {
    "HID", "STORAGE", "SERIAL", "RNDIS_ETHERNET", "ECM_ETHERNET", "AUTO_ETHERNET", "OFF",
}

MODE_INSTRUCTIONS = """
The Bash Bunny was not detected.  Please follow these steps:

  1. Locate the physical switch on the Bash Bunny.
  2. Slide the switch to position 3  (closest to the USB plug) — ARMING MODE.
  3. LED should slowly blink BLUE when in arming mode.
  4. Plug the Bash Bunny into a USB-A port on this computer.
  5. Wait ~15 seconds for the device to fully boot.

If LED is NOT blinking blue:
  • Ensure switch is fully in position 3 (not between positions).
  • Try unplugging and replugging.
  • The mass storage drive should appear as "BashBunny".
"""

RESET_INSTRUCTIONS = """
Factory Reset Procedure (restores firmware v1.0):

  1. Set the switch to ARMING MODE (position 3).
  2. Plug the Bash Bunny in, wait for LED to turn on, then UNPLUG it immediately
     after the GREEN LED turns off.
  3. Repeat step 2 three more times (4 total cycles).
  4. Plug in and wait ~5 minutes.
  5. LED: Red/Blue alternating = recovery in progress
     LED: Green = rebooting
     LED: Blue slow blink = arming mode ready (reset complete)
  6. After reset, return here to update to the latest firmware.

  WARNING: Factory reset erases all payloads and loot.
"""

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_bunny() -> bool:
    """Detect Bash Bunny by VID or mounted drive label."""
    if detect_usb_device(VID):
        info(f"Detected via USB VID {VID}")
        return True
    drive = find_mounted_drive(DRIVE_LABEL)
    if drive:
        info(f"Detected via mounted drive: {drive}")
        return True
    if ping(BUNNY_IP):
        info(f"Detected via ping at {BUNNY_IP}")
        return True
    return False


# ── Arming-mode wait ──────────────────────────────────────────────────────────

_ARMING_INSTRUCTIONS = (
    "How to put the Bash Bunny into ARMING MODE:\n"
    "\n"
    "  The Bash Bunny has a physical switch on its side with 3 positions:\n"
    "\n"
    "      Position 1 ──── Farthest from the USB plug  (runs Payload 1)\n"
    "      Position 2 ──── Middle                       (runs Payload 2)\n"
    "      Position 3 ──── Closest to the USB plug      (ARMING MODE  ←)\n"
    "\n"
    "  Steps:\n"
    "    1. Slide the switch FULLY to Position 3 (closest to the USB plug).\n"
    "    2. Plug the Bash Bunny into a USB-A port on this computer.\n"
    "    3. Wait ~15 seconds for the boot LED sequence:\n"
    "\n"
    "       ● RED solid        — OS loading (first ~5 s)\n"
    "       ● YELLOW solid     — Setup / init stage\n"
    "       ● GREEN solid      — Cleanup / ready stage\n"
    "       ● BLUE slow blink  — ARMING MODE ready ✓\n"
    "\n"
    "    4. The 'BashBunny' drive will mount on your desktop when ready.\n"
    "\n"
    "  This script detects the device automatically — no button press needed."
)


def wait_arming_mode(timeout: int = 300) -> bool:
    """
    Show arming mode instructions and poll for Bash Bunny detection.
    In web mode: opens the waiting modal in Quiver and closes it on detection.
    In terminal mode: prints instructions and shows polling progress.
    Returns True if detected within timeout seconds.
    """
    wait_start(_ARMING_INSTRUCTIONS)

    deadline = time.time() + timeout
    poll_interval = 3
    last_reported = -(poll_interval + 1)

    while time.time() < deadline:
        if detect_bunny():
            wait_done("Bash Bunny detected in arming mode!")
            return True
        elapsed = int(time.time() - (deadline - timeout))
        if elapsed - last_reported >= 10:
            remaining = int(deadline - time.time())
            wait_status(
                f"Waiting for Bash Bunny… {elapsed}s elapsed, {remaining}s remaining"
            )
            last_reported = elapsed
        time.sleep(poll_interval)

    wait_timeout(
        f"Bash Bunny not detected after {timeout // 60} minute(s). "
        "Check that the switch is fully in position 3 and the LED is slow-blinking BLUE."
    )
    return False


# ── macOS ICS helpers ──────────────────────────────────────────────────────────

def _find_bb_usb_interface() -> tuple:
    """
    Search networksetup -listallhardwareports for the Bash Bunny USB interface.
    Returns (device_name, display_name) or (None, None).
    """
    hw_out = run_output("networksetup -listallhardwareports 2>/dev/null")
    blocks = re.split(r"(?=^Hardware Port)", hw_out, flags=re.MULTILINE)
    keywords = ("RNDIS", "CDC", "Gadget", "Linux", "Bash Bunny", "ECM")
    for block in blocks:
        if any(kw.lower() in block.lower() for kw in keywords):
            m_dev  = re.search(r"Device:\s+(\S+)", block)
            m_port = re.search(r"Hardware Port:\s+(.+)", block)
            if m_dev:
                return m_dev.group(1).strip(), (m_port.group(1).strip() if m_port else "USB Ethernet")
    return None, None


def _check_bridge100_ip() -> Optional[str]:
    """Return the IP address of bridge100 if macOS Internet Sharing is active."""
    out = run_output("ifconfig bridge100 2>/dev/null")
    for ln in out.splitlines():
        m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", ln)
        if m:
            return m.group(1)
    return None


def _ics_system_settings_wizard(internet_if: Optional[str],
                                  internet_svc: Optional[str],
                                  bb_if: Optional[str],
                                  bb_svc: Optional[str]) -> bool:
    """Guide user through macOS System Settings Internet Sharing with auto-verification."""
    # Attempt to fill in missing names from networksetup
    if not bb_svc and bb_if:
        bb_svc = get_macos_service_for_iface(bb_if)
    if not bb_if or not bb_svc:
        bb_if2, bb_svc2 = _find_bb_usb_interface()
        if bb_if2:
            bb_if, bb_svc = bb_if2, bb_svc2

    share_from = internet_svc or internet_if or "your Wi-Fi or Ethernet"
    share_to   = bb_svc or "RNDIS/Ethernet Gadget  ← look for USB/Linux/ECM entry"

    # Detect macOS version for correct Settings path
    os_ver_str = run_output("sw_vers -productVersion 2>/dev/null").strip()
    try:
        major = int(os_ver_str.split(".")[0])
    except Exception:
        major = 13
    if major >= 13:
        settings_nav = "Apple menu  →  System Settings  →  General  →  Sharing"
    else:
        settings_nav = "Apple menu  →  System Preferences  →  Sharing"

    col = 66  # column width for the box
    def row(left):
        return f"│  {left:<{col}}│"

    print(
        "┌─ macOS Internet Sharing — Step by Step " + "─" * (col - 39) + "┐\n"
        + row("") + "\n"
        + row(f"  1. Open:  {settings_nav}") + "\n"
        + row("") + "\n"
        + row("  2. Click 'Internet Sharing' in the list (don't enable the") + "\n"
        + row("     toggle/checkbox yet).") + "\n"
        + row("") + "\n"
        + row("  3. Set 'Share your connection from' to:") + "\n"
        + row(f"        ▶  {share_from}") + "\n"
        + row("") + "\n"
        + row("  4. In 'To computers using', checkmark the entry:") + "\n"
        + row(f"        ▶  {share_to}") + "\n"
        + row("") + "\n"
        + row("  5. Now enable the 'Internet Sharing' toggle / checkbox.") + "\n"
        + row("     Click 'Start' when macOS asks for confirmation.") + "\n"
        + row("") + "\n"
        + row("  NOTE: A new interface 'bridge100' will appear — this is normal.") + "\n"
        + row("") + "\n"
        + "└" + "─" * (col + 3) + "┘"
    )

    if not WEB_MODE:
        pause("Press ENTER once Internet Sharing is enabled…")
    else:
        info("Watching for Internet Sharing to activate (bridge100)…")
        info("Enable Internet Sharing in System Settings, then this will continue.")

    # Auto-verify: poll for bridge100
    info("Waiting for bridge100 to appear (up to 2 minutes)…")
    deadline = time.time() + 120
    bridge_ip = None
    while time.time() < deadline:
        bridge_ip = _check_bridge100_ip()
        if bridge_ip:
            break
        remaining = int(deadline - time.time())
        info(f"bridge100 not yet active… {remaining}s remaining")
        time.sleep(5)

    if bridge_ip:
        ok(f"Internet Sharing active — bridge100 host IP: {bridge_ip}")
        prefix = ".".join(bridge_ip.split(".")[:3])
        bb_bridge_ip = f"{prefix}.2"
        info(f"Bash Bunny should receive DHCP address: ~{bb_bridge_ip}")
        # Poll briefly for BB's DHCP address
        dhcp_dl = time.time() + 25
        while time.time() < dhcp_dl:
            if ping(bb_bridge_ip):
                ok(f"Bash Bunny responds at {bb_bridge_ip} via bridge ✓")
                break
            time.sleep(3)
        return True
    else:
        warn("bridge100 did not appear within 2 minutes.")
        warn("Internet Sharing may not have been enabled, or the wrong interface was selected.")
        if confirm("Try automated PF NAT instead?", default=True):
            return enable_ics(BUNNY_IP)
        return False


def _ics_wizard_macos() -> bool:
    """
    Guided macOS Internet Sharing wizard.
    Auto-detects interfaces, presents options with precise names, and
    auto-verifies completion.
    """
    info("Detecting network interfaces…")

    internet_if  = get_internet_interface()
    internet_svc = get_macos_service_for_iface(internet_if) if internet_if else None
    if internet_if:
        info(f"Your internet interface: {internet_if} ({internet_svc or 'unknown service'})")
    else:
        warn("Could not auto-detect your internet interface (WiFi/Ethernet).")

    bb_if  = get_interface_for_ip(BUNNY_IP)
    bb_svc = get_macos_service_for_iface(bb_if) if bb_if else None
    if bb_if:
        info(f"Bash Bunny USB interface: {bb_if} ({bb_svc or 'unknown service'})")
    else:
        # Try to find it even if routing not set up yet
        bb_if, bb_svc = _find_bb_usb_interface()
        if bb_if:
            info(f"Bash Bunny USB interface (from hardware ports): {bb_if} ({bb_svc})")
        else:
            warn("Could not find Bash Bunny USB interface — ensure it is booted in arming mode.")

    # Check if ICS is already active
    bridge_ip = _check_bridge100_ip()
    if bridge_ip:
        ok(f"Internet Sharing is already active! bridge100 at {bridge_ip}")
        return True

    method = numbered_menu(
        "Choose how to share internet with the Bash Bunny:",
        [
            "Automatic  — PF NAT rules (requires sudo, no GUI navigation needed)",
            "Guided     — macOS System Settings / System Preferences wizard",
            "Skip       — Bash Bunny already has internet access",
        ],
    )

    if method == 2:
        return True
    if method == 0:
        return enable_ics(BUNNY_IP)
    return _ics_system_settings_wizard(internet_if, internet_svc, bb_if, bb_svc)


# ── Serial-console repair ─────────────────────────────────────────────────────

def find_bb_serial_port() -> Optional[str]:
    """
    Auto-detect the Bash Bunny serial console port.
    On macOS the BB CDC-ACM device appears as /dev/tty.usbmodemXXXX.
    On Linux it appears as /dev/ttyACM0 or /dev/ttyUSB0.
    """
    import glob
    os_name = get_os()
    if os_name == "macos":
        patterns = ["/dev/tty.usbmodem*", "/dev/tty.SLAB_USBtoUART*",
                    "/dev/tty.usbserial-*"]
    else:
        patterns = ["/dev/ttyACM*", "/dev/ttyUSB*"]
    for pat in patterns:
        matches = sorted(glob.glob(pat))
        if matches:
            return matches[0]
    return None


def _fix_bb_serial_side(console: SerialConsole) -> bool:
    """
    Run inside the BB (via serial) to ensure usb0 is up at 172.16.64.1
    and that dropbear (SSH) is listening.
    """
    # ── network interface ──────────────────────────────────────────────────
    info("BB › checking usb0 interface…")
    addr_out = console.run("ip addr show usb0 2>/dev/null || ifconfig usb0 2>/dev/null")

    if addr_out:
        for line in addr_out.splitlines():
            info(f"  BB › {line}")
    else:
        warn("BB › no output from usb0 query — interface may not exist yet")

    if BUNNY_IP not in addr_out:
        warn(f"BB › usb0 not at {BUNNY_IP} — bringing up and assigning IP…")
        out = console.run("ip link set usb0 up 2>/dev/null || ifconfig usb0 up 2>/dev/null")
        if out:
            info(f"BB › ip link set usb0 up: {out}")
        out = console.run("ip addr flush dev usb0 2>/dev/null")
        assign_cmd = (
            f"ip addr add {BUNNY_IP}/24 dev usb0 2>&1 "
            f"|| ifconfig usb0 {BUNNY_IP} netmask 255.255.255.0 2>&1"
        )
        out = console.run(assign_cmd)
        if out:
            info(f"BB › assign IP: {out}")
        # Confirm assignment
        confirm_out = console.run("ip addr show usb0 2>/dev/null || ifconfig usb0 2>/dev/null")
        if BUNNY_IP in confirm_out:
            ok(f"BB › usb0 is now at {BUNNY_IP}/24")
        else:
            err(f"BB › usb0 still not at {BUNNY_IP} after assignment attempt")
            err(f"BB › current state: {confirm_out or '(no output)'}")
            return False
    else:
        ok(f"BB › usb0 already at {BUNNY_IP}")

    # ── dropbear SSH ───────────────────────────────────────────────────────
    info("BB › checking dropbear SSH daemon…")
    ps_out = console.run("ps w 2>/dev/null | grep '[d]ropbear'")
    info(f"BB › ps output: {ps_out or '(empty)'}")

    if "dropbear" not in ps_out:
        warn("BB › dropbear not running — attempting to start…")
        # -R creates host keys automatically; -B allows blank-password root
        started = console.run(
            "dropbear -R -B 2>&1 "
            "|| /etc/init.d/dropbear start 2>&1 "
            "|| /etc/init.d/ssh start 2>&1",
            timeout=10,
        )
        info(f"BB › start output: {started or '(no output)'}")
        time.sleep(1.5)
        ps_check = console.run("ps w 2>/dev/null | grep '[d]ropbear'")
        info(f"BB › re-check ps: {ps_check or '(empty)'}")
        if "dropbear" in ps_check:
            ok("BB › dropbear started successfully")
        else:
            err("BB › could not start dropbear — SSH will not be available")
            return False
    else:
        ok("BB › dropbear is running")

    return True


def _fix_host_interface_macos(bb_ip: str = BUNNY_IP) -> Optional[str]:
    """
    On macOS, find the BB's ECM/CDC Ethernet interface, assign
    172.16.64.64/24 to it, and return the interface name.
    """
    info("Host › locating BB network interface…")

    # Primary: ask networksetup for an interface that looks like a USB gadget
    hw_out = run_output("networksetup -listallhardwareports 2>/dev/null")
    info(f"Host › networksetup hardware ports:\n{hw_out or '  (no output)'}")

    blocks   = re.split(r"(?=^Hardware Port)", hw_out, flags=re.MULTILINE)
    bb_iface = None
    keywords = ("RNDIS", "CDC", "Gadget", "Linux", "Bash Bunny", "ECM")
    for block in blocks:
        matched_kw = [kw for kw in keywords if kw in block]
        if matched_kw:
            m = re.search(r"Device:\s+(\S+)", block)
            if m:
                bb_iface = m.group(1).strip()
                info(f"Host › matched keyword(s) {matched_kw} → interface {bb_iface}")
                break

    # Fallback: scan en* interfaces for one without an IP (newly appeared)
    if not bb_iface:
        info("Host › keyword match failed — scanning en* interfaces for unconfigured gadget…")
        ifconfig_l = run_output("ifconfig -l 2>/dev/null").split()
        info(f"Host › active interfaces: {' '.join(ifconfig_l)}")
        for iface in sorted(ifconfig_l):
            if not re.match(r"^en\d+$", iface) or iface in ("en0", "en1"):
                continue
            ifc_out = run_output(f"ifconfig {iface} 2>/dev/null")
            has_inet = "inet " in ifc_out
            has_bb   = "172.16.64" in ifc_out
            info(f"Host › {iface}: inet={has_inet}, bb_subnet={has_bb}")
            if not has_inet or has_bb:
                bb_iface = iface
                info(f"Host › selected {iface} as BB gadget interface")
                break

    if not bb_iface:
        warn("Host › could not auto-detect BB interface from networksetup or ifconfig scan")
        bb_iface = prompt(
            "Enter the BB host interface name (e.g. en3)", "en3"
        )

    info(f"Host › assigning 172.16.64.64/24 to {bb_iface}…")
    info("  Why: Host needs a static IP in the BB subnet so it can forward packets.")
    info("  Expected: ifconfig exits silently if successful.")
    info("  If it fails: ensure the interface is up and the Bash Bunny is in arming mode.")
    r = sudo_run(f"ifconfig {bb_iface} 172.16.64.64 netmask 255.255.255.0 up 2>&1")
    if r.stdout.strip():
        info(f"Host › ifconfig output: {r.stdout.strip()}")
    if r.returncode == 0:
        ok(f"Host › {bb_iface} configured: 172.16.64.64/24")
    else:
        warn(f"Host › ifconfig returned code {r.returncode} — may already be configured")
        # Show current state for diagnosis
        cur = run_output(f"ifconfig {bb_iface} 2>/dev/null")
        info(f"Host › current {bb_iface} state: {cur or '(no output)'}")

    return bb_iface


def _apply_pf_nat(internet_if: str, bb_if: str) -> bool:
    """Apply minimal pfctl NAT so the BB can reach the internet."""
    info(f"Host › applying PF NAT: {bb_if} → {internet_if}")
    pf_conf = (
        f"nat on {internet_if} from {bb_if}:network to any -> ({internet_if})\n"
        f"pass in  quick on {bb_if}\n"
        f"pass out quick on {internet_if}\n"
    )
    pf_file = Path("/tmp/quiver_pf.conf")
    pf_file.write_text(pf_conf)
    info(f"Host › PF rules written to {pf_file}:")
    for line in pf_conf.strip().splitlines():
        info(f"  {line}")

    r_sysctl = sudo_run("sysctl -w net.inet.ip.forwarding=1 2>&1")
    info(f"Host › ip forwarding: {(r_sysctl.stdout + r_sysctl.stderr).strip() or 'ok'}")

    r_disable = sudo_run("pfctl -d 2>&1")
    disable_out = (r_disable.stdout + r_disable.stderr).strip()
    info(f"Host › pfctl -d: {disable_out or 'ok (was already disabled)'}")

    r = sudo_run(f"pfctl -e -f {pf_file} 2>&1")
    pfctl_out = (r.stdout + r.stderr).strip()
    info(f"Host › pfctl -e -f: rc={r.returncode} output={pfctl_out or '(none)'}")

    if r.returncode == 0 or "pf enabled" in pfctl_out.lower():
        ok(f"Host › PF NAT active: {bb_if} → {internet_if}")
        return True
    err(f"Host › pfctl failed (rc={r.returncode}): {pfctl_out[:300]}")
    return False


def _configure_bb_gateway(console: SerialConsole,
                           gateway: str = "172.16.64.64",
                           dns: str = "8.8.8.8") -> bool:
    """Set the BB's default route and DNS so it can reach the internet."""
    info(f"BB › setting default gateway to {gateway} and DNS to {dns}…")

    # Show existing routes for diagnosis
    routes_before = console.run("ip route 2>/dev/null || route -n 2>/dev/null")
    info(f"BB › routes before:\n{routes_before or '  (no output)'}")

    del_out = console.run("ip route del default 2>&1 || route del default 2>&1")
    if del_out:
        info(f"BB › route del default: {del_out}")

    gw_out = console.run(
        f"ip route add default via {gateway} 2>&1 "
        f"|| route add default gw {gateway} 2>&1"
    )
    if gw_out:
        info(f"BB › route add default: {gw_out}")

    resolv_out = console.run(f'echo "nameserver {dns}" > /etc/resolv.conf && cat /etc/resolv.conf')
    info(f"BB › /etc/resolv.conf: {resolv_out or '(not readable)'}")

    routes_after = console.run("ip route 2>/dev/null || route -n 2>/dev/null")
    info(f"BB › routes after:\n{routes_after or '  (no output)'}")

    # Quick connectivity test via ping
    info(f"BB › testing connectivity (ping {dns})…")
    ping_out = console.run(f"ping -c 2 -W 3 {dns} 2>&1", timeout=12)
    info(f"BB › ping output:\n{ping_out or '  (no output)'}")
    if "2 received" in ping_out or "2 packets received" in ping_out:
        ok(f"BB › internet connectivity confirmed via ping {dns}")
        return True

    # Fallback: HTTP connectivity test
    info("BB › ping inconclusive — trying HTTP fetch…")
    curl_out = console.run(
        "wget -qO- --timeout=5 http://ipinfo.io/ip 2>&1 || "
        "curl -s --max-time 5 http://ipinfo.io/ip 2>&1",
        timeout=15,
    )
    info(f"BB › HTTP fetch output: {curl_out or '(no output)'}")
    if curl_out.strip() and not curl_out.strip().startswith("wget") and not curl_out.strip().startswith("curl"):
        ok(f"BB › internet confirmed — public IP: {curl_out.strip()}")
        return True

    warn("BB › could not verify internet access from device")
    warn("BB › check: host interface is up, PF NAT is loaded, IP forwarding is enabled")
    return False


def fix_via_serial() -> bool:
    """
    Full serial-based repair sequence:
      1. Find / prompt for serial port
      2. Connect to the BB serial console
      3. Fix BB usb0 + SSH (dropbear) on the BB side
      4. Configure host macOS interface at 172.16.64.64
      5. Apply PF NAT for internet sharing
      6. Set BB default gateway + DNS
      7. Return True if SSH is now reachable
    """
    heading("Serial Console — SSH & Internet Setup")

    # ── Locate serial port ─────────────────────────────────────────────────
    info("Scanning for BB serial port…")
    os_name = get_os()
    if os_name == "macos":
        patterns = ["/dev/tty.usbmodem*", "/dev/tty.SLAB_USBtoUART*", "/dev/tty.usbserial-*"]
    else:
        patterns = ["/dev/ttyACM*", "/dev/ttyUSB*"]
    info(f"Checking patterns: {', '.join(patterns)}")

    port = find_bb_serial_port()
    if port:
        ok(f"Serial port found: {port}")
    else:
        warn("No serial port matched — check the BB is plugged in and switch is at position 3")
        port = prompt(
            "Enter serial port path (e.g. /dev/tty.usbmodem1)",
            "/dev/tty.usbmodem1",
        )
        info(f"Using user-supplied port: {port}")

    # ── Open console ───────────────────────────────────────────────────────
    info(f"Opening {port} at 115200 8N1…")
    console = SerialConsole(port, baud=115200)
    if not console.connect():
        err(f"Could not open serial console on {port}")
        err("Ensure: BB is in switch 3 (arming mode), USB cable is data-capable, "
            "no other process has the port open (screen, minicom, etc.)")
        return False
    ok(f"Serial console open on {port}")

    try:
        # ── Step 1: BB-side network + SSH ──────────────────────────────────
        info("--- BB-side repair ---")
        if not _fix_bb_serial_side(console):
            err("BB-side repair failed — cannot continue")
            return False

        # ── Step 2: host-side interface + NAT ─────────────────────────────
        info("--- Host-side interface & NAT ---")
        if os_name == "macos":
            bb_if = _fix_host_interface_macos()
            if not bb_if:
                err("Could not identify or configure host BB interface")
                return False

            internet_if = get_internet_interface()
            info(f"Host › internet-facing interface: {internet_if or '(not found)'}")
            if not internet_if:
                warn("Host › cannot detect internet interface — NAT setup skipped")
                warn("Host › run 'route -n get default' to diagnose")
            else:
                _apply_pf_nat(internet_if, bb_if)

        elif os_name == "linux":
            device_if = get_interface_for_ip(BUNNY_IP)
            if not device_if:
                warn(f"Host › no interface routes to {BUNNY_IP} — prompting…")
                device_if = prompt("Enter BB host interface name", "usb0")
            info(f"Host › using interface {device_if}")
            info("Host › assigning 172.16.64.64/24 — this IP is the gateway the BB will use.")
            r1 = sudo_run(f"ip addr add 172.16.64.64/24 dev {device_if} 2>&1")
            info(f"Host › ip addr add: {(r1.stdout + r1.stderr).strip() or 'ok'}")
            r2 = sudo_run(f"ip link set {device_if} up 2>&1")
            info(f"Host › ip link set up: {(r2.stdout + r2.stderr).strip() or 'ok'}")
            enable_ics(BUNNY_IP)

        # Small pause to let the interface settle before configuring the BB route
        info("Host › waiting 2s for interface to settle…")
        time.sleep(2)

        # Verify host can ping BB before setting up BB gateway
        info(f"Host › pinging BB at {BUNNY_IP}…")
        if ping(BUNNY_IP):
            ok(f"Host › {BUNNY_IP} is reachable from host")
        else:
            warn(f"Host › {BUNNY_IP} not responding to ping — gateway config may still work")

        # ── Step 3: BB gateway + DNS ───────────────────────────────────────
        info("--- BB gateway & DNS ---")
        _configure_bb_gateway(console)

    finally:
        info("Closing serial console.")
        console.close()

    # ── Final SSH ping check ───────────────────────────────────────────────
    info(f"Final check: pinging {BUNNY_IP}…")
    if ping(BUNNY_IP):
        ok(f"{BUNNY_IP} responds to ping — SSH should be available")
        return True
    else:
        warn(f"{BUNNY_IP} still not responding to ping")
        warn("SSH may still work if the interface came up without ICMP. Will attempt SSH anyway.")
        return True  # Worth trying SSH regardless


# ── Internet Sharing ──────────────────────────────────────────────────────────

def setup_internet_sharing() -> bool:
    heading("Step 7 — Internet Sharing Setup")
    os_name = get_os()

    if os_name == "macos":
        return _ics_wizard_macos()

    elif os_name == "linux":
        print("""
  Setting up NAT via iptables so the Bash Bunny can reach the internet.
  The Bash Bunny expects its gateway at 172.16.64.64.

  Assign your interface IP first if not already set:
    sudo ip addr add 172.16.64.64/24 dev <bunny_if>
        """)
        device_if = get_interface_for_ip(BUNNY_IP)
        if not device_if:
            device_if = prompt("Enter the Bash Bunny interface name (e.g. usb0)", "usb0")
        info(f"Configuring NAT for interface: {device_if}")
        info("Assigning gateway IP 172.16.64.64/24 to the Bash Bunny host interface…")
        info("  Why: The Bash Bunny expects its default gateway at 172.16.64.64.")
        info("  Expected: 'ip addr add' returns silently (address may already be set).")
        info("  If it fails: check the interface name with 'ip link show'.")
        sudo_run(f"ip addr add 172.16.64.64/24 dev {device_if} 2>/dev/null")
        sudo_run(f"ip link set {device_if} up")
        return enable_ics(BUNNY_IP)

    else:
        print("""
  Windows Manual ICS Setup:
    1. Payload must use ATTACKMODE RNDIS_ETHERNET.
    2. Control Panel → Network Connections → right-click Wi-Fi (or Ethernet) → Properties
       → Sharing tab → check "Allow other network users to connect..."
       → Select the Bash Bunny adapter from the dropdown.
    3. Right-click Bash Bunny interface → Properties → TCP/IPv4
       Set IP: 172.16.64.64, Mask: 255.255.255.0, Gateway: blank
        """)
        pause("Complete manual setup, then press ENTER…")
        return True


# ── Firmware Update ───────────────────────────────────────────────────────────

def firmware_update(ssh: SSHClient) -> bool:
    heading("Step 8 — Firmware Update")

    # Check current version
    rc, ver_out, _ = ssh.run("cat /etc/bunny_version 2>/dev/null || cat /etc/os-release 2>/dev/null")
    current_ver = "unknown"
    for line in ver_out.splitlines():
        if "VERSION" in line.upper():
            current_ver = line.split("=", 1)[-1].strip().strip('"')
            break
    info(f"Current firmware version: {current_ver}")

    print(f"\n  Download the latest Bash Bunny firmware from:\n  {FIRMWARE_URL}")
    fw_path = prompt("Path to downloaded firmware .tar.gz (leave blank to skip update)")
    if not fw_path:
        warn("Skipping firmware update.")
        return True

    fw_path = Path(fw_path).expanduser()
    if not fw_path.exists():
        err(f"File not found: {fw_path}")
        return False

    if not fw_path.suffix in (".gz", ".tar"):
        warn("Expected a .tar.gz file. Proceeding anyway…")

    # Copy to Bash Bunny drive root
    drive = find_mounted_drive(DRIVE_LABEL)
    if drive:
        info("Copying firmware to Bash Bunny drive root…")
        dest = drive / fw_path.name
        shutil.copy2(fw_path, dest)
        ok(f"Firmware copied to {dest}")
        info("Safely eject the drive, leave switch in position 3, and replug.")
        info("LED: Red/Blue alternating = flashing (up to 10 min). Do NOT unplug.")
        info("LED: Blue slow blink = update complete.")
        pause("Press ENTER after the update is complete and the Bunny reboots…")
    else:
        # Fallback: upload via SSH if Bunny is reachable
        info("Drive not found; attempting to upload via SFTP…")
        remote_path = f"/tmp/{fw_path.name}"
        if not ssh.upload(str(fw_path), remote_path):
            err("Upload failed.")
            return False
        ok(f"Uploaded to {remote_path}")
        warn("Bash Bunny firmware update via SSH is not officially supported.")
        warn("Prefer the drive method described above.")

    return True


# ── Payload Upload ────────────────────────────────────────────────────────────

def validate_bb_payload(path: Path) -> list[str]:
    """
    Validate a Bash Bunny payload.txt file.
    Returns list of warning/error strings (empty = OK).
    """
    issues = []
    try:
        content = path.read_text()
    except Exception as e:
        return [f"Cannot read payload: {e}"]

    lines = content.splitlines()

    if not any("ATTACKMODE" in ln for ln in lines):
        issues.append("WARNING: No ATTACKMODE command found. Device will not enumerate correctly.")

    # Check header comments
    has_title = any(ln.strip().startswith("# Title:") for ln in lines)
    has_desc  = any(ln.strip().startswith("# Description:") for ln in lines)
    if not has_title:
        issues.append("INFO: No '# Title:' header (recommended for documentation)")
    if not has_desc:
        issues.append("INFO: No '# Description:' header (recommended for documentation)")

    # Check ATTACKMODE arguments
    for ln in lines:
        m = re.match(r"^\s*ATTACKMODE\s+(.*)", ln)
        if m:
            modes = m.group(1).upper().split()
            for mode in modes:
                # Strip VID/PID/MAN/PROD/SN specifiers
                if re.match(r"(VID|PID|MAN|PROD|SN)_", mode):
                    continue
                if mode not in ATTACKMODES:
                    issues.append(f"WARNING: Unrecognised ATTACKMODE argument: {mode}")

    # Check LED states
    for ln in lines:
        m = re.match(r"^\s*LED\s+(.*)", ln)
        if m:
            state = m.group(1).strip().upper().split()[0] if m.group(1).strip() else ""
            # LED can be a colour/state word or hex colour
            if state and not re.match(r"^#?[0-9A-F]{3,6}$", state) and state not in LED_STATES:
                issues.append(f"WARNING: Unrecognised LED state: {state}")

    # Check QUACK syntax
    for i, ln in enumerate(lines, 1):
        if "QUACK " in ln:
            quack_cmd = ln.split("QUACK ", 1)[-1].strip()
            if not quack_cmd:
                issues.append(f"WARNING: Line {i}: Empty QUACK command")

    # Bash syntax check on the non-QUACK portion
    bash_errors = check_bash_syntax(str(path))
    for be in bash_errors:
        issues.append(f"BASH SYNTAX: {be}")

    return issues


def upload_payload(ssh: SSHClient) -> bool:
    heading("Step 9 — Payload Upload")

    switch = numbered_menu(
        "Which switch position should receive the payload?",
        ["Switch 1 (payloads/switch1/)", "Switch 2 (payloads/switch2/)"]
    ) + 1

    remote_dir = f"/root/udisk/payloads/switch{switch}"

    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        payload_path = Path(preselected).expanduser()
    else:
        payload_path = Path(prompt("Path to payload.txt (or payload directory)")).expanduser()

    if not payload_path.exists():
        err(f"Not found: {payload_path}")
        return False

    # Resolve to directory or single file
    if payload_path.is_dir():
        payload_txt = payload_path / "payload.txt"
        if not payload_txt.exists():
            err("No payload.txt found in that directory.")
            return False
        payload_dir = payload_path
    else:
        if payload_path.name != "payload.txt":
            warn(f"File is named '{payload_path.name}'; Bash Bunny requires 'payload.txt'. Rename?")
            if confirm("Rename to payload.txt?"):
                new_path = payload_path.parent / "payload.txt"
                shutil.copy2(payload_path, new_path)
                payload_path = new_path
        payload_txt = payload_path
        payload_dir = None

    # Validate payload
    heading("Step 10 — Payload Review & Package Check")
    info("Validating payload syntax…")
    issues = validate_bb_payload(payload_txt)
    if issues:
        warn(f"{len(issues)} issue(s) found:")
        for issue in issues:
            print(f"    {issue}")
        if not confirm("Continue with upload despite issues?"):
            return False
    else:
        ok("Payload syntax looks good.")

    # Check external command dependencies
    info("Scanning payload for external command dependencies…")
    extra_commands = extract_required_commands(
        str(payload_txt),
        known_builtins=BB_BUILTINS,
    )
    if extra_commands:
        info(f"Commands referenced in payload: {', '.join(extra_commands)}")
        availability = check_packages_debian(ssh, extra_commands)
        missing = [cmd for cmd, avail in availability.items() if not avail]
        if missing:
            warn(f"Missing commands: {', '.join(missing)}")
            for cmd in missing:
                if confirm(f"Attempt to install '{cmd}' via apt-get?"):
                    install_debian_package(ssh, cmd)
        else:
            ok("All referenced commands are available on the device.")
    else:
        ok("No external command dependencies detected.")

    # Upload
    info(f"Uploading payload to {remote_dir}…")

    # Ensure target directory exists
    ssh.run(f"mkdir -p {remote_dir}")

    if payload_dir:
        # Upload entire directory contents
        try:
            sftp = ssh._client.open_sftp()
            for item in payload_dir.rglob("*"):
                if item.is_file():
                    rel = item.relative_to(payload_dir)
                    remote_file = f"{remote_dir}/{rel}"
                    # Create remote subdirs
                    remote_subdir = str(Path(remote_file).parent)
                    ssh.run(f"mkdir -p {remote_subdir}")
                    sftp.put(str(item), remote_file)
                    ok(f"  Uploaded: {rel}")
            sftp.close()
        except Exception as e:
            err(f"Directory upload failed: {e}")
            return False
    else:
        if not ssh.upload(str(payload_txt), f"{remote_dir}/payload.txt"):
            err("Upload failed.")
            return False

    ok(f"Payload uploaded to switch{switch} position.")
    return True


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(ssh: SSHClient, ics_enabled: bool):
    heading("Step 11 — Cleanup")
    info("Closing SSH connection…")
    ssh.close()
    if ics_enabled:
        info("Reverting internet sharing configuration…")
        disable_ics()
    ok("Done! Bash Bunny is ready.")
    print("""
  Next steps:
    • Set the switch to position 1 or 2 to run your payload.
    • The LED will indicate stages:  SETUP → ATTACK → FINISH
    • Loot is stored in /root/udisk/loot/  (visible on the drive in arming mode)
    """)


# ── Firmware Update (via Bash Bunny API + drive copy) ─────────────────────────

def run_bb_updater() -> bool:
    """
    Query the Bash Bunny firmware API, download the latest Bash Bunny firmware,
    and copy it to the root of the mounted BashBunny drive.  The device
    installs the firmware automatically on the next boot.

    Returns True if the device is already current or if firmware was
    successfully placed on the drive.  Returns False on error.
    """
    drive = find_mounted_drive(DRIVE_LABEL)
    if not drive:
        warn("BashBunny drive not mounted.")
        warn("Ensure the device is in arming mode (switch position 3) and fully booted.")
        return False

    ok(f"BashBunny drive: {drive}")

    # Read current version from the drive
    current_version = "unknown"
    for vf_name in ("VERSION", "version.txt"):
        vf = drive / vf_name
        if vf.exists():
            current_version = vf.read_text(errors="replace").strip()
            break
    info(f"Current firmware version: {current_version}")

    # Query Bash Bunny firmware API
    info("Checking latest firmware version from Bash Bunny API…")
    try:
        req = urllib.request.Request(
            FIRMWARE_API_URL,
            headers={"User-Agent": "Quiver/1.0 BashBunnyUpdater"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
        data = json.loads(raw)
    except Exception as exc:
        warn(f"Could not reach Bash Bunny firmware API: {exc}")
        info(f"Visit {FIRMWARE_URL} to download firmware manually, then copy the")
        info(".tar.gz file to the root of the BashBunny drive and replug the device.")
        return False

    # Parse API response — handle both {"version":"1.7","url":"..."} and
    # {"latest":{"version":"...","url":"..."}} shapes.
    if "latest" in data and isinstance(data["latest"], dict):
        entry = data["latest"]
    elif "version" in data:
        entry = data
    else:
        warn("Unexpected API response format — cannot determine latest firmware.")
        info(f"Response received: {str(data)[:300]}")
        return False

    latest_version  = entry.get("version", "unknown")
    download_url    = entry.get("url", "")

    if not download_url:
        warn("API response did not include a firmware download URL.")
        info(f"Visit {FIRMWARE_URL} to download manually.")
        return False

    info(f"Latest firmware: {latest_version}")

    if current_version != "unknown" and current_version == latest_version:
        ok(f"Firmware is already up to date (version {current_version}).")
        return True

    info(f"Downloading firmware {latest_version}…")
    fw_filename = download_url.rstrip("/").split("/")[-1] or "bunny_update.tar.gz"
    fw_dest     = drive / fw_filename

    try:
        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": "Quiver/1.0 BashBunnyUpdater"},
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            total      = int(resp.headers.get("Content-Length", 0) or 0)
            downloaded = 0
            chunk_size = 65536
            with open(str(fw_dest), "wb") as fout:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    fout.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = int(downloaded / total * 100)
                        info(f"  {pct:3d}%  {downloaded:,} / {total:,} bytes")
    except Exception as exc:
        err(f"Firmware download failed: {exc}")
        try:
            fw_dest.unlink()
        except Exception:
            pass
        return False

    ok(f"Firmware {latest_version} saved to drive root: {fw_dest.name}")
    print("""
  The Bash Bunny will update automatically when you eject it and replug.

  What to do next:
    1. Eject the BashBunny drive from your computer.
    2. Unplug the Bash Bunny from USB.
    3. Plug it back in (switch still at position 3).

  LED indicators during update:
    ● RED / BLUE alternating — flashing in progress (up to 10 min — do NOT unplug)
    ● GREEN                  — rebooting after flash
    ● BLUE slow blink        — update complete, back in arming mode ✓
    """)
    pause("Complete the steps above, then press ENTER when the BLUE blink is visible…")
    return True


# ── Payload Selection + Drive Copy ────────────────────────────────────────────

def select_and_copy_payload() -> bool:
    """
    Display available Bash Bunny payloads from payloads.json, let the user
    select one and choose a switch position, then copy the payload.txt to
    the appropriate directory on the mounted BashBunny drive.
    If QUIVER_SELECTED_PAYLOAD is set, skip the menu and use that path directly.
    """
    script_dir = Path(__file__).parent

    # If a payload was pre-selected in the Quiver UI, use it directly.
    preselected = get_selected_payload()
    if preselected:
        payload_path = Path(preselected).expanduser()
        if not payload_path.exists():
            err(f"Pre-selected payload not found: {payload_path}")
            return False
        info(f"Using pre-selected payload: {payload_path}")
    else:
        payloads_json = script_dir / "payloads" / "payloads.json"
        if not payloads_json.exists():
            err(f"payloads.json not found at {payloads_json}")
            return False
        try:
            with open(payloads_json, encoding="utf-8") as f:
                all_payloads = json.load(f)
        except Exception as exc:
            err(f"Could not load payloads.json: {exc}")
            return False

        bb_payloads = all_payloads.get("bash_bunny", [])
        if not bb_payloads:
            warn("No Bash Bunny payloads found in payloads.json.")
            return False

        payload_names = [p["name"] for p in bb_payloads]
        selected_idx  = numbered_menu("Select a payload to upload:", payload_names)
        selected      = bb_payloads[selected_idx]

        payload_path = script_dir / selected["path"]
        if not payload_path.exists():
            err(f"Payload file not found: {payload_path}")
            return False

        info(f"Selected payload: {selected['name']}")
        info(f"Payload file:     {payload_path}")

    # Select switch position
    switch = numbered_menu(
        "Which switch position should receive this payload?",
        ["Switch 1  (payloads/switch1/)",
         "Switch 2  (payloads/switch2/)"],
    ) + 1

    payload_label = payload_path.name
    # Confirm before writing
    if not confirm(
        f"Copy '{payload_label}' to switch{switch}?  "
        f"(This will overwrite any existing payload.txt at that position.)",
        default=True,
    ):
        info("Cancelled.")
        return False

    # Locate the mounted drive
    drive = find_mounted_drive(DRIVE_LABEL)
    if not drive:
        warn("BashBunny drive not mounted.")
        warn("Ensure the device is in arming mode (switch position 3).")
        return False

    dest_dir  = drive / "payloads" / f"switch{switch}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_file = dest_dir / "payload.txt"

    info(f"Copying to {dest_file}…")
    shutil.copy2(str(payload_path), str(dest_file))
    ok(f"'{payload_label}' successfully uploaded to switch{switch}.")
    ok(f"  Path on device: payloads/switch{switch}/payload.txt")

    return True


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    # Ensure apt packages are installed on Kali/Debian before anything else.
    # paramiko → SSH; requests → API checks; pyserial/serial → serial console.
    info("Checking required system packages (Kali/Debian)…")
    info("  Why: paramiko (SSH), pyserial (serial console) must be available.")
    info("  If apt-get fails: run manually: sudo apt-get install -y python3-paramiko python3-serial")
    ensure_apt_packages(["python3-paramiko", "python3-serial"])

    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Step 1: Verify device connection ─────────────────────────────────────
    heading("Step 1 — Connect the Bash Bunny in Arming Mode")
    detected = verify_device_connection(
        detect_bunny, TOOL_NAME, _ARMING_INSTRUCTIONS, max_retries=3
    )
    if not detected:
        err("Bash Bunny not detected. Exiting.")
        sys.exit(1)

    check_firmware_version()

    # ── Step 2: Firmware update ───────────────────────────────────────────────
    heading("Step 2 — Firmware Update")
    updated = run_bb_updater()

    # If firmware was downloaded, the device rebooted — wait for it to come back.
    if updated:
        heading("Step 3 — Waiting for Device After Update")
        info("Waiting for Bash Bunny to return to arming mode after firmware update…")
        detected = verify_device_connection(
            detect_bunny, TOOL_NAME, _ARMING_INSTRUCTIONS, max_retries=3
        )
        if not detected:
            warn("Device not re-detected after update.")
            if not confirm("Continue to payload upload anyway?", default=True):
                sys.exit(0)

    # ── Step 4: Payload upload via drive copy ─────────────────────────────────
    heading("Step 4 — Payload Upload")
    preselected = get_selected_payload()
    if preselected or confirm("Upload a payload to the Bash Bunny?", default=True):
        success = select_and_copy_payload()
        if not success:
            warn("Payload upload did not complete.")

    # ── Done ─────────────────────────────────────────────────────────────────
    heading("Complete")
    ok("Bash Bunny setup complete.")
    print("""
  Next steps:
    • Eject the BashBunny drive, then set the switch to position 1 or 2.
    • Unplug and replug — the device will run the selected payload.
    • LED stages:  SETUP → ATTACK → FINISH
    • Loot is stored in loot/  (visible on the BashBunny drive in arming mode)
    """)


if __name__ == "__main__":
    main()
