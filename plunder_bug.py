#!/usr/bin/env python3
"""
Plunder Bug Tool Manager
Handles detection, interface configuration, mode switching (active/passive),
and packet capture for the Plunder Bug inline Ethernet LAN tap.

The Plunder Bug is a pure hardware inline Ethernet tap. It has NO SSH,
NO firmware updates, NO configuration files — it is a USB Ethernet adapter
that mirrors traffic from its two RJ45 ports to the connected host computer.

VID:PID: ASIX AX88772C — 0x0B95:0x772B
MAC OUI:  00:13:37 (Plunder Bug registered OUI)

Usage:
    python3 plunder_bug.py
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
    run_streaming_sudo,
    detect_usb_device,
    get_interface_for_ip, ping,
    detection_loop,
    check_kernel_module, load_kernel_module, check_interface_link, set_interface_promisc,
)


def check_firmware_version():
    heading("Firmware Version Check")
    info("The Plunder Bug is a hardware-only passive Ethernet tap.")
    info("It has NO user-updatable firmware, NO SSH, and NO configuration interface.")
    info("No firmware version check is possible or necessary.")
    info("")
    info("If the device is not functioning correctly:")
    info("  • Try a different USB-C cable (must be data+power, not charge-only)")
    info("  • Check the ASIX AX88772C driver is loaded (Linux: modprobe asix)")
    info("  • Download the latest ASIX driver from: https://www.asix.com.tw/en/support/download")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Plunder Bug"
DESCRIPTION = "Inline Ethernet LAN tap — passive/active traffic mirroring"
VID_ASIX    = "0B95"   # ASIX Electronics Corp.
PID_772B    = "772B"   # AX88772B/C
HAK5_OUI    = "00:13:37"

ASIX_DRIVER_URL = "https://www.asix.com.tw/en/support/download"
FIRMWARE_NOTE = """
  *** The Plunder Bug has NO user-updatable firmware ***
  It is a hardware-only device. No SSH, no configuration, no updates.
"""

MODE_INSTRUCTIONS = """
Plunder Bug not detected.

  Connection method:
    1. Use the USB-C cable to connect the Plunder Bug to this computer.
       (USB-C port is the Tap/Power port.)
    2. Wait ~5-10 seconds for the ASIX USB Ethernet driver to load.
    3. A new Ethernet network interface will appear (ASIX AX88772C).
    4. The green LED on the Plunder Bug illuminates when powered via USB-C.

  Driver notes:
    Linux:   Built-in asix kernel module (loads automatically)
    macOS:   Usually automatic; if not, download from: https://www.asix.com.tw
    Windows: Usually automatic via Windows Update; manual install from ASIX if needed

  Do NOT confuse the two RJ45 ports:
    Port 1 (closest to green LED): Uplink / Upstream (connect to router/switch)
    Port 2 (far from LED):         Downlink / Target device
"""

RESET_INSTRUCTIONS = """
Plunder Bug Troubleshooting:

  The Plunder Bug has no factory reset — it is a passive hardware device.

  If the device is not detected:
    1. Try a different USB-C cable.
    2. Try a different USB port (use USB 3.0 if available for more power).
    3. Verify the ASIX AX88772C driver is installed:
       Linux:   sudo modprobe asix
       macOS:   Download driver from https://www.asix.com.tw
       Windows: Check Device Manager for unknown USB devices

  If the green LED is NOT lit:
    • USB-C cable may be power-only (not data+power). Use a data cable.
    • Try a different USB port or powered USB hub.

  If traffic capture is empty:
    • Verify both RJ45 ports are connected (upstream device and downstream target).
    • Ensure Ethernet link is active on both ports (link LEDs on both ports).
    • Switch to passive mode to eliminate host traffic injection.
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def find_plunder_bug_interface() -> str | None:
    """Find the Plunder Bug's interface by ASIX USB VID:PID or MAC OUI."""
    os_name = get_os()

    if os_name == "linux":
        # Look for ASIX device in ip link output with Plunder Bug OUI
        out = run_output("ip link show 2>/dev/null")
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if HAK5_OUI.lower().replace(":", "") in line.lower().replace(":", ""):
                m = re.match(r"^\d+:\s+(\w+):", line)
                if m:
                    return m.group(1)
        # Fallback: find ASIX interface by checking /sys
        import glob as glb
        for sysfs in glb.glob("/sys/bus/usb/drivers/asix/*/net/*/"):
            iface = Path(sysfs).name
            if iface:
                return iface

    elif os_name == "macos":
        out = run_output("networksetup -listallhardwareports 2>/dev/null")
        # Look for ASIX or AX88772 in the port list
        blocks = re.split(r"\n(?=Hardware Port)", out)
        for block in blocks:
            if "ASIX" in block.upper() or "AX88772" in block.upper():
                m = re.search(r"Device:\s+(\w+)", block)
                if m:
                    return m.group(1)
        # Also check by MAC OUI
        mac_out = run_output("ifconfig 2>/dev/null")
        for m_if, m_mac in re.findall(r"^(\w+):.*?\n.*?ether\s+([\da-f:]+)", mac_out, re.MULTILINE | re.DOTALL):
            if m_mac.lower().startswith(HAK5_OUI.lower()):
                return m_if

    elif os_name == "windows":
        out = run_output("netsh interface show interface 2>nul")
        for line in out.splitlines():
            if "asix" in line.lower() or "plunder" in line.lower():
                parts = line.split()
                if len(parts) >= 4:
                    return parts[-1]
    return None


def detect_plunder_bug() -> bool:
    """Detect Plunder Bug via USB VID:PID or interface presence."""
    if detect_usb_device(VID_ASIX, PID_772B):
        return True
    if find_plunder_bug_interface():
        return True
    return False


# ── Mode Switching ────────────────────────────────────────────────────────────

def switch_to_passive_mode(iface: str) -> bool:
    """
    Switch to passive mode (mute): disable host IP stack on tap interface.
    Prevents the host from transmitting on the tapped segment.
    """
    os_name = get_os()
    info(f"Switching {iface} to PASSIVE mode (mute)…")

    if os_name == "linux":
        info(f"Adding iptables OUTPUT DROP rule for {iface} — blocks host from sending on the tap segment…")
        r1 = sudo_run(f"iptables -A OUTPUT -o {iface} -j DROP 2>/dev/null")
        r2 = sudo_run(f"ip6tables -A OUTPUT -o {iface} -j DROP 2>/dev/null")
        # Also bring down the IP
        info(f"Flushing IP addresses on {iface} to prevent ARP/DHCP from exposing the host…")
        sudo_run(f"ip addr flush dev {iface} 2>/dev/null")
        ok("Passive mode active — host will not transmit on the tap interface.")
        return True

    elif os_name == "macos":
        # Disable IPv4 and IPv6 on the interface
        service = None
        out = run_output("networksetup -listallhardwareports")
        blocks = re.split(r"\n(?=Hardware Port)", out)
        for block in blocks:
            if iface in block:
                m = re.search(r"Hardware Port:\s+(.+)", block)
                if m:
                    service = m.group(1).strip()
                    break
        if service:
            info(f"Disabling IPv4 and IPv6 on '{service}' to silence the host on the tap segment…")
            sudo_run(f"networksetup -setv4off '{service}' 2>/dev/null")
            sudo_run(f"networksetup -setv6off '{service}' 2>/dev/null")
            ok("Passive mode active (IPv4 and IPv6 disabled on tap interface).")
        else:
            warn(f"Could not find Network service for {iface}.")
            warn("Manually: System Settings → Network → select interface → IPv4: Off, IPv6: Off")
            return False
        return True

    else:
        print("""
  Windows — Switch to Passive Mode:
    1. Open ncpa.cpl (Network Connections)
    2. Right-click the Plunder Bug / ASIX AX88772C adapter
    3. Select Properties
    4. Uncheck:  Internet Protocol Version 4 (TCP/IPv4)
                 Internet Protocol Version 6 (TCP/IPv6)
    5. Click OK

  Or run: plunderbug.ps1 mute  (download from the Plunder Bug download page)
        """)
        pause("Switch to passive mode, then press ENTER…")
        return True


def switch_to_active_mode(iface: str) -> bool:
    """
    Switch to active mode (unmute): re-enable host IP stack on tap interface.
    """
    os_name = get_os()
    info(f"Switching {iface} to ACTIVE mode (unmute)…")

    if os_name == "linux":
        info(f"Removing iptables DROP rule for {iface} — host will resume transmitting on the tap segment…")
        sudo_run(f"iptables -D OUTPUT -o {iface} -j DROP 2>/dev/null")
        sudo_run(f"ip6tables -D OUTPUT -o {iface} -j DROP 2>/dev/null")
        info(f"Requesting DHCP lease on {iface}…")
        sudo_run(f"dhclient {iface} 2>/dev/null &")
        ok("Active mode restored.")
        return True

    elif os_name == "macos":
        service = None
        out = run_output("networksetup -listallhardwareports")
        blocks = re.split(r"\n(?=Hardware Port)", out)
        for block in blocks:
            if iface in block:
                m = re.search(r"Hardware Port:\s+(.+)", block)
                if m:
                    service = m.group(1).strip()
                    break
        if service:
            info(f"Re-enabling DHCP on '{service}'…")
            sudo_run(f"networksetup -setdhcp '{service}' 2>/dev/null")
            sudo_run(f"networksetup -setv6automatic '{service}' 2>/dev/null")
            ok("Active mode restored (DHCP re-enabled).")
        else:
            warn(f"Could not find Network service for {iface}. Re-enable IPv4/IPv6 manually.")
            return False
        return True

    else:
        print("""
  Windows — Restore Active Mode:
    1. Open ncpa.cpl
    2. Right-click the Plunder Bug adapter
    3. Re-check TCP/IPv4 and TCP/IPv6
    4. Click OK

  Or run: plunderbug.ps1 unmute
        """)
        pause("Restore active mode, then press ENTER…")
        return True


# ── Packet Capture ────────────────────────────────────────────────────────────

def start_packet_capture(iface: str) -> bool:
    """Set up packet capture on the Plunder Bug interface."""
    heading("Packet Capture Setup")

    print(f"""
  The Plunder Bug mirrors all traffic from both RJ45 ports to interface: {iface}

  Ensure:
    • Port 1 (near LED): connected to upstream device (router/switch)
    • Port 2 (far from LED): connected to downstream target device

  Capture tools:
    A) tcpdump (command line)
    B) Open Wireshark with the correct interface
    C) Show interface name only (for use with other tools)
    """)

    cap_method = numbered_menu("Capture method:", [
        "tcpdump (saves to .pcap file)",
        "Open Wireshark",
        "Show interface name and exit",
        "Skip",
    ])

    if cap_method == 0:
        output_file = prompt("Output .pcap file path", f"/tmp/plunderbug_{int(time.time())}.pcap")
        filter_expr = prompt("tcpdump filter expression (leave blank for all traffic)", "")
        os_name = get_os()

        if os_name in ("linux", "macos"):
            tcpdump_args = ["tcpdump", "-i", iface, "-w", output_file]
            if filter_expr:
                tcpdump_args.append(filter_expr)
            info(f"Starting tcpdump on {iface} → {output_file}")
            info("tcpdump requires root — using sudo. Press Ctrl+C to stop capture.")
            info("If the capture file is empty: verify both RJ45 ports are plugged in and link LEDs are lit.")
            print(f"\n  Running: sudo {' '.join(tcpdump_args)}")
            print("  Press Ctrl+C to stop capture.\n")
            try:
                run_streaming_sudo(
                    tcpdump_args,
                    on_line=lambda l: print(f"  {l}"),
                    timeout=86400,
                )
            except KeyboardInterrupt:
                pass
            p = Path(output_file)
            if p.exists() and p.stat().st_size > 0:
                ok(f"Capture saved to: {output_file}")
            else:
                warn("Capture file is empty or not created.")
                warn("Troubleshooting: ensure interface is in promiscuous mode and both RJ45 ports have link.")
                warn(f"Manual retry: sudo tcpdump -i {iface} -w {output_file}")
        else:
            print(f"  Command: tcpdump -i {iface} -w {output_file}")
            print("  (Run this in a terminal as Administrator)")

    elif cap_method == 1:
        os_name = get_os()
        if os_name == "macos":
            run(f"open -a Wireshark 2>/dev/null || open -a 'Wireshark.app' 2>/dev/null")
        elif os_name == "linux":
            run(f"wireshark -i {iface} 2>/dev/null &")
        print(f"  Select interface: {iface}  (ASIX AX88772C USB Ethernet)")
        info("Wireshark launched (or try manually if it didn't open).")

    elif cap_method == 2:
        print(f"\n  Plunder Bug interface name: {iface}")
        print(f"  Use this with tcpdump, Wireshark, tshark, etc.")

    return True


# ── Physical Connection Guide ─────────────────────────────────────────────────

def print_connection_guide():
    print("""
  Physical connection:

  [Upstream Device / Router / Switch]
            │ RJ45
            ▼
  ┌─────────────────┐
  │  Port 1 (near   │
  │  green LED)     │◄──── connect to upstream (router/LAN)
  │                 │
  │  PLUNDER BUG    │◄──── USB-C to this computer (tap)
  │                 │
  │  Port 2 (far    │
  │  from LED)      │◄──── connect to target device
  └─────────────────┘
            │ RJ45
            ▼
  [Target Device / Host being monitored]

  LED indicators:
    Green LED ON  = powered via USB-C
    Link LEDs     = Ethernet link active on each RJ45 port
    """)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking required apt packages (python3-requests, python3-scapy)…")
        ensure_apt_packages(["python3-requests", "python3-scapy"])

    print_banner(TOOL_NAME, DESCRIPTION)
    print(FIRMWARE_NOTE)

    heading("Step 1 — Connect the Device")
    print_connection_guide()
    print("""
  Connect the Plunder Bug via USB-C cable to this computer.
  Both RJ45 ports should have Ethernet cables for traffic to be mirrored.

  Expected LED states:
    ● Solid GREEN          — USB-C connected to host computer, device powered ✓
    ● Solid AMBER/YELLOW   — Ethernet link active on one or both RJ45 ports ✓
    ● GREEN + AMBER        — USB powered AND Ethernet link up — capturing traffic ✓
    ● No LED               — Not powered; check USB-C cable and port

  RJ45 link LEDs (small LEDs near each port):
    ● Green link LED on    — Port has active Ethernet connection
    ● Blinking link LED    — Traffic flowing through that port
    ● No link LED          — Cable unplugged or no link negotiated

  NOTE: The Plunder Bug has no "boot sequence" — it powers on instantly.
  If no LED, try a different USB-C cable (some cables are charge-only, not data).
    """)
    pause("Press ENTER once the Plunder Bug is connected via USB-C…")

    # Steps 2-6
    detected = detection_loop(
        detect_fn=detect_plunder_bug,
        mode_instructions=MODE_INSTRUCTIONS,
        reset_instructions=RESET_INSTRUCTIONS,
    )
    if not detected:
        sys.exit(1)

    # Step 4 — Find interface
    heading("Step 4 — Interface Identification")

    os_name = get_os()

    # On Linux: ensure ASIX kernel module is loaded before looking for interface
    if os_name == "linux":
        if check_kernel_module("asix"):
            info("ASIX kernel module loaded.")
        else:
            warn("ASIX kernel module not loaded. Attempting to load…")
            if not load_kernel_module("asix"):
                warn("Could not load 'asix' module. Try: sudo modprobe ax88179_178a")
                load_kernel_module("ax88179_178a")
            time.sleep(2)

    info("Searching for Plunder Bug interface by ASIX VID:PID and MAC OUI…")
    info("On Kali/Linux the asix kernel module must be loaded — this is checked automatically.")
    iface = find_plunder_bug_interface()
    if iface:
        ok(f"Plunder Bug detected on interface: {iface}")
    else:
        warn("Could not automatically identify the interface.")
        if os_name == "linux":
            warn("Check 'ip link show' output for a new interface after plugging in.")
            warn("Expected: ASIX USB Ethernet (asix or ax88179_178a module).")
            warn("If the interface is missing entirely, try: sudo modprobe asix")
            warn("Then unplug and replug the USB-C cable.")
        elif os_name == "macos":
            warn(f"Check System Settings → Network for a new interface.")
            warn(f"If missing, download ASIX driver from: {ASIX_DRIVER_URL}")
        iface = prompt("Enter the interface name for the Plunder Bug (e.g. eth1, usb0, en3)")
        if not iface:
            err("Interface name required.")
            sys.exit(1)

    # Confirm ASIX MAC
    if os_name in ("linux", "macos"):
        mac_out = run_output(f"ip link show {iface} 2>/dev/null || ifconfig {iface} 2>/dev/null")
        oui_found = HAK5_OUI.lower() in mac_out.lower()
        if oui_found:
            ok(f"Plunder Bug MAC OUI ({HAK5_OUI}) confirmed on {iface}.")
        else:
            info(f"MAC OUI not confirmed as Plunder Bug OUI — ensure {iface} is the correct interface.")

    check_firmware_version()

    # Check both RJ45 ports have Ethernet link
    if os_name in ("linux", "macos"):
        link_up = check_interface_link(iface)
        if link_up:
            ok(f"Interface {iface}: Ethernet link active.")
        else:
            warn(f"Interface {iface}: No carrier detected.")
            warn("Both RJ45 ports must be connected for traffic to be mirrored.")
            warn("Verify: Port 1 (near LED) → upstream device, Port 2 → target device.")

    # Steps 5-6 — Not applicable
    # Step 7 — Internet sharing — N/A (pure tap, no management interface)
    heading("Steps 7-8 — Not Applicable")
    info("The Plunder Bug has no firmware to update and requires no internet sharing.")
    info("It is a hardware-only device with no OS or SSH.")

    # Step 9 — "Payload" is capture + mode selection
    heading("Steps 9-10 — Mode Configuration & Capture")

    current_mode = numbered_menu("Select operating mode:", [
        "Passive (RECOMMENDED — host is silent, pure sniffing only)",
        "Active (host participates in the network, may cause detection)",
    ])

    passive_enabled = False
    if current_mode == 0:
        passive_enabled = switch_to_passive_mode(iface)
        if passive_enabled:
            info("In passive mode the host computer does NOT transmit on the tapped segment.")
            info("This minimises the risk of detection.")
            # Enable promiscuous mode so the host sees ALL traffic (not just its MAC)
            set_interface_promisc(iface, enable=True)
    else:
        ok("Active mode: host can communicate on both segments.")
        info("WARNING: Active mode may expose the tap to detection.")

    # Capture
    if confirm("\nStart packet capture now?"):
        start_packet_capture(iface)

    # Step 11 — Cleanup
    heading("Step 11 — Cleanup")
    if passive_enabled and confirm("Restore active mode (re-enable IP on interface)?"):
        set_interface_promisc(iface, enable=False)
        switch_to_active_mode(iface)

    ok("Plunder Bug session complete.")
    print(f"""
  Deployment summary:
    Interface: {iface}  (ASIX AX88772C USB Ethernet)
    Mode:      {'Passive (silent)' if passive_enabled else 'Active'}

  For ongoing capture:
    sudo tcpdump -i {iface} -w capture.pcap
    wireshark  →  select {iface}

  To switch modes later:
    Passive:  sudo iptables -A OUTPUT -o {iface} -j DROP
    Active:   sudo iptables -D OUTPUT -o {iface} -j DROP
    """)


if __name__ == "__main__":
    main()
