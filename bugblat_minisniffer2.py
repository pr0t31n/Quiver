#!/usr/bin/env python3
"""
BugBlat MiniSniffer 2 USB Protocol Analyzer Manager
Manages the BugBlat MiniSniffer 2 USB traffic analyzer.
Supports Wireshark capture setup, usbmon configuration, and capture guidance.

Usage:
    python3 bugblat_minisniffer2.py

BugBlat MiniSniffer 2 is a USB 2.0 protocol analyzer from BugBlat (UK vendor).
It sits INLINE between your analysis computer and the target USB device.

Physical setup:
    [Analysis computer] ←USB→ [MiniSniffer 2] ←USB→ [Target USB device]
    (Host port)                (TWO USB ports)        (Device port)

NOTE: VID:PID values for BugBlat MiniSniffer 2 should be verified with the
vendor or device manager. The values 16D0:05B4 are estimates based on similar
products. If detection fails, connect the device and run:
  lsusb            (Linux)
  system_profiler SPUSBDataType  (macOS)
to find the actual VID:PID.

Linux USB capture:
    sudo modprobe usbmon
    Wireshark → capture on usbmonN interface
    Or: tcpdump -i usbmon1 -w capture.pcap

macOS USB capture:
    Wireshark with USBPcap support
    Or BugBlat USB Explorer proprietary software

BugBlat website: https://www.bugblat.com/
"""

import sys
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, ensure_pip_packages, ensure_system_tool,
    require_sudo, sudo_run, sudo_output,
    ensure_apt_packages, ensure_brew_packages,
    web_detect_loop, run_streaming,
    find_mounted_drive,
    detect_usb_libusb_any,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "BugBlat MiniSniffer 2"
DESCRIPTION = "USB 2.0 protocol analyzer — inline capture between host and target device"

# NOTE: VID:PID values for BugBlat MiniSniffer 2 should be verified with the
# vendor or device manager. The values 16D0:05B4 are estimates based on similar
# products from the MCS vendor IDs (16D0 = MCS). If detection fails, connect
# the device and run: lsusb (Linux) or system_profiler SPUSBDataType (macOS)
# to find the actual VID:PID. Contact BugBlat at https://www.bugblat.com/ for
# confirmed VID:PID values.
VID_PIDS = [
    (0x16D0, 0x05B4),  # BugBlat MiniSniffer 2 (verify with vendor)
    (0x16D0, 0x0753),  # BugBlat alternative (verify with vendor)
]

BUGBLAT_URL  = "https://www.bugblat.com/"
BUGBLAT_SW   = "https://www.bugblat.com/products/minisniffer/"

CONNECT_INSTRUCTIONS = (
    "BugBlat MiniSniffer 2 not detected.\n\n"
    "  Connect BugBlat MiniSniffer 2. It has TWO USB ports:\n"
    "    HOST port   — connects to YOUR analysis computer\n"
    "    DEVICE port — connects to the TARGET USB device being analyzed\n\n"
    "  VID:PID 16D0:05B4 (primary estimate — verify with vendor/device manager)\n"
    "  VID:PID 16D0:0753 (alternative estimate)\n\n"
    "  IMPORTANT: VID:PID values are estimates. If detection fails:\n"
    "    Linux: lsusb (look for BugBlat or 16D0 vendor)\n"
    "    macOS: system_profiler SPUSBDataType | grep -A5 -i bugblat\n\n"
    "  The device should appear as a USB analyzer device when connected\n"
    "  to your analysis computer's HOST port.\n\n"
    "  Troubleshooting:\n"
    "    Linux: dmesg | tail -20 (check USB enumeration)\n"
    "    Linux: lsusb -v | grep -A5 '16d0'\n"
    "    macOS: ioreg -p IOUSB -l | grep -i bugblat\n"
    "    Permission: sudo usermod -aG plugdev $USER (then log out/in)"
)

UDEV_RULES_CONTENT = (
    '# BugBlat MiniSniffer 2 udev rules\n'
    '# NOTE: VID:PID values are estimates — verify with vendor\n'
    '# BugBlat MiniSniffer 2 primary VID:PID 16D0:05B4\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="16d0", ATTRS{idProduct}=="05b4", '
    'MODE="0666", GROUP="plugdev"\n'
    '# BugBlat alternative VID:PID 16D0:0753\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="16d0", ATTRS{idProduct}=="0753", '
    'MODE="0666", GROUP="plugdev"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-bugblat-minisniffer2.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    """Detect BugBlat MiniSniffer 2 via USB VID:PID using libusb."""
    info("Scanning USB bus for BugBlat MiniSniffer 2 VID:PIDs via libusb…")
    info("  Checking 16D0:05B4 (primary estimate) and 16D0:0753 (alternative)…")
    info("  NOTE: VID:PID values are estimates. Verify with vendor if detection fails.")
    return detect_usb_libusb_any(VID_PIDS)


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for BugBlat on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("Skipping udev rule check (not Linux).")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("udev rules not found — installing BugBlat MiniSniffer 2 rules…")
    info(f"  Target: {UDEV_RULES_PATH}")
    info("  Enables non-root USB access to BugBlat analyzer (VID 16D0).")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the MiniSniffer 2 to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("  Add rules for VID 16d0, products 05b4 and 0753")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    """Show lsusb output and USB vendor/product info for BugBlat MiniSniffer 2."""
    heading("Device Info")
    info("BugBlat MiniSniffer 2 USB Protocol Analyzer")
    info("")
    info("IMPORTANT NOTE: VID:PID values may need verification.")
    info("  The values 16D0:05B4 and 16D0:0753 are estimates based on MCS vendor IDs.")
    info("  If device detection fails, find the actual VID:PID using the commands below.")
    info("")
    info("Hardware overview:")
    info("  - Inline USB 2.0 analyzer (full-speed and high-speed capable)")
    info("  - TWO USB ports: one HOST-side, one DEVICE-side")
    info("  - Captures all USB traffic passing between host and target device")
    info("  - Compatible with Wireshark via usbmon (Linux) and pcap export")
    info("  - BugBlat USB Explorer proprietary software for Windows")
    info("")

    os_flavor = get_os_flavor()
    if os_flavor == "macos":
        info("Running: system_profiler SPUSBDataType (full USB device tree)…")
        try:
            out = run_output("system_profiler SPUSBDataType 2>/dev/null")
            if out:
                found_bugblat = False
                for line in out.splitlines():
                    if any(vp in line.lower() for vp in ["16d0", "bugblat", "minisniffer"]):
                        ok(f"  [MATCH] {line}")
                        found_bugblat = True
                    else:
                        info(f"  {line}")
                if not found_bugblat:
                    warn("No BugBlat device found in USB device tree.")
                    info("  If MiniSniffer 2 is connected, its VID:PID may differ from expected.")
                    info("  Search the output above for any unrecognized USB devices.")
            else:
                warn("No output from system_profiler.")
        except Exception as e:
            err(f"system_profiler failed: {e}")
        info("")
        info("Additional macOS USB diagnostics:")
        info("  ioreg -p IOUSB -l | grep -A10 '16d0'")
        info("  Or use the 'System Information' app → USB section")
    else:
        # Linux
        info("Running: lsusb (all connected USB devices)…")
        try:
            out = run_output("lsusb 2>/dev/null")
            if out:
                found_bugblat = False
                for line in out.splitlines():
                    line_lower = line.lower()
                    if any(vp in line_lower for vp in ["16d0:05b4", "16d0:0753", "bugblat"]):
                        ok(f"  [MATCH] {line}")
                        found_bugblat = True
                    else:
                        info(f"  {line}")
                if not found_bugblat:
                    warn("No BugBlat VID:PID match found in lsusb output.")
                    info("  If MiniSniffer 2 is connected, scan for vendor 16d0:")
                    out2 = run_output("lsusb 2>/dev/null | grep -i '16d0'")
                    if out2:
                        info("  Devices with VID 16D0 (MCS):")
                        for line in out2.splitlines():
                            info(f"    {line}")
                    else:
                        info("  No devices with VID 16D0 found.")
                        info("  MiniSniffer 2 may use a different VID:PID than estimated.")
                        info("  Contact BugBlat: https://www.bugblat.com/")
            else:
                warn("No lsusb output. Install: sudo apt install usbutils")
        except Exception as e:
            err(f"lsusb failed: {e}")
            info("Install usbutils: sudo apt install usbutils")

        info("")
        info("Running verbose lsusb for any 16D0 vendor devices…")
        try:
            out = run_output("lsusb -v 2>/dev/null | grep -A20 '16d0'")
            if out:
                info("  Verbose USB info for VID 16D0:")
                for line in out.splitlines():
                    info(f"    {line}")
            else:
                info("  No verbose info for VID 16D0.")
        except Exception as e:
            info(f"  (Verbose lsusb failed: {e})")

        info("")
        info("Checking dmesg for USB analyzer attachment events…")
        try:
            dmesg_out = run_output("dmesg 2>/dev/null | grep -iE '16d0|bugblat|minisniffer|usb.*analyzer' | tail -20")
            if dmesg_out:
                info("  Recent USB events related to BugBlat:")
                for line in dmesg_out.splitlines():
                    info(f"    {line}")
            else:
                info("  No BugBlat-related entries in dmesg.")
        except Exception as e:
            info(f"  (dmesg check failed: {e})")

    info("")
    info("Physical inline setup reminder:")
    info("  The MiniSniffer 2 has TWO USB connectors:")
    info("    PORT A (HOST side)   → connect to this analysis computer")
    info("    PORT B (DEVICE side) → connect to the USB device being analyzed")
    info("  All USB traffic between the two sides is captured transparently.")
    ok("Device info complete.")


def op_setup_wireshark_capture():
    """Guide user through setting up Wireshark USB capture."""
    heading("Setup Wireshark USB Capture")
    info("Wireshark can capture USB traffic from the BugBlat MiniSniffer 2.")
    info("")

    os_flavor = get_os_flavor()

    if os_flavor == "macos":
        info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        info("WIRESHARK USB CAPTURE — macOS")
        info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        info("")
        info("Step 1: Install Wireshark (if not already installed)")
        info("  brew install --cask wireshark")
        info("  OR: download from https://www.wireshark.org/download.html")
        info("  NOTE: macOS build includes ChmodBPF for USB capture permissions")
        info("")
        info("Step 2: Check Wireshark installation")
        ws_path = run_output("which wireshark 2>/dev/null")
        if ws_path:
            ok(f"  Wireshark found: {ws_path.strip()}")
        else:
            warn("  Wireshark not found in PATH.")
            info("  Attempting install: brew install --cask wireshark")
            ensure_brew_packages(["--cask wireshark"])

        info("")
        info("Step 3: USB capture interfaces on macOS")
        info("  macOS exposes USB capture via XPC/kernel extension in Wireshark")
        info("  Available USB interfaces appear as 'USB' in Wireshark capture list")
        info("  If no USB interface appears, ensure Wireshark is up to date")
        info("")
        info("Step 4: Start capture")
        info("  a. Connect MiniSniffer 2 HOST port to this computer")
        info("  b. Connect target USB device to MiniSniffer 2 DEVICE port")
        info("  c. Open Wireshark")
        info("  d. Select the USB capture interface")
        info("  e. Click the blue shark-fin 'Start' button")
        info("")
        info("Step 5: Filter USB traffic (display filters)")
        info("  usb                         — show all USB packets")
        info("  usb.device_address == 3     — filter by device address")
        info("  usb.transfer_type == 0x01   — isochronous transfers")
        info("  usb.transfer_type == 0x02   — control transfers")
        info("  usb.transfer_type == 0x03   — bulk transfers")
        info("  usb.transfer_type == 0x00   — interrupt transfers (HID keyboard/mouse)")
        info("")
        info("Alternative: Use BugBlat's proprietary USB Explorer software")
        info(f"  Download: {BUGBLAT_SW}")

    else:
        # Linux
        info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        info("WIRESHARK USB CAPTURE — Linux")
        info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        info("")
        info("Step 1: Install Wireshark")
        info("  sudo apt-get install wireshark")
        info("  During install: select 'Yes' to allow non-root users to capture packets")
        info("  If already installed but can't capture: sudo dpkg-reconfigure wireshark-common")
        info("")
        info("Checking for Wireshark installation…")
        ws_path = run_output("which wireshark 2>/dev/null")
        if ws_path:
            ok(f"  Wireshark found: {ws_path.strip()}")
            ws_ver = run_output("wireshark --version 2>/dev/null | head -1")
            if ws_ver:
                info(f"  Version: {ws_ver.strip()}")
        else:
            warn("  Wireshark not found.")
            info("  Installing: sudo apt-get install wireshark")
            ensure_apt_packages(["wireshark"])

        info("")
        info("Step 2: Load usbmon kernel module (required for USB capture)")
        info("  sudo modprobe usbmon")
        info("")
        info("Checking usbmon module status…")
        mod_out = run_output("lsmod 2>/dev/null | grep usbmon")
        if mod_out:
            ok("  usbmon module is loaded.")
        else:
            warn("  usbmon module not loaded.")
            info("  Attempting: sudo modprobe usbmon")
            r = sudo_run("modprobe usbmon")
            if r.returncode == 0:
                ok("  usbmon module loaded successfully.")
            else:
                err("  Failed to load usbmon module.")
                info("  Try manually: sudo modprobe usbmon")
                info("  If that fails: check if USB monitoring is compiled into the kernel:")
                info("    cat /boot/config-$(uname -r) | grep CONFIG_USB_MON")

        info("")
        info("Step 3: Find USB bus number for target device")
        info("  Connect the BugBlat MiniSniffer 2 and target device")
        info("  Run: lsusb (note the Bus number, e.g. 'Bus 001')")
        info("  The usbmon interface is: usbmon<BUS_NUMBER>  (e.g. usbmon1 for Bus 001)")
        info("")
        lsusb_out = run_output("lsusb 2>/dev/null")
        if lsusb_out:
            info("  Current USB devices:")
            for line in lsusb_out.splitlines():
                info(f"    {line}")
        info("")
        info("Step 4: Check available usbmon interfaces")
        try:
            usbmon_ifaces = run_output("ls /sys/kernel/debug/usb/usbmon 2>/dev/null")
            if usbmon_ifaces:
                ok("  usbmon interfaces available:")
                for iface in usbmon_ifaces.splitlines():
                    info(f"    {iface}")
            else:
                warn("  /sys/kernel/debug/usb/usbmon not found.")
                info("  Ensure usbmon is loaded: sudo modprobe usbmon")
                info("  Also ensure debugfs is mounted: mount | grep debugfs")
                info("  Mount debugfs if needed: sudo mount -t debugfs none /sys/kernel/debug")
        except Exception as e:
            info(f"  (usbmon check: {e})")

        info("")
        info("Step 5: Start Wireshark and select usbmon interface")
        info("  sudo wireshark   (with root for full USB access)")
        info("  OR without root: add user to wireshark group:")
        info("    sudo usermod -aG wireshark $USER")
        info("    newgrp wireshark")
        info("")
        info("Step 6: Capture filters")
        info("  In Wireshark select interface: usbmon1 (or usbmonN for your bus)")
        info("  Apply display filters:")
        info("    usb                         — all USB packets")
        info("    usb.device_address == X     — specific device on bus")
        info("    usb.transfer_type == 0x00   — interrupt transfers (HID)")
        info("    usb.transfer_type == 0x02   — control transfers")
        info("    usb.transfer_type == 0x03   — bulk transfers (mass storage)")
        info("")
        info("Step 7: Alternative tcpdump USB capture (no GUI needed)")
        info("  sudo tcpdump -i usbmon1 -w /tmp/usb_capture.pcap")
        info("  Then open the .pcap file in Wireshark for analysis.")

    ok("Wireshark USB capture setup guide complete.")


def op_setup_usbmon():
    """Linux usbmon kernel module setup and troubleshooting."""
    heading("Setup usbmon (Linux USB Monitor)")
    os_flavor = get_os_flavor()

    if os_flavor == "macos":
        info("usbmon is a Linux-specific USB monitoring module.")
        info("On macOS, USB capture is handled by Wireshark's built-in XPC/IOKit support.")
        info("See 'Setup Wireshark Capture' option for macOS-specific instructions.")
        ok("macOS usbmon setup not applicable.")
        return

    info("usbmon is the Linux kernel module for USB packet capture.")
    info("It exposes USB traffic as capture interfaces (usbmon0, usbmon1, etc.).")
    info("These interfaces can be read by Wireshark, tcpdump, or custom programs.")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("STEP 1: Load usbmon kernel module")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("Check current status…")
    mod_out = run_output("lsmod 2>/dev/null | grep usbmon")
    if mod_out:
        ok("usbmon module is already loaded:")
        for line in mod_out.splitlines():
            info(f"  {line}")
    else:
        warn("usbmon not loaded. Loading now…")
        r = sudo_run("modprobe usbmon")
        if r.returncode == 0:
            ok("usbmon module loaded successfully.")
        else:
            err("Failed to load usbmon.")
            info("Troubleshooting:")
            info("  Check kernel config: zcat /proc/config.gz | grep CONFIG_USB_MON")
            info("  Or: cat /boot/config-$(uname -r) | grep CONFIG_USB_MON")
            info("  CONFIG_USB_MON=m means it's a module (should load with modprobe)")
            info("  CONFIG_USB_MON=y means it's built-in (no module needed, just mount debugfs)")
            info("  If not present: kernel was compiled without USB monitoring support")
            info("  Solution: use a kernel with CONFIG_USB_MON enabled")
            return

    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("STEP 2: Mount debugfs (required for usbmon interface access)")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    debug_out = run_output("mount 2>/dev/null | grep debugfs")
    if debug_out:
        ok("debugfs is mounted:")
        for line in debug_out.splitlines():
            info(f"  {line}")
    else:
        warn("debugfs not mounted. Mounting now…")
        r = sudo_run("mount -t debugfs none /sys/kernel/debug")
        if r.returncode == 0:
            ok("debugfs mounted at /sys/kernel/debug")
        else:
            err("Failed to mount debugfs.")
            info("Try: sudo mount -t debugfs debugfs /sys/kernel/debug")
            info("To make persistent, add to /etc/fstab:")
            info("  debugfs  /sys/kernel/debug  debugfs  defaults  0  0")

    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("STEP 3: Verify usbmon interfaces are available")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    try:
        usbmon_path = Path("/sys/kernel/debug/usb/usbmon")
        if usbmon_path.exists():
            contents = run_output(f"ls {usbmon_path} 2>/dev/null")
            if contents:
                ok(f"usbmon interfaces found in {usbmon_path}:")
                for iface in contents.splitlines():
                    info(f"  {iface}")
            else:
                warn(f"{usbmon_path} is empty. usbmon may not be fully initialized.")
        else:
            warn(f"{usbmon_path} does not exist.")
            info("  Ensure usbmon is loaded and debugfs is mounted.")
    except Exception as e:
        info(f"  (usbmon interface check: {e})")

    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("STEP 4: Identify USB bus numbers (for correct usbmon interface)")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("USB buses are numbered; use 'lsusb' to find the bus your device is on.")
    info("The usbmon interface corresponds: Bus 001 → usbmon1, Bus 002 → usbmon2, etc.")
    info("usbmon0 captures all buses simultaneously (may be very noisy).")
    info("")
    out = run_output("lsusb 2>/dev/null")
    if out:
        info("Current USB devices (note Bus numbers):")
        for line in out.splitlines():
            line_lower = line.lower()
            if any(vp in line_lower for vp in ["16d0:05b4", "16d0:0753", "bugblat"]):
                ok(f"  [BUGBLAT] {line}")
            else:
                info(f"  {line}")
    else:
        warn("  lsusb output not available. Install: sudo apt install usbutils")

    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("STEP 5: Capture commands")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("Wireshark (GUI):")
    info("  sudo wireshark")
    info("  Select interface: usbmon1 (or appropriate bus number)")
    info("")
    info("tcpdump (CLI, saves to pcap):")
    info("  sudo tcpdump -i usbmon1 -w /tmp/usb_capture.pcap")
    info("  sudo tcpdump -i usbmon0 -w /tmp/usb_all_buses.pcap  (all buses)")
    info("")
    info("Read-only from usbmon files directly:")
    info("  sudo cat /sys/kernel/debug/usb/usbmon/1u  (text format, bus 1)")
    info("  sudo cat /sys/kernel/debug/usb/usbmon/1b  (binary format, bus 1)")
    info("")
    info("Make usbmon persistent across reboots:")
    info("  Add 'usbmon' to /etc/modules:")
    info("  echo 'usbmon' | sudo tee -a /etc/modules")

    ok("usbmon setup complete.")


def op_show_capture_guide():
    """Comprehensive guide for USB protocol analysis with BugBlat MiniSniffer 2."""
    heading("USB Protocol Analysis Capture Guide")
    info("Comprehensive guide for capturing and analyzing USB traffic with BugBlat MiniSniffer 2.")
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 1: Physical Setup (Critical — Read This First)")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("The BugBlat MiniSniffer 2 is an INLINE analyzer.")
    info("It must be placed BETWEEN the host computer and the target USB device.")
    info("")
    info("Physical connection diagram:")
    info("")
    info("  ┌─────────────────┐    USB    ┌──────────────────┐    USB    ┌─────────────────┐")
    info("  │   Your Analysis │◄─────────►│  BugBlat         │◄─────────►│  Target USB     │")
    info("  │   Computer      │  (HOST)   │  MiniSniffer 2   │  (DEVICE) │  Device Under   │")
    info("  │                 │   port    │                  │   port    │  Test (DUT)     │")
    info("  └─────────────────┘           └──────────────────┘           └─────────────────┘")
    info("")
    info("  PORT A (HOST side):   cable from MiniSniffer to YOUR analysis computer")
    info("  PORT B (DEVICE side): cable from MiniSniffer to the TARGET device being analyzed")
    info("")
    info("The MiniSniffer 2 is TRANSPARENT to the USB bus — the target device functions")
    info("normally while all USB traffic is captured by the analyzer.")
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 2: What Can Be Captured")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("USB transfer types (all visible in captured traffic):")
    info("  CONTROL   — device enumeration, configuration, feature requests")
    info("  BULK      — mass storage (USB drives, printers), large data transfers")
    info("  INTERRUPT — HID devices: keyboard, mouse, gamepad (small, frequent packets)")
    info("  ISOCHRONOUS — audio/video: USB webcams, microphones, USB audio devices")
    info("")
    info("Common use cases for USB traffic analysis:")
    info("  - Reverse engineering proprietary USB protocols")
    info("  - Debugging USB device driver issues")
    info("  - Security research: USB HID injection analysis")
    info("  - Analyzing USB firmware update protocols")
    info("  - BadUSB research and detection")
    info("  - USB bootloader protocol reverse engineering")
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 3: Wireshark USB Display Filters (Cheat Sheet)")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("Basic filters:")
    info("  usb                              — all USB packets")
    info("  usb.device_address == 3          — packets from/to device address 3")
    info("  usb.endpoint_address == 0x81     — endpoint 1, IN direction")
    info("  usb.endpoint_address.direction == 1  — all IN (device→host) transfers")
    info("  usb.endpoint_address.direction == 0  — all OUT (host→device) transfers")
    info("")
    info("Transfer type filters:")
    info("  usb.transfer_type == 0x00        — isochronous")
    info("  usb.transfer_type == 0x01        — interrupt (HID)")
    info("  usb.transfer_type == 0x02        — control")
    info("  usb.transfer_type == 0x03        — bulk (mass storage)")
    info("")
    info("HID-specific filters:")
    info("  usb.transfer_type == 0x01        — all interrupt (keyboard/mouse data)")
    info("  usbhid                           — HID class traffic")
    info("  usbhid.data                      — HID report data field")
    info("")
    info("Finding device address:")
    info("  1. In Wireshark, look for 'GET DESCRIPTOR Response DEVICE' packets")
    info("  2. The USB address is shown in the source/destination fields")
    info("  3. Or: lsusb -v to find device addresses on the bus")
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 4: Interpreting USB HID Data (Keyboard/Mouse)")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("HID Keyboard report format (8 bytes):")
    info("  Byte 0: Modifier keys (bit flags: CTRL, SHIFT, ALT, GUI)")
    info("  Byte 1: Reserved (always 0)")
    info("  Bytes 2-7: Keycodes (up to 6 simultaneous keys, 0 = no key)")
    info("")
    info("Modifier key bits (Byte 0):")
    info("  0x01 = Left CTRL    0x10 = Right CTRL")
    info("  0x02 = Left SHIFT   0x20 = Right SHIFT")
    info("  0x04 = Left ALT     0x40 = Right ALT")
    info("  0x08 = Left GUI     0x80 = Right GUI (Windows key)")
    info("")
    info("To decode keystrokes from a pcap:")
    info("  tshark -r capture.pcap -Y 'usbhid.data' -T fields -e usbhid.data")
    info("  Then map keycode bytes to HID keycode table")
    info("  HID usage table: https://usb.org/sites/default/files/hut1_21.pdf")
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 5: Saving and Exporting Captures")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("Wireshark GUI: File → Save As → choose .pcapng format")
    info("tcpdump CLI:   sudo tcpdump -i usbmon1 -w capture.pcap")
    info("tshark CLI:    sudo tshark -i usbmon1 -w capture.pcap")
    info("")
    info("Reading saved captures:")
    info("  Wireshark: File → Open capture.pcap")
    info("  tshark:    tshark -r capture.pcap")
    info("  Python:    pip install scapy → from scapy.all import rdpcap")
    info("")
    info("BugBlat USB Explorer (Windows proprietary):")
    info(f"  Download: {BUGBLAT_SW}")
    info("  Provides BugBlat-specific decoding and visualization features")
    ok("Capture guide complete.")


def op_show_software_info():
    """Show info about BugBlat USB Explorer software and download."""
    heading("BugBlat Software Info")
    info("BugBlat is a small UK-based vendor specializing in USB protocol analyzers.")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("BUGBLAT USB EXPLORER — PROPRIETARY SOFTWARE")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("BugBlat USB Explorer is BugBlat's proprietary software for their analyzers.")
    info("  Website:   https://www.bugblat.com/")
    info(f"  Product:   {BUGBLAT_SW}")
    info("  Platform:  Windows (primary); check site for macOS/Linux support")
    info("")
    info("USB Explorer features:")
    info("  - Real-time USB traffic visualization")
    info("  - USB descriptor decoder (device, config, interface, endpoint)")
    info("  - Transaction-level display with timing information")
    info("  - Filtering by device address, endpoint, transfer type")
    info("  - Export to pcap for use with Wireshark")
    info("  - USB protocol decoding (HID, Mass Storage, CDC, etc.)")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("OPEN-SOURCE ALTERNATIVES")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("Wireshark (cross-platform, free):")
    info("  https://www.wireshark.org/")
    info("  - Supports usbmon (Linux) and USBPcap (Windows) for USB capture")
    info("  - Full USB protocol dissectors built-in")
    info("  - Scripting with Lua for custom dissectors")
    info("")
    info("USBPcap (Windows USB capture driver for Wireshark):")
    info("  https://desowin.org/usbpcap/")
    info("  - Windows kernel driver that captures USB traffic")
    info("  - Integrates with Wireshark automatically")
    info("")
    info("vusb-analyzer (Python-based USB traffic visualizer):")
    info("  https://github.com/aappleby/vusb-analyzer")
    info("  - Python tool for visualizing USB pcap files")
    info("")
    info("python-usb-monitor (for scripted USB event monitoring):")
    info("  pip install pyusb")
    info("  Allows USB device monitoring via Python/libusb")
    info("")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("VID:PID VERIFICATION")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("")
    info("The VID:PID values used in this script (16D0:05B4, 16D0:0753) are estimates.")
    info("To find the actual VID:PID of your MiniSniffer 2:")
    info("")
    info("  Linux:")
    info("    1. Connect MiniSniffer 2 (HOST port to this computer)")
    info("    2. Run: lsusb")
    info("    3. Look for a new entry (compare before/after connection)")
    info("    4. Note the 'ID XXXX:XXXX' value — that is the VID:PID")
    info("")
    info("  macOS:")
    info("    1. Connect MiniSniffer 2")
    info("    2. Run: system_profiler SPUSBDataType")
    info("    3. Find the entry for the new device")
    info("    4. Note 'Product ID' and 'Vendor ID' values")
    info("")
    info("  Windows:")
    info("    1. Connect MiniSniffer 2")
    info("    2. Open Device Manager")
    info("    3. Find the device, right-click → Properties → Details → Hardware IDs")
    info("    4. VID_XXXX&PID_XXXX shows the VID:PID")
    info("")
    info("  Once you have the correct VID:PID:")
    info("    - Update VID_PIDS list in this script")
    info("    - Update UDEV_RULES_CONTENT with correct values")
    info(f"    - Contact BugBlat to confirm: {BUGBLAT_URL}")
    ok("BugBlat software info complete.")


# ── Firmware Version Check ────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("BugBlat MiniSniffer 2 — Proprietary firmware.")
    info("  Firmware updates are managed via the BugBlat USB Explorer software.")
    info("  Download USB Explorer from: https://www.bugblat.com/products/minisniffer/")
    info("  The software will notify you if a firmware update is available.")
    info("")
    info("  To check current firmware version:")
    info("  Linux/macOS: lsusb -v -d 16D0: | grep bcdDevice")
    info("  This shows the USB device firmware revision number.")

    try:
        out = run_output("lsusb -v -d 16D0: 2>/dev/null | grep bcdDevice")
        if out:
            ok(f"  USB firmware revision: {out.strip()}")
    except Exception:
        pass

    info("")
    info("  No automatic update available for this proprietary device.")
    info("  Visit the BugBlat website to check for firmware updates manually.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    os_flavor = get_os_flavor()
    info(f"Detected OS: {os_flavor}")
    info("")
    info("IMPORTANT: BugBlat MiniSniffer 2 VID:PID values are estimates.")
    info("  If detection fails, run Device Info for diagnostic commands.")
    info("")

    # Install system tools
    info("Checking required tools…")
    if os_flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking apt packages: wireshark, usbutils…")
        info("  wireshark: USB packet capture and analysis GUI")
        info("  usbutils: lsusb command for USB device enumeration")
        ensure_apt_packages(["usbutils"])
        # wireshark optional but recommended
        ws_present = run_output("which wireshark 2>/dev/null")
        if not ws_present:
            if confirm("Install Wireshark for USB capture? (recommended)", default=True):
                ensure_apt_packages(["wireshark"])
    elif os_flavor == "macos":
        info("Checking for Wireshark on macOS…")
        ws_present = run_output("which wireshark 2>/dev/null")
        if not ws_present:
            if confirm("Install Wireshark via brew? (recommended)", default=True):
                ensure_brew_packages(["--cask wireshark"])

    # pip packages
    info("Checking Python packages: pyusb (for USB device enumeration)…")
    ensure_pip_packages([("usb", "pyusb")])

    # udev rules (Linux)
    if os_flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking udev rules for BugBlat MiniSniffer 2 (VID 16D0)…")
        _check_udev_rules()

    # usbmon setup hint (Linux)
    if os_flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking usbmon kernel module…")
        mod_out = run_output("lsmod 2>/dev/null | grep usbmon")
        if mod_out:
            ok("usbmon module is loaded — ready for USB capture.")
        else:
            warn("usbmon module not loaded.")
            info("  For USB capture with Wireshark, usbmon must be loaded.")
            info("  Load now: sudo modprobe usbmon")
            info("  Or use the 'Setup usbmon' menu option.")

    info("")
    info("Scanning for BugBlat MiniSniffer 2 via USB VID:PID…")
    info("  NOTE: VID:PID 16D0:05B4 and 16D0:0753 are estimates — verify with vendor.")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        warn("BugBlat MiniSniffer 2 not detected.")
        info("  If device is connected, its VID:PID may differ from expected values.")
        info("  Run 'Device Info' for diagnostic commands to find actual VID:PID.")
        if not confirm("Continue without detected device?", default=True):
            err("Exiting.")
            sys.exit(1)
    else:
        ok("BugBlat MiniSniffer 2 detected on USB bus.")

    check_firmware_version()

    MENU_OPTIONS = [
        "Device Info (lsusb / system_profiler)",
        "Setup Wireshark Capture",
        "Setup usbmon (Linux)",
        "Capture Guide (USB Protocol Analysis)",
        "BugBlat Software Info",
        "Exit",
    ]

    while True:
        choice = numbered_menu("BugBlat MiniSniffer 2 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_setup_wireshark_capture()
        elif choice == 2:
            op_setup_usbmon()
        elif choice == 3:
            op_show_capture_guide()
        elif choice == 4:
            op_show_software_info()
        elif choice == 5:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
