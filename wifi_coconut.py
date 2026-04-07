#!/usr/bin/env python3
"""
Wi-Fi Coconut Tool Manager
Handles detection, driver setup, and packet capture for the Wi-Fi Coconut
by Hak5 — a 14-radio 802.11 monitor-mode USB capture device.

Hardware:
  14 × Atheros AR9271 USB WiFi radios on an internal USB hub.
  Each radio enumerates as a separate USB device: VID:PID 0CF3:9271.
  On Linux, all 14 radios appear as wlan* interfaces when the ath9k_htc
  kernel module is loaded and the wifi_coconut driver is installed.

macOS support:
  NOT officially supported. The AR9271 chipset requires ath9k_htc which
  is not available on macOS. Linux (Kali recommended) is required.

Driver:
  https://github.com/hak5/wifi-coconut
  Build from source or use the DKMS package. The driver configures all
  14 radios and presents them as a unified capture interface.

Dependencies:
  aircrack-ng, wireshark/tshark, libpcap-dev, linux-headers

Usage:
    python3 wifi_coconut.py
"""

import os
import sys
import re
import time
import tempfile
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
    check_latest_github_release, announce_firmware_update,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Wi-Fi Coconut"
DESCRIPTION = "14-radio 802.11 monitor-mode USB capture device by Hak5"

# Each AR9271 chip on the internal USB hub shares this VID:PID
AR9271_VID = 0x0CF3
AR9271_PID = 0x9271
VID_PIDS   = [(AR9271_VID, AR9271_PID)]

# We expect exactly 14 radios for a Coconut; >=2 triggers Coconut detection
MIN_RADIO_COUNT = 2
EXPECTED_RADIO_COUNT = 14

GITHUB_OWNER = "hak5"
GITHUB_REPO  = "wifi-coconut"

CONNECT_INSTRUCTIONS = (
    "Wi-Fi Coconut not detected.\n\n"
    "  1. Connect the Wi-Fi Coconut to a USB 3.0 port (USB hub with >2A power).\n\n"
    "  2. Ensure the ath9k_htc kernel module is loaded:\n"
    "       sudo modprobe ath9k_htc\n\n"
    "  3. Verify USB enumeration:\n"
    "       lsusb | grep '0cf3:9271'\n"
    "       (should show 14 entries for a fully working Coconut)\n\n"
    "  4. Install the wifi_coconut driver if not already done (see menu).\n\n"
    "  5. NOTE: Wi-Fi Coconut is NOT supported on macOS.\n"
    "     Linux (Kali Linux recommended) is required.\n\n"
    "  6. Driver source: https://github.com/hak5/wifi-coconut\n"
    "  7. Ensure USB power budget: the Coconut draws ~2.5A @ 5V total."
)

UDEV_RULES_CONTENT = """\
# Wi-Fi Coconut (Atheros AR9271) udev rules
# Each of the 14 AR9271 radios shares VID:PID 0CF3:9271
SUBSYSTEM=="usb", ATTRS{idVendor}=="0cf3", ATTRS{idProduct}=="9271", MODE="0666", GROUP="plugdev"
KERNEL=="phy*", SUBSYSTEM=="ieee80211", ACTION=="add", RUN+="/usr/sbin/iw phy %k set monitor none"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-wifi-coconut.rules"


# ── Detection helpers ─────────────────────────────────────────────────────────

def _count_ar9271_usb_devices() -> int:
    """Return the number of 0CF3:9271 USB devices visible on the system."""
    try:
        out = run_output("lsusb 2>/dev/null")
        if not out:
            return 0
        return out.lower().count("0cf3:9271")
    except Exception:
        return 0


def _get_coconut_interfaces() -> list[str]:
    """
    Return a list of wlan* interface names that are associated with AR9271
    radios (ath9k_htc driver), or managed by the wifi_coconut driver.
    """
    interfaces = []
    try:
        out = run_output("iw dev 2>/dev/null")
        if not out:
            return interfaces
        for line in out.splitlines():
            m = re.match(r"\s+Interface\s+(wlan\d+)", line)
            if m:
                interfaces.append(m.group(1))
    except Exception:
        pass
    return interfaces


def _is_module_loaded(module: str) -> bool:
    try:
        out = run_output(f"lsmod 2>/dev/null | grep '^{module}'")
        return bool(out and out.strip())
    except Exception:
        return False


def detect_device() -> bool:
    """Return True if at least MIN_RADIO_COUNT AR9271 devices are detected."""
    return _count_ar9271_usb_devices() >= MIN_RADIO_COUNT


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    flavor = get_os_flavor()
    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Wi-Fi Coconut (AR9271) radios…")
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the Wi-Fi Coconut to apply new permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual fix: sudo tee {UDEV_RULES_PATH}")
        info(UDEV_RULES_CONTENT)
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Firmware / driver version check ──────────────────────────────────────────

def check_firmware_version(_unused=None):
    heading("Driver / Firmware Version Check")
    flavor = get_os_flavor()

    if flavor == "macos":
        err("Wi-Fi Coconut is NOT supported on macOS.")
        info("The AR9271 chipset requires the ath9k_htc Linux kernel module.")
        info("Use Kali Linux or another Debian-based distribution.")
        return

    # Check ath9k_htc kernel module
    if _is_module_loaded("ath9k_htc"):
        ok("ath9k_htc kernel module is loaded.")
    else:
        warn("ath9k_htc kernel module is NOT loaded.")
        info("Load it with: sudo modprobe ath9k_htc")

    # Check wifi_coconut kernel module / driver
    if _is_module_loaded("wifi_coconut"):
        ok("wifi_coconut driver module is loaded.")
    else:
        warn("wifi_coconut driver module is NOT loaded.")
        info("Install the driver via menu option 2 or build from source.")

    # Check radio count
    count = _count_ar9271_usb_devices()
    if count >= EXPECTED_RADIO_COUNT:
        ok(f"All {count} AR9271 radios detected via USB.")
    elif count >= MIN_RADIO_COUNT:
        warn(f"Only {count}/{EXPECTED_RADIO_COUNT} AR9271 radios detected.")
        info("Check USB power — the Coconut needs a high-current USB 3.0 port or powered hub.")
    else:
        err(f"No AR9271 radios detected (expected {EXPECTED_RADIO_COUNT}).")
        info("Check USB connection and kernel module status.")

    # Check GitHub for latest driver release
    info("Checking latest wifi-coconut release on GitHub…")
    latest_tag, release_url = check_latest_github_release(GITHUB_OWNER, GITHUB_REPO)
    if latest_tag:
        ok(f"Latest wifi-coconut release: {latest_tag}")
        info(f"Release URL: {release_url}")
    else:
        warn("Could not retrieve GitHub release info for wifi-coconut.")

    # Check interfaces
    ifaces = _get_coconut_interfaces()
    if ifaces:
        ok(f"Found {len(ifaces)} wlan interface(s): {', '.join(ifaces)}")
    else:
        warn("No wlan interfaces found. Driver may not be loaded or interfaces not up.")


# ── Operations ────────────────────────────────────────────────────────────────

def op_detect_and_driver_status():
    heading("Detect Device & Driver Status")
    flavor = get_os_flavor()

    if flavor == "macos":
        err("Wi-Fi Coconut is NOT supported on macOS.")
        info("Please use Kali Linux or a Debian-based Linux distribution.")
        return

    info("Checking USB bus for AR9271 radios…")
    try:
        count = _count_ar9271_usb_devices()
        if count >= EXPECTED_RADIO_COUNT:
            ok(f"Wi-Fi Coconut detected: {count} AR9271 radios on USB bus.")
        elif count >= MIN_RADIO_COUNT:
            warn(f"Partial detection: {count}/{EXPECTED_RADIO_COUNT} AR9271 radios found.")
            info("Some radios may be missing. Check USB power and cable.")
        elif count == 1:
            warn("Only 1 AR9271 radio found — this may be a standard USB WiFi adapter.")
            info("Wi-Fi Coconut should show 14 devices. Check USB connection.")
        else:
            err("No AR9271 radios detected.")
            info("Connect the Wi-Fi Coconut to a USB 3.0 port.")
            info("Verify: lsusb | grep '0cf3:9271'")
            return

        info("")
        info("Kernel module status:")
        for mod in ("ath9k", "ath9k_htc", "wifi_coconut"):
            loaded = _is_module_loaded(mod)
            if loaded:
                ok(f"  {mod}: loaded")
            else:
                warn(f"  {mod}: NOT loaded")

        info("")
        ifaces = _get_coconut_interfaces()
        if ifaces:
            ok(f"Active wlan interfaces ({len(ifaces)}):")
            for iface in ifaces:
                mode_out = run_output(f"iw dev {iface} info 2>/dev/null") or ""
                mode_m = re.search(r"type\s+(\S+)", mode_out)
                mode = mode_m.group(1) if mode_m else "unknown"
                info(f"  {iface}  (mode: {mode})")
        else:
            warn("No wlan interfaces found. Load the driver (option 2) first.")

    except Exception as e:
        err(f"Detection error: {e}")


def op_install_update_driver():
    heading("Install / Update wifi_coconut Driver")
    flavor = get_os_flavor()

    if flavor == "macos":
        err("Wi-Fi Coconut is NOT supported on macOS.")
        info("The driver requires Linux kernel headers and the ath9k_htc subsystem.")
        return

    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        warn(f"Detected OS flavor: '{flavor}'. Proceeding but apt packages may not apply.")

    info("Installing kernel build dependencies and support packages…")
    try:
        kernel_ver = run_output("uname -r 2>/dev/null") or "generic"
        kernel_ver = kernel_ver.strip()
        info(f"Kernel version: {kernel_ver}")
        ensure_apt_packages([
            "git", "build-essential", "dkms",
            f"linux-headers-{kernel_ver}",
            "libusb-1.0-0-dev",
        ])
    except Exception as e:
        warn(f"Package installation warning: {e}")
        info("Continuing — some packages may already be present.")

    info("")
    info("Loading ath9k_htc kernel module…")
    try:
        r = sudo_run("modprobe ath9k_htc 2>&1")
        if r.returncode == 0:
            ok("ath9k_htc module loaded.")
        else:
            warn("modprobe ath9k_htc returned non-zero. Module may already be built-in.")
    except Exception as e:
        warn(f"modprobe error: {e}")

    info("")
    info("Cloning wifi-coconut driver from GitHub…")
    clone_dir = Path(tempfile.mkdtemp(prefix="wifi_coconut_"))
    info(f"Build directory: {clone_dir}")

    try:
        rc = run_streaming(
            ["git", "clone", "--depth=1",
             f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}.git",
             str(clone_dir)],
            on_line=lambda l: info(f"  git: {l}"),
            timeout=120,
        )
        if rc != 0:
            err("git clone failed. Check internet connection.")
            info(f"Manual: git clone https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}")
            return
        ok("Repository cloned.")
    except Exception as e:
        err(f"Clone error: {e}")
        return

    info("")
    info("Building driver from source…")
    info("This may take a few minutes on slower systems.")
    try:
        rc = run_streaming(
            ["make", "-C", str(clone_dir)],
            on_line=lambda l: info(f"  make: {l}"),
            timeout=300,
        )
        if rc != 0:
            err("Build failed. Check kernel headers and build-essential packages.")
            info(f"Build directory left at: {clone_dir}")
            info("Manual build: cd {clone_dir} && make && sudo make install")
            return
        ok("Driver built successfully.")
    except Exception as e:
        err(f"Build error: {e}")
        return

    info("")
    info("Installing driver (sudo make install)…")
    try:
        r = sudo_run(f"make -C {clone_dir} install 2>&1")
        if r.returncode == 0:
            ok("Driver installed.")
            info("Load it now: sudo modprobe wifi_coconut")
            r2 = sudo_run("modprobe wifi_coconut 2>&1")
            if r2.returncode == 0:
                ok("wifi_coconut module loaded.")
            else:
                warn("Could not auto-load wifi_coconut — try: sudo modprobe wifi_coconut")
        else:
            err("Driver install failed.")
            info(f"Check output above. Build dir: {clone_dir}")
    except Exception as e:
        err(f"Install error: {e}")

    info("")
    info("DKMS registration (for persistent driver across kernel updates):")
    info("  sudo dkms add {clone_dir}")
    info("  sudo dkms install wifi-coconut/<version>")
    info("Refer to https://github.com/hak5/wifi-coconut for DKMS instructions.")


def op_start_capture():
    heading("Start Packet Capture")
    flavor = get_os_flavor()
    if flavor == "macos":
        err("Capture is not supported on macOS. Use Linux.")
        return

    ifaces = _get_coconut_interfaces()
    if not ifaces:
        err("No wlan interfaces found. Ensure the driver is loaded and device is connected.")
        info("Run option 1 to check device/driver status, option 2 to install driver.")
        return

    info(f"Available interfaces: {', '.join(ifaces)}")
    iface = prompt(f"Interface to capture on (default: {ifaces[0]})", default=ifaces[0])
    if iface not in ifaces:
        warn(f"Interface '{iface}' not in detected list. Proceeding anyway.")

    channel = prompt("Channel to monitor (1-14, or 'all' for hopping, default: 6)", default="6")
    outfile = prompt("Output pcap file path (default: /tmp/coconut_capture.pcap)",
                     default="/tmp/coconut_capture.pcap")

    info(f"Setting {iface} to monitor mode…")
    try:
        r = sudo_run(f"ip link set {iface} down 2>/dev/null")
        r = sudo_run(f"iw dev {iface} set type monitor 2>/dev/null")
        r = sudo_run(f"ip link set {iface} up 2>/dev/null")
        if channel.lower() != "all":
            sudo_run(f"iw dev {iface} set channel {channel} 2>/dev/null")
            ok(f"Set {iface} to monitor mode on channel {channel}.")
        else:
            ok(f"Set {iface} to monitor mode (channel hopping handled by tcpdump).")
    except Exception as e:
        warn(f"Monitor mode setup error: {e}")

    info(f"Starting tcpdump capture to {outfile}…")
    info("Press Ctrl+C to stop capture.")
    try:
        cmd = ["sudo", "tcpdump", "-i", iface, "-w", outfile, "-v"]
        rc = run_streaming(cmd, on_line=lambda l: info(f"  tcpdump: {l}"), timeout=3600)
        if rc == 0:
            ok(f"Capture saved to {outfile}")
        else:
            info(f"Capture ended (exit code {rc}). File: {outfile}")
    except KeyboardInterrupt:
        ok(f"Capture stopped. Output: {outfile}")
    except Exception as e:
        err(f"Capture error: {e}")
        info("Manual: sudo tcpdump -i {iface} -w {outfile}")


def op_channel_hopping_capture():
    heading("Channel Hopping Capture (All Channels)")
    flavor = get_os_flavor()
    if flavor == "macos":
        err("Channel hopping capture is not supported on macOS.")
        return

    ifaces = _get_coconut_interfaces()
    if not ifaces:
        err("No wlan interfaces found.")
        return

    info(f"Available interfaces: {', '.join(ifaces)}")
    info("Channel hopping assigns different channels to different radios simultaneously.")
    info("With 14 radios, channels 1-14 can all be monitored concurrently.")
    info("")

    outdir = prompt("Output directory for pcap files (default: /tmp/coconut_hop)",
                    default="/tmp/coconut_hop")
    Path(outdir).mkdir(parents=True, exist_ok=True)

    channels = list(range(1, min(len(ifaces), 14) + 1))
    info(f"Assigning {len(channels)} channels across {len(ifaces)} interface(s)…")

    try:
        for i, ch in enumerate(channels):
            if i >= len(ifaces):
                break
            iface = ifaces[i]
            sudo_run(f"ip link set {iface} down 2>/dev/null")
            sudo_run(f"iw dev {iface} set type monitor 2>/dev/null")
            sudo_run(f"iw dev {iface} set channel {ch} 2>/dev/null")
            sudo_run(f"ip link set {iface} up 2>/dev/null")
            ok(f"  {iface} → channel {ch}")
    except Exception as e:
        warn(f"Interface setup error: {e}")

    info("")
    info("Starting parallel tcpdump captures on all interfaces…")
    info("Output files: {outdir}/capture_chXX.pcap")
    info("Press Ctrl+C to stop all captures.")

    import subprocess as _sp
    procs = []
    try:
        for i, ch in enumerate(channels):
            if i >= len(ifaces):
                break
            iface = ifaces[i]
            outfile = f"{outdir}/capture_ch{ch:02d}.pcap"
            p = _sp.Popen(
                ["sudo", "tcpdump", "-i", iface, "-w", outfile, "-q"],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            )
            procs.append((iface, ch, outfile, p))
            info(f"  Started capture: {iface} ch{ch} → {outfile}")

        ok(f"All {len(procs)} captures running. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        info("Stopping all captures…")
        for iface, ch, outfile, p in procs:
            p.terminate()
        time.sleep(1)
        ok(f"All captures stopped. Files in: {outdir}")
    except Exception as e:
        err(f"Channel hopping capture error: {e}")
    finally:
        for _, _, _, p in procs:
            try:
                p.terminate()
            except Exception:
                pass


def op_view_interfaces():
    heading("View Connected Interfaces")
    flavor = get_os_flavor()
    if flavor == "macos":
        err("Wi-Fi Coconut is NOT supported on macOS.")
        info("On macOS, try: airport -s  (for system WiFi info only)")
        return
    info("Listing wlan interfaces (iw dev)…")
    try:
        out = run_output("iw dev 2>/dev/null") or "(no output)"
        info(out)
        ifaces = _get_coconut_interfaces()
        if ifaces:
            ok(f"Found {len(ifaces)} wlan interface(s): {', '.join(ifaces)}")
            for iface in ifaces:
                phy_out = run_output(f"iw phy $(iw dev {iface} info 2>/dev/null | awk '/wiphy/{{print $2}}') info 2>/dev/null | head -5") or ""
                if phy_out:
                    info(f"  {iface} phy info: {phy_out.splitlines()[0]}")
        else:
            warn("No wlan interfaces found.")
    except Exception as e:
        err(f"Interface listing error: {e}")


def op_launch_wireshark():
    heading("Launch Wireshark with All Interfaces")
    flavor = get_os_flavor()
    if flavor == "macos":
        err("Wi-Fi Coconut is NOT supported on macOS.")
        return

    ifaces = _get_coconut_interfaces()
    if not ifaces:
        err("No wlan interfaces found. Ensure device and driver are ready.")
        return

    info("Checking for Wireshark / tshark…")
    try:
        ensure_apt_packages(["wireshark", "tshark"])
    except Exception as e:
        warn(f"Could not install Wireshark packages: {e}")

    info(f"Launching Wireshark with {len(ifaces)} interface(s)…")
    iface_args = []
    for iface in ifaces:
        iface_args += ["-i", iface]

    import subprocess as _sp
    try:
        if run_output("which wireshark 2>/dev/null"):
            cmd = ["wireshark"] + iface_args
            info(f"Command: {' '.join(cmd)}")
            _sp.Popen(cmd)
            ok("Wireshark launched.")
        elif run_output("which tshark 2>/dev/null"):
            outfile = prompt("Output pcap file for tshark (default: /tmp/coconut_ws.pcap)",
                             default="/tmp/coconut_ws.pcap")
            cmd = ["sudo", "tshark"] + iface_args + ["-w", outfile]
            info(f"Command: {' '.join(cmd)}")
            info("Press Ctrl+C to stop.")
            rc = run_streaming(cmd, on_line=lambda l: info(f"  tshark: {l}"), timeout=3600)
            ok(f"tshark capture saved to {outfile}")
        else:
            err("Neither wireshark nor tshark found.")
            info("Install: sudo apt-get install wireshark tshark")
    except KeyboardInterrupt:
        ok("Wireshark/tshark capture stopped.")
    except Exception as e:
        err(f"Wireshark launch error: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Platform check ────────────────────────────────────────────────────────
    flavor = get_os_flavor()
    if flavor == "macos":
        err("Wi-Fi Coconut is NOT supported on macOS.")
        err("The AR9271 chipset requires the Linux ath9k_htc kernel module.")
        info("Please use Kali Linux or another Debian-based distribution.")
        info("Continuing in limited mode for informational purposes…")

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Installing required packages for Wi-Fi capture and analysis…")
        try:
            ensure_apt_packages([
                "aircrack-ng", "tshark", "tcpdump", "iw", "usbutils",
                "build-essential", "git", "dkms",
            ])
        except Exception as e:
            warn(f"Some packages could not be installed: {e}")
    elif flavor == "macos":
        info("macOS is not supported, but checking available tools…")
        try:
            ensure_brew_packages(["wireshark"])
        except Exception as e:
            info(f"Brew check skipped: {e}")

    # ── Linux udev rules ──────────────────────────────────────────────────────
    _check_udev_rules()

    # ── Kernel module check ───────────────────────────────────────────────────
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        heading("Kernel Module Check")
        for mod in ("ath9k", "ath9k_htc"):
            if _is_module_loaded(mod):
                ok(f"Module '{mod}' is loaded.")
            else:
                info(f"Loading kernel module '{mod}'…")
                try:
                    r = sudo_run(f"modprobe {mod} 2>/dev/null")
                    if r.returncode == 0:
                        ok(f"Module '{mod}' loaded.")
                    else:
                        warn(f"Could not load '{mod}'. Check kernel headers.")
                except Exception as e:
                    warn(f"modprobe {mod} error: {e}")

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    if flavor == "macos":
        warn("Skipping USB detection on macOS (not supported).")
        info("Connect the Wi-Fi Coconut to a Linux system and rerun this tool.")
        sys.exit(1)

    info(f"Scanning USB bus for AR9271 radios (VID:PID {AR9271_VID:04X}:{AR9271_PID:04X})…")
    info(f"A full Wi-Fi Coconut should have {EXPECTED_RADIO_COUNT} radios.")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=300)
    if not found:
        err("Wi-Fi Coconut not detected within timeout. Exiting.")
        sys.exit(1)

    count = _count_ar9271_usb_devices()
    ok(f"Wi-Fi Coconut detected: {count} AR9271 radio(s) on USB.")
    check_firmware_version()

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Detect Device & Check Driver Status",
        "Install / Update wifi_coconut Driver",
        "Start Capture (single interface, single channel)",
        "Channel Hopping Capture (all channels, all radios)",
        "View Connected Interfaces (iw dev)",
        "Launch Wireshark with All Interfaces",
        "Check Driver / Firmware Version",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_detect_and_driver_status()
        elif choice == 1:
            op_install_update_driver()
        elif choice == 2:
            op_start_capture()
        elif choice == 3:
            op_channel_hopping_capture()
        elif choice == 4:
            op_view_interfaces()
        elif choice == 5:
            op_launch_wireshark()
        elif choice == 6:
            check_firmware_version()
        elif choice == 7:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
