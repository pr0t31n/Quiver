#!/usr/bin/env python3
"""
Ubertooth One Tool Manager
Controls the Ubertooth One Bluetooth monitor via subprocess CLI tools.
All operations use ubertooth-util, ubertooth-btle, ubertooth-rx,
ubertooth-specan, and ubertooth-dfu.

Usage:
    python3 ubertooth_one.py
"""

import sys
import time
import subprocess
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    detect_usb_libusb,
    require_sudo, sudo_run, sudo_output, run_streaming_sudo,
    ensure_apt_packages, ensure_brew_packages, ensure_pip_packages,
    ensure_system_tool,
    web_detect_loop, run_streaming,
    check_latest_github_release, compare_versions, announce_firmware_update,
)

# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME   = "Ubertooth One"
DESCRIPTION = "Bluetooth monitor/sniffer — BLE and Classic BR/EDR capture"

VID_NORMAL = 0x1D50
PID_NORMAL = 0x6002
VID_DFU    = 0x1D50
PID_DFU    = 0x6003

CONNECT_INSTRUCTIONS = (
    "Ubertooth One not detected.\n\n"
    "  1. Plug in Ubertooth One via USB\n"
    "  2. Install tools:\n"
    "     Kali: sudo apt install ubertooth python3-usb python3-scapy\n"
    "     macOS: brew install ubertooth\n"
    "  3. Linux udev: check /etc/udev/rules.d/ for ubertooth rules\n"
    "     Kali apt package installs rules automatically.\n"
    "     Manual: copy from /usr/share/ubertooth/udev/ if present\n"
    "  4. Add user to plugdev: sudo usermod -aG plugdev $USER (re-login)\n\n"
    "  VID:PID 1D50:6002 (normal) | 1D50:6003 (DFU mode)"
)

# Required CLI tools with apt package mapping
UBERTOOTH_TOOLS = {
    "ubertooth-util":   ("brew install ubertooth  /  apt install ubertooth", "ubertooth"),
    "ubertooth-btle":   ("brew install ubertooth  /  apt install ubertooth", "ubertooth"),
    "ubertooth-rx":     ("brew install ubertooth  /  apt install ubertooth", "ubertooth"),
    "ubertooth-specan": ("brew install ubertooth  /  apt install ubertooth", "ubertooth"),
    "ubertooth-dfu":    ("brew install ubertooth  /  apt install ubertooth", "ubertooth"),
}


# ── Firmware version check ────────────────────────────────────────────────────

def _get_current_version() -> str:
    """Return the firmware version from ubertooth-util -v output, or ''."""
    try:
        result = subprocess.run(
            ["ubertooth-util", "-v"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout + result.stderr
        for line in output.splitlines():
            stripped = line.strip()
            # ubertooth-util -v outputs lines like:
            #   Firmware version: 2020-12-R1 (API:1.07)
            if "firmware" in stripped.lower() and "version" in stripped.lower():
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip().split()[0]
            # Also handles bare version lines from ubertooth-util -f
            if stripped.lower().startswith("release:"):
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
        return ""
    except Exception:
        return ""


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking installed firmware version...")
    current = _get_current_version()
    if not current:
        warn("Could not determine installed firmware version.")
        info("Continuing without version check.")
        return
    ok(f"Installed firmware: {current}")

    info("Checking latest available version on GitHub...")
    latest, release_url = check_latest_github_release("greatscottgadgets", "ubertooth")
    if not latest:
        warn("Could not reach GitHub. Skipping version check.")
        return

    wants_update = announce_firmware_update(TOOL_NAME, current, latest, release_url)
    if wants_update:
        op_firmware_update()


# ── Detection ──────────────────────────────────────────────────────────────────

def detect_ubertooth() -> bool:
    return detect_usb_libusb(VID_NORMAL, PID_NORMAL)


# ── Tool check helper ─────────────────────────────────────────────────────────

def _require_tool(tool: str) -> bool:
    """Return True if tool is available; otherwise try apt install and emit error."""
    hint, apt_pkg = UBERTOOTH_TOOLS.get(tool, ("apt install ubertooth", "ubertooth"))
    return ensure_system_tool(tool, hint, apt_pkg=apt_pkg, brew_pkg="ubertooth")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Querying Ubertooth One firmware version and device status…")
    info("ubertooth-util -v outputs:")
    info("  compile time  — firmware build timestamp")
    info("  release       — firmware version string")
    info("  serial        — USB serial number")
    info("Troubleshooting:")
    info("  'ubertooth-util: not found' → sudo apt install ubertooth")
    info("  'Unable to open Ubertooth device' → check udev rules and replug")
    info("  'LIBUSB_ERROR_ACCESS' → permission denied; check plugdev group membership")
    if not _require_tool("ubertooth-util"):
        return
    rc = run_streaming_sudo(["ubertooth-util", "-v"], on_line=lambda l: info(l), timeout=10)
    if rc != 0:
        warn(f"ubertooth-util -v exited with code {rc}")
        info("Try: sudo ubertooth-util -v  to confirm it works with elevated privileges")


def op_ble_capture():
    heading("BLE Capture (BTLE Sniffer)")
    info("Capture Bluetooth Low Energy (BLE) advertisement packets.")
    info("Ubertooth One limitations for BLE:")
    info("  - Monitors all 3 BLE advertising channels (37, 38, 39) by hopping")
    info("  - Cannot capture data channel packets without knowing the access address")
    info("  - '-f' flag = follow all advertisements (promiscuous advertisement sniffing)")
    info("  - Output is a PCAP file readable with Wireshark (dissector: BTLE)")
    info("Troubleshooting BLE capture:")
    info("  - No packets: move Ubertooth closer to BLE device")
    info("  - 'Timeout' errors are normal; advertising interval varies per device")
    info("  - Wireshark: set protocol to 'btle' or install 'ubertooth' Wireshark plugin")
    if not _require_tool("ubertooth-btle"):
        return

    out_file = prompt("Output .pcap file path", "/tmp/ubertooth_ble.pcap")
    dur_str  = prompt("Capture duration (seconds)", "30")

    try:
        duration = float(dur_str)
    except ValueError:
        err("Invalid duration.")
        return

    out_path = Path(out_file).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    info(f"Starting BLE capture → {out_path} (follow all advertisements)")
    info(f"Duration: {duration}s — press Ctrl+C to stop early")
    cmd = ["ubertooth-btle", "-f", "-q", str(out_path)]
    info(f"Running (with sudo): {' '.join(cmd)}")
    try:
        import os
        if os.getuid() == 0:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            from common import _SUDO_PASS
            full_cmd = ["sudo", "-S"] + cmd if _SUDO_PASS else ["sudo"] + cmd
            proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if _SUDO_PASS:
                try:
                    proc.stdin.write((_SUDO_PASS + "\n").encode())
                    proc.stdin.flush()
                except BrokenPipeError:
                    pass
            proc.stdin.close()
        info(f"Capturing for {duration}s… Press Ctrl+C to stop early.")
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        ok(f"Capture complete. Output: {out_path}")
        info(f"Open with Wireshark: wireshark {out_path}")
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=5)
        info("Capture interrupted.")
        ok(f"Partial capture saved to {out_path}")
    except Exception as e:
        err(f"BLE capture failed: {e}")
        info("Troubleshooting: try running 'sudo ubertooth-btle -f -q /tmp/test.pcap' manually")


def op_follow_ble_device():
    heading("Follow BLE Device")
    info("Track a specific BLE device by its MAC address and capture its traffic.")
    info("Useful for analyzing BLE sensors, wearables, or IoT devices.")
    info("Limitation: Ubertooth One can only follow ONE device at a time.")
    info("Tip: Use 'BLE Capture' first to find MAC addresses, then follow here.")
    if not _require_tool("ubertooth-btle"):
        return

    mac_addr = prompt("Target BLE device MAC address (e.g. AA:BB:CC:DD:EE:FF)")
    if not mac_addr:
        warn("No MAC address entered.")
        return

    out_file = prompt("Output .pcap file path", "/tmp/ubertooth_ble_follow.pcap")
    dur_str  = prompt("Capture duration (seconds)", "60")

    try:
        duration = float(dur_str)
    except ValueError:
        err("Invalid duration.")
        return

    out_path = Path(out_file).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["ubertooth-btle", "-f", "-t", mac_addr, "-q", str(out_path)]
    info(f"Following BLE device {mac_addr} for {duration}s…")
    info(f"Running (with sudo): {' '.join(cmd)}")
    try:
        import os
        from common import _SUDO_PASS
        if os.getuid() == 0:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            full_cmd = ["sudo", "-S"] + cmd if _SUDO_PASS else ["sudo"] + cmd
            proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if _SUDO_PASS:
                try:
                    proc.stdin.write((_SUDO_PASS + "\n").encode())
                    proc.stdin.flush()
                except BrokenPipeError:
                    pass
            proc.stdin.close()
        info(f"Capturing for {duration}s… Press Ctrl+C to stop early.")
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        ok(f"Follow capture complete. Output: {out_path}")
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=5)
        info("Capture interrupted.")
        ok(f"Partial capture saved to {out_path}")
    except Exception as e:
        err(f"Follow capture failed: {e}")


def op_classic_bt_capture():
    heading("Classic Bluetooth Capture (BR/EDR)")
    info("Capture Classic Bluetooth (BR/EDR) traffic using ubertooth-rx.")
    info("Ubertooth One BR/EDR limitations:")
    info("  - Can only monitor ONE channel at a time (out of 79 channels)")
    info("  - Frequency hopping means you will miss most packets unless you")
    info("    know the hop sequence (requires piconet clock synchronization)")
    info("  - ubertooth-rx works best near devices that are actively pairing")
    info("  - For full BR/EDR capture, multiple Ubertooth devices are needed")
    info("Troubleshooting:")
    info("  - No packets: BR/EDR hops 1600 times/sec; capture near pairing event")
    info("  - Use '-c' flag to specify a fixed channel to monitor")
    if not _require_tool("ubertooth-rx"):
        return

    out_file = prompt("Output file path", "/tmp/ubertooth_breder.pcap")
    dur_str  = prompt("Capture duration (seconds)", "30")

    try:
        duration = float(dur_str)
    except ValueError:
        err("Invalid duration.")
        return

    out_path = Path(out_file).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["ubertooth-rx", "-d", str(out_path)]
    info(f"Starting BR/EDR capture → {out_path} for {duration}s…")
    info(f"Running (with sudo): {' '.join(cmd)}")
    try:
        import os
        from common import _SUDO_PASS
        if os.getuid() == 0:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            full_cmd = ["sudo", "-S"] + cmd if _SUDO_PASS else ["sudo"] + cmd
            proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if _SUDO_PASS:
                try:
                    proc.stdin.write((_SUDO_PASS + "\n").encode())
                    proc.stdin.flush()
                except BrokenPipeError:
                    pass
            proc.stdin.close()
        info(f"Capturing for {duration}s… Press Ctrl+C to stop early.")
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        ok(f"Capture complete. Output: {out_path}")
    except KeyboardInterrupt:
        proc.terminate()
        proc.wait(timeout=5)
        info("Capture interrupted.")
        ok(f"Partial capture saved to {out_path}")
    except Exception as e:
        err(f"BR/EDR capture failed: {e}")


def op_spectrum_analyzer():
    heading("Spectrum Analyzer (2.4 GHz)")
    info("Sweep the 2.4 GHz band and display channel RSSI as a text bar chart.")
    info("ubertooth-specan covers 2.4–2.48 GHz (Bluetooth / Wi-Fi / Zigbee band).")
    info("Output interpretation:")
    info("  Channel 0   = 2402 MHz (BT advertising ch 37)")
    info("  Channel 38  = 2440 MHz (BT data channel midpoint)")
    info("  Channel 78  = 2480 MHz (BT advertising ch 39)")
    info("  Wi-Fi ch 1  ≈ 2412 MHz, ch 6 ≈ 2437 MHz, ch 11 ≈ 2462 MHz")
    info("Troubleshooting:")
    info("  - No data: ubertooth-specan may need sudo")
    info("  - All RSSI very low: check antenna connection on Ubertooth One")
    info("  - High noise floor: move away from Wi-Fi APs or microwave ovens")
    if not _require_tool("ubertooth-specan"):
        return

    dur_str = prompt("Duration (seconds)", "15")
    try:
        duration = float(dur_str)
    except ValueError:
        err("Invalid duration.")
        return

    info(f"Running spectrum analyzer for {duration}s (Ctrl+C to stop early)…")
    info("Data displayed as channel RSSI text grid.")

    # ubertooth-specan outputs gnuplot-style data: channel rssi pairs
    channel_rssi = {}

    def handle_line(line: str):
        parts = line.strip().split()
        if len(parts) >= 2:
            try:
                ch   = int(parts[0])
                rssi = int(parts[1])
                channel_rssi[ch] = rssi
                bar_len = max(0, int((rssi + 100) / 2))
                bar = "#" * min(bar_len, 40)
                info(f"  Ch {ch:3d}  RSSI={rssi:4d} dBm  {bar}")
            except ValueError:
                pass

    cmd = ["ubertooth-specan"]
    info(f"Running (with sudo): {' '.join(cmd)}")
    try:
        import os
        from common import _SUDO_PASS
        deadline = time.time() + duration
        if os.getuid() == 0:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        else:
            full_cmd = ["sudo", "-S"] + cmd if _SUDO_PASS else ["sudo"] + cmd
            proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            if _SUDO_PASS:
                try:
                    proc.stdin.write(_SUDO_PASS + "\n")
                    proc.stdin.flush()
                except BrokenPipeError:
                    pass
            proc.stdin.close()
        for line in proc.stdout:
            handle_line(line.rstrip())
            if time.time() >= deadline:
                break
        proc.terminate()
        proc.wait(timeout=5)
    except KeyboardInterrupt:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            pass
        info("Spectrum analysis interrupted.")
    except Exception as e:
        err(f"Spectrum analyzer failed: {e}")
        return

    if channel_rssi:
        ok(f"Spectrum scan complete. {len(channel_rssi)} channel(s) observed.")
        peak_ch = max(channel_rssi, key=channel_rssi.get)
        info(f"Peak channel: {peak_ch}  RSSI={channel_rssi[peak_ch]} dBm")
    else:
        warn("No spectrum data received.")
        info("Troubleshooting: try 'sudo ubertooth-specan' directly in terminal")


def op_firmware_version():
    heading("Firmware Version")
    info("Queries the firmware version string from the Ubertooth One.")
    if not _require_tool("ubertooth-util"):
        return
    rc = run_streaming_sudo(["ubertooth-util", "-V"], on_line=lambda l: info(l), timeout=10)
    if rc != 0:
        warn(f"ubertooth-util -V exited with code {rc}")


def op_firmware_update():
    heading("Firmware Update")
    info("Flash new firmware to the Ubertooth One via DFU mode.")
    info("Steps: device enters DFU mode → ubertooth-dfu flashes .dfu file → device reboots.")
    info("Firmware downloads: https://github.com/greatscottgadgets/ubertooth/releases")
    info("Look for: ubertooth-*.dfu in the release assets.")
    info("Troubleshooting firmware update:")
    info("  - 'Cannot open DFU device' → device not in DFU mode; retry ubertooth-util -f")
    info("  - After flash: unplug and replug; run 'ubertooth-util -v' to confirm version")
    info("  - If bricked: hold bootloader button while plugging in (if hardware supports it)")
    if not _require_tool("ubertooth-util"):
        return
    if not _require_tool("ubertooth-dfu"):
        return

    fw_file = prompt("Path to firmware .dfu file")
    if not fw_file:
        warn("No file specified.")
        return

    fw_path = Path(fw_file).expanduser()
    if not fw_path.exists():
        err(f"File not found: {fw_path}")
        return

    warn("This will enter DFU mode and flash firmware to the Ubertooth One.")
    if not confirm("Proceed with firmware update?", default=False):
        info("Cancelled.")
        return

    info("Step 1: Entering DFU mode (ubertooth-util -f)…")
    rc1 = run_streaming_sudo(["ubertooth-util", "-f"], on_line=lambda l: info(l), timeout=10)
    if rc1 != 0:
        warn(f"ubertooth-util -f exited with code {rc1} — device may already be in DFU mode.")

    info("Waiting 3 seconds for device to re-enumerate in DFU mode…")
    time.sleep(3)

    info(f"Step 2: Flashing firmware {fw_path.name} via ubertooth-dfu…")
    cmd = ["ubertooth-dfu", "-d", str(fw_path), "-U", "0"]
    rc2 = run_streaming_sudo(cmd, on_line=lambda l: info(l), timeout=120)
    if rc2 == 0:
        ok("Firmware update complete. Replug the Ubertooth One.")
    else:
        warn(f"ubertooth-dfu exited with code {rc2}")
        info("Troubleshooting: confirm .dfu file is valid and device is in DFU mode (VID:PID 1D50:6003)")


def op_reset_device():
    heading("Reset Device")
    info("Sends a USB reset command to the Ubertooth One via ubertooth-util -r.")
    if not _require_tool("ubertooth-util"):
        return
    if not confirm("Reset Ubertooth One?", default=False):
        info("Cancelled.")
        return
    rc = run_streaming_sudo(["ubertooth-util", "-r"], on_line=lambda l: info(l), timeout=10)
    if rc == 0:
        ok("Reset command sent.")
    else:
        warn(f"ubertooth-util -r exited with code {rc}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    # Prefer apt packages on Kali/Debian/Ubuntu
    info("Checking apt packages: ubertooth, python3-usb, python3-scapy…")
    ensure_apt_packages(["ubertooth", "python3-usb", "python3-scapy"])
    ensure_brew_packages(["ubertooth"])

    # No pip packages needed when apt ubertooth is installed

    # Detection
    detected = web_detect_loop(detect_ubertooth, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not detected:
        err("Ubertooth One not detected. Exiting.")
        sys.exit(1)
    ok("Ubertooth One detected.")

    check_firmware_version()

    MENU_OPTIONS = [
        "Device Info (ubertooth-util -v)",
        "BLE Capture (follow all advertisements)",
        "Follow BLE Device (by MAC address)",
        "Classic BT Capture (BR/EDR)",
        "Spectrum Analyzer (2.4 GHz text grid)",
        "Firmware Version (ubertooth-util -V)",
        "Firmware Update (ubertooth-dfu)",
        "Reset Device (ubertooth-util -r)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Ubertooth One — Select Operation", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_ble_capture()
        elif choice == 2:
            op_follow_ble_device()
        elif choice == 3:
            op_classic_bt_capture()
        elif choice == 4:
            op_spectrum_analyzer()
        elif choice == 5:
            op_firmware_version()
        elif choice == 6:
            op_firmware_update()
        elif choice == 7:
            op_reset_device()
        elif choice == 8:
            ok("Goodbye.")
            sys.exit(0)


if __name__ == "__main__":
    main()
