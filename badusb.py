#!/usr/bin/env python3
"""
BadUSB Device Manager
Manages ATmega32U4-based HID injection devices: DigiSpark, Arduino Micro,
SparkFun Pro Micro. Supports payload listing, device programming, and
comprehensive guide output for HID injection attack hardware.

Usage:
    python3 badusb.py

Supported devices:
    DigiSpark (Digistump)  — VID:PID 16C0:05DC — Micronucleus bootloader
    Arduino Micro          — VID:PID 2341:8037  — AVRDUDE / avr109 bootloader
    SparkFun Pro Micro 5V  — VID:PID 1B4F:9205  — AVRDUDE / avr109 bootloader
    SparkFun Pro Micro 3V  — VID:PID 1B4F:9206  — AVRDUDE / avr109 bootloader
    Atmel DFU bootloader   — VID:PID 03EB:2FF4  — AVRDUDE / DFU mode

WARNING: HID injection devices emulate a USB keyboard. They can type arbitrary
keystrokes into any computer they are plugged into. USE ONLY ON SYSTEMS YOU OWN
OR HAVE EXPLICIT WRITTEN PERMISSION TO TEST. Unauthorized use is illegal.

Linux serial permissions:
    Add user to dialout: sudo usermod -aG dialout $USER
    Check udev rules:    ls /etc/udev/rules.d/ | grep badusb
    Verify USB device:   lsusb | grep -iE "16c0|2341|1b4f|03eb"
    Debug enumeration:   dmesg | tail -30
"""

import os
import sys
import time
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
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    get_firmware_dir, get_selected_payload,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "BadUSB"
DESCRIPTION = "ATmega32U4-based HID injection device manager (DigiSpark, Arduino Micro, Pro Micro)"

VID_PIDS = [
    (0x16C0, 0x05DC),  # DigiSpark (Digistump/DigiStump)
    (0x1B4F, 0x9205),  # SparkFun Pro Micro (5V 16MHz)
    (0x1B4F, 0x9206),  # SparkFun Pro Micro (3.3V 8MHz)
    (0x2341, 0x8037),  # Arduino Micro
    (0x03EB, 0x2FF4),  # Atmel DFU ATmega32U4 bootloader
]

PAYLOADS_DIR = Path(__file__).parent / "payloads" / "badusb"

CONNECT_INSTRUCTIONS = (
    "BadUSB devices appear as USB HID keyboard devices.\n\n"
    "  DigiSpark VID:PID 16C0:05DC\n"
    "  Arduino Micro VID:PID 2341:8037\n"
    "  SparkFun Pro Micro (5V) VID:PID 1B4F:9205\n"
    "  SparkFun Pro Micro (3.3V) VID:PID 1B4F:9206\n"
    "  Atmel DFU bootloader VID:PID 03EB:2FF4\n\n"
    "  NOTE: Some variants auto-execute payload on plug-in — ensure target is\n"
    "  correct before connecting. DigiSpark has a ~5 second window after plug-in\n"
    "  before payload execution begins.\n\n"
    "  Troubleshooting:\n"
    "    Linux: lsusb | grep -i '16c0\\|2341\\|1b4f\\|03eb'\n"
    "    Linux: dmesg | tail -20 (check for USB HID enumeration)\n"
    "    macOS: system_profiler SPUSBDataType | grep -A5 -i 'digispark\\|arduino'\n"
    "    udev rules: ls /etc/udev/rules.d/ | grep badusb\n"
    "    Permission fix: sudo usermod -aG dialout $USER (then log out/in)"
)

UDEV_RULES_CONTENT = (
    '# BadUSB HID injection devices udev rules\n'
    '# DigiSpark (VID:PID 16C0:05DC)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="05dc", '
    'MODE="0666", GROUP="plugdev"\n'
    '# SparkFun Pro Micro 5V (VID:PID 1B4F:9205)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="1b4f", ATTRS{idProduct}=="9205", '
    'MODE="0666", GROUP="plugdev"\n'
    '# SparkFun Pro Micro 3.3V (VID:PID 1B4F:9206)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="1b4f", ATTRS{idProduct}=="9206", '
    'MODE="0666", GROUP="plugdev"\n'
    '# Arduino Micro (VID:PID 2341:8037)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="2341", ATTRS{idProduct}=="8037", '
    'MODE="0666", GROUP="plugdev"\n'
    '# Atmel DFU ATmega32U4 bootloader (VID:PID 03EB:2FF4)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="03eb", ATTRS{idProduct}=="2ff4", '
    'MODE="0666", GROUP="plugdev"\n'
    '# Also allow serial access for Arduino Micro / Pro Micro CDC ACM\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="2341", ATTRS{idProduct}=="8037", '
    'MODE="0666", GROUP="dialout"\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1b4f", ATTRS{idProduct}=="9205", '
    'MODE="0666", GROUP="dialout"\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1b4f", ATTRS{idProduct}=="9206", '
    'MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-badusb.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    """Detect any BadUSB VID:PID via libusb (non-serial HID/USB)."""
    info("Scanning USB bus for BadUSB VID:PIDs via libusb…")
    info("  Checking: 16C0:05DC (DigiSpark), 2341:8037 (Arduino Micro),")
    info("            1B4F:9205/9206 (Pro Micro), 03EB:2FF4 (Atmel DFU)")
    return detect_usb_libusb_any(VID_PIDS)


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for BadUSB devices on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("Skipping udev rule check (not a Linux system).")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("udev rules not found — installing BadUSB device rules…")
    info(f"  Target: {UDEV_RULES_PATH}")
    info("  This enables non-root USB programming access for DigiSpark/Arduino/Pro Micro.")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        info("Reloading udev rules and triggering USB re-detection…")
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the device to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual fix: sudo nano {UDEV_RULES_PATH}")
        info("  Paste udev rules for VIDs: 16c0, 2341, 1b4f, 03eb")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    """Show lsusb output and USB vendor/product info for detected BadUSB device."""
    heading("Device Info")
    info("Querying USB bus for BadUSB device information…")
    info("BadUSB devices are pure HID (keyboard) devices — no serial console.")
    info("They appear as USB input devices, not serial ports.")
    info("Expected: HID interface, possibly CDC ACM for Arduino/Pro Micro.")
    info("")
    info("Running lsusb to show all connected USB devices…")
    try:
        os_flavor = get_os_flavor()
        if os_flavor == "macos":
            info("Running: system_profiler SPUSBDataType")
            out = run_output("system_profiler SPUSBDataType 2>/dev/null")
            if out:
                for line in out.splitlines():
                    info(line)
            else:
                warn("No output from system_profiler. Is a device connected?")
                info("Try: system_profiler SPUSBDataType | grep -A10 -i 'digispark'")
        else:
            info("Running: lsusb (shows all USB devices with VID:PID)")
            out = run_output("lsusb 2>/dev/null")
            if out:
                for line in out.splitlines():
                    # Highlight our known VIDs
                    vid_pids_lower = ["16c0:05dc", "2341:8037", "1b4f:9205",
                                      "1b4f:9206", "03eb:2ff4"]
                    line_lower = line.lower()
                    if any(vp in line_lower for vp in vid_pids_lower):
                        ok(f"  [MATCH] {line}")
                    else:
                        info(f"  {line}")
            else:
                warn("No lsusb output. Is 'usbutils' installed?")
                info("Install: sudo apt install usbutils")
            info("")
            info("Running: dmesg | grep -i 'usb\\|hid' (last 20 lines) for device attachment events…")
            dmesg_out = run_output("dmesg 2>/dev/null | grep -iE 'usb.*hid|hid.*usb|digispark|arduino|pro.micro' | tail -20")
            if dmesg_out:
                info("Recent USB HID events:")
                for line in dmesg_out.splitlines():
                    info(f"  {line}")
            else:
                info("No recent HID USB events in dmesg.")
    except Exception as e:
        err(f"Device info failed: {e}")
        info("Troubleshooting: ensure usbutils is installed (apt install usbutils)")
        info("  Try manually: lsusb | grep -iE '16c0|2341|1b4f|03eb'")
        info("  Or check: dmesg | tail -30")

    info("")
    info("Device identification guide:")
    info("  16C0:05DC — DigiSpark (Digistump) — appears as V-USB HID device")
    info("  2341:8037 — Arduino Micro — appears as USB HID + CDC ACM serial")
    info("  1B4F:9205 — SparkFun Pro Micro 5V 16MHz — HID + CDC ACM")
    info("  1B4F:9206 — SparkFun Pro Micro 3.3V 8MHz — HID + CDC ACM")
    info("  03EB:2FF4 — Atmel DFU bootloader (ATmega32U4) — programming mode")
    ok("Device info complete.")


def op_list_payloads():
    """List available DuckyScript payloads from payloads/badusb/ directory."""
    heading("List Available Payloads")
    info(f"Looking for DuckyScript payloads in: {PAYLOADS_DIR}")
    info("Supported formats: .txt (DuckyScript), .hex (compiled firmware), .ino (Arduino sketch)")
    info("")

    if not PAYLOADS_DIR.exists():
        warn(f"Payload directory not found: {PAYLOADS_DIR}")
        info("Creating payload directory…")
        try:
            PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
            ok(f"Created: {PAYLOADS_DIR}")
            info("Place DuckyScript .txt files or compiled .hex files in this directory.")
        except Exception as e:
            err(f"Could not create payload directory: {e}")
        info("")
        info("DuckyScript payload format example (save as payloads/badusb/example.txt):")
        info("  DELAY 1000")
        info("  GUI r")
        info("  DELAY 500")
        info("  STRING notepad")
        info("  ENTER")
        info("  DELAY 1000")
        info("  STRING Hello from BadUSB!")
        info("  ENTER")
        return

    txt_files  = list(PAYLOADS_DIR.glob("*.txt"))
    hex_files  = list(PAYLOADS_DIR.glob("*.hex"))
    ino_files  = list(PAYLOADS_DIR.glob("*.ino"))
    all_files  = txt_files + hex_files + ino_files

    if not all_files:
        warn(f"No payload files found in {PAYLOADS_DIR}")
        info("Supported file types: .txt (DuckyScript source), .hex (compiled), .ino (Arduino)")
        info("Payload resources:")
        info("  USB Rubber Ducky scripts: https://github.com/hak5/usbrubberducky-payloads")
        info("  DigiSpark sketches: https://github.com/digistump/DigistumpArduino")
        info("  DuckScript reference: https://docs.hak5.org/hak5-usb-rubber-ducky/")
        return

    info(f"Found {len(all_files)} payload file(s) in {PAYLOADS_DIR}:")
    info("")

    if txt_files:
        info(f"DuckyScript source files ({len(txt_files)}):")
        for f in sorted(txt_files):
            size = f.stat().st_size
            info(f"  {f.name:<40} ({size} bytes)")
    if hex_files:
        info(f"Compiled HEX firmware files ({len(hex_files)}):")
        for f in sorted(hex_files):
            size = f.stat().st_size
            info(f"  {f.name:<40} ({size} bytes)")
    if ino_files:
        info(f"Arduino sketch files ({len(ino_files)}):")
        for f in sorted(ino_files):
            size = f.stat().st_size
            info(f"  {f.name:<40} ({size} bytes)")

    info("")
    info("To deploy a payload:")
    info("  DigiSpark (.hex): use 'Program DigiSpark' option with micronucleus")
    info("  Arduino Micro/Pro Micro (.hex): use 'Program Arduino Micro/Pro Micro' option with avrdude")
    info("  .txt DuckyScript: compile to .hex using Arduino IDE + board support first")
    ok(f"Payload listing complete. {len(all_files)} file(s) found.")


def op_program_digispark():
    """Guide user through DigiSpark programming with micronucleus."""
    heading("Program DigiSpark")
    warn("=" * 60)
    warn("SECURITY WARNING: You are about to program a HID injection device.")
    warn("Ensure the payload is intended for a system you own or have")
    warn("explicit written authorization to test. Unauthorized HID")
    warn("injection is ILLEGAL under computer fraud/misuse laws.")
    warn("=" * 60)
    info("")
    info("DigiSpark uses the Micronucleus USB bootloader.")
    info("The Micronucleus bootloader enumerates as VID:PID 16C0:05DC for ~5 seconds")
    info("after power-on, then jumps to the user firmware.")
    info("IMPORTANT: You MUST plug in the DigiSpark AFTER running micronucleus.")
    info("  The tool waits for the device to enumerate on the USB bus.")
    info("")
    info("Micronucleus installation:")
    info("  macOS: brew install --cask digistump")
    info("         (installs micronucleus + DigiStump Arduino board support)")
    info("  Linux (Kali/Debian/Ubuntu): apt-get install micronucleus")
    info("         If not in apt: download from https://github.com/micronucleus/micronucleus/releases")
    info("         Or build from source: git clone https://github.com/micronucleus/micronucleus")
    info("  The micronucleus binary should be in PATH after installation.")
    info("")

    # Check for micronucleus
    info("Checking for 'micronucleus' tool in PATH…")
    micronucleus_path = run_output("which micronucleus 2>/dev/null")
    if not micronucleus_path:
        warn("'micronucleus' not found in PATH.")
        info("Attempting installation…")
        os_flavor = get_os_flavor()
        if os_flavor == "macos":
            info("Running: brew install --cask digistump")
            ensure_brew_packages(["--cask digistump"])
        else:
            info("Attempting: apt-get install micronucleus")
            ensure_apt_packages(["micronucleus"])
        micronucleus_path = run_output("which micronucleus 2>/dev/null")
        if not micronucleus_path:
            warn("micronucleus still not found after install attempt.")
            info("Manual install options:")
            info("  1. Download binary: https://github.com/micronucleus/micronucleus/releases")
            info("  2. Build from source:")
            info("     git clone https://github.com/micronucleus/micronucleus")
            info("     cd micronucleus/commandline && make")
            info("     sudo cp micronucleus /usr/local/bin/")
            info("  3. macOS: brew install --cask digistump")
            if not confirm("Continue anyway (specify full path to micronucleus)?", default=False):
                return
            micronucleus_path = prompt("Full path to micronucleus binary", "/usr/local/bin/micronucleus")
            if not micronucleus_path or not Path(micronucleus_path).exists():
                err("micronucleus binary not found. Cannot continue.")
                return
    else:
        ok(f"micronucleus found: {micronucleus_path.strip()}")

    info("")
    info("Select the .hex firmware file to flash to the DigiSpark.")
    info(f"Payloads directory: {PAYLOADS_DIR}")

    # List available .hex files
    hex_files = list(PAYLOADS_DIR.glob("*.hex")) if PAYLOADS_DIR.exists() else []
    if hex_files:
        info(f"Available .hex files in {PAYLOADS_DIR}:")
        for i, f in enumerate(hex_files):
            info(f"  [{i}] {f.name}")

    hex_path = prompt("Path to .hex firmware file for DigiSpark")
    if not hex_path:
        warn("No .hex file specified. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        info("Ensure the .hex file exists and the path is correct.")
        return

    info("")
    info(f"About to flash: {hex_file.name}")
    info("IMPORTANT: Do NOT plug in the DigiSpark yet!")
    info("The micronucleus command will tell you when to plug it in.")
    info("You will have approximately 5 seconds after plugging in to upload.")
    info("")
    if not confirm(f"Flash {hex_file.name} to DigiSpark?", default=False):
        info("Flash cancelled.")
        return

    micronucleus_bin = micronucleus_path.strip() if micronucleus_path else "micronucleus"
    cmd = [micronucleus_bin, "--run", str(hex_file)]
    info(f"Running: {' '.join(cmd)}")
    info("Waiting for DigiSpark to be plugged in (micronucleus is now listening)…")
    info(">>> PLUG IN THE DIGISPARK NOW <<<")
    info("You have ~60 seconds before micronucleus times out.")
    info("")
    info("Troubleshooting if upload fails:")
    info("  'libusb: not found' → apt install libusb-dev or brew install libusb")
    info("  'udev rules' error → ensure /etc/udev/rules.d/60-badusb.rules is installed")
    info("  'connection refused' → DigiSpark may have jumped to application firmware")
    info("    Solution: quickly unplug and replug within the 5-second bootloader window")
    info("  'verification failed' → check .hex file integrity, try re-flashing")

    try:
        rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=120)
        if rc == 0:
            ok("DigiSpark flashed successfully!")
            info("The device will now auto-execute the payload when plugged into a target.")
            warn("REMINDER: Only use on systems you own or have explicit authorization to test.")
        else:
            warn(f"micronucleus exited with code {rc}")
            info("If upload failed, try:")
            info("  1. Replug the DigiSpark and run this option again")
            info("  2. Check udev rules are installed and applied")
            info("  3. Verify the .hex file was compiled for ATtiny85 (DigiSpark chip)")
    except Exception as e:
        err(f"DigiSpark programming failed: {e}")
        info("Troubleshooting:")
        info("  - Check micronucleus is installed and in PATH")
        info("  - Check udev rules for VID:PID 16C0:05DC")
        info("  - Ensure DigiSpark was plugged in within the bootloader window")
        info("  - Try: sudo micronucleus --run <file.hex> (with root)")


def op_program_arduino():
    """Guide user through Arduino Micro/Pro Micro programming with avrdude."""
    heading("Program Arduino Micro / Pro Micro")
    warn("=" * 60)
    warn("SECURITY WARNING: You are about to program a HID injection device.")
    warn("Ensure the payload is intended for a system you own or have")
    warn("explicit written authorization to test. Unauthorized HID")
    warn("injection is ILLEGAL under computer fraud/misuse laws.")
    warn("=" * 60)
    info("")
    info("Arduino Micro and SparkFun Pro Micro use AVRDUDE for programming.")
    info("These devices use the Caterina USB bootloader (avr109 protocol).")
    info("The bootloader is triggered by a double-tap of the RST button,")
    info("or by opening the serial port at 1200 baud (auto-reset).")
    info("")
    info("avrdude installation:")
    info("  Linux (Kali/Debian/Ubuntu): apt-get install avrdude")
    info("  macOS: brew install avrdude")
    info("")
    info("Bootloader entry methods:")
    info("  Method 1 (Auto-reset): Open serial port at 1200 baud — board resets to bootloader")
    info("  Method 2 (Manual): Double-tap the RST button quickly")
    info("  Method 3 (Physical): Short the RST pin to GND briefly")
    info("  After reset: board enumerates briefly as Atmel DFU 03EB:2FF4 or Caterina")
    info("")

    # Check for avrdude
    info("Checking for 'avrdude' tool in PATH…")
    avrdude_path = run_output("which avrdude 2>/dev/null")
    if not avrdude_path:
        warn("'avrdude' not found in PATH.")
        info("Attempting installation…")
        os_flavor = get_os_flavor()
        if os_flavor == "macos":
            info("Running: brew install avrdude")
            ensure_brew_packages(["avrdude"])
        else:
            info("Running: apt-get install avrdude")
            ensure_apt_packages(["avrdude"])
        avrdude_path = run_output("which avrdude 2>/dev/null")
        if not avrdude_path:
            warn("avrdude still not found after install attempt.")
            info("Download from: https://github.com/avrdudes/avrdude/releases")
            return
        else:
            ok(f"avrdude installed: {avrdude_path.strip()}")
    else:
        ok(f"avrdude found: {avrdude_path.strip()}")

    info("")
    # Select device type
    device_choice = numbered_menu(
        "Select target device",
        ["Arduino Micro (VID:PID 2341:8037, ATmega32U4)",
         "SparkFun Pro Micro 5V 16MHz (VID:PID 1B4F:9205, ATmega32U4)",
         "SparkFun Pro Micro 3.3V 8MHz (VID:PID 1B4F:9206, ATmega32U4)",
         "Cancel"]
    )
    if device_choice == 3:
        info("Cancelled.")
        return

    baud_map = {0: "57600", 1: "57600", 2: "57600"}
    baud_rate = baud_map[device_choice]
    device_names = {
        0: "Arduino Micro",
        1: "SparkFun Pro Micro 5V",
        2: "SparkFun Pro Micro 3.3V"
    }
    device_name = device_names[device_choice]
    info(f"Selected: {device_name}")
    info(f"  MCU: ATmega32U4, Bootloader: Caterina (avr109), Baud: {baud_rate}")

    # Find serial port
    vid_pids_for_device = {
        0: [(0x2341, 0x8037)],
        1: [(0x1B4F, 0x9205)],
        2: [(0x1B4F, 0x9206)],
    }
    target_vids = vid_pids_for_device[device_choice]
    info(f"Looking for serial port for {device_name}…")
    port = find_serial_port_by_vidpid(target_vids)
    if port:
        ok(f"Found device serial port: {port}")
    else:
        warn(f"{device_name} not found on serial port. Checking if bootloader mode is needed…")
        info("Triggering bootloader via 1200-baud auto-reset…")
        info("  This opens the serial port at 1200 baud to trigger Caterina bootloader reset.")
        port_manual = prompt("Enter current serial port (e.g. /dev/ttyACM0 or /dev/cu.usbmodem*)")
        if port_manual:
            port = port_manual
            info(f"Using manually specified port: {port}")
            info("Attempting 1200 baud reset to trigger bootloader…")
            try:
                import serial
                ser = serial.Serial(port, 1200)
                time.sleep(0.1)
                ser.close()
                info("1200 baud pulse sent. Waiting for bootloader enumeration…")
                time.sleep(3)
                new_port = find_serial_port_by_vidpid(target_vids)
                if new_port:
                    port = new_port
                    ok(f"Bootloader port: {port}")
                else:
                    info("Port may have changed. Try double-tapping RST button.")
            except Exception as e:
                warn(f"1200 baud reset failed: {e}")
                info("Try manually double-tapping the RST button on the board.")
        else:
            err("No serial port specified. Cannot continue.")
            info("Connect the device and re-run this option.")
            return

    if not port:
        err(f"Could not find {device_name} on any serial port.")
        info("Troubleshooting:")
        info("  - Is the device connected via USB?")
        info("  - Is the user in the dialout group? (sudo usermod -aG dialout $USER)")
        info("  - Are udev rules installed? (ls /etc/udev/rules.d/60-badusb.rules)")
        info("  - Check: lsusb and dmesg | tail -20")
        return

    info(f"Serial port: {port}")
    info(f"Payload directory: {PAYLOADS_DIR}")

    # List available .hex files
    hex_files = list(PAYLOADS_DIR.glob("*.hex")) if PAYLOADS_DIR.exists() else []
    if hex_files:
        info(f"Available .hex files in {PAYLOADS_DIR}:")
        for i, f in enumerate(hex_files):
            info(f"  [{i}] {f.name}")

    hex_path = prompt("Path to .hex firmware file for Arduino/Pro Micro")
    if not hex_path:
        warn("No .hex file specified. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return

    info("")
    info(f"About to flash: {hex_file.name}")
    info(f"  Target: {device_name} on {port}")
    info(f"  Command: avrdude -p atmega32u4 -P {port} -c avr109 -b {baud_rate} -D -U flash:w:{hex_file}")
    info("")
    info("IMPORTANT: Ensure the device is in bootloader mode before proceeding!")
    info("  Bootloader mode: double-tap RST button or use 1200 baud auto-reset.")
    info("  In bootloader mode the device briefly enumerates on a different VID:PID.")
    if not confirm(f"Flash {hex_file.name} to {device_name} on {port}?", default=False):
        info("Flash cancelled.")
        return

    info("Running avrdude…")
    info("Troubleshooting avrdude failures:")
    info("  'stk500_recv(): programmer is not responding' → device not in bootloader mode")
    info("    Solution: double-tap RST quickly and immediately run the flash command")
    info("  'avrdude: butterfly_recv(): programmer is not responding' → same as above")
    info("  'can't open device' → permission denied, check dialout group")
    info("  'device signature' mismatch → wrong board selected or device not connected")

    cmd = [
        "avrdude",
        "-p", "atmega32u4",
        "-P", port,
        "-c", "avr109",
        "-b", baud_rate,
        "-D",
        "-U", f"flash:w:{hex_file}:i",
    ]
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=120)
        if rc == 0:
            ok(f"{device_name} flashed successfully!")
            info("The device will reboot and run the new firmware.")
            warn("REMINDER: Only use on systems you own or have explicit authorization to test.")
        else:
            warn(f"avrdude exited with code {rc}")
            info("If the flash failed:")
            info("  1. Try entering bootloader mode again (double-tap RST)")
            info("  2. Check that the correct port is specified")
            info("  3. Verify the .hex file was compiled for ATmega32U4")
            info("  4. Try: sudo avrdude ... (with root privileges)")
    except Exception as e:
        err(f"Arduino programming failed: {e}")
        info("Troubleshooting: ensure avrdude is installed: apt install avrdude / brew install avrdude")
        info("  Verify device is in bootloader mode and port is correct.")


def op_show_programming_guide():
    """Show comprehensive guide for programming each BadUSB variant."""
    heading("BadUSB Programming Guide")
    warn("=" * 65)
    warn("ETHICAL USE WARNING")
    warn("=" * 65)
    warn("HID injection devices emulate USB keyboards and can type any")
    warn("keystrokes into any computer they are plugged into.")
    warn("ONLY use on systems you OWN or have EXPLICIT WRITTEN PERMISSION")
    warn("to test. Unauthorized use constitutes a computer crime under:")
    warn("  - US: Computer Fraud and Abuse Act (CFAA)")
    warn("  - UK: Computer Misuse Act 1990")
    warn("  - EU: Directive on Attacks Against Information Systems")
    warn("  - And equivalent laws in virtually every jurisdiction.")
    warn("=" * 65)
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 1: DigiSpark (Digistump) — ATtiny85 + V-USB")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("Hardware: ATtiny85 MCU + V-USB (software USB emulation)")
    info("Bootloader: Micronucleus (USB HID bootloader)")
    info("VID:PID: 16C0:05DC")
    info("")
    info("Setup steps:")
    info("  1. Install Arduino IDE: https://www.arduino.cc/en/software")
    info("  2. Add Digistump board URL in Arduino IDE preferences:")
    info("       http://digistump.com/package_digistump_index.json")
    info("  3. Install Digistump AVR Boards via Boards Manager")
    info("  4. Install micronucleus command-line tool:")
    info("       macOS: brew install --cask digistump")
    info("       Linux: apt-get install micronucleus")
    info("             OR: https://github.com/micronucleus/micronucleus/releases")
    info("  5. Write DigiSpark sketch in Arduino IDE:")
    info("       #include <DigiKeyboard.h>")
    info("       void setup() {")
    info("         DigiKeyboard.delay(5000);  // Wait for OS to recognize device")
    info("         DigiKeyboard.sendKeyStroke(0);")
    info("         DigiKeyboard.println(\"Hello World\");")
    info("       }")
    info("  6. Compile to .hex: Sketch → Export Compiled Binary")
    info("  7. Flash via micronucleus: micronucleus --run sketch.hex")
    info("  8. Plug in DigiSpark AFTER running micronucleus command")
    info("")
    info("IMPORTANT TIMING: DigiSpark has a ~5 second bootloader window.")
    info("  After 5 seconds, it jumps to user firmware (payload executes!).")
    info("  Always run 'micronucleus --run <file>' BEFORE plugging in.")
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 2: Arduino Micro (2341:8037) / SparkFun Pro Micro")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("Hardware: ATmega32U4 MCU (native USB)")
    info("Bootloader: Caterina (avr109 protocol)")
    info("VID:PID: 2341:8037 (Arduino Micro), 1B4F:9205/9206 (Pro Micro)")
    info("")
    info("Setup steps:")
    info("  1. Install avrdude:")
    info("       Linux: apt-get install avrdude")
    info("       macOS: brew install avrdude")
    info("  2. Write sketch in Arduino IDE with Keyboard library:")
    info("       #include <Keyboard.h>")
    info("       void setup() {")
    info("         delay(2000);")
    info("         Keyboard.begin();")
    info("         Keyboard.println(\"Hello World\");")
    info("         Keyboard.end();")
    info("       }")
    info("  3. Select board: Arduino Micro or SparkFun Pro Micro")
    info("  4. Compile: Sketch → Export Compiled Binary (.hex)")
    info("  5. Enter bootloader mode:")
    info("       Method A: Double-tap the RST button")
    info("       Method B: Open serial port at 1200 baud (python3 -c \"import serial; serial.Serial('/dev/ttyACM0', 1200).close()\")")
    info("       Method C: Short RST pin to GND briefly")
    info("  6. Flash immediately after bootloader mode:")
    info("       avrdude -p atmega32u4 -P /dev/ttyACM0 -c avr109 -b 57600 -D -U flash:w:sketch.hex")
    info("")
    info("NOTE: The bootloader window is brief. Have the avrdude command ready.")
    info("  Arduino-CLI can also be used: arduino-cli upload -p /dev/ttyACM0 --fqbn arduino:avr:micro sketch/")
    info("")

    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("SECTION 3: DuckyScript Payload Reference (USB Rubber Ducky syntax)")
    info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    info("DuckyScript commands (compatible with most HID injection tools):")
    info("  DELAY <ms>         — wait N milliseconds")
    info("  STRING <text>      — type a string of text")
    info("  ENTER              — press Enter key")
    info("  GUI <key>          — Windows key + key (e.g. GUI r = Win+R)")
    info("  ALT <key>          — Alt + key")
    info("  CTRL <key>         — Ctrl + key")
    info("  SHIFT <key>        — Shift + key")
    info("  TAB                — press Tab key")
    info("  ESCAPE             — press Escape key")
    info("  UPARROW / DOWNARROW / LEFTARROW / RIGHTARROW — arrow keys")
    info("  F1 through F12     — function keys")
    info("")
    info("DuckyScript to Arduino conversion tools:")
    info("  Hak5 Ducky Encoder: https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Encode")
    info("  Duckuino (DuckyScript → Arduino): https://github.com/Plazmaz/Duckuino")
    info("  Duck Toolkit: https://ducktoolkit.com/")
    info("")
    info("Reference payloads: https://github.com/hak5/usbrubberducky-payloads")
    ok("Programming guide complete.")


# ── Firmware Version Check ────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking micronucleus bootloader version on BadUSB device...")
    current = None
    try:
        import subprocess as _sp
        r = _sp.run(["micronucleus", "--dump-prog", "--run"],
                    capture_output=True, text=True, timeout=15)
        if r.returncode == 0 or r.stderr:
            import re
            text = r.stdout + r.stderr
            m = re.search(r'Bootloader\s+version[:\s]+(\S+)', text, re.IGNORECASE)
            if not m:
                m = re.search(r'micronucleus\s+([\d.]+)', text, re.IGNORECASE)
            if m:
                current = m.group(1)
                ok(f"Micronucleus bootloader version: {current}")
    except FileNotFoundError:
        info("micronucleus not installed (needed for DigiSpark flashing).")
        info("  Linux: sudo apt install micronucleus")
        info("  macOS: brew install micronucleus")
    except Exception as e:
        info(f"  Bootloader version check failed: {e}")

    if not current:
        info("  Could not determine bootloader version. Device may not be in upload mode.")
        info("  For DigiSpark: unplug and replug within 5 seconds of running micronucleus.")

    info("Checking latest micronucleus release on GitHub...")
    latest, url = check_latest_github_release("micronucleus", "micronucleus")
    if latest:
        if current:
            announce_firmware_update("Micronucleus Bootloader", current, latest.lstrip("v"), url)
        else:
            info(f"  Latest micronucleus: {latest}  ({url})")
    else:
        warn("Could not check GitHub for micronucleus updates.")


# ── Firmware payloads (main-page "FIRMWARE - ..." auto-flash) ─────────────────
# Wires the module's EXISTING programming flows as no-menu payloads. These
# devices carry operator-compiled sketches (no auto-source firmware exists), so
# each prepare_fn installs the flasher and locates an operator-supplied .hex,
# aborting BEFORE the confirmation if none is present.
#   DigiSpark (ATtiny85 + Micronucleus) — micronucleus --run <hex>
#   Arduino Micro / SparkFun Pro Micro (ATmega32U4 + Caterina) — avrdude avr109
# Compile sketches with the Arduino IDE (Sketch → Export Compiled Binary) and
# drop the .hex into the firmware dir. DuckyScript → Arduino via Duckuino
# (https://github.com/Plazmaz/Duckuino).

ARDUINO_VID_PIDS = [(0x2341, 0x8037), (0x1B4F, 0x9205), (0x1B4F, 0x9206)]


def _fw_dir() -> Path:
    d = get_firmware_dir("badusb")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _find_operator_hex():
    """Newest operator-supplied .hex from the firmware dir or payloads/badusb/."""
    cands = []
    for d in [_fw_dir(), PAYLOADS_DIR]:
        if d.exists():
            cands.extend(sorted(d.glob("*.hex")))
    return cands[-1] if cands else None


def _ensure_micronucleus() -> str:
    mn = run_output("which micronucleus 2>/dev/null")
    if mn and mn.strip():
        return mn.strip()
    info("  micronucleus not found — attempting install…")
    if get_os_flavor() == "macos":
        ensure_brew_packages(["--cask digistump"])
    else:
        ensure_apt_packages(["micronucleus"])
    mn = run_output("which micronucleus 2>/dev/null")
    return mn.strip() if (mn and mn.strip()) else ""


def _ensure_avrdude() -> str:
    av = run_output("which avrdude 2>/dev/null")
    if av and av.strip():
        return av.strip()
    info("  avrdude not found — attempting install…")
    if get_os_flavor() == "macos":
        ensure_brew_packages(["avrdude"])
    else:
        ensure_apt_packages(["avrdude"])
    av = run_output("which avrdude 2>/dev/null")
    return av.strip() if (av and av.strip()) else ""


def _fw_device_info():
    heading("Device Info")
    info(f"Board : {TOOL_NAME}")
    info("BadUSB devices are HID/USB — programming is over the bootloader, not a console.")


def _prep_digispark(staged) -> bool:
    mn = _ensure_micronucleus()
    if not mn:
        err("  micronucleus could not be installed — aborting before the flash.")
        info("  Install: https://github.com/micronucleus/micronucleus/releases")
        return False
    hexf = _find_operator_hex()
    if not hexf:
        err("  No operator-supplied .hex found — aborting before the flash.")
        info(f"  Place a compiled ATtiny85 .hex in {_fw_dir()} (or payloads/badusb/).")
        return False
    staged["mn"] = mn
    staged["hex"] = hexf
    ok(f"  Ready: micronucleus + {hexf.name}")
    return True


def _prep_arduino(staged) -> bool:
    av = _ensure_avrdude()
    if not av:
        err("  avrdude could not be installed — aborting before the flash.")
        info("  Install: https://github.com/avrdudes/avrdude/releases")
        return False
    hexf = _find_operator_hex()
    if not hexf:
        err("  No operator-supplied .hex found — aborting before the flash.")
        info(f"  Place a compiled ATmega32U4 .hex in {_fw_dir()} (or payloads/badusb/).")
        return False
    port = find_serial_port_by_vidpid(ARDUINO_VID_PIDS)
    if not port:
        err("  No Arduino Micro / Pro Micro serial port found — aborting before the flash.")
        info("  Connect the board and ensure it enumerates as /dev/ttyACM* or /dev/cu.usbmodem*.")
        return False
    staged["hex"] = hexf
    staged["port"] = port
    ok(f"  Ready: avrdude + {hexf.name}  (port {port})")
    return True


def _flash_digispark(staged):
    cmd = [staged["mn"], "--run", str(staged["hex"])]
    info(f"Running: {' '.join(cmd)}")
    info(">>> PLUG IN THE DIGISPARK NOW <<<  (micronucleus is listening ~60s)")
    run_streaming(cmd, on_line=lambda l: info(f"  micronucleus: {l}"), timeout=120)


def _flash_arduino(staged):
    port = staged["port"]
    hexf = staged["hex"]
    info("  Triggering the Caterina bootloader via a 1200-baud open/close…")
    try:
        import serial
        s = serial.Serial(port, 1200)
        time.sleep(0.1)
        s.close()
        time.sleep(3)
        np = find_serial_port_by_vidpid(ARDUINO_VID_PIDS)
        if np:
            port = np
    except Exception as e:
        warn(f"  1200-baud reset failed ({e}) — double-tap RST manually if avrdude stalls.")
    cmd = ["avrdude", "-p", "atmega32u4", "-P", port, "-c", "avr109",
           "-b", "57600", "-D", "-U", f"flash:w:{hexf}:i"]
    info(f"Running: {' '.join(cmd)}")
    run_streaming(cmd, on_line=lambda l: info(f"  avrdude: {l}"), timeout=120)


# ── Local .ino → .hex compilation (arduino-cli) ───────────────────────────────
# BadUSB "firmware" is a compiled Arduino sketch. Rather than requiring a prebuilt
# .hex, this compiles a selected .ino locally with arduino-cli — installing the
# correct board core (DigiSpark / Arduino Micro / SparkFun Pro Micro) — then flashes
# the result with the module's existing micronucleus / avrdude path. The sketch
# comes from the operator (selected payload, firmware dir, or a cloned public repo
# via import_community_payloads.py --tools badusb); it is not authored here.
#
# core, FQBN, and (optional) board-manager index per board kind:
_ARDUINO_CORES = {
    "digispark": ("digistump:avr", "digistump:avr:digispark-tiny",
                  "https://raw.githubusercontent.com/ArminJo/DigistumpArduino/master/package_digistump_index.json"),
    "micro":     ("arduino:avr", "arduino:avr:micro", None),
    "promicro5": ("SparkFun:avr", "SparkFun:avr:promicro:cpu=16MHzatmega32U4",
                  "https://raw.githubusercontent.com/sparkfun/Arduino_Boards/master/IDE_Board_Manager/package_sparkfun_index.json"),
    "promicro3": ("SparkFun:avr", "SparkFun:avr:promicro:cpu=8MHzatmega32U4",
                  "https://raw.githubusercontent.com/sparkfun/Arduino_Boards/master/IDE_Board_Manager/package_sparkfun_index.json"),
}


def _ensure_arduino_cli() -> str:
    a = run_output("which arduino-cli 2>/dev/null")
    if a and a.strip():
        return a.strip()
    info("  arduino-cli not found — installing…")
    if get_os_flavor() == "macos":
        ensure_brew_packages(["arduino-cli"])
    else:
        run("curl -fsSL https://raw.githubusercontent.com/arduino/arduino-cli/master/"
            "install.sh | BINDIR=/usr/local/bin sh")
    a = run_output("which arduino-cli 2>/dev/null")
    return a.strip() if (a and a.strip()) else ""


def _resolve_badusb_board() -> str:
    """Board kind from QUIVER_BADUSB_BOARD, else auto-detected from the connected
    VID:PID. DigiSpark isn't a serial device, so it's the fallback default."""
    env = os.environ.get("QUIVER_BADUSB_BOARD", "").strip().lower()
    if env in _ARDUINO_CORES:
        return env
    if find_serial_port_by_vidpid([(0x1B4F, 0x9205)]):
        return "promicro5"
    if find_serial_port_by_vidpid([(0x1B4F, 0x9206)]):
        return "promicro3"
    if find_serial_port_by_vidpid([(0x2341, 0x8037)]):
        return "micro"
    return "digispark"


def _ensure_arduino_core(kind: str) -> bool:
    cli = _ensure_arduino_cli()
    if not cli:
        err("  arduino-cli could not be installed.")
        return False
    core, _fqbn, index = _ARDUINO_CORES[kind]
    run(f"{cli} config init --overwrite")
    if index:
        run(f"{cli} config add board_manager.additional_urls {index}")
    run(f"{cli} core update-index")
    if run(f"{cli} core install {core}").returncode != 0:
        err(f"  Could not install the Arduino core '{core}'.")
        return False
    return True


def _select_badusb_ino():
    """The .ino to compile: the selected payload if it's a sketch, else the newest
    .ino under the firmware dir / payloads/badusb/ (including cloned community/)."""
    p = get_selected_payload()
    if p and str(p).endswith(".ino"):
        pth = Path(p) if os.path.isabs(p) else (Path(__file__).resolve().parent / p)
        if pth.exists():
            return pth
    cands = []
    for d in (_fw_dir(), PAYLOADS_DIR):
        if d and Path(d).exists():
            cands.extend(sorted(Path(d).rglob("*.ino")))
    return cands[-1] if cands else None


def _compile_ino(ino_path, kind: str):
    """Compile a sketch with arduino-cli for the board kind. arduino-cli compiles a
    sketch DIRECTORY whose name matches the .ino, so a loose .ino is staged into
    <tmp>/<stem>/<stem>.ino first. Returns the application .hex (not the
    *.with_bootloader.hex), or None on failure."""
    import tempfile
    import shutil as _sh
    cli = _ensure_arduino_cli()
    if not cli:
        return None
    _core, fqbn, _index = _ARDUINO_CORES[kind]
    ino_path = Path(ino_path)
    stem = ino_path.stem
    tmp = Path(tempfile.mkdtemp(prefix="quiver_badusb_"))
    sketchdir = tmp / stem
    sketchdir.mkdir(parents=True, exist_ok=True)
    _sh.copy(str(ino_path), str(sketchdir / f"{stem}.ino"))
    out = tmp / "out"
    info(f"  Compiling {ino_path.name} for {fqbn}…")
    rc = run_streaming([cli, "compile", "--fqbn", fqbn, "--output-dir", str(out),
                        str(sketchdir)],
                       on_line=lambda l: info(f"  arduino-cli: {l}"), timeout=600)
    if rc != 0:
        return None
    hexes = [p for p in sorted(out.glob("*.hex")) if "with_bootloader" not in p.name]
    if not hexes:
        hexes = sorted(out.glob("*.hex"))
    return hexes[-1] if hexes else None


def _prep_compile_sketch(staged) -> bool:
    """PREPARE: resolve the board + sketch, install the toolchain/core, compile the
    .ino to .hex, and ensure the flasher — so only the write remains. Returns True
    only when a .hex was produced and the flasher is ready."""
    kind = _resolve_badusb_board()
    ino = _select_badusb_ino()
    if not ino:
        err("  No .ino sketch found — select one as the payload, drop one in the")
        info(f"  firmware dir ({_fw_dir()}), or import public sketches:")
        info("    payloads/import_community_payloads.py --tools badusb")
        return False
    info(f"  Board : {kind}    Sketch : {ino.name}")
    if not _ensure_arduino_core(kind):
        return False
    hexf = _compile_ino(ino, kind)
    if not hexf:
        err("  Compilation failed — aborting before the flash (see arduino-cli output).")
        return False
    ok(f"  Compiled: {hexf.name}")
    staged["kind"] = kind
    staged["hex"] = hexf
    if kind == "digispark":
        mn = _ensure_micronucleus()
        if not mn:
            err("  micronucleus could not be installed — aborting before the flash.")
            return False
        staged["mn"] = mn
    else:
        if not _ensure_avrdude():
            err("  avrdude could not be installed — aborting before the flash.")
            return False
        port = find_serial_port_by_vidpid(ARDUINO_VID_PIDS)
        if not port:
            err("  No Arduino/Pro Micro serial port found — aborting before the flash.")
            return False
        staged["port"] = port
    return True


def _flash_compiled_sketch(staged):
    if staged.get("kind") == "digispark":
        _flash_digispark(staged)      # uses staged["mn"], staged["hex"]
    else:
        _flash_arduino(staged)        # uses staged["port"], staged["hex"]


def _dispatch_firmware_payload(fw: dict):
    """Route a selected .qfw firmware payload to the right prepare/flash pair."""
    fw_name = fw.get("firmware", "")
    label = fw.get("label", f"Flash {fw_name}")
    staged: dict = {}
    if fw_name == "Compile Sketch":
        run_firmware_payload(
            label,
            info_fn=_fw_device_info,
            prepare_fn=lambda: _prep_compile_sketch(staged),
            flash_fn=lambda: _flash_compiled_sketch(staged),
            summary_lines=[
                "Board    : auto (DigiSpark / Arduino Micro / Pro Micro) — QUIVER_BADUSB_BOARD overrides",
                "Firmware : Arduino sketch (.ino) compiled locally via arduino-cli",
                "Flasher  : micronucleus (DigiSpark) / avrdude avr109 (ATmega32U4)",
            ],
        )
    elif fw_name == "DigiSpark":
        run_firmware_payload(
            label,
            info_fn=_fw_device_info,
            prepare_fn=lambda: _prep_digispark(staged),
            flash_fn=lambda: _flash_digispark(staged),
            summary_lines=[
                f"Board    : DigiSpark (ATtiny85 + Micronucleus)",
                "Firmware : operator-supplied compiled .hex (Arduino sketch)",
                "Flasher  : micronucleus --run",
            ],
        )
    elif fw_name == "Arduino Micro / Pro Micro":
        run_firmware_payload(
            label,
            info_fn=_fw_device_info,
            prepare_fn=lambda: _prep_arduino(staged),
            flash_fn=lambda: _flash_arduino(staged),
            summary_lines=[
                f"Board    : Arduino Micro / SparkFun Pro Micro (ATmega32U4 + Caterina)",
                "Firmware : operator-supplied compiled .hex (Arduino sketch)",
                "Flasher  : avrdude -c avr109 (1200-baud bootloader trigger)",
            ],
        )
    else:
        err(f"Unknown firmware payload: {fw_name!r}")
        info("  Supported: DigiSpark, Arduino Micro / Pro Micro")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    warn("=" * 65)
    warn("ETHICAL USE NOTICE")
    warn("=" * 65)
    warn("BadUSB/HID injection devices emulate USB keyboards.")
    warn("They can type arbitrary keystrokes into any connected computer.")
    warn("USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT WRITTEN PERMISSION.")
    warn("Unauthorized use is ILLEGAL in most jurisdictions worldwide.")
    warn("=" * 65)
    info("")

    os_flavor = get_os_flavor()
    info(f"Detected OS: {os_flavor}")
    info("")

    # Install system tools
    if os_flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking required apt packages: avrdude, arduino-cli, usbutils…")
        info("  avrdude: ATmega32U4 programmer (Arduino Micro, Pro Micro)")
        info("  usbutils: provides lsusb for device detection")
        ensure_apt_packages(["avrdude", "usbutils"])
        info("Note: arduino-cli may not be in apt. Check: https://arduino.github.io/arduino-cli/")
        info("Note: micronucleus may not be in apt. Check: https://github.com/micronucleus/micronucleus/releases")
    elif os_flavor == "macos":
        info("Checking required brew packages: avrdude…")
        info("  avrdude: ATmega32U4 programmer (Arduino Micro, Pro Micro)")
        ensure_brew_packages(["avrdude"])
        info("Note: For DigiSpark support, run: brew install --cask digistump")
        info("      This installs micronucleus + DigiStump Arduino board support.")

    # pip packages
    info("Checking Python packages: pyserial (for 1200-baud auto-reset)…")
    ensure_pip_packages([("serial", "pyserial")])

    # udev rules check (Linux only)
    if os_flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking udev rules for BadUSB VID:PIDs…")
        _check_udev_rules()

    # Device detection
    info("")
    info("Scanning for BadUSB device via USB VID:PID matching…")
    info("  Checking for any of: 16C0:05DC, 2341:8037, 1B4F:9205, 1B4F:9206, 03EB:2FF4")
    info("  Note: DigiSpark only enumerates for ~5 seconds after plug-in.")
    info("  Note: Device may appear as HID keyboard, not a serial port.")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        warn("BadUSB device not detected.")
        info("You can still use the Programming Guide and Payload Listing options.")
        info("Re-run the script with device connected for Device Info / Programming.")
        if not confirm("Continue without detected device?", default=True):
            err("Exiting.")
            sys.exit(1)

    if found:
        ok("BadUSB device detected on USB bus.")
    info("")

    check_firmware_version()

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    MENU_OPTIONS = [
        "Device Info (lsusb)",
        "List Payloads",
        "Program DigiSpark (micronucleus)",
        "Program Arduino Micro / Pro Micro (avrdude)",
        "Programming Guide",
        "Exit",
    ]

    while True:
        choice = numbered_menu("BadUSB — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_list_payloads()
        elif choice == 2:
            op_program_digispark()
        elif choice == 3:
            op_program_arduino()
        elif choice == 4:
            op_show_programming_guide()
        elif choice == 5:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
