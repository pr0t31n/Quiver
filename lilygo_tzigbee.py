#!/usr/bin/env python3
"""
LilyGo T-Zigbee Tool Manager
Handles device info, ESP32-C3 firmware flashing, Zigbee coordinator flashing,
Zigbee network info, and permit-join via zigpy-znp.

Usage:
    python3 lilygo_tzigbee.py
"""

import asyncio
import os
import subprocess
import sys
import threading
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
    selected_firmware_payload, run_firmware_payload, get_firmware_dir,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "LilyGo T-Zigbee"
DESCRIPTION = "Dual-MCU ESP32-C3 + Zigbee coordinator development board"

VID_PIDS = [
    (0x303A, 0x1001),  # ESP32-C3 native USB
    (0x1A86, 0x7523),  # CH340
    (0x10C4, 0xEA60),  # CP210x
]

ZIGBEE_BAUD = 115200

CONNECT_INSTRUCTIONS = (
    "LilyGo T-Zigbee v1.2 not detected.\n\n"
    "  1. Connect via USB-C cable\n"
    "  2. Linux udev rules for USB-serial chips:\n"
    "     CH340  (1A86:7523): kernel module ch341 — usually auto-loaded\n"
    "     CP210x (10C4:EA60): kernel module cp210x — usually auto-loaded\n"
    "     If device not appearing: sudo modprobe ch341  OR  sudo modprobe cp210x\n"
    "  3. Add user to dialout: sudo usermod -aG dialout $USER (re-login)\n"
    "  4. ESP32-C3 native USB (v1.2): VID 303A:1001\n"
    "     CH340 bridge (older): VID 1A86:7523\n"
    "  5. Set DIP switch:\n"
    "     Position 1 = ESP32-C3 programming\n"
    "     Position 2 = Zigbee radio (ZNP mode)\n\n"
    "  Coordinator firmware: https://github.com/Koenkk/Z-Stack-firmware"
)

# udev rules for common USB-serial chips used on LilyGo T-Zigbee
UDEV_RULES_CONTENT = (
    '# LilyGo T-Zigbee USB-serial udev rules\n'
    '# CH340 (VID:PID 1A86:7523)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7523", '
    'MODE="0666", GROUP="dialout"\n'
    '# CP210x (VID:PID 10C4:EA60)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", '
    'MODE="0666", GROUP="dialout"\n'
    '# ESP32-C3 native USB (VID:PID 303A:1001)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="1001", '
    'MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-lilygo-tzigbee.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules check ──────────────────────────────────────────────────────────

def _check_udev_rules():
    """Check and install udev rules for CH340 and CP210x on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for CH340 and CP210x USB-serial chips…")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the LilyGo T-Zigbee to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual fix: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")

    # Check kernel modules
    info("Checking USB-serial kernel modules…")
    for mod in ("ch341", "cp210x"):
        out = run_output(f"lsmod 2>/dev/null | grep {mod}")
        if out:
            ok(f"Kernel module '{mod}' is loaded.")
        else:
            info(f"Module '{mod}' not loaded — attempting modprobe…")
            r = sudo_run(f"modprobe {mod}")
            if r.returncode == 0:
                ok(f"Module '{mod}' loaded.")
            else:
                info(f"Module '{mod}' not available (may not be needed for your chip).")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info(f"Serial port: {port}")
    info("Troubleshooting device detection:")
    info("  - CH340 on Linux: check 'lsmod | grep ch341'")
    info("  - CP210x on Linux: check 'lsmod | grep cp210x'")
    info("  - Permission denied: add user to dialout group")
    from serial.tools import list_ports
    for p in list_ports.comports():
        if p.device == port:
            info(f"Description : {p.description}")
            info(f"Manufacturer: {p.manufacturer or 'N/A'}")
            vid = f"0x{p.vid:04X}" if p.vid else "N/A"
            pid = f"0x{p.pid:04X}" if p.pid else "N/A"
            info(f"VID:PID     : {vid}:{pid}")
            info(f"Serial No.  : {p.serial_number or 'N/A'}")
    info("DIP switch positions:")
    info("  Position 1 → ESP32-C3 programming / host bridge")
    info("  Position 2 → Zigbee radio ZNP mode (115200 baud)")
    ok("Device info complete.")


def flash_esp32c3(port: str, firmware_bin: str):
    info("Flash parameters for ESP32-C3:")
    info("  --baud 460800 — fast flash baud rate (auto-negotiated)")
    info("  --flash_mode dio — dual I/O SPI mode")
    info("  --flash_freq 80m — 80 MHz flash clock")
    info("  0x0 — start address for merged binary (bootloader + app combined)")
    info("Troubleshooting flash:")
    info("  'Failed to connect' → hold BOOT button while pressing RST, then release BOOT")
    info("  'Wrong chip detected' → verify DIP switch is in Position 1 (ESP32-C3 side)")
    info("  'MD5 mismatch' → USB cable issue; try a different cable or hub")
    cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32c3",
        "--port", port,
        "--baud", "460800",
        "--before", "default_reset",
        "--after", "hard_reset",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_freq", "80m",
        "--flash_size", "detect",
        "0x0", firmware_bin,
    ]
    run_streaming(cmd, on_line=lambda l: info(l), timeout=120)


def op_flash_esp32c3(port: str):
    heading("Flash ESP32-C3 Firmware")
    warn("Ensure the DIP switch is set to Position 1 (ESP32-C3 programming).")
    info("If the board does not auto-enter flash mode:")
    info("  1. Hold the BOOT button")
    info("  2. Press and release RST")
    info("  3. Release BOOT — board is now in download mode")
    firmware_path = prompt("Path to .bin firmware file")
    if not firmware_path:
        warn("No file path provided. Aborting.")
        return
    fw = Path(firmware_path)
    if not fw.exists():
        err(f"File not found: {fw}")
        return
    if not confirm(f"Flash {fw.name} to ESP32-C3 on {port}?"):
        info("Flash cancelled.")
        return
    info(f"Flashing {fw.name} via esptool...")
    try:
        flash_esp32c3(port, str(fw))
        ok("ESP32-C3 flash complete.")
    except Exception as e:
        err(f"Flash failed: {e}")
        info("Troubleshooting: ensure esptool is installed (apt install esptool)")
        info("  or try: pip install esptool --break-system-packages")


def op_flash_zigbee_coordinator(port: str):
    heading("Flash Zigbee Coordinator")
    warn("Set the DIP switch to Position 2 (Zigbee radio side) before flashing.")
    warn("The Zigbee radio uses cc2538-bsl for flashing — NOT esptool.")
    info("cc2538-bsl is a Python tool for flashing TI CC2538/CC26xx/CC13xx chips.")
    info("Coordinator firmware sources:")
    info("  - https://github.com/Koenkk/Z-Stack-firmware (recommended)")
    info("  - Choose: coordinator/Z-Stack_3.x.0/ for Zigbee 3.0")
    info("Troubleshooting cc2538-bsl flash:")
    info("  'Timeout' → ensure DIP switch is in Position 2 and device is reconnected")
    info("  'Access denied' → check dialout group membership")
    info("  'Serial port not found' → device re-enumerated on different port after DIP switch change")
    pause("Press ENTER when the DIP switch is in Position 2 and device is reconnected.")

    bsl_script = Path(__file__).parent / "cc2538-bsl" / "cc2538-bsl.py"
    if not bsl_script.exists():
        warn("cc2538-bsl not found. Attempting to clone from GitHub...")
        info("Source: https://github.com/JelmerT/cc2538-bsl")
        clone_dir = Path(__file__).parent / "cc2538-bsl"
        result = run(
            f"git clone https://github.com/JelmerT/cc2538-bsl {clone_dir}"
        )
        if result.returncode != 0 or not bsl_script.exists():
            err("Failed to clone cc2538-bsl. Install git and retry.")
            info("Manual: git clone https://github.com/JelmerT/cc2538-bsl")
            return
        ok("cc2538-bsl cloned successfully.")

    hex_path = prompt("Path to Zigbee coordinator .hex firmware file")
    if not hex_path:
        warn("No file path provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return
    if not confirm(f"Flash {hex_file.name} to Zigbee radio on {port}?"):
        info("Flash cancelled.")
        return

    info(f"Flashing Zigbee coordinator firmware via cc2538-bsl...")
    cmd = [
        sys.executable, str(bsl_script),
        "-ewv",
        "-p", port,
        "--baud", "500000",
        str(hex_file),
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=180)
        ok("Zigbee coordinator flash complete.")
    except Exception as e:
        err(f"Zigbee flash failed: {e}")
        info("Troubleshooting: ensure pyserial is installed: apt install python3-serial")


def run_znp_info(port: str):
    async def _inner():
        from zigpy_znp.znp.znp import ZNP
        config = {
            "device": {
                "path": port,
                "baudrate": ZIGBEE_BAUD,
                "flow_control": None,
            }
        }
        znp = ZNP(config)
        await znp.connect()
        info("ZNP coordinator connected")
        try:
            version = znp.version
            info(f"ZNP version: {version}")
        except Exception:
            pass
        await znp.disconnect()
        ok("ZNP info retrieved.")

    asyncio.run(_inner())


def op_zigbee_network_info(port: str):
    heading("Zigbee Network Info")
    warn("Ensure DIP switch is in Position 2 (Zigbee radio / ZNP mode).")
    info(f"Connecting to ZNP coordinator on {port} at {ZIGBEE_BAUD} baud...")
    info("Troubleshooting ZNP connection:")
    info("  - 'SerialException' → DIP switch in wrong position; check Position 2")
    info("  - 'Timeout' → coordinator firmware not flashed; use 'Flash Zigbee Coordinator'")
    info("  - Wrong baud rate: ZNP uses 115200 by default")
    t = threading.Thread(target=run_znp_info, args=(port,), daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        err("Timed out waiting for ZNP coordinator response (30s).")
        info("Troubleshooting: ensure zigpy-znp is installed: pip install zigpy-znp --break-system-packages")


def run_znp_permit_join(port: str, duration: int = 60):
    async def _inner():
        from zigpy_znp.znp.znp import ZNP
        config = {
            "device": {
                "path": port,
                "baudrate": ZIGBEE_BAUD,
                "flow_control": None,
            }
        }
        znp = ZNP(config)
        await znp.connect()
        info("ZNP coordinator connected")
        # Send permit join via ZDO broadcast
        import zigpy.zdo.types as zdo_t
        await znp.request_callback_rsp(
            request=znp.frame_from_znp(
                "ZDO", "MGMT_PERMIT_JOIN_REQ",
                {
                    "AddrMode": 0xFF,
                    "DstAddr": 0xFFFC,
                    "Duration": duration,
                    "TCSignificance": 0,
                },
            ),
            callback=None,
        )
        info(f"Permit join opened for {duration} seconds.")
        await asyncio.sleep(2)
        await znp.disconnect()

    try:
        asyncio.run(_inner())
        ok("Permit join command sent.")
    except Exception as e:
        # Fallback: simpler approach without ZDO binding details
        warn(f"Advanced permit join failed ({e}); ZNP coordinator connected but ZDO request failed.")
        warn("Use your Zigbee gateway software to open the network.")


def op_open_zigbee_network(port: str):
    heading("Open Zigbee Network (Permit Join)")
    warn("Ensure DIP switch is in Position 2 (Zigbee radio / ZNP mode).")
    info("Sending permit join (60 seconds) to ZNP coordinator...")
    info("After permit join: pair Zigbee devices using their join procedure.")
    t = threading.Thread(target=run_znp_permit_join, args=(port, 60), daemon=True)
    t.start()
    t.join(timeout=30)
    if t.is_alive():
        err("Timed out waiting for permit join response (30s).")


def op_serial_console():
    heading("Serial Console")
    info("Use the Shell tab for serial console access.")
    info("Suggested command:  minicom -D <port> -b 115200")
    info("or:                 screen <port> 115200")
    info("Install minicom: sudo apt install minicom")


# ── Firmware payloads (main-page "FIRMWARE - ") ───────────────────────────────

def _fw_user_dir() -> Path:
    d = get_firmware_dir("lilygo_tzigbee") / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ensure_cc2538_bsl() -> Path:
    """Clone JelmerT/cc2538-bsl (the CC2538/CC26xx serial bootloader flasher) if
    absent and return the path to cc2538-bsl.py, or None on failure."""
    bsl_script = Path(__file__).parent / "cc2538-bsl" / "cc2538-bsl.py"
    if bsl_script.exists():
        ok(f"  cc2538-bsl present: {bsl_script}")
        return bsl_script
    clone_dir = Path(__file__).parent / "cc2538-bsl"
    info("  Cloning cc2538-bsl from https://github.com/JelmerT/cc2538-bsl …")
    r = run(f"git clone https://github.com/JelmerT/cc2538-bsl {clone_dir}")
    if r.returncode == 0 and bsl_script.exists():
        ok("  cc2538-bsl cloned.")
        return bsl_script
    err("  Failed to clone cc2538-bsl. Ensure git is installed and retry.")
    return None


def _run_esp32c3_payload(fw, port):
    state = {}

    def prep():
        d = _fw_user_dir()
        bins = sorted(d.glob("*.bin"))
        f = bins[0] if len(bins) == 1 else (d / "app.bin" if (d / "app.bin").exists() else None)
        if not f:
            err("  No ESP32-C3 .bin found. Set the DIP switch to Position 1 and drop the")
            err(f"  merged .bin into: {d}")
            return False
        state["fw"] = f
        ok(f"  ESP32-C3 firmware ready: {f}")
        return True

    def flash():
        flash_esp32c3(port, str(state["fw"]))

    run_firmware_payload(
        fw.get("label", "Flash ESP32-C3 firmware"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[f"Board    : {TOOL_NAME}",
                       "DIP      : Position 1 (ESP32-C3 programming)",
                       "Firmware : operator-supplied merged .bin → 0x0 (esptool)",
                       f"Port     : {port}"])


def _run_zigbee_coordinator_payload(fw, port):
    state = {}

    def prep():
        bsl = _ensure_cc2538_bsl()
        if not bsl:
            return False
        d = _fw_user_dir()
        hexes = sorted(d.glob("*.hex"))
        f = hexes[0] if hexes else None
        if not f:
            err("  No Zigbee coordinator .hex found. Download a Z-Stack coordinator image")
            err("  from https://github.com/Koenkk/Z-Stack-firmware (coordinator/Z-Stack_3.x.0/)")
            err(f"  and drop the .hex into: {d}")
            return False
        state["bsl"] = bsl
        state["hex"] = f
        ok(f"  Coordinator firmware ready: {f}")
        return True

    def flash():
        cmd = [sys.executable, str(state["bsl"]), "-ewv", "-p", port,
               "--baud", "500000", str(state["hex"])]
        info(f"Running: {' '.join(cmd)}")
        run_streaming(cmd, on_line=lambda l: info(l), timeout=180)

    run_firmware_payload(
        fw.get("label", "Flash Zigbee coordinator"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[f"Board    : {TOOL_NAME}",
                       "DIP      : Position 2 (Zigbee radio / ZNP)",
                       "Firmware : Z-Stack coordinator .hex via cc2538-bsl (Koenkk/Z-Stack-firmware)",
                       f"Port     : {port}"])


def _dispatch_firmware_payload(fw, port):
    name = fw.get("firmware", "")
    if name == "ESP32C3":
        _run_esp32c3_payload(fw, port)
    elif name == "ZigbeeCoordinator":
        _run_zigbee_coordinator_payload(fw, port)
    else:
        err(f"Unknown firmware payload '{name}' for {TOOL_NAME}.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    # Prefer apt packages on Kali/Debian/Ubuntu
    info("Checking apt packages: esptool, python3-serial…")
    ensure_apt_packages(["esptool", "python3-serial"])
    ensure_brew_packages(["esptool"])

    # Zigbee stack via pip (not in apt)
    info("Checking Zigbee Python stack (zigpy-znp, zigpy)…")
    ensure_pip_packages([
        ("zigpy_znp", "zigpy-znp"),
        ("zigpy",     "zigpy"),
        ("bellows",   "bellows"),
    ])

    # Check udev rules for USB-serial chips
    info("Checking udev rules for USB-serial chips (CH340, CP210x)…")
    _check_udev_rules()

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("LilyGo T-Zigbee not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Connected on {port}")

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw, port)
        return

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash ESP32-C3 Firmware",
        "FIRMWARE - Flash Zigbee Coordinator",
        "Zigbee Network Info",
        "Open Zigbee Network (Permit Join)",
        "Serial Console",
        "Exit",
    ]

    while True:
        choice = numbered_menu("LilyGo T-Zigbee — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_esp32c3(port)
        elif choice == 2:
            op_flash_zigbee_coordinator(port)
        elif choice == 3:
            op_zigbee_network_info(port)
        elif choice == 4:
            op_open_zigbee_network(port)
        elif choice == 5:
            op_serial_console()
        elif choice == 6:
            info("Goodbye.")
            break

        # Re-check port after operations (flashing may reassign)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
