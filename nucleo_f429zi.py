#!/usr/bin/env python3
"""
STM32 Nucleo-F429ZI Tool Manager
Handles SWD debug/flash via pyocd and VCP serial console (USART3 bridge).

USB VID:PID (ST-Link V2-1): 0x0483:0x374B  (debugger + VCP + MSD composite)
USB VID:PID (user CDC):     0x0483:0x5740

Usage:
    python3 nucleo_f429zi.py
"""

import os
import sys
import subprocess

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, detect_usb_libusb, detect_usb_libusb_any,
    ensure_apt_packages, ensure_pip_packages, ensure_system_tool,
    require_sudo, sudo_run,
    web_detect_loop, run_streaming,
    check_latest_github_release, announce_firmware_update,
)


def check_firmware_version():
    heading("Firmware Version Check")
    info("Reading Nucleo ST-Link firmware version via 'st-info --probe'…")
    current = None
    try:
        import subprocess as _sp
        result = _sp.run(["st-info", "--probe"], capture_output=True, text=True, timeout=15)
        for line in (result.stdout + result.stderr).splitlines():
            low = line.lower()
            if "firmware" in low or "version" in low:
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    current = parts[1].strip()
                    break
    except FileNotFoundError:
        warn("'st-info' not found. Install stlink-tools: sudo apt install stlink-tools")
    except Exception as e:
        warn(f"Could not run 'st-info --probe': {e}")

    if current:
        ok(f"Nucleo ST-Link firmware: {current}")
    else:
        info("Could not auto-detect ST-Link firmware version from st-info output.")
        info("To update ST-Link V2-1 firmware: use STSW-LINK007 via STM32CubeProgrammer (Windows GUI only).")

    latest, url = check_latest_github_release("stlink-org", "stlink")
    if latest:
        announce_firmware_update(TOOL_NAME, current, latest, url)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "STM32 Nucleo-F429ZI"
DESCRIPTION = "STM32F429ZI dev board — SWD flash/debug via pyocd + VCP serial bridge"

PYOCD_TARGET = "stm32f429zi"

VID_PID_STLINK = [(0x0483, 0x374B), (0x0483, 0x5740)]
VID_STLINK     = 0x0483
PID_STLINK_V21 = 0x374B

CONNECT_INSTRUCTIONS = (
    "Nucleo-F429ZI not detected.\n\n"
    "  1. Connect Nucleo via USB cable to the ST-Link USB connector (CN1)\n"
    "     NOT the USER USB (CN13)\n"
    "  2. Linux: install ST-Link udev rules (option available in menu)\n"
    "     or run: sudo cp /usr/share/stlink/udev/rules.d/49-stlink.rules /etc/udev/rules.d/\n"
    "             sudo udevadm control --reload-rules\n"
    "  3. Install pyocd: pip install pyocd --break-system-packages\n"
    "  4. Install target pack: pyocd pack update && pyocd pack install stm32f429zi\n\n"
    "  VID:PID 0483:374B (ST-Link V2-1)"
)

UDEV_RULES_SRC = "/usr/share/stlink/udev/rules.d/49-stlink.rules"
UDEV_RULES_DST = "/etc/udev/rules.d/49-stlink.rules"

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_nucleo() -> bool:
    if find_serial_port_by_vidpid(VID_PID_STLINK) is not None:
        return True
    return detect_usb_libusb(VID_STLINK, PID_STLINK_V21)


# ── udev helpers ──────────────────────────────────────────────────────────────

def _install_stlink_udev():
    """Install ST-Link udev rules from stlink-tools package."""
    import shutil
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        warn("udev rules only apply on Linux.")
        return
    src = UDEV_RULES_SRC
    dst = UDEV_RULES_DST
    if not os.path.exists(src):
        warn(f"ST-Link rules not found at {src}.")
        info("Install stlink-tools first: sudo apt install stlink-tools")
        info("Alternatively, create a minimal rule manually:")
        info("  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"0483\", ATTR{idProduct}==\"374b\", MODE=\"0666\", GROUP=\"plugdev\"' \\")
        info("    | sudo tee /etc/udev/rules.d/49-stlink.rules")
        return
    info(f"Copying {src} → {dst}")
    r = sudo_run(f"cp {src} {dst} && udevadm control --reload-rules && udevadm trigger")
    if r.returncode == 0:
        ok("ST-Link udev rules installed and reloaded.")
        info("If the device is already connected, unplug and reconnect it.")
    else:
        err("Failed to install udev rules.")
        err((r.stdout + r.stderr).strip()[:300])


# ── pyocd helpers ─────────────────────────────────────────────────────────────

def _pyocd_probes():
    """Return list of connected probes via pyocd Python API, or None on error."""
    info("Enumerating connected debug probes via pyocd API...")
    try:
        from pyocd.core.helpers import ConnectHelper
        return ConnectHelper.get_connected_probes()
    except ImportError:
        err("pyocd not installed. Run: pip install pyocd --break-system-packages")
        return None
    except Exception as e:
        err(f"pyocd probe enumeration failed: {e}")
        info("Troubleshooting:")
        info("  - Check udev rules allow access to the ST-Link USB device")
        info("  - Try running: pyocd list  (should show ST-Link probe)")
        info("  - Ensure the target pack is installed: pyocd pack install stm32f429zi")
        return None


def _flash_firmware(firmware_path: str, target: str = PYOCD_TARGET) -> bool:
    """Flash firmware using pyocd Python API."""
    info(f"Opening SWD session with target {target} at 4 MHz...")
    try:
        from pyocd.core.helpers import ConnectHelper
        from pyocd.flash.file_programmer import FileProgrammer
        with ConnectHelper.session_with_chosen_probe(
            options={"target_override": target, "frequency": 4_000_000},
        ) as session:
            FileProgrammer(session).program(firmware_path, base_address=0x08000000)
            session.board.target.reset()
        return True
    except ImportError:
        err("pyocd not installed. Run: pip install pyocd --break-system-packages")
        return False
    except Exception as e:
        err(f"Flash failed: {e}")
        info("Troubleshooting:")
        info("  - 'Target not found': install the target pack: pyocd pack install stm32f429zi")
        info("  - 'No connected probes': check USB connection and udev rules")
        info("  - 'Transfer fault': check SWD wiring if using an external probe")
        return False


# ── Operations ────────────────────────────────────────────────────────────────

def op_probe_info():
    heading("Probe Info")
    info("Listing connected pyocd debug probes (ST-Link enumeration)...")
    probes = _pyocd_probes()
    if probes is None:
        return
    if not probes:
        warn("No probes detected by pyocd.")
        info("Fallback: running 'pyocd list'...")
        run_streaming(["pyocd", "list"], on_line=lambda l: info(l), timeout=20)
        return
    for p in probes:
        info(f"  Probe:       {p.description}")
        info(f"  Unique ID:   {p.unique_id}")
        info(f"  Vendor:      {getattr(p, 'vendor_name', 'N/A')}")
    ok(f"Found {len(probes)} probe(s).")


def op_install_target_pack():
    heading("Install Target Pack")
    info("pyocd uses CMSIS-Pack target descriptions to know how to program a specific MCU.")
    info("The stm32f429zi pack contains flash algorithms and memory maps for the F429ZI.")
    info("Step 1: Updating pack index from internet (downloads pack index file)...")
    rc = run_streaming(["pyocd", "pack", "update"], on_line=lambda l: info(l), timeout=120)
    if rc != 0:
        warn(f"pyocd pack update exited with code {rc}.")
        info("If update fails: check internet connectivity or proxy settings.")
    info(f"Step 2: Installing pack for target: {PYOCD_TARGET}...")
    rc = run_streaming(
        ["pyocd", "pack", "install", PYOCD_TARGET],
        on_line=lambda l: info(l), timeout=120,
    )
    if rc == 0:
        ok(f"Pack installed: {PYOCD_TARGET}")
        info("You can now flash/debug the STM32F429ZI.")
    else:
        err(f"Pack install failed (exit code {rc}).")
        info("Troubleshooting:")
        info("  - Try: pyocd pack find stm32f429  (to check available variants)")
        info("  - Try: pyocd pack install STM32F429ZITx  (alternate name)")


def op_erase_chip():
    heading("Erase Chip")
    info(f"Performing a full chip erase on {PYOCD_TARGET}.")
    info("This will erase all flash memory including the application and any stored data.")
    if not confirm(f"Erase entire flash on {PYOCD_TARGET}?", default=False):
        info("Erase cancelled.")
        return
    rc = run_streaming(
        ["pyocd", "erase", "--chip", "-t", PYOCD_TARGET],
        on_line=lambda l: info(l), timeout=60,
    )
    if rc == 0:
        ok("Chip erase complete.")
    else:
        err(f"Chip erase failed (exit code {rc}).")
        info("If target not found: install pack first (option 2 in menu).")


def op_flash_firmware():
    heading("Flash Firmware (pyocd)")
    info("Flashing via pyocd FileProgrammer — supports .bin, .hex, and .elf formats.")
    info(".bin: requires correct base address (0x08000000 for STM32F429ZI flash)")
    info(".hex/.elf: address info is embedded in the file")
    fw_path = prompt("Path to firmware file (.bin/.hex/.elf)")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    info(f"Flashing {fw_path} via pyocd FileProgrammer...")
    if _flash_firmware(fw_path):
        ok("Firmware flashed and target reset.")
    else:
        err("Firmware flash failed.")


def op_flash_stflash():
    heading("Flash via st-flash")
    info("st-flash is part of the stlink-tools package — an alternative to pyocd for .bin files.")
    info("It communicates with the ST-Link directly without needing CMSIS-Pack target descriptions.")
    if not ensure_system_tool(
        "st-flash",
        "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    ):
        return
    fw_path = prompt("Path to .bin firmware file")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    address = prompt("Flash start address (hex)", default="0x08000000")
    info(f"Running: st-flash write {fw_path} {address}")
    info("Expected: progress bar showing pages written and verified.")
    rc = run_streaming(
        ["st-flash", "write", fw_path, address],
        on_line=lambda l: info(l), timeout=120,
    )
    if rc == 0:
        ok("st-flash write complete.")
    else:
        err(f"st-flash exited with code {rc}.")
        info("Troubleshooting:")
        info("  - 'STLINK_SWDCLK_TOO_FAST': try lower frequency with --freq=100k")
        info("  - 'Target voltage too low': check VCC connection on SWD header")
        info("  - 'Flash locked': run st-flash erase first")


def op_verify_flash():
    heading("Verify Flash")
    info("Reads back the flashed firmware and compares it to the source file.")
    info("A passing verification confirms the flash operation was successful.")
    fw_path = prompt("Path to firmware file to verify (.bin/.hex/.elf)")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    rc = run_streaming(
        ["pyocd", "flash", "--verify", "-t", PYOCD_TARGET, fw_path],
        on_line=lambda l: info(l), timeout=120,
    )
    if rc == 0:
        ok("Flash verification passed.")
    else:
        err(f"Verification failed or mismatched (exit code {rc}).")
        info("If mismatch: reflash the firmware — the write may have been interrupted.")


def op_read_memory():
    heading("Read Memory")
    info("Reads raw bytes from the target's address space via SWD.")
    info("Useful for dumping flash contents, reading registers, or checking SRAM.")
    addr_str = prompt("Start address (hex, e.g. 0x08000000)")
    len_str  = prompt("Length in bytes (decimal, e.g. 256)", default="256")
    try:
        addr   = int(addr_str, 16)
        length = int(len_str)
    except ValueError:
        err("Invalid address or length.")
        return
    info(f"Reading {length} bytes from 0x{addr:08X}...")
    try:
        from pyocd.core.helpers import ConnectHelper
        with ConnectHelper.session_with_chosen_probe(
            options={"target_override": PYOCD_TARGET, "frequency": 4_000_000},
        ) as session:
            data = session.board.target.read_memory_block8(addr, length)
        # Hex dump
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part  = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            info(f"  0x{addr+i:08X}:  {hex_part:<48}  {ascii_part}")
        ok(f"Read {length} bytes from 0x{addr:08X}.")
    except ImportError:
        err("pyocd not installed.")
    except Exception as e:
        err(f"Memory read failed: {e}")


def op_reset_target():
    heading("Reset Target")
    info("Sends a hardware reset signal to the target via ST-Link SWD.")
    info("The target will reboot and start running its firmware.")
    try:
        from pyocd.core.helpers import ConnectHelper
        with ConnectHelper.session_with_chosen_probe(
            options={"target_override": PYOCD_TARGET, "frequency": 4_000_000},
        ) as session:
            session.board.target.reset()
        ok("Target reset.")
    except ImportError:
        err("pyocd not installed.")
    except Exception as e:
        err(f"Reset failed: {e}")


def op_gdb_server():
    heading("Start GDB Server")
    info("Starting pyocd GDB server on port 3333 (Ctrl-C to stop)...")
    info("Connect with GDB:")
    info("  arm-none-eabi-gdb firmware.elf")
    info("  (gdb) target extended-remote :3333")
    info("  (gdb) monitor reset halt")
    info("  (gdb) load  (optional: reflash)")
    info("  (gdb) continue")
    info("Troubleshooting GDB connection:")
    info("  - 'Remote connection closed': ensure pyocd is still running")
    info("  - 'No symbol table': compile with -g flag")
    info("  - Breakpoints not working: check that the target is halted before setting breakpoints")
    try:
        proc = subprocess.Popen(
            ["pyocd", "gdbserver", "-t", PYOCD_TARGET, "--port", "3333"],
        )
        proc.wait()
    except FileNotFoundError:
        err("pyocd not found in PATH.")
    except KeyboardInterrupt:
        info("GDB server stopped.")


def op_vcp_console():
    heading("VCP Console (USART3 Bridge)")
    info("The Nucleo ST-Link exposes a Virtual COM Port (VCP) bridged to the MCU's USART3.")
    info("Default settings: 115200 baud, 8N1, no flow control.")
    port = find_serial_port_by_vidpid(VID_PID_STLINK)
    if port:
        info(f"VCP serial port: {port}")
        info("Use the Shell tab for an interactive UART console (USART3 bridge).")
        info("Suggested command:")
        info(f"  screen {port} 115200")
        info("  (or: minicom -D {port} -b 115200 -8)")
        info("  (or: picocom -b 115200 {port})")
    else:
        warn("No VCP serial port detected for the Nucleo ST-Link interface.")
        info("Ensure the Nucleo is connected via CN1 (ST-Link USB) and the VCP driver is active.")
        info("On Linux, check: ls /dev/ttyACM*")


def op_install_udev():
    heading("Install ST-Link udev Rules (Linux)")
    info("udev rules allow non-root users to access the ST-Link USB device.")
    info("Without these rules, pyocd and st-flash require root (sudo).")
    info(f"Source: {UDEV_RULES_SRC}")
    info(f"Destination: {UDEV_RULES_DST}")
    if not confirm("Install ST-Link udev rules and reload udevadm?", default=True):
        info("Cancelled.")
        return
    _install_stlink_udev()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    info("Checking and installing required packages...")
    info("APT packages: python3-serial (pyserial), stlink-tools (st-flash, st-info, st-util)")
    ensure_apt_packages(["python3-serial", "stlink-tools"])

    info("PIP package: pyocd (ARM CoreSight SWD debugger — not in apt)")
    ensure_pip_packages([
        ("pyocd",   "pyocd"),
    ])

    ensure_system_tool(
        "st-flash",
        "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    )
    ensure_system_tool(
        "st-info",
        "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    )

    print_banner(TOOL_NAME, DESCRIPTION)

    found = web_detect_loop(detect_nucleo, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Nucleo-F429ZI not detected. Exiting.")
        sys.exit(1)

    ok("Nucleo-F429ZI detected.")

    check_firmware_version()

    MENU_OPTIONS = [
        "Probe Info",
        "Install Target Pack",
        "Erase Chip",
        "Flash Firmware (pyocd)",
        "Flash via st-flash",
        "Verify Flash",
        "Read Memory",
        "Reset Target",
        "Start GDB Server",
        "VCP Console (USART3 bridge)",
        "Install ST-Link udev Rules (Linux)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Nucleo-F429ZI — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_probe_info()
        elif choice == 1:
            op_install_target_pack()
        elif choice == 2:
            op_erase_chip()
        elif choice == 3:
            op_flash_firmware()
        elif choice == 4:
            op_flash_stflash()
        elif choice == 5:
            op_verify_flash()
        elif choice == 6:
            op_read_memory()
        elif choice == 7:
            op_reset_target()
        elif choice == 8:
            op_gdb_server()
        elif choice == 9:
            op_vcp_console()
        elif choice == 10:
            op_install_udev()
        elif choice == 11:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
