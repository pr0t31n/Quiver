#!/usr/bin/env python3
"""
ST-Link V2 Tool Manager
Handles SWD debug/flash for ARM Cortex-M targets via pyocd and st-flash/st-info.

USB VID:PIDs:
  0x0483:0x3748  ST-Link V2 standalone
  0x0483:0x374B  ST-Link V2-1 (also on Nucleo/Discovery boards)
  0x0483:0x374E  ST-Link V3E
  0x0483:0x374F  ST-Link V3S

Usage:
    python3 stlink_v2.py
"""

import sys

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
    info("Reading ST-Link probe firmware version via 'st-info --probe'…")
    current = None
    try:
        import subprocess as _sp
        result = _sp.run(["st-info", "--probe"], capture_output=True, text=True, timeout=15)
        for line in (result.stdout + result.stderr).splitlines():
            low = line.lower()
            if "firmware" in low or "version" in low or "v" in low:
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    current = parts[1].strip()
                    break
    except FileNotFoundError:
        warn("'st-info' not found. Install stlink-tools: sudo apt install stlink-tools")
    except Exception as e:
        warn(f"Could not run 'st-info --probe': {e}")

    if current:
        ok(f"ST-Link firmware: {current}")
    else:
        info("Could not auto-detect ST-Link firmware version from st-info output.")
        info("To update ST-Link V2 firmware: use STSW-LINK007 via STM32CubeProgrammer (Windows GUI only).")

    latest, url = check_latest_github_release("stlink-org", "stlink")
    if latest:
        announce_firmware_update(TOOL_NAME, current, latest, url)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "ST-Link V2"
DESCRIPTION = "ST-Link V2/V2-1/V3 SWD/JTAG programmer for STM32 and other ARM Cortex-M MCUs"

VID_PIDS = [
    (0x0483, 0x3748),  # V2 standalone
    (0x0483, 0x374B),  # V2-1
    (0x0483, 0x374E),  # V3E
    (0x0483, 0x374F),  # V3S
]

UDEV_RULES_SRC = "/usr/share/stlink/udev/rules.d/49-stlink.rules"
UDEV_RULES_DST = "/etc/udev/rules.d/49-stlink.rules"

CONNECT_INSTRUCTIONS = (
    "ST-Link V2 not detected.\n\n"
    "  1. Connect ST-Link V2 via USB\n"
    "  2. Wire SWD to target:\n"
    "     SWDIO  → target SWDIO\n"
    "     SWDCLK → target SWDCLK\n"
    "     GND    → target GND\n"
    "     3.3V   → target VCC (only if powering target from ST-Link)\n"
    "  3. Linux: install udev rules (see menu or run once):\n"
    "     sudo cp /usr/share/stlink/udev/rules.d/49-stlink.rules /etc/udev/rules.d/\n"
    "     sudo udevadm control --reload-rules\n"
    "     sudo usermod -aG plugdev $USER\n"
    "  4. Install pyocd: pip install pyocd --break-system-packages\n\n"
    "  V2 VID:PID 0483:3748 | V2-1 VID:PID 0483:374B | V3: 0483:374E/374F\n\n"
    "  Note: ST-Link V2 firmware can only be updated via ST's STSW-LINK007 GUI tool."
)

# ── State ─────────────────────────────────────────────────────────────────────

current_target: str = ""  # e.g. "stm32f103c8"

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_stlink() -> bool:
    return detect_usb_libusb_any(VID_PIDS)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_target() -> bool:
    if not current_target:
        warn("No target MCU set. Use option 3 (Set Target MCU) first.")
        return False
    return True


def _run_pyocd(args: list, timeout: int = 60) -> int:
    cmd = ["pyocd"] + args
    info(f"Running: {' '.join(cmd)}")
    return run_streaming(cmd, on_line=lambda l: info(l), timeout=timeout)


def _install_stlink_udev():
    """Install ST-Link udev rules from stlink-tools package."""
    import os
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        warn("udev rules only apply on Linux.")
        return
    import shutil
    src = UDEV_RULES_SRC
    dst = UDEV_RULES_DST
    if not os.path.exists(src):
        warn(f"ST-Link rules not found at {src}.")
        info("Install stlink-tools first: sudo apt install stlink-tools")
        info("Alternatively, create a minimal rule:")
        info("  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"0483\", MODE=\"0666\", GROUP=\"plugdev\"' \\")
        info("    | sudo tee /etc/udev/rules.d/49-stlink.rules")
        return
    info(f"Copying {src} → {dst}")
    r = sudo_run(f"cp {src} {dst} && udevadm control --reload-rules && udevadm trigger")
    if r.returncode == 0:
        ok("ST-Link udev rules installed and reloaded.")
        info("Unplug and reconnect the ST-Link for the rules to take effect.")
    else:
        err("Failed to install udev rules.")
        err((r.stdout + r.stderr).strip()[:300])


# ── Operations ────────────────────────────────────────────────────────────────

def op_probe_info():
    heading("Probe Info")
    info("Reading ST-Link probe details via st-info (from stlink-tools package)...")
    info("Expected output: serial number, firmware version, chip ID of the connected target.")
    ensure_system_tool(
        "st-info",
        "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    )
    rc = run_streaming(["st-info", "--probe"], on_line=lambda l: info(l), timeout=20)
    if rc != 0:
        warn("st-info --probe returned non-zero. Falling back to pyocd list...")
        info("If st-info shows no probes: check udev rules and USB connection.")
        _run_pyocd(["list"], timeout=20)


def op_list_targets():
    heading("List pyocd Targets (stm32)")
    info("Querying pyocd target database — filtered to STM32 entries.")
    info("Use the target name shown here as input for 'Set Target MCU'.")
    import subprocess
    try:
        result = subprocess.run(
            ["pyocd", "list", "--targets"],
            capture_output=True, text=True, timeout=30,
        )
        lines = result.stdout.splitlines() + result.stderr.splitlines()
        stm_lines = [l for l in lines if "stm32" in l.lower() or "STM32" in l]
        if stm_lines:
            for l in stm_lines:
                info(l)
            ok(f"Found {len(stm_lines)} STM32 target(s) in database.")
        else:
            for l in lines[:60]:
                info(l)
            info("(Use grep/search for 'stm32' in the list above.)")
            info("If list is empty: run 'Install Target Pack' (option 11) first.")
    except FileNotFoundError:
        err("pyocd not found in PATH.")
        info("Install: pip install pyocd --break-system-packages")
    except subprocess.TimeoutExpired:
        err("pyocd list --targets timed out.")


def op_set_target():
    global current_target
    heading("Set Target MCU")
    info("The target MCU name is used by pyocd to select the correct flash algorithm.")
    info("Examples: stm32f103c8  stm32f407vg  stm32l476rg  stm32h743xi")
    info("The name must match a pyocd target pack entry. Run 'List pyocd Targets' to browse.")
    name = prompt("Target MCU name", default=current_target or "stm32f103c8")
    if name:
        current_target = name.strip().lower()
        ok(f"Target set to: {current_target}")
    else:
        warn("No target entered; target unchanged.")


def op_erase_chip():
    heading("Erase Target Chip")
    if not _require_target():
        return
    info(f"Performing a full chip erase on target: {current_target}")
    info("This erases all flash sectors including read-protection pages (if unlocked).")
    if not confirm(f"Erase entire flash on {current_target}?", default=False):
        info("Erase cancelled.")
        return
    rc = _run_pyocd(["erase", "--chip", "-t", current_target], timeout=60)
    if rc == 0:
        ok("Chip erase complete.")
    else:
        warn(f"pyocd erase returned {rc}. Trying st-flash erase...")
        info("st-flash erase attempts to unlock and erase via mass-erase command.")
        rc2 = run_streaming(["st-flash", "erase"], on_line=lambda l: info(l), timeout=60)
        if rc2 == 0:
            ok("st-flash erase complete.")
        else:
            err("Erase failed via both pyocd and st-flash.")
            info("Troubleshooting:")
            info("  - Target may be read-protected: use STM32CubeProgrammer to unlock")
            info("  - Check SWD wiring: SWDIO, SWDCLK, GND must be connected")


def op_flash_bin():
    heading("Flash Firmware (.bin)")
    info("Uses st-flash to write a raw binary to the target at a specified address.")
    info("For most STM32 targets, flash starts at 0x08000000.")
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
    info("Expected: progress output showing pages written, then verification result.")
    rc = run_streaming(
        ["st-flash", "write", fw_path, address],
        on_line=lambda l: info(l), timeout=120,
    )
    if rc == 0:
        ok("st-flash write complete.")
    else:
        err(f"st-flash exited with code {rc}.")
        info("Troubleshooting flash failures:")
        info("  - 'STLINK_SWDCLK_TOO_FAST': add --freq=100k to slow down")
        info("  - 'Flash locked / option bytes': erase with mass-erase first")
        info("  - 'Target voltage': check that target VCC is present")
        info("  - Verify address matches target flash start (0x08000000 for most STM32)")


def op_flash_hex_elf():
    heading("Flash Firmware (.hex/.elf)")
    if not _require_target():
        return
    info("Uses pyocd to flash .hex or .elf files (address info embedded in file).")
    info("pyocd reads the target pack to select the correct flash algorithm.")
    fw_path = prompt("Path to .hex or .elf firmware file")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    rc = _run_pyocd(["flash", "-t", current_target, fw_path], timeout=120)
    if rc == 0:
        ok("Firmware flashed via pyocd.")
    else:
        err(f"pyocd flash exited with code {rc}.")
        info("Troubleshooting:")
        info("  - 'Target not found': run 'Install Target Pack' first")
        info("  - 'No connected probes': check USB and udev rules")
        info("  - Try erasing the chip first, then reflash")


def op_verify_flash():
    heading("Verify Flash")
    if not _require_target():
        return
    info("Reads back flash contents and compares to the source file byte-by-byte.")
    info("A passing verification confirms the firmware was written correctly.")
    fw_path = prompt("Path to firmware file to verify")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    rc = _run_pyocd(["flash", "--verify", "-t", current_target, fw_path], timeout=120)
    if rc == 0:
        ok("Flash verification passed.")
    else:
        err(f"Verification failed (exit code {rc}).")
        info("Mismatch may indicate: incomplete flash, wrong firmware file, or bad flash sector.")


def op_read_flash():
    heading("Read Flash")
    if not _require_target():
        return
    info("Reads a region of flash memory from the target.")
    info("Output is saved to a binary file for offline analysis.")
    addr_str = prompt("Start address (hex, e.g. 0x08000000)", default="0x08000000")
    len_str  = prompt("Length in bytes (decimal)", default="1024")
    out_path = prompt("Output file path", default="/tmp/flash_dump.bin")
    info(f"Running pyocd read {addr_str} +{len_str} → {out_path}...")
    rc = _run_pyocd(
        ["commander", "-t", current_target, "-c",
         f"read32 {addr_str} {len_str} > {out_path}"],
        timeout=60,
    )
    if rc == 0:
        ok(f"Flash read complete → {out_path}")
    else:
        warn(f"pyocd commander returned {rc}. Check output above.")


def op_reset_target():
    heading("Reset Target")
    if not _require_target():
        return
    info("Sending hardware reset signal to target via ST-Link SWD.")
    rc = _run_pyocd(["commander", "-t", current_target, "-c", "reset run"], timeout=20)
    if rc == 0:
        ok("Target reset.")
    else:
        err(f"Reset failed (exit code {rc}).")


def op_gdb_server():
    heading("Start GDB Server")
    if not _require_target():
        return
    info(f"Starting pyocd GDB server for {current_target} on port 3333 (Ctrl-C to stop)...")
    info("Connecting with arm-none-eabi-gdb:")
    info("  arm-none-eabi-gdb firmware.elf")
    info("  (gdb) target extended-remote :3333")
    info("  (gdb) monitor reset halt")
    info("  (gdb) load  (reflash from gdb)")
    info("  (gdb) break main  (set breakpoint)")
    info("  (gdb) continue")
    info("Troubleshooting GDB connection:")
    info("  - 'Could not connect': ensure pyocd GDB server is still running on port 3333")
    info("  - 'Protocol error': try 'target remote :3333' instead of 'extended-remote'")
    info("  - Semihosting: add --enable-semihosting flag to pyocd gdbserver if needed")
    import subprocess
    try:
        proc = subprocess.Popen(
            ["pyocd", "gdbserver", "-t", current_target, "--port", "3333"],
        )
        proc.wait()
    except FileNotFoundError:
        err("pyocd not found in PATH.")
    except KeyboardInterrupt:
        info("GDB server stopped.")


def op_install_pack():
    heading("Install Target Pack")
    if not _require_target():
        return
    info("pyocd uses CMSIS-Pack files to know how to flash a specific MCU.")
    info("The pack includes flash algorithms, memory maps, and register definitions.")
    # Derive family prefix (e.g. stm32f1 from stm32f103c8)
    family = current_target[:7] if len(current_target) >= 7 else current_target
    info(f"Installing pyocd pack for family: {family}...")
    info("Step 1: pyocd pack update (downloads index from internet)")
    _run_pyocd(["pack", "update"], timeout=120)
    info(f"Step 2: pyocd pack install {family}")
    rc = _run_pyocd(["pack", "install", family], timeout=120)
    if rc == 0:
        ok(f"Pack installed: {family}")
        info("You can now flash/debug targets in this MCU family.")
    else:
        err(f"Pack install failed (exit code {rc}).")
        info("Troubleshooting:")
        info(f"  - Try the full target name: pyocd pack install {current_target}")
        info("  - Check internet connectivity for pack index download")
        info("  - Run: pyocd pack find stm32  (to see available variants)")


def op_install_udev():
    heading("Install ST-Link udev Rules (Linux)")
    info("udev rules allow non-root users to access the ST-Link USB device.")
    info("Without these rules, pyocd and st-flash require root privileges.")
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
    info("APT packages: python3-serial, stlink-tools (st-flash, st-info), python3-usb (pyusb)")
    ensure_apt_packages(["python3-serial", "stlink-tools", "python3-usb"])

    info("PIP package: pyocd (ARM SWD debugger — not in apt)")
    ensure_pip_packages([
        ("pyocd", "pyocd"),
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

    found = web_detect_loop(detect_stlink, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("ST-Link V2 not detected. Exiting.")
        sys.exit(1)

    ok("ST-Link detected.")

    check_firmware_version()

    MENU_OPTIONS = [
        "Probe Info",
        "List pyocd Targets (stm32)",
        "Set Target MCU",
        "Erase Target Chip",
        "Flash Firmware (.bin) via st-flash",
        "Flash Firmware (.hex/.elf) via pyocd",
        "Verify Flash",
        "Read Flash",
        "Reset Target",
        "Start GDB Server",
        "Install Target Pack",
        "Install ST-Link udev Rules (Linux)",
        "Exit",
    ]

    while True:
        target_label = f"  [target: {current_target or '(not set)'}]"
        choice = numbered_menu(f"ST-Link V2 — Main Menu{target_label}", MENU_OPTIONS)

        if choice == 0:
            op_probe_info()
        elif choice == 1:
            op_list_targets()
        elif choice == 2:
            op_set_target()
        elif choice == 3:
            op_erase_chip()
        elif choice == 4:
            op_flash_bin()
        elif choice == 5:
            op_flash_hex_elf()
        elif choice == 6:
            op_verify_flash()
        elif choice == 7:
            op_read_flash()
        elif choice == 8:
            op_reset_target()
        elif choice == 9:
            op_gdb_server()
        elif choice == 10:
            op_install_pack()
        elif choice == 11:
            op_install_udev()
        elif choice == 12:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
