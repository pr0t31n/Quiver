#!/usr/bin/env python3
"""
J-Link EDU Mini Tool Manager
Handles SWD flash/debug, RTT console, and GDB server via SEGGER pylink-square.

USB VID:PIDs:
  0x1366:0x0101  J-Link EDU
  0x1366:0x0105  J-Link EDU (also CDC)
  0x1366:0x1015  J-Link EDU Mini

LICENSE: J-Link EDU Mini is for personal/educational use only.

Usage:
    python3 jlink_edu_mini.py
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
)


def check_firmware_version():
    heading("Firmware Version Check")
    info("Reading J-Link EDU Mini firmware version via pylink-square…")
    current = None
    try:
        import pylink
        jl = pylink.JLink()
        jl.open()
        current = str(jl.firmware_version)
        jl.close()
    except ImportError:
        warn("pylink-square not installed. Install: pip install pylink-square --break-system-packages")
    except Exception as e:
        warn(f"Could not read J-Link firmware version: {e}")

    if current:
        ok(f"J-Link EDU Mini firmware: {current}")
    else:
        info("Could not auto-detect J-Link EDU Mini firmware version.")

    info("")
    info("J-Link EDU Mini firmware updates require the SEGGER J-Link Software:")
    info("  1. Download from: https://www.segger.com/downloads/jlink/")
    info("  2. Run 'JLinkExe' and type 'erase' then 'exit' — or use J-Link Commander")
    info("  3. Or: open J-Link Configurator (GUI) → select device → Update Firmware")
    info("  4. macOS: brew install --cask segger-jlink  then run J-Link Configurator")
    info("  5. IMPORTANT: J-Link EDU Mini is for personal/educational use only")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "J-Link EDU Mini"
DESCRIPTION = "SEGGER J-Link EDU Mini SWD debugger — educational/personal use only"

VID_PIDS = [
    (0x1366, 0x0101),
    (0x1366, 0x0105),
    (0x1366, 0x1015),
]

JLINK_MAX_SPEED = 4000  # kHz — EDU Mini hardware limit

CONNECT_INSTRUCTIONS = (
    "J-Link EDU Mini not detected.\n\n"
    "  1. Connect J-Link EDU Mini via USB\n"
    "  2. Install SEGGER J-Link Software (required for pylink-square DLL):\n"
    "     macOS:  brew install --cask segger-jlink\n"
    "     Linux:  Download from https://www.segger.com/downloads/jlink/\n"
    "             Choose 'J-Link Software and Documentation Pack' (.deb for Debian/Ubuntu)\n"
    "             sudo dpkg -i JLink_Linux_*.deb\n"
    "  3. Install Python binding: pip install pylink-square --break-system-packages\n"
    "  4. Connect SWD pins to target:\n"
    "     Pin 1: VTref (target 3.3V)\n"
    "     Pin 2: SWDIO\n"
    "     Pin 4: SWDCLK\n"
    "     Pin 3/5: GND\n"
    "  5. Linux udev rule for J-Link (run once):\n"
    "     echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1366\", MODE=\"0666\", GROUP=\"plugdev\"' \\\n"
    "       | sudo tee /etc/udev/rules.d/99-jlink.rules\n"
    "     sudo udevadm control --reload-rules\n"
    "  6. EDU Mini license: personal/educational use only\n\n"
    "  VID:PID 1366:0101 / 1366:0105 / 1366:1015"
)

DLL_NOTE = (
    "SEGGER J-Link Software not installed or DLL not found.\n"
    "pylink-square requires the SEGGER J-Link DLL to communicate with the hardware.\n\n"
    "Installation:\n"
    "  macOS:   brew install --cask segger-jlink\n"
    "  Linux:   Download .deb from https://www.segger.com/downloads/jlink/\n"
    "           sudo dpkg -i JLink_Linux_*.deb\n"
    "           DLL location after install: /opt/SEGGER/JLink/libjlinkarm.so\n"
    "  Windows: Run the installer from the SEGGER website\n\n"
    "After installing, restart this script.\n"
    "If pylink-square still cannot find the DLL, set the environment variable:\n"
    "  export JLINK_SDK_PATH=/opt/SEGGER/JLink"
)

UDEV_NOTE = (
    "Linux udev rule for J-Link (all variants VID 1366:xxxx):\n"
    "  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1366\", MODE=\"0666\", GROUP=\"plugdev\"' \\\n"
    "    | sudo tee /etc/udev/rules.d/99-jlink.rules\n"
    "  sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "  sudo usermod -aG plugdev $USER  (then log out/in)\n\n"
    "Alternatively, SEGGER installs their own udev rules when you install the .deb package:\n"
    "  /etc/udev/rules.d/99-jlink.rules"
)

# ── State ─────────────────────────────────────────────────────────────────────

current_target: str = ""  # e.g. "STM32F103C8"

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_jlink() -> bool:
    return detect_usb_libusb_any(VID_PIDS)


# ── pylink helpers ────────────────────────────────────────────────────────────

def _open_jlink():
    """Open and return a configured JLink instance, or None on failure."""
    info("Opening J-Link connection via pylink-square...")
    try:
        import pylink
        jl = pylink.JLink()
        jl.open()
        jl.set_tif(pylink.enums.JLinkInterfaces.SWD)
        jl.set_speed(JLINK_MAX_SPEED)
        return jl
    except ImportError:
        err("pylink-square not installed.")
        info("Install: pip install pylink-square --break-system-packages")
        return None
    except Exception as e:
        msg = str(e)
        if "dll" in msg.lower() or "library" in msg.lower() or "dylib" in msg.lower() or "so" in msg.lower():
            err("J-Link DLL/library not found.")
            info(DLL_NOTE)
        elif "usb" in msg.lower() or "access" in msg.lower() or "permission" in msg.lower():
            err(f"USB access error: {e}")
            info("Check udev rules and plugdev group membership.")
            info(UDEV_NOTE)
        else:
            err(f"Failed to open J-Link: {e}")
            info("If this is a 'No J-Link found' error: check USB connection and udev rules.")
        return None


def _require_target() -> bool:
    if not current_target:
        warn("No target set. Use option 2 (Set Target) first.")
        return False
    return True


# ── Operations ────────────────────────────────────────────────────────────────

def op_probe_info():
    heading("Probe Info")
    info("Reading J-Link EDU Mini probe details (firmware, serial, hardware version)...")
    jl = _open_jlink()
    if jl is None:
        return
    try:
        info(f"  Product name:      {jl.product_name}")
        info(f"  Serial number:     {jl.serial_number}")
        info(f"  Firmware version:  {jl.firmware_version}")
        info(f"  Hardware version:  {jl.hardware_version}")
        info(f"  Speed:             {JLINK_MAX_SPEED} kHz (EDU Mini max)")
        ok("Probe info retrieved.")
    except Exception as e:
        err(f"Could not read probe info: {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_set_target():
    global current_target
    heading("Set Target")
    info("The target name must match a SEGGER device database entry.")
    info("It is case-sensitive and must be an exact match.")
    info("Examples: STM32F103C8  STM32F429ZI  nRF52840_xxAA  ATSAMD21G18  RP2040_Core0")
    info("Full device database: https://www.segger.com/products/debug-probes/j-link/technology/supported-devices/")
    name = prompt("Target chip name (SEGGER database name)", default=current_target or "STM32F103C8")
    if name:
        current_target = name.strip()
        ok(f"Target set to: {current_target}")
    else:
        warn("No target entered; target unchanged.")


def op_connect_target():
    heading("Connect to Target")
    if not _require_target():
        return
    info(f"Connecting to {current_target} via SWD at {JLINK_MAX_SPEED} kHz...")
    info("A successful connection reads the target's CPU ID register.")
    info("Failure usually means: wrong target name, bad SWD wiring, or target not powered.")
    jl = _open_jlink()
    if jl is None:
        return
    try:
        jl.connect(current_target)
        info(f"  Target:    {current_target}")
        info(f"  SWD speed: {JLINK_MAX_SPEED} kHz")
        ok(f"Connected to {current_target}.")
    except Exception as e:
        err(f"Connection failed: {e}")
        info("Troubleshooting connection failures:")
        info("  - Check SWDIO, SWDCLK, GND, VTref wiring")
        info("  - Verify target name matches SEGGER device database exactly")
        info("  - Ensure target is powered (check VTref pin reads correct voltage)")
        info("  - Some targets require a reset during connect: check J-Link docs")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_erase_flash():
    heading("Erase Target Flash")
    if not _require_target():
        return
    info(f"Performing full flash erase on {current_target}.")
    info("This erases all program memory — the target will not run any firmware afterwards.")
    if not confirm(f"Erase flash on {current_target}?", default=False):
        info("Erase cancelled.")
        return
    jl = _open_jlink()
    if jl is None:
        return
    try:
        jl.connect(current_target)
        jl.erase()
        ok("Flash erase complete.")
    except Exception as e:
        err(f"Erase failed: {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_flash_firmware():
    heading("Flash Firmware")
    if not _require_target():
        return
    info("Flashing firmware via J-Link flash_file API.")
    info("Supports .bin, .hex, and .elf files.")
    info("For .bin files, you must provide the correct base address.")
    fw_path = prompt("Path to firmware file (.bin/.hex/.elf)")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    addr_str = prompt("Base address (hex)", default="0x08000000")
    try:
        addr = int(addr_str, 16)
    except ValueError:
        err(f"Invalid address: {addr_str}")
        return
    info(f"Flashing {fw_path} at 0x{addr:08X} via J-Link...")
    info("Expected: J-Link progress messages showing sectors erased and programmed.")
    jl = _open_jlink()
    if jl is None:
        return
    try:
        jl.connect(current_target)
        info(f"Flashing {fw_path} at 0x{addr:08X}...")
        jl.flash_file(fw_path, addr)
        jl.reset(ms=50, halt=False)
        ok("Firmware flashed and target reset.")
    except Exception as e:
        err(f"Flash failed: {e}")
        info("Troubleshooting:")
        info("  - 'Flash programming failed': check target name and address")
        info("  - 'Target not connected': verify SWD wiring")
        info("  - Try erasing first before reflashing")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_verify_flash():
    heading("Verify Flash")
    if not _require_target():
        return
    info("Reads back flash memory and compares to source file.")
    fw_path = prompt("Path to firmware file to verify")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    addr_str = prompt("Base address (hex)", default="0x08000000")
    try:
        addr = int(addr_str, 16)
    except ValueError:
        err(f"Invalid address: {addr_str}")
        return
    jl = _open_jlink()
    if jl is None:
        return
    try:
        jl.connect(current_target)
        info(f"Verifying {fw_path} at 0x{addr:08X}...")

        def _progress(action, prog_str, byte_count):
            info(f"  {action}: {prog_str} ({byte_count} bytes)")

        jl.flash_file(fw_path, addr, on_progress=_progress)
        ok("Verification complete (flash_file with progress).")
    except Exception as e:
        err(f"Verify failed: {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_reset_target():
    heading("Reset Target")
    if not _require_target():
        return
    info("Sending hardware reset to target via J-Link.")
    jl = _open_jlink()
    if jl is None:
        return
    try:
        jl.connect(current_target)
        jl.reset(ms=50, halt=False)
        ok("Target reset (normal boot).")
    except Exception as e:
        err(f"Reset failed: {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_halt_resume():
    heading("Halt / Resume")
    if not _require_target():
        return
    sub_options = [
        "Halt",
        "Resume",
        "Reset + Halt",
        "Cancel",
    ]
    choice = numbered_menu("Halt/Resume Action", sub_options)
    if choice == 3:
        info("Cancelled.")
        return
    jl = _open_jlink()
    if jl is None:
        return
    try:
        jl.connect(current_target)
        if choice == 0:
            jl.halt()
            ok("Target halted.")
        elif choice == 1:
            jl.restart()
            ok("Target resumed.")
        elif choice == 2:
            jl.reset(ms=50, halt=True)
            ok("Target reset and halted.")
    except Exception as e:
        err(f"Operation failed: {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_read_memory():
    heading("Read Memory")
    if not _require_target():
        return
    info("Reads a block of memory from the target (SRAM, flash, peripheral registers).")
    addr_str = prompt("Start address (hex, e.g. 0x20000000)")
    len_str  = prompt("Length in bytes (decimal, e.g. 64)", default="64")
    try:
        addr   = int(addr_str, 16)
        length = int(len_str)
    except ValueError:
        err("Invalid address or length.")
        return
    jl = _open_jlink()
    if jl is None:
        return
    try:
        jl.connect(current_target)
        words  = jl.memory_read32(addr, (length + 3) // 4)
        # Flatten to bytes
        data = []
        for w in words:
            data += [(w >> (8 * i)) & 0xFF for i in range(4)]
        data = data[:length]
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part   = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            info(f"  0x{addr+i:08X}:  {hex_part:<48}  {ascii_part}")
        ok(f"Read {length} bytes from 0x{addr:08X}.")
    except Exception as e:
        err(f"Memory read failed: {e}")
    finally:
        try:
            jl.close()
        except Exception:
            pass


def op_rtt_console():
    heading("RTT Console")
    if not _require_target():
        return
    info("SEGGER RTT (Real-Time Transfer) allows printf-style debug output over SWD.")
    info("The target firmware must have SEGGER RTT support compiled in.")
    info("RTT library: https://www.segger.com/products/debug-probes/j-link/technology/about-real-time-transfer/")
    info("Starting RTT console (Ctrl-C to stop)...")
    info("Troubleshooting RTT:")
    info("  - 'No RTT control block found': firmware may not have RTT initialized")
    info("  - 'RTT channel 0 not found': RTT buffer may not be flushed yet")
    info("  - Ensure target is running (not halted) when starting RTT")
    jl = _open_jlink()
    if jl is None:
        return
    try:
        import time
        jl.connect(current_target)
        jl.rtt_start()
        ok("RTT started. Reading channel 0...")
        while True:
            data = jl.rtt_read(0, 512)
            if data:
                text = bytes(data).decode("utf-8", errors="replace")
                for line in text.splitlines():
                    info(line)
            time.sleep(0.05)
    except KeyboardInterrupt:
        info("RTT console stopped.")
    except Exception as e:
        err(f"RTT failed: {e}")
        info("Check that RTT is initialized in firmware and the target is running.")
    finally:
        try:
            jl.rtt_stop()
        except Exception:
            pass
        try:
            jl.close()
        except Exception:
            pass


def op_gdb_server():
    heading("Start GDB Server")
    if not _require_target():
        return
    import subprocess
    info(f"Starting JLinkGDBServer for {current_target} on port 3333 (Ctrl-C to stop)...")
    info("Connect with GDB:")
    info("  arm-none-eabi-gdb firmware.elf")
    info("  (gdb) target extended-remote :3333")
    info("  (gdb) monitor reset halt")
    info("  (gdb) load  (optional: reflash)")
    info("  (gdb) continue")
    info("Troubleshooting JLinkGDBServer:")
    info("  - 'Cannot connect to J-Link': check USB and udev rules")
    info("  - 'Device not supported': verify target name in SEGGER device database")
    info("  - Port conflict: change --port if 3333 is already in use")
    info("  - On Linux: ensure SEGGER J-Link software is installed (.deb)")
    try:
        proc = subprocess.Popen([
            "JLinkGDBServer",
            "-device", current_target,
            "-if", "SWD",
            "-speed", str(JLINK_MAX_SPEED),
            "-port", "3333",
        ])
        proc.wait()
    except FileNotFoundError:
        err("JLinkGDBServer not found in PATH.")
        info(DLL_NOTE)
    except KeyboardInterrupt:
        info("GDB server stopped.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    info("Checking and installing required packages...")
    info("APT package: python3-usb (pyusb for USB detection)")
    ensure_apt_packages(["python3-usb"])

    info("PIP package: pylink-square (SEGGER J-Link Python binding — not in apt)")
    info("Note: pylink-square requires the SEGGER J-Link Software to be installed separately.")
    ensure_pip_packages([
        ("pylink", "pylink-square"),
    ])

    info("Checking for JLinkExe (SEGGER J-Link Software)...")
    ensure_system_tool(
        "JLinkExe",
        "Download from https://www.segger.com/downloads/jlink/\n"
        "  Choose 'J-Link Software and Documentation Pack' for your OS.\n"
        "  macOS: brew install --cask segger-jlink\n"
        "  Linux: sudo dpkg -i JLink_Linux_*.deb  (installs to /opt/SEGGER/JLink)\n"
        "  After install, JLinkExe and JLinkGDBServer will be in PATH.",
        # No apt_pkg — JLink is NOT in apt
    )

    if get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        info("Linux udev note for J-Link:")
        info(UDEV_NOTE)

    print_banner(TOOL_NAME, DESCRIPTION)
    warn("J-Link EDU Mini is licensed for personal/educational use only.")

    found = web_detect_loop(detect_jlink, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("J-Link EDU Mini not detected. Exiting.")
        sys.exit(1)

    ok("J-Link EDU Mini detected.")

    check_firmware_version()

    MENU_OPTIONS = [
        "Probe Info",
        "Set Target",
        "Connect to Target",
        "Erase Target Flash",
        "Flash Firmware",
        "Verify Flash",
        "Reset Target",
        "Halt / Resume",
        "Read Memory",
        "RTT Console",
        "Start GDB Server",
        "Exit",
    ]

    while True:
        target_label = f"  [target: {current_target or '(not set)'}]"
        choice = numbered_menu(f"J-Link EDU Mini — Main Menu{target_label}", MENU_OPTIONS)

        if choice == 0:
            op_probe_info()
        elif choice == 1:
            op_set_target()
        elif choice == 2:
            op_connect_target()
        elif choice == 3:
            op_erase_flash()
        elif choice == 4:
            op_flash_firmware()
        elif choice == 5:
            op_verify_flash()
        elif choice == 6:
            op_reset_target()
        elif choice == 7:
            op_halt_resume()
        elif choice == 8:
            op_read_memory()
        elif choice == 9:
            op_rtt_console()
        elif choice == 10:
            op_gdb_server()
        elif choice == 11:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
