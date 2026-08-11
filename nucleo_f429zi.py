#!/usr/bin/env python3
"""
STM32 Nucleo-F429ZI Tool Manager
Handles SWD debug/flash via pyocd and VCP serial console (USART3 bridge), plus a
MikroE Click Shield (mikroBUS) pentest subsystem: autodetect/configure Clicks in
sockets 1-4 and sniff / inject / flood / replay their buses (CAN, RS-485, RS-232,
802.15.4/XBee, UWB, NFC) through companion firmware, with built-in diagnostics.

USB VID:PID (ST-Link V2-1): 0x0483:0x374B  (debugger + VCP + MSD composite)
USB VID:PID (user CDC):     0x0483:0x5740

Usage:
    python3 nucleo_f429zi.py
"""

import os
import sys
import json
import time
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
    get_firmware_dir, selected_firmware_payload, run_firmware_payload,
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


def _flash_stflash_bin(fw_path: str, address: str = "0x08000000") -> bool:
    """Shared st-flash core: write a raw .bin at *address*. Reused by the menu op
    and the firmware payload."""
    info(f"Running: st-flash write {fw_path} {address}")
    info("Expected: progress bar showing pages written and verified.")
    rc = run_streaming(
        ["st-flash", "write", fw_path, address],
        on_line=lambda l: info(l), timeout=120,
    )
    if rc == 0:
        ok("st-flash write complete.")
        return True
    err(f"st-flash exited with code {rc}.")
    info("Troubleshooting:")
    info("  - 'STLINK_SWDCLK_TOO_FAST': try lower frequency with --freq=100k")
    info("  - 'Target voltage too low': check VCC connection on SWD header")
    info("  - 'Flash locked': run st-flash erase first")
    return False


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
    _flash_stflash_bin(fw_path, address)


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


# ── Click Shield (mikroBUS) pentest subsystem ──────────────────────────────────
#
# Assumed physical chain:
#     Nucleo-F429ZI  ->  MIKROE Click Shield for Nucleo-144  ->  Click(s) in
#     mikroBUS socket 1-4.
#
# The STM32 drives each Click's bus (SPI / I2C / UART / GPIO) and bridges it to
# this host tool over the ST-Link Virtual COM Port (USART3). That requires the
# companion "Quiver Click" firmware on the STM32, implementing the line protocol
# below. Flash it with "Flash Click Firmware".
#
# Host -> MCU  (one ASCII command per line, '\n'-terminated):
#   PING                                  -> PONG QCLICK-FW <ver>
#   SCAN                                  -> per socket: "SOCK <n> <chip|none> <bus>"
#   SELFTEST <sock>                       -> "OK ..." / "ERR ..." (bus health)
#   STATUS                                -> per-socket populated click + link state
#   CFG <sock> <click> [k=v ...]          -> bind a click to a socket + params
#   SNIFF <sock> [count]                  -> stream frames: "RX <sock> <us> <hex>"
#   STOP <sock>                           -> stop an active sniff/flood
#   TX <sock> <hex>                       -> transmit one frame (injection)
#   FLOOD <sock> <hex> <count> [gap_ms]   -> repeated TX (flood / DoS)
#   AT <sock> <command>                   -> pass-through for modem clicks
#   NFC <sock> READ|EMULATE|RELAY         -> NFC 2 Click actions
#   UWB <sock> RANGE|RELAY                -> UWB 3 Click actions
# MCU -> Host:  "OK ...", "ERR ...", "PONG ...", "RX <sock> <us> <hex>",
#               "SOCK <n> <chip> <bus>"
#
# Every ACTIVE operation (inject / flood / replay / emulate / relay) is gated
# behind an authorisation confirmation — use only against in-scope assets.
# Cellular RF jamming/DoS is intentionally NOT provided (illegal).

CLICK_CFG_DIR  = os.path.expanduser("~/.quiver")
CLICK_CFG_PATH = os.path.join(CLICK_CFG_DIR, "click_shield_config.json")
CLICK_CAP_DIR  = os.path.join(CLICK_CFG_DIR, "click_captures")
CLICK_FW_ENV   = "QUIVER_CLICK_FW"          # optional path override for companion fw
CLICK_SOCKETS  = ["1", "2", "3", "4"]       # Click Shield for Nucleo-144 sockets

# Registry of the Click boards this rig supports. "frame" selects the wire format
# used by sniff/inject/replay; "caps" gates which pentest ops are offered.
CLICKS = {
    "can_spi": {
        "name": "CAN SPI Click", "bus": "SPI", "chip": "MCP2515 + MCP2551",
        "frame": "can", "caps": ["sniff", "inject", "flood", "replay"],
        "params": {"bitrate": 500000, "mode": "normal"},
        "note": "CAN 2.0 frames as <id_hex>#<data_hex>. flood = bus DoS.",
    },
    "rs485_8": {
        "name": "RS485 8 Click", "bus": "UART", "chip": "RS-485 transceiver",
        "frame": "serial", "caps": ["sniff", "inject", "flood", "replay"],
        "params": {"baud": 115200, "half_duplex": True},
        "note": "Half-duplex differential serial (Modbus/DMX/industrial).",
    },
    "rs232_4": {
        "name": "RS232 4 Click", "bus": "UART", "chip": "RS-232 transceiver",
        "frame": "serial", "caps": ["sniff", "inject", "replay"],
        "params": {"baud": 115200},
        "note": "Point-to-point RS-232 (console/management ports).",
    },
    "xbee_2": {
        "name": "XBee 2 Click", "bus": "UART", "chip": "Digi XBee (IEEE 802.15.4)",
        "frame": "ieee802154", "caps": ["sniff", "inject", "flood", "replay"],
        "params": {"channel": 15, "panid": "0x1234", "api_mode": 2},
        "note": "2.4 GHz 802.15.4 / DigiMesh. flood = channel/PAN DoS.",
    },
    "uwb_3": {
        "name": "UWB 3 Click", "bus": "SPI", "chip": "Qorvo DW3000",
        "frame": "uwb", "caps": ["sniff", "range", "relay"],
        "params": {"channel": 5, "preamble": 9},
        "note": "802.15.4z HRP UWB — ranging capture and relay-attack testing.",
    },
    "nfc_2": {
        "name": "NFC 2 Click", "bus": "I2C", "chip": "NXP PN7150",
        "frame": "nfc", "caps": ["sniff", "emulate", "relay"],
        "params": {"tech": "A"},
        "note": "13.56 MHz NFC — read, tag emulation, and reader<->card relay.",
    },
    "5g_nb_iot": {
        "name": "5G NB IoT Click", "bus": "UART", "chip": "NB-IoT cellular modem",
        "frame": "at", "caps": ["at", "enum"],
        "params": {"apn": "", "baud": 115200},
        "note": "Connectivity/AT enumeration only. RF jamming/DoS is illegal and "
                "is intentionally NOT provided.",
    },
    "shuttle": {
        "name": "Shuttle Click", "bus": "passive", "chip": "-",
        "frame": "-", "caps": [], "params": {},
        "note": "mikroBUS expansion adapter — carries another Click off-board; "
                "configure the click it hosts, not the shuttle itself.",
    },
}

# Chip signatures the firmware SCAN can report, mapped to a click id. Passive
# transceiver clicks (RS-232/RS-485) expose no queryable chip and stay ambiguous.
CHIP_SIGNATURES = {
    "PN7150": "nfc_2", "DW3000": "uwb_3", "DECA0302": "uwb_3",
    "MCP2515": "can_spi", "XBEE": "xbee_2", "MODEM": "5g_nb_iot", "NBIOT": "5g_nb_iot",
}

# Per-click intermediate troubleshooting hints (shown by diagnostics/self-test).
CLICK_TROUBLESHOOT = {
    "can_spi": ["Needs another CAN node + 120Ω termination at BOTH bus ends.",
                "Bitrate must match the bus (common: 250k/500k).",
                "'mode' must not be 'listen' when injecting/flooding."],
    "rs485_8": ["Check A/B (D+/D-) polarity — swap the pair if no data.",
                "120Ω termination at both ends + fail-safe bias resistors.",
                "Match baud/parity; DE/RE direction timing for half-duplex."],
    "rs232_4": ["TX/RX may be swapped (straight vs null-modem).",
                "Match baud/parity/stop bits; confirm a common ground."],
    "xbee_2":  ["Match channel + PAN ID + API mode to the target network.",
                "Use 802.15.4 XBee firmware for raw sniffing (not Zigbee).",
                "Antenna attached; adequate 3V3 rail."],
    "uwb_3":   ["Needs a UWB peer/anchor to range against.",
                "Match channel/preamble/PRF with the peer.",
                "DW3000 device-ID reads 0xDECA0302 — else check SPI CS/wiring."],
    "nfc_2":   ["Place a tag/card in the field for READ; a second reader for RELAY.",
                "PN7150 on I2C 0x28; check I2C + IRQ/VEN jumpers.",
                "Nearby metal detunes the RF field."],
    "5g_nb_iot": ["Insert an activated NB-IoT SIM; attach the cellular antenna.",
                "Set the correct APN; check AT+CSQ / AT+CEREG? for coverage.",
                "RF jamming/DoS is NOT supported (illegal)."],
}


def _default_click_config():
    return {"vcp_baud": 115200, "sockets": {s: None for s in CLICK_SOCKETS}}


def _load_click_config():
    try:
        with open(CLICK_CFG_PATH) as f:
            cfg = json.load(f)
    except (FileNotFoundError, ValueError):
        return _default_click_config()
    cfg.setdefault("vcp_baud", 115200)
    cfg.setdefault("sockets", {})
    for s in CLICK_SOCKETS:
        cfg["sockets"].setdefault(s, None)
    return cfg


def _save_click_config(cfg):
    os.makedirs(CLICK_CFG_DIR, exist_ok=True)
    with open(CLICK_CFG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    ok(f"Configuration saved: {CLICK_CFG_PATH}")


def _open_click_serial(cfg):
    port = find_serial_port_by_vidpid(VID_PID_STLINK)
    if not port:
        err("No Nucleo VCP serial port found (VID:PID 0483:374B).")
        return None
    try:
        import serial
    except ImportError:
        err("pyserial not installed. Run: pip install pyserial --break-system-packages")
        return None
    try:
        ser = serial.Serial(port, cfg.get("vcp_baud", 115200), timeout=1)
        time.sleep(0.2)
        ser.reset_input_buffer()
        return ser
    except Exception as e:
        err(f"Could not open {port}: {e}")
        info("  Close other apps using the port (screen/minicom); check dialout group.")
        return None


def _click_cmd(ser, line, read_replies=True, timeout=2.0):
    """Send one command line; return list of reply lines (until OK/ERR/PONG)."""
    ser.write((line.strip() + "\n").encode())
    ser.flush()
    replies = []
    if not read_replies:
        return replies
    end = time.time() + timeout
    while time.time() < end:
        raw = ser.readline()
        if not raw:
            continue
        txt = raw.decode(errors="replace").strip()
        if txt:
            replies.append(txt)
            if txt.startswith(("OK", "ERR", "PONG")):
                break
    return replies


def _click_fw_present(cfg):
    """Return (present, banner) by PINGing the companion firmware."""
    ser = _open_click_serial(cfg)
    if not ser:
        return False, None
    try:
        replies = _click_cmd(ser, "PING", timeout=2.0)
    finally:
        ser.close()
    for r in replies:
        if r.startswith("PONG"):
            return True, r
    return False, None


def _click_scan(cfg):
    """Ask firmware to probe each socket. Returns {sock: {'chip','bus','click'}} or None."""
    ser = _open_click_serial(cfg)
    if not ser:
        return None
    try:
        replies = _click_cmd(ser, "SCAN", timeout=5.0)
    finally:
        ser.close()
    found = {}
    for r in replies:
        parts = r.split()
        if len(parts) >= 3 and parts[0] == "SOCK":
            sock, chip = parts[1], parts[2]
            bus = parts[3] if len(parts) >= 4 else "?"
            click = None
            up = chip.upper()
            for sig, cid in CHIP_SIGNATURES.items():
                if sig in up:
                    click = cid
                    break
            found[sock] = {"chip": chip, "bus": bus, "click": click}
    return found


def _configured_sockets(cfg):
    return [(s, cfg["sockets"][s]) for s in CLICK_SOCKETS if cfg["sockets"].get(s)]


def _pick_socket(cfg, need_cap=None):
    populated = _configured_sockets(cfg)
    if need_cap:
        populated = [(s, e) for (s, e) in populated
                     if need_cap in CLICKS.get(e["click"], {}).get("caps", [])]
    if not populated:
        warn("No configured socket" + (f" supports '{need_cap}'." if need_cap else "."))
        info("Run 'Autodetect Shield & Clicks' or 'Configure Shield' first.")
        return None, None
    labels = [f"Socket {s}: {CLICKS[e['click']]['name']}" for (s, e) in populated]
    idx = numbered_menu("Select socket", labels + ["Cancel"])
    if idx == len(populated):
        return None, None
    return populated[idx]


def _authz_gate(action):
    warn(f"{action} is an ACTIVE operation — it transmits onto the target bus/RF.")
    warn("Only run against assets explicitly in scope for the engagement.")
    return confirm("Confirm the target is authorised and in scope?", default=False)


def _click_push_config(cfg):
    """Best-effort push of socket bindings to the firmware, if it is present."""
    present, _ = _click_fw_present(cfg)
    if not present:
        info("Companion Click firmware not detected — config saved locally only.")
        info("Flash it via 'Flash Click Firmware', then re-run to push the binding.")
        return
    ser = _open_click_serial(cfg)
    if not ser:
        return
    try:
        for s, entry in _configured_sockets(cfg):
            kv = " ".join(f"{k}={v}" for k, v in entry.get("params", {}).items())
            rep = _click_cmd(ser, f"CFG {s} {entry['click']} {kv}".strip())
            info(f"  socket {s}: {' '.join(rep) if rep else '(no reply)'}")
    finally:
        ser.close()
    ok("Pushed socket bindings to Click firmware.")


def op_click_autodetect():
    heading("Autodetect Shield & Clicks")
    info("Chain: Nucleo -> Click Shield for Nucleo-144 -> Click(s) in socket 1-4.")
    info("The Click Shield itself is a PASSIVE board with no ID chip — it is inferred")
    info("from the Nucleo + any Clicks detected on the mikroBUS sockets. Clicks are")
    info("probed by the firmware over their bus (SPI ID / I2C addr / UART response);")
    info("passive RS-232/RS-485 transceivers have no queryable chip and need manual")
    info("confirmation.")
    cfg = _load_click_config()
    present, banner = _click_fw_present(cfg)
    if not present:
        warn("Companion Click firmware not detected — cannot probe sockets.")
        info("Flash it via 'Flash Click Firmware', then re-run autodetect.")
        info("Meanwhile you can set sockets by hand via 'Configure Shield'.")
        return
    ok(f"Click firmware: {banner}")
    found = _click_scan(cfg)
    if not found:
        warn("SCAN returned nothing. Use 'Run Diagnostics' to localise the fault.")
        return
    info("Detected per socket:")
    any_click = False
    for s in CLICK_SOCKETS:
        d = found.get(s)
        if not d or d.get("chip", "none").lower() == "none":
            info(f"  Socket {s}: empty")
            continue
        if d.get("click"):
            any_click = True
            info(f"  Socket {s}: {CLICKS[d['click']]['name']}  (chip {d['chip']}, {d['bus']})")
        else:
            info(f"  Socket {s}: UART/passive device on {d['bus']} — chip {d['chip']} "
                 f"(RS232 4 or RS485 8; confirm manually)")
    if not any_click and not any(d and d.get("chip", "none").lower() != "none"
                                 for d in found.values()):
        warn("No Clicks found on any socket.")
        info("If a Click is seated: check its power-select jumper (3V3/5V), bus-select")
        info("jumpers, and full insertion — then re-run, or use 'Run Diagnostics'.")
        return
    ok("Shield inferred present (Nucleo + Clicks detected).")
    if not confirm("Write detected Clicks into the configuration?", default=True):
        return
    for s in CLICK_SOCKETS:
        d = found.get(s) or {}
        if d.get("click"):
            cfg["sockets"][s] = {"click": d["click"],
                                 "params": dict(CLICKS[d["click"]].get("params", {}))}
        elif d.get("chip", "none").lower() not in ("none", ""):
            opts = ["RS232 4 Click", "RS485 8 Click", "(leave empty)"]
            idx = numbered_menu(f"Socket {s}: unidentified UART device — which Click?", opts)
            if idx == 0:
                cfg["sockets"][s] = {"click": "rs232_4", "params": dict(CLICKS["rs232_4"]["params"])}
            elif idx == 1:
                cfg["sockets"][s] = {"click": "rs485_8", "params": dict(CLICKS["rs485_8"]["params"])}
    _save_click_config(cfg)
    _click_push_config(cfg)


def op_click_configure():
    heading("Configure Click Shield")
    info("Chain: Nucleo-F429ZI -> Click Shield for Nucleo-144 -> Click(s) in socket 1-4.")
    info("Tip: 'Autodetect Shield & Clicks' can populate most of this automatically.")
    cfg = _load_click_config()
    baud = prompt("VCP link baud (host<->Nucleo)", default=str(cfg.get("vcp_baud", 115200)))
    try:
        cfg["vcp_baud"] = int(baud)
    except ValueError:
        warn("Invalid baud; keeping previous.")
    click_ids = list(CLICKS.keys())
    for s in CLICK_SOCKETS:
        cur = cfg["sockets"].get(s)
        cur_label = CLICKS[cur["click"]]["name"] if cur else "empty"
        info("")
        info(f"mikroBUS socket {s} (currently: {cur_label})")
        opts = [CLICKS[c]["name"] for c in click_ids] + ["(leave empty)"]
        idx = numbered_menu(f"Assign Click to socket {s}", opts)
        if idx == len(click_ids):
            cfg["sockets"][s] = None
            continue
        cid = click_ids[idx]
        info(f"  {CLICKS[cid]['name']} — {CLICKS[cid]['note']}")
        params = dict(CLICKS[cid].get("params", {}))
        for k, v in list(params.items()):
            nv = prompt(f"    {k}", default=str(v))
            if isinstance(v, bool):
                params[k] = nv.strip().lower() in ("1", "true", "yes", "y", "on")
            elif isinstance(v, int):
                try:
                    params[k] = int(nv)
                except ValueError:
                    params[k] = v
            else:
                params[k] = nv
        cfg["sockets"][s] = {"click": cid, "params": params}
    _save_click_config(cfg)
    _click_push_config(cfg)


def op_click_show():
    heading("Click Shield — Current Config")
    cfg = _load_click_config()
    info(f"Config file : {CLICK_CFG_PATH}")
    info(f"VCP baud    : {cfg.get('vcp_baud', 115200)}")
    any_pop = False
    for s in CLICK_SOCKETS:
        entry = cfg["sockets"].get(s)
        if not entry:
            info(f"  Socket {s}: (empty)")
            continue
        any_pop = True
        c = CLICKS.get(entry["click"], {})
        info(f"  Socket {s}: {c.get('name', entry['click'])}  [{c.get('bus', '?')}]  "
             f"caps={','.join(c.get('caps', [])) or '-'}")
        for k, v in entry.get("params", {}).items():
            info(f"      {k} = {v}")
    if not any_pop:
        info("  (no sockets configured — run 'Autodetect' or 'Configure Shield')")
    present, banner = _click_fw_present(cfg)
    if present:
        ok(f"Companion Click firmware: {banner}")
    else:
        warn("Companion Click firmware not detected (PING got no PONG).")


def op_click_detect_fw():
    heading("Detect Click Firmware")
    cfg = _load_click_config()
    info("Sending PING to the Nucleo over the VCP link…")
    present, banner = _click_fw_present(cfg)
    if present:
        ok(f"Click firmware responding: {banner}")
    else:
        warn("No PONG from the companion Click firmware.")
        info("  - Flash it via 'Flash Click Firmware'.")
        info("  - Confirm the VCP baud matches the firmware (Configure Shield).")
        info("  - Confirm the Nucleo is on CN1 (ST-Link USB), then 'Reset Target'.")


def op_click_flash_fw():
    heading("Flash Click Firmware")
    info("Flashes the companion 'Quiver Click' firmware that drives the mikroBUS")
    info("peripherals and speaks the host command protocol over USART3/VCP.")
    info("It is board/socket-specific — build it from the Quiver Click firmware source")
    info("for the F429ZI, or point to a prebuilt image below.")
    default_fw = os.environ.get(CLICK_FW_ENV, "")
    fw_path = prompt("Path to Click firmware (.bin/.hex/.elf)", default=default_fw)
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    if _flash_firmware(fw_path):
        ok("Click firmware flashed and target reset.")
        info("Run 'Detect Click Firmware' to confirm it answers PING.")
    else:
        err("Flash failed. See 'Run Diagnostics' stage 1-2 for probe/SWD issues.")


def op_click_sniff():
    heading("Sniff (Click Shield)")
    cfg = _load_click_config()
    s, entry = _pick_socket(cfg, need_cap="sniff")
    if not entry:
        return
    c = CLICKS[entry["click"]]
    info(f"Sniffing socket {s} — {c['name']} ({c['frame']} frames). {c['note']}")
    present, _ = _click_fw_present(cfg)
    if not present:
        warn("Companion Click firmware not detected — cannot sniff. Flash it first.")
        return
    os.makedirs(CLICK_CAP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    cap_path = os.path.join(CLICK_CAP_DIR, f"sniff_sock{s}_{entry['click']}_{ts}.cap")
    count = prompt("Frame count (blank = until Ctrl-C)", default="")
    ser = _open_click_serial(cfg)
    if not ser:
        return
    info(f"Writing captured frames to: {cap_path}")
    info("Press Ctrl-C to stop.")
    n = 0
    limit = int(count) if count.strip().isdigit() else None
    try:
        with open(cap_path, "w") as capf:
            _click_cmd(ser, f"SNIFF {s} {count}".strip(), read_replies=False)
            while True:
                raw = ser.readline()
                if not raw:
                    continue
                txt = raw.decode(errors="replace").strip()
                if not txt:
                    continue
                if txt.startswith("RX"):
                    capf.write(txt + "\n")
                    capf.flush()
                    n += 1
                    info(f"  [{n}] {txt}")
                    if limit and n >= limit:
                        break
                elif txt.startswith(("OK", "ERR")):
                    info(f"  {txt}")
    except KeyboardInterrupt:
        info("Sniff stopped by user.")
    finally:
        try:
            _click_cmd(ser, f"STOP {s}", read_replies=False)
        except Exception:
            pass
        ser.close()
    if n == 0:
        warn("No frames captured.")
        for hint in CLICK_TROUBLESHOOT.get(entry["click"], []):
            info(f"  - {hint}")
    else:
        ok(f"Captured {n} frame(s) -> {cap_path}")


def op_click_inject():
    heading("Inject Frame (Click Shield)")
    cfg = _load_click_config()
    s, entry = _pick_socket(cfg, need_cap="inject")
    if not entry:
        return
    c = CLICKS[entry["click"]]
    info(f"Socket {s} — {c['name']} ({c['frame']}). {c['note']}")
    frame = prompt("Frame to transmit (hex; CAN uses <id>#<data>)")
    if not frame:
        warn("No frame provided.")
        return
    if not _authz_gate("Injection"):
        info("Aborted — not authorised.")
        return
    present, _ = _click_fw_present(cfg)
    if not present:
        warn("Companion Click firmware not detected. Flash it first.")
        return
    ser = _open_click_serial(cfg)
    if not ser:
        return
    try:
        for r in _click_cmd(ser, f"TX {s} {frame}"):
            info(f"  {r}")
    finally:
        ser.close()
    ok("Injection sent.")


def op_click_flood():
    heading("Flood / DoS (Click Shield)")
    warn("This transmits repeatedly and can disrupt the target bus/RF (denial of service).")
    cfg = _load_click_config()
    s, entry = _pick_socket(cfg, need_cap="flood")
    if not entry:
        return
    c = CLICKS[entry["click"]]
    info(f"Socket {s} — {c['name']} ({c['frame']}). {c['note']}")
    frame = prompt("Frame to repeat (hex; CAN <id>#<data>)")
    if not frame:
        warn("No frame provided.")
        return
    count = prompt("Repeat count", default="1000")
    gap = prompt("Inter-frame gap ms (0 = as fast as possible)", default="0")
    if not _authz_gate("Flood / DoS"):
        info("Aborted — not authorised.")
        return
    present, _ = _click_fw_present(cfg)
    if not present:
        warn("Companion Click firmware not detected. Flash it first.")
        return
    ser = _open_click_serial(cfg)
    if not ser:
        return
    try:
        for r in _click_cmd(ser, f"FLOOD {s} {frame} {count} {gap}".strip(), timeout=5.0):
            info(f"  {r}")
    finally:
        ser.close()
    ok("Flood command dispatched.")


def op_click_replay():
    heading("Replay Capture (Click Shield)")
    cfg = _load_click_config()
    s, entry = _pick_socket(cfg, need_cap="replay")
    if not entry:
        return
    cap_path = prompt("Path to capture file (from Sniff)")
    if not cap_path:
        warn("No path provided.")
        return
    import pathlib
    if not pathlib.Path(cap_path).exists():
        err(f"File not found: {cap_path}")
        return
    frames = []
    for line in open(cap_path):
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0] == "RX":
            try:
                frames.append((int(parts[2]), parts[3]))
            except ValueError:
                continue
    if not frames:
        warn("No 'RX <sock> <us> <hex>' frames parsed from capture.")
        return
    info(f"Parsed {len(frames)} frame(s) from {cap_path}.")
    preserve = confirm("Preserve original inter-frame timing?", default=True)
    if not _authz_gate("Replay"):
        info("Aborted — not authorised.")
        return
    present, _ = _click_fw_present(cfg)
    if not present:
        warn("Companion Click firmware not detected. Flash it first.")
        return
    ser = _open_click_serial(cfg)
    if not ser:
        return
    sent = 0
    prev_us = None
    try:
        for us, hexf in frames:
            if preserve and prev_us is not None:
                delay = (us - prev_us) / 1_000_000.0
                if 0 < delay < 30:
                    time.sleep(delay)
            prev_us = us
            _click_cmd(ser, f"TX {s} {hexf}", read_replies=False)
            sent += 1
            if sent % 50 == 0:
                info(f"  replayed {sent}/{len(frames)}")
    except KeyboardInterrupt:
        info("Replay interrupted.")
    finally:
        ser.close()
    ok(f"Replayed {sent} frame(s) on socket {s}.")


def op_click_special():
    heading("Click-Specific Tools")
    cfg = _load_click_config()
    s, entry = _pick_socket(cfg)
    if not entry:
        return
    cid = entry["click"]
    c = CLICKS[cid]
    present, _ = _click_fw_present(cfg)
    if not present:
        warn("Companion Click firmware not detected. Flash it first.")
        return
    ser = _open_click_serial(cfg)
    if not ser:
        return
    try:
        if cid == "nfc_2":
            actions = ["Poll/read tag", "Emulate tag", "Relay reader<->card", "Cancel"]
            i = numbered_menu("NFC 2 Click", actions)
            cmds = {0: f"NFC {s} READ", 1: f"NFC {s} EMULATE", 2: f"NFC {s} RELAY"}
            if i in cmds:
                if i in (1, 2) and not _authz_gate("NFC " + actions[i]):
                    return
                for r in _click_cmd(ser, cmds[i], timeout=5.0):
                    info(f"  {r}")
        elif cid == "uwb_3":
            actions = ["Passive range capture", "Relay-attack test", "Cancel"]
            i = numbered_menu("UWB 3 Click", actions)
            cmds = {0: f"UWB {s} RANGE", 1: f"UWB {s} RELAY"}
            if i in cmds:
                if i == 1 and not _authz_gate("UWB relay"):
                    return
                for r in _click_cmd(ser, cmds[i], timeout=5.0):
                    info(f"  {r}")
        elif cid == "5g_nb_iot":
            info("NB-IoT: AT pass-through (connectivity/enumeration only — no RF DoS).")
            at = prompt("AT command", default="AT+CSQ")
            for r in _click_cmd(ser, f"AT {s} {at}", timeout=5.0):
                info(f"  {r}")
        else:
            info(f"No click-specific tools for {c['name']}.")
            info("Use the generic Sniff / Inject / Flood / Replay operations.")
    finally:
        ser.close()


def op_click_diagnose():
    heading("Click Shield — Diagnostics")
    info("Walking the chain Nucleo -> VCP -> firmware -> shield -> clicks, stage by")
    info("stage. The FIRST failing stage is where to focus.")
    cfg = _load_click_config()
    fails = []

    info("")
    info("[1/6] Nucleo / ST-Link presence…")
    if detect_nucleo():
        ok("  Nucleo ST-Link detected on USB (0483:374B).")
    else:
        err("  Nucleo not detected on USB.")
        info("   basic : use CN1 (ST-Link), NOT CN13 (USER); try another cable/port.")
        info("   inter : Linux — install ST-Link udev rules (main menu); check")
        info("           'lsusb | grep 0483' and 'dmesg | tail'.")
        fails.append(1)

    info("")
    info("[2/6] VCP serial link (USART3 bridge)…")
    port = find_serial_port_by_vidpid(VID_PID_STLINK)
    if port:
        ok(f"  VCP serial port: {port}")
        ser = _open_click_serial(cfg)
        if ser:
            ok(f"  Opened {port} at {cfg.get('vcp_baud', 115200)} baud.")
            ser.close()
        else:
            err("  Port present but could not be opened.")
            info("   basic : close other apps using it (screen/minicom/Arduino IDE).")
            info("   inter : add your user to 'dialout' and re-login; 'ls -l /dev/ttyACM*'.")
            fails.append(2)
    else:
        err("  No VCP serial port found.")
        info("   basic : confirm the Nucleo enumerates (stage 1) and shows /dev/ttyACM*.")
        info("   inter : some ST-Link firmware hides the VCP — update ST-Link fw / CDC driver.")
        fails.append(2)

    info("")
    info("[3/6] Companion Click firmware (PING)…")
    present, banner = _click_fw_present(cfg)
    if present:
        ok(f"  Firmware responding: {banner}")
    else:
        err("  No PONG from Click firmware.")
        info("   basic : flash it via 'Flash Click Firmware', then 'Reset Target'.")
        info("   inter : baud mismatch — set VCP baud to the firmware's (Configure Shield);")
        info("           if it flashed but is silent, the app may have crashed on boot.")
        fails.append(3)

    info("")
    info("[4/6] Shield + mikroBUS socket probe (SCAN)…")
    found = None
    if present:
        found = _click_scan(cfg)
        if found and any(d.get("chip", "none").lower() != "none" for d in found.values()):
            ok("  Shield inferred present; Clicks responded on at least one socket:")
            for s in CLICK_SOCKETS:
                d = found.get(s) or {}
                chip = d.get("chip", "none")
                if chip.lower() != "none":
                    tail = f" -> {CLICKS[d['click']]['name']}" if d.get("click") else " (UART/passive)"
                    info(f"    Socket {s}: chip {chip} ({d.get('bus', '?')}){tail}")
        else:
            err("  No Clicks responded on any socket.")
            info("   basic : reseat the shield on the Nucleo headers; reseat each Click fully.")
            info("   inter : check each Click's power-select jumper (3V3/5V) and SPI/I2C")
            info("           bus-select jumpers; confirm the populated socket matches config.")
            fails.append(4)
    else:
        warn("  Skipped — firmware not responding (fix stage 3 first).")

    info("")
    info("[5/6] Config vs. detected consistency…")
    configured = _configured_sockets(cfg)
    if not configured:
        warn("  No sockets configured. Run 'Autodetect' or 'Configure Shield'.")
    elif found:
        mism = False
        for s, entry in configured:
            d = found.get(s) or {}
            det = d.get("click")
            if det and det != entry["click"]:
                warn(f"  Socket {s}: configured {CLICKS[entry['click']]['name']} "
                     f"but detected {CLICKS[det]['name']}.")
                mism = True
            elif d.get("chip", "none").lower() == "none":
                warn(f"  Socket {s}: configured {CLICKS[entry['click']]['name']} "
                     f"but nothing detected there.")
                mism = True
        if not mism:
            ok("  Configuration matches detected hardware.")
        else:
            info("   fix : re-run 'Autodetect' to sync, or correct 'Configure Shield'.")
    else:
        warn("  Skipped — no SCAN data.")

    info("")
    info("[6/6] Per-socket self-test…")
    if present and configured:
        ser = _open_click_serial(cfg)
        if ser:
            try:
                for s, entry in configured:
                    reps = _click_cmd(ser, f"SELFTEST {s}", timeout=5.0)
                    line = " ".join(reps) if reps else "(no reply)"
                    cid = entry["click"]
                    if reps and any(r.startswith("OK") for r in reps):
                        ok(f"  Socket {s} {CLICKS[cid]['name']}: {line}")
                    else:
                        err(f"  Socket {s} {CLICKS[cid]['name']}: {line}")
                        for hint in CLICK_TROUBLESHOOT.get(cid, []):
                            info(f"     - {hint}")
            finally:
                ser.close()
    else:
        warn("  Skipped — need firmware + at least one configured socket.")

    info("")
    if not fails:
        ok("Diagnostics complete — core chain is healthy.")
    else:
        warn(f"Diagnostics complete — first issue at stage {min(fails)}. Fix that, then re-run.")


def op_click_shield_menu():
    heading("Click Shield (mikroBUS) — Pentest Toolkit")
    info("Chain: Nucleo-F429ZI -> Click Shield for Nucleo-144 -> Click(s) in socket 1-4.")
    info("Sniff / inject / flood / replay run through the companion Click firmware over")
    info("the VCP link. Active operations are gated behind an authorisation prompt.")
    SUB = [
        "Autodetect Shield & Clicks",
        "Configure Shield (assign clicks to sockets)",
        "Show Current Config",
        "Detect Click Firmware (PING)",
        "Run Diagnostics / Troubleshoot",
        "FIRMWARE - Flash Click Firmware",
        "Sniff a socket",
        "Inject frame",
        "Flood / DoS",
        "Replay capture",
        "Click-specific tools (NFC / UWB / NB-IoT)",
        "Back",
    ]
    while True:
        ch = numbered_menu("Click Shield", SUB)
        if ch == 0:
            op_click_autodetect()
        elif ch == 1:
            op_click_configure()
        elif ch == 2:
            op_click_show()
        elif ch == 3:
            op_click_detect_fw()
        elif ch == 4:
            op_click_diagnose()
        elif ch == 5:
            op_click_flash_fw()
        elif ch == 6:
            op_click_sniff()
        elif ch == 7:
            op_click_inject()
        elif ch == 8:
            op_click_flood()
        elif ch == 9:
            op_click_replay()
        elif ch == 10:
            op_click_special()
        elif ch == 11:
            break


# ── Firmware payload wiring ────────────────────────────────────────────────────
#
# The main-page firmware payloads flash the companion Click firmware onto the
# STM32F429ZI, reusing the module's existing flash paths (pyocd / st-flash).
# The image is operator-supplied — set QUIVER_CLICK_FW or drop the file in the
# tool's firmware dir; prepare aborts BEFORE the confirmation if none is found.

_NUCLEO_FW_PATH = {"path": ""}


def _nucleo_locate_fw(exts) -> str:
    """Find an operator-supplied firmware image: env override first, then the
    tool's firmware dir (newest file matching one of *exts*)."""
    env = os.environ.get(CLICK_FW_ENV, "").strip()
    if env and os.path.exists(env) and env.lower().endswith(tuple(exts)):
        return env
    fdir = get_firmware_dir("nucleo_f429zi")
    if fdir.exists():
        cands = sorted(p for e in exts for p in fdir.rglob(f"*{e}"))
        if cands:
            return str(cands[-1])
    return ""


def _prep_nucleo_fw(kind: str) -> bool:
    """Firmware-payload PREPARE: locate the operator-supplied Click firmware and
    confirm the flasher is available. Returns True only when the sole remaining
    step is the write; returns False (abort before confirm) if no image is found."""
    if kind == "stflash":
        exts = (".bin",)
        if not ensure_system_tool(
            "st-flash", "apt install stlink-tools  (Kali/Debian/Ubuntu)",
            apt_pkg="stlink-tools",
        ):
            err("  st-flash unavailable — install stlink-tools.")
            return False
    else:
        exts = (".bin", ".hex", ".elf")
        try:
            import pyocd  # noqa: F401
        except ImportError:
            err("  pyocd not installed — run: pip install pyocd --break-system-packages")
            return False

    fw = _nucleo_locate_fw(exts)
    if not fw:
        fdir = get_firmware_dir("nucleo_f429zi")
        err("  No operator-supplied Click firmware found.")
        info(f"  Supply the image ({'/'.join(exts)}) via one of:")
        info(f"    - set {CLICK_FW_ENV}=/path/to/firmware{exts[0]}, or")
        info(f"    - drop the file in {fdir}")
        return False
    ok(f"  Firmware ready: {fw}")
    _NUCLEO_FW_PATH["path"] = fw
    return True


def _dispatch_firmware_payload(fw: dict):
    which = (fw.get("firmware") or "").strip().lower()
    label = fw.get("label", "Flash Firmware")
    if which in ("st-flash", "stflash"):
        run_firmware_payload(
            label,
            info_fn=op_probe_info,
            prepare_fn=lambda: _prep_nucleo_fw("stflash"),
            flash_fn=lambda: _flash_stflash_bin(_NUCLEO_FW_PATH["path"], "0x08000000"),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : Click companion firmware (.bin)",
                "Flasher  : st-flash write @ 0x08000000",
            ],
        )
    else:
        run_firmware_payload(
            label,
            info_fn=op_probe_info,
            prepare_fn=lambda: _prep_nucleo_fw("pyocd"),
            flash_fn=lambda: _flash_firmware(_NUCLEO_FW_PATH["path"]),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : Click companion firmware (.bin/.hex/.elf)",
                f"Flasher  : pyocd FileProgrammer, target {PYOCD_TARGET}",
            ],
        )


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

    # Firmware payload selected on the main page → auto-run (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    MENU_OPTIONS = [
        "Probe Info",
        "Install Target Pack",
        "Erase Chip",
        "FIRMWARE - Flash Firmware (pyocd)",
        "FIRMWARE - Flash via st-flash",
        "Verify Flash",
        "Read Memory",
        "Reset Target",
        "Start GDB Server",
        "VCP Console (USART3 bridge)",
        "Install ST-Link udev Rules (Linux)",
        "Click Shield (mikroBUS) — sniff / inject / replay",
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
            op_click_shield_menu()
        elif choice == 12:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
