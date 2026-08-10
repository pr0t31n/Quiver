#!/usr/bin/env python3
"""
Nordic nRF52840 Development Kit / USB Dongle Tool Manager
Handles device detection (dongle vs DK), BLE sniffing, Zigbee/Thread NCP info,
DFU firmware flashing (dongle), J-Link programming (DK), and firmware management.

Usage:
    python3 nordic_nrf52840.py

USB VID:PIDs:
    0x1915:0x521F — nRF52840 Dongle (DFU bootloader CDC, press RESET to enter)
    0x1915:0x520F — nRF52840 Dongle (application CDC UART)
    0x1366:0x1015 — nRF52840-DK (Segger J-Link JTAG debugger on-board)

Device variants:
    nRF52840 Dongle (PCA10059):
        - Small USB dongle form factor
        - Onboard RGB LED + green LED
        - Press side button briefly to reset, hold side button while inserting to enter DFU
        - DFU bootloader via CDC serial (nrfutil dfu usb-serial)
        - No J-Link — firmware flashing via nrfutil only

    nRF52840-DK (PCA10056):
        - Full development kit with Arduino headers
        - Onboard Segger J-Link JTAG debugger
        - Firmware programming via an auto-provisioned J-Link backend
          (nrfjprog if present, else SEGGER J-Link Commander, else nrfutil) —
          no manual tool download required
        - Detected by its J-Link probe even when it presents no VCOM serial port
        - CDC UART for debug output

Linux serial permissions:
    Devices appear as /dev/ttyACM* (USB CDC ACM).
    Add user to dialout: sudo usermod -aG dialout $USER (then re-login)
    Check: id  and  ls -la /dev/ttyACM*
    Debug: dmesg | tail -20

nrfutil DFU reference:
    nrfutil dfu usb-serial -pkg <package.zip> -p <port>
    Package creation:
        nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\
            --application <firmware.hex> <output.zip>

nrfjprog (J-Link) reference:
    nrfjprog --ids                              List connected J-Link devices
    nrfjprog --program <hex> --sectorerase      Flash firmware (erase sectors first)
    nrfjprog --reset                            Reset the device
    nrfjprog --eraseall                         Full chip erase
    nrfjprog --readregs                         Read CPU registers
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
    check_latest_github_release, announce_firmware_update, get_firmware_dir,
    selected_firmware_payload, run_firmware_payload,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Nordic nRF52840"
DESCRIPTION = "nRF52840 Dongle / Development Kit — BLE, Zigbee, Thread, IEEE 802.15.4"

VID_PIDS = [
    (0x1915, 0x521F),  # nRF52840 Dongle — DFU bootloader CDC
    (0x1915, 0x520F),  # nRF52840 Dongle — application CDC
    (0x1366, 0x1015),  # nRF52840-DK — J-Link JTAG
]

VID_PID_DONGLE_DFU = [(0x1915, 0x521F)]
VID_PID_DONGLE_APP = [(0x1915, 0x520F)]
VID_PID_DK_JLINK   = [(0x1366, 0x1015)]

BAUD_RATE = 115200

BLE_SNIFFER_API_URL = (
    "https://api.github.com/repos/NordicSemiconductor/pc-nrfconnect-ble/releases/latest"
)
SDK_NRF_API_URL = (
    "https://api.github.com/repos/NordicSemiconductor/sdk-nrf/releases/latest"
)

# BLE pairing-crack / MITM tooling repos (fetched by firmware/download.py into
# firmware/nordic_nrf52840/, mirroring the cc26x2r1 / nrf52833_dk boards).
CRACKLE_REPO   = "https://github.com/mikeryan/crackle"
# WHAD is the maintained successor to Mirage (same author/team). The nRF52840
# BLE MITM/sniffer backend is the whad-team ButteRFly firmware, flashed by WHAD's
# own `winstall`, and driven by the WHAD host tools (wsniff/wanalyze/…).
WHAD_REPO      = "https://github.com/whad-team/whad-client"
BUTTERFLY_REPO = "https://github.com/whad-team/butterfly"

CONNECT_INSTRUCTIONS = (
    "Nordic nRF52840 not detected — nothing matching is on the USB bus.\n"
    "Flashing tools are auto-provisioned; the checks below are PHYSICAL only.\n\n"
    "  DK (PCA10056) — the on-board J-Link must enumerate (VID 1366):\n"
    "    1. USB DATA cable, not charge-only — a power-only cable lights the\n"
    "       board LED but never enumerates (the #1 cause of this message).\n"
    "    2. Plug into the J-LINK port (short top edge, next to the coin cell),\n"
    "       NOT the nRF USB port (long bottom edge) — only J-LINK enumerates\n"
    "       the debugger, and a factory-fresh nRF USB port stays silent.\n"
    "    3. Power switch SW8 -> ON (and power-source switch on VDD/USB).\n"
    "    4. Try another USB port / cable if still silent.\n\n"
    "  DONGLE (PCA10059) — VID:PID 1915:520F (app) or 1915:521F (DFU):\n"
    "    1. Insert the dongle; application mode enumerates as 1915:520F.\n"
    "    2. DFU mode: press the side button briefly — LED pulses red,\n"
    "       USB re-enumerates as 1915:521F.\n\n"
    "  Quick physical confirmation (no tools needed):\n"
    "    macOS: ioreg -p IOUSB -l -w 0 | grep -iE 'idVendor.*(4966|6421)'\n"
    "    Linux: lsusb | grep -E '1366|1915'\n"
    "  If those show nothing, the board is not on the bus — it is a cable,\n"
    "  port, or power issue, and no software can detect it until it enumerates."
)

UDEV_RULES_CONTENT = (
    '# Nordic nRF52840 udev rules\n'
    '# nRF52840 Dongle DFU bootloader (VID:PID 1915:521F)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="521f", '
    'MODE="0666", GROUP="dialout"\n'
    '# nRF52840 Dongle application (VID:PID 1915:520F)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="520f", '
    'MODE="0666", GROUP="dialout"\n'
    '# nRF52840-DK J-Link (VID:PID 1366:1015)\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="1366", MODE="0666", GROUP="plugdev"\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1366", MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-nordic-nrf52840.rules"


# ── Flash-backend / J-Link tooling (auto-provisioned) ─────────────────────────

def _jlink_exe() -> str:
    """Locate the SEGGER J-Link Commander binary (the auto-provisioned backend)."""
    for cand in ("JLinkExe", "JLink"):
        p = run_output(f"which {cand} 2>/dev/null || true")
        if p and p.strip():
            return p.strip()
    for cand in (
        "/usr/local/bin/JLinkExe",
        "/opt/SEGGER/JLink/JLinkExe",
        "/Applications/SEGGER/JLink/JLinkExe",
    ):
        if Path(cand).exists():
            return cand
    return ""


def _jlink_emus() -> list:
    """Return J-Link emulator serial numbers currently on USB (authoritative DK probe)."""
    jlink = _jlink_exe()
    if not jlink:
        return []
    out = run_output(
        f"printf 'ShowEmuList\\nexit\\n' | {jlink} -nogui 1 2>&1 || true"
    ) or ""
    import re
    return re.findall(r"Serial number:\s*(\d+)", out)


def _usb_vidpid_present() -> bool:
    """Dependency-free USB scan for SEGGER (0x1366) / Nordic (0x1915) via ioreg/lsusb."""
    if get_os_flavor() == "darwin":
        out = run_output("ioreg -p IOUSB -l -w 0 2>/dev/null || true") or ""
        # 0x1366 == 4966, 0x1915 == 6421 in ioreg's decimal idVendor field.
        return '"idVendor" = 4966' in out or '"idVendor" = 6421' in out
    out = (run_output("lsusb 2>/dev/null || true") or "").lower()
    return "1366:" in out or "1915:" in out


# ── Detection (multi-method: serial VCOM · J-Link probe · raw USB) ─────────────

def detect_nrf52840() -> bool:
    info("Scanning for nRF52840 (serial VCOM 1915/1366, J-Link probe, raw USB)…")
    if find_serial_port_by_vidpid(VID_PIDS) is not None:
        return True
    # The DK's identity is the J-Link debugger — it may present no matching VCOM,
    # so probe the debugger and the raw USB bus directly.
    if _jlink_emus():
        info("  Detected via J-Link debug probe (no VCOM required).")
        return True
    if _usb_vidpid_present():
        info("  Detected via raw USB VID match (SEGGER/Nordic on the bus).")
        return True
    return False


def _identify_variant() -> str:
    """Return 'dongle_dfu', 'dongle_app', 'dk', or 'unknown'."""
    if find_serial_port_by_vidpid(VID_PID_DONGLE_DFU):
        return "dongle_dfu"
    if find_serial_port_by_vidpid(VID_PID_DONGLE_APP):
        return "dongle_app"
    if find_serial_port_by_vidpid(VID_PID_DK_JLINK) or _jlink_emus():
        return "dk"
    return "unknown"


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for nRF52840 on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Nordic nRF52840…")
    info(f"  Writing to: {UDEV_RULES_PATH}")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the device to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Tool checks ───────────────────────────────────────────────────────────────

def _check_nrfutil():
    """Detect nrfutil (Nordic DFU tool for the dongle). NON-DESTRUCTIVE.

    Deliberately does NOT pip-install nrfutil: the legacy PyPI nrfutil pins
    click==7.1.2, which downgrades the shared interpreter and breaks every Flask
    app on it (Quiver included), and it also requires enum34, which will not build
    on modern Python. The DK path does not need nrfutil at all (it flashes via the
    J-Link backend). Only the DONGLE DFU path needs it.
    """
    info("Checking nrfutil (Nordic DFU tool — dongle only)…")
    path = run_output("which nrfutil 2>/dev/null || true")
    if path and path.strip():
        ok(f"nrfutil found: {path.strip()}")
        ver = run_output("nrfutil version 2>/dev/null || true")
        if ver:
            info(f"  nrfutil version: {ver.strip()}")
        return True
    info("nrfutil not present — the DK does not need it (J-Link backend flashes the DK).")
    info("  Not auto-installing: the PyPI nrfutil pins an old 'click' that would")
    info("  break Flask/Quiver on this interpreter. For the DONGLE DFU path, install")
    info("  Nordic's standalone nrfutil binary from developer.nordicsemi.com/nrfutil,")
    info("  or run it from an isolated venv/pipx so it can't clobber shared packages.")
    return False


def _ensure_flash_backend() -> str:
    """Ensure a J-Link flashing backend is available, auto-installing if needed.

    Returns the backend id: 'nrfjprog', 'jlink', 'nrfutil', or '' (none).
    Fully automated — no manual downloads. Priority: nrfjprog (if a user already
    has the nRF Command Line Tools) → SEGGER J-Link Commander (auto-installed via
    brew cask on macOS) → nrfutil device (pip). The DK only needs ONE of these.
    """
    info("Ensuring a J-Link flashing backend (auto-provisioned)…")

    if run_output("which nrfjprog 2>/dev/null || true").strip():
        ok("Flash backend: nrfjprog (nRF Command Line Tools).")
        return "nrfjprog"

    if _jlink_exe():
        ok(f"Flash backend: SEGGER J-Link Commander ({_jlink_exe()}).")
        return "jlink"

    # Auto-install the J-Link Commander backend — no manual download.
    flavor = get_os_flavor()
    if flavor == "darwin" and run_output("which brew 2>/dev/null || true").strip():
        info("  Installing SEGGER J-Link via brew cask (segger-jlink)…")
        run("brew install --cask segger-jlink")
    elif flavor in ("kali", "debian", "ubuntu", "linux"):
        # SEGGER J-Link isn't in apt, and the PyPI nrfutil pins an old 'click' that
        # breaks Flask apps sharing this interpreter — so do NOT pip-install it.
        # Use nrfjprog / a standalone nrfutil binary if already present; otherwise
        # DK flashing needs one installed out-of-band (capture/crackle still work).
        if run_output("which nrfutil 2>/dev/null || true").strip():
            run("nrfutil install device 2>/dev/null || true")
    if _jlink_exe():
        ok(f"Flash backend: SEGGER J-Link Commander ({_jlink_exe()}).")
        return "jlink"

    # Last resort: nrfutil device (pip). Legacy nrfutil is already ensured for DFU.
    if run_output("which nrfutil 2>/dev/null || true").strip():
        run("nrfutil install device 2>/dev/null || true")
        ok("Flash backend: nrfutil device.")
        return "nrfutil"

    warn("No flash backend could be provisioned automatically.")
    info("  Capture/crackle still work; only DK firmware flashing needs a backend.")
    return ""


def _flash_hex_jlink(hexfile: Path, erase_all: bool = False) -> bool:
    """Flash a .hex to the nRF52840-DK via SEGGER J-Link Commander (auto backend)."""
    jlink = _jlink_exe()
    if not jlink:
        return False
    import tempfile
    erase_cmd = "erase" if erase_all else ""
    script = Path(tempfile.mktemp(suffix=".jlink"))
    script.write_text(
        f"si SWD\nspeed 4000\nr\n{erase_cmd}\nloadfile {hexfile}\nr\ng\nexit\n"
    )
    # run_streaming() calls Popen(cmd) WITHOUT shell=True, so cmd MUST be an argv
    # list — a single string would be exec'd as one (nonexistent) filename.
    cmd = [
        jlink, "-device", "nRF52840_xxAA", "-if", "SWD", "-speed", "4000",
        "-autoconnect", "1", "-nogui", "1", "-ExitOnError", "1",
        "-CommanderScript", str(script),
    ]
    info(f"Running: {' '.join(cmd)}")
    ok_flag = {"seen": False, "err": False}

    def _line(l):
        info(f"  jlink: {l}")
        low = l.lower()
        if "o.k." in low or "programming done" in low or "script processing completed" in low:
            ok_flag["seen"] = True
        if "cannot connect" in low or "failed" in low or "error" in low:
            ok_flag["err"] = True

    try:
        rc = run_streaming(cmd, on_line=_line, timeout=300)
    finally:
        script.unlink(missing_ok=True)
    return rc == 0 and ok_flag["seen"] and not ok_flag["err"]


def _flash_dk_hex(hexfile: Path, erase_all: bool = False) -> bool:
    """Flash a hex to the DK using whichever backend is available (auto)."""
    backend = _ensure_flash_backend()
    if backend == "nrfjprog":
        erase = "--chiperase" if erase_all else "--sectorerase"
        try:
            r = run(f"nrfjprog --program {hexfile} {erase} --verify")
            if r.returncode == 0:
                run("nrfjprog --reset")
                return True
            warn("nrfjprog flash failed — falling back to J-Link Commander…")
        except FileNotFoundError:
            pass
        if _jlink_exe():
            return _flash_hex_jlink(hexfile, erase_all)
        return False
    if backend == "jlink":
        return _flash_hex_jlink(hexfile, erase_all)
    if backend == "nrfutil":
        try:
            r = run(f"nrfutil device program --firmware {hexfile} "
                    f"--x-family nrf52 --options reset=RESET_SYSTEM,chip_erase_mode="
                    f"{'ERASE_ALL' if erase_all else 'ERASE_SECTORS'}")
            return r.returncode == 0
        except Exception as e:
            err(f"nrfutil device program error: {e}")
            return False
    return False


# ── GitHub version checks ─────────────────────────────────────────────────────

def _get_latest_version(url: str, label: str) -> str:
    info(f"Fetching latest {label} version from GitHub…")
    info(f"  URL: {url}")
    try:
        import requests
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        tag = data.get("tag_name", "unknown")
        info(f"  Latest {label}: {tag}")
        return tag
    except Exception as e:
        warn(f"Could not fetch {label} version: {e}")
        return "unknown"


# ── Serial helpers ────────────────────────────────────────────────────────────

def _open_serial(port: str):
    import serial
    info(f"Opening serial port {port} at {BAUD_RATE} baud…")
    ser = serial.Serial(port=port, baudrate=BAUD_RATE, timeout=2)
    time.sleep(0.3)
    ser.reset_input_buffer()
    return ser


def _check_dialout(port: str):
    if get_os_flavor() == "darwin":
        return
    import grp
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    try:
        gid = grp.getgrnam("dialout").gr_gid
        if gid in os.getgroups():
            return
    except KeyError:
        return
    warn(f"User '{username}' may not be in the 'dialout' group.")
    info(f"  Fix: sudo usermod -aG dialout {username}  (then log out/in)")
    if confirm("Add to dialout group now?", default=True):
        sudo_run(f"usermod -aG dialout {username}")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Identifying connected nRF52840 variant and device details.")
    info("")

    variant = _identify_variant()
    if variant == "dongle_dfu":
        info("VARIANT DETECTED: nRF52840 Dongle — DFU bootloader mode (1915:521F)")
        info("  The dongle is ready for firmware flashing via nrfutil.")
        info("  LED behavior in DFU mode: blinking red")
        info("  To exit DFU mode: press RESET, or flash new firmware.")
    elif variant == "dongle_app":
        info("VARIANT DETECTED: nRF52840 Dongle — application mode (1915:520F)")
        info("  The dongle is running its application firmware.")
        info("  To enter DFU mode: press the side button briefly.")
        info("  LED behavior depends on firmware (BLE sniffer, Zigbee, etc.)")
    elif variant == "dk":
        info("VARIANT DETECTED: nRF52840-DK (J-Link, 1366:1015)")
        info("  The DK's onboard J-Link debugger is connected.")
        info("  Use nrfjprog for firmware programming and device info.")
        info("  CDC UART may be on a separate /dev/ttyACM* interface.")
    else:
        warn("Variant could not be identified — defaulting to generic info.")

    info("")
    info("USB port details:")
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.device == port:
                info(f"  Device      : {p.device}")
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
                info(f"  Serial No.  : {p.serial_number or 'N/A'}")
    except Exception as e:
        warn(f"Could not enumerate USB ports via pyserial: {e}")

    # If DK, list the J-Link probe(s) — prefer nrfjprog, else the J-Link backend.
    if variant == "dk":
        info("")
        if run_output("which nrfjprog 2>/dev/null || true").strip():
            info("Listing J-Link devices (nrfjprog --ids)…")
            try:
                run("nrfjprog --ids")
            except Exception as e:
                warn(f"nrfjprog --ids error: {e}")
        emus = _jlink_emus()
        if emus:
            ok(f"J-Link probe serial number(s): {', '.join(emus)}")
        else:
            warn("No J-Link probe reported by the backend.")
            info("  If the DK is plugged in: use a data cable on the J-LINK port, SW8 -> ON.")

    ok("Device info complete.")


def op_ble_sniff(port: str):
    heading("BLE Sniffer Setup")
    info("Configuring the nRF52840 as a Bluetooth Low Energy (BLE) sniffer.")
    info("")
    info("REQUIRED FIRMWARE: nRF Sniffer for Bluetooth LE")
    info("  Nordic's official BLE sniffer firmware for Wireshark integration.")
    info("  This firmware allows the nRF52840 to capture BLE advertising and data packets.")
    info("  Works with Wireshark via the nRF Sniffer plugin (extcap).")
    info("")
    info("DOWNLOAD:")
    info("  nRF Sniffer firmware and Wireshark plugin:")
    info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE")
    info("  Or via nRF Connect for Desktop > Bluetooth Low Energy Sniffer app")
    info("")
    info("VARIANT NOTES:")
    variant = _identify_variant()
    if variant in ("dongle_app", "dongle_dfu"):
        info("  Dongle detected — use nrfutil DFU to flash BLE sniffer firmware.")
        info("  Follow: op_flash_dongle() from this menu.")
    elif variant == "dk":
        info("  DK detected — use nrfjprog J-Link to flash BLE sniffer firmware.")
        info("  Follow: op_flash_dk() from this menu.")

    info("")
    info("Checking for latest BLE sniffer release…")
    latest = _get_latest_version(BLE_SNIFFER_API_URL, "BLE sniffer")
    if latest != "unknown":
        ok(f"Latest BLE sniffer version available: {latest}")

    info("")
    info("WIRESHARK INTEGRATION:")
    info("  After flashing, install the Wireshark extcap plugin:")
    info("    1. Locate the extcap/ folder from the nRF Sniffer download")
    info("    2. Copy nrf_sniffer_ble.py and nrf_sniffer_ble.bat (Windows) to:")
    info("       Linux:  ~/.config/wireshark/extcap/  or  /usr/lib/x86_64-linux-gnu/wireshark/extcap/")
    info("       macOS:  ~/.config/wireshark/extcap/  or  /Applications/Wireshark.app/.../extcap/")
    info("    3. Make executable: chmod +x nrf_sniffer_ble.py")
    info("    4. Restart Wireshark — 'nRF Sniffer for Bluetooth LE' appears as capture interface")
    info("")
    info("USAGE:")
    info("  Open Wireshark → select 'nRF Sniffer for Bluetooth LE' interface")
    info("  Or from CLI: wireshark -i nrf_sniffer_ble -k")
    info("  Filter: btle.advertising_header.pdu_type == 0x00  (ADV_IND packets)")
    info("")
    pause("Press ENTER to continue.")


def op_zigbee_info():
    heading("Zigbee / Thread NCP Info")
    info("The nRF52840 can act as a Zigbee or Thread Network Co-Processor (NCP).")
    info("")
    info("FIRMWARE OPTIONS:")
    info("  1. Zigbee NCP (Network Co-Processor)")
    info("     - Used with Home Assistant, Zigbee2MQTT, OpenHAB")
    info("     - Communicates with host over CDC UART (ZBOSS NCP protocol)")
    info("     - Firmware: sdk-nrf Zigbee NCP sample")
    info("")
    info("  2. OpenThread Border Router (OTBR)")
    info("     - Thread/Matter networking co-processor")
    info("     - Requires OpenThread Border Router on Linux host")
    info("")
    info("  3. Zigbee Sniffer (IEEE 802.15.4)")
    info("     - Wireshark integration via extcap plugin")
    info("     - Capture Zigbee, Thread, 6LoWPAN traffic")
    info("")
    info("LATEST SDK-NRF RELEASE:")
    latest = _get_latest_version(SDK_NRF_API_URL, "sdk-nrf (Zigbee/Thread)")
    if latest != "unknown":
        ok(f"Latest sdk-nrf version: {latest}")
    info("")
    info("FIRMWARE SOURCE:")
    info("  Nordic sdk-nrf: https://github.com/NordicSemiconductor/sdk-nrf")
    info("  Pre-built binaries: in sdk-nrf release assets or Nordic nRF Connect for Desktop")
    info("")
    info("ZIGBEE2MQTT INTEGRATION:")
    info("  Once NCP firmware is flashed and device is on /dev/ttyACM*:")
    info("  In zigbee2mqtt configuration.yaml:")
    info("    serial:")
    info("      port: /dev/ttyACM0")
    info("      adapter: zboss   # for Nordic NCP firmware")
    info("")
    pause("Press ENTER to continue.")


def op_flash_dongle(port: str):
    heading("Flash Dongle via nrfutil DFU")
    info("Flashing firmware to the nRF52840 dongle via USB CDC DFU.")
    info("This method uses nrfutil and the dongle's built-in DFU bootloader.")
    info("The dongle MUST be in DFU mode before flashing.")
    info("")
    info("HOW TO ENTER DFU MODE:")
    info("  Method 1 (from running firmware): press the small side button briefly")
    info("    - The LED will blink red/yellow — device is in DFU mode")
    info("    - USB re-enumerates as VID:PID 1915:521F")
    info("  Method 2 (cold boot DFU): hold side button while inserting into USB")
    info("    - Useful if firmware is bricked / not responding")
    info("")
    info("DFU PACKAGE FORMAT:")
    info("  nrfutil expects a .zip DFU package (not a raw .hex or .bin).")
    info("  To create a DFU package from a .hex file:")
    info("    nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\")
    info("        --application <firmware.hex> <output_package.zip>")
    info("  Note: --sd-req 0x00 means no SoftDevice requirement.")
    info("")

    # Verify DFU mode
    dfu_port = find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
    app_port  = find_serial_port_by_vidpid(VID_PID_DONGLE_APP)

    if dfu_port:
        info(f"Dongle is in DFU mode on {dfu_port}.")
        flash_port = dfu_port
    elif app_port:
        warn(f"Dongle is in application mode on {app_port}. DFU mode required.")
        warn("  Press the SIDE BUTTON on the dongle now to enter DFU mode.")
        pause("Press ENTER after the dongle LED is blinking (DFU mode active).")
        # Re-check
        dfu_port = find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
        if not dfu_port:
            err("Dongle still not in DFU mode. Cannot proceed.")
            info("  Troubleshooting:")
            info("    - The side button is the small button on the edge (not the USER button)")
            info("    - If device is unresponsive: remove and reinsert while holding the side button")
            return
        flash_port = dfu_port
        info(f"DFU mode confirmed on {flash_port}.")
    else:
        err("No nRF52840 dongle detected. Ensure the device is connected.")
        return

    pkg_path = prompt("Path to DFU .zip package file")
    if not pkg_path:
        warn("No package path provided. Aborting.")
        return
    pkg = Path(pkg_path)
    if not pkg.exists():
        err(f"File not found: {pkg}")
        return
    if pkg.suffix.lower() != ".zip":
        warn(f"Expected a .zip DFU package, got: {pkg.name}")
        info("  Create a package: nrfutil pkg generate --hw-version 52 --sd-req 0x00 --application <hex> <pkg.zip>")
        if not confirm("Continue anyway?", default=False):
            return

    if not confirm(f"Flash {pkg.name} to dongle on {flash_port}?", default=True):
        info("Flash cancelled.")
        return

    info(f"Running: nrfutil dfu usb-serial -pkg {pkg} -p {flash_port}")
    info("  Watch for progress output — the process takes ~10-30 seconds.")
    info("  Do NOT unplug the dongle during flashing.")
    try:
        r = run(f"nrfutil dfu usb-serial -pkg {pkg} -p {flash_port}")
        if r.returncode == 0:
            ok("Dongle firmware flashed successfully via nrfutil DFU.")
            info("  The dongle will reboot and run the new firmware.")
            info("  USB may re-enumerate as 1915:520F (application mode).")
        else:
            err("nrfutil DFU flash failed.")
            info("Troubleshooting:")
            info("  - Verify the dongle is in DFU mode (LED blinking, VID:PID 1915:521F)")
            info("  - Check: ls -la /dev/ttyACM* and dmesg | tail -20")
            info("  - Ensure the .zip package was created for nRF52840 (hw-version 52)")
            info("  - Try without --sd-req: some firmware may need --sd-req 0xXXXX")
            info("  - Check nrfutil version: nrfutil version (older versions may have issues)")
    except FileNotFoundError:
        err("nrfutil not found. Install with: pip install nrfutil --break-system-packages")
    except Exception as e:
        err(f"Flash error: {e}")
        info(f"  Debug: check dmesg | tail -20 and ls -la {flash_port}")


def op_flash_dk(port: str):
    heading("Flash DK via J-Link (auto backend)")
    info("Programming the nRF52840-DK via the onboard Segger J-Link debugger.")
    info("The flashing backend is auto-provisioned (nrfjprog if present, else the")
    info("SEGGER J-Link Commander, else nrfutil) — no manual tool install needed.")
    info("The DK must be on its J-LINK port (short top edge, NOT the nRF USB port).")
    info("")

    # Confirm the DK's J-Link is actually on the bus (probe, not just VCOM).
    if not (find_serial_port_by_vidpid(VID_PID_DK_JLINK) or _jlink_emus()):
        err("nRF52840-DK J-Link not detected on USB.")
        info("  It is a physical-layer issue — nothing to configure in software:")
        info("  - Use a DATA USB cable (not charge-only)")
        info("  - Plug into the J-LINK port (next to the coin cell), not nRF USB")
        info("  - Power switch SW8 -> ON")
        return
    emus = _jlink_emus()
    if emus:
        ok(f"J-Link probe(s) on USB: {', '.join(emus)}")

    hex_path = prompt("Path to firmware .hex file")
    if not hex_path:
        warn("No file path provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return
    if hex_file.suffix.lower() not in (".hex", ".bin"):
        warn(f"Unexpected file extension: {hex_file.suffix}")
        info("  J-Link flashing uses .hex (Intel HEX) format.")
        if not confirm("Continue?", default=False):
            return

    erase_mode = numbered_menu("Erase mode", [
        "Sector erase (recommended — erase only written sectors)",
        "Full chip erase (use for a clean reflash)",
    ])
    erase_all = erase_mode == 1

    if not confirm(f"Flash {hex_file.name} to nRF52840-DK?", default=True):
        info("Flash cancelled.")
        return

    info("Flashing via the auto-provisioned J-Link backend — do NOT disconnect…")
    if _flash_dk_hex(hex_file, erase_all=erase_all):
        ok("Firmware flashed and device reset — new firmware is running.")
    else:
        err("Flash failed.")
        info("Troubleshooting:")
        info("  - Re-seat the USB cable on the J-LINK port (data cable, not charge-only)")
        info("  - Ensure the .hex is built for nRF52840")
        info("  - Linux: user in the 'plugdev' group for J-Link access")
        info("  - The J-Link OB firmware may need an update (SEGGER J-Link Configurator)")


def _sniffer_fw_dir() -> Path:
    """firmware/nordic_nrf52840/ble_sniffer — where download.py vendors the hex."""
    return get_firmware_dir("nordic_nrf52840") / "ble_sniffer"


def _find_sniffer_hex() -> Path:
    """Locate the nRF52840-DK nRF Sniffer .hex under the vendored firmware dir.

    Prefers the DK-specific hex (sniffer_nrf52840dk_nrf52840_*.hex) over the
    dongle hex — flashing a dongle image to the DK, or vice-versa, is wrong.
    """
    base = _sniffer_fw_dir()
    if not base.exists():
        return None
    dk = sorted(base.rglob("*nrf52840dk*.hex"))
    if dk:
        return dk[0]
    matches = sorted(base.rglob("*nrf52840*.hex")) or sorted(base.rglob("*.hex"))
    return matches[0] if matches else None


def _find_extcap_plugin() -> Path:
    """Locate the nRF Sniffer Wireshark extcap plugin (nrf_sniffer_ble.py)."""
    base = get_firmware_dir("nordic_nrf52840")
    if not base.exists():
        return None
    matches = sorted(base.rglob("nrf_sniffer_ble.py"))
    return matches[0] if matches else None


def _extcap_dir() -> Path:
    return Path.home() / ".config" / "wireshark" / "extcap"


def _prep_sniffer_flash(port: str) -> bool:
    """Firmware-payload PREPARE: obtain the nRF Sniffer hex + a J-Link backend so
    only the write remains. Returns True only when fully ready."""
    ready = True
    if not (find_serial_port_by_vidpid(VID_PID_DK_JLINK) or _jlink_emus()):
        err("  nRF52840-DK J-Link not detected on USB (connect the J-LINK port).")
        ready = False
    hexf = _find_sniffer_hex()
    if not hexf:
        info("  Fetching the nRF Sniffer firmware…")
        if run_output("which nrfutil 2>/dev/null || true").strip():
            run("nrfutil install ble-sniffer 2>/dev/null || true")
        hexf = _find_sniffer_hex()
    if hexf and Path(hexf).exists():
        ok(f"  Firmware ready: {hexf}")
    else:
        err("  nRF Sniffer hex unavailable — run: "
            "python3 firmware/download.py --tools nordic_nrf52840 --yes")
        ready = False
    backend = _ensure_flash_backend()
    if backend:
        ok(f"  Flash backend ready: {backend}")
    else:
        err("  No J-Link flash backend could be provisioned.")
        ready = False
    return ready


def _autoflash_nrf_sniffer(port: str):
    """Firmware-payload FLASH: everything is prepped — write the nRF Sniffer hex."""
    hexf = _find_sniffer_hex()
    if not hexf or not Path(hexf).exists():
        err("nRF Sniffer hex missing at flash time — aborting.")
        return
    if _flash_dk_hex(hexf, erase_all=False):
        ok("nRF Sniffer firmware flashed — the DK is now a BLE sniffer.")
    else:
        err("Flash failed — re-seat the J-LINK cable and retry.")


def op_flash_sniffer_dk(port: str):
    heading("Flash nRF Sniffer Firmware to DK (J-Link)")
    info("Flashing the nRF Sniffer for Bluetooth LE firmware onto the nRF52840-DK")
    info("via the onboard J-Link. This is the firmware that turns the DK into a")
    info("passive BLE sniffer for Wireshark — the prerequisite for pairing capture.")
    info("")

    if not (find_serial_port_by_vidpid(VID_PID_DK_JLINK) or _jlink_emus()):
        err("nRF52840-DK J-Link not detected on USB.")
        info("  Connect via the J-LINK port (data cable, not charge-only), SW8 -> ON.")
        info("  The dongle variant flashes the sniffer via 'Flash Dongle (nrfutil DFU)'.")
        return

    hexf = _find_sniffer_hex()
    if not hexf:
        warn("No nRF Sniffer .hex found under firmware/nordic_nrf52840/ble_sniffer/.")
        info("  Auto-fetching it now (nrfutil ble-sniffer component)…")
        if run_output("which nrfutil 2>/dev/null || true").strip():
            run("nrfutil install ble-sniffer 2>/dev/null || true")
        info("  Or fetch via the downloader:")
        info("    python3 firmware/download.py --tools nordic_nrf52840 --yes")
        hexf = _find_sniffer_hex()
        if not hexf:
            info("  Sniffer hex still not present — run the downloader, then retry.")
            return
    ok(f"nRF Sniffer firmware: {hexf}")

    if not confirm(f"Flash {hexf.name} to the nRF52840-DK?", default=True):
        info("Flash cancelled.")
        return

    info("Flashing the sniffer via the auto-provisioned J-Link backend…")
    if _flash_dk_hex(hexf, erase_all=False):
        ok("nRF Sniffer firmware flashed — the DK is now a BLE sniffer.")
        info("  Next: 'Wireshark extcap Setup', then 'BLE Capture'.")
    else:
        err("Sniffer flash failed.")
        info("  Re-seat the J-LINK cable (data cable) and ensure the .hex is for nRF52840.")


def op_wireshark_extcap():
    heading("Wireshark extcap Setup (nRF Sniffer)")
    info("Installing the nRF Sniffer Wireshark extcap plugin so the DK shows up as")
    info("a live capture interface named 'nRF Sniffer for Bluetooth LE'.")
    info("")
    info("The plugin (nrf_sniffer_ble.py) ships inside the nRF Sniffer download and")
    info("lets Wireshark drive the sniffer — including FOLLOWING a specific device,")
    info("which is how you capture a full pairing exchange for the PIN crack.")
    info("")

    plugin = _find_extcap_plugin()
    if not plugin:
        warn("nrf_sniffer_ble.py not found under firmware/nordic_nrf52840/.")
        info("  Fetch the nRF Sniffer package first:")
        info("    python3 firmware/download.py --tools nordic_nrf52840 --yes")
        info("  The plugin lives in the 'extcap/' folder of that download.")
        return
    ok(f"extcap plugin found: {plugin}")

    extcap = _extcap_dir()
    info("")
    info("The plugin needs the SheerWater/nordic python deps (pyserial) importable.")
    ensure_pip_packages([("serial", "pyserial")])

    if not confirm(f"Install the plugin into {extcap}?", default=True):
        info("SETUP (manual):")
        info(f"  mkdir -p {extcap}")
        info(f"  cp {plugin} {extcap}/")
        info(f"  chmod +x {extcap}/nrf_sniffer_ble.py")
        info("  Restart Wireshark; confirm: wireshark --list-interfaces | grep -i nrf")
        return

    try:
        extcap.mkdir(parents=True, exist_ok=True)
        dest = extcap / plugin.name
        r = run(f"cp {plugin} {dest}")
        if r.returncode == 0:
            run(f"chmod +x {dest}")
            ok(f"Installed extcap plugin: {dest}")
            info("  Restart Wireshark — 'nRF Sniffer for Bluetooth LE' appears in the")
            info("  interface list. Click its gear icon to pick the target device to")
            info("  follow before you start the capture.")
            info("  Verify: tshark -D | grep -i nrf_sniffer")
        else:
            err("Failed to copy the extcap plugin.")
            info(f"  Manual: cp {plugin} {dest} && chmod +x {dest}")
    except Exception as e:
        err(f"extcap install error: {e}")


def op_ble_capture(port: str):
    heading("BLE Capture (nRF Sniffer -> pcap)")
    info("Capturing BLE traffic with the DK's nRF Sniffer firmware into a pcap.")
    info("To crack a pairing PIN you MUST capture the FULL pairing handshake, so")
    info("start this capture BEFORE the two devices pair (or force a re-pair).")
    info("")
    info("TARGET FOLLOWING: the nRF Sniffer follows ONE device at a time. The most")
    info("reliable way to lock onto your target is Wireshark's toolbar (the extcap")
    info("gear picks the device). This headless path captures on the sniffer")
    info("interface for a fixed duration; use it once the sniffer is set to follow")
    info("your target, or to grab all advertising traffic to identify the target.")
    info("")

    tshark = run_output("which tshark 2>/dev/null || true")
    if not (tshark and tshark.strip()):
        err("tshark not found — install Wireshark/tshark first.")
        info("  Linux: sudo apt-get install -y tshark")
        info("  macOS: brew install --cask wireshark  (or: brew install wireshark)")
        return

    if not _find_extcap_plugin() and not _extcap_dir().joinpath("nrf_sniffer_ble.py").exists():
        warn("nRF Sniffer extcap plugin not installed — run 'Wireshark extcap Setup' first.")
        info("  Without it, tshark will not see the nRF Sniffer interface.")
        return

    info("Enumerating capture interfaces (tshark -D)…")
    listing = run_output("tshark -D 2>/dev/null || true")
    ifaces = [ln for ln in (listing or "").splitlines() if "nrf_sniffer" in ln.lower()]
    if not ifaces:
        warn("No nRF Sniffer interface found in 'tshark -D' output.")
        info("  - Restart Wireshark/tshark after installing the extcap plugin")
        info("  - Confirm the DK is flashed with nRF Sniffer firmware and enumerated")
        info("  - Check: tshark -D   and   ls -la /dev/ttyACM*")
        return

    info("nRF Sniffer interfaces:")
    for ln in ifaces:
        info(f"  {ln}")
    # tshark -D lines look like "N. iface_name" — take the name of the first match.
    iface = ifaces[0].split(".", 1)[-1].strip().split()[0]
    iface = prompt("Capture interface name", default=iface)
    if not iface:
        warn("No interface provided. Aborting.")
        return

    try:
        duration = int(prompt("Capture duration (seconds)", default="120") or "120")
    except ValueError:
        duration = 120

    default_pcap = str(Path.cwd() / f"nrf_sniffer_{time.strftime('%Y%m%d_%H%M%S')}.pcap")
    pcap = Path(prompt("Output pcap path", default=default_pcap))
    pcap.parent.mkdir(parents=True, exist_ok=True)

    info(f"Interface : {iface}")
    info(f"Duration  : {duration}s")
    info(f"Output    : {pcap}")
    if not confirm("Start the capture now?", default=True):
        info("Capture cancelled.")
        return

    cmd = ["tshark", "-i", iface, "-a", f"duration:{duration}", "-w", str(pcap)]
    info(f"Running: {' '.join(cmd)}")
    info("  Trigger/force the pairing on the target now so the handshake is captured.")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(f"  tshark: {l}"),
                           timeout=duration + 60)
        if rc != 0:
            warn(f"tshark exited with code {rc}.")
    except KeyboardInterrupt:
        info("Capture interrupted by user (Ctrl-C).")

    if pcap.exists() and pcap.stat().st_size > 0:
        ok(f"pcap saved: {pcap} ({pcap.stat().st_size // 1024} KB)")
        info("  Legacy pairing? Recover the PIN/TK with 'Crack Pairing (crackle)'.")
        info("  Secure Connections? crackle can't help — use 'BLE MITM (WHAD)'.")
    else:
        warn("No pcap data was written — was any BLE traffic seen?")
        info("  Verify the DK is on nRF Sniffer firmware and following the target.")


def op_crack_pairing():
    heading("Crack Pairing (crackle)")
    info("Recovering the pairing key material from a capture of a BLE LEGACY pairing")
    info("exchange using crackle by Mike Ryan.")
    info("")
    info("IMPORTANT — crackle only cracks BLE LEGACY pairing:")
    info("  - Works on: LE Legacy pairing (JustWorks, Passkey Entry)")
    info("  - For Passkey Entry, the recovered TK IS the 6-digit PIN")
    info("  - Does NOT work on: LE Secure Connections (ECDH) — use 'BLE MITM (WHAD)'")
    info("  The capture MUST contain the full pairing handshake (connect request")
    info("  through key distribution) — capture BEFORE the devices pair.")
    info("")
    info("crackle recovers the TK/STK/LTK, then decrypts the encrypted packets and")
    info("writes a cleartext pcap you can analyse in Wireshark.")
    info("")

    crackle = run_output("which crackle 2>/dev/null || true")
    if not (crackle and crackle.strip()):
        # Fall back to the vendored build under firmware/nordic_nrf52840/crackle.
        vendored = get_firmware_dir("nordic_nrf52840") / "crackle" / "crackle"
        if vendored.exists():
            crackle = str(vendored)
        else:
            warn("crackle not found on PATH.")
            info("  Fetch + build it via the firmware downloader:")
            info("    python3 firmware/download.py --tools nordic_nrf52840 --yes")
            info("  Or from source:")
            info(f"    git clone {CRACKLE_REPO} && cd crackle && make")
            info("    sudo cp crackle /usr/local/bin/   (optional — put it on PATH)")
            info("  Debian/Kali package: sudo apt-get install -y crackle")
            return
    ok(f"crackle: {crackle.strip()}")

    pcap_path = prompt("Path to the captured .pcap (must contain legacy pairing)")
    if not pcap_path:
        warn("No pcap provided. Aborting.")
        return
    pcap = Path(pcap_path)
    if not pcap.exists():
        err(f"File not found: {pcap}")
        return

    default_out = str(pcap.with_name(pcap.stem + "_decrypted.pcap"))
    out_pcap = Path(prompt("Output decrypted pcap path", default=default_out))

    if not confirm(f"Run crackle on {pcap.name}?", default=True):
        info("crackle run cancelled.")
        return

    cmd = [crackle.strip(), "-i", str(pcap), "-o", str(out_pcap)]
    info(f"Running: {' '.join(cmd)}")
    rc = run_streaming(cmd, on_line=lambda l: info(f"  crackle: {l}"), timeout=600)
    if rc == 0 and out_pcap.exists():
        ok(f"Decrypted pcap written: {out_pcap}")
        info("  crackle prints the recovered TK (PIN)/LTK above — note it for the report.")
        info("  Open the decrypted pcap in Wireshark — ATT/GATT payloads are cleartext.")
    else:
        warn(f"crackle exited with code {rc}.")
        info("Troubleshooting:")
        info("  - Ensure the capture contains a COMPLETE legacy pairing handshake")
        info("  - LE Secure Connections cannot be cracked (ECDH) — check the capture")
        info("  - Re-capture with the sniffer running BEFORE the devices pair")
        info("  - Try crackle -v for verbose output on what it found")


def _butterfly_hex_for_dk():
    """Locate a vendored butterfly.hex, else download it from the whad-team release.

    The DK needs the raw J-Link-flashable hex (butterfly.hex), NOT the makerdiary
    (mdk) hex and NOT the DFU zip. Returns a Path or None.
    """
    bdir = get_firmware_dir("nordic_nrf52840") / "butterfly"
    if bdir.exists():
        hits = (sorted(bdir.rglob("butterfly.hex"))
                or [p for p in sorted(bdir.rglob("*.hex")) if "mdk" not in p.name.lower()]
                or sorted(bdir.rglob("*.hex")))
        if hits:
            return hits[0]
    try:
        from common import get_github_release_asset_url, download_firmware
        tag, _ = check_latest_github_release("whad-team", "butterfly")
        if tag:
            url = get_github_release_asset_url("whad-team", "butterfly", tag,
                                               r"^butterfly\.hex$")
            if url:
                bdir.mkdir(parents=True, exist_ok=True)
                dest = bdir / "butterfly.hex"
                if download_firmware(url, dest, "ButteRFly"):
                    return dest
    except Exception as e:  # noqa: BLE001 — network/asset lookup best-effort
        warn(f"butterfly.hex download failed: {e}")
    return None


def op_ble_mitm():
    heading("BLE MITM (WHAD + ButteRFly)")
    info("Active man-in-the-middle for BLE — used when the target pairs with LE")
    info("Secure Connections (which crackle CANNOT break), or to relay a legacy")
    info("pairing. The nRF52840 runs the whad-team ButteRFly firmware and is driven")
    info("by the WHAD host tools; the board sits between central and peripheral,")
    info("relaying the connection and capturing/handling the pairing.")
    info("")
    info("STACK (whad-team, the maintained successor to Mirage):")
    info("  - ButteRFly firmware (whad-team) on the nRF52840 — the radio backend")
    info("  - WHAD on the host — sniff/analyze/mitm tooling (pip install whad)")
    info("")
    info("NOTE: LE Secure Connections uses ECDH, so the passkey cannot be recovered")
    info("passively. A MITM works by relaying the pair and either observing Passkey")
    info("Entry, forcing a JustWorks/legacy downgrade, or brute-forcing the 6-digit")
    info("passkey — effectiveness depends on the target's IO capabilities and whether")
    info("it enforces authenticated pairing. Confirm this is in scope for the client.")
    info("")
    warn("ButteRFly REPLACES the nRF Sniffer firmware on the DK (one firmware at a")
    warn("time). Re-flash the nRF Sniffer hex via 'Flash nRF Sniffer Firmware to DK'")
    warn("to return to the passive-capture workflow.")
    info("")

    dk_present = bool(find_serial_port_by_vidpid(VID_PID_DK_JLINK) or _jlink_emus())
    dongle_present = bool(find_serial_port_by_vidpid(VID_PID_DONGLE_DFU + VID_PID_DONGLE_APP))

    if dk_present:
        # The DK has NO DFU bootloader, so winstall/nrfutil DFU CANNOT flash it
        # ("No trigger interface found"). Flash the raw butterfly.hex over J-Link.
        info("nRF52840-DK detected — flashing ButteRFly over J-Link/SWD.")
        info("  (winstall/nrfutil DFU do NOT work on the DK — no bootloader trigger.)")
        bfly_hex = _butterfly_hex_for_dk()
        if not bfly_hex:
            warn("Could not locate or download butterfly.hex.")
            info("  Fetch it: python3 firmware/download.py --tools nordic_nrf52840 --yes")
            info(f"  Or manually: {BUTTERFLY_REPO}/releases (butterfly.hex)")
        elif confirm(f"Flash {bfly_hex.name} to the DK via J-Link now?", default=False):
            if _flash_dk_hex(bfly_hex, erase_all=False):
                ok("ButteRFly flashed to the DK.")
                warn("Now connect the DK's nRF USB port (J3) too: ButteRFly's WHAD")
                warn("interface appears there (Nordic CDC, VID 1915), NOT on the")
                warn("J-Link VCOM (SEGGER, VID 1366). Confirm the port with: whadup")
            else:
                err("ButteRFly J-Link flash failed — re-seat the J-LINK cable and retry.")
    else:
        # Dongle (PCA10059) — DFU via WHAD's winstall is the right path.
        winstall = run_output("which winstall 2>/dev/null || true").strip()
        if not dongle_present:
            warn("No nRF52840 DK or dongle detected on USB.")
        if winstall:
            ok(f"WHAD flasher: {winstall}")
            if confirm("Flash whad-team ButteRFly to the DONGLE via winstall (DFU)?",
                       default=False):
                info("Running: winstall --flash butterfly")
                r = run("winstall --flash butterfly")
                if r.returncode == 0:
                    ok("ButteRFly firmware flashed via winstall.")
                else:
                    warn("winstall flash returned non-zero — see output above.")
                    info("  Put the dongle in DFU mode first (press RESET — LED pulses red).")
        else:
            warn("WHAD not installed (winstall not on PATH).")
            info("  Install the host framework + flasher: pip install whad")
            info(f"    (source: {WHAD_REPO})")

    # WHAD host tools
    info("")
    whad = run_output("which wsniff 2>/dev/null || true").strip()
    if whad:
        ok(f"WHAD tools present (wsniff: {whad}).")
    else:
        warn("WHAD host tools not found — install with: pip install whad")

    info("")
    info("RUN (once ButteRFly is flashed and WHAD is installed):")
    info("  Confirm the board is seen as a WHAD interface:  whadup")
    info("  Passively recover a LEGACY pairing PIN (the BLE passkey workflow):")
    info("    wsniff -i <iface> ble --pcap capture.pcap | wanalyze legacy_pairing_cracking")
    info("  Full active relay: use WHAD's BLE MITM tooling, or the project's")
    info("  ble-connect.py / ble-spawn.py proxy driven by the recovered PIN.")
    info("")
    pause("Press ENTER to continue.")


def op_create_dfu_package():
    heading("Create DFU Package")
    info("Creating a nrfutil DFU .zip package from a .hex firmware file.")
    info("This package is required for flashing the dongle via USB CDC DFU.")
    info("")
    info("nrfutil pkg generate parameters:")
    info("  --hw-version 52    Hardware version (always 52 for nRF52840)")
    info("  --sd-req 0x00      No SoftDevice requirement (for ZB/Thread/custom firmware)")
    info("  --sd-req 0x0101    Require SoftDevice S140 (for BLE firmware with S140)")
    info("  --application      Path to the .hex file to package")
    info("")
    info("Common SoftDevice requirement codes:")
    info("  0x0101 = S140 v7.x  (BLE)")
    info("  0x00   = No SoftDevice (Zigbee, Thread, custom)")
    info("")

    hex_path = prompt("Path to source .hex firmware file")
    if not hex_path:
        warn("No file provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return

    output_name = hex_file.stem + "_dfu_package.zip"
    output_path = prompt(f"Output .zip package path", default=str(hex_file.parent / output_name))
    output_zip = Path(output_path)

    sd_req = prompt("SoftDevice requirement code (0x00 for none, 0x0101 for S140)", default="0x00")

    if not confirm(f"Create DFU package: {output_zip.name}?", default=True):
        info("Package creation cancelled.")
        return

    cmd = (
        f"nrfutil pkg generate --hw-version 52 --sd-req {sd_req} "
        f"--application {hex_file} {output_zip}"
    )
    info(f"Running: {cmd}")
    try:
        r = run(cmd)
        if r.returncode == 0:
            ok(f"DFU package created: {output_zip}")
            info(f"  Use this .zip with 'Flash Dongle via nrfutil DFU'.")
        else:
            err("DFU package creation failed.")
            info("  Check: is the .hex file valid? (nrfjprog --program can verify)")
            info("  Check: is nrfutil installed? (pip install nrfutil)")
            info("  Try different --sd-req value if your firmware uses a SoftDevice")
    except FileNotFoundError:
        err("nrfutil not found. Install: pip install nrfutil --break-system-packages")
    except Exception as e:
        err(f"Package creation error: {e}")


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking the vendored nRF Sniffer firmware for the nRF52840…")
    # NOTE: the nRF Sniffer for Bluetooth LE is NOT distributed via GitHub — there
    # is no such repo. It ships in Nordic's website zip and via nrfutil's
    # ble-sniffer component. Report the locally-vendored hex instead of hitting a
    # nonexistent GitHub repo (which previously logged a hard error every run).
    hexf = _find_sniffer_hex()
    if hexf:
        import re
        m = re.search(r'_(\d+\.\d+\.\d+)\.hex$', hexf.name)
        ver = m.group(1) if m else "unknown"
        ok(f"  nRF Sniffer firmware present: {hexf.name} (v{ver})")
    else:
        warn("  No nRF Sniffer firmware on disk yet.")
        info("  The nRF Sniffer is NOT on GitHub — obtain it via one of:")
        info("    - nrfutil (modern): nrfutil install ble-sniffer && "
             "nrfutil ble-sniffer bootstrap")
        info("    - Nordic site: "
             "https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE")
        info("    - Quiver downloader: "
             "python3 firmware/download.py --tools nordic_nrf52840 --yes")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial
    info("Ensuring pyserial for USB CDC serial communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    # requests for GitHub API
    info("Ensuring requests library for version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Checking udev rules for nRF52840 USB access…")
    _check_udev_rules()

    info("Ensuring nrfutil (DFU tool for dongle flashing)…")
    _check_nrfutil()

    _ensure_flash_backend()

    info("Detecting nRF52840 (serial VCOM · J-Link probe · raw USB)…")
    info("  Dongle DFU mode   : 1915:521F — press side button to activate")
    info("  Dongle app mode   : 1915:520F — normal operation")
    info("  DK J-Link         : VID 1366 — J-LINK port (probe, VCOM optional)")

    found = web_detect_loop(detect_nrf52840, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Nordic nRF52840 not detected. Exiting.")
        sys.exit(1)

    # The DK is identified by its J-Link probe and may expose no matching VCOM —
    # a missing serial port is NOT fatal (flash/capture/crackle don't need it).
    port = find_serial_port_by_vidpid(VID_PIDS) or ""
    variant = _identify_variant()

    if port:
        ok(f"nRF52840 detected on {port}")
    elif variant == "dk":
        ok("nRF52840-DK detected via J-Link probe (no VCOM serial port).")
    else:
        ok("nRF52840 detected (no serial port resolved).")

    check_firmware_version()

    if variant == "dongle_dfu":
        ok("Variant: nRF52840 Dongle — DFU bootloader mode (1915:521F)")
        info("  Device is ready for DFU firmware flashing via nrfutil.")
    elif variant == "dongle_app":
        ok("Variant: nRF52840 Dongle — application mode (1915:520F)")
        info("  Press side button to enter DFU mode for firmware flashing.")
    elif variant == "dk":
        ok("Variant: nRF52840-DK — J-Link JTAG debugger")
        info("  Firmware programming uses the auto-provisioned J-Link backend.")
        info("  CDC UART debug output may be on a separate /dev/ttyACM* port.")
    else:
        warn("Could not identify specific variant.")

    if port:
        _check_dialout(port)

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        run_firmware_payload(
            fw.get("label", "Flash nRF Sniffer (DK)"),
            info_fn=lambda: op_device_info(port),
            prepare_fn=lambda: _prep_sniffer_flash(port),
            flash_fn=lambda: _autoflash_nrf_sniffer(port),
            summary_lines=[
                f"Board    : {TOOL_NAME} (nRF52840-DK)",
                f"Firmware : {fw.get('firmware', 'nRF Sniffer for Bluetooth LE')}",
                "Flasher  : auto-provisioned J-Link backend (nrfjprog/JLink/nrfutil)",
            ],
        )
        return

    MENU_OPTIONS = [
        "Device Info",
        "BLE Sniffer Setup (firmware/Wireshark reference)",
        "FIRMWARE - Flash nRF Sniffer Firmware to DK (J-Link)",
        "Wireshark extcap Setup (nRF Sniffer)",
        "BLE Capture (nRF Sniffer -> pcap)",
        "Crack Pairing (crackle — legacy PIN/TK)",
        "BLE MITM (WHAD + ButteRFly — Secure Connections)",
        "Zigbee / Thread NCP Info",
        "FIRMWARE - Flash Dongle (nrfutil DFU)",
        "FIRMWARE - Flash DK (J-Link — auto backend)",
        "Create DFU Package",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Nordic nRF52840 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_ble_sniff(port)
        elif choice == 2:
            op_flash_sniffer_dk(port)
        elif choice == 3:
            op_wireshark_extcap()
        elif choice == 4:
            op_ble_capture(port)
        elif choice == 5:
            op_crack_pairing()
        elif choice == 6:
            op_ble_mitm()
        elif choice == 7:
            op_zigbee_info()
        elif choice == 8:
            op_flash_dongle(port)
        elif choice == 9:
            op_flash_dk(port)
        elif choice == 10:
            op_create_dfu_package()
        elif choice == 11:
            info("Goodbye.")
            break

        # Re-check port after operations (dongle mode may change)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")
            variant = _identify_variant()
            if variant == "dongle_dfu":
                info("  Dongle is now in DFU mode.")
            elif variant == "dongle_app":
                info("  Dongle is now in application mode.")


if __name__ == "__main__":
    main()
