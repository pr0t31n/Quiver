#!/usr/bin/env python3
"""
Nordic nRF52833-DK (PCA10100) Tool Manager
Handles device detection (onboard SEGGER J-Link OB), flashing the nRF Sniffer
for Bluetooth LE firmware, Wireshark extcap integration, BLE capture guidance,
and pairing-key cracking with crackle.

Usage:
    python3 nrf52833_dk.py

BLE SNIFFING BACKEND — nRF Sniffer, NOT Sniffle:
    This board sniffs BLE using Nordic's official "nRF Sniffer for Bluetooth LE"
    firmware, driven from Wireshark via the nRF Sniffer extcap plugin.
    IMPORTANT: Sniffle (https://github.com/nccgroup/Sniffle) is a Texas
    Instruments-only sniffer (CC1352 / CC26x2). Sniffle does NOT support Nordic
    nRF52 parts. Do NOT attempt to flash Sniffle to this board — use nRF Sniffer.

USB VID:PIDs (onboard SEGGER J-Link OB):
    0x1366:0x1015 — SEGGER J-Link OB (nRF52833-DK debug probe)
    0x1366:0x1051 — SEGGER J-Link OB (alternate J-Link OB composite PID)
    The J-Link OB exposes a CDC Virtual COM (VCOM) that appears as /dev/ttyACM*.
    The nRF Sniffer firmware streams captured BLE packets over this VCOM.

Board revision caveat (PCA10100 v3):
    Some nRF52833-DK board revisions (notably v3) are NOT covered by a prebuilt
    nRF Sniffer .hex in the release zip and may require building the sniffer
    firmware from source. Check the board revision printed on the silkscreen
    (near the PCA10100 marking) before flashing.

Linux serial permissions:
    The J-Link VCOM appears as /dev/ttyACM* (USB CDC ACM).
    Add user to dialout: sudo usermod -aG dialout $USER (then re-login)
    Add user to plugdev for J-Link access: sudo usermod -aG plugdev $USER
    Check: id  and  ls -la /dev/ttyACM*
    Debug: dmesg | tail -20  and  lsusb | grep 1366

nrfjprog (J-Link) reference:
    nrfjprog --ids                                      List connected J-Link probes
    nrfjprog --deviceversion                            Show the connected SoC variant
    nrfjprog --program <hex> --sectorerase --verify     Flash + verify firmware
    nrfjprog --reset                                    Reset the device
    nrfjprog --eraseall                                 Full chip erase

nRF Sniffer for Bluetooth LE reference:
    Download: https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE
    hex/         — prebuilt sniffer firmware (choose the nRF52833 / PCA10100 build)
    extcap/      — nrf_sniffer_ble.py Wireshark plugin + requirements.txt
    Wireshark interface name after setup: "nRF Sniffer for Bluetooth LE"
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
    selected_firmware_payload, run_firmware_payload, flash_swd_hex,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Nordic nRF52833-DK"
DESCRIPTION = "nRF52833-DK (PCA10100) — BLE sniffer via nRF Sniffer (onboard J-Link)"

VID_PIDS = [
    (0x1366, 0x1015),  # SEGGER J-Link OB — nRF52833-DK debug probe
    (0x1366, 0x1051),  # SEGGER J-Link OB — alternate composite PID
]

BAUD_RATE = 1000000  # nRF Sniffer on nRF52 streams over the J-Link VCOM at 1 Mbaud

SNIFFER_RELEASE_URL = (
    "https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE"
)

CONNECT_INSTRUCTIONS = (
    "Nordic nRF52833-DK (PCA10100) not detected.\n\n"
    "  1. Connect the DK via USB using the J-Link USB port (the port next to\n"
    "     the SEGGER J-Link OB — labelled 'J-LINK' on the board, NOT the nRF\n"
    "     USB port on the opposite edge).\n"
    "  2. The onboard SEGGER J-Link OB enumerates as VID:PID 1366:1015\n"
    "     (or 1366:1051 on some board/firmware combos) and exposes a CDC VCOM\n"
    "     that appears as /dev/ttyACM*.\n"
    "  3. The green LED5 (power) should be lit steadily.\n"
    "  4. Install SEGGER J-Link Software:\n"
    "       Linux: download the .deb from https://www.segger.com/downloads/jlink/\n"
    "              sudo dpkg -i JLink_Linux_*.deb\n"
    "       macOS: brew install --cask segger-jlink\n"
    "  5. Install nRF Command Line Tools (nrfjprog):\n"
    "       https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools\n"
    "       Linux: download .tar.gz, extract, run install.sh\n"
    "       macOS: brew install --cask nordic-nrf-command-line-tools\n\n"
    "  Linux permissions:\n"
    "    sudo usermod -aG dialout $USER  (then re-login)\n"
    "    sudo usermod -aG plugdev $USER  (for J-Link access)\n"
    "    Check: dmesg | tail -20\n"
    "    Check: lsusb | grep 1366\n\n"
    "  NOTE: This board uses nRF Sniffer for BLE — NOT Sniffle (Sniffle is TI-only)."
)

UDEV_RULES_CONTENT = (
    '# Nordic nRF52833-DK (PCA10100) udev rules\n'
    '# SEGGER J-Link OB (VID 1366) — USB debug probe access\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="1366", MODE="0666", GROUP="plugdev"\n'
    '# SEGGER J-Link OB CDC VCOM (VID 1366) — serial access for nRF Sniffer\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1366", MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-nordic-nrf52833-dk.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_nrf52833_dk() -> bool:
    info("Scanning USB for nRF52833-DK J-Link OB (VID:PIDs 1366:1015, 1366:1051)…")
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for the nRF52833-DK J-Link OB on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for Nordic nRF52833-DK…")
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

def _check_nrfjprog():
    """Check for nrfjprog (nRF Command Line Tools)."""
    info("Checking nrfjprog (nRF Command Line Tools for J-Link programming)…")
    path = run_output("which nrfjprog 2>/dev/null || true")
    if path and path.strip():
        ok(f"nrfjprog found: {path.strip()}")
        ver = run_output("nrfjprog --version 2>/dev/null || true")
        if ver:
            info(f"  nrfjprog version: {ver.strip()}")
        return True
    warn("nrfjprog not found.")
    info("  nrfjprog is part of the nRF Command Line Tools package from Nordic Semiconductor.")
    info("  Required for J-Link firmware programming on the nRF52833-DK.")
    info("  Download from: https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
    flavor = get_os_flavor()
    if flavor == "darwin":
        info("  macOS install: brew install --cask nordic-nrf-command-line-tools")
        info("  Or: download the macOS .pkg installer from the Nordic website")
        if confirm("Attempt to install via brew cask?", default=True):
            ensure_brew_packages(["nordic-nrf-command-line-tools"])
    else:
        info("  Linux install:")
        info("    1. Download the .tar.gz from https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
        info("    2. Extract: tar xzf nRF-Command-Line-Tools_*.tar.gz")
        info("    3. Run installer: sudo ./install.sh")
        info("    4. Or install the .deb package if available for your distro")
        info("  Kali note: The nRF Command Line Tools .deb may work directly.")
    return False


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


def _wireshark_extcap_dir() -> Path:
    """Return the per-user Wireshark extcap directory for this platform."""
    return Path.home() / ".config" / "wireshark" / "extcap"


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Identifying the connected nRF52833-DK and its onboard J-Link probe.")
    info("")

    info("USB port details (J-Link CDC VCOM):")
    try:
        from serial.tools import list_ports
        matched = False
        for p in list_ports.comports():
            if p.device == port:
                matched = True
                info(f"  Device      : {p.device}")
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
                info(f"  Serial No.  : {p.serial_number or 'N/A'}")
        if not matched:
            warn(f"Could not find {port} in the current pyserial port list.")
    except Exception as e:
        warn(f"Could not enumerate USB ports via pyserial: {e}")

    info("")
    info("Running 'nrfjprog --ids' to list connected J-Link probes…")
    try:
        r = run("nrfjprog --ids")
        if r.returncode == 0:
            ok("nrfjprog probe listing complete.")
        else:
            warn("nrfjprog --ids returned an error.")
            info("  Ensure J-Link Software is installed and the DK is connected.")
            info("  Install: https://www.segger.com/downloads/jlink/")
    except FileNotFoundError:
        warn("nrfjprog not found. Install nRF Command Line Tools.")
        info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
    except Exception as e:
        err(f"nrfjprog error: {e}")

    info("")
    info("Running 'nrfjprog --deviceversion' to identify the SoC variant…")
    try:
        r = run("nrfjprog --deviceversion")
        if r.returncode == 0:
            ok("Device version query complete.")
            info("  Expected: an NRF52833-family part (e.g. NRF52833_xxAA).")
        else:
            warn("nrfjprog --deviceversion returned an error.")
            info("  If 'No emulator connected': re-seat the J-Link USB cable.")
            info("  If 'Cannot read device version': try nrfjprog --recover first.")
    except FileNotFoundError:
        warn("nrfjprog not found — skipping device version query.")
    except Exception as e:
        err(f"nrfjprog error: {e}")

    ok("Device info complete.")


def _find_sniffer_hex():
    """Locate the downloaded nRF52833 nRF Sniffer .hex (firmware/download.py drops
    it under firmware/nrf52833_dk/ble_sniffer/, hex_glob '*nrf52833*')."""
    base = get_firmware_dir("nrf52833_dk") / "ble_sniffer"
    for pat in ("*nrf52833*.hex", "*52833*.hex", "*sniffer*.hex"):
        hits = sorted(base.rglob(pat))
        if hits:
            return hits[0]
    return None


def _prep_sniffer_flash(port: str) -> bool:
    """Firmware-payload PREPARE: fetch the nRF Sniffer hex + a J-Link backend so
    only the write remains. Returns True only when fully ready."""
    ready = True
    if not find_serial_port_by_vidpid(VID_PIDS):
        err("  nRF52833-DK (J-Link OB) not detected on USB — connect the 'J-LINK' port.")
        ready = False
    hexf = _find_sniffer_hex()
    if not hexf:
        info("  Fetching the nRF Sniffer firmware (nrfutil ble-sniffer)…")
        dl = Path(__file__).resolve().parent / "firmware" / "download.py"
        if dl.exists():
            run(f"python3 {dl} --tools nrf52833_dk --yes")
        hexf = _find_sniffer_hex()
    if hexf and Path(hexf).exists():
        ok(f"  Firmware ready: {hexf}")
    else:
        err("  nRF Sniffer hex unavailable — run: "
            "python3 firmware/download.py --tools nrf52833_dk --yes")
        ready = False
    if run_output("which nrfjprog JLinkExe openocd 2>/dev/null || true").strip():
        ok("  Flash backend present (nrfjprog/JLink/openocd).")
    elif get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        info("  Installing openocd (apt) as the J-Link/SWD flash backend…")
        run("sudo apt-get install -y openocd")
        if not run_output("which openocd 2>/dev/null || true").strip():
            err("  No J-Link flash backend could be provisioned.")
            ready = False
    else:
        err("  No J-Link flash backend (install nRF Command Line Tools or SEGGER J-Link).")
        ready = False
    return ready


def _autoflash_nrf_sniffer(port: str):
    """Firmware-payload FLASH: everything is prepped — write the nRF Sniffer hex."""
    hexf = _find_sniffer_hex()
    if not hexf or not Path(hexf).exists():
        err("nRF Sniffer hex missing at flash time — aborting.")
        return
    if flash_swd_hex(hexf, "nRF52833_xxAA", "NRF52"):
        ok("nRF Sniffer firmware flashed — the DK is now a BLE sniffer.")
    else:
        err("Flash failed — re-seat the J-LINK cable and retry.")


def op_flash_sniffer(port: str):
    heading("Flash nRF Sniffer Firmware")
    info("Flashing the 'nRF Sniffer for Bluetooth LE' firmware via the onboard J-Link.")
    info("This turns the nRF52833-DK into a passive BLE packet sniffer for Wireshark.")
    info("")
    info("REMINDER: this board uses nRF Sniffer — NOT Sniffle.")
    info("  Sniffle only supports Texas Instruments CC1352/CC26x2 parts and will")
    info("  NOT run on the Nordic nRF52833. Use the Nordic nRF Sniffer firmware.")
    info("")
    info("STEP 1 — DOWNLOAD the nRF Sniffer package:")
    info(f"  {SNIFFER_RELEASE_URL}")
    info("  Extract the zip. The firmware images live under: hex/")
    info("  Choose the build for the nRF52833 / PCA10100 (nRF52833-DK) board.")
    info("  Example filename: sniffer_nrf52833dk_nrf52833_<ver>.hex")
    info("")
    info("  ┌─ BOARD REVISION CAVEAT ───────────────────────────────────────────┐")
    info("  │ Some nRF52833-DK board revisions (notably PCA10100 v3) are NOT     │")
    info("  │ covered by a prebuilt nRF Sniffer .hex in the release zip and may  │")
    info("  │ require BUILDING the sniffer firmware from source.                 │")
    info("  │ Check the board revision printed on the silkscreen (near the       │")
    info("  │ PCA10100 marking) BEFORE flashing. If it is v3 and no matching     │")
    info("  │ hex exists, build from the nRF Sniffer source per Nordic's docs.   │")
    info("  └───────────────────────────────────────────────────────────────────┘")
    info("")

    # Verify the DK / J-Link is connected
    dk_port = find_serial_port_by_vidpid(VID_PIDS)
    if not dk_port:
        err("nRF52833-DK (J-Link OB) not detected.")
        info("  Ensure the DK is connected via the J-Link USB port (labelled 'J-LINK').")
        info("  Install J-Link Software: https://www.segger.com/downloads/jlink/")
        return
    info(f"nRF52833-DK detected via J-Link on {dk_port}.")

    info("Running nrfjprog --ids to confirm the J-Link connection…")
    try:
        r = run("nrfjprog --ids")
        if r.returncode != 0:
            warn("nrfjprog --ids failed. J-Link software may not be installed.")
            info("  Install from: https://www.segger.com/downloads/jlink/")
            info("  Kali/Debian: sudo dpkg -i JLink_Linux_*.deb")
            info("  macOS: brew install --cask segger-jlink")
    except FileNotFoundError:
        err("nrfjprog not found. Install nRF Command Line Tools.")
        info("  https://www.nordicsemi.com/Products/Development-tools/nRF-Command-Line-Tools")
        return

    info("")
    hex_path = prompt("Path to the nRF Sniffer .hex file (from the package hex/ folder)")
    if not hex_path:
        warn("No file path provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return
    if hex_file.suffix.lower() != ".hex":
        warn(f"Unexpected file extension: {hex_file.suffix}")
        info("  nRF Sniffer firmware is distributed as an Intel HEX (.hex) file.")
        if not confirm("Continue anyway?", default=False):
            return

    if not confirm(f"Flash {hex_file.name} to the nRF52833-DK via J-Link?", default=True):
        info("Flash cancelled.")
        return

    cmd = f"nrfjprog --program {hex_file} --sectorerase --verify --reset"
    info(f"Running: {cmd}")
    info("  --sectorerase : erase only the sectors being written")
    info("  --verify      : verify flash contents after writing")
    info("  --reset       : reset the device so the sniffer starts immediately")
    info("  This takes a few seconds. Do NOT disconnect during flashing.")
    try:
        r = run(cmd)
        if r.returncode == 0:
            ok("nRF Sniffer firmware flashed and verified via nrfjprog.")
            info("  The DK is now streaming BLE packets over the J-Link VCOM.")
            info("  Next: run 'Wireshark extcap setup' to install the plugin,")
            info("  then use 'BLE Capture' to sniff from Wireshark.")
        else:
            err("nrfjprog flash failed.")
            info("Troubleshooting:")
            info("  - Check J-Link connection: nrfjprog --ids")
            info("  - Ensure the .hex is the nRF52833 / PCA10100 sniffer build")
            info("  - If your board is PCA10100 v3, a prebuilt hex may not exist —")
            info("    build the nRF Sniffer firmware from source (see docstring caveat)")
            info("  - If 'No emulator connected': re-seat the USB cable on the J-Link port")
            info("  - Check udev rules for J-Link access (plugdev group)")
            info(f"  - Try with sudo: sudo {cmd}")
            info("  - J-Link firmware update may be needed: JLinkExe → connect → updatefw")
    except FileNotFoundError:
        err("nrfjprog not found. Install nRF Command Line Tools.")
    except Exception as e:
        err(f"nrfjprog flash error: {e}")


def op_wireshark_extcap():
    heading("Wireshark extcap Setup")
    info("Installing the nRF Sniffer Wireshark extcap plugin so the DK appears as")
    info("a capture interface named 'nRF Sniffer for Bluetooth LE'.")
    info("")
    info("The extcap plugin bridges Wireshark to the sniffer firmware over the")
    info("J-Link VCOM. Without it, Wireshark cannot see the nRF52833-DK.")
    info("")

    extcap_dir = _wireshark_extcap_dir()
    info(f"Target extcap directory: {extcap_dir}")
    info("")
    info("STEP 1 — locate the extcap/ folder inside the nRF Sniffer package you")
    info("         downloaded (same zip as the firmware). It contains:")
    info("           nrf_sniffer_ble.py     — the extcap plugin")
    info("           requirements.txt       — its Python dependencies (pyserial etc.)")
    info("           SnifferAPI/            — supporting Python package")
    info("")

    src_dir = prompt("Path to the extcap/ folder from the nRF Sniffer package")
    if not src_dir:
        warn("No path provided. Aborting.")
        return
    src = Path(src_dir)
    if not src.exists() or not src.is_dir():
        err(f"Directory not found: {src}")
        return
    plugin = src / "nrf_sniffer_ble.py"
    if not plugin.exists():
        warn(f"nrf_sniffer_ble.py not found in {src}")
        info("  Ensure you pointed at the 'extcap' folder from the nRF Sniffer zip.")
        if not confirm("Continue and copy the folder contents anyway?", default=False):
            return

    info(f"Creating extcap directory: {extcap_dir}")
    try:
        extcap_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        err(f"Could not create {extcap_dir}: {e}")
        return

    info(f"Copying extcap contents from {src} to {extcap_dir}…")
    import shutil
    copied = 0
    try:
        for item in src.iterdir():
            dest = extcap_dir / item.name
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)
            copied += 1
        ok(f"Copied {copied} item(s) into {extcap_dir}")
    except Exception as e:
        err(f"Copy failed: {e}")
        info(f"  Manual: cp -r {src}/* {extcap_dir}/")
        return

    dest_plugin = extcap_dir / "nrf_sniffer_ble.py"
    if dest_plugin.exists():
        info(f"Making the plugin executable: chmod +x {dest_plugin}")
        try:
            os.chmod(dest_plugin, 0o755)
            ok("nrf_sniffer_ble.py is now executable.")
        except Exception as e:
            warn(f"chmod failed: {e}")
            info(f"  Manual: chmod +x {dest_plugin}")

    reqs = extcap_dir / "requirements.txt"
    if reqs.exists():
        info(f"Installing extcap Python requirements from {reqs}…")
        flavor = get_os_flavor()
        bsp = "--break-system-packages" if flavor in ("kali", "debian", "ubuntu", "linux") else ""
        cmd = f'{sys.executable} -m pip install -r "{reqs}"'
        if bsp:
            cmd += f" {bsp}"
        cmd += " 2>&1"
        info(f"  {cmd}")
        r = run(cmd)
        if r.returncode == 0:
            ok("extcap requirements installed.")
        else:
            warn("pip install of extcap requirements failed.")
            info(f"  Output: {(r.stdout + r.stderr)[:300]}")
            info("  The plugin needs pyserial at minimum — ensure it is installed.")
    else:
        info("No requirements.txt found in the extcap folder — ensuring pyserial…")
        ensure_pip_packages([("serial", "pyserial")])

    info("")
    ok("Wireshark extcap setup complete.")
    info("  Restart Wireshark, then look for the capture interface:")
    info("    'nRF Sniffer for Bluetooth LE'")
    info("  If it does not appear: Help → About Wireshark → Folders → Extcap path,")
    info("  and confirm nrf_sniffer_ble.py is there and executable.")
    pause("Press ENTER to continue.")


def op_ble_capture(port: str):
    heading("BLE Capture")
    info("BLE capture with the nRF52833-DK is DRIVEN FROM WIRESHARK via the")
    info("nRF Sniffer extcap interface — there is no standalone capture CLI here.")
    info("")
    info("PREREQUISITES:")
    info("  1. nRF Sniffer firmware flashed  ('Flash nRF Sniffer firmware')")
    info("  2. Wireshark extcap plugin installed  ('Wireshark extcap setup')")
    info("")
    info(f"The DK's J-Link VCOM is currently on: {port}")
    info("")
    info("HOW TO CAPTURE:")
    info("  1. Open Wireshark.")
    info("  2. Select the interface 'nRF Sniffer for Bluetooth LE'.")
    info("  3. Open its interface options (the gear/settings icon) and select the")
    info(f"     device serial port — pick {port} (the J-Link VCOM).")
    info("  4. Optionally pick a specific advertising device to follow, or leave")
    info("     it on 'All advertising devices' to capture broadly.")
    info("  5. Start the capture. BLE advertising and (followed) connection")
    info("     packets appear as 'nordic_ble' / 'btle' frames.")
    info("")
    info("USEFUL DISPLAY FILTERS:")
    info("  btle.advertising_header.pdu_type == 0x00   ADV_IND (connectable adv)")
    info("  btle                                       all BLE link-layer packets")
    info("  nordic_ble                                 nRF Sniffer metadata layer")
    info("")
    info("CLI LAUNCH (optional):")
    info("  wireshark -i nrf_sniffer_ble -k")
    info("")
    info("REFERENCE — nRF Sniffer capture instructions:")
    info(f"  {SNIFFER_RELEASE_URL}")
    info("  See the 'nRF Sniffer for Bluetooth LE User Guide' for advanced options")
    info("  (following a device, passkey/OOB entry, and RSSI/channel filtering).")
    info("")
    info("TIP: To later crack legacy pairing from a capture, save the session as a")
    info("     .pcap and use this tool's 'Crack Pairing (crackle)' option.")
    pause("Press ENTER to continue.")


def op_crack_pairing():
    heading("Crack Pairing (crackle)")
    info("crackle cracks BLE LEGACY pairing (LE Legacy) captured with the sniffer,")
    info("recovering the Temporary Key (TK) / Long Term Key (LTK) and decrypting")
    info("the encrypted connection within the capture.")
    info("")
    info("IMPORTANT LIMITATION:")
    info("  crackle only works against BLE LEGACY pairing (Just Works / passkey).")
    info("  It does NOT break LE Secure Connections (LESC, ECDH-based) pairing.")
    info("  The capture must include the pairing exchange (from the connection")
    info("  request through key distribution).")
    info("")

    # Check crackle availability
    crackle_path = run_output("which crackle 2>/dev/null || true")
    if not (crackle_path and crackle_path.strip()):
        warn("crackle not found in PATH.")
        info("  crackle has no distro package on most systems — build from source:")
        info("    git clone https://github.com/mikeryan/crackle")
        info("    cd crackle && make")
        info("    sudo cp crackle /usr/local/bin/   (optional — put it on PATH)")
        info("  Build dependency: a C compiler (build-essential / Xcode CLT).")
        if confirm("Attempt to git clone and build crackle now?", default=False):
            build_dir = Path("/tmp/crackle_build")
            info(f"Cloning into {build_dir}…")
            run(f"rm -rf {build_dir}")
            r = run(f"git clone https://github.com/mikeryan/crackle {build_dir}")
            if r.returncode != 0:
                err("git clone failed.")
                info(f"  {(r.stdout + r.stderr)[:300]}")
                return
            info("Building crackle (make)…")
            r2 = run(f"make -C {build_dir}")
            if r2.returncode == 0 and (build_dir / "crackle").exists():
                ok(f"crackle built: {build_dir / 'crackle'}")
                crackle_path = str(build_dir / "crackle")
            else:
                err("crackle build failed.")
                info(f"  {(r2.stdout + r2.stderr)[:300]}")
                info("  Ensure a C compiler is installed (build-essential / Xcode CLT).")
                return
        else:
            return
    else:
        crackle_path = crackle_path.strip()
        ok(f"crackle found: {crackle_path}")

    info("")
    pcap_path = prompt("Path to the BLE capture .pcap file")
    if not pcap_path:
        warn("No pcap path provided. Aborting.")
        return
    pcap = Path(pcap_path)
    if not pcap.exists():
        err(f"File not found: {pcap}")
        return

    out_default = str(pcap.parent / (pcap.stem + "_decrypted.pcap"))
    out_path = prompt("Output decrypted .pcap path", default=out_default)
    out_pcap = Path(out_path)

    if not confirm(f"Run crackle on {pcap.name} → {out_pcap.name}?", default=True):
        info("Cracking cancelled.")
        return

    cmd = f"{crackle_path} -i {pcap} -o {out_pcap}"
    info(f"Running: {cmd}")
    info("  crackle will report the recovered TK/LTK if the pairing is legacy")
    info("  and present in the capture, then write the decrypted pcap.")
    try:
        r = run(cmd)
        out_text = (r.stdout + r.stderr)
        if out_text.strip():
            for line in out_text.strip().splitlines():
                info(f"  crackle: {line}")
        if r.returncode == 0 and out_pcap.exists():
            ok(f"crackle finished. Decrypted capture: {out_pcap}")
            info("  Open the decrypted pcap in Wireshark to inspect the plaintext GATT traffic.")
        elif r.returncode == 0:
            ok("crackle finished.")
            info("  No output pcap was written — the capture may not contain")
            info("  legacy pairing, or no encrypted packets were present to decrypt.")
        else:
            err("crackle returned a non-zero exit code.")
            info("Troubleshooting:")
            info("  - Confirm the capture contains a full LEGACY pairing exchange")
            info("  - LE Secure Connections (LESC) pairing cannot be cracked by crackle")
            info("  - Ensure the pcap is a raw BLE capture (nordic_ble / btle frames)")
    except FileNotFoundError:
        err("crackle not found. Build it from https://github.com/mikeryan/crackle")
    except Exception as e:
        err(f"crackle error: {e}")


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking nRF52833-DK tooling and nRF Sniffer firmware availability…")
    info("  The sniffer firmware version is bundled in the nRF Sniffer package hex/.")
    try:
        r_info = run_output("nrfjprog --version 2>/dev/null")
        if r_info:
            import re
            m = re.search(r'nrfjprog\s+([\d.]+)', r_info)
            if m:
                info(f"  nrfjprog version: {m.group(1)}")
    except Exception as e:
        info(f"  nrfjprog check failed: {e}")

    info("Checking latest nRF Sniffer for Bluetooth LE release on GitHub…")
    latest, url = check_latest_github_release("NordicSemiconductor", "nRF-Sniffer-for-Bluetooth-LE")
    if latest:
        info(f"  Latest nRF Sniffer (GitHub mirror): {latest}")
        info(f"  Release: {url}")
    else:
        info("  No GitHub release found — download the nRF Sniffer package from Nordic:")
        info(f"    {SNIFFER_RELEASE_URL}")


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

    info("BLE backend: nRF Sniffer for Bluetooth LE (Nordic) — NOT Sniffle (TI-only).")

    info("Checking udev rules for nRF52833-DK J-Link USB access…")
    _check_udev_rules()

    info("Checking nrfjprog (J-Link tool for DK programming)…")
    _check_nrfjprog()

    info("Detecting nRF52833-DK via USB VID:PIDs 1366:1015, 1366:1051…")
    info("  The onboard SEGGER J-Link OB enumerates under VID 1366 and exposes")
    info("  a CDC VCOM at /dev/ttyACM* used by the nRF Sniffer firmware.")

    found = web_detect_loop(detect_nrf52833_dk, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Nordic nRF52833-DK not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"nRF52833-DK J-Link VCOM detected on {port}")
    check_firmware_version()

    _check_dialout(port)

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        run_firmware_payload(
            fw.get("label", "Flash nRF Sniffer firmware"),
            info_fn=lambda: op_device_info(port),
            prepare_fn=lambda: _prep_sniffer_flash(port),
            flash_fn=lambda: _autoflash_nrf_sniffer(port),
            summary_lines=[
                f"Board    : {TOOL_NAME} (nRF52833-DK, PCA10100)",
                f"Firmware : {fw.get('firmware', 'nRF Sniffer for Bluetooth LE')}",
                "Flasher  : nrfjprog/JLink/openocd over the onboard J-Link (SWD)",
            ],
        )
        return

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash nRF Sniffer firmware",
        "Wireshark extcap setup",
        "BLE Capture",
        "Crack Pairing (crackle)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Nordic nRF52833-DK — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_sniffer(port)
        elif choice == 2:
            op_wireshark_extcap()
        elif choice == 3:
            op_ble_capture(port)
        elif choice == 4:
            op_crack_pairing()
        elif choice == 5:
            info("Goodbye.")
            break

        # Re-check port after operations (J-Link VCOM may re-enumerate)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
