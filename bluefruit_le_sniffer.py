#!/usr/bin/env python3
"""
Adafruit Bluefruit LE Sniffer Tool Manager
Handles device detection (onboard CP2104 USB-UART), Wireshark extcap setup for
the legacy nRF Sniffer v2 firmware, BLE capture guidance, and crackle-based
pairing decryption for captured BLE legacy pairings.

Usage:
    python3 bluefruit_le_sniffer.py

Device: Adafruit Bluefruit LE Sniffer (Adafruit product #2269)
    - nRF51822 SoC — Bluetooth Low Energy 4.0 ONLY
    - Ships PRE-FLASHED with Nordic's nRF Sniffer Firmware V2
    - Streams captured BLE packets to Wireshark via the extcap interface
    - Onboard Silicon Labs CP2104 USB-to-UART bridge (VID:PID 10C4:EA60)

HARD LIMITATIONS — state these plainly, this is the most LIMITED BLE sniffer:
    - BLE 4.0 ONLY. It cannot decode BLE 5.x-only PHYs (2M / Coded / LE Long Range).
    - BLE ONLY. It does NOT capture Bluetooth Classic (BR/EDR).
    - ONE connection at a time. It follows a single connection; it cannot track
      multiple concurrent connections like newer multi-connection sniffers.
    - NO DFU bootloader. Reflashing / updating the firmware requires an external
      J-Link (or ST-Link via OpenOCD) wired to the SWD pads (SWCLK/SWDIO). There
      is no USB-serial DFU path on this board.

USB VID:PID:
    0x10C4:0xEA60 — Silicon Labs CP2104 USB-UART bridge (onboard)

    CAVEAT: 10C4:EA60 is the GENERIC Silicon Labs CP210x VID:PID and is shared by
    a very large number of unrelated CP210x boards (ESP dev boards, USB-serial
    dongles, radios, etc.). Detection here matches ANY CP210x device — confirm the
    matched port really is the Bluefruit LE Sniffer before capturing.

Baud rate:
    460800 — the nRF51 sniffer Firmware V2 UART speed.

Linux serial permissions:
    Device appears as /dev/ttyUSB* (CP210x driver: cp210x).
    Add user to dialout: sudo usermod -aG dialout $USER (then re-login)
    Check: id  and  ls -la /dev/ttyUSB*
    Debug: dmesg | tail -20  and  lsusb | grep 10c4

nRF Sniffer v2 (nRF51) extcap reference:
    This device uses the LEGACY nRF Sniffer for Bluetooth LE v2 package
    (nrf_sniffer.py + the SnifferAPI/ Python module) — NOT the current
    nRF52-era nRF Sniffer v3/v4 extcap. Adafruit ships a fork of the v2 package.
    Extcap install location (Linux/macOS):
        ~/.config/wireshark/extcap/

crackle reference (BLE pairing decryption):
    crackle -i <input.pcap> -o <decrypted.pcap>
    Cracks BLE LEGACY pairing (all BLE 4.0 devices use legacy pairing), recovers
    the TK/STK/LTK and decrypts the encrypted connection in the capture.
    Source: https://github.com/mikeryan/crackle
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

TOOL_NAME   = "Adafruit Bluefruit LE Sniffer"
DESCRIPTION = "Adafruit #2269 — nRF51822 BLE 4.0 sniffer (Firmware V2, Wireshark extcap)"

VID_PIDS = [
    (0x10C4, 0xEA60),  # Silicon Labs CP2104 USB-UART bridge (onboard)
]

BAUD_RATE = 460800  # nRF51 sniffer Firmware V2 UART speed

CONNECT_INSTRUCTIONS = (
    "Adafruit Bluefruit LE Sniffer not detected.\n\n"
    "  1. Plug the Bluefruit LE Sniffer (#2269) into a USB port.\n"
    "     The onboard Silicon Labs CP2104 enumerates as VID:PID 10C4:EA60.\n"
    "  2. Linux: it appears as /dev/ttyUSB* (cp210x kernel driver).\n"
    "     macOS: it appears as /dev/tty.usbserial-* or /dev/tty.SLAB_USBtoUART.\n"
    "  3. If it is not detected: try a different USB port or a known-good\n"
    "     data-capable USB cable (some cables are power-only).\n\n"
    "  CAVEAT — SHARED VID:PID:\n"
    "    10C4:EA60 is the generic Silicon Labs CP210x ID used by MANY unrelated\n"
    "    boards (ESP dev boards, serial dongles, radios). If you have other\n"
    "    CP210x devices attached, detection may match one of THEM instead of the\n"
    "    sniffer. Unplug other CP210x devices, or confirm the matched port is the\n"
    "    sniffer (Device Info shows the serial number to help identify it).\n\n"
    "  Linux permissions:\n"
    "    sudo usermod -aG dialout $USER  (then re-login)\n"
    "    Check: dmesg | tail -20\n"
    "    Check: lsusb | grep 10c4\n"
    "    Driver: lsmod | grep cp210x"
)

UDEV_RULES_CONTENT = (
    '# Adafruit Bluefruit LE Sniffer udev rules\n'
    '# Onboard Silicon Labs CP2104 USB-UART (VID:PID 10C4:EA60)\n'
    '# NOTE: 10C4:EA60 is the generic CP210x ID — this rule also matches other\n'
    '# CP210x devices attached to the system.\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", '
    'MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-adafruit-ble-sniffer.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_bluefruit_sniffer() -> bool:
    info("Scanning USB for CP210x bridge (VID:PID 10C4:EA60)…")
    info("  NOTE: 10C4:EA60 is shared by many CP210x boards — confirm it's the sniffer.")
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for the Bluefruit LE Sniffer CP2104 on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for the Bluefruit LE Sniffer (CP2104)…")
    info(f"  Writing to: {UDEV_RULES_PATH}")
    info("  NOTE: this rule matches ALL CP210x devices (shared 10C4:EA60 ID).")
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


# ── Serial helpers ────────────────────────────────────────────────────────────

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


def _extcap_dir() -> Path:
    """Return the Wireshark per-user extcap directory for this platform."""
    return Path.home() / ".config" / "wireshark" / "extcap"


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Enumerating the Bluefruit LE Sniffer's onboard CP2104 serial port.")
    info("")
    info("USB port details:")
    matched_is_cp210x = False
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
                if p.vid == 0x10C4 and p.pid == 0xEA60:
                    matched_is_cp210x = True
    except Exception as e:
        warn(f"Could not enumerate USB ports via pyserial: {e}")

    info("")
    info("SHARED-VID CAVEAT:")
    if matched_is_cp210x:
        warn("  The matched port is a generic Silicon Labs CP210x (10C4:EA60).")
        warn("  This VID:PID is used by MANY unrelated CP210x boards — this may")
        warn("  NOT be the Bluefruit LE Sniffer if you have other CP210x devices.")
        info("  Confirm by the serial number above, or unplug other CP210x devices")
        info("  and re-run so only the sniffer remains.")
    else:
        info("  Matched port is not a plain CP2104 — double-check the device.")

    info("")
    info("DEVICE LIMITS (Adafruit #2269, nRF51822):")
    info("  - Bluetooth LE 4.0 ONLY — cannot decode BLE 5.x-only PHYs.")
    info("  - BLE ONLY — does NOT capture Bluetooth Classic (BR/EDR).")
    info("  - Follows ONE connection at a time (no multi-connection tracking).")
    info("  - Ships with Nordic nRF Sniffer Firmware V2 (nRF51 legacy sniffer).")
    info("  - NO DFU: reflashing needs a J-Link + SWD (see 'Reflash firmware').")
    info("")
    info(f"  Configured UART baud for Firmware V2: {BAUD_RATE}")
    ok("Device info complete.")


def op_extcap_setup(port: str):
    heading("Wireshark extcap Setup")
    info("Setting up the LEGACY nRF Sniffer v2 extcap for the nRF51 sniffer.")
    info("")
    info("IMPORTANT — WHICH EXTCAP:")
    info("  The Bluefruit LE Sniffer (nRF51822) uses the nRF Sniffer for")
    info("  Bluetooth LE *v2* package (nrf_sniffer.py + the SnifferAPI/ module).")
    info("  This is the LEGACY package for nRF51 hardware. Do NOT use the current")
    info("  nRF52-era nRF Sniffer v3/v4 extcap — it will not talk to this board.")
    info("  Adafruit maintains a fork of the v2 package for this product.")
    info("")
    info("DOWNLOAD:")
    info("  - Adafruit's nRF Sniffer v2 fork / package for the Bluefruit LE Sniffer:")
    info("    https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer")
    info("  - Or Nordic's archived nRF Sniffer for Bluetooth LE v2 (nRF51) package.")
    info("  The package contains an extcap/ folder with nrf_sniffer.py and a")
    info("  SnifferAPI/ Python module plus a requirements.txt (needs pyserial).")
    info("")

    extcap_dir = _extcap_dir()
    info("INSTALL STEPS:")
    info(f"  1. Create the extcap dir:  mkdir -p {extcap_dir}")
    info(f"  2. Copy the extcap script:  cp nrf_sniffer.py {extcap_dir}/")
    info(f"  3. Copy the API module:     cp -r SnifferAPI {extcap_dir}/")
    info(f"  4. Make it executable:      chmod +x {extcap_dir}/nrf_sniffer.py")
    info("  5. Install Python deps:     pip install pyserial  (extcap requirement)")
    info("  6. Restart Wireshark — an interface named 'nRF Sniffer' appears,")
    info(f"     bound to the CP2104 serial port ({port}).")
    info("")

    if confirm("Create the extcap directory now?", default=True):
        try:
            extcap_dir.mkdir(parents=True, exist_ok=True)
            ok(f"extcap directory ready: {extcap_dir}")
        except Exception as e:
            err(f"Could not create extcap directory: {e}")
            info(f"  Manual: mkdir -p {extcap_dir}")

    existing = extcap_dir / "nrf_sniffer.py"
    if existing.exists():
        ok(f"Found existing extcap script: {existing}")
        info("  Wireshark should list the 'nRF Sniffer' interface after a restart.")
    else:
        warn("nrf_sniffer.py is not yet in the extcap directory.")
        info("  Copy it from the downloaded nRF Sniffer v2 package (steps above).")

    info("")
    info("Ensuring pyserial (required by the extcap script)…")
    ensure_pip_packages([("serial", "pyserial")])

    info("")
    info("VERIFY:")
    info("  - In Wireshark, refresh interfaces (Capture → Refresh Interfaces).")
    info("  - The 'nRF Sniffer' interface should appear. Its gear/options let you")
    info(f"    select the serial port ({port}) and the device to follow.")
    info("  - CLI check: nrf_sniffer.py --extcap-interfaces  (lists the interface).")
    pause("Press ENTER to continue.")


def op_ble_capture(port: str):
    heading("BLE Capture")
    info("BLE capture on this device is driven FROM Wireshark via the extcap.")
    info("This tool does not capture directly — it guides you through Wireshark.")
    info("")
    info("PREREQUISITE:")
    info("  The nRF Sniffer v2 extcap must be installed (see 'Wireshark extcap")
    info("  setup'). Without it Wireshark has no 'nRF Sniffer' interface.")
    info("")
    info("CAPTURE STEPS:")
    info("  1. Open Wireshark.")
    info("  2. Select the 'nRF Sniffer' capture interface.")
    info(f"  3. In the interface options, choose the CP2104 serial port: {port}")
    info("  4. Pick the advertising device to follow from the device list, then")
    info("     start the capture.")
    info("")
    info("SINGLE-CONNECTION BEHAVIOUR:")
    info("  This sniffer follows ONE connection at a time. When you select a")
    info("  device to follow, it locks onto that device's advertising/connection.")
    info("  It cannot track multiple concurrent connections — to watch a different")
    info("  device, stop and re-select in the interface options.")
    info("")
    info("BLE 4.0 SCOPE:")
    info("  - Captures BLE 4.0 advertising + a single followed connection.")
    info("  - Does NOT capture Bluetooth Classic (BR/EDR).")
    info("  - Cannot decode BLE 5.x-only PHYs (2M / Coded).")
    info("")
    info("USEFUL WIRESHARK DISPLAY FILTERS:")
    info("  btle                                   All BLE link-layer packets")
    info("  btle.advertising_header.pdu_type == 0  ADV_IND advertising packets")
    info("  btle.data_header                       Connection (data channel) PDUs")
    info("")
    info("SAVING FOR CRACKLE:")
    info("  To later decrypt a captured pairing, save the capture as a .pcap and")
    info("  feed it to the 'Crack Pairing (crackle)' menu option.")
    pause("Press ENTER to continue.")


def op_crack_pairing():
    heading("Crack Pairing (crackle)")
    info("Decrypt a captured BLE LEGACY pairing with crackle.")
    info("crackle recovers the TK/STK/LTK from a captured legacy pairing exchange")
    info("and decrypts the encrypted connection in the pcap.")
    info("")
    info("SCOPE NOTE:")
    info("  crackle targets BLE LEGACY pairing. Every BLE 4.0 device uses legacy")
    info("  pairing (LE Secure Connections arrived with BLE 4.2), so this matches")
    info("  exactly what the Bluefruit LE Sniffer can capture.")
    info("")

    # Ensure crackle is available.
    have = ensure_system_tool(
        "crackle",
        "git clone https://github.com/mikeryan/crackle && cd crackle && make",
        apt_pkg="crackle",
        brew_pkg=None,
    )
    if not have:
        warn("crackle is not installed.")
        info("BUILD FROM SOURCE:")
        info("  git clone https://github.com/mikeryan/crackle")
        info("  cd crackle && make")
        info("  sudo cp crackle /usr/local/bin/   (optional — put it on PATH)")
        if confirm("Attempt to clone and build crackle now?", default=False):
            build_dir = Path.home() / ".quiver_crackle_build"
            info(f"Cloning into {build_dir / 'crackle'}…")
            build_dir.mkdir(parents=True, exist_ok=True)
            r_clone = run(
                f"git clone https://github.com/mikeryan/crackle "
                f"{build_dir / 'crackle'}"
            )
            if r_clone.returncode != 0:
                err("git clone failed.")
                info("  Check network access and that git is installed.")
                return
            info("Building crackle (make)…")
            r_make = run(f"make -C {build_dir / 'crackle'}")
            if r_make.returncode == 0:
                ok(f"crackle built: {build_dir / 'crackle' / 'crackle'}")
                info("  Add it to PATH or reference it directly below.")
            else:
                err("make failed.")
                info("  Ensure a C compiler and libpcap headers are installed:")
                info("    Linux: sudo apt-get install build-essential libpcap-dev")
                info("    macOS: brew install libpcap")
                return
        else:
            return

    pcap_path = prompt("Path to input .pcap capture file")
    if not pcap_path:
        warn("No pcap path provided. Aborting.")
        return
    pcap = Path(pcap_path)
    if not pcap.exists():
        err(f"File not found: {pcap}")
        return
    if pcap.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        warn(f"Expected a pcap capture, got: {pcap.name}")
        if not confirm("Continue anyway?", default=False):
            return

    default_out = str(pcap.parent / (pcap.stem + "_decrypted.pcap"))
    out_path = prompt("Output (decrypted) .pcap path", default=default_out)
    out_pcap = Path(out_path)

    if not confirm(f"Run crackle on {pcap.name} → {out_pcap.name}?", default=True):
        info("Cancelled.")
        return

    cmd = f"crackle -i {pcap} -o {out_pcap}"
    info(f"Running: {cmd}")
    info("  crackle scans the capture for a legacy pairing and, if found,")
    info("  brute-forces the TK, derives the keys, and writes a decrypted pcap.")
    try:
        r = run(cmd)
        if r.returncode == 0:
            ok(f"crackle finished. Decrypted output: {out_pcap}")
            info("  Open the decrypted pcap in Wireshark to read the plaintext")
            info("  ATT/GATT traffic that was previously encrypted.")
        else:
            err("crackle returned an error / found nothing to decrypt.")
            info("Troubleshooting:")
            info("  - The capture must contain the FULL legacy pairing exchange")
            info("    (pairing request/response + confirm/random) to recover the TK.")
            info("  - If the devices used LE Secure Connections (BLE 4.2+), crackle")
            info("    cannot crack it — but the Bluefruit sniffer is BLE 4.0 only.")
            info("  - Ensure the pcap was saved with the nRF Sniffer link-layer")
            info("    (BLE) encapsulation, not a stripped/HCI format.")
    except FileNotFoundError:
        err("crackle not found on PATH.")
        info("  Reference the built binary directly, e.g.:")
        info(f"    ~/.quiver_crackle_build/crackle/crackle -i {pcap} -o {out_pcap}")
    except Exception as e:
        err(f"crackle error: {e}")


def _find_nrf51_hex():
    """Locate an nRF51 sniffer .hex to flash. There is no automated download source
    for the Bluefruit sniffer firmware, so the operator drops the image under
    firmware/bluefruit_le_sniffer/ (any subdir) before selecting the payload."""
    base = get_firmware_dir("bluefruit_le_sniffer")
    for pat in ("*nrf51*.hex", "*51822*.hex", "*sniffer*.hex", "*.hex"):
        hits = sorted(base.rglob(pat))
        if hits:
            return hits[0]
    return None


def _prep_reflash(port: str) -> bool:
    """Firmware-payload PREPARE: confirm an nRF51 hex + a J-Link backend are present
    so only the SWD write remains. Returns True only when fully ready.

    NOTE: the Bluefruit sniffer (nRF51822) has NO DFU/USB reflash path — an external
    SWD programmer (J-Link/ST-Link) wired to the SWD pads is required, and the nRF51
    firmware image is not redistributable, so it must be supplied by the operator."""
    ready = True
    hexf = _find_nrf51_hex()
    if hexf and Path(hexf).exists():
        ok(f"  Firmware ready: {hexf}")
    else:
        err("  No nRF51 sniffer .hex found. Place the image under:")
        err(f"    {get_firmware_dir('bluefruit_le_sniffer')}")
        err("  (nRF51822 firmware is not auto-downloadable — supply it manually.)")
        ready = False
    if run_output("which nrfjprog JLinkExe openocd 2>/dev/null || true").strip():
        ok("  Flash backend present (nrfjprog/JLink/openocd).")
    elif get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        info("  Installing openocd (apt) as the SWD flash backend…")
        run("sudo apt-get install -y openocd")
        if not run_output("which openocd 2>/dev/null || true").strip():
            err("  No SWD flash backend could be provisioned.")
            ready = False
    else:
        err("  No SWD flash backend (install nRF Command Line Tools or SEGGER J-Link).")
        ready = False
    warn("  External SWD wiring required: SWDIO/SWCLK/GND/VTref → programmer.")
    return ready


def _autoflash_reflash(port: str):
    """Firmware-payload FLASH: everything is prepped — write the nRF51 hex over SWD."""
    hexf = _find_nrf51_hex()
    if not hexf or not Path(hexf).exists():
        err("nRF51 sniffer hex missing at flash time — aborting.")
        return
    if flash_swd_hex(hexf, "nRF51822_xxAA", "NRF51"):
        ok("Bluefruit sniffer firmware flashed over SWD.")
    else:
        err("Flash failed — check SWD wiring (SWDIO/SWCLK/GND/VTref) and retry.")


def op_reflash_firmware():
    heading("Reflash Firmware (J-Link + SWD)")
    info("This is INFORMATIONAL. This tool does NOT perform an automated flash.")
    info("")
    info("WHY NO AUTOMATED FLASH:")
    info("  The Bluefruit LE Sniffer (nRF51822) has NO DFU bootloader and no")
    info("  USB-serial firmware update path. The CP2104 is only a UART bridge to")
    info("  the nRF51 — it cannot reprogram the nRF51's flash. Updating or")
    info("  replacing the sniffer firmware requires an external SWD programmer.")
    info("")
    info("WHAT YOU NEED:")
    info("  - A SEGGER J-Link (any variant), OR an ST-Link driven via OpenOCD.")
    info("  - Wires to the board's SWD pads:")
    info("      SWDIO  → J-Link SWDIO")
    info("      SWCLK  → J-Link SWCLK")
    info("      GND    → J-Link GND")
    info("      VTref  → board 3.3V (target reference voltage)")
    info("  - The nRF51822 sniffer firmware .hex from Adafruit / Nordic.")
    info("")
    info("FIRMWARE SOURCE:")
    info("  Adafruit Bluefruit LE Sniffer firmware (nRF51822):")
    info("    https://github.com/adafruit/Adafruit_BLESniffer_Python")
    info("    https://learn.adafruit.com/introducing-the-adafruit-bluefruit-le-sniffer")
    info("  Nordic nRF Sniffer for Bluetooth LE (v2, nRF51) firmware hex is in the")
    info("  archived v2 package.")
    info("")
    info("FLASH (manual, at your own risk) — J-Link example:")
    info("    nrfjprog --family NRF51 --program sniffer_nrf51822.hex --chiperase")
    info("    nrfjprog --family NRF51 --reset")
    info("  OpenOCD + ST-Link example:")
    info("    openocd -f interface/stlink.cfg -f target/nrf51.cfg \\")
    info("        -c 'program sniffer_nrf51822.hex verify reset exit'")
    info("")
    warn("A bad flash can brick the sniffer. Only proceed if you have a working")
    warn("SWD programmer and the correct nRF51822 firmware image.")

    info("")
    info("Checking latest Adafruit sniffer firmware release on GitHub…")
    latest, url = check_latest_github_release("adafruit", "Adafruit_BLESniffer_Python")
    if latest:
        info(f"  Latest tag: {latest}")
        info(f"  Release   : {url}")
    else:
        warn("Could not reach GitHub for a version check.")
    pause("Press ENTER to continue.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial for USB CDC/UART serial communication.
    info("Ensuring pyserial for CP2104 USB-UART communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    # requests for GitHub API version checks.
    info("Ensuring requests library for version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Checking udev rules for CP2104 USB access…")
    _check_udev_rules()

    info("Detecting Bluefruit LE Sniffer via CP2104 VID:PID 10C4:EA60…")
    info("  Onboard bridge: Silicon Labs CP2104 USB-UART")
    info("  CAVEAT: 10C4:EA60 is the generic CP210x ID — shared by many boards.")
    info("          Confirm the matched port is really the sniffer.")

    found = web_detect_loop(
        detect_bluefruit_sniffer, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800
    )
    if not found:
        err("Adafruit Bluefruit LE Sniffer not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"CP2104 serial port detected on {port}")
    warn("Confirm this is the Bluefruit LE Sniffer — 10C4:EA60 is a shared CP210x ID.")

    info("Device summary:")
    info("  Adafruit #2269 — nRF51822, BLE 4.0 ONLY, single connection, BLE-only.")
    info("  Ships with Nordic nRF Sniffer Firmware V2. No DFU (SWD reflash only).")

    _check_dialout(port)

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        run_firmware_payload(
            fw.get("label", "Reflash firmware (J-Link + SWD)"),
            info_fn=lambda: op_device_info(port),
            prepare_fn=lambda: _prep_reflash(port),
            flash_fn=lambda: _autoflash_reflash(port),
            summary_lines=[
                f"Board    : {TOOL_NAME} (Adafruit #2269, nRF51822)",
                f"Firmware : {fw.get('firmware', 'nRF Sniffer V2 (nRF51)')}",
                "Flasher  : nrfjprog/JLink/openocd over EXTERNAL SWD (no DFU path)",
            ],
        )
        return

    MENU_OPTIONS = [
        "Device Info",
        "Wireshark extcap setup",
        "BLE Capture",
        "Crack Pairing (crackle)",
        "FIRMWARE - Reflash firmware (J-Link + SWD)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Adafruit Bluefruit LE Sniffer — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_extcap_setup(port)
        elif choice == 2:
            op_ble_capture(port)
        elif choice == 3:
            op_crack_pairing()
        elif choice == 4:
            op_reflash_firmware()
        elif choice == 5:
            info("Goodbye.")
            break

        # Re-check port after operations (device may have been replugged).
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
