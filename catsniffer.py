#!/usr/bin/env python3
"""
CatSniffer v3 Tool Manager (Electronic Cats / LilyGo)

Handles device detection, and firmware flashing of the on-board TI CC1352P7
radio via the SAMD21 USB bridge's serial ROM bootloader. Offers three radio
firmwares:
  1. Sniffle    — NCC Group BLE 5 sniffer (Bluetooth Rx), prebuilt CC1352P7 hex.
  2. CatSniffer — Electronic Cats multi-protocol firmware (Zigbee/802.15.4 +
                  sub-GHz sniff).
  3. SmartRF    — TI 802.15.4 / Zigbee packet sniffer firmware (Zigbee Rx).

Usage:
    python3 catsniffer.py

HARDWARE (READ BEFORE FLASHING):
    CatSniffer v3 pairs a TI CC1352P7 multi-band radio with a Microchip SAMD21
    that acts as the USB-to-serial bridge. You do NOT flash the CC1352 over
    JTAG/XDS110 here — you flash it over the CC13xx/CC26xx serial ROM bootloader,
    reached THROUGH the SAMD21 bridge. The community "catnip" uploader wraps this;
    under the hood it is the same JelmerT/cc2538-bsl serial-bootloader flasher
    used for the Sonoff / LilyGo CC-radio dongles. This module uses cc2538-bsl
    directly (the community-standard flasher) so no extra vendor tooling is needed.

    The SAMD21 bridge firmware maps DTR/RTS to the CC1352's RESET/BOOT lines, so
    cc2538-bsl can toggle the radio into the bootloader automatically. If auto
    entry fails, the SAMD21 bridge firmware may need reflashing (out of scope
    here) or the board's boot button held during reset.

Serial port:
    The SAMD21 enumerates as a USB CDC ACM port. On Linux it appears as
    /dev/ttyACM*, on macOS as /dev/tty.usbmodem*. Add your user to the dialout
    group (Linux) for access: sudo usermod -aG dialout $USER (then re-login).

Firmware sources:
    Sniffle    : https://github.com/nccgroup/Sniffle/releases  (sniffle_cc1352p7_*.hex)
    CatSniffer : https://github.com/ElectronicCats/CatSniffer-Firmware/releases
    SmartRF    : TI SmartRF Packet Sniffer 2 / Electronic Cats sniffer_fw build.
"""

import sys
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, ensure_pip_packages, ensure_system_tool,
    require_sudo, sudo_run,
    ensure_apt_packages, ensure_brew_packages,
    web_detect_loop, run_streaming,
    get_firmware_dir, download_firmware, get_github_release_asset_url,
    check_latest_github_release,
    selected_firmware_payload, run_firmware_payload,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "CatSniffer v3"
DESCRIPTION = "Electronic Cats CatSniffer v3 — CC1352P7 radio behind a SAMD21 USB bridge (BLE/Zigbee/sub-GHz sniffer)"

# USB VID:PIDs for the SAMD21 USB bridge on the CatSniffer v3.
# NOTE: Electronic Cats / LilyGo boards have shipped with more than one SAMD21
# USB descriptor across batches. The values below cover the community-observed
# candidates (pid.codes-registered Electronic Cats IDs + the SAMD21 UF2/CDC IDs).
# If your unit does not match, add its VID:PID (see `python3 -m serial.tools.list_ports -v`)
# and it will be detected. Detection falls back to any CDC ACM port if none match.
VID_PIDS = [
    (0x239A, 0x0029),  # Microchip/Adafruit SAMD21 CDC (UF2 bootloader family)
    (0x239A, 0x8029),
    (0x1209, 0x2017),  # Electronic Cats (pid.codes vendor block) — CatSniffer
    (0x2E8A, 0x000A),  # LilyGo-variant CDC
    (0x10C4, 0xEA60),  # CP210x (some bridge variants)
    (0x1A86, 0x7523),  # CH340  (some bridge variants)
]

BSL_BAUD = 500000

CC2538_BSL_REPO = "https://github.com/JelmerT/cc2538-bsl"

CONNECT_INSTRUCTIONS = (
    "CatSniffer v3 not detected.\n\n"
    "  1. Connect the CatSniffer v3 via its USB-C port.\n"
    "  2. The on-board SAMD21 enumerates as a USB CDC serial port:\n"
    "       Linux : /dev/ttyACM*\n"
    "       macOS : /dev/tty.usbmodem*\n"
    "  3. If nothing appears:\n"
    "       - Try a different USB-C cable (must be data-capable, not charge-only).\n"
    "       - The SAMD21 bridge firmware must be present. If the board only shows\n"
    "         a UF2 mass-storage drive, the bridge sketch needs (re)flashing first.\n"
    "  4. Linux permissions:\n"
    "       sudo usermod -aG dialout $USER   (then log out / in)\n"
    "       Check: ls -la /dev/ttyACM*  and  dmesg | tail -20\n\n"
    "  Firmware is flashed to the CC1352P7 over the serial bootloader (cc2538-bsl)\n"
    "  through the SAMD21 bridge — no XDS110 / JTAG probe is used.\n"
    "  Sources:\n"
    "    Sniffle    : https://github.com/nccgroup/Sniffle/releases\n"
    "    CatSniffer : https://github.com/ElectronicCats/CatSniffer-Firmware/releases"
)


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    info("Scanning USB for the CatSniffer v3 SAMD21 bridge (CDC serial)…")
    if find_serial_port_by_vidpid(VID_PIDS) is not None:
        return True
    # Fallback: the SAMD21 descriptor varies by batch — accept any CDC ACM port.
    return _first_cdc_port() is not None


def _first_cdc_port():
    """Best-effort: return the first USB CDC ACM / usbmodem serial port, or None.
    Used as a fallback when the exact SAMD21 VID:PID is not in VID_PIDS."""
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            dev = (p.device or "")
            if "ttyACM" in dev or "usbmodem" in dev or "ttyUSB" in dev:
                return dev
    except Exception:
        pass
    return None


def _resolve_port():
    """Resolve the CatSniffer serial port: prefer a known VID:PID, else the first
    CDC ACM port."""
    return find_serial_port_by_vidpid(VID_PIDS) or _first_cdc_port()


# ── cc2538-bsl (serial bootloader flasher) ────────────────────────────────────

def _bsl_script() -> Path:
    return Path(__file__).parent / "cc2538-bsl" / "cc2538-bsl.py"


def _ensure_cc2538_bsl() -> Path:
    """Clone JelmerT/cc2538-bsl (the CC2538/CC26xx/CC13xx serial-bootloader
    flasher) if absent and return the path to cc2538-bsl.py, or None on failure.
    Idempotent — a present checkout is reused."""
    bsl = _bsl_script()
    if bsl.exists():
        ok(f"  cc2538-bsl present: {bsl}")
        return bsl
    if not ensure_system_tool("git", "https://git-scm.com/downloads",
                              apt_pkg="git", brew_pkg="git"):
        err("  git not found — cannot fetch cc2538-bsl.")
        info(f"  Manual: git clone {CC2538_BSL_REPO} {bsl.parent}")
        return None
    clone_dir = bsl.parent
    info(f"  Cloning cc2538-bsl from {CC2538_BSL_REPO} …")
    r = run(f"git clone {CC2538_BSL_REPO} {clone_dir}")
    if r.returncode == 0 and bsl.exists():
        ok("  cc2538-bsl cloned.")
        return bsl
    err("  Failed to clone cc2538-bsl. Ensure git is installed and retry.")
    info(f"  Manual: git clone {CC2538_BSL_REPO} {clone_dir}")
    return None


# ── Firmware sourcing ─────────────────────────────────────────────────────────

# Each firmware key describes where to source the CC1352P7 .hex and how to label
# it. Auto-download is best-effort (release asset names are not standardised); if
# it fails, the operator can drop a .hex into the tool's firmware dir and prepare
# picks it up.
CATSNIFFER_FW = {
    "Sniffle": {
        "subdir": "sniffle",
        "owner": "nccgroup", "repo": "Sniffle",
        # Sniffle ships a per-chip prebuilt; the CatSniffer v3 carries CC1352P7.
        "patterns": [r"sniffle.*cc1352p7.*\.hex$",
                     r"sniffle.*p7.*\.hex$"],
        "src": "https://github.com/nccgroup/Sniffle/releases",
        "label": "Flash Sniffle BLE sniffer",
        "desc": "Sniffle BLE 5 sniffer (CC1352P7) — Bluetooth Rx",
    },
    "CatSnifferMultiprotocol": {
        "subdir": "multiprotocol",
        "owner": "ElectronicCats", "repo": "CatSniffer-Firmware",
        # Electronic Cats multi-protocol build (802.15.4 / Zigbee + sub-GHz sniff).
        "patterns": [r".*multiprotocol.*cc1352p7.*\.hex$",
                     r".*catsniffer.*cc1352p7.*\.hex$",
                     r".*multiprotocol.*\.hex$"],
        "src": "https://github.com/ElectronicCats/CatSniffer-Firmware/releases",
        "label": "Flash CatSniffer multiprotocol firmware",
        "desc": "Electronic Cats multi-protocol firmware — Zigbee/802.15.4 + sub-GHz Rx",
    },
    "SmartRFZigbeeSniffer": {
        "subdir": "smartrf",
        "owner": "ElectronicCats", "repo": "CatSniffer-Firmware",
        # TI SmartRF 802.15.4 packet-sniffer build. TI's own SmartRF Packet
        # Sniffer 2 firmware is login-gated on ti.com, so we source the equivalent
        # sniffer_fw build packaged by Electronic Cats. If it cannot be found,
        # drop a TI sniffer_fw CC1352P7 .hex into the firmware dir manually.
        "patterns": [r".*sniffer_fw.*cc1352p7.*\.hex$",
                     r".*smartrf.*cc1352p7.*\.hex$",
                     r".*sniffer_fw.*\.hex$",
                     r".*802154.*\.hex$"],
        "src": "https://github.com/ElectronicCats/CatSniffer-Firmware/releases "
               "(or TI SmartRF Packet Sniffer 2)",
        "label": "Flash SmartRF 802.15.4 Zigbee sniffer",
        "desc": "TI SmartRF 802.15.4 / Zigbee packet sniffer — Zigbee Rx",
    },
}


def _fw_variant_dir(subdir: str) -> Path:
    d = get_firmware_dir("catsniffer") / subdir
    d.mkdir(parents=True, exist_ok=True)
    return d


def _find_local_hex(subdir: str):
    d = _fw_variant_dir(subdir)
    hexes = sorted(d.glob("*.hex"))
    return hexes[-1] if hexes else None


def _download_fw_hex(name: str):
    """Best-effort auto-download of the CC1352P7 .hex for firmware *name* from its
    documented GitHub release. Returns the .hex Path or None."""
    spec = CATSNIFFER_FW[name]
    d = _fw_variant_dir(spec["subdir"])
    for pat in spec["patterns"]:
        url = get_github_release_asset_url(spec["owner"], spec["repo"], "", pat)
        if url:
            dest = d / url.split("/")[-1]
            if download_firmware(url, dest, f"CatSniffer {name}") and dest.exists():
                return dest
    return None


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("BOARD: CatSniffer v3 (Electronic Cats / LilyGo)")
    info("  Radio  : TI CC1352P7 (multi-band 2.4 GHz + sub-1 GHz)")
    info("  Bridge : Microchip SAMD21 USB-to-serial (exposes the CDC port below)")
    info("  Flash  : CC1352P7 serial ROM bootloader via cc2538-bsl (through SAMD21)")
    info("")
    info(f"Serial port: {port}")
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.device == port:
                info(f"Description : {p.description}")
                info(f"Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"VID:PID     : {vid}:{pid}")
                info(f"Serial No.  : {p.serial_number or 'N/A'}")
    except Exception as e:
        warn(f"Could not enumerate serial port details: {e}")
    info("")
    info("Troubleshooting:")
    info("  - 'Permission denied' → add user to dialout group and re-login.")
    info("  - No port at all → the SAMD21 bridge firmware may be missing; if the")
    info("    board only shows a UF2 drive, reflash the bridge sketch first.")
    ok("Device info complete.")


def op_flash_firmware(port: str):
    """Interactive (menu) flash: pick a firmware, source the hex, write it."""
    heading("Flash CC1352P7 Firmware (serial bootloader)")
    names = list(CATSNIFFER_FW)
    idx = numbered_menu("Select firmware to flash",
                        [f"{n} — {CATSNIFFER_FW[n]['desc']}" for n in names])
    name = names[idx]
    spec = CATSNIFFER_FW[name]

    bsl = _ensure_cc2538_bsl()
    if not bsl:
        return

    hex_file = _find_local_hex(spec["subdir"]) or _download_fw_hex(name)
    if not hex_file or not Path(hex_file).exists():
        err(f"{name} firmware .hex could not be sourced automatically.")
        info(f"  Drop a CC1352P7 .hex into: {_fw_variant_dir(spec['subdir'])}")
        info(f"  Source: {spec['src']}")
        manual = prompt("Path to a .hex to flash (or leave blank to abort)")
        if not manual:
            return
        hex_file = Path(manual)
        if not hex_file.exists():
            err(f"File not found: {hex_file}")
            return

    info(f"Firmware: {hex_file}")
    if not confirm(f"Flash {Path(hex_file).name} to the CC1352P7 on {port}?", default=True):
        info("Flash cancelled.")
        return
    _bsl_flash(bsl, port, Path(hex_file))


def _bsl_flash(bsl: Path, port: str, hex_file: Path):
    """Write *hex_file* to the CC1352P7 via cc2538-bsl over the SAMD21 bridge.
    Streams the flasher output; surfaces errors."""
    # -e erase, -w write, -v verify; DTR/RTS bootloader entry is handled by
    # cc2538-bsl against the SAMD21 bridge's RESET/BOOT mapping.
    cmd = [
        sys.executable, str(bsl),
        "-e", "-w", "-v",
        "-p", port,
        "--bootloader-sonoff-usb",
        str(hex_file),
    ]
    info(f"Running: {' '.join(cmd)}")
    info("  cc2538-bsl toggles the CC1352P7 into its serial bootloader via the")
    info("  SAMD21 bridge, then erases, writes and verifies the image.")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(f"  cc2538-bsl: {l}"), timeout=300)
        if rc == 0:
            ok("Firmware flash complete.")
            info("  The CC1352P7 resets into the new firmware. Give it a few seconds.")
        else:
            err(f"cc2538-bsl exited with code {rc}.")
            info("Troubleshooting:")
            info("  - Ensure no other process holds the serial port (close Wireshark/monitors).")
            info("  - If bootloader entry fails, the SAMD21 bridge firmware may not map")
            info("    RESET/BOOT — try holding the board's boot button during flash, or")
            info("    drop the '--bootloader-sonoff-usb' flag / add '--bootloader-invert-lines'.")
            info("  - Verify pyserial is installed: python3 -c 'import serial'.")
    except Exception as e:
        err(f"Firmware flash failed: {e}")
        info("  Ensure pyserial is installed and the port is not in use.")


# ── Firmware payloads (main-page "FIRMWARE - ") ───────────────────────────────

def _prep_flash(name: str, port: str, staged: dict) -> bool:
    """PREPARE step: ensure cc2538-bsl is present and the firmware .hex is ready
    (downloaded or operator-supplied). Returns True only when ready to flash;
    False aborts BEFORE the confirm."""
    ready = True
    spec = CATSNIFFER_FW[name]

    info("Ensuring pyserial (required by cc2538-bsl)…")
    ensure_pip_packages([("serial", "pyserial")])

    bsl = _ensure_cc2538_bsl()
    if bsl:
        staged["bsl"] = str(bsl)
    else:
        err("  cc2538-bsl serial flasher unavailable — cannot flash.")
        ready = False

    hex_file = _find_local_hex(spec["subdir"]) or _download_fw_hex(name)
    if hex_file and Path(hex_file).exists():
        ok(f"  Firmware ready: {hex_file}")
        staged["hex"] = str(hex_file)
    else:
        err(f"  {name} firmware .hex could not be sourced automatically.")
        info(f"  Drop a CC1352P7 .hex into: {_fw_variant_dir(spec['subdir'])}")
        info(f"  Source: {spec['src']}")
        ready = False

    if not port:
        err("  No serial port resolved for the CatSniffer — cannot flash.")
        ready = False

    return ready


def _flash_payload(port: str, staged: dict):
    """FLASH step: everything is prepped — just write."""
    bsl = staged.get("bsl")
    hex_file = staged.get("hex")
    if not bsl or not Path(bsl).exists():
        err("cc2538-bsl missing at flash time — aborting.")
        return
    if not hex_file or not Path(hex_file).exists():
        err("Firmware .hex missing at flash time — aborting.")
        return
    _bsl_flash(Path(bsl), port, Path(hex_file))


def _dispatch_firmware_payload(fw: dict, port: str):
    """Route a selected .qfw firmware payload to the right CatSniffer firmware."""
    name = fw.get("firmware", "")
    if name not in CATSNIFFER_FW:
        err(f"Unknown CatSniffer firmware payload: {name!r}")
        info(f"  Supported: {', '.join(CATSNIFFER_FW)}")
        return
    spec = CATSNIFFER_FW[name]
    staged: dict = {}
    run_firmware_payload(
        fw.get("label", spec["label"]),
        info_fn=lambda: op_device_info(port),
        prepare_fn=lambda: _prep_flash(name, port, staged),
        flash_fn=lambda: _flash_payload(port, staged),
        summary_lines=[
            f"Board    : {TOOL_NAME} (CC1352P7 via SAMD21 bridge)",
            f"Firmware : {name} — {spec['desc']}",
            f"Source   : {spec['src']}",
            f"Port     : {port}",
            "Flasher  : cc2538-bsl serial ROM bootloader (-e -w -v)",
        ],
    )


# ── Version check ─────────────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking latest Sniffle and CatSniffer firmware releases on GitHub…")
    for owner, repo, label in (
        ("nccgroup", "Sniffle", "Sniffle"),
        ("ElectronicCats", "CatSniffer-Firmware", "CatSniffer firmware"),
    ):
        latest, url = check_latest_github_release(owner, repo)
        if latest:
            info(f"  Latest {label}: {latest}")
            info(f"    {url}")
        else:
            warn(f"  Could not reach GitHub for the {label} version check.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    info("Ensuring pyserial for USB CDC serial communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    info("Ensuring requests library for GitHub version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("CatSniffer v3 not detected. Exiting.")
        sys.exit(1)

    port = _resolve_port()
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"CatSniffer v3 detected on {port}")

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw, port)
        return

    check_firmware_version()

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash CC1352P7 Firmware",
        "Firmware Version Check",
        "Exit",
    ]

    while True:
        choice = numbered_menu("CatSniffer v3 — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_firmware(port)
        elif choice == 2:
            check_firmware_version()
        elif choice == 3:
            info("Goodbye.")
            break

        # Re-check port after operations (bridge may re-enumerate after flashing).
        new_port = _resolve_port()
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
