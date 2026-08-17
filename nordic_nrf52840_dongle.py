#!/usr/bin/env python3
"""
Nordic nRF52840 USB Dongle (PCA10059) Tool Manager
Handles dongle detection, BLE / 802.15.4 sniffing reference, Zigbee/Thread NCP
info, and USB-DFU firmware flashing via nrfutil + the dongle's Open Bootloader.

This module is the DONGLE-ONLY sibling of nordic_nrf52840.py (which also handles
the nRF52840-DK). The PCA10059 dongle has NO on-board J-Link / SWD debugger, so
firmware is written over USB DFU (Nordic Open Bootloader), NOT over J-Link.

Usage:
    python3 nordic_nrf52840_dongle.py

USB VID:PIDs:
    0x1915:0x521F — nRF52840 Dongle, Open DFU Bootloader (press RESET to enter)
    0x1915:0x520F — nRF52840 Dongle, application CDC UART (running firmware)

Entering DFU / bootloader mode:
    Press the small RESET button on the dongle. The red LED pulses and the USB
    device re-enumerates as VID:PID 1915:521F. The Open Bootloader then accepts
    a DFU .zip package over the CDC serial port (/dev/ttyACM*).

nrfutil DFU reference (this is the write mechanism for the dongle):
    nrfutil dfu usb-serial -pkg <package.zip> -p /dev/ttyACM0 -b 115200
    DFU package creation (from a raw .hex):
        nrfutil pkg generate --hw-version 52 --sd-req 0x00 \\
            --application <firmware.hex> <output.zip>
    (--sd-req 0x00 = no SoftDevice; use 0x0101 for firmware built on S140 v7.x.)

Linux serial permissions:
    Devices appear as /dev/ttyACM* (USB CDC ACM).
    Add user to dialout: sudo usermod -aG dialout $USER (then re-login)
    Check: id  and  ls -la /dev/ttyACM*
"""

import os
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os_flavor, run, run_output,
    find_serial_port_by_vidpid, ensure_pip_packages,
    sudo_run,
    ensure_apt_packages,
    web_detect_loop, run_streaming,
    get_firmware_dir, check_latest_github_release,
    require_sudo,
    selected_firmware_payload, run_firmware_payload,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "nRF52840 Dongle"
TOOL_ID     = "nordic_nrf52840_dongle"
DESCRIPTION = "nRF52840 Dongle (PCA10059) — BLE / 802.15.4 sniffing, USB-DFU flashing (nrfutil)"

VID_PID_DONGLE_DFU = [(0x1915, 0x521F)]   # Open DFU bootloader (press RESET)
VID_PID_DONGLE_APP = [(0x1915, 0x520F)]   # application CDC
VID_PIDS = VID_PID_DONGLE_DFU + VID_PID_DONGLE_APP

BAUD_RATE = 115200

# The dongle shares the sniffer/butterfly firmware assets vendored by the
# nordic_nrf52840 downloader, so this module reads from BOTH its own firmware
# dir and the shared nordic_nrf52840 dir.
SHARED_TOOL_ID = "nordic_nrf52840"

SDK_NRF_API_URL = (
    "https://api.github.com/repos/NordicSemiconductor/sdk-nrf/releases/latest"
)

# WHAD / ButteRFly — the maintained successor to Mirage. butterfly is the
# nRF52840 BLE MITM/sniffer radio firmware; flashed to the dongle over DFU.
WHAD_REPO      = "https://github.com/whad-team/whad-client"
BUTTERFLY_REPO = "https://github.com/whad-team/butterfly"

CONNECT_INSTRUCTIONS = (
    "nRF52840 Dongle (PCA10059) not detected — nothing matching is on the USB bus.\n\n"
    "  1. Insert the dongle directly into a USB-A port (a data port, not a\n"
    "     charge-only hub). Application mode enumerates as VID:PID 1915:520F.\n"
    "  2. To flash, put it in DFU/bootloader mode: press the small RESET button.\n"
    "     The red LED pulses and USB re-enumerates as 1915:521F (Open Bootloader).\n"
    "  3. A factory-fresh dongle with no application only appears in DFU mode\n"
    "     (1915:521F) — that is normal; press RESET if you see nothing.\n\n"
    "  Quick physical confirmation (no tools needed):\n"
    "    macOS: ioreg -p IOUSB -l -w 0 | grep -i 'idVendor.*6421'\n"
    "    Linux: lsusb | grep -i 1915\n"
    "  If those show nothing, the dongle is not on the bus — try another port\n"
    "  or cable; no software can detect it until it enumerates."
)

UDEV_RULES_CONTENT = (
    '# Nordic nRF52840 Dongle (PCA10059) udev rules\n'
    '# Open DFU bootloader (VID:PID 1915:521F)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="521f", '
    'MODE="0666", GROUP="dialout"\n'
    '# Application CDC (VID:PID 1915:520F)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1915", ATTRS{idProduct}=="520f", '
    'MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-nordic-nrf52840-dongle.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def _usb_vidpid_present() -> bool:
    """Dependency-free USB scan for Nordic (0x1915) via ioreg/lsusb."""
    if get_os_flavor() == "darwin":
        out = run_output("ioreg -p IOUSB -l -w 0 2>/dev/null || true") or ""
        # 0x1915 == 6421 in ioreg's decimal idVendor field.
        return '"idVendor" = 6421' in out
    out = (run_output("lsusb 2>/dev/null || true") or "").lower()
    return "1915:" in out


def detect_dongle() -> bool:
    info("Scanning for nRF52840 Dongle (serial VCOM 1915:520F/521F, raw USB)…")
    if find_serial_port_by_vidpid(VID_PIDS) is not None:
        return True
    if _usb_vidpid_present():
        info("  Detected via raw USB VID match (Nordic 0x1915 on the bus).")
        return True
    return False


def _identify_variant() -> str:
    """Return 'dfu', 'app', or 'unknown'."""
    if find_serial_port_by_vidpid(VID_PID_DONGLE_DFU):
        return "dfu"
    if find_serial_port_by_vidpid(VID_PID_DONGLE_APP):
        return "app"
    return "unknown"


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for the dongle on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for the nRF52840 Dongle…")
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
        info("Unplug and replug the dongle to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── nrfutil (the DFU tool) ────────────────────────────────────────────────────

def _nrfutil_path() -> str:
    return (run_output("which nrfutil 2>/dev/null || true") or "").strip()


def _ensure_nrfutil() -> bool:
    """Ensure nrfutil is available for DFU packaging + flashing.

    The dongle is flashed over USB DFU, which requires nrfutil. If it is not
    already on PATH we pip-install it. NOTE: the legacy PyPI 'nrfutil' pins an
    old 'click', which can downgrade a shared interpreter — install it in an
    isolated venv/pipx if this interpreter also runs Flask apps. We install here
    because DFU flashing genuinely needs it and there is no lighter alternative.
    """
    info("Ensuring nrfutil (Nordic DFU packaging + flashing tool)…")
    path = _nrfutil_path()
    if path:
        ok(f"nrfutil found: {path}")
        ver = run_output("nrfutil version 2>/dev/null || true")
        if ver:
            info(f"  nrfutil version: {ver.strip()}")
        return True
    info("nrfutil not present — installing via pip (nrfutil)…")
    info("  (If this interpreter also runs Flask/Quiver, prefer: pipx install nrfutil)")
    run(f"{sys.executable} -m pip install --break-system-packages nrfutil")
    path = _nrfutil_path()
    if path:
        ok(f"nrfutil installed: {path}")
        return True
    err("nrfutil still not on PATH after install attempt.")
    info("  Install manually: pip install nrfutil --break-system-packages")
    info("  or the standalone binary from developer.nordicsemi.com/nrfutil")
    return False


def _nrfutil_pkg_generate(hex_path: Path, out_zip: Path, sd_req: str = "0x00") -> bool:
    """Build a DFU .zip package from a .hex via nrfutil pkg generate.

    Tries the legacy bare subcommand first (`nrfutil pkg generate …`, which the
    pip 'nrfutil' provides), then the modern namespaced form
    (`nrfutil nrf5sdk-tools pkg generate …`) as a fallback.
    """
    base_args = [
        "pkg", "generate", "--hw-version", "52", "--sd-req", sd_req,
        "--application", str(hex_path), str(out_zip),
    ]
    for prefix in (["nrfutil"], ["nrfutil", "nrf5sdk-tools"]):
        cmd = prefix + base_args
        info("Running: " + " ".join(cmd))
        flags = {"unknown": False}

        def _line(l, _f=flags):
            info(f"  nrfutil: {l}")
            low = l.lower()
            if "no such command" in low or "invalid choice" in low or "usage:" in low:
                _f["unknown"] = True

        rc = run_streaming(cmd, on_line=_line, timeout=120)
        if rc == 0 and out_zip.exists():
            return True
        if not flags["unknown"]:
            # A real failure (bad hex, bad sd-req) — do not retry the other namespace.
            break
    return False


def _flash_dongle_dfu(zip_path: Path, port: str) -> bool:
    """Write a DFU .zip to the dongle over USB CDC via nrfutil dfu usb-serial.

    Tries the legacy bare subcommand first, then the modern namespaced form.
    """
    base_args = [
        "dfu", "usb-serial", "-pkg", str(zip_path), "-p", port, "-b", str(BAUD_RATE),
    ]
    for prefix in (["nrfutil"], ["nrfutil", "nrf5sdk-tools"]):
        cmd = prefix + base_args
        info("Running: " + " ".join(cmd))
        info("  Watch for progress — the write takes ~10-30 seconds. Do NOT unplug.")
        flags = {"unknown": False, "err": False, "done": False}

        def _line(l, _f=flags):
            info(f"  nrfutil: {l}")
            low = l.lower()
            if "no such command" in low or "invalid choice" in low or "usage:" in low:
                _f["unknown"] = True
            if "error" in low or "failed" in low or "timed out" in low:
                _f["err"] = True
            if "completed successfully" in low or "device programmed" in low:
                _f["done"] = True

        rc = run_streaming(cmd, on_line=_line, timeout=240)
        if rc == 0 and not flags["err"]:
            return True
        if not flags["unknown"]:
            break
    return False


# ── DFU port helpers ──────────────────────────────────────────────────────────

def _wait_for_dfu_port(prompt_first: bool = True) -> str:
    """Return the dongle's DFU CDC port, prompting the operator to press RESET.

    Returns the port string when the dongle is in DFU mode, else "".
    """
    dfu = find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
    if dfu:
        return dfu
    app = find_serial_port_by_vidpid(VID_PID_DONGLE_APP)
    if app:
        warn(f"Dongle is in APPLICATION mode on {app}; DFU/bootloader mode is required.")
    else:
        warn("Dongle not currently on a serial port.")
    if prompt_first:
        warn("Press the small RESET button on the dongle now — the red LED will pulse")
        warn("and USB re-enumerates as the Open Bootloader (VID:PID 1915:521F).")
        pause("Press ENTER once the dongle's red LED is pulsing (DFU mode active).")
    # Give the OS a moment to enumerate the re-attached CDC device.
    for _ in range(10):
        dfu = find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
        if dfu:
            return dfu
        time.sleep(0.5)
    return ""


# ── Firmware asset location ───────────────────────────────────────────────────

def _fw_search_dirs():
    """Directories that may hold vendored dongle firmware (own + shared)."""
    dirs = []
    for tid in (TOOL_ID, SHARED_TOOL_ID):
        d = get_firmware_dir(tid)
        if d.exists():
            dirs.append(d)
    return dirs


def _find_sniffer_dongle_asset():
    """Locate the nRF Sniffer firmware for the DONGLE.

    Prefers a ready-made DFU .zip, then a dongle-specific .hex
    (sniffer_nrf52840dongle_nrf52840_*.hex), then any nRF52840 sniffer hex.
    Flashing the DK hex to the dongle (or vice-versa) is wrong, so dongle images
    are strongly preferred.
    """
    for base in _fw_search_dirs():
        for sub in ("ble_sniffer", "sniffer", ""):
            root = base / sub if sub else base
            if not root.exists():
                continue
            zips = sorted(root.rglob("*nrf52840dongle*.zip")) or sorted(root.rglob("*dongle*.zip"))
            if zips:
                return zips[0]
            hexes = sorted(root.rglob("*nrf52840dongle*.hex"))
            if hexes:
                return hexes[0]
    # Last resort: any nRF52840 sniffer hex anywhere in the search dirs.
    for base in _fw_search_dirs():
        hexes = sorted(base.rglob("*sniffer*nrf52840*.hex"))
        if hexes:
            return hexes[0]
    return None


def _butterfly_dongle_asset():
    """Locate (or download) the ButteRFly firmware for the DONGLE.

    Prefers a DFU .zip or a dongle/mdk .hex; falls back to downloading
    butterfly.hex from the whad-team/butterfly release. Returns a Path or None.

    NOTE: whad-team publishes butterfly.hex (raw) and drives dongle flashing via
    its own `winstall`; a dongle-specific DFU zip is not always in the release
    assets. When only butterfly.hex is found we build the DFU package from it.
    """
    for base in _fw_search_dirs():
        for sub in ("butterfly", ""):
            root = base / sub if sub else base
            if not root.exists():
                continue
            zips = sorted(root.rglob("*dongle*.zip")) or sorted(root.rglob("butterfly*.zip"))
            if zips:
                return zips[0]
            hexes = (sorted(root.rglob("*dongle*.hex"))
                     or sorted(root.rglob("*mdk*.hex"))
                     or sorted(root.rglob("butterfly*.hex")))
            if hexes:
                return hexes[0]
    # Download butterfly.hex from the whad-team release as a last resort.
    try:
        from common import get_github_release_asset_url, download_firmware
        tag, _ = check_latest_github_release("whad-team", "butterfly")
        if tag:
            bdir = get_firmware_dir(TOOL_ID) / "butterfly"
            bdir.mkdir(parents=True, exist_ok=True)
            # Prefer a dongle/mdk asset, else the plain butterfly.hex.
            for pat in (r".*dongle.*\.hex$", r".*mdk.*\.hex$", r"^butterfly\.hex$"):
                url = get_github_release_asset_url("whad-team", "butterfly", tag, pat)
                if url:
                    dest = bdir / Path(url.split("?")[0]).name
                    if download_firmware(url, dest, "ButteRFly"):
                        return dest
    except Exception as e:  # noqa: BLE001 — best-effort network lookup
        warn(f"butterfly firmware download failed: {e}")
    return None


def _ensure_dfu_zip(asset: Path, out_name: str, sd_req: str = "0x00"):
    """Return a DFU .zip for *asset*: pass through if already a .zip, else build
    one from the .hex via nrfutil pkg generate. Returns a Path or None."""
    if asset.suffix.lower() == ".zip":
        return asset
    if asset.suffix.lower() != ".hex":
        warn(f"Unexpected firmware file type: {asset.name} (expected .hex or .zip).")
        return None
    out_zip = get_firmware_dir(TOOL_ID) / out_name
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    info(f"Building DFU package from {asset.name} (sd-req {sd_req})…")
    if _nrfutil_pkg_generate(asset, out_zip, sd_req=sd_req):
        ok(f"  DFU package ready: {out_zip}")
        return out_zip
    err("  Failed to build the DFU package (nrfutil pkg generate).")
    return None


# ── Firmware-payload PREPARE / FLASH (auto-run path) ──────────────────────────

def _prep_sniffer_flash() -> bool:
    """PREPARE the nRF Sniffer DFU flash: ensure nrfutil, obtain a DFU zip, and
    confirm the dongle is in bootloader mode. Returns True only when ready."""
    ready = True
    if not _ensure_nrfutil():
        ready = False
    asset = _find_sniffer_dongle_asset()
    if not asset:
        err("  nRF Sniffer firmware for the dongle not found on disk.")
        info("    Fetch it: python3 firmware/download.py --tools nordic_nrf52840 --yes")
        info("    (The nRF Sniffer download contains sniffer_nrf52840dongle_*.hex.)")
        return False
    ok(f"  nRF Sniffer firmware: {asset}")
    # nRF Sniffer is built on the S140 SoftDevice → sd-req 0x0101 when packaging.
    zip_path = _ensure_dfu_zip(asset, "nrf_sniffer_dongle_dfu.zip", sd_req="0x0101")
    if not zip_path:
        ready = False
    else:
        globals()["_PREP_ZIP"] = zip_path
    dfu_port = _wait_for_dfu_port()
    if dfu_port:
        ok(f"  Dongle in DFU mode on {dfu_port}.")
        globals()["_PREP_PORT"] = dfu_port
    else:
        err("  Dongle not in DFU/bootloader mode — press RESET (red LED pulses) and retry.")
        ready = False
    return ready


def _autoflash_sniffer():
    """FLASH: everything prepped — write the nRF Sniffer DFU package."""
    zip_path = globals().get("_PREP_ZIP")
    port = globals().get("_PREP_PORT") or find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
    if not zip_path or not Path(zip_path).exists() or not port:
        err("nRF Sniffer DFU package or DFU port missing at flash time — aborting.")
        return
    if _flash_dongle_dfu(Path(zip_path), port):
        ok("nRF Sniffer firmware flashed — the dongle is now a BLE/802.15.4 sniffer.")
        info("  It reboots into application mode (1915:520F). Use it via Wireshark's")
        info("  nRF Sniffer extcap plugin.")
    else:
        err("DFU flash failed — re-enter DFU mode (press RESET) and retry.")


def _prep_butterfly_flash() -> bool:
    """PREPARE the ButteRFly DFU flash (BLE Rx/Tx MITM)."""
    ready = True
    if not _ensure_nrfutil():
        ready = False
    asset = _butterfly_dongle_asset()
    if not asset:
        err("  ButteRFly firmware for the dongle not found and download failed.")
        info(f"    Drop a butterfly dongle .hex/.zip into "
             f"{get_firmware_dir(TOOL_ID) / 'butterfly'} and retry,")
        info(f"    or fetch it from {BUTTERFLY_REPO}/releases.")
        return False
    ok(f"  ButteRFly firmware: {asset}")
    # ButteRFly is a bare (no-SoftDevice) radio firmware → sd-req 0x00.
    zip_path = _ensure_dfu_zip(asset, "butterfly_dongle_dfu.zip", sd_req="0x00")
    if not zip_path:
        ready = False
    else:
        globals()["_PREP_ZIP"] = zip_path
    dfu_port = _wait_for_dfu_port()
    if dfu_port:
        ok(f"  Dongle in DFU mode on {dfu_port}.")
        globals()["_PREP_PORT"] = dfu_port
    else:
        err("  Dongle not in DFU/bootloader mode — press RESET (red LED pulses) and retry.")
        ready = False
    return ready


def _autoflash_butterfly():
    """FLASH: everything prepped — write the ButteRFly DFU package."""
    zip_path = globals().get("_PREP_ZIP")
    port = globals().get("_PREP_PORT") or find_serial_port_by_vidpid(VID_PID_DONGLE_DFU)
    if not zip_path or not Path(zip_path).exists() or not port:
        err("ButteRFly DFU package or DFU port missing at flash time — aborting.")
        return
    if _flash_dongle_dfu(Path(zip_path), port):
        ok("ButteRFly flashed — the dongle is now a WHAD BLE Rx/Tx (active MITM) radio.")
        info("  Drive it with the WHAD host tools (whadup / wsniff / wanalyze).")
        info(f"  Install WHAD on the host: pip install whad   ({WHAD_REPO})")
    else:
        err("DFU flash failed — re-enter DFU mode (press RESET) and retry.")


# ── Operations (interactive menu) ─────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Identifying the connected nRF52840 Dongle (PCA10059).")
    info("")

    variant = _identify_variant()
    if variant == "dfu":
        info("VARIANT: nRF52840 Dongle — DFU/bootloader mode (1915:521F)")
        info("  Ready for firmware flashing via nrfutil DFU. Red LED pulses in DFU mode.")
        info("  To exit DFU: flash firmware, or replug the dongle.")
    elif variant == "app":
        info("VARIANT: nRF52840 Dongle — application mode (1915:520F)")
        info("  Running its application firmware. Press RESET to enter DFU for flashing.")
    else:
        warn("Dongle serial port not resolved — it may be on the raw USB bus only.")

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

    ok("Device info complete.")


def op_ble_sniff():
    heading("BLE / 802.15.4 Sniffer Setup (reference)")
    info("The dongle runs Nordic's nRF Sniffer firmware to capture BLE (and, with")
    info("the 802.15.4 sniffer, Zigbee/Thread) traffic into Wireshark via extcap.")
    info("")
    info("REQUIRED FIRMWARE: nRF Sniffer for Bluetooth LE / 802.15.4")
    info("  Download: https://www.nordicsemi.com/Products/Development-tools/nRF-Sniffer-for-Bluetooth-LE")
    info("  Or via nRF Connect for Desktop. The download ships dongle hex images")
    info("  named sniffer_nrf52840dongle_nrf52840_*.hex plus the Wireshark plugin.")
    info("")
    info("FLASHING: use 'FIRMWARE - Flash nRF Sniffer (DFU)' from this menu, or the")
    info("  Quiver firmware payload. The dongle is written over USB DFU (nrfutil).")
    info("")
    info("WIRESHARK INTEGRATION:")
    info("  Copy nrf_sniffer_ble.py from the download's extcap/ folder to:")
    info("    Linux:  ~/.config/wireshark/extcap/")
    info("    macOS:  ~/.config/wireshark/extcap/")
    info("  chmod +x it, restart Wireshark — the sniffer appears as a capture interface.")
    info("")
    pause("Press ENTER to continue.")


def op_zigbee_info():
    heading("Zigbee / Thread NCP Info")
    info("The nRF52840 dongle can act as a Zigbee or Thread Network Co-Processor")
    info("(NCP) or an IEEE 802.15.4 sniffer, communicating over its CDC UART.")
    info("")
    info("FIRMWARE OPTIONS:")
    info("  1. Zigbee NCP — Home Assistant / Zigbee2MQTT (adapter: zboss)")
    info("  2. OpenThread RCP/NCP — Thread/Matter border router")
    info("  3. 802.15.4 Sniffer — Wireshark capture of Zigbee/Thread/6LoWPAN")
    info("")
    latest, _ = check_latest_github_release("NordicSemiconductor", "sdk-nrf")
    if latest:
        ok(f"Latest sdk-nrf release: {latest}")
    info("")
    info("FIRMWARE SOURCE:")
    info("  Nordic sdk-nrf: https://github.com/NordicSemiconductor/sdk-nrf")
    info("  Flash the NCP .hex to the dongle over DFU (this module's DFU flow).")
    info("")
    info("ZIGBEE2MQTT INTEGRATION (once NCP firmware is flashed):")
    info("  serial:")
    info("    port: /dev/ttyACM0")
    info("    adapter: zboss")
    info("")
    pause("Press ENTER to continue.")


def op_flash_dongle(port: str):
    heading("Flash Dongle via nrfutil DFU")
    info("Writing a DFU .zip package to the dongle's Open Bootloader over USB CDC.")
    info("The dongle MUST be in DFU/bootloader mode (press RESET — red LED pulses).")
    info("")

    if not _ensure_nrfutil():
        return

    flash_port = _wait_for_dfu_port()
    if not flash_port:
        err("Dongle not in DFU mode. Cannot proceed.")
        info("  Press the small RESET button; the red LED pulses and USB re-enumerates")
        info("  as 1915:521F. Then re-run this operation.")
        return
    ok(f"DFU mode confirmed on {flash_port}.")

    pkg_path = prompt("Path to DFU .zip package (or a .hex to auto-package)")
    if not pkg_path:
        warn("No path provided. Aborting.")
        return
    src = Path(pkg_path)
    if not src.exists():
        err(f"File not found: {src}")
        return

    if src.suffix.lower() == ".hex":
        sd_req = prompt("SoftDevice requirement (0x00 none, 0x0101 for S140/BLE)",
                        default="0x00")
        zip_path = _ensure_dfu_zip(src, src.stem + "_dfu.zip", sd_req=sd_req)
        if not zip_path:
            return
    elif src.suffix.lower() == ".zip":
        zip_path = src
    else:
        warn(f"Expected a .zip DFU package or a .hex, got: {src.name}")
        if not confirm("Continue treating it as a DFU .zip?", default=False):
            return
        zip_path = src

    if not confirm(f"Flash {Path(zip_path).name} to the dongle on {flash_port}?",
                   default=True):
        info("Flash cancelled.")
        return

    if _flash_dongle_dfu(Path(zip_path), flash_port):
        ok("Dongle firmware flashed successfully via nrfutil DFU.")
        info("  The dongle reboots into application mode (1915:520F).")
    else:
        err("nrfutil DFU flash failed.")
        info("Troubleshooting:")
        info("  - Verify DFU mode (red LED pulsing, VID:PID 1915:521F)")
        info("  - Check: ls -la /dev/ttyACM* and dmesg | tail -20")
        info("  - The .zip must be built for nRF52840 (hw-version 52)")
        info("  - nrfutil version: nrfutil version")


def op_create_dfu_package():
    heading("Create DFU Package")
    info("Creating a nrfutil DFU .zip package from a .hex firmware file.")
    info("")
    info("nrfutil pkg generate parameters:")
    info("  --hw-version 52    always 52 for nRF52840")
    info("  --sd-req 0x00      no SoftDevice (Zigbee/Thread/custom/ButteRFly)")
    info("  --sd-req 0x0101    require S140 v7.x (BLE firmware, e.g. nRF Sniffer)")
    info("")

    if not _ensure_nrfutil():
        return

    hex_path = prompt("Path to source .hex firmware file")
    if not hex_path:
        warn("No file provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        return

    output_name = hex_file.stem + "_dfu_package.zip"
    output_path = prompt("Output .zip package path",
                         default=str(hex_file.parent / output_name))
    output_zip = Path(output_path)
    sd_req = prompt("SoftDevice requirement (0x00 none, 0x0101 for S140)", default="0x00")

    if not confirm(f"Create DFU package: {output_zip.name}?", default=True):
        info("Package creation cancelled.")
        return

    if _nrfutil_pkg_generate(hex_file, output_zip, sd_req=sd_req):
        ok(f"DFU package created: {output_zip}")
        info("  Use it with 'Flash Dongle via nrfutil DFU'.")
    else:
        err("DFU package creation failed.")
        info("  Check the .hex is valid and the --sd-req matches the firmware build.")


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking vendored dongle firmware assets…")
    sniffer = _find_sniffer_dongle_asset()
    if sniffer:
        ok(f"  nRF Sniffer firmware present: {sniffer.name}")
    else:
        warn("  No nRF Sniffer firmware on disk yet.")
        info("    Fetch via: python3 firmware/download.py --tools nordic_nrf52840 --yes")


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

    info("Ensuring requests library for version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Checking udev rules for nRF52840 Dongle USB access…")
    _check_udev_rules()

    info("Detecting nRF52840 Dongle (serial VCOM · raw USB)…")
    info("  DFU/bootloader mode : 1915:521F — press RESET (red LED pulses)")
    info("  Application mode     : 1915:520F — running firmware")

    found = web_detect_loop(detect_dongle, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("nRF52840 Dongle not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS) or ""
    variant = _identify_variant()

    if port:
        ok(f"nRF52840 Dongle detected on {port}")
    else:
        ok("nRF52840 Dongle detected (no serial port resolved).")

    check_firmware_version()

    if variant == "dfu":
        ok("Variant: Dongle — DFU/bootloader mode (1915:521F); ready to flash.")
    elif variant == "app":
        ok("Variant: Dongle — application mode (1915:520F); press RESET to flash.")
    else:
        warn("Could not identify dongle mode.")

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        fwname = fw.get("firmware", "")
        if "butterfly" in fwname.lower():
            run_firmware_payload(
                fw.get("label", "Flash ButteRFly (BLE MITM)"),
                info_fn=lambda: op_device_info(port),
                prepare_fn=_prep_butterfly_flash,
                flash_fn=_autoflash_butterfly,
                summary_lines=[
                    f"Board    : {TOOL_NAME} (PCA10059)",
                    "Firmware : ButteRFly (whad-team) — BLE Rx/Tx (active MITM)",
                    "Flasher  : nrfutil USB-DFU (Open Bootloader, .zip package)",
                ],
            )
        else:
            run_firmware_payload(
                fw.get("label", "Flash nRF Sniffer (DFU)"),
                info_fn=lambda: op_device_info(port),
                prepare_fn=_prep_sniffer_flash,
                flash_fn=_autoflash_sniffer,
                summary_lines=[
                    f"Board    : {TOOL_NAME} (PCA10059)",
                    f"Firmware : {fw.get('firmware', 'nRF Sniffer for 802.15.4/BLE')}",
                    "Flasher  : nrfutil USB-DFU (Open Bootloader, .zip package)",
                ],
            )
        return

    MENU_OPTIONS = [
        "Device Info",
        "BLE / 802.15.4 Sniffer Setup (reference)",
        "FIRMWARE - Flash nRF Sniffer (DFU)",
        "FIRMWARE - Flash ButteRFly / WHAD (DFU)",
        "Zigbee / Thread NCP Info",
        "FIRMWARE - Flash Dongle (nrfutil DFU — custom package)",
        "Create DFU Package",
        "Exit",
    ]

    while True:
        choice = numbered_menu("nRF52840 Dongle — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_ble_sniff()
        elif choice == 2:
            run_firmware_payload(
                "Flash nRF Sniffer (DFU)",
                info_fn=lambda: op_device_info(port),
                prepare_fn=_prep_sniffer_flash,
                flash_fn=_autoflash_sniffer,
                summary_lines=[
                    f"Board    : {TOOL_NAME} (PCA10059)",
                    "Firmware : nRF Sniffer for 802.15.4/BLE",
                    "Flasher  : nrfutil USB-DFU (Open Bootloader, .zip package)",
                ],
            )
        elif choice == 3:
            run_firmware_payload(
                "Flash ButteRFly / WHAD (DFU)",
                info_fn=lambda: op_device_info(port),
                prepare_fn=_prep_butterfly_flash,
                flash_fn=_autoflash_butterfly,
                summary_lines=[
                    f"Board    : {TOOL_NAME} (PCA10059)",
                    "Firmware : ButteRFly (whad-team) — BLE Rx/Tx (active MITM)",
                    "Flasher  : nrfutil USB-DFU (Open Bootloader, .zip package)",
                ],
            )
        elif choice == 4:
            op_zigbee_info()
        elif choice == 5:
            op_flash_dongle(port)
        elif choice == 6:
            op_create_dfu_package()
        elif choice == 7:
            info("Goodbye.")
            break

        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")
            variant = _identify_variant()
            if variant == "dfu":
                info("  Dongle is now in DFU mode.")
            elif variant == "app":
                info("  Dongle is now in application mode.")


if __name__ == "__main__":
    main()
