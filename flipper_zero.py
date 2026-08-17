#!/usr/bin/env python3
"""
Flipper Zero Tool Manager
Handles device info, file management, Sub-GHz, NFC, RFID, app launching,
reboots, and firmware updates via PyFlipper over USB CDC.

Usage:
    python3 flipper_zero.py

Flipper Zero file system paths:
    /ext/       — SD card (most user files, payloads, captures go here)
    /int/       — Internal flash (limited space, for settings/databases)
    /ext/badusb/        — Bad USB DuckyScript payloads
    /ext/subghz/        — Sub-GHz captured/saved signals (.sub files)
    /ext/nfc/           — NFC saved cards (.nfc files)
    /ext/lfrfid/        — LF RFID saved cards (.rfid files)
    /ext/infrared/      — IR remotes (.ir files)
    /ext/ibutton/       — iButton/DS1990 keys
    /ext/update/        — Firmware update files
    /ext/apps/          — External apps/plugins (.fap files)

Linux serial permissions:
    The Flipper Zero appears as /dev/ttyACM* (USB CDC).
    If you get 'Permission denied', add your user to the dialout group:
        sudo usermod -aG dialout $USER
    Then log out and back in (or run: newgrp dialout).
"""

import os
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, ensure_pip_packages, ensure_system_tool,
    web_detect_loop, run_streaming,
    require_sudo, sudo_run, sudo_output, run_streaming_sudo,
    ensure_apt_packages, ensure_brew_packages, get_os_flavor,
    get_selected_payload, verify_device_connection,
    check_latest_github_release, compare_versions, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    get_firmware_dir, download_firmware, get_github_release_asset_url,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Flipper Zero"
DESCRIPTION = "Multi-tool device for pentesters and hardware hackers"

VID_PID_CDC = [(0x0483, 0x5740)]
VID_PID_DFU = [(0x0483, 0xDF11)]

BAUD_RATE   = 115200

CONNECT_INSTRUCTIONS = (
    "Flipper Zero not detected.\n\n"
    "  1. Connect Flipper Zero via USB-C cable\n"
    "  2. Unlock the device if screen shows lock\n"
    "  3. On the Flipper: Menu → Settings → USB → CDC is enabled by default\n\n"
    "  The device appears as /dev/ttyACM* (Linux) or /dev/cu.usbmodemflip_* (macOS)\n\n"
    "  Linux permission fix if needed:\n"
    "    sudo usermod -aG dialout $USER  (then log out/in)\n"
    "    Verify: ls -la /dev/ttyACM*\n"
    "    Debug:  dmesg | tail -20"
)

# ── Firmware version check ────────────────────────────────────────────────────

def _get_current_version(flipper) -> str:
    """Return the firmware version string from the connected Flipper Zero, or ''."""
    try:
        info_data = flipper.system.device_info()
        if isinstance(info_data, dict):
            for key, value in info_data.items():
                if "firmware" in key.lower() and "version" in key.lower():
                    return str(value).strip()
        return ""
    except Exception:
        return ""


def check_firmware_version(flipper):
    heading("Firmware Version Check")
    info("Checking installed firmware version...")
    current = _get_current_version(flipper)
    if not current:
        warn("Could not determine installed firmware version.")
        info("Continuing without version check.")
        return
    ok(f"Installed firmware: {current}")

    info("Checking latest available version on GitHub...")
    latest, release_url = check_latest_github_release("flipperdevices", "flipperzero-firmware")
    if not latest:
        warn("Could not reach GitHub. Skipping version check.")
        return

    wants_update = announce_firmware_update(TOOL_NAME, current, latest, release_url)
    if wants_update:
        op_firmware_update(flipper, "")


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_flipper() -> bool:
    return find_serial_port_by_vidpid(VID_PID_CDC) is not None


# ── dialout group check ───────────────────────────────────────────────────────

def _check_dialout(port: str):
    """Check dialout group membership; offer to add user if missing."""
    import grp
    username = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    try:
        dialout_gid = grp.getgrnam("dialout").gr_gid
        if dialout_gid in os.getgroups():
            return
    except KeyError:
        return

    warn(f"User '{username}' may not be in the 'dialout' group.")
    info("This causes 'Permission denied' on /dev/ttyACM* serial devices.")
    info(f"  Verify: id {username}   and   ls -la {port}")
    if confirm(f"Add '{username}' to the 'dialout' group now?", default=True):
        rc = sudo_run(f"usermod -aG dialout {username}")
        if rc.returncode == 0:
            ok(f"Added '{username}' to dialout. Log out/in or run: newgrp dialout")
        else:
            err("Failed. Try manually: sudo usermod -aG dialout $USER")


# ── PyFlipper connection ──────────────────────────────────────────────────────

def connect_flipper(port: str):
    """Return an open PyFlipper instance or None on failure."""
    info(f"Opening PyFlipper session on {port}…")
    info("PyFlipper communicates with the Flipper Zero over the RPC serial protocol.")
    info("If connection fails, check that the Flipper is unlocked and USB is CDC mode.")
    try:
        from pyflipper import PyFlipper
        flipper = PyFlipper(com=port)
        return flipper
    except Exception as e:
        err(f"Could not connect via PyFlipper: {e}")
        info("Troubleshooting:")
        info("  - Ensure Flipper is unlocked (no lock screen)")
        info("  - On Flipper: Settings → USB → ensure 'USB-UART Bridge' or CDC is selected")
        info("  - Try: screen /dev/ttyACM0 115200  to confirm REPL is responsive")
        info("  - pyflipper pip install: pip install pyflipper --break-system-packages")
        return None


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(flipper):
    heading("Device Info")
    info("Querying power/device info via flipper.power.info().")
    info("Expected fields: hardware version, firmware version, battery level, charge state.")
    try:
        info_data = flipper.power.info()
        if isinstance(info_data, dict):
            for k, v in info_data.items():
                info(f"{k}: {v}")
        else:
            info(str(info_data))
        ok("Device info retrieved.")
    except Exception as e:
        err(f"Device info failed: {e}")
        info("If the Flipper locked or disconnected, use the Reboot option to reconnect.")


def op_list_files(flipper):
    heading("List Files")
    info("Lists files and directories on the Flipper Zero storage.")
    info("Common paths:")
    info("  /ext/       — SD card root (most files go here)")
    info("  /int/       — Internal flash (limited)")
    info("  /ext/badusb/        — DuckyScript payloads")
    info("  /ext/subghz/        — Sub-GHz signals")
    info("  /ext/nfc/           — NFC card saves")
    info("  /ext/lfrfid/        — LF RFID saves")
    path = prompt("Remote path", default="/ext")
    if not path:
        path = "/ext"
    try:
        result = flipper.storage.list(path=path)
        if result:
            if isinstance(result, (list, tuple)):
                for entry in result:
                    info(str(entry))
            else:
                info(str(result))
            ok(f"Listed: {path}")
        else:
            warn(f"No entries returned for {path}")
            info("Check the path exists. SD card paths start with /ext/, internal with /int/")
    except Exception as e:
        err(f"List files failed: {e}")


def op_upload_payload(flipper):
    heading("Upload Payload")
    info("Uploads a local file to the Flipper Zero over the RPC protocol.")
    info("Typical destinations:")
    info("  /ext/badusb/<name>.txt   — Bad USB DuckyScript payloads")
    info("  /ext/subghz/<name>.sub   — Sub-GHz signal files")
    info("  /ext/nfc/<name>.nfc      — NFC card data")
    info("  /ext/lfrfid/<name>.rfid  — LF RFID card data")
    info("  /ext/infrared/<name>.ir  — Infrared remote files")
    preselected = get_selected_payload()
    if preselected:
        info(f"Using pre-selected payload: {preselected}")
        local_file = Path(preselected).expanduser()
    else:
        local_path = prompt("Local file path")
        if not local_path:
            warn("No local path provided.")
            return
        local_file = Path(local_path)
    if not local_file.exists():
        err(f"Local file not found: {local_file}")
        return

    default_remote = f"/ext/badusb/{local_file.name}"
    remote_path = prompt("Remote path on Flipper", default=default_remote)
    if not remote_path:
        remote_path = default_remote

    info(f"Uploading {local_file.name} → {remote_path}")
    info("Large files may take a while; the RPC protocol transfers in small chunks.")
    try:
        with open(local_file, "rb") as fh:
            data = fh.read()
        flipper.storage.write.file(file=remote_path, data=data)
        ok(f"Uploaded: {local_file.name}")
    except Exception as e:
        err(f"Upload failed: {e}")
        info("Ensure the destination directory exists on the Flipper SD card.")
        info("Example: create /ext/badusb/ if it doesn't exist using the Flipper file manager.")


def op_download_file(flipper):
    heading("Download File")
    info("Downloads a file from the Flipper Zero to your local machine.")
    info("Use 'List Files' to find the remote path first.")
    remote_path = prompt("Remote path on Flipper")
    if not remote_path:
        warn("No remote path provided.")
        return
    default_local = Path.cwd() / Path(remote_path).name
    local_path = prompt("Local save path", default=str(default_local))
    if not local_path:
        local_path = str(default_local)

    info(f"Downloading {remote_path} → {local_path}")
    try:
        data = flipper.storage.read.file(file=remote_path)
        with open(local_path, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode())
        ok(f"Downloaded to {local_path}")
    except Exception as e:
        err(f"Download failed: {e}")
        info("Verify the remote path is correct and the file exists on the Flipper.")


def op_subghz_transmit(flipper):
    heading("Sub-GHz Transmit")
    info("Transmits a raw Sub-GHz hex key at a specified frequency.")
    info("Common Sub-GHz frequencies:")
    info("  433.92 MHz (433920000) — EU/Asia garage doors, car fobs, weather stations")
    info("  315 MHz    (315000000) — North American car fobs, gate openers")
    info("  868.35 MHz (868350000) — EU ISM band (Z-Wave, LoRa, alarm systems)")
    info("  915 MHz    (915000000) — US ISM band (Z-Wave US, TPMS)")
    info("The Flipper must have Sub-GHz region set appropriately (Settings → Region).")
    info("WARNING: Transmitting on licensed frequencies without authorization is illegal.")
    hex_key = prompt("Hex key to transmit (e.g. DEADBEEF)")
    if not hex_key:
        warn("No key provided.")
        return
    freq_str = prompt("Frequency in Hz", default="433920000")
    try:
        frequency = int(freq_str)
    except ValueError:
        err(f"Invalid frequency: {freq_str}")
        return
    count_str = prompt("Repeat count", default="3")
    try:
        count = int(count_str)
    except ValueError:
        err(f"Invalid count: {count_str}")
        return

    info(f"Transmitting {hex_key} at {frequency} Hz × {count}…")
    info("If TX fails, ensure the Flipper region/frequency is not restricted.")
    info("On Flipper: System → Sub-GHz → Region must allow this frequency.")
    try:
        result = flipper.subghz.tx(key=hex_key, frequency=frequency, count=count)
        info(str(result) if result else "Transmission complete.")
        ok("Sub-GHz TX done.")
    except Exception as e:
        err(f"Sub-GHz transmit failed: {e}")
        info("If error is 'region restricted', change region in Flipper settings or use custom firmware.")


def op_nfc_scan(flipper):
    heading("NFC Scan")
    info("Activates the Flipper NFC reader to detect ISO 14443-A/B cards (13.56 MHz HF).")
    info("Supported card types: MIFARE Classic, MIFARE Ultralight, NTAG2xx, EMV bank cards.")
    info("Hold the card close to the top of the Flipper (NFC antenna is at the top).")
    info("Expected output: UID, SAK, ATQA, card type identification.")
    info("Troubleshooting if no card detected:")
    info("  - Ensure card is within 2-3 cm of the Flipper top edge")
    info("  - Metal cases can block NFC — remove any metal back cover")
    info("  - Some cards use proprietary encryption (e.g. DESFire) — detection still works, reading may not")
    info("Scanning for NFC cards — bring a card close to the Flipper antenna…")
    try:
        result = flipper.nfc.detect()
        if result:
            if isinstance(result, dict):
                for k, v in result.items():
                    info(f"{k}: {v}")
            else:
                info(str(result))
            ok("NFC card detected.")
        else:
            warn("No NFC card detected.")
            info("Try holding the card steady for a few seconds directly over the Flipper top.")
    except Exception as e:
        err(f"NFC scan failed: {e}")


def op_rfid_read(flipper):
    heading("RFID Read (125 kHz LF)")
    info("Activates the Flipper LF RFID reader for 125 kHz proximity cards.")
    info("Supported protocols: EM4100, HID Prox, Indala, IoProx, Paradox, PAC/Stanley, Keri.")
    info("Hold the card close to the back of the Flipper (LF antenna is on the back).")
    info("Expected output: Card type, ID/UID bytes, raw data.")
    info("Troubleshooting if no card read:")
    info("  - LF antenna is on the BACK of the Flipper — face the card to the back")
    info("  - Hold steady for 2-3 seconds — LF reads are slower than NFC")
    info("  - Some cards use unknown/unsupported protocols — try 'RAW' read in Flipper UI")
    info("  - Interference from other nearby 125 kHz readers can cause issues")
    info("Reading LF RFID — bring a card close to the Flipper antenna…")
    try:
        result = flipper.rfid.read()
        if result:
            if isinstance(result, dict):
                for k, v in result.items():
                    info(f"{k}: {v}")
            else:
                info(str(result))
            ok("RFID card read.")
        else:
            warn("No RFID card read.")
            info("Try the read from the Flipper UI directly: Main Menu → 125 kHz RFID → Read")
    except Exception as e:
        err(f"RFID read failed: {e}")


def op_launch_app(flipper):
    heading("Launch App")
    info("Launches a built-in or external app on the Flipper Zero.")
    info("Common built-in app names:")
    info("  'Bad USB'    — USB HID injection")
    info("  'Sub-GHz'   — Sub-GHz radio")
    info("  'NFC'        — NFC operations")
    info("  '125 kHz RFID' — LF RFID")
    info("  'Infrared'   — IR remote control")
    info("  'iButton'    — DS1990/iButton keys")
    info("  'GPIO'       — GPIO pin control")
    info("  'Snake'      — built-in game")
    app_name = prompt("App name (e.g. Bad USB, Sub-GHz)")
    if not app_name:
        warn("No app name provided.")
        return
    info(f"Launching app: {app_name}")
    try:
        flipper.loader.open(app_name=app_name)
        ok(f"App launched: {app_name}")
    except Exception as e:
        err(f"Launch app failed: {e}")
        info("Ensure the app name exactly matches the Flipper menu entry.")
        info("External .fap apps must be installed to /ext/apps/ first.")


def op_reboot(flipper):
    heading("Reboot Device")
    info("Sends a reboot command to the Flipper Zero over the RPC protocol.")
    info("The Flipper will disconnect briefly, then re-enumerate as /dev/ttyACM*.")
    info("After reboot, this tool will attempt to reconnect automatically.")
    if not confirm("Reboot the Flipper Zero now?"):
        info("Reboot cancelled.")
        return
    try:
        flipper.power.reboot()
        ok("Reboot command sent. Device is restarting.")
    except Exception as e:
        err(f"Reboot failed: {e}")


def op_firmware_update(flipper, port: str):
    heading("Firmware Update")
    info("Uploads a firmware package (.fuf) to the Flipper Zero and initiates installation.")
    info("The .fuf file is a Flipper Update Package — download from:")
    info("  Official: https://update.flipperzero.one/")
    info("  Unleashed (custom): https://github.com/DarkFlippers/unleashed-firmware/releases")
    info("  RogueMaster: https://github.com/RogueMaster/flipperzero-firmware-wPlugins/releases")
    info("")
    info("Process:")
    info("  1. Firmware is uploaded to /ext/update/ on the Flipper SD card")
    info("  2. 'update install' command is issued to start the update")
    info("  3. Flipper reboots into update mode and flashes — DO NOT disconnect USB")
    info("  4. Flipper reboots again into the new firmware")
    fuf_path = prompt("Path to .fuf firmware file")
    if not fuf_path:
        warn("No file path provided.")
        return
    fuf_file = Path(fuf_path)
    if not fuf_file.exists():
        err(f"File not found: {fuf_file}")
        return
    if fuf_file.suffix.lower() != ".fuf":
        warn(f"File does not have a .fuf extension: {fuf_file.name}")
        if not confirm("Continue anyway?", default=False):
            return

    remote_update_path = "/ext/update/fw.fuf"
    info(f"Uploading firmware to {remote_update_path}…")
    info("Large firmware files can take a minute to upload over USB serial.")
    try:
        with open(fuf_file, "rb") as fh:
            data = fh.read()
        flipper.storage.write.file(file=remote_update_path, data=data)
        ok("Firmware file uploaded.")
    except Exception as e:
        err(f"Firmware upload failed: {e}")
        info("Ensure /ext/update/ directory exists and the SD card has enough space.")
        return

    info("Triggering firmware install…")
    info("The Flipper will reboot into update mode — this takes 1-3 minutes.")
    info("Do not disconnect USB or power during the update.")
    try:
        flipper.update.install(manifest=remote_update_path)
        ok("Firmware update initiated. The Flipper Zero will reboot and flash.")
        warn("Do not disconnect USB until the update is complete.")
    except Exception as e:
        err(f"Firmware install command failed: {e}")
        info("You can also trigger the update manually on the Flipper:")
        info("  Navigate to the update file in the file manager and select 'Run in App'")


# ── Firmware payloads (main-page auto-flash) ──────────────────────────────────
# The four practical Flipper Zero firmwares. Each is distributed as a
# "web-updater" self-update package (a .tgz) attached to that project's GitHub
# releases. We fetch the latest release's .tgz, extract it, then apply it via the
# module's EXISTING update path (upload the update package to /ext/update/ on the
# SD card and issue flipper.update.install(manifest=…) over RPC).

FIRMWARE_REPOS = {
    "Official":    ("flipperdevices", "flipperzero-firmware",
                    "Official Flipper Zero firmware (flipperdevices/flipperzero-firmware)"),
    "Unleashed":   ("DarkFlippers", "unleashed-firmware",
                    "Unleashed custom firmware (DarkFlippers/unleashed-firmware)"),
    "RogueMaster": ("RogueMaster", "flipperzero-firmware-wPlugins",
                    "RogueMaster custom firmware (RogueMaster/flipperzero-firmware-wPlugins)"),
    "Momentum":    ("Next-Flip", "Momentum-Firmware",
                    "Momentum custom firmware, successor to Xtreme (Next-Flip/Momentum-Firmware)"),
}

# Web-updater package asset — every project ships one named like
# 'flipper-z-f7-update-<ver>.tgz'.
_WEB_UPDATER_ASSET_RE = r"f7-update.*\.tgz$"


def _prep_flipper_web_updater(fw_name: str, staged: dict) -> bool:
    """PREPARE step: resolve the latest release, download the web-updater .tgz,
    extract it, and locate update.fuf. Returns True only when the package is
    fully staged locally so the only remaining step is the write."""
    owner, repo, desc = FIRMWARE_REPOS[fw_name]
    info(f"Firmware : {fw_name} — {desc}")

    tag, rel_url = check_latest_github_release(owner, repo)
    if not tag:
        err(f"  Could not resolve the latest release for {owner}/{repo} — aborting.")
        info(f"  Check manually: https://github.com/{owner}/{repo}/releases")
        return False
    ok(f"  Latest release: {tag}")

    asset_url = get_github_release_asset_url(owner, repo, tag, _WEB_UPDATER_ASSET_RE)
    if not asset_url:
        err(f"  No web-updater .tgz asset found in {owner}/{repo} {tag} — aborting.")
        info(f"  Download manually from: {rel_url or f'https://github.com/{owner}/{repo}/releases'}")
        return False

    slug = fw_name.lower()
    dl_dir = get_firmware_dir("flipper_zero") / slug
    dl_dir.mkdir(parents=True, exist_ok=True)
    tgz_name = asset_url.rsplit("/", 1)[-1] or f"{slug}-update.tgz"
    tgz_path = dl_dir / tgz_name

    if not download_firmware(asset_url, tgz_path, tool_name=f"{fw_name} web-updater"):
        err("  Web-updater package download failed — aborting.")
        info(f"  Download manually: {asset_url}")
        return False

    import shutil as _sh
    import tarfile
    extract_dir = dl_dir / "extracted"
    if extract_dir.exists():
        _sh.rmtree(extract_dir, ignore_errors=True)
    extract_dir.mkdir(parents=True, exist_ok=True)
    info(f"  Extracting {tgz_path.name}…")
    try:
        with tarfile.open(tgz_path, "r:gz") as tf:
            tf.extractall(extract_dir)
    except Exception as e:  # noqa: BLE001
        err(f"  Failed to extract the web-updater package: {e}")
        return False

    fufs = sorted(extract_dir.rglob("update.fuf"))
    if not fufs:
        err("  update.fuf manifest not found inside the package — aborting.")
        info("  The release asset may not be a web-updater package.")
        return False
    update_fuf = fufs[0]

    staged["fw_name"] = fw_name
    staged["tag"] = tag
    staged["update_fuf"] = update_fuf
    staged["pkg_dir"] = update_fuf.parent
    staged["qflipper"] = _sh.which("qFlipper") or _sh.which("qflipper") or ""
    ok(f"  Update package staged: {staged['pkg_dir']}")
    if staged["qflipper"]:
        info(f"  qFlipper detected ({staged['qflipper']}) — you may alternatively "
             "apply the package with the qFlipper desktop app.")
    return True


def _flash_flipper_web_updater(flipper, staged: dict):
    """FLASH step: upload the staged update package to /ext/update/<pkg>/ on the
    SD card and issue the install over RPC — the module's existing update path."""
    pkg_dir = staged["pkg_dir"]
    update_fuf = staged["update_fuf"]
    remote_base = f"/ext/update/{pkg_dir.name}"

    info(f"Uploading the update package to {remote_base}/ on the Flipper SD card…")
    for d in ("/ext/update", remote_base):
        try:
            flipper.storage.mkdir(path=d)
        except Exception:
            pass  # already exists / created by an earlier write

    files = sorted(p for p in pkg_dir.rglob("*") if p.is_file())
    remote_fuf = f"{remote_base}/{update_fuf.name}"
    for f in files:
        rel = f.relative_to(pkg_dir)
        remote = f"{remote_base}/{rel.as_posix()}"
        if rel.parent != Path("."):
            try:
                flipper.storage.mkdir(path=f"{remote_base}/{rel.parent.as_posix()}")
            except Exception:
                pass
        info(f"  → {rel.as_posix()} ({f.stat().st_size // 1024} KB)")
        try:
            with open(f, "rb") as fh:
                flipper.storage.write.file(file=remote, data=fh.read())
        except Exception as e:  # noqa: BLE001
            err(f"  Upload failed for {rel.as_posix()}: {e}")
            info("  Ensure the SD card has enough free space and is writable.")
            return
        if f == update_fuf:
            remote_fuf = remote
    ok("Update package uploaded to the SD card.")

    info(f"Triggering the install from {remote_fuf} — the Flipper reboots into")
    info("update mode and flashes. This takes 1-3 minutes.")
    warn("Do NOT disconnect USB or power until the update completes.")
    try:
        flipper.update.install(manifest=remote_fuf)
        ok(f"{staged['fw_name']} update initiated — the Flipper will reboot and flash.")
        warn("Do not disconnect USB until the update is complete.")
    except Exception as e:  # noqa: BLE001
        err(f"Firmware install command failed: {e}")
        info("You can complete the update manually on the Flipper:")
        info(f"  Archive/File manager → {remote_fuf} → 'Run in App'.")


def _dispatch_firmware_payload(fw: dict, flipper, port: str):
    """Route a selected .qfw firmware payload to the right prepare/flash pair."""
    fw_name = fw.get("firmware", "")
    if fw_name not in FIRMWARE_REPOS:
        err(f"Unknown Flipper Zero firmware payload: {fw_name!r}")
        info(f"  Supported: {', '.join(FIRMWARE_REPOS)}")
        return
    owner, repo, _desc = FIRMWARE_REPOS[fw_name]
    staged: dict = {}
    run_firmware_payload(
        fw.get("label", f"Flash {fw_name} firmware"),
        info_fn=lambda: op_device_info(flipper),
        prepare_fn=lambda: _prep_flipper_web_updater(fw_name, staged),
        flash_fn=lambda: _flash_flipper_web_updater(flipper, staged),
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            f"Firmware : {fw_name} ({owner}/{repo})",
            f"Release  : {staged.get('tag', 'latest')}",
            f"Package  : {staged.get('pkg_dir', '(web-updater .tgz)')}",
            f"Port     : {port}",
            "Flasher  : SD update-package flow (flipper.update.install over RPC)",
        ],
    )


# ── Wi-Fi Dev Board (ESP32-S2 add-on) firmware payloads ───────────────────────
# The Flipper Zero Wi-Fi Dev Board is a separate ESP32-S2 module that clips onto
# the Flipper's GPIO header and is flashed *directly* over its own USB-C port with
# esptool — NOT through the Flipper's RPC/SD update flow. So dev-board payloads are
# intercepted early in main(), before Flipper CDC detection/PyFlipper, and routed
# here. Mirrors esp32d.py's esptool flow (python -m esptool, streaming output).

# ESP32-S2 native USB (download/app) + common USB-serial bridges some dev boards use.
DEVBOARD_VID_PIDS = [
    (0x303A, 0x0002),   # Espressif ESP32-S2 native USB (ROM download mode)
    (0x303A, 0x4001),   # Espressif ESP32-S2 native USB CDC (running app)
    (0x10C4, 0xEA60),   # CP2102 / CP2104 (Silicon Labs) — bridged dev boards
    (0x1A86, 0x7523),   # CH340G — bridged dev boards
]

DEVBOARD_CHIP = "esp32s2"

DEVBOARD_CONNECT_INSTRUCTIONS = (
    "Flipper Zero Wi-Fi Dev Board (ESP32-S2) not detected.\n\n"
    "  1. Connect the DEV BOARD directly to this computer via its own USB-C port\n"
    "     (not through the Flipper). \n"
    "  2. Put it into bootloader/download mode: hold the BOOT button, tap RESET,\n"
    "     then release BOOT.\n"
    "  3. The board enumerates as Espressif native USB (303A:0002) or, on bridged\n"
    "     boards, /dev/ttyUSB* (CP2102/CH340).\n\n"
    "  Linux permission fix if needed:\n"
    "    sudo usermod -aG dialout $USER  (then log out/in)\n"
    "    Verify: ls -la /dev/ttyACM* /dev/ttyUSB*"
)

# ESP32 Marauder — the maintained repo ships a dedicated Flipper Dev Board (S2)
# build. Asset naming has varied across releases; try the flipper/S2 patterns in
# order. The Flipper build is a single combined image flashed at 0x0.
DEVBOARD_MARAUDER_OWNER = "justcallmekoko"
DEVBOARD_MARAUDER_REPO  = "ESP32Marauder"
DEVBOARD_MARAUDER_PATTERNS = [
    r"esp32_marauder.*flipper.*\.bin",
    r"esp32_marauder.*s2.*\.bin",
]

# Black Magic Probe (Black Magic Debug) — the project provides ESP32-S2 builds that
# turn the dev board into a wireless/USB SWD-JTAG debugger. Exact release asset
# naming is not guaranteed stable, so prepare_fn falls back to an operator-supplied
# .bin and verifies presence before the flash. Combined image flashed at 0x0.
DEVBOARD_BLACKMAGIC_OWNER = "blackmagic-debug"
DEVBOARD_BLACKMAGIC_REPO  = "blackmagic"
DEVBOARD_BLACKMAGIC_PATTERNS = [
    r"blackmagic.*esp32.?s2.*\.bin",
    r"blackmagic.*esp32.*\.bin",
]


def detect_devboard() -> bool:
    return find_serial_port_by_vidpid(DEVBOARD_VID_PIDS) is not None


def _run_devboard_esptool(args: list, timeout: int = 180) -> int:
    """Run esptool as a Python module with streaming output (mirrors esp32d.py)."""
    cmd = [sys.executable, "-m", "esptool"] + args
    info(f"Running: {' '.join(cmd)}")
    try:
        return run_streaming(cmd, on_line=lambda l: info(f"  esptool: {l}"), timeout=timeout)
    except FileNotFoundError:
        err("esptool not found even after install attempt.")
        info("Manual install: pip install esptool --break-system-packages")
        return 1
    except Exception as e:  # noqa: BLE001
        err(f"esptool execution error: {e}")
        return 1


def _devboard_user_dir() -> Path:
    """Where an operator may drop a firmware .bin when auto-download can't resolve it."""
    d = get_firmware_dir("flipper_zero_devboard") / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _devboard_download_asset(owner, repo, patterns, dest_dir, what):
    """Download the first GitHub release asset matching any of *patterns* (regex)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tag, rel_url = check_latest_github_release(owner, repo)
    if tag:
        ok(f"  Latest {what} release: {tag}")
    for pat in patterns:
        url = get_github_release_asset_url(owner, repo, tag or "", pat)
        if url:
            fname = url.rsplit("/", 1)[-1]
            dest = dest_dir / fname
            if dest.exists() and dest.stat().st_size > 0:
                ok(f"  {what} already present: {dest.name}")
                return dest
            if download_firmware(url, dest, what):
                return dest
    return None


def op_devboard_info(port: str):
    heading("Wi-Fi Dev Board Info")
    info(f"Serial port : {port}")
    info(f"ESP chip    : {DEVBOARD_CHIP}")
    info("Running 'esptool chip_id' to query the ESP32-S2 dev board…")
    info("Troubleshooting:")
    info("  'Failed to connect' → Hold BOOT, tap RESET, release BOOT, then retry")
    info("  'Permission denied' → sudo usermod -aG dialout $USER  (then log out/in)")
    rc = _run_devboard_esptool(["--chip", DEVBOARD_CHIP, "--port", port,
                                 "--baud", "115200", "chip_id"], timeout=60)
    if rc == 0:
        ok("Dev board info retrieved.")
    else:
        err("chip_id failed. See troubleshooting notes above.")


def _run_devboard_marauder_payload(fw: dict, port: str):
    state = {}
    dest = get_firmware_dir("flipper_zero_devboard") / "marauder"

    def prep():
        binf = _devboard_download_asset(
            DEVBOARD_MARAUDER_OWNER, DEVBOARD_MARAUDER_REPO,
            DEVBOARD_MARAUDER_PATTERNS, dest, "ESP32 Marauder (Flipper Dev Board)")
        if not binf:
            # Fall back to an operator-supplied image before aborting.
            user = _devboard_user_dir()
            bins = sorted(user.glob("*marauder*.bin")) or sorted(user.glob("*.bin"))
            binf = bins[0] if bins else None
        if not binf:
            err("  Could not fetch an ESP32 Marauder Flipper-Dev-Board .bin from the")
            err(f"  latest release of {DEVBOARD_MARAUDER_OWNER}/{DEVBOARD_MARAUDER_REPO}.")
            err(f"  Check https://github.com/{DEVBOARD_MARAUDER_OWNER}/{DEVBOARD_MARAUDER_REPO}/releases")
            err(f"  and drop the flipper/S2 build .bin into {_devboard_user_dir()}")
            return False
        state["fw"] = binf
        ok(f"  Marauder firmware ready: {binf.name}")
        return True

    def flash():
        _run_devboard_esptool([
            "--chip", DEVBOARD_CHIP, "--port", port, "--baud", "921600",
            "write_flash", "0x0", str(state["fw"]),
        ], timeout=300)

    run_firmware_payload(
        fw.get("label", "Flash ESP32 Marauder"),
        info_fn=lambda: op_devboard_info(port),
        prepare_fn=prep,
        flash_fn=flash,
        summary_lines=[
            "Board    : Flipper Zero Wi-Fi Dev Board (ESP32-S2)",
            f"Firmware : ESP32 Marauder ({DEVBOARD_MARAUDER_OWNER}/{DEVBOARD_MARAUDER_REPO}) → 0x0",
            f"Port     : {port}",
            "Flasher  : esptool --chip esp32s2 write_flash 0x0",
        ],
    )


def _run_devboard_blackmagic_payload(fw: dict, port: str):
    state = {}
    dest = get_firmware_dir("flipper_zero_devboard") / "blackmagic"

    def prep():
        binf = _devboard_download_asset(
            DEVBOARD_BLACKMAGIC_OWNER, DEVBOARD_BLACKMAGIC_REPO,
            DEVBOARD_BLACKMAGIC_PATTERNS, dest, "Black Magic Probe (ESP32-S2)")
        if not binf:
            # Black Magic ESP32-S2 release asset naming is not guaranteed; fall back
            # to an operator-supplied image and verify presence before flashing.
            user = _devboard_user_dir()
            bins = sorted(user.glob("*blackmagic*.bin")) or sorted(user.glob("*.bin"))
            binf = bins[0] if bins else None
        if not binf:
            err("  Could not fetch a Black Magic Probe ESP32-S2 .bin from the latest")
            err(f"  release of {DEVBOARD_BLACKMAGIC_OWNER}/{DEVBOARD_BLACKMAGIC_REPO}.")
            err(f"  Check https://github.com/{DEVBOARD_BLACKMAGIC_OWNER}/{DEVBOARD_BLACKMAGIC_REPO}/releases")
            err(f"  and drop the ESP32-S2 build .bin into {_devboard_user_dir()}")
            return False
        state["fw"] = binf
        ok(f"  Black Magic firmware ready: {binf.name}")
        return True

    def flash():
        _run_devboard_esptool([
            "--chip", DEVBOARD_CHIP, "--port", port, "--baud", "921600",
            "write_flash", "0x0", str(state["fw"]),
        ], timeout=300)

    run_firmware_payload(
        fw.get("label", "Flash Black Magic Probe"),
        info_fn=lambda: op_devboard_info(port),
        prepare_fn=prep,
        flash_fn=flash,
        summary_lines=[
            "Board    : Flipper Zero Wi-Fi Dev Board (ESP32-S2)",
            f"Firmware : Black Magic Probe ({DEVBOARD_BLACKMAGIC_OWNER}/{DEVBOARD_BLACKMAGIC_REPO}) → 0x0",
            f"Port     : {port}",
            "Flasher  : esptool --chip esp32s2 write_flash 0x0",
        ],
    )


def _is_devboard_payload(fw: dict) -> bool:
    return "dev board" in str(fw.get("board", "")).strip().lower()


def _devboard_flash_flow(fw: dict):
    """Standalone flash flow for the ESP32-S2 Wi-Fi Dev Board (no Flipper/PyFlipper)."""
    print_banner("Flipper Zero Wi-Fi Dev Board", "ESP32-S2 add-on — direct esptool flash")

    heading("Dependency Check")
    flavor = get_os_flavor()
    info("Ensuring esptool + pyserial are available for ESP32-S2 flashing…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["esptool", "python3-serial"])
    elif flavor == "macos":
        ensure_brew_packages(["esptool"])
    ensure_pip_packages([("esptool", "esptool>=4.7"), ("serial", "pyserial")])

    heading("Device Detection")
    info("Scanning for the ESP32-S2 dev board (native USB 303A:xxxx or CP2102/CH340)…")
    found = verify_device_connection(
        detect_devboard, "Flipper Zero Wi-Fi Dev Board",
        DEVBOARD_CONNECT_INSTRUCTIONS, max_retries=3
    )
    if not found:
        err("Wi-Fi Dev Board not detected. Exiting.")
        sys.exit(1)
    port = find_serial_port_by_vidpid(DEVBOARD_VID_PIDS)
    if not port:
        err("Dev board appeared but serial port could not be resolved. Exiting.")
        sys.exit(1)
    ok(f"Wi-Fi Dev Board found on {port}")

    name = fw.get("firmware", "")
    if name == "Marauder":
        _run_devboard_marauder_payload(fw, port)
    elif name == "BlackMagic":
        _run_devboard_blackmagic_payload(fw, port)
    else:
        err(f"Unknown Wi-Fi Dev Board firmware payload: {name!r}")
        info("  Supported: Marauder, BlackMagic")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    # Wi-Fi Dev Board (ESP32-S2) payloads flash directly over the board's own USB
    # port with esptool — intercept BEFORE Flipper CDC detection/PyFlipper.
    fw_early = selected_firmware_payload()
    if fw_early and _is_devboard_payload(fw_early):
        _devboard_flash_flow(fw_early)
        return

    flavor = get_os_flavor()
    if flavor == "linux":
        info("Ensuring required APT package: python3-serial")
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    info("Installing pip packages: pyflipper, flipperzero-protobuf")
    info("These are not available in apt and must be installed via pip.")
    ensure_pip_packages([
        ("pyflipper", "pyflipper"),
        ("flipperzero_protobuf", "flipperzero-protobuf"),
    ])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Detecting Flipper Zero via USB VID:PID 0483:5740 (CDC mode)…")
    info("Expected device: /dev/ttyACM* (Linux) or /dev/cu.usbmodemflip_* (macOS)")

    found = verify_device_connection(
        detect_flipper, TOOL_NAME, CONNECT_INSTRUCTIONS, max_retries=3
    )
    if not found:
        err("Flipper Zero not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PID_CDC)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Flipper Zero found on {port}")
    _check_dialout(port)

    info("Connecting via PyFlipper…")
    flipper = connect_flipper(port)
    if not flipper:
        sys.exit(1)

    ok("PyFlipper session established.")

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw, flipper, port)
        return

    check_firmware_version(flipper)

    MENU_OPTIONS = [
        "Device Info",
        "List Files",
        "Upload Payload",
        "Download File",
        "Sub-GHz Transmit",
        "NFC Scan",
        "RFID Read",
        "Launch App",
        "Reboot Device",
        "FIRMWARE - Firmware Update",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Flipper Zero — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(flipper)
        elif choice == 1:
            op_list_files(flipper)
        elif choice == 2:
            op_upload_payload(flipper)
        elif choice == 3:
            op_download_file(flipper)
        elif choice == 4:
            op_subghz_transmit(flipper)
        elif choice == 5:
            op_nfc_scan(flipper)
        elif choice == 6:
            op_rfid_read(flipper)
        elif choice == 7:
            op_launch_app(flipper)
        elif choice == 8:
            op_reboot(flipper)
            # After reboot, re-detect and reconnect
            info("Waiting for Flipper Zero to restart…")
            time.sleep(5)
            found = web_detect_loop(detect_flipper, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=120)
            if found:
                new_port = find_serial_port_by_vidpid(VID_PID_CDC)
                if new_port:
                    flipper = connect_flipper(new_port)
                    if flipper:
                        port = new_port
                        ok(f"Reconnected on {port}")
                    else:
                        err("Reconnection failed. Exiting.")
                        break
        elif choice == 9:
            op_firmware_update(flipper, port)
        elif choice == 10:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
