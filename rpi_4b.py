#!/usr/bin/env python3
"""
Raspberry Pi 4B (8GB) Tool Manager

The Raspberry Pi 4B is a full ARM64 single-board computer, NOT a microcontroller.
There is no UF2 / BOOTSEL flow. This module provisions the board the same way the
Pi 4B provisioning module does — two operations, both wired as no-menu firmware
payloads:

  1. OS Image  — writes a bootable OS (Raspberry Pi OS 64-bit or Kali Linux ARM64)
                 to an SD card or USB/NVMe target using `rpi-imager --cli` (with a
                 `dd` fallback). A device-safety guard enumerates removable/external
                 targets, verifies the downloaded image's SHA-256 when a checksum is
                 published, prompts the operator to pick the target, and REFUSES the
                 host's own system disk.

  2. Bootloader EEPROM  — the Pi 4B boot firmware lives in a dedicated SPI EEPROM
                 (BCM2712 / RP1). `rpi-eeprom-update -a` stages the latest bootloader
                 for application on the next reboot. This operation only works when
                 THIS module is running ON the Pi 4B itself (rpi-eeprom-update is a
                 Raspberry Pi OS tool); prepare_fn refuses to proceed on a non-Pi host.

Usage:
    python3 rpi_5.py
"""

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    require_sudo, sudo_run,
    ensure_apt_packages, ensure_system_tool,
    run_streaming_sudo,
    web_detect_loop,
    selected_firmware_payload, run_firmware_payload,
    download_firmware, get_firmware_dir,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Raspberry Pi 4B"
DESCRIPTION = "Raspberry Pi 4B (8GB) ARM64 SBC — OS imaging & bootloader EEPROM provisioning"

FW_TOOL_ID  = "rpi_4b"

# Community-standard "latest" redirect endpoints maintained by Raspberry Pi Ltd.
# These 302-redirect to the newest raspios_arm64 image / its .sha256 sibling.
# NOTE: if the redirect layout ever changes, prepare_fn will report the failure
# and abort BEFORE any confirmation — nothing is written on a broken download.
RASPIOS_IMG_URL = "https://downloads.raspberrypi.com/raspios_arm64_latest"
RASPIOS_SHA_URL = "https://downloads.raspberrypi.com/raspios_arm64_latest.sha256"

# Kali has no stable "_latest" redirect for its Raspberry Pi ARM64 image, so the
# operator supplies the URL (or a local file). Directory listing for reference:
KALI_ARM_INDEX  = "https://kali.download/arm-images/"

CONNECT_INSTRUCTIONS = (
    "Raspberry Pi 4B provisioning context not ready.\n\n"
    "  For 'OS Image':\n"
    "    - Insert the target SD card (via a USB card reader) or a USB/NVMe enclosure\n"
    "      into THIS host computer. It must appear as a removable/external disk.\n"
    "    - The image is written to that removable target — NOT to the Pi directly.\n\n"
    "  For 'Bootloader EEPROM':\n"
    "    - Run this module ON the Raspberry Pi 4B itself (Raspberry Pi OS).\n"
    "    - `rpi-eeprom-update` only exists / applies on the Pi.\n\n"
    "  Linux target check : lsblk -dpno NAME,SIZE,MODEL,RM,TYPE\n"
    "  macOS  target check : diskutil list external physical"
)


# ── Platform / device context ─────────────────────────────────────────────────

def _read_pi_model() -> str:
    """Return the Raspberry Pi model string from the device-tree, or '' if not a Pi."""
    for p in ("/proc/device-tree/model", "/sys/firmware/devicetree/base/model"):
        try:
            txt = Path(p).read_bytes().decode("utf-8", "replace").replace("\x00", "").strip()
            if txt:
                return txt
        except Exception:
            pass
    return ""


def _running_on_pi4() -> bool:
    model = _read_pi_model()
    return "raspberry pi 4" in model.lower()


def detect_device() -> bool:
    """
    Lenient provisioning-context detection:
      True if we're running ON a Pi 4B, OR a removable/external target disk is present.
    Either condition is enough to do useful work (EEPROM vs OS imaging).
    """
    if _running_on_pi4():
        return True
    return len(_list_target_disks()) > 0


# ── Device-safety guard: enumerate target disks & refuse the system disk ───────

def _linux_root_disk() -> str:
    """Return the whole-disk device backing '/', e.g. '/dev/sda' or '/dev/nvme0n1'."""
    src = run_output("findmnt -no SOURCE / 2>/dev/null").strip()
    if not src:
        return ""
    # src may be a partition (e.g. /dev/sda2) or a mapper device; resolve to its parent disk.
    name = src.split("/")[-1]
    pk = run_output(f"lsblk -no PKNAME /dev/{name} 2>/dev/null").strip().splitlines()
    if pk and pk[0].strip():
        return "/dev/" + pk[0].strip()
    return src


def _list_target_disks() -> list[dict]:
    """
    Enumerate candidate WHOLE-disk targets, each: {dev, size, model, removable, system}.
    Linux : every TYPE==disk from lsblk; system flag = disk backing '/'.
    macOS : external physical disks from diskutil (internal disks are excluded outright).
    """
    os_name = get_os()
    disks: list[dict] = []

    if os_name == "linux":
        root_disk = _linux_root_disk()
        out = run_output("lsblk -dpno NAME,SIZE,MODEL,RM,TYPE 2>/dev/null")
        for ln in out.splitlines():
            parts = ln.split(None, 4)
            if len(parts) < 5:
                continue
            name, size, model, rm, typ = parts[0], parts[1], parts[2], parts[3], parts[4]
            # When MODEL is empty lsblk collapses columns; re-parse defensively.
            if typ != "disk":
                # model was empty -> fields shift; re-split without model
                p2 = ln.split()
                if len(p2) >= 4 and p2[-1] == "disk":
                    name, size, rm, typ = p2[0], p2[1], p2[-2], p2[-1]
                    model = ""
                else:
                    continue
            disks.append({
                "dev": name,
                "size": size,
                "model": model.strip() or "unknown",
                "removable": rm.strip() == "1",
                "system": (name == root_disk),
            })

    elif os_name == "macos":
        listing = run_output("diskutil list external physical 2>/dev/null")
        for ln in listing.splitlines():
            ln = ln.strip()
            if ln.startswith("/dev/disk"):
                dev = ln.split()[0]
                info_txt = run_output(f"diskutil info {dev} 2>/dev/null")
                internal = "Internal:                  Yes" in info_txt or \
                           _diskutil_field(info_txt, "Internal") == "Yes"
                size = _diskutil_field(info_txt, "Disk Size") or "unknown"
                model = _diskutil_field(info_txt, "Device / Media Name") or "unknown"
                removable = _diskutil_field(info_txt, "Removable Media") in ("Yes", "Removable")
                disks.append({
                    "dev": dev,
                    "size": size,
                    "model": model,
                    "removable": removable or not internal,
                    "system": internal,   # internal == system disk; refuse it
                })

    return disks


def _diskutil_field(info_txt: str, key: str) -> str:
    for ln in info_txt.splitlines():
        if ln.strip().startswith(key + ":"):
            return ln.split(":", 1)[1].strip()
    return ""


def _is_system_disk(dev: str) -> bool:
    """Refuse the host's own system disk regardless of how it was chosen."""
    os_name = get_os()
    if os_name == "linux":
        root_disk = _linux_root_disk()
        if dev == root_disk:
            return True
        # Also refuse if any partition of dev is mounted at a critical mountpoint.
        mnts = run_output(f"lsblk -nro MOUNTPOINT {dev} 2>/dev/null")
        for mp in mnts.split():
            if mp in ("/", "/boot", "/boot/efi", "/home", "/var", "/usr"):
                return True
        return False
    elif os_name == "macos":
        info_txt = run_output(f"diskutil info {dev} 2>/dev/null")
        return _diskutil_field(info_txt, "Internal") == "Yes"
    return False


def _choose_target_disk() -> str:
    """Enumerate targets, let the operator pick a SAFE one, and hard-refuse system disks."""
    disks = _list_target_disks()
    safe = [d for d in disks if not d["system"]]

    if not safe:
        err("  No safe removable/external target disk found.")
        info("  Insert an SD card (USB reader) or a USB/NVMe enclosure and re-run.")
        info("  Linux : lsblk -dpno NAME,SIZE,MODEL,RM,TYPE")
        info("  macOS : diskutil list external physical")
        return ""

    labels = []
    for d in safe:
        flag = "removable" if d["removable"] else "external"
        labels.append(f"{d['dev']}  [{d['size']}]  {d['model']}  ({flag})")
    labels.append("Enter a device path manually")

    warn("  Choose the TARGET disk carefully — its contents will be ERASED.")
    for d in disks:
        if d["system"]:
            info(f"  (system disk {d['dev']} is hidden from this list and will be refused)")

    idx = numbered_menu("Select the target disk to image:", labels)
    if idx < len(safe):
        chosen = safe[idx]["dev"]
    else:
        chosen = prompt("Device path (e.g. /dev/sdX or /dev/diskN)").strip()

    if not chosen:
        warn("  No target selected.")
        return ""

    if _is_system_disk(chosen):
        err(f"  REFUSED: {chosen} is the host's system disk. Never imaging that.")
        return ""

    known = {d["dev"] for d in disks}
    if chosen not in known:
        warn(f"  {chosen} was not in the enumerated disk list — double-check the path.")
        if not confirm(f"  Are you certain {chosen} is the removable target (NOT a system disk)?",
                       default=False):
            return ""

    return chosen


# ── OS image acquisition + checksum verification ──────────────────────────────

def _fw_dir() -> Path:
    d = get_firmware_dir(FW_TOOL_ID)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_checksum(img: Path, sha_url: str) -> bool:
    """
    Download the published .sha256, compare to the local file's digest.
    Returns True when verified; when the checksum can't be fetched, warns and lets
    the operator decide (community-standard fallback) rather than hard-failing.
    """
    info("  Verifying image SHA-256 against the published checksum…")
    sha_file = _fw_dir() / (img.name + ".sha256")
    if not download_firmware(sha_url, sha_file, "SHA-256 checksum"):
        warn("  Could not download the published checksum — cannot auto-verify.")
        return confirm("  Continue WITHOUT checksum verification?", default=False)
    try:
        published = sha_file.read_text().split()[0].strip().lower()
    except Exception as e:
        warn(f"  Could not parse checksum file: {e}")
        return confirm("  Continue WITHOUT checksum verification?", default=False)

    info("  Computing local SHA-256 (this can take a moment on large images)…")
    actual = _sha256_of(img).lower()
    if actual == published:
        ok(f"  Checksum OK: {actual}")
        return True
    err("  CHECKSUM MISMATCH — the download is corrupt or tampered.")
    err(f"    published: {published}")
    err(f"    actual   : {actual}")
    return False


def _acquire_os_image() -> Path | None:
    """Return a path to the OS image to write (.img / .img.xz / .img.gz), or None."""
    choice = numbered_menu("Which OS image?", [
        "Raspberry Pi OS 64-bit (auto-download latest + checksum)",
        "Kali Linux ARM64 for Raspberry Pi (enter download URL)",
        "Local image file already on disk (.img / .img.xz / .img.gz)",
    ])

    if choice == 0:
        dest = _fw_dir() / "raspios_arm64_latest.img.xz"
        if not (dest.exists() and dest.stat().st_size > 0):
            if not download_firmware(RASPIOS_IMG_URL, dest, "Raspberry Pi OS 64-bit image"):
                err("  Raspberry Pi OS download failed.")
                return None
        else:
            ok(f"  Using cached image: {dest.name}")
        if not _verify_checksum(dest, RASPIOS_SHA_URL):
            return None
        return dest

    if choice == 1:
        info(f"  Kali ARM image index (for reference): {KALI_ARM_INDEX}")
        info("  Paste the direct URL to a kali-linux-*-raspberry-pi-arm64.img.xz file.")
        url = prompt("Kali ARM64 image URL").strip()
        if not url:
            warn("  No URL provided.")
            return None
        dest = _fw_dir() / url.rsplit("/", 1)[-1]
        if not (dest.exists() and dest.stat().st_size > 0):
            if not download_firmware(url, dest, "Kali ARM64 image"):
                err("  Kali image download failed.")
                return None
        else:
            ok(f"  Using cached image: {dest.name}")
        # Kali publishes SHA256SUMS in the same directory; try the sibling .sha256sum.
        sha_url = url + ".sha256sum"
        if not _verify_checksum(dest, sha_url):
            return None
        return dest

    # Local file
    p = prompt("Path to local image file").strip()
    if not p:
        warn("  No path provided.")
        return None
    img = Path(p).expanduser()
    if not img.exists():
        err(f"  File not found: {img}")
        return None
    if img.suffix.lower() not in (".img", ".xz", ".gz"):
        warn(f"  Unexpected extension: {img.suffix} (expected .img/.img.xz/.img.gz)")
        if not confirm("  Use this file anyway?", default=False):
            return None
    ok(f"  Using local image: {img}")
    return img


# ── Flash tooling ─────────────────────────────────────────────────────────────

def _have_rpi_imager() -> bool:
    return shutil.which("rpi-imager") is not None


def _ensure_flasher() -> str:
    """
    Ensure a flasher is available. Prefer rpi-imager (handles .xz + verify);
    fall back to dd (always present) + xz/gunzip for decompression.
    Returns 'rpi-imager' or 'dd'.
    """
    info("  Checking for rpi-imager (preferred flasher)…")
    if _have_rpi_imager():
        ok("  rpi-imager present.")
        return "rpi-imager"
    # Try to install rpi-imager (apt package: rpi-imager; brew cask: raspberry-pi-imager)
    flavor = get_os_flavor()
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  rpi-imager not found — trying apt (rpi-imager)…")
        ensure_apt_packages(["rpi-imager"])
    elif flavor == "macos":
        info("  rpi-imager not found — trying brew cask (raspberry-pi-imager)…")
        run("brew install --cask raspberry-pi-imager")
    if _have_rpi_imager():
        ok("  rpi-imager installed.")
        return "rpi-imager"
    warn("  rpi-imager unavailable — falling back to dd (raw write).")
    info("  dd is standard on this platform; decompression uses xz/gunzip as needed.")
    return "dd"


def _decompress_for_dd(img: Path) -> Path | None:
    """dd needs a raw .img; decompress .xz/.gz into the firmware dir if required."""
    suf = img.suffix.lower()
    if suf == ".img":
        return img
    raw = _fw_dir() / (img.stem if suf in (".xz", ".gz") else img.name + ".img")
    if raw.exists() and raw.stat().st_size > 0:
        ok(f"  Using previously decompressed image: {raw.name}")
        return raw
    if suf == ".xz":
        if not shutil.which("xz"):
            ensure_system_tool("xz", "install xz-utils", apt_pkg="xz-utils", brew_pkg="xz")
        info(f"  Decompressing {img.name} with xz → {raw.name} …")
        # -dkc keeps the source and streams to stdout; redirect into the raw target.
        r = run(f"xz -dkc -T0 {str(img)!r} > {str(raw)!r}")
        if r.returncode != 0:
            err("  xz decompression failed.")
            return None
        return raw if raw.exists() and raw.stat().st_size > 0 else None
    if suf == ".gz":
        if not shutil.which("gunzip"):
            ensure_system_tool("gunzip", "install gzip", apt_pkg="gzip", brew_pkg="gzip")
        info(f"  Decompressing {img.name} with gunzip…")
        r = run(f"gunzip -kc {str(img)!r} > {str(raw)!r}")
        if r.returncode != 0:
            err("  gunzip decompression failed.")
            return None
        return raw if raw.exists() else None
    warn(f"  Don't know how to decompress {suf}; passing through.")
    return img


def _macos_raw_dev(dev: str) -> str:
    """macOS: raw device /dev/rdiskN is dramatically faster for dd."""
    if dev.startswith("/dev/disk"):
        return dev.replace("/dev/disk", "/dev/rdisk", 1)
    return dev


def _write_image(img: Path, dev: str, method: str) -> bool:
    os_name = get_os()

    if method == "rpi-imager":
        # rpi-imager --cli <src> <dst> ; handles .xz transparently and verifies.
        cmd = ["rpi-imager", "--cli", str(img), dev]
        info(f"  Running: {' '.join(cmd)}")
        rc = run_streaming_sudo(cmd, on_line=lambda l: info(f"  rpi-imager: {l}"),
                                timeout=3600)
        if rc == 0:
            ok("  rpi-imager reported success.")
            return True
        err(f"  rpi-imager exited with code {rc}.")
        return False

    # dd fallback
    raw_img = _decompress_for_dd(img)
    if not raw_img or not raw_img.exists():
        err("  No raw .img available for dd — aborting the write.")
        return False

    # Unmount the target before a raw write.
    if os_name == "linux":
        parts = run_output(f"lsblk -nro NAME {dev} 2>/dev/null").split()
        for name in parts:
            sudo_run(f"umount /dev/{name} 2>/dev/null")
        out_dev = dev
        bs = "4M"
    else:  # macOS
        sudo_run(f"diskutil unmountDisk {dev} 2>/dev/null")
        out_dev = _macos_raw_dev(dev)
        bs = "4m"

    cmd = ["dd", f"if={raw_img}", f"of={out_dev}", f"bs={bs}", "conv=fsync"]
    if os_name == "linux":
        cmd.append("status=progress")
    info(f"  Running: sudo {' '.join(cmd)}")
    rc = run_streaming_sudo(cmd, on_line=lambda l: info(f"  dd: {l}"), timeout=3600)
    sudo_run("sync")
    if rc == 0:
        ok("  dd write complete (buffers flushed).")
        if os_name == "macos":
            sudo_run(f"diskutil eject {dev} 2>/dev/null")
        return True
    err(f"  dd exited with code {rc}.")
    return False


# ── Firmware payload: OS Image ────────────────────────────────────────────────

def _prep_os_image(staged: dict) -> bool:
    method = _ensure_flasher()
    img = _acquire_os_image()
    if not img:
        err("  Could not obtain a verified OS image — aborting before the flash.")
        return False
    dev = _choose_target_disk()
    if not dev:
        err("  No valid, non-system target disk selected — aborting before the flash.")
        return False
    staged["method"] = method
    staged["img"] = img
    staged["dev"] = dev
    ok(f"  Ready: write {img.name} → {dev} via {method}.")
    return True


def _flash_os_image(staged: dict):
    img = staged.get("img")
    dev = staged.get("dev")
    method = staged.get("method")
    if not img or not Path(img).exists() or not dev:
        err("OS image or target missing at flash time — aborting.")
        return
    # Final safety re-check immediately before the destructive write.
    if _is_system_disk(dev):
        err(f"ABORT: {dev} resolved to the system disk at flash time. Refusing.")
        return
    _write_image(Path(img), dev, method)
    info("  When the write completes, move the card/drive to the Pi 4B and power on.")


# ── Firmware payload: Bootloader EEPROM ───────────────────────────────────────

def _prep_eeprom(staged: dict) -> bool:
    if get_os() != "linux" or not _running_on_pi4():
        err("  Bootloader EEPROM update must run ON the Raspberry Pi 4B itself.")
        info("  Detected model: " + (_read_pi_model() or "not a Raspberry Pi"))
        info("  rpi-eeprom-update is a Raspberry Pi OS tool and cannot run on this host.")
        return False
    info("  Ensuring rpi-eeprom is installed (provides rpi-eeprom-update)…")
    if not shutil.which("rpi-eeprom-update"):
        ensure_apt_packages(["rpi-eeprom"])
    if not shutil.which("rpi-eeprom-update"):
        err("  rpi-eeprom-update not available even after install attempt.")
        return False
    # Show what an update would do (read-only), so the summary is meaningful.
    info("  Current bootloader status:")
    rc = run_streaming_sudo(["rpi-eeprom-update"],
                            on_line=lambda l: info(f"  eeprom: {l}"), timeout=60)
    if rc != 0:
        warn("  Could not read current EEPROM status (continuing).")
    staged["ready"] = True
    return True


def _flash_eeprom(staged: dict):
    if not staged.get("ready"):
        err("EEPROM prep did not complete — aborting.")
        return
    info("  Staging the latest bootloader (rpi-eeprom-update -a)…")
    cmd = ["rpi-eeprom-update", "-a"]
    info(f"  Running: sudo {' '.join(cmd)}")
    rc = run_streaming_sudo(cmd, on_line=lambda l: info(f"  eeprom: {l}"), timeout=120)
    if rc == 0:
        ok("  Bootloader update staged. It is applied on the NEXT reboot.")
        info("  Reboot the Pi 4B to apply: sudo reboot")
    else:
        err(f"  rpi-eeprom-update exited with code {rc}.")


# ── Device info ───────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info(f"Board : {TOOL_NAME}")
    model = _read_pi_model()
    if model:
        ok(f"Running ON a Raspberry Pi: {model}")
        info("  SoC     : Broadcom BCM2711 (quad Cortex-A72 @ 1.8 GHz)")
        info("  I/O     : VL805 USB 3.0 controller + on-SoC Gigabit Ethernet")
        info("  Boot FW : SPI EEPROM bootloader (rpi-eeprom-update)")
        info("  Wireless: dual-band 802.11ac Wi-Fi + Bluetooth 5.0/BLE")
    else:
        info("Not running on a Pi — host provisioning mode (OS imaging only).")
    info("")
    info("Detected target disks (image destinations):")
    disks = _list_target_disks()
    if not disks:
        info("  (none — insert an SD card via USB reader or a USB/NVMe enclosure)")
    for d in disks:
        tag = "SYSTEM DISK — will be refused" if d["system"] else \
              ("removable" if d["removable"] else "external")
        info(f"  {d['dev']}  [{d['size']}]  {d['model']}  ({tag})")


# ── Firmware payload dispatch ─────────────────────────────────────────────────

def _dispatch_firmware_payload(fw: dict):
    fw_name = fw.get("firmware", "")
    label = fw.get("label", f"Flash {fw_name}")
    staged: dict = {}

    if fw_name == "OS Image":
        run_firmware_payload(
            label,
            info_fn=op_device_info,
            prepare_fn=lambda: _prep_os_image(staged),
            flash_fn=lambda: _flash_os_image(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : OS Image (Raspberry Pi OS 64-bit / Kali ARM64 / local .img)",
                "Flasher  : rpi-imager --cli (dd fallback)",
                "Target   : operator-selected removable/external disk (system disk refused)",
                "Verify   : SHA-256 checked against the published checksum when available",
            ],
        )
    elif fw_name == "Bootloader EEPROM":
        run_firmware_payload(
            label,
            info_fn=op_device_info,
            prepare_fn=lambda: _prep_eeprom(staged),
            flash_fn=lambda: _flash_eeprom(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : Bootloader EEPROM (SPI, applied on next reboot)",
                "Flasher  : rpi-eeprom-update -a  (must run ON the Pi 4B)",
            ],
        )
    else:
        err(f"Unknown firmware payload: {fw_name!r}")
        info("  Supported: OS Image, Bootloader EEPROM")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Dependency Check")
    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Ensuring util-linux (lsblk/findmnt) and xz-utils are present…")
        ensure_apt_packages(["util-linux", "xz-utils"])

    # A firmware payload selected on the main page → auto-flash (no menu).
    # prepare_fn performs the real readiness gate (image download, checksum,
    # target selection, Pi-presence check), so we dispatch directly.
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    heading("Device Detection")
    info("Provisioning context: a removable target disk (for imaging) OR running on a Pi 4B.")
    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("No provisioning context detected within timeout. Exiting.")
        sys.exit(1)

    MENU_OPTIONS = [
        "Device Info (Pi model + target disks)",
        "FIRMWARE - Flash OS Image (rpi-imager/dd to SD/USB, safety-guarded)",
        "FIRMWARE - Update Bootloader EEPROM (rpi-eeprom-update -a, on the Pi)",
        "Exit",
    ]

    while True:
        heading(f"{TOOL_NAME} — Main Menu")
        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)
        if choice == 0:
            op_device_info()
        elif choice == 1:
            _dispatch_firmware_payload({"firmware": "OS Image",
                                        "label": "Flash OS Image to SD/USB"})
        elif choice == 2:
            _dispatch_firmware_payload({"firmware": "Bootloader EEPROM",
                                        "label": "Update Bootloader EEPROM"})
        elif choice == 3:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
