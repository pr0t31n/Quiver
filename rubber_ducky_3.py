#!/usr/bin/env python3
"""
USB Rubber Ducky 3 Tool Manager
Handles detection, payload deployment, SD card management, and firmware
updates for the USB Rubber Ducky 3 (RP2040-based) by Hak5.

The USB Rubber Ducky 3 uses an RP2040 microcontroller and runs DuckyScript 3.0.
It presents as a USB mass storage device (SD card) or a USB HID keyboard
depending on operating mode.

Device modes:
  Attack mode  — appears as USB HID (Apple Keyboard spoof) VID:PID 05AC:8102
                 SD card volume: "DUCKY" on macOS /Volumes/DUCKY
                 or /media/<user>/DUCKY on Linux
  Storage mode — appears as USB mass storage VID:PID 1B4F:9204 (or RPI-RP2)
  Bootloader   — hold button while connecting, appears as "RPI-RP2" drive
                 used to drag-drop UF2 firmware files

Firmware updates:
  - Automated: download UF2 from GitHub hak5/usb-rubber-ducky releases
  - Enter bootloader by holding the button while plugging in
  - Copy the .uf2 file to the RPI-RP2 drive

DuckyScript 3.0:
  - Payloads are .txt files stored on the SD card
  - Compiler: https://payloadstudio.hak5.org/  (online)
  - Local encoder: duck encoder (Java, from Hak5 downloads)
  - inject.bin is the compiled payload run by the device

Usage:
    python3 rubber_ducky_3.py
"""

import os
import sys
import re
import time
import shutil
import tempfile
import platform
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
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    download_firmware, get_firmware_dir, get_github_release_asset_url,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "USB Rubber Ducky 3"
DESCRIPTION = "RP2040-based USB HID injection device (DuckyScript 3.0) by Hak5"

# VID:PID in HID (attack) mode — spoofs Apple Keyboard
VID_PID_HID       = (0x05AC, 0x8102)
# VID:PID in USB mass storage / storage mode
VID_PID_STORAGE   = (0x1B4F, 0x9204)
# VID:PID in RP2040 bootloader mode (for UF2 firmware flashing)
VID_PID_BOOTLOADER = (0x2E8A, 0x0003)   # Raspberry Pi RP2040 bootloader

VID_PIDS = [VID_PID_HID, VID_PID_STORAGE, VID_PID_BOOTLOADER]

GITHUB_OWNER    = "hak5"
GITHUB_REPO     = "usb-rubber-ducky"
PAYLOAD_STUDIO  = "https://payloadstudio.hak5.org/"
HAK5_DOWNLOADS  = "https://hak5.org/downloads"

# Volume names to look for
DUCKY_VOLUME_NAMES   = ["DUCKY", "RUBBER DUCKY"]
BOOT_VOLUME_NAMES    = ["RPI-RP2"]

CONNECT_INSTRUCTIONS = (
    "USB Rubber Ducky 3 not detected.\n\n"
    "  1. Plug the USB Rubber Ducky 3 into a USB port.\n\n"
    "  2. In attack mode, the SD card will mount as 'DUCKY':\n"
    "       macOS: /Volumes/DUCKY\n"
    "       Linux: /media/<user>/DUCKY  or  /run/media/<user>/DUCKY\n\n"
    "  3. VID:PID identifiers:\n"
    "       Attack / HID mode:   05AC:8102  (Apple Keyboard spoof)\n"
    "       Storage mode:        1B4F:9204\n"
    "       Bootloader (RPI-RP2): 2E8A:0003\n\n"
    "  4. If the device doesn't appear:\n"
    "       - Try a different USB port (USB 2.0 recommended)\n"
    "       - Ensure the SD card is inserted\n"
    "       - Check: lsusb | grep -E '05ac|1b4f|2e8a'\n\n"
    "  5. For firmware updates, enter bootloader by holding the\n"
    "     button on the Ducky WHILE plugging it in.\n\n"
    "  6. Payload reference: https://github.com/hak5/usb-rubber-ducky"
)

UDEV_RULES_CONTENT = """\
# USB Rubber Ducky 3 udev rules
# HID (attack) mode — Apple Keyboard spoof
SUBSYSTEM=="usb", ATTRS{idVendor}=="05ac", ATTRS{idProduct}=="8102", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="05ac", ATTRS{idProduct}=="8102", MODE="0666", GROUP="plugdev"
# Storage mode (Sparkfun Pro Micro RP2040)
SUBSYSTEM=="usb", ATTRS{idVendor}=="1b4f", ATTRS{idProduct}=="9204", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="block", ATTRS{idVendor}=="1b4f", ATTRS{idProduct}=="9204", MODE="0666", GROUP="plugdev"
# RP2040 bootloader (UF2 flashing mode)
SUBSYSTEM=="usb", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0003", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="block", ATTRS{idVendor}=="2e8a", ATTRS{idProduct}=="0003", MODE="0666", GROUP="plugdev"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-rubber-ducky.rules"


# ── SD card / volume helpers ──────────────────────────────────────────────────

def _find_ducky_mount() -> Path | None:
    """
    Search for the DUCKY volume mount point.
    Returns a Path if found, or None.
    """
    flavor = get_os_flavor()
    try:
        if flavor == "macos":
            for vol_name in DUCKY_VOLUME_NAMES:
                p = Path(f"/Volumes/{vol_name}")
                if p.is_dir():
                    return p
        else:
            # Linux: check /media/<user>/, /run/media/<user>/, /mnt/
            search_roots = [Path("/media"), Path("/run/media"), Path("/mnt")]
            for root in search_roots:
                if not root.exists():
                    continue
                # /media/<user>/DUCKY  or  /media/DUCKY
                for vol_name in DUCKY_VOLUME_NAMES:
                    direct = root / vol_name
                    if direct.is_dir():
                        return direct
                    # one level deeper: /media/username/DUCKY
                    for sub in root.iterdir():
                        if sub.is_dir():
                            candidate = sub / vol_name
                            if candidate.is_dir():
                                return candidate
    except Exception as e:
        warn(f"Error searching for DUCKY mount: {e}")
    return None


def _find_rpi_rp2_mount() -> Path | None:
    """
    Search for the RPI-RP2 bootloader volume.
    Returns a Path if found, or None.
    """
    flavor = get_os_flavor()
    try:
        if flavor == "macos":
            p = Path("/Volumes/RPI-RP2")
            if p.is_dir():
                return p
        else:
            for root in [Path("/media"), Path("/run/media"), Path("/mnt")]:
                if not root.exists():
                    continue
                for vol_name in BOOT_VOLUME_NAMES:
                    direct = root / vol_name
                    if direct.is_dir():
                        return direct
                    for sub in root.iterdir():
                        if sub.is_dir():
                            candidate = sub / vol_name
                            if candidate.is_dir():
                                return candidate
    except Exception as e:
        warn(f"Error searching for RPI-RP2 mount: {e}")
    return None


def detect_device() -> bool:
    """Return True if DUCKY or RPI-RP2 volume is mounted, or VID:PID matched."""
    if _find_ducky_mount() is not None:
        return True
    if _find_rpi_rp2_mount() is not None:
        return True
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    flavor = get_os_flavor()
    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for USB Rubber Ducky 3…")
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the Rubber Ducky to apply new permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual fix: sudo tee {UDEV_RULES_PATH} << 'EOF'")
        info(UDEV_RULES_CONTENT)
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Firmware version check ────────────────────────────────────────────────────

def check_firmware_version(mount: Path | None = None):
    heading("Firmware Version Check")

    if mount is None:
        mount = _find_ducky_mount()

    current = None

    if mount:
        ok(f"Ducky SD card mounted at: {mount}")
        # The device writes a version.txt to the SD card root
        version_file = mount / "version.txt"
        if version_file.exists():
            try:
                raw = version_file.read_text(errors="replace").strip()
                # version.txt may look like "3.0" or "v3.1.2" or a build string
                m = re.search(r"v?([\d.]+)", raw)
                if m:
                    current = m.group(1)
                    ok(f"Firmware version (from version.txt): {current}")
                else:
                    info(f"version.txt content: {raw[:200]}")
            except Exception as e:
                warn(f"Could not read version.txt: {e}")
        else:
            warn("version.txt not found on SD card.")
            info("The firmware version file may be named differently on this build.")
            info(f"SD card contents: {[f.name for f in mount.iterdir()][:20]}")
    else:
        warn("DUCKY SD card not mounted. Cannot read version.txt.")
        info("Plug in the Rubber Ducky and ensure the SD card volume mounts.")

    # Check GitHub for latest firmware release
    info("Checking latest firmware release on GitHub (hak5/usb-rubber-ducky)…")
    try:
        latest_tag, release_url = check_latest_github_release(GITHUB_OWNER, GITHUB_REPO)
        if latest_tag:
            ok(f"Latest firmware on GitHub: {latest_tag}")
            info(f"Release URL: {release_url}")
            if current:
                announce_firmware_update(
                    TOOL_NAME, current, latest_tag.lstrip("v"), release_url
                )
        else:
            warn("Could not retrieve GitHub release info.")
    except Exception as e:
        warn(f"GitHub version check error: {e}")


# ── Operations ────────────────────────────────────────────────────────────────

def op_detect_and_check_version():
    heading("Detect Device & Check Firmware Version")
    info("Scanning for USB Rubber Ducky 3 (DUCKY volume or VID:PID match)…")
    try:
        mount = _find_ducky_mount()
        rpi_mount = _find_rpi_rp2_mount()
        port = find_serial_port_by_vidpid(VID_PIDS)

        if mount:
            ok(f"USB Rubber Ducky 3 detected — SD card mounted at: {mount}")
        elif rpi_mount:
            ok(f"USB Rubber Ducky 3 detected in BOOTLOADER mode — RPI-RP2 at: {rpi_mount}")
            info("Device is in firmware update mode. Use 'Firmware Update' option.")
        elif port:
            ok(f"USB Rubber Ducky 3 detected via VID:PID on port: {port}")
            warn("SD card volume not mounted. The device may be in HID-only mode.")
        else:
            err("USB Rubber Ducky 3 not detected.")
            info("Troubleshooting:")
            info("  - Ensure SD card is inserted in the Ducky")
            info("  - Try: lsblk | grep -i ducky  OR  ls /Volumes/ | grep -i ducky")
            info(f"  - VID:PID (attack): 05AC:8102  (storage): 1B4F:9204")
            return

        check_firmware_version(mount)

    except Exception as e:
        err(f"Detection error: {e}")


def op_list_payloads():
    heading("List Payloads on SD Card")
    try:
        mount = _find_ducky_mount()
        if not mount:
            err("DUCKY SD card not mounted.")
            info("Plug in the USB Rubber Ducky and ensure it mounts as 'DUCKY'.")
            return

        ok(f"SD card mounted at: {mount}")
        info("Scanning for payload files (.txt, .duck, .bin)…")

        payloads = []
        for ext in ("*.txt", "*.duck", "*.bin", "*.js"):
            payloads.extend(mount.glob(ext))

        if payloads:
            ok(f"Found {len(payloads)} payload file(s):")
            for p in sorted(payloads):
                size = p.stat().st_size
                info(f"  {p.name:40s}  ({size:,} bytes)")
        else:
            info("No payload files (.txt/.duck/.bin) found on SD card root.")
            info("Upload a DuckyScript payload and compile it to inject.bin.")

        inject_bin = mount / "inject.bin"
        if inject_bin.exists():
            ok(f"inject.bin present ({inject_bin.stat().st_size:,} bytes) — device will run this on next plug-in.")
        else:
            warn("inject.bin not found — no payload will execute on plug-in.")

    except Exception as e:
        err(f"List payloads error: {e}")


def op_deploy_payload():
    heading("Deploy DuckyScript Payload")
    info("Copy a DuckyScript (.txt) or pre-compiled inject.bin to the Ducky SD card.")
    info("If you provide a .txt source, it will be compiled to inject.bin first.")
    info("")
    info("Compiler options:")
    info("  Online (recommended): https://payloadstudio.hak5.org/")
    info("  Local Java encoder:   java -jar ducky-encoder.jar -i payload.txt -o inject.bin")
    info("")

    try:
        mount = _find_ducky_mount()
        if not mount:
            err("DUCKY SD card not mounted. Cannot deploy payload.")
            return

        payload_path = prompt("Path to payload file (.txt source or compiled inject.bin)")
        if not payload_path:
            warn("No path provided. Aborting.")
            return

        p = Path(payload_path)
        if not p.exists():
            err(f"File not found: {p}")
            return

        if p.suffix.lower() == ".bin":
            # Pre-compiled inject.bin — copy directly
            dest = mount / "inject.bin"
            if dest.exists() and not confirm(f"Overwrite existing {dest.name}?"):
                info("Cancelled.")
                return
            info(f"Copying {p.name} → {dest}…")
            try:
                shutil.copy2(str(p), str(dest))
                ok(f"inject.bin deployed to {mount}.")
                info("Safely eject and replug the Ducky to execute the payload.")
            except Exception as e:
                err(f"Copy failed: {e}")

        elif p.suffix.lower() in (".txt", ".duck"):
            # DuckyScript source — try local compile, otherwise copy source
            info("DuckyScript source detected. Attempting local compilation…")
            compiled = _compile_duckyscript(p)
            if compiled:
                dest = mount / "inject.bin"
                if dest.exists() and not confirm(f"Overwrite existing {dest.name}?"):
                    info("Cancelled.")
                    return
                shutil.copy2(str(compiled), str(dest))
                ok(f"Compiled and deployed inject.bin to {mount}.")
                info("Safely eject and replug the Ducky to execute the payload.")
            else:
                warn("Local compilation failed. Copying source .txt to SD card.")
                dest_txt = mount / p.name
                shutil.copy2(str(p), str(dest_txt))
                ok(f"Payload source copied to {dest_txt}.")
                info("Compile online at: https://payloadstudio.hak5.org/")
                info("Then copy the resulting inject.bin back to the SD card.")
        else:
            warn(f"Unrecognised file type: {p.suffix}")
            info("Expected .bin (compiled) or .txt/.duck (DuckyScript source).")

    except Exception as e:
        err(f"Deploy payload error: {e}")


def _compile_duckyscript(source: Path) -> Path | None:
    """
    Attempt to compile a DuckyScript .txt file to inject.bin using a local encoder.
    Returns Path to the compiled .bin, or None on failure.
    """
    # Try ducky-encoder (Java)
    encoder_jar = run_output("find /opt /usr/local/share /home -name 'encoder.jar' 2>/dev/null -maxdepth 6 | head -1")
    if encoder_jar and encoder_jar.strip():
        encoder_jar = encoder_jar.strip()
        out_bin = Path(tempfile.mktemp(suffix=".bin"))
        info(f"Found encoder.jar at: {encoder_jar}")
        try:
            rc = run_streaming(
                ["java", "-jar", encoder_jar, "-i", str(source), "-o", str(out_bin)],
                on_line=lambda l: info(f"  encoder: {l}"),
                timeout=30,
            )
            if rc == 0 and out_bin.exists():
                ok("DuckyScript compiled successfully with local encoder.")
                return out_bin
        except Exception as e:
            info(f"  Local encoder error: {e}")

    # Try python-based duckyscript compiler if installed
    try:
        import subprocess as _sp
        result = _sp.run(
            [sys.executable, "-m", "duckyscript", str(source)],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            # Output may be written as inject.bin in CWD
            cwd_bin = Path("inject.bin")
            if cwd_bin.exists():
                ok("DuckyScript compiled via Python duckyscript module.")
                return cwd_bin
    except Exception:
        pass

    info("No local DuckyScript compiler found.")
    info("Compile online at: https://payloadstudio.hak5.org/")
    return None


def op_compile_duckyscript():
    heading("Compile DuckyScript to inject.bin")
    info("Compile a DuckyScript 3.0 payload (.txt) to inject.bin.")
    info("")
    info("Online compiler (no local install needed):")
    info(f"  {PAYLOAD_STUDIO}")
    info("")
    info("Local Java encoder (from hak5.org downloads):")
    info("  java -jar encoder.jar -i payload.txt -o inject.bin -l us")
    info("")
    info("DuckyScript 3.0 new features:")
    info("  DEFINE, IF/ELSE/END_IF, WHILE/END_WHILE, FUNCTION/END_FUNCTION")
    info("  RANDOM_CHAR, RANDOM_LOWERCASE_LETTER, RANDOM_UPPERCASE_LETTER")
    info("  RANDOM_NUMBER, RANDOM_LETTER, RANDOM_SPECIAL")
    info("  SAVE_HOST_KEYBOARD_LOCK_STATE / RESTORE_HOST_KEYBOARD_LOCK_STATE")
    info("  LED_R / LED_G / LED_B for LED feedback")
    info("")

    source_path = prompt("Path to DuckyScript .txt source file")
    if not source_path:
        warn("No path provided. Aborting.")
        return

    p = Path(source_path)
    if not p.exists():
        err(f"File not found: {p}")
        return

    output_path = prompt(
        "Output inject.bin path (default: same dir as source)",
        default=str(p.parent / "inject.bin"),
    )
    out = Path(output_path)

    info(f"Attempting to compile {p.name} → {out.name}…")
    try:
        compiled = _compile_duckyscript(p)
        if compiled:
            shutil.copy2(str(compiled), str(out))
            ok(f"Compiled payload written to: {out}")
            info("Copy inject.bin to the DUCKY SD card root to deploy.")

            mount = _find_ducky_mount()
            if mount and confirm("DUCKY SD card is mounted. Copy inject.bin to SD card now?"):
                dest = mount / "inject.bin"
                shutil.copy2(str(out), str(dest))
                ok(f"inject.bin deployed to {mount}.")
                info("Safely eject and replug the Ducky to execute the payload.")
        else:
            warn("Compilation failed. Use the online compiler:")
            info(f"  {PAYLOAD_STUDIO}")
    except Exception as e:
        err(f"Compilation error: {e}")


def op_format_sd_card():
    heading("Format SD Card (exFAT)")
    warn("WARNING: Formatting will erase ALL data on the DUCKY SD card!")
    warn("All payloads and settings will be lost.")
    info("")
    flavor = get_os_flavor()

    try:
        mount = _find_ducky_mount()
        if not mount:
            err("DUCKY SD card not mounted. Cannot identify device to format.")
            info("Plug in the Rubber Ducky and ensure the SD card mounts first.")
            return

        ok(f"DUCKY SD card found at: {mount}")

        if flavor == "macos":
            info("Use Disk Utility to format on macOS:")
            info("  1. Open Disk Utility (Applications → Utilities → Disk Utility)")
            info("  2. Select the DUCKY volume in the left panel")
            info("  3. Click Erase → Format: ExFAT → Name: DUCKY")
            info("  4. Click Erase to confirm")
            info("")
            info("Or use the command line (replace diskNsN with your disk):")
            info("  diskutil list | grep DUCKY")
            info("  diskutil eraseDisk ExFAT DUCKY /dev/<diskNsN>")
            if confirm("Attempt auto-format via diskutil on macOS?", default=False):
                # Find the underlying disk device
                disk_info = run_output(f"df '{mount}' 2>/dev/null | tail -1 | awk '{{print $1}}'")
                if disk_info and "/dev/" in disk_info:
                    device = disk_info.strip()
                    info(f"Identified device: {device}")
                    if confirm(f"Format {device} as ExFAT named DUCKY? THIS IS DESTRUCTIVE.", default=False):
                        r = run_output(f"diskutil eraseDisk ExFAT DUCKY {device} 2>&1")
                        info(r or "(no output)")
                        ok("Format complete. The SD card is now formatted as ExFAT.")
                    else:
                        info("Format cancelled.")
                else:
                    warn("Could not identify device node. Format manually with Disk Utility.")

        else:
            # Linux
            disk_info = run_output(f"df '{mount}' 2>/dev/null | tail -1 | awk '{{print $1}}'")
            if not disk_info:
                warn("Could not identify device for the mounted volume.")
                info("Find it manually: lsblk | grep DUCKY")
                return
            device = disk_info.strip()
            info(f"Identified device: {device}")
            warn(f"This will format {device} as exFAT and erase all data!")
            if not confirm(f"Format {device} as exFAT (label: DUCKY)?", default=False):
                info("Format cancelled.")
                return
            try:
                ensure_apt_packages(["exfatprogs"])
            except Exception as e:
                warn(f"exfatprogs install warning: {e}")
            try:
                r = sudo_run(f"umount '{mount}' 2>/dev/null")
                r = sudo_run(f"mkfs.exfat -n DUCKY {device} 2>&1")
                if r.returncode == 0:
                    ok(f"SD card formatted as exFAT (label: DUCKY) on {device}.")
                    info("Re-plug the Rubber Ducky to remount the SD card.")
                else:
                    err("Format failed.")
                    info("Try: sudo mkfs.exfat -n DUCKY /dev/<device>")
            except Exception as e:
                err(f"Format error: {e}")

    except Exception as e:
        err(f"SD card format error: {e}")


def op_check_firmware_update():
    heading("Check for Firmware Update")
    info("Checking GitHub for latest USB Rubber Ducky 3 firmware…")
    try:
        latest_tag, release_url = check_latest_github_release(GITHUB_OWNER, GITHUB_REPO)
        if latest_tag:
            ok(f"Latest firmware: {latest_tag}")
            info(f"Download page:  {release_url}")
        else:
            warn("Could not retrieve firmware info from GitHub.")
            info(f"Check manually: https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases")
            return

        mount = _find_ducky_mount()
        current = None
        if mount:
            version_file = mount / "version.txt"
            if version_file.exists():
                raw = version_file.read_text(errors="replace").strip()
                m = re.search(r"v?([\d.]+)", raw)
                if m:
                    current = m.group(1)

        if current:
            result = announce_firmware_update(
                TOOL_NAME, current, latest_tag.lstrip("v"), release_url
            )
            if result:
                op_firmware_update()
        else:
            info("Could not determine current firmware version (SD card not mounted or no version.txt).")
            info(f"Latest available: {latest_tag} — {release_url}")
            if confirm("Proceed to firmware update walkthrough?"):
                op_firmware_update()

    except Exception as e:
        err(f"Firmware check error: {e}")


def op_firmware_update():
    heading("Firmware Update (UF2 drag-and-drop)")
    info("The USB Rubber Ducky 3 uses the RP2040 UF2 bootloader for firmware updates.")
    info("Updates can be semi-automated: we download the UF2 and walk you through it.")
    info("")

    # Step 1: Download the latest UF2
    info("Step 1 — Finding latest firmware release…")
    try:
        latest_tag, release_url = check_latest_github_release(GITHUB_OWNER, GITHUB_REPO)
        if not latest_tag:
            warn("Could not fetch release info from GitHub.")
            info(f"Download manually from: https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases")
            latest_tag = prompt("Enter firmware version tag (e.g. v1.5)", default="")
        else:
            ok(f"Latest release: {latest_tag}")
            info(f"Release page: {release_url}")
    except Exception as e:
        err(f"Release check error: {e}")
        return

    # Step 2: Attempt to download the UF2 file
    uf2_url = (
        f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/download/"
        f"{latest_tag}/ducky.uf2"
    )
    uf2_dest = Path(tempfile.mkdtemp()) / "ducky.uf2"

    info("")
    info(f"Step 2 — Downloading firmware UF2 from:")
    info(f"  {uf2_url}")

    downloaded = False
    try:
        import urllib.request as _urlreq
        info("Downloading…")
        _urlreq.urlretrieve(uf2_url, str(uf2_dest))
        if uf2_dest.exists() and uf2_dest.stat().st_size > 0:
            ok(f"Downloaded: {uf2_dest} ({uf2_dest.stat().st_size:,} bytes)")
            downloaded = True
        else:
            warn("Downloaded file is empty or missing.")
    except Exception as e:
        warn(f"Auto-download failed: {e}")
        info("Download manually from the release page.")
        info(f"  {release_url}")
        manual_path = prompt("Path to manually downloaded ducky.uf2 (or leave blank to abort)")
        if manual_path:
            uf2_dest = Path(manual_path)
            if uf2_dest.exists():
                downloaded = True
            else:
                err(f"File not found: {uf2_dest}")
                return

    if not downloaded:
        info("Cannot proceed without a valid UF2 file.")
        return

    # Step 3: Enter bootloader mode
    info("")
    info("Step 3 — Enter bootloader mode:")
    info("  1. UNPLUG the USB Rubber Ducky from the computer.")
    info("  2. Hold the button on the bottom of the Ducky (or the small tactile switch).")
    info("  3. While holding the button, plug the Ducky back into USB.")
    info("  4. Release the button after 2 seconds.")
    info("  5. The Ducky should appear as 'RPI-RP2' drive.")
    info("")
    pause("Press ENTER after the RPI-RP2 drive appears…")

    # Step 4: Find the RPI-RP2 drive and copy the UF2
    info("Step 4 — Locating RPI-RP2 bootloader volume…")
    boot_mount = _find_rpi_rp2_mount()
    retries = 0
    while boot_mount is None and retries < 5:
        warn("RPI-RP2 not found yet. Waiting 3 seconds…")
        time.sleep(3)
        boot_mount = _find_rpi_rp2_mount()
        retries += 1

    if not boot_mount:
        err("RPI-RP2 bootloader drive not found.")
        info("Troubleshooting:")
        info("  - Unplug, hold button, replug while holding button for 2+ seconds")
        info("  - Check: ls /Volumes/RPI-RP2  (macOS) or lsblk | grep RPI-RP2  (Linux)")
        info(f"  - Manually copy {uf2_dest} to the RPI-RP2 drive when it appears.")
        return

    ok(f"RPI-RP2 bootloader drive found at: {boot_mount}")

    # Step 5: Copy UF2
    info(f"Step 5 — Copying {uf2_dest.name} to {boot_mount}…")
    try:
        dest_uf2 = boot_mount / "ducky.uf2"
        shutil.copy2(str(uf2_dest), str(dest_uf2))
        ok("UF2 firmware file copied to RPI-RP2 drive.")
        info("The Rubber Ducky will automatically reboot and apply the firmware update.")
        info("This takes approximately 10–30 seconds.")
        info("After rebooting, the device will eject the RPI-RP2 volume and return to normal mode.")
        info("")
        info("Verify: plug the Ducky back in and check version.txt on the DUCKY SD card.")
    except Exception as e:
        err(f"Failed to copy UF2: {e}")
        info(f"Copy manually: cp {uf2_dest} {boot_mount}/")


def op_enter_bootloader_mode():
    heading("Enter Bootloader Mode")
    info("Bootloader mode allows drag-and-drop UF2 firmware updates.")
    info("")
    info("How to enter bootloader mode (RPI-RP2):")
    info("  1. Unplug the USB Rubber Ducky from the computer.")
    info("  2. Locate the small button on the Ducky (top or bottom of PCB).")
    info("  3. Press and HOLD the button.")
    info("  4. While holding the button, plug the Ducky back into a USB port.")
    info("  5. Hold the button for 2 full seconds, then release.")
    info("  6. The Ducky should enumerate as a mass storage drive named 'RPI-RP2'.")
    info("")
    info("Expected result:")
    info("  macOS: /Volumes/RPI-RP2 drive appears on Desktop")
    info("  Linux: /media/<user>/RPI-RP2 or /run/media/<user>/RPI-RP2")
    info("  VID:PID: 2E8A:0003 (Raspberry Pi RP2040 Bootloader)")
    info("")
    info("To exit bootloader mode without flashing:")
    info("  Simply unplug and replug the Ducky without holding the button.")
    info("")
    pause("Press ENTER after entering bootloader mode to check for RPI-RP2…")

    boot_mount = _find_rpi_rp2_mount()
    if boot_mount:
        ok(f"RPI-RP2 bootloader drive found at: {boot_mount}")
        ok("Device is in bootloader mode and ready for UF2 firmware update.")
        info("Use 'Check for Firmware Update' (option 6) to flash new firmware.")
    else:
        warn("RPI-RP2 drive not found.")
        info("Check that you held the button while plugging in.")
        info("Linux: check 'lsblk' for a new FAT32 device labelled RPI-RP2.")
        info("macOS: check 'ls /Volumes/' for RPI-RP2.")


# ── Firmware payloads (main-page "FIRMWARE - ..." auto-flash) ─────────────────
# In-the-wild firmwares wired as no-menu payloads. The Ducky 3 is RP2040-based,
# so both firmwares are written by copying a .uf2 onto the RPI-RP2 bootloader
# drive (the module's existing UF2 update flow). Sources:
#   Hak5 Ducky firmware — https://github.com/hak5/usb-rubber-ducky (releases, ducky.uf2)
#   Pico Ducky (alternative) — https://github.com/dbisu/pico-ducky
#       (CircuitPython USB Rubber Ducky; CircuitPython from https://circuitpython.org)

import urllib.request as _urlreq
import zipfile as _zipfile

FW_CIRCUITPY_BOARD = "raspberry_pi_pico"   # generic RP2040 CircuitPython build
PICO_DUCKY_OWNER   = "dbisu"
PICO_DUCKY_REPO    = "pico-ducky"
_FW_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


def _fw_dir() -> Path:
    d = get_firmware_dir("rubber_ducky_3")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _http_get_text(url: str, timeout: int = 20) -> str:
    req = _urlreq.Request(url, headers={"User-Agent": _FW_UA})
    with _urlreq.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _scrape_first(url: str, pattern: str) -> str:
    try:
        html = _http_get_text(url)
    except Exception as e:
        warn(f"  Could not fetch {url}: {e}")
        return ""
    m = re.search(pattern, html)
    return m.group(0) if m else ""


def _fetch_hak5_ducky_uf2():
    """Obtain the Hak5 Ducky UF2 from GitHub releases, else an operator-supplied
    *.uf2 dropped into the firmware dir."""
    fwd = _fw_dir()
    url = get_github_release_asset_url(GITHUB_OWNER, GITHUB_REPO, "", r"\.uf2$")
    if not url:
        tag, _ = check_latest_github_release(GITHUB_OWNER, GITHUB_REPO)
        if tag:
            url = (f"https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases/"
                   f"download/{tag}/ducky.uf2")
    if url:
        dest = fwd / url.rsplit("/", 1)[-1]
        if dest.exists() and dest.stat().st_size > 0:
            ok(f"  Hak5 Ducky UF2 already downloaded: {dest.name}")
            return dest
        if download_firmware(url, dest, "Hak5 Ducky UF2"):
            return dest
    existing = sorted(fwd.glob("*.uf2"))
    if existing:
        ok(f"  Using operator-supplied UF2: {existing[-1].name}")
        return existing[-1]
    return None


def _fetch_circuitpython_uf2():
    page = f"https://circuitpython.org/board/{FW_CIRCUITPY_BOARD}/"
    info(f"  Locating the latest CircuitPython UF2 on {page} …")
    url = _scrape_first(
        page,
        r"https://downloads\.circuitpython\.org/bin/" + re.escape(FW_CIRCUITPY_BOARD)
        + r"/en_US/adafruit-circuitpython-" + re.escape(FW_CIRCUITPY_BOARD)
        + r"-en_US-[0-9.]+\.uf2")
    if not url:
        warn("  No CircuitPython UF2 link found on the board page.")
        return None
    dest = _fw_dir() / url.rsplit("/", 1)[-1]
    if dest.exists() and dest.stat().st_size > 0:
        ok(f"  CircuitPython UF2 already downloaded: {dest.name}")
        return dest
    return dest if download_firmware(url, dest, "CircuitPython UF2") else None


def _fetch_pico_ducky():
    info("  Fetching the pico-ducky payload package (dbisu/pico-ducky, US layout) …")
    url = get_github_release_asset_url(PICO_DUCKY_OWNER, PICO_DUCKY_REPO, "",
                                       r"pico-ducky-.*-US\.zip")
    if not url:
        warn("  Could not resolve a pico-ducky release asset from GitHub.")
        return None
    zip_dest = _fw_dir() / url.rsplit("/", 1)[-1]
    if not (zip_dest.exists() and zip_dest.stat().st_size > 0):
        if not download_firmware(url, zip_dest, "pico-ducky package"):
            return None
    extract_dir = _fw_dir() / "pico-ducky"
    try:
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        with _zipfile.ZipFile(zip_dest) as zf:
            zf.extractall(extract_dir)
    except Exception as e:
        err(f"  Failed to extract pico-ducky package: {e}")
        return None
    for cand in [extract_dir, *extract_dir.rglob("*")]:
        if cand.is_dir() and (cand / "code.py").exists():
            ok(f"  pico-ducky files ready: {cand}")
            return cand
    warn("  Extracted the pico-ducky package but code.py was not found inside.")
    return None


def _copy_uf2_to_bootloader(uf2: Path) -> bool:
    info("  Enter bootloader mode now: unplug, hold the button, replug (RPI-RP2 appears).")
    drive = None
    for _ in range(60):
        drive = _find_rpi_rp2_mount()
        if drive:
            break
        wait_status("  Waiting for the RPI-RP2 bootloader drive…")
        time.sleep(1)
    wait_done()
    if not drive:
        err("  RPI-RP2 bootloader drive did not appear — cannot flash.")
        return False
    ok(f"  RPI-RP2 drive: {drive}")
    try:
        shutil.copy2(str(uf2), str(drive / uf2.name))
    except Exception as e:
        err(f"  Copy to RPI-RP2 failed: {e}")
        return False
    ok(f"  Copied {uf2.name} → {drive} — the Ducky will reboot into the new firmware.")
    return True


def _find_circuitpy_drive():
    flavor = get_os_flavor()
    if flavor == "macos":
        p = Path("/Volumes/CIRCUITPY")
        return p if p.is_dir() else None
    user = os.environ.get("USER", "")
    for base in [Path(f"/media/{user}"), Path(f"/run/media/{user}"), Path("/media")]:
        c = base / "CIRCUITPY"
        if c.is_dir():
            return c
    return None


def _fw_device_info():
    heading("Device Info")
    info(f"Board : {TOOL_NAME} (RP2040)")
    mount = _find_ducky_mount()
    boot = _find_rpi_rp2_mount()
    if boot:
        info(f"Mode  : bootloader (RPI-RP2 at {boot}) — ready for UF2 flashing")
    elif mount:
        info(f"Mode  : storage (DUCKY SD card at {mount})")
    else:
        info("Mode  : HID / not mounted")


def _prep_hak5_ducky(staged) -> bool:
    uf2 = _fetch_hak5_ducky_uf2()
    if not uf2:
        err("  Could not obtain the Hak5 Ducky UF2 — aborting before the flash.")
        info(f"  Drop a ducky.uf2 into {_fw_dir()} or download from:")
        info(f"    https://github.com/{GITHUB_OWNER}/{GITHUB_REPO}/releases")
        return False
    staged["uf2"] = uf2
    ok(f"  Ready to flash Hak5 Ducky firmware: {Path(uf2).name}")
    return True


def _prep_pico_ducky(staged) -> bool:
    uf2 = _fetch_circuitpython_uf2()
    if not uf2:
        err("  Could not obtain the CircuitPython UF2 (pico-ducky base) — aborting.")
        return False
    pd = _fetch_pico_ducky()
    if not pd:
        err("  Could not obtain the pico-ducky payload set — aborting before the flash.")
        return False
    staged["uf2"] = uf2
    staged["pd_dir"] = pd
    ok("  Ready to flash CircuitPython + copy the pico-ducky files.")
    return True


def _flash_hak5_ducky(staged):
    uf2 = staged.get("uf2")
    if not uf2 or not Path(uf2).exists():
        err("Hak5 Ducky UF2 missing at flash time — aborting.")
        return
    _copy_uf2_to_bootloader(Path(uf2))


def _flash_pico_ducky(staged):
    uf2 = staged.get("uf2")
    pd = staged.get("pd_dir")
    if not uf2 or not Path(uf2).exists() or not pd:
        err("pico-ducky assets missing at flash time — aborting.")
        return
    if not _copy_uf2_to_bootloader(Path(uf2)):
        return
    info("  Waiting for the CIRCUITPY drive to appear after CircuitPython boots…")
    drv = None
    for _ in range(90):
        drv = _find_circuitpy_drive()
        if drv:
            break
        wait_status("  Waiting for CIRCUITPY…")
        time.sleep(1)
    wait_done()
    if not drv:
        err("  CIRCUITPY drive not found — copy the pico-ducky files manually from:")
        info(f"    {pd}")
        return
    ok(f"  CIRCUITPY drive: {drv}")
    for item in Path(pd).iterdir():
        dest = drv / item.name
        try:
            if item.is_dir():
                shutil.copytree(item, dest, dirs_exist_ok=True)
            else:
                shutil.copy2(item, dest)
        except Exception as e:
            warn(f"  Could not copy {item.name}: {e}")
    ok("  pico-ducky files copied to CIRCUITPY — the device now runs as a pico-ducky.")
    info("  Edit payload.dd on the CIRCUITPY drive to set your DuckyScript payload.")


def _dispatch_firmware_payload(fw: dict):
    """Route a selected .qfw firmware payload to the right prepare/flash pair."""
    fw_name = fw.get("firmware", "")
    label = fw.get("label", f"Flash {fw_name}")
    staged: dict = {}
    if fw_name == "Hak5 Ducky":
        run_firmware_payload(
            label,
            info_fn=_fw_device_info,
            prepare_fn=lambda: _prep_hak5_ducky(staged),
            flash_fn=lambda: _flash_hak5_ducky(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : Hak5 Ducky (hak5/usb-rubber-ducky, ducky.uf2)",
                "Flasher  : copy UF2 to the RPI-RP2 bootloader drive",
            ],
        )
    elif fw_name == "Pico Ducky":
        run_firmware_payload(
            label,
            info_fn=_fw_device_info,
            prepare_fn=lambda: _prep_pico_ducky(staged),
            flash_fn=lambda: _flash_pico_ducky(staged),
            summary_lines=[
                f"Board    : {TOOL_NAME} (RP2040)",
                "Firmware : Pico Ducky (dbisu/pico-ducky, CircuitPython USB Rubber Ducky)",
                "Flasher  : flash CircuitPython UF2, then copy pico-ducky files to CIRCUITPY",
            ],
        )
    else:
        err(f"Unknown firmware payload: {fw_name!r}")
        info("  Supported: Hak5 Ducky, Pico Ducky")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    flavor = get_os_flavor()
    info("USB Rubber Ducky 3 is a standalone USB HID device — minimal host dependencies.")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking Linux utilities…")
        try:
            ensure_apt_packages(["usbutils", "exfatprogs", "dosfstools"])
        except Exception as e:
            warn(f"Package install warning: {e}")
    elif flavor == "macos":
        info("macOS — exFAT support is built-in.")

    info("Checking Python packages…")
    ensure_pip_packages([("requests", "requests")])

    # ── Linux udev rules ──────────────────────────────────────────────────────
    _check_udev_rules()

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    info("Searching for USB Rubber Ducky 3…")
    info("  DUCKY volume (attack mode): /Volumes/DUCKY  or  /media/.../DUCKY")
    info("  Storage VID:PID: 1B4F:9204  |  HID VID:PID: 05AC:8102")
    info("  Bootloader: RPI-RP2 drive (VID:PID 2E8A:0003)")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=300)
    if not found:
        err("USB Rubber Ducky 3 not detected within timeout. Exiting.")
        sys.exit(1)

    mount = _find_ducky_mount()
    rpi_mount = _find_rpi_rp2_mount()

    if mount:
        ok(f"USB Rubber Ducky 3 detected — SD card at: {mount}")
    elif rpi_mount:
        ok(f"USB Rubber Ducky 3 in BOOTLOADER mode — RPI-RP2 at: {rpi_mount}")
        warn("Device is in bootloader mode. Use option 6 to flash firmware.")
    else:
        ok("USB Rubber Ducky 3 detected via USB (SD card not mounted).")

    check_firmware_version(mount)

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Detect Device & Check Firmware Version",
        "List Payloads on SD Card",
        "Deploy DuckyScript Payload (copy to SD card)",
        "Compile DuckyScript to inject.bin",
        "Format SD Card (exFAT)",
        "Check for Firmware Update (GitHub)",
        "Enter Bootloader Mode (instructions + RPI-RP2 check)",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_detect_and_check_version()
        elif choice == 1:
            op_list_payloads()
        elif choice == 2:
            op_deploy_payload()
        elif choice == 3:
            op_compile_duckyscript()
        elif choice == 4:
            op_format_sd_card()
        elif choice == 5:
            op_check_firmware_update()
        elif choice == 6:
            op_enter_bootloader_mode()
        elif choice == 7:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
