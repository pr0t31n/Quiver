#!/usr/bin/env python3
"""
CANable (USB-CAN) Tool Manager
Handles device info and firmware flashing for CANable-class USB-to-CAN
adapters (CANable 1.0 = STM32F042, CANable 2.0 = STM32G431). Covers the
many slcan/gs_usb clones built on the same design — DSD TECH SH-C30G /
SH-C31A, Innomaker USB-CAN, Waveshare USB-CAN-A, Jhoinrch, etc.

Firmware is flashed over the STM32 built-in USB DFU bootloader with
dfu-util. Two interchangeable firmwares are offered:

  candleLight — native gs_usb / SocketCAN interface (appears as a can0
                netdev on Linux; use with `ip link`, can-utils, python-can).
  slcan       — serial-line CAN (appears as /dev/ttyACM*; use with slcand
                / `slcan_attach`, or python-can's slcan backend).

Usage:
    python3 canable.py

Entering DFU mode (required before flashing):
    - CANable 1.0: set the BOOT jumper to the 3.3V/BOOT position, then
      plug in USB (or press RESET while BOOT is held).
    - CANable 2.0 / many clones: double-tap the RESET button quickly after
      plugging in, or short the BOOT0 pad to 3.3V while plugging in.
    In DFU mode the board enumerates as USB 0483:df11 (STM32 BOOTLOADER).
    Verify with: lsusb | grep -i 0483:df11

Linux serial permissions (for slcan builds on /dev/ttyACM*):
    If you get "Permission denied", add your user to the dialout group:
        sudo usermod -aG dialout $USER
    Then log out and back in (or run: newgrp dialout).
    Check with: id   and   ls -la /dev/ttyACM*
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
    ensure_apt_packages, ensure_brew_packages,
    detect_usb_libusb, detect_usb_libusb_any,
    web_detect_loop, run_streaming,
    require_sudo, sudo_run,
    get_firmware_dir, get_github_release_asset_url, check_latest_github_release,
    download_firmware, selected_firmware_payload, run_firmware_payload,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "CANable (USB-CAN)"
DESCRIPTION = "USB-to-CAN adapter (STM32) — gs_usb/SocketCAN or slcan over DFU"

# STM32 built-in DFU bootloader (all CANable revisions share this).
VID_PID_DFU        = [(0x0483, 0xDF11)]
# candleLight (gs_usb) application mode — a libusb device, no serial port.
VID_PID_CANDLELIGHT = [(0x1D50, 0x606F)]
# slcan application mode enumerates as a USB CDC ACM serial port. The exact
# VID:PID varies across the many clones, so slcan app-mode is detected by the
# presence of a /dev/ttyACM* port rather than a fixed ID (see detect_slcan()).

# Firmware sources (community-standard upstreams):
#   candleLight — candle-usb/candleLight_fw releases ship one .bin per board
#                 target (canable, canable2, cantact, …).
#   slcan       — normaldotcom/canable-fw is the original CANable firmware repo
#                 whose releases include an slcan .bin.
# Because CANable 1.0 (STM32F042) and 2.0 (STM32G431) need DIFFERENT binaries,
# the correct image cannot be guessed — the operator selects the board target
# via QUIVER_CANABLE_BOARD (default "canable"), mirroring the Bus Pirate flow.
CANDLELIGHT_OWNER = "candle-usb"
CANDLELIGHT_REPO  = "candleLight_fw"
SLCAN_OWNER       = "normaldotcom"
SLCAN_REPO        = "canable-fw"

# Env overrides: point these at an operator-supplied .bin to skip the download.
CANDLELIGHT_BIN_ENV = "QUIVER_CANABLE_CANDLELIGHT_BIN"
SLCAN_BIN_ENV       = "QUIVER_CANABLE_SLCAN_BIN"
BOARD_ENV           = "QUIVER_CANABLE_BOARD"   # e.g. "canable" (1.0) or "canable2" (2.0)

# dfu-util flash parameters — STM32 internal flash base, leave (reboot) after write.
DFU_VID_PID   = "0483:df11"
DFU_ALT       = "0"
DFU_ADDRESS   = "0x08000000:leave"

# Resolved firmware path chosen by the prepare step, flashed by the flash step.
_CANABLE_FW_PATH = None

CONNECT_INSTRUCTIONS = (
    "CANable (USB-CAN) not detected.\n\n"
    "  1. Connect the CANable adapter via USB\n"
    "  2. Wait for it to enumerate\n\n"
    "  Application mode appears as one of:\n"
    "    candleLight (gs_usb): libusb device 1d50:606f (SocketCAN can0)\n"
    "    slcan               : /dev/ttyACM* CDC serial port\n\n"
    "  DFU (flashing) mode appears as USB 0483:df11 (STM32 BOOTLOADER):\n"
    "    CANable 1.0: set BOOT jumper to BOOT position, then plug in USB\n"
    "    CANable 2.0 / clones: double-tap RESET after plugging in\n\n"
    "  Debug:\n"
    "    Check USB:    lsusb\n"
    "    Check serial: ls -la /dev/ttyACM*   (slcan builds)\n"
    "    Check kernel: dmesg | tail -20"
)


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_dfu() -> bool:
    """True when the board is in STM32 DFU bootloader mode (0483:df11)."""
    return detect_usb_libusb_any(VID_PID_DFU)


def detect_candlelight() -> bool:
    """True when a candleLight (gs_usb) application-mode device is present."""
    return detect_usb_libusb_any(VID_PID_CANDLELIGHT)


def detect_slcan() -> bool:
    """True when an slcan CDC serial port looks present. The clones use many
    different VID:PIDs, so fall back to any /dev/ttyACM* enumeration."""
    if find_serial_port_by_vidpid([(0x1D50, None), (0xAD50, None), (0x16D0, None)]):
        return True
    # Generic fallback: a CDC ACM port exists.
    import glob
    if get_os() == "linux":
        return bool(glob.glob("/dev/ttyACM*"))
    if get_os() == "macos":
        return bool(glob.glob("/dev/tty.usbmodem*"))
    return False


def detect_canable() -> bool:
    """Detected in ANY mode — application (candleLight/slcan) or DFU."""
    return detect_dfu() or detect_candlelight() or detect_slcan()


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Reporting how the CANable currently enumerates on USB.")
    info("This tells you which mode the board is in before flashing.")

    if detect_dfu():
        ok("DFU bootloader detected: USB 0483:df11 (STM32 BOOTLOADER).")
        info("  The board is ready to accept a firmware write with dfu-util.")
    else:
        info("Not in DFU mode.")

    if detect_candlelight():
        ok("candleLight (gs_usb) application firmware detected: USB 1d50:606f.")
        info("  Bring up the interface with:")
        info("    sudo ip link set can0 up type can bitrate 500000")
        info("    candump can0    (from can-utils)")

    port = find_serial_port_by_vidpid([(0x1D50, None), (0xAD50, None), (0x16D0, None)])
    if not port:
        import glob
        cands = glob.glob("/dev/ttyACM*") if get_os() == "linux" else \
                glob.glob("/dev/tty.usbmodem*")
        port = cands[0] if cands else None
    if port:
        ok(f"CDC serial port present (likely slcan): {port}")
        info("  Attach with slcand, e.g.:")
        info(f"    sudo slcand -o -c -s6 {port} can0 && sudo ip link set can0 up")

    # Surface the raw USB line for the operator's records.
    if get_os() == "linux":
        out = run_output("lsusb 2>/dev/null")
        for line in out.splitlines():
            if any(t in line.lower() for t in ("0483:df11", "1d50:606f", "canable", "stm")):
                info(f"  lsusb: {line}")

    if not detect_canable():
        warn("No CANable-class device detected in any mode.")
        info("  Verify: lsusb   and   ls -la /dev/ttyACM*")
        info("  Debug:  dmesg | tail -20")


def _check_dfu_util() -> bool:
    """Ensure dfu-util is installed (apt/brew). Returns True when available."""
    info("Checking dfu-util (STM32 DFU flashing tool)…")
    if ensure_system_tool(
        "dfu-util",
        "sudo apt install dfu-util   /   brew install dfu-util",
        apt_pkg="dfu-util", brew_pkg="dfu-util",
    ):
        ver = run_output("dfu-util --version 2>/dev/null | head -1")
        if ver.strip():
            ok(f"dfu-util available: {ver.strip()}")
        else:
            ok("dfu-util available.")
        return True
    err("dfu-util is required to flash the CANable and is not available.")
    return False


def _wait_for_dfu() -> bool:
    """Instruct the operator to enter DFU mode and wait until 0483:df11 appears.
    Returns True once the DFU device is present, False on timeout."""
    if detect_dfu():
        ok("  CANable already in DFU bootloader mode (0483:df11).")
        return True

    info("  The CANable must be in STM32 DFU bootloader mode before flashing.")
    info("  Enter DFU mode now:")
    info("    CANable 1.0: set the BOOT jumper to BOOT, then re-plug USB.")
    info("    CANable 2.0 / clones: double-tap RESET right after plugging in,")
    info("      or short BOOT0 to 3.3V while plugging in.")
    info("  Verify (should list 0483:df11): lsusb | grep -i df11")

    found = web_detect_loop(
        detect_dfu, "CANable DFU bootloader",
        "Put the CANable into DFU bootloader mode (0483:df11).\n\n"
        "  CANable 1.0: BOOT jumper to BOOT, then re-plug USB.\n"
        "  CANable 2.0 / clones: double-tap RESET after plugging in.\n\n"
        "  It will enumerate as USB 0483:df11 (STM32 BOOTLOADER).",
        timeout=600, interval=3.0,
    )
    if not found:
        err("  DFU bootloader (0483:df11) did not appear — aborting before flash.")
        info("  Troubleshooting: lsusb   /   dmesg | tail -20")
        return False
    ok("  DFU bootloader detected (0483:df11).")
    return True


def _locate_bin(env_var: str, subdir: str) -> Path:
    """Find an operator-supplied .bin (env override, then firmware subdir)."""
    env = os.environ.get(env_var, "").strip()
    if env and Path(env).exists():
        return Path(env)
    fdir = get_firmware_dir("canable") / subdir
    if fdir.exists():
        bins = sorted(fdir.glob("*.bin"))
        if bins:
            return bins[-1]
    return None


def _download_candlelight() -> Path:
    """Obtain a candleLight .bin (operator-supplied, else GitHub release)."""
    existing = _locate_bin(CANDLELIGHT_BIN_ENV, "candlelight")
    if existing:
        ok(f"  candleLight firmware ready (operator-supplied): {existing}")
        return existing

    board = os.environ.get(BOARD_ENV, "canable").strip() or "canable"
    fdir = get_firmware_dir("canable") / "candlelight"
    fdir.mkdir(parents=True, exist_ok=True)

    info(f"  No local candleLight .bin — downloading the '{board}' target from")
    info(f"  {CANDLELIGHT_OWNER}/{CANDLELIGHT_REPO} releases.")
    info(f"  (Set {BOARD_ENV} to change the board target: e.g. canable, canable2.)")
    tag, _ = check_latest_github_release(CANDLELIGHT_OWNER, CANDLELIGHT_REPO)
    url = get_github_release_asset_url(CANDLELIGHT_OWNER, CANDLELIGHT_REPO, tag,
                                       rf"{board}.*\.bin$")
    if not url:
        url = get_github_release_asset_url(CANDLELIGHT_OWNER, CANDLELIGHT_REPO, tag,
                                           rf".*{board}.*\.bin$")
    if not url:
        err(f"  No candleLight .bin matching board '{board}' in release {tag or '(latest)'}.")
        info(f"  Check asset names: https://github.com/{CANDLELIGHT_OWNER}/{CANDLELIGHT_REPO}/releases")
        info(f"  Or drop the correct .bin in {fdir} (or set {CANDLELIGHT_BIN_ENV}=/path/to.bin).")
        return None

    dest = fdir / url.rsplit("/", 1)[-1]
    if download_firmware(url, dest, tool_name="CANable candleLight firmware"):
        ok(f"  candleLight firmware ready (downloaded): {dest}")
        return dest
    err("  candleLight firmware download failed — see output above.")
    return None


def _download_slcan() -> Path:
    """Obtain an slcan .bin (operator-supplied, else GitHub release)."""
    existing = _locate_bin(SLCAN_BIN_ENV, "slcan")
    if existing:
        ok(f"  slcan firmware ready (operator-supplied): {existing}")
        return existing

    fdir = get_firmware_dir("canable") / "slcan"
    fdir.mkdir(parents=True, exist_ok=True)

    info(f"  No local slcan .bin — downloading from")
    info(f"  {SLCAN_OWNER}/{SLCAN_REPO} releases.")
    tag, _ = check_latest_github_release(SLCAN_OWNER, SLCAN_REPO)
    url = get_github_release_asset_url(SLCAN_OWNER, SLCAN_REPO, tag, r"slcan.*\.bin$")
    if not url:
        url = get_github_release_asset_url(SLCAN_OWNER, SLCAN_REPO, tag, r".*slcan.*\.bin$")
    if not url:
        err(f"  No slcan .bin found in release {tag or '(latest)'}.")
        info(f"  Check asset names: https://github.com/{SLCAN_OWNER}/{SLCAN_REPO}/releases")
        info(f"  Or drop the correct .bin in {fdir} (or set {SLCAN_BIN_ENV}=/path/to.bin).")
        return None

    dest = fdir / url.rsplit("/", 1)[-1]
    if download_firmware(url, dest, tool_name="CANable slcan firmware"):
        ok(f"  slcan firmware ready (downloaded): {dest}")
        return dest
    err("  slcan firmware download failed — see output above.")
    return None


def _prep_canable_firmware(kind: str) -> bool:
    """Firmware-payload PREPARE: install dfu-util, obtain the requested .bin, and
    verify the board is in DFU mode. Returns True only when the write is the only
    step left. kind is 'candlelight' or 'slcan'."""
    global _CANABLE_FW_PATH

    if not _check_dfu_util():
        return False

    if kind == "slcan":
        binpath = _download_slcan()
    else:
        binpath = _download_candlelight()
    if not binpath:
        return False
    _CANABLE_FW_PATH = binpath

    # The board must be in DFU mode for dfu-util to write it — confirm now so we
    # abort BEFORE the "are you sure?" gate on a board that isn't ready.
    if not _wait_for_dfu():
        return False

    ok(f"  Ready to flash: {binpath.name}")
    return True


def _flash_canable_firmware():
    """Firmware-payload FLASH: everything is prepped — write the .bin via dfu-util.
    Command: dfu-util -d 0483:df11 -a 0 -R -s 0x08000000:leave -D <fw.bin>"""
    if not _CANABLE_FW_PATH or not Path(_CANABLE_FW_PATH).exists():
        err("Firmware .bin missing at flash time — aborting.")
        return

    if not detect_dfu():
        err("CANable is no longer in DFU mode (0483:df11) — aborting the write.")
        info("  Re-enter DFU mode and retry: lsusb | grep -i df11")
        return

    cmd = ["dfu-util", "-d", DFU_VID_PID, "-a", DFU_ALT,
           "-R", "-s", DFU_ADDRESS, "-D", str(_CANABLE_FW_PATH)]
    info("Flashing with dfu-util:")
    info("  " + " ".join(cmd))
    rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=300)
    if rc == 0:
        ok("Firmware flash completed. The board rebooted into the new firmware.")
        info("  candleLight: it should now appear as SocketCAN (can0 / 1d50:606f).")
        info("  slcan: it should now appear as a /dev/ttyACM* serial port.")
        info("  Re-check with 'Device Info'.")
    else:
        err(f"dfu-util exited with code {rc} — flash may have failed.")
        info("  Troubleshooting:")
        info("    - Ensure the board is still in DFU mode: lsusb | grep -i df11")
        info("    - dfu-util may need root for raw USB access (this tool runs via sudo).")
        info("    - Try a different USB cable/port; some cables are power-only.")


def op_flash_firmware():
    """Interactive firmware flash (menu path). Mirrors the payload flow but lets
    the operator pick the firmware, then runs the same prepare + flash steps."""
    heading("Flash Firmware")
    info("Flash a CANable firmware over the STM32 DFU bootloader with dfu-util.")
    info("  candleLight — native gs_usb / SocketCAN (can0 netdev).")
    info("  slcan       — serial-line CAN (/dev/ttyACM*).")
    choice = numbered_menu("Firmware to flash",
                           ["candleLight (gs_usb / SocketCAN)",
                            "slcan (serial-line CAN)",
                            "Cancel"])
    if choice == 2:
        info("Cancelled.")
        return
    kind = "candlelight" if choice == 0 else "slcan"

    op_device_info()
    if not _prep_canable_firmware(kind):
        err("Preparation failed — not flashing.")
        return
    label = "candleLight" if kind == "candlelight" else "slcan"
    if not confirm(f"Flash {label} firmware to the CANable now? This overwrites the current firmware.",
                   default=False):
        info("Flash cancelled.")
        return
    _flash_canable_firmware()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    # pyserial is used to enumerate slcan CDC ports; pyusb backs libusb detection.
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Ensuring required APT packages: python3-serial, python3-usb, dfu-util")
        info("  python3-serial → enumerate slcan CDC ports; python3-usb → DFU/gs_usb detection.")
        ensure_apt_packages(["python3-serial", "python3-usb", "dfu-util"])
    else:
        ensure_pip_packages([("serial", "pyserial"), ("usb", "pyusb")])
        ensure_system_tool("dfu-util", "brew install dfu-util", brew_pkg="dfu-util")

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Detecting CANable — application mode (candleLight 1d50:606f or slcan")
    info("/dev/ttyACM*) or DFU bootloader (0483:df11)…")
    info("If not found, check: lsusb   and   ls /dev/ttyACM*   and   dmesg | tail -20")

    found = web_detect_loop(detect_canable, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("CANable not detected. Exiting.")
        sys.exit(1)

    ok("CANable detected.")

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        fw_name = (fw.get("firmware", "") or "").lower()
        kind = "slcan" if "slcan" in fw_name else "candlelight"
        pretty = "slcan (serial-line CAN)" if kind == "slcan" else "candleLight (gs_usb / SocketCAN)"
        run_firmware_payload(
            fw.get("label", "Flash CANable firmware (DFU)"),
            info_fn=op_device_info,
            prepare_fn=lambda: _prep_canable_firmware(kind),
            flash_fn=_flash_canable_firmware,
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                f"Firmware : {pretty}",
                "Bootloader: STM32 USB DFU (0483:df11)",
                "Flasher  : dfu-util -d 0483:df11 -a 0 -R -s 0x08000000:leave -D <fw.bin>",
            ],
        )
        return

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash Firmware (candleLight / slcan via DFU)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("CANable (USB-CAN) — Main Menu", MENU_OPTIONS)
        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_flash_firmware()
        elif choice == 2:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
