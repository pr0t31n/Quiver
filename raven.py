#!/usr/bin/env python3
"""
RZUSBSTICK / AVR Raven Tool Manager
Handles device info and KillerBee firmware flashing for the Atmel RZUSBSTICK
(AT86RF230 radio + AT90USB1287 MCU) — the classic KillerBee Zigbee / 802.15.4
sniffer & injector.

USB identity:
  KillerBee application firmware  — VID:PID 03EB:210A  (Atmel RZUSBSTICK app)
  AT90USB1287 Atmel DFU bootloader — VID:PID 03EB:2FFB  (flash mode)

Flashing:
  The AT90USB1287 is flashed over USB DFU with dfu-programmer once the DFU
  bootloader is present.  The KillerBee firmware 'kb-rzusbstick-006.hex' ships
  with DFU + native bootloader support, so subsequent updates are USB-only.

    dfu-programmer at90usb1287 erase
    dfu-programmer at90usb1287 flash kb-rzusbstick-006.hex
    dfu-programmer at90usb1287 reset

  avrdude (with a hardware JTAG/DFU programmer, e.g. AVR Dragon) is the fallback
  when dfu-programmer is unavailable.

  To enter DFU mode: hold the RZUSBSTICK button (HWB) while plugging in / on
  reset so the AT90USB1287 enumerates as the Atmel DFU bootloader (03EB:2FFB).
  A brand-new stick with no DFU bootloader must be primed once with a hardware
  JTAG programmer (avrdude + AVR Dragon) — see the KillerBee firmware README.

Usage:
    python3 raven.py
"""

import sys
import shutil
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    detect_usb_libusb, detect_usb_libusb_any,
    require_sudo, sudo_run, sudo_output,
    ensure_apt_packages, ensure_brew_packages, ensure_pip_packages,
    ensure_system_tool,
    web_detect_loop, run_streaming,
    check_latest_github_release, announce_firmware_update, get_firmware_dir,
    download_firmware, selected_firmware_payload, run_firmware_payload,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "RZUSBSTICK / AVR Raven"
TOOL_ID     = "raven"
DESCRIPTION = "Atmel RZUSBSTICK — KillerBee Zigbee/802.15.4 sniffer & injector"

# KillerBee application firmware (running) VID:PID
VID_APP = 0x03EB
PID_APP = 0x210A
# AT90USB1287 Atmel DFU bootloader (flash mode) VID:PID
VID_DFU = 0x03EB
PID_DFU = 0x2FFB

# dfu-programmer target part name for the AT90USB1287 on the RZUSBSTICK.
DFU_PART = "at90usb1287"

DETECT_VID_PIDS = [(VID_APP, PID_APP), (VID_DFU, PID_DFU)]

CONNECT_INSTRUCTIONS = (
    "RZUSBSTICK / AVR Raven not detected.\n\n"
    "  1. Plug the RZUSBSTICK into a USB-A port.\n"
    "  2. USB identities:\n"
    "       Running KillerBee firmware : VID:PID 03EB:210A\n"
    "       DFU bootloader (flash mode): VID:PID 03EB:2FFB\n\n"
    "  3. To FLASH, put the stick in DFU mode:\n"
    "       Hold the RZUSBSTICK button (HWB) while plugging it in / on reset\n"
    "       so the AT90USB1287 enumerates as the Atmel DFU bootloader.\n"
    "       Verify with: lsusb | grep 03eb\n\n"
    "  4. Linux permissions (raw USB / DFU): add a udev rule or use sudo.\n"
    "       Quick: run this manager with sudo, or add your user to plugdev.\n\n"
    "  5. A brand-new stick with NO DFU bootloader must be primed once with a\n"
    "     hardware JTAG programmer (avrdude + AVR Dragon). After that, all\n"
    "     updates are USB-only via dfu-programmer."
)


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    """Return True if the RZUSBSTICK is present in either app or DFU mode."""
    return detect_usb_libusb_any(DETECT_VID_PIDS)


def _in_dfu_mode() -> bool:
    """Return True if the AT90USB1287 DFU bootloader (03EB:2FFB) is present."""
    return detect_usb_libusb(VID_DFU, PID_DFU)


def _in_app_mode() -> bool:
    """Return True if the KillerBee application firmware (03EB:210A) is present."""
    return detect_usb_libusb(VID_APP, PID_APP)


def _lsusb_atmel() -> str:
    """Run lsusb and return lines that mention Atmel or VID 03eb."""
    try:
        out = run_output("lsusb 2>/dev/null")
        if not out:
            return ""
        lines = [l for l in out.splitlines()
                 if "03eb" in l.lower() or "atmel" in l.lower()]
        return "\n".join(lines)
    except Exception as e:
        warn(f"lsusb query failed: {e}")
        return ""


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    """Show USB device information for the RZUSBSTICK."""
    heading("Device Info")
    info(f"Tool : {TOOL_NAME} -- {DESCRIPTION}")
    info("")
    info("The RZUSBSTICK pairs an AT86RF230 2.4 GHz 802.15.4 radio with an")
    info("AT90USB1287 USB microcontroller.  With KillerBee firmware it becomes a")
    info("Zigbee / 802.15.4 packet sniffer and frame injector.")
    info("")

    if _in_dfu_mode():
        ok("DFU bootloader detected (VID:PID 03EB:2FFB) -- ready to flash.")
    elif _in_app_mode():
        ok("KillerBee application firmware detected (VID:PID 03EB:210A).")
        info("To flash, re-enter DFU mode (hold HWB button while re-plugging).")
    else:
        warn("RZUSBSTICK not visible via VID:PID -- port may have re-enumerated.")

    info("")
    info("Scanning lsusb for Atmel USB devices (VID 03EB)...")
    lines = _lsusb_atmel()
    if lines:
        ok("Atmel devices found via lsusb:")
        for line in lines.splitlines():
            info(f"  {line}")
    else:
        warn("No Atmel devices found in lsusb output (normal on macOS or if lsusb is absent).")

    info("")
    info("Checking for KillerBee tools (zbid, zbstumbler, zbdump)...")
    for tool in ("zbid", "zbstumbler", "zbdump"):
        p = run_output(f"which {tool} 2>/dev/null")
        if p:
            ok(f"  {tool}: {p.strip()}")
        else:
            info(f"  {tool} not found (install KillerBee: pip install killerbee).")

    info("")
    info("Checking for dfu-programmer (firmware flasher)...")
    dfu = shutil.which("dfu-programmer")
    if dfu:
        ok(f"  dfu-programmer: {dfu}")
    else:
        info("  dfu-programmer not found -- installed on demand when flashing.")

    info("")
    ok("Device info complete.")
    pause()


def op_flash_firmware():
    """
    Flash KillerBee firmware to the RZUSBSTICK over USB DFU (dfu-programmer).

    Requires the AT90USB1287 to be in DFU mode (hold the HWB button while
    plugging in). dfu-programmer runs erase -> flash -> reset.
    """
    heading("Flash KillerBee Firmware (USB DFU)")

    # ── Ensure dfu-programmer ──
    info("Checking for dfu-programmer...")
    if not shutil.which("dfu-programmer"):
        flavor = get_os_flavor()
        if flavor in ("kali", "debian", "ubuntu", "linux"):
            info("dfu-programmer not found. Installing via apt...")
            ensure_apt_packages(["dfu-programmer"])
        elif flavor == "macos":
            info("dfu-programmer not found. Installing via brew...")
            ensure_brew_packages(["dfu-programmer"])
    if not shutil.which("dfu-programmer"):
        err("dfu-programmer could not be installed automatically.")
        info("Manual install: sudo apt-get install dfu-programmer  (Linux)")
        info("                brew install dfu-programmer           (macOS)")
        info("Fallback: avrdude with a hardware JTAG programmer (AVR Dragon).")
        pause()
        return
    ok(f"dfu-programmer found: {shutil.which('dfu-programmer')}")

    # ── DFU mode check ──
    info("")
    if not _in_dfu_mode():
        warn("AT90USB1287 DFU bootloader (03EB:2FFB) not detected.")
        info("Put the RZUSBSTICK in DFU mode: hold the HWB button while plugging")
        info("it in (or on reset), then verify with: lsusb | grep 03eb")
        if not confirm("Continue anyway (DFU device might still be present)?", default=False):
            info("Cancelled. Enter DFU mode and try again.")
            pause()
            return
    else:
        ok("DFU bootloader detected -- ready to flash.")

    # ── Firmware source ──
    info("")
    info("KillerBee firmware for the RZUSBSTICK:")
    info("  Repo : https://github.com/riverloopsec/killerbee (firmware/)")
    info("  File : kb-rzusbstick-006.hex (DFU + native bootloader support)")
    info("")
    subdir, url, fname, _label = RAVEN_FW["KillerBee"]
    hexf = _find_raven_hex(subdir)
    if not hexf:
        d = _raven_fw_variant_dir(subdir)
        d.mkdir(parents=True, exist_ok=True)
        dest = d / fname
        info("Downloading KillerBee firmware from riverloopsec/killerbee...")
        if download_firmware(url, dest, "RZUSBSTICK KillerBee") and dest.exists():
            hexf = dest
    if not hexf or not Path(hexf).exists():
        err("KillerBee firmware .hex could not be sourced automatically.")
        info(f"Drop the .hex into: {_raven_fw_variant_dir(subdir)}")
        info("Source: https://github.com/riverloopsec/killerbee/tree/master/firmware")
        pause()
        return
    ok(f"Firmware ready: {hexf}")

    # ── Confirm and flash ──
    info("")
    info(f"Firmware file : {hexf}")
    info(f"Flash target  : dfu-programmer {DFU_PART}")
    info("Sequence      : erase -> flash -> reset")
    warn("This ERASES the AT90USB1287 flash before writing.")
    if not confirm(f"Flash {Path(hexf).name} to the RZUSBSTICK via USB DFU?"):
        info("Cancelled.")
        return

    staged = {"hex": str(hexf)}
    _flash_raven(staged)
    pause()


def op_killerbee_survey():
    """
    Guide the operator through using the RZUSBSTICK as a KillerBee sniffer.

    Requires KillerBee firmware flashed and the KillerBee Python tools installed
    (zbid, zbstumbler, zbdump, zbwireshark).
    """
    heading("KillerBee Survey / Zigbee Sniffing")
    info("Use the RZUSBSTICK as a Zigbee / 802.15.4 sniffer with KillerBee.")
    info("")
    info("PREREQUISITE: KillerBee firmware flashed + KillerBee tools installed.")
    info("  Install: pip install killerbee --break-system-packages")
    info("  Repo   : https://github.com/riverloopsec/killerbee")
    info("")

    info("Checking for KillerBee tools...")
    have_any = False
    for tool in ("zbid", "zbstumbler", "zbdump"):
        p = run_output(f"which {tool} 2>/dev/null")
        if p:
            ok(f"  {tool}: {p.strip()}")
            have_any = True
        else:
            warn(f"  {tool} not found.")
    if not have_any:
        info("")
        info("Install KillerBee first, then re-run this survey.")
        pause()
        return

    info("")
    info("Identify attached KillerBee interfaces:")
    info("  zbid")
    info("")
    info("Scan (stumble) for Zigbee networks across channels 11-26:")
    info("  zbstumbler")
    info("")
    info("Capture 802.15.4 frames on a channel to a pcap:")
    info("  zbdump -c 15 -w /tmp/zigbee-ch15.pcap")
    info("")
    info("Live-view frames in Wireshark:")
    info("  zbwireshark -c 15")
    info("")
    info("Zigbee 2.4 GHz channels: 11-26 (channel 11 = 2405 MHz, 26 = 2480 MHz).")
    pause()


# ── Firmware Version Check ────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking latest KillerBee release on GitHub (firmware ships in-repo)...")
    latest, url = check_latest_github_release("riverloopsec", "killerbee")
    if latest:
        info(f"  Latest KillerBee release: {latest}")
        info(f"  Release URL: {url}")
        info("  RZUSBSTICK firmware: firmware/kb-rzusbstick-006.hex")
    else:
        warn("Could not check GitHub for KillerBee releases (offline / rate-limited).")


# ── Firmware payloads (main-page) ─────────────────────────────────────────────

# firmware key → (subdir, raw download URL, filename, default label).
# Source: riverloopsec/killerbee firmware directory (documented above).
RAVEN_FW = {
    "KillerBee": (
        "killerbee",
        "https://raw.githubusercontent.com/riverloopsec/killerbee/master/"
        "firmware/kb-rzusbstick-006.hex",
        "kb-rzusbstick-006.hex",
        "Flash KillerBee firmware (Zigbee sniffer/injector)",
    ),
}


def _raven_fw_variant_dir(subdir: str) -> Path:
    return get_firmware_dir(TOOL_ID) / subdir


def _find_raven_hex(subdir: str):
    d = _raven_fw_variant_dir(subdir)
    if not d.exists():
        return None
    hexes = sorted(d.glob("*.hex"))
    return hexes[-1] if hexes else None


def _prep_raven_flash(name: str, staged: dict) -> bool:
    """PREPARE step: ensure dfu-programmer is present and the KillerBee firmware
    .hex is downloaded so only the write remains. Returns True only when ready;
    False aborts before the confirm."""
    subdir, url, fname, _label = RAVEN_FW[name]
    ready = True

    # dfu-programmer is cross-platform (apt on Linux, brew on macOS).
    if not shutil.which("dfu-programmer"):
        flavor = get_os_flavor()
        if flavor in ("kali", "debian", "ubuntu", "linux"):
            info("  dfu-programmer not found — installing via apt…")
            ensure_apt_packages(["dfu-programmer"])
        elif flavor == "macos":
            info("  dfu-programmer not found — installing via brew…")
            ensure_brew_packages(["dfu-programmer"])
    if not shutil.which("dfu-programmer"):
        err("  dfu-programmer could not be installed — cannot flash over USB DFU.")
        info("  Manual: sudo apt-get install dfu-programmer  /  brew install dfu-programmer")
        info("  Fallback: avrdude + hardware JTAG programmer (AVR Dragon).")
        ready = False

    # DFU mode is required for the write; warn (do not hard-abort) so the operator
    # can enter DFU mode at the confirm — but flashing will fail if not in DFU.
    if not _in_dfu_mode():
        warn("  AT90USB1287 DFU bootloader (03EB:2FFB) not detected.")
        info("  Enter DFU mode: hold the HWB button while plugging the stick in.")
        info("  Verify: lsusb | grep 03eb")

    hexf = _find_raven_hex(subdir)
    if not hexf:
        d = _raven_fw_variant_dir(subdir)
        d.mkdir(parents=True, exist_ok=True)
        dest = d / fname
        info(f"  Downloading {name} firmware from riverloopsec/killerbee…")
        if download_firmware(url, dest, f"RZUSBSTICK {name}") and dest.exists():
            hexf = dest
    if hexf and Path(hexf).exists():
        ok(f"  Firmware ready: {hexf}")
        staged["hex"] = str(hexf)
    else:
        err(f"  {name} firmware .hex could not be sourced automatically.")
        info(f"  Drop the .hex into: {_raven_fw_variant_dir(subdir)}")
        info("  Source: https://github.com/riverloopsec/killerbee/tree/master/firmware")
        ready = False
    return ready


def _flash_raven(staged: dict):
    """FLASH step: dfu-programmer erase -> flash -> reset, each streamed."""
    hexf = staged.get("hex")
    if not hexf or not Path(hexf).exists():
        err("Firmware .hex missing at flash time — aborting.")
        return

    info("Do NOT unplug the RZUSBSTICK during this operation.")
    info("")

    # 1) erase — some dfu-programmer versions require --force; try plain first.
    erase_cmd = ["dfu-programmer", DFU_PART, "erase"]
    info(f"Running: {' '.join(erase_cmd)}")
    rc = run_streaming(erase_cmd, on_line=lambda l: info(f"  dfu-programmer: {l}"), timeout=120)
    if rc != 0:
        force_cmd = ["dfu-programmer", DFU_PART, "erase", "--force"]
        info(f"Retrying erase with --force: {' '.join(force_cmd)}")
        rc = run_streaming(force_cmd, on_line=lambda l: info(f"  dfu-programmer: {l}"), timeout=120)
        if rc != 0:
            err(f"dfu-programmer erase failed (exit {rc}).")
            info("Troubleshooting:")
            info("  'no device present' -> stick not in DFU mode (hold HWB, re-plug)")
            info("  permission errors   -> run with sudo or add a udev rule")
            return

    # 2) flash
    flash_cmd = ["dfu-programmer", DFU_PART, "flash", str(hexf)]
    info(f"Running: {' '.join(flash_cmd)}")
    rc = run_streaming(flash_cmd, on_line=lambda l: info(f"  dfu-programmer: {l}"), timeout=180)
    if rc != 0:
        err(f"dfu-programmer flash failed (exit {rc}).")
        info("  Verify the .hex is a valid AT90USB1287 image and the stick is in DFU mode.")
        return

    # 3) reset (boot the new firmware)
    reset_cmd = ["dfu-programmer", DFU_PART, "reset"]
    info(f"Running: {' '.join(reset_cmd)}")
    run_streaming(reset_cmd, on_line=lambda l: info(f"  dfu-programmer: {l}"), timeout=60)

    ok("KillerBee firmware flashed successfully!")
    info("Unplug and replug the RZUSBSTICK to boot the new firmware.")
    info("It should enumerate as the KillerBee app (VID:PID 03EB:210A).")
    info("Verify tools: zbid  (lists attached KillerBee interfaces).")


def _dispatch_firmware_payload(fw: dict):
    """Route a selected .qfw firmware payload to the right RZUSBSTICK firmware."""
    name = fw.get("firmware", "")
    if name not in RAVEN_FW:
        err(f"Unknown RZUSBSTICK firmware payload: {name!r}")
        info(f"  Supported: {', '.join(RAVEN_FW)}")
        return
    _subdir, _url, _fname, deflabel = RAVEN_FW[name]
    staged: dict = {}
    run_firmware_payload(
        fw.get("label", deflabel),
        info_fn=None,
        prepare_fn=lambda: _prep_raven_flash(name, staged),
        flash_fn=lambda: _flash_raven(staged),
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            f"Firmware : {name} (riverloopsec/killerbee, kb-rzusbstick-006.hex)",
            f"Flasher  : dfu-programmer {DFU_PART}  (erase -> flash -> reset, USB DFU)",
            "Mode     : requires DFU bootloader (03EB:2FFB) — hold HWB while plugging in",
        ],
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")
    info("")

    info("Checking for pyusb (required for USB VID:PID detection)...")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  Trying apt: apt-get install python3-usb")
        ensure_apt_packages(["python3-usb"])
    info("  Checking pip for pyusb...")
    ensure_pip_packages([("usb", "pyusb")])
    info("")

    info("Checking for dfu-programmer (required for firmware flashing)...")
    if shutil.which("dfu-programmer"):
        ok("  dfu-programmer is installed.")
    else:
        info("  dfu-programmer not found -- installed on demand when flashing.")
        if flavor in ("kali", "debian", "ubuntu", "linux"):
            info("  Manual install now: sudo apt-get install dfu-programmer")
        elif flavor == "macos":
            info("  Manual install now: brew install dfu-programmer")
    info("")

    info("Checking for KillerBee tools (optional, for sniffing/injection)...")
    if run_output("which zbid 2>/dev/null"):
        ok("  KillerBee tools (zbid) are installed.")
    else:
        info("  KillerBee not found (optional).")
        info("  Install: pip install killerbee --break-system-packages")
    info("")

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    info("Scanning for the RZUSBSTICK via VID:PID...")
    info("  Running KillerBee firmware : 03EB:210A")
    info("  DFU bootloader (flash mode): 03EB:2FFB")
    info("")
    info("If the stick is connected but not detected, it may need firmware flashed,")
    info("or you may need to enter DFU mode (hold the HWB button while plugging in).")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("RZUSBSTICK not detected within timeout. Exiting.")
        sys.exit(1)

    if _in_dfu_mode():
        ok("RZUSBSTICK detected in DFU mode (03EB:2FFB).")
    else:
        ok("RZUSBSTICK detected (03EB:210A, KillerBee app firmware).")
    info("")

    check_firmware_version()

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Device Info (USB details, tool check)",
        "FIRMWARE - Flash KillerBee Firmware (USB DFU)",
        "KillerBee Survey / Zigbee Sniffing",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} -- Main Menu", MENU_OPTIONS)

        if choice == 0:
            try:
                op_device_info()
            except Exception as e:
                err(f"Device info error: {e}")

        elif choice == 1:
            try:
                op_flash_firmware()
            except Exception as e:
                err(f"Flash firmware error: {e}")

        elif choice == 2:
            try:
                op_killerbee_survey()
            except Exception as e:
                err(f"KillerBee survey error: {e}")

        elif choice == 3:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
