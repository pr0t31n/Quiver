#!/usr/bin/env python3
"""
Qorvo DWM3000EVB UWB Shield Tool Manager
Handles firmware flashing and info for the Qorvo (Decawave) DWM3000EVB — a
DW3000 Ultra-Wideband (IEEE 802.15.4z HRP UWB) Arduino/ST shield.

    ┌──────────────────────────────────────────────────────────────────────┐
    │  IMPORTANT: The DWM3000EVB has NO onboard microcontroller.            │
    │  It is a DW3000 UWB transceiver breakout driven by a HOST MCU over    │
    │  SPI (Arduino/mikroBUS/Nucleo shield headers). In the Quiver rig the  │
    │  host MCU is the STM32 Nucleo-F429ZI. "Flashing the DWM3000EVB" here  │
    │  therefore means writing the Qorvo DW3000 example firmware (two-way    │
    │  ranging / Nearby-Interaction) to the HOST Nucleo over its onboard    │
    │  ST-Link — exactly the same ST-Link path used by nucleo_f429zi.py.    │
    └──────────────────────────────────────────────────────────────────────┘

Usage:
    python3 dwm3000evb.py

Board overview:
    - Qorvo DW3000 (DW3110) UWB transceiver — IEEE 802.15.4z HRP UWB
    - Channel 5 (6.5 GHz) and Channel 9 (8.0 GHz)
    - Driven over SPI by a host MCU (Nucleo-F429ZI in this rig)
    - No USB / no MCU of its own — the host MCU's ST-Link is the flash path

UWB capabilities of DW3000:
    - Two-Way Ranging (TWR) — precision distance measurement (±10cm typical)
    - TDoA positioning with multiple anchors
    - FiRa protocol — interoperable UWB ranging (Apple U1 / Samsung / NXP)
    - Both transmit and receive (Rx/Tx) UWB frames

Host MCU (Nucleo-F429ZI) ST-Link:
    USB VID:PID 0x0483:0x374B  (ST-Link V2-1: debugger + VCP + MSD composite)

Firmware source:
    The Qorvo DW3000 STM32/Nucleo example firmware ("DW3xxx SDK" two-way-ranging
    example) is distributed behind Qorvo account registration and cannot be
    auto-downloaded without credentials:
        https://www.qorvo.com/products/p/DWM3000EVB
        https://www.qorvo.com/products/d/da007992   (DW3000 software / SDK)
    Prepare therefore (1) optionally downloads from an operator-supplied URL
    (env QUIVER_DWM3000_FW_URL), else (2) uses an operator-supplied image dropped
    into the tool's firmware dir, and verifies st-flash + the image before flashing.
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
    find_serial_port_by_vidpid, detect_usb_libusb,
    ensure_apt_packages, ensure_pip_packages, ensure_system_tool,
    require_sudo, sudo_run,
    web_detect_loop, run_streaming,
    check_latest_github_release, announce_firmware_update,
    get_firmware_dir, selected_firmware_payload, run_firmware_payload,
    download_firmware,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Qorvo DWM3000EVB"
TOOL_ID     = "dwm3000evb"
DESCRIPTION = ("DW3000 UWB shield (no MCU) — flashed via its host Nucleo-F429ZI "
               "ST-Link; IEEE 802.15.4z, FiRa, TWR")

# The DWM3000EVB has no USB of its own. Detection and flashing go through the
# host Nucleo-F429ZI's onboard ST-Link V2-1.
VID_PID_STLINK = [(0x0483, 0x374B), (0x0483, 0x5740)]
VID_STLINK     = 0x0483
PID_STLINK_V21 = 0x374B

# Flash geometry for the STM32F429ZI host MCU application region.
FLASH_ADDR = "0x08000000"

# Operator override knobs (Qorvo firmware is behind a registration wall).
FW_ENV_PATH = "QUIVER_DWM3000_FW"       # explicit path to a prebuilt image
FW_ENV_URL  = "QUIVER_DWM3000_FW_URL"   # direct-download URL (if the operator has one)

QORVO_PRODUCT_URL = "https://www.qorvo.com/products/p/DWM3000EVB"
QORVO_SDK_URL     = "https://www.qorvo.com/products/d/da007992"

CONNECT_INSTRUCTIONS = (
    "Qorvo DWM3000EVB host (Nucleo-F429ZI ST-Link) not detected.\n\n"
    "  The DWM3000EVB is a DW3000 UWB SHIELD with NO onboard MCU. It is flashed\n"
    "  THROUGH its host STM32 Nucleo-F429ZI over the Nucleo's onboard ST-Link.\n\n"
    "  1. Seat the DWM3000EVB on the Nucleo-F429ZI Arduino/shield headers\n"
    "     (DW3000 SPI: SCK/MISO/MOSI/CS + IRQ/RST wired to the Nucleo).\n"
    "  2. Connect the Nucleo via USB to the ST-Link connector (CN1), NOT CN13.\n"
    "  3. Install stlink-tools:  sudo apt install stlink-tools\n"
    "  4. Linux: install ST-Link udev rules (menu option) if access is denied.\n\n"
    "  VID:PID 0483:374B (ST-Link V2-1 on the host Nucleo)"
)

UDEV_RULES_SRC = "/usr/share/stlink/udev/rules.d/49-stlink.rules"
UDEV_RULES_DST = "/etc/udev/rules.d/49-stlink.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_host_stlink() -> bool:
    """Detect the host Nucleo-F429ZI's ST-Link (the DWM3000EVB has no USB)."""
    info("Scanning USB for the host Nucleo ST-Link (VID:PID 0483:374B)…")
    if find_serial_port_by_vidpid(VID_PID_STLINK) is not None:
        return True
    return detect_usb_libusb(VID_STLINK, PID_STLINK_V21)


# ── udev helpers ──────────────────────────────────────────────────────────────

def _install_stlink_udev():
    """Install ST-Link udev rules from the stlink-tools package."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        warn("udev rules only apply on Linux.")
        return
    src, dst = UDEV_RULES_SRC, UDEV_RULES_DST
    if not os.path.exists(src):
        warn(f"ST-Link rules not found at {src}.")
        info("Install stlink-tools first: sudo apt install stlink-tools")
        info("Or create a minimal rule manually:")
        info("  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"0483\", ATTR{idProduct}==\"374b\", "
             "MODE=\"0666\", GROUP=\"plugdev\"' \\")
        info("    | sudo tee /etc/udev/rules.d/49-stlink.rules")
        return
    info(f"Copying {src} → {dst}")
    r = sudo_run(f"cp {src} {dst} && udevadm control --reload-rules && udevadm trigger")
    if r.returncode == 0:
        ok("ST-Link udev rules installed and reloaded.")
        info("If the Nucleo is already connected, unplug and reconnect it.")
    else:
        err("Failed to install udev rules.")
        err((r.stdout + r.stderr).strip()[:300])


def op_install_udev():
    heading("Install ST-Link udev Rules (Linux)")
    info("udev rules let non-root users access the host Nucleo's ST-Link USB device.")
    info("Without them, st-flash / st-info require root (sudo).")
    info(f"Source: {UDEV_RULES_SRC}")
    info(f"Destination: {UDEV_RULES_DST}")
    if not confirm("Install ST-Link udev rules and reload udevadm?", default=True):
        info("Cancelled.")
        return
    _install_stlink_udev()


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Gathering DWM3000EVB + host information.")
    info("")
    info("DWM3000EVB hardware summary:")
    info("  UWB Radio  : Qorvo DW3000 (DW3110) — IEEE 802.15.4z HRP UWB transceiver")
    info("  Host bus   : SPI (SCK/MISO/MOSI/CS + IRQ/RST) from the host MCU")
    info("  Host MCU   : STM32 Nucleo-F429ZI (this rig) — carries + flashes the shield")
    info("  Onboard MCU: NONE — the DWM3000EVB cannot run code by itself")
    info("  Channels   : 5 (6.5 GHz) and 9 (8.0 GHz)")
    info("")
    info("Because the shield has no MCU, all firmware lives on the HOST Nucleo and")
    info("is written over the Nucleo's onboard ST-Link (VID:PID 0483:374B).")
    info("")

    # ST-Link presence
    port = find_serial_port_by_vidpid(VID_PID_STLINK)
    if port:
        ok(f"  Host ST-Link VCP: {port} — VID:PID 0483:374B")
    else:
        warn("  Host ST-Link VCP not enumerated as a serial port.")
        info("    ST-Link may still be present as a raw USB/SWD device.")

    # st-info probe (part of stlink-tools)
    info("")
    info("Probing the ST-Link with 'st-info --probe'…")
    try:
        import subprocess as _sp
        r = _sp.run(["st-info", "--probe"], capture_output=True, text=True, timeout=15)
        out = (r.stdout + r.stderr).strip()
        if out:
            for line in out.splitlines():
                info(f"  {line}")
        else:
            info("  (st-info returned no output)")
    except FileNotFoundError:
        warn("  'st-info' not found. Install stlink-tools: sudo apt install stlink-tools")
    except Exception as e:  # noqa: BLE001
        warn(f"  Could not run 'st-info --probe': {e}")

    # pyserial detail
    if port:
        info("")
        info("USB port details (pyserial):")
        try:
            from serial.tools import list_ports
            for p in list_ports.comports():
                if p.device == port:
                    info(f"  Device      : {p.device}")
                    info(f"  Description : {p.description}")
                    vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                    pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                    info(f"  VID:PID     : {vid}:{pid}")
                    info(f"  Serial No.  : {p.serial_number or 'N/A'}")
        except Exception as e:  # noqa: BLE001
            warn(f"Could not read pyserial port info: {e}")

    ok("Device info gathering complete.")


def _flash_stflash_bin(fw_path: str, address: str = FLASH_ADDR) -> bool:
    """Write a raw .bin to the host Nucleo at *address* via st-flash. Streamed."""
    info(f"Running: st-flash write {fw_path} {address}")
    info("Expected: progress bar showing pages written and verified.")
    rc = run_streaming(
        ["st-flash", "write", fw_path, address],
        on_line=lambda l: info(f"  st-flash: {l}"), timeout=180,
    )
    if rc == 0:
        ok("st-flash write complete — host Nucleo now runs the DWM3000 firmware.")
        return True
    err(f"st-flash exited with code {rc}.")
    info("Troubleshooting:")
    info("  - 'STLINK_SWDCLK_TOO_FAST': retry with lower freq (st-flash --freq=100k …)")
    info("  - 'Target voltage too low': check the Nucleo is USB-powered on CN1")
    info("  - 'Flash locked': run 'st-flash erase' first")
    return False


def _flash_cubeprog(fw_path: str, address: str = FLASH_ADDR) -> bool:
    """Fallback flasher via STM32CubeProgrammer CLI (STM32_Programmer_CLI).

    Used for .hex/.elf images (address is embedded) or when st-flash is absent.
    """
    import shutil as _sh
    exe = _sh.which("STM32_Programmer_CLI")
    if not exe:
        err("STM32_Programmer_CLI not found (install STM32CubeProgrammer).")
        info("  https://www.st.com/en/development-tools/stm32cubeprog.html")
        return False
    is_bin = fw_path.lower().endswith(".bin")
    cmd = [exe, "-c", "port=SWD", "-w", fw_path]
    if is_bin:
        cmd.append(address)
    cmd += ["-v", "-rst"]
    info(f"Running: {' '.join(cmd)}")
    rc = run_streaming(cmd, on_line=lambda l: info(f"  cubeprog: {l}"), timeout=180)
    if rc == 0:
        ok("STM32CubeProgrammer write complete — host Nucleo reset.")
        return True
    err(f"STM32_Programmer_CLI exited with code {rc}.")
    return False


def _flash_dispatch(fw_path: str) -> bool:
    """Pick the right flasher for the image: st-flash for .bin, CubeProgrammer for
    .hex/.elf (or wherever st-flash is unavailable)."""
    import shutil as _sh
    low = fw_path.lower()
    # st-flash writes raw .bin only; .hex/.elf carry their own addresses and need
    # STM32CubeProgrammer.
    if low.endswith(".bin") and _sh.which("st-flash"):
        return _flash_stflash_bin(fw_path, FLASH_ADDR)
    if _sh.which("STM32_Programmer_CLI"):
        return _flash_cubeprog(fw_path, FLASH_ADDR)
    err("No suitable flasher found for this image (checked st-flash + CubeProgrammer).")
    info("  .bin  → install stlink-tools (st-flash)")
    info("  .hex/.elf → install STM32CubeProgrammer (STM32_Programmer_CLI)")
    return False


def op_flash_manual():
    heading("Flash Host Nucleo (DWM3000 firmware)")
    info("Writes DW3000 example firmware to the host Nucleo-F429ZI over ST-Link.")
    info("The DWM3000EVB shield itself has no MCU — this programs the host that")
    info("drives it over SPI.")
    if not ensure_system_tool(
        "st-flash",
        "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    ):
        info("  (.hex/.elf can instead be flashed with STM32CubeProgrammer.)")
    fw_path = prompt("Path to firmware image (.bin/.hex/.elf)")
    if not fw_path:
        warn("No path provided. Aborting.")
        return
    if not Path(fw_path).exists():
        err(f"File not found: {fw_path}")
        return
    if fw_path.lower().endswith(".bin"):
        addr = prompt("Flash start address (hex)", default=FLASH_ADDR)
        _flash_stflash_bin(fw_path, addr)
    else:
        _flash_dispatch(fw_path)


def op_erase_chip():
    heading("Erase Host Nucleo Flash")
    info("Full-chip erase of the host STM32F429ZI via st-flash.")
    if not ensure_system_tool(
        "st-flash", "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    ):
        return
    if not confirm("Erase the entire host Nucleo flash?", default=False):
        info("Erase cancelled.")
        return
    rc = run_streaming(["st-flash", "erase"], on_line=lambda l: info(f"  st-flash: {l}"),
                       timeout=60)
    if rc == 0:
        ok("Chip erase complete.")
    else:
        err(f"Chip erase failed (exit code {rc}).")


# ── Firmware payloads (main-page) ─────────────────────────────────────────────
#
# One firmware option: the Qorvo DW3000 two-way-ranging example. Qorvo's DW3000
# STM32/Nucleo SDK is behind a registration wall, so the image is operator-
# supplied: set QUIVER_DWM3000_FW=/path, or QUIVER_DWM3000_FW_URL for a direct
# download, or drop the image into the tool's firmware dir. prepare_fn aborts
# BEFORE the confirmation if no image / no flasher is present.

_STAGED = {"path": ""}


def _fw_dir() -> Path:
    return get_firmware_dir(TOOL_ID)


def _locate_local_fw(exts) -> str:
    """Env override first, then the newest matching image in the firmware dir."""
    env = os.environ.get(FW_ENV_PATH, "").strip()
    if env and os.path.exists(env) and env.lower().endswith(tuple(exts)):
        return env
    d = _fw_dir()
    if d.exists():
        cands = sorted(p for e in exts for p in d.rglob(f"*{e}"))
        if cands:
            return str(cands[-1])
    return ""


def _prep_ranging_fw() -> bool:
    """PREPARE: ensure a flasher is available and locate/download the DW3000
    ranging firmware. Returns True only when the sole remaining step is the write."""
    exts = (".bin", ".hex", ".elf")
    _fw_dir().mkdir(parents=True, exist_ok=True)

    # 1) Flasher availability. st-flash covers .bin; CubeProgrammer covers all.
    import shutil as _sh
    have_stflash = ensure_system_tool(
        "st-flash", "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    )
    have_cube = _sh.which("STM32_Programmer_CLI") is not None
    if not have_stflash and not have_cube:
        err("  No flasher available. Install stlink-tools (st-flash) or")
        err("  STM32CubeProgrammer (STM32_Programmer_CLI).")
        return False

    # 2) Host ST-Link must be present.
    if not detect_host_stlink():
        err("  Host Nucleo ST-Link (0483:374B) not detected — connect the Nucleo")
        err("  carrying the DWM3000EVB shield over CN1 (ST-Link USB).")
        return False

    # 3) Locate the firmware image; try an operator-supplied URL if configured.
    fw = _locate_local_fw(exts)
    if not fw:
        url = os.environ.get(FW_ENV_URL, "").strip()
        if url:
            # Qorvo firmware normally needs an authenticated session; only a
            # direct operator-supplied URL is attempted here.
            ext = os.path.splitext(url.split("?")[0])[1].lower()
            if ext not in exts:
                ext = ".bin"
            dest = _fw_dir() / f"dwm3000_ranging{ext}"
            info(f"  Attempting download of DW3000 ranging firmware from {FW_ENV_URL}…")
            if download_firmware(url, dest, tool_name=TOOL_NAME) and dest.exists():
                fw = str(dest)
            else:
                err("  Download failed — supply the image locally instead.")
    if not fw:
        err("  No DW3000 ranging firmware found.")
        info("  Qorvo's DW3000 STM32/Nucleo SDK example is behind a registration wall")
        info("  and cannot be auto-downloaded without credentials. Supply it via:")
        info(f"    - env {FW_ENV_PATH}=/path/to/firmware.bin  (or .hex/.elf), or")
        info(f"    - env {FW_ENV_URL}=<direct download URL>, or")
        info(f"    - drop the image into {_fw_dir()}")
        info(f"  Source: {QORVO_PRODUCT_URL}  /  {QORVO_SDK_URL}")
        return False

    # .hex/.elf need CubeProgrammer (st-flash writes raw .bin only).
    if not fw.lower().endswith(".bin") and not have_cube:
        err(f"  Image is {os.path.splitext(fw)[1]} but STM32_Programmer_CLI is not")
        err("  installed. Install STM32CubeProgrammer, or supply a raw .bin image.")
        return False

    ok(f"  Firmware ready: {fw}")
    _STAGED["path"] = fw
    return True


def _flash_ranging_fw():
    fw = _STAGED.get("path")
    if not fw or not Path(fw).exists():
        err("Firmware image missing at flash time — aborting.")
        return
    _flash_dispatch(fw)


def _dispatch_firmware_payload(fw: dict):
    """Route a selected .qfw firmware payload to the flashing method."""
    name = (fw.get("firmware") or "").strip()
    if name in ("Qorvo-Ranging", "qorvo-ranging"):
        run_firmware_payload(
            fw.get("label", "Flash Qorvo DWM3000 Ranging (host Nucleo)"),
            info_fn=op_device_info,
            prepare_fn=_prep_ranging_fw,
            flash_fn=_flash_ranging_fw,
            summary_lines=[
                f"Board    : {TOOL_NAME} (flashed via host Nucleo-F429ZI ST-Link)",
                "Firmware : Qorvo DW3000 two-way-ranging example (operator-supplied)",
                f"Flasher  : st-flash write @ {FLASH_ADDR} (.bin) / STM32CubeProgrammer (.hex/.elf)",
                "Note     : the DWM3000EVB has no MCU — this programs its HOST Nucleo",
            ],
        )
    else:
        err(f"Unknown DWM3000EVB firmware payload: {name!r}")
        info("  Supported: Qorvo-Ranging")


# ── Firmware version check ────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("The DWM3000EVB DW3000 example firmware ships in Qorvo's DW3000 SDK,")
    info("which requires account registration:")
    info(f"  {QORVO_PRODUCT_URL}")
    info(f"  {QORVO_SDK_URL}")
    info("")
    latest, url = check_latest_github_release("Makerfabs", "Makerfabs-ESP32-UWB-DW3000")
    if latest:
        info(f"  Reference DW3000 example repo latest tag: {latest}")
        if url:
            info(f"  {url}")
    info("  (Community DW3000 host examples exist for Arduino; the Nucleo host")
    info("   image used here is operator-supplied.)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    info("Checking and installing required packages…")
    info("APT packages: python3-serial (pyserial), stlink-tools (st-flash, st-info)")
    ensure_apt_packages(["python3-serial", "stlink-tools"])

    ensure_system_tool(
        "st-flash",
        "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    )
    ensure_system_tool(
        "st-info",
        "apt install stlink-tools  (Kali/Debian/Ubuntu)",
        apt_pkg="stlink-tools",
    )

    print_banner(TOOL_NAME, DESCRIPTION)

    info("NOTE: The DWM3000EVB is a DW3000 UWB SHIELD with no onboard MCU. It is")
    info("flashed THROUGH its host STM32 Nucleo-F429ZI over the Nucleo's ST-Link.")
    info("")
    info("UWB (Ultra-Wideband) capabilities of the DW3000:")
    info("  - IEEE 802.15.4z HRP UWB — ranging and positioning (Rx + Tx)")
    info("  - FiRa protocol — interoperable with Apple/Samsung/NXP UWB")
    info("  - TWR (Two-Way Ranging) — precision distance measurement ±10cm")
    info("")

    found = web_detect_loop(detect_host_stlink, TOOL_NAME, CONNECT_INSTRUCTIONS,
                            timeout=1800)
    if not found:
        err("Host Nucleo ST-Link (for DWM3000EVB) not detected. Exiting.")
        sys.exit(1)

    ok("Host Nucleo ST-Link detected — DWM3000EVB shield can be flashed.")

    check_firmware_version()

    # Firmware payload selected on the main page → auto-run (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash Host Nucleo (DWM3000 ranging firmware)",
        "Erase Host Nucleo Flash",
        "Install ST-Link udev Rules (Linux)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Qorvo DWM3000EVB — Main Menu", MENU_OPTIONS)
        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_flash_manual()
        elif choice == 2:
            op_erase_chip()
        elif choice == 3:
            op_install_udev()
        elif choice == 4:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
