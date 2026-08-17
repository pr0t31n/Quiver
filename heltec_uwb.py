#!/usr/bin/env python3
"""
Heltec UWB Sniffer Dongle Tool Manager
Handles device detection, firmware option listing, and firmware flashing for the
Heltec UWB Sniffer Dongle (an OEM re-brand of the Eforthink / Forthink
"UWB Dongle Sniffer" module).

Usage:
    python3 heltec_uwb.py

Board overview:
    The Heltec UWB Sniffer Dongle is a USB-A ultra-wideband packet analyzer.
    RESEARCH NOTE (2026-08): despite the "Heltec UWB" name and the common
    assumption that Heltec UWB gear is DW3000 + ESP32, this specific dongle is an
    OEM re-brand of the Eforthink/Forthink "UWB Dongle Sniffer" module and is
    built around:
        - NXP NCJ29D5 UWB IC (Trimension family, IEEE 802.15.4a/z HRP UWB) with an
          INTEGRATED ARM Cortex-M33 host core (this is the "ARM Cortex-M33" in the
          retail spec — NOT an ESP32 and NOT a Qorvo/Decawave DW3000).
        - FTDI FT4222H USB-to-SPI bridge (VID:PID 0403:601C). The host PC talks to
          the NCJ29D5 over SPI through the FT4222H; on Windows it enumerates as
          "FT4222 A/B" interfaces. It is a libusb/D2XX device, NOT a CDC tty — so
          there is no serial COM port and no esptool/nrfutil/dfu path.

    Because the silicon is neither ESP32 nor DW3000, the esptool recipe that the
    Heltec LoRa32 boards use does NOT apply here. Firmware is an ENCRYPTED .pkg
    that is pushed to the NCJ29D5 through the FT4222H bridge by the vendor's
    "SWUP" (Software Update Program) tool, distributed in the vendor GitHub repo:
        https://github.com/forthink-xyz/forthink_uwb_sniffer_tool
    The repo ships the Sniffer host app (Windows + Linux x86_64/ARM64), the
    firmware .pkg (pkg/) and the SWUP updater. This module clones that repo,
    locates the SWUP updater + the .pkg, verifies the FT4222H is present, and then
    invokes SWUP to perform the write.

    UWB capabilities of the NCJ29D5 (full transceiver silicon → Rx + Tx), though
    the stock sniffer firmware is a PASSIVE capture build (Rx only):
        - IEEE 802.15.4a/z HRP UWB promiscuous packet capture → Wireshark
          (companion: https://github.com/forthink-xyz/uwb-sniffer-wireshark)
        - CCC / FiRa / 802.15.4z frame decode, up to 6.8 Mbps
        - TOF / TDOA positioning research

Firmware sources & flasher (all vendor-supplied; see notes):
    Repo : https://github.com/forthink-xyz/forthink_uwb_sniffer_tool
    pkg/ : encrypted UWB-Dongle-Sniffer firmware .pkg
    SWUP : vendor "Software Update Program" updater (bundled in the repo)
"""

import sys
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os_flavor, run, run_output,
    ensure_apt_packages, ensure_pip_packages, ensure_brew_packages,
    ensure_system_tool, require_sudo, sudo_run,
    web_detect_loop, run_streaming,
    detect_usb_libusb_any, get_firmware_dir,
    selected_firmware_payload, run_firmware_payload,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Heltec UWB Sniffer Dongle"
DESCRIPTION = "NXP NCJ29D5 (Cortex-M33) UWB sniffer via FT4222H USB-SPI bridge — IEEE 802.15.4a/z, CCC/FiRa"

# FTDI FT4222H USB-to-SPI bridge — the dongle's only USB endpoint. libusb device,
# no serial tty. FT4222H default VID:PID.
VID_PIDS = [
    (0x0403, 0x601C),  # FTDI FT4222H (USB-SPI bridge to the NCJ29D5)
]

# Vendor repo carrying the Sniffer host app, the firmware .pkg and the SWUP updater.
FORTHINK_REPO_URL = "https://github.com/forthink-xyz/forthink_uwb_sniffer_tool.git"

CONNECT_INSTRUCTIONS = (
    "Heltec UWB Sniffer Dongle not detected.\n\n"
    "  1. Plug the dongle into a USB-A port.\n"
    "  2. It enumerates as an FTDI FT4222H bridge (VID:PID 0403:601C), NOT a\n"
    "     serial COM/tty port. Verify with:  lsusb | grep 0403:601c\n"
    "  3. Linux: the FT4222H needs libusb access — install a udev rule (below)\n"
    "     or run as root, otherwise the SWUP updater cannot open the device.\n\n"
    "  Board notes:\n"
    "    - NXP NCJ29D5 UWB IC with integrated ARM Cortex-M33 (host core)\n"
    "    - FTDI FT4222H USB-to-SPI bridge (host PC ↔ NCJ29D5 over SPI)\n"
    "    - IEEE 802.15.4a/z HRP UWB, CCC/FiRa, up to 6.8 Mbps\n"
    "    - Passive sniffer firmware captures UWB frames to Wireshark"
)

UDEV_NOTE = (
    "Linux udev rule for the FT4222H bridge (0403:601c):\n"
    "  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"0403\", ATTR{idProduct}==\"601c\", "
    "MODE=\"0666\", GROUP=\"plugdev\"' \\\n"
    "    | sudo tee /etc/udev/rules.d/99-ft4222-uwb.rules\n"
    "  sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "  Also add your user to plugdev: sudo usermod -aG plugdev $USER (then re-login)\n"
    "  NOTE: if the standard ftdi_sio kernel driver claims the device, the SWUP/\n"
    "  D2XX access may fail — the vendor libft4222/D2XX stack expects the raw USB\n"
    "  interface. Consult the repo's doc/ if SWUP cannot open the dongle."
)

FLASH_CLI_NOTE = (
    "The exact SWUP command-line convention is not publicly documented; this\n"
    "module invokes the located updater with the .pkg as its argument. If SWUP\n"
    "reports a usage error, open the repo's doc/ folder for the correct flags and\n"
    "re-run — the firmware source and updater are otherwise correct."
)


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    info("Scanning USB for the FT4222H bridge (VID:PID 0403:601C)…")
    return detect_usb_libusb_any(VID_PIDS)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fw_dir() -> Path:
    d = get_firmware_dir("heltec_uwb")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _user_dir() -> Path:
    d = _fw_dir() / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _repo_dir() -> Path:
    return _fw_dir() / "forthink_uwb_sniffer_tool"


def _clone_or_update_repo() -> Path | None:
    """Idempotently fetch the vendor repo (Sniffer app + firmware .pkg + SWUP).
    Returns the repo path on success, else None."""
    repo = _repo_dir()
    ensure_system_tool(
        "git",
        "Install git via apt: sudo apt install git  (or brew install git)",
        apt_pkg="git",
    )
    if (repo / ".git").exists():
        info(f"  Vendor repo already present — pulling latest into {repo}")
        rc = run_streaming(
            ["git", "-C", str(repo), "pull", "--ff-only"],
            on_line=lambda l: info(l), timeout=180,
        )
        if rc != 0:
            warn("  git pull failed; using the existing checkout as-is.")
        return repo
    info(f"  Cloning {FORTHINK_REPO_URL}")
    info(f"  → {repo}")
    rc = run_streaming(
        ["git", "clone", "--depth", "1", FORTHINK_REPO_URL, str(repo)],
        on_line=lambda l: info(l), timeout=300,
    )
    if rc != 0 or not (repo / ".git").exists():
        err("  Failed to clone the vendor UWB sniffer repo.")
        info(f"  Manual: git clone {FORTHINK_REPO_URL} {repo}")
        return None
    ok("  Vendor repo ready.")
    return repo


def _find_swup_binary(repo: Path) -> tuple[Path | None, bool]:
    """Locate the SWUP (Software Update Program) updater inside the repo.
    Returns (path, is_windows_exe). Prefers a native binary for this OS."""
    flavor = get_os_flavor()
    windows = False
    # Collect anything that looks like the updater.
    candidates = []
    for pat in ("*swup*", "*SWUP*", "*[Uu]pdate*"):
        candidates += list(repo.rglob(pat))
    candidates = [c for c in candidates if c.is_file()]
    if not candidates:
        return None, False

    def _is_exe(p: Path) -> bool:
        import os
        return os.access(p, os.X_OK) or p.suffix.lower() in (".exe", ".bin", ".sh", ".py")

    exes = [c for c in candidates if _is_exe(c)]
    exes = exes or candidates

    # Prefer a native (non-.exe) build on Linux/macOS; on failure fall back to .exe.
    native = [c for c in exes if c.suffix.lower() != ".exe"]
    win = [c for c in exes if c.suffix.lower() == ".exe"]

    if flavor in ("kali", "debian", "ubuntu", "linux", "darwin") and native:
        return native[0], False
    if win:
        return win[0], True
    if native:
        return native[0], False
    return exes[0], exes[0].suffix.lower() == ".exe"


def _find_pkg(search_dirs) -> Path | None:
    """Find a firmware .pkg across the given directories (recursively)."""
    for d in search_dirs:
        d = Path(d)
        if not d.exists():
            continue
        hits = sorted(d.rglob("*.pkg"))
        if hits:
            return hits[-1]
    return None


def _build_swup_cmd(swup: Path, is_windows: bool, pkg: Path) -> list[str]:
    """Build the SWUP invocation. The precise flag set is undocumented (see
    FLASH_CLI_NOTE); we pass the .pkg as the argument and, for a Windows .exe on a
    non-Windows host, wrap with wine."""
    base: list[str]
    if swup.suffix.lower() == ".py":
        base = [sys.executable, str(swup)]
    elif is_windows and get_os_flavor() != "windows":
        # Windows-only updater on Linux/macOS → run under wine if available.
        base = ["wine", str(swup)]
    else:
        base = [str(swup)]
    return base + [str(pkg)]


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Heltec UWB Sniffer Dongle hardware summary:")
    info("  UWB IC     : NXP NCJ29D5 (Trimension, IEEE 802.15.4a/z HRP UWB)")
    info("  Host core  : ARM Cortex-M33 (integrated in the NCJ29D5)")
    info("  USB bridge : FTDI FT4222H (USB-to-SPI, VID:PID 0403:601C)")
    info("  Data path  : USB → FT4222H → SPI → NCJ29D5")
    info("  Throughput : up to 6.8 Mbps UWB; CCC / FiRa / 802.15.4z decode")
    info("")

    info("Enumerating USB (looking for the FT4222H bridge 0403:601c)…")
    if get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        out = run_output("lsusb | grep -i '0403:601c' || true")
        if out and out.strip():
            for line in out.strip().splitlines():
                ok(f"  {line.strip()}")
        else:
            warn("  FT4222H (0403:601c) not shown by lsusb.")
            info("  Check the cable/port and re-run. See udev note below.")
            info(UDEV_NOTE)

    info("")
    info("pyusb device details:")
    try:
        import usb.core  # type: ignore
        dev = usb.core.find(idVendor=0x0403, idProduct=0x601C)
        if dev is not None:
            ok(f"  Found FT4222H  bus={dev.bus} address={dev.address}")
            try:
                info(f"  Manufacturer : {usb.util.get_string(dev, dev.iManufacturer)}")
                info(f"  Product      : {usb.util.get_string(dev, dev.iProduct)}")
            except Exception:
                info("  (string descriptors unavailable without device access)")
        else:
            warn("  pyusb did not find the FT4222H (0403:601c).")
    except ImportError:
        warn("  pyusb not installed — install with: pip install pyusb --break-system-packages")
    except Exception as e:
        warn(f"  pyusb probe failed: {e}")

    ok("Device info complete.")


def op_firmware_options():
    heading("Firmware Options for the Heltec UWB Sniffer Dongle")
    info("Firmware is an ENCRYPTED .pkg pushed to the NCJ29D5 through the FT4222H")
    info("bridge by the vendor SWUP updater. Both ship in the vendor GitHub repo:")
    info(f"  {FORTHINK_REPO_URL}")
    info("")
    info("  [1] UWB Sniffer firmware (stock)")
    info("      Passive IEEE 802.15.4a/z UWB capture → Wireshark. Rx-only build.")
    info("  [2] Custom firmware package (.pkg)")
    info("      Operator-supplied .pkg (e.g. a ranging/FiRa build) flashed via SWUP.")
    info("")
    info("Flash either from the main page's FIRMWARE payloads, or via this menu.")
    info(FLASH_CLI_NOTE)


# ── Firmware payloads (main-page "FIRMWARE - ") ───────────────────────────────

def _prep_common(staged: dict, *, pkg_from_repo: bool) -> bool:
    """Shared PREPARE: ensure FT4222H present, fetch the vendor repo, locate the
    SWUP updater, and locate the .pkg (repo pkg/ for stock, user dir for custom).
    Returns True only when everything needed to flash is in hand."""
    ready = True

    # 1. Device must be attached (we flash over its FT4222H bridge).
    if not detect_usb_libusb_any(VID_PIDS):
        err("  FT4222H bridge (0403:601c) not detected — connect the dongle.")
        info(UDEV_NOTE)
        ready = False

    # 2. pyusb, so the updater (and our probes) can reach the FT4222H.
    ensure_pip_packages([("usb", "pyusb")])

    # 3. Vendor repo (Sniffer app + firmware .pkg + SWUP updater).
    repo = _clone_or_update_repo()
    if not repo:
        err("  Could not obtain the vendor SWUP updater / firmware.")
        return False

    # 4. Locate the SWUP updater.
    swup, is_win = _find_swup_binary(repo)
    if not swup:
        err("  SWUP updater not found inside the vendor repo checkout.")
        info(f"  Inspect {repo} (look under exe/ or tool/) and place the updater there.")
        ready = False
    else:
        ok(f"  SWUP updater located: {swup}")
        if is_win and get_os_flavor() != "windows":
            import shutil as _sh
            if _sh.which("wine"):
                warn("  Updater is a Windows .exe; will run it under wine.")
            else:
                err("  Updater is Windows-only and wine is not installed.")
                info("  Install wine (sudo apt install wine) or run SWUP on Windows.")
                ready = False
        staged["swup"] = swup
        staged["is_win"] = is_win

    # 5. Locate the firmware .pkg.
    if pkg_from_repo:
        pkg = _find_pkg([repo / "pkg", repo])
        if not pkg:
            err("  No firmware .pkg found in the vendor repo (pkg/).")
            info(f"  Check {repo / 'pkg'} — the vendor may distribute it separately.")
            ready = False
        else:
            ok(f"  Stock UWB sniffer firmware ready: {pkg}")
            staged["pkg"] = pkg
    else:
        ud = _user_dir()
        pkg = _find_pkg([ud])
        if not pkg:
            err("  No operator-supplied .pkg found.")
            info(f"  Drop your firmware .pkg into: {ud}")
            ready = False
        else:
            ok(f"  Custom firmware package ready: {pkg}")
            staged["pkg"] = pkg

    return ready


def _flash_swup(staged: dict):
    """FLASH: run the SWUP updater against the staged .pkg over the FT4222H."""
    swup = staged.get("swup")
    pkg = staged.get("pkg")
    if not swup or not pkg or not Path(swup).exists() or not Path(pkg).exists():
        err("SWUP updater or firmware .pkg missing at flash time — aborting.")
        return
    cmd = _build_swup_cmd(Path(swup), bool(staged.get("is_win")), Path(pkg))
    info(f"Running: {' '.join(cmd)}")
    info("  Writing firmware to the NCJ29D5 through the FT4222H SPI bridge.")
    info("  Do NOT unplug the dongle during the update.")
    info(FLASH_CLI_NOTE)
    rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=600)
    if rc == 0:
        ok("SWUP firmware update completed.")
        info("  Re-plug the dongle if it does not re-enumerate on its own.")
    else:
        err(f"SWUP updater exited with code {rc}.")
        info("  Troubleshooting:")
        info("    - Confirm the FT4222H is accessible (udev rule / plugdev / root).")
        info("    - If ftdi_sio has claimed the port, unbind it or use the D2XX stack.")
        info("    - Verify the SWUP argument convention against the repo doc/.")


def _run_sniffer_payload(fw: dict):
    staged: dict = {}
    run_firmware_payload(
        fw.get("label", "Flash UWB Sniffer Firmware (SWUP)"),
        info_fn=op_device_info,
        prepare_fn=lambda: _prep_common(staged, pkg_from_repo=True),
        flash_fn=lambda: _flash_swup(staged),
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            "Firmware : UWB Sniffer (stock, encrypted .pkg from vendor repo)",
            "Silicon  : NXP NCJ29D5 (Cortex-M33) via FT4222H USB-SPI bridge",
            "Flasher  : vendor SWUP updater (forthink_uwb_sniffer_tool)",
        ],
    )


def _run_custom_payload(fw: dict):
    staged: dict = {}
    run_firmware_payload(
        fw.get("label", "Flash Custom Firmware Package (SWUP)"),
        info_fn=op_device_info,
        prepare_fn=lambda: _prep_common(staged, pkg_from_repo=False),
        flash_fn=lambda: _flash_swup(staged),
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            "Firmware : operator-supplied .pkg (drop into the firmware 'user' dir)",
            "Silicon  : NXP NCJ29D5 (Cortex-M33) via FT4222H USB-SPI bridge",
            "Flasher  : vendor SWUP updater (forthink_uwb_sniffer_tool)",
        ],
    )


def _dispatch_firmware_payload(fw: dict):
    name = fw.get("firmware", "")
    if name == "UWBSniffer":
        _run_sniffer_payload(fw)
    elif name == "CustomPkg":
        _run_custom_payload(fw)
    else:
        err(f"Unknown {TOOL_NAME} firmware payload: {name!r}")
        info("  Supported: UWBSniffer, CustomPkg")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    info("Ensuring pyusb for FT4222H (libusb) detection…")
    ensure_pip_packages([("usb", "pyusb")])

    info("Ensuring git for fetching the vendor SWUP updater + firmware…")
    if flavor == "macos":
        ensure_brew_packages(["git"])
    else:
        ensure_apt_packages(["git"])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("This dongle is an Eforthink/Forthink UWB sniffer re-brand:")
    info("  NXP NCJ29D5 (Cortex-M33) UWB IC behind an FTDI FT4222H USB-SPI bridge.")
    info("  Firmware is an encrypted .pkg flashed by the vendor SWUP updater —")
    info("  esptool/nrfutil/dfu-util do NOT apply to this hardware.")
    info("")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err(f"{TOOL_NAME} not detected. Exiting.")
        sys.exit(1)

    ok("Heltec UWB Sniffer Dongle detected (FT4222H bridge present).")

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash UWB Sniffer Firmware (SWUP)",
        "FIRMWARE - Flash Custom Firmware Package (SWUP)",
        "Firmware Options",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Heltec UWB Sniffer Dongle — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            _run_sniffer_payload({})
        elif choice == 2:
            _run_custom_payload({})
        elif choice == 3:
            op_firmware_options()
        elif choice == 4:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
