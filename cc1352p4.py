#!/usr/bin/env python3
"""
TI CC1352P-4 LaunchPad (LAUNCHXL-CC1352P-4) Tool Manager
Handles device detection (onboard XDS110 debugger), Bluetooth 5 / BLE sniffing
via NCC Group Sniffle, Sub-1GHz capture, Sniffle firmware build + flash, pairing
crypto cracking with crackle, and Wireshark extcap integration.

Usage:
    python3 cc1352p4.py

USB VID:PID:
    0x0451:0xBEF3 — TI XDS110 onboard debugger (Application/User UART + Aux CDC)

THE "-4" BOARD VARIANT (READ BEFORE FLASHING):
    The LAUNCHXL-CC1352P-4 carries the CC1352P1F3 silicon. Current Sniffle
    (v1.11+) uses chip-based platform names and has a SINGLE build for this
    chip — PLATFORM=CC1352P1F3 — and ships a prebuilt for it
    (sniffle_cc1352p1_cc2652p1.hex). There is NO separate "-4" build; the old
    PLATFORM=CC1352P_4 token no longer exists. So the normal path is to FLASH
    THE PREBUILT (no TI SDK needed); a from-source build is only for modifying
    Sniffle and additionally requires the TI SimpleLink SDK.

    The "-4" caveat that remains: on this board 2.4 GHz routes through the
    high-power PA path, so after flashing, run a short BLE capture to confirm
    reception. If captures are empty despite nearby BLE traffic, the -4 RF
    routing may need a Sniffle SysConfig adjustment (advanced). Reflashing over
    SWD is always recoverable, so testing the prebuilt first is low-risk.

XDS110 CDC ports:
    The onboard XDS110 exposes TWO CDC serial ports:
      • Application/User UART — this is the port Sniffle talks to (BLE data)
      • Aux Data port         — secondary/auxiliary, NOT used by Sniffle
    On Linux both appear as /dev/ttyACM* (lower ACM index is usually the
    Application/User UART). On macOS they appear as /dev/tty.usbmodem*.

Sniffle reference (NCC Group):
    Repo   : https://github.com/nccgroup/Sniffle
    Build  : cd fw && make PLATFORM=CC1352P1F3
    Capture: python3 python_cli/sniff_receiver.py -s <port> -b 2000000 -o out.pcap
    Extcap : sniffle_extcap  (drop into Wireshark's extcap/ dir)

Linux serial permissions:
    Device appears as /dev/ttyACM* (USB CDC ACM).
    Add user to dialout: sudo usermod -aG dialout $USER (then re-login)
    Check: id  and  ls -la /dev/ttyACM*
    Debug: dmesg | tail -20
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
    web_detect_loop, run_streaming, verify_xds110_identity, flash_ti_uniflash,
    find_mounted_drive,
    check_latest_github_release, announce_firmware_update, get_firmware_dir,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "TI CC1352P-4 LaunchPad"
DESCRIPTION = "LAUNCHXL-CC1352P-4 — BLE (2.4GHz via PA path) + Sub-1GHz sniffer via Sniffle (XDS110)"

VID_PIDS = [
    (0x0451, 0xBEF3),  # TI XDS110 onboard debugger — Application/User UART + Aux CDC
]

BAUD_RATE = 2000000

SNIFFLE_REPO_URL = "https://github.com/nccgroup/Sniffle"
CRACKLE_REPO_URL = "https://github.com/mikeryan/crackle"

CONNECT_INSTRUCTIONS = (
    "TI CC1352P-4 LaunchPad not detected.\n\n"
    "  LAUNCHXL-CC1352P-4 — VID:PID 0451:BEF3 (XDS110 onboard debugger):\n"
    "    1. Connect the LaunchPad via the XDS110 USB port (the micro-USB near\n"
    "       the top of the board, labelled 'XDS110 USB').\n"
    "    2. The onboard XDS110 enumerates as VID:PID 0451:BEF3 and presents\n"
    "       TWO CDC serial ports:\n"
    "         • Application/User UART — used by Sniffle for BLE capture\n"
    "         • Aux Data port         — secondary, not used by Sniffle\n"
    "    3. On Linux both appear as /dev/ttyACM* (lower index = App/User UART).\n"
    "       On macOS both appear as /dev/tty.usbmodem*.\n"
    "    4. If nothing appears: try a different USB port or a data-capable\n"
    "       (not charge-only) micro-USB cable.\n\n"
    "  NOTE — THIS IS THE '-4' VARIANT:\n"
    "    2.4 GHz routes through the high-power PA path. Current Sniffle has a\n"
    "    single CC1352P1F3 build for this silicon (a prebuilt hex is provided) —\n"
    "    flash it, then run a BLE capture to confirm 2.4 GHz reception.\n\n"
    "  Linux permissions:\n"
    "    sudo usermod -aG dialout $USER  (then re-login)\n"
    "    Check: dmesg | tail -20\n"
    "    Check: lsusb | grep -i 0451"
)

UDEV_RULES_CONTENT = (
    '# TI XDS110 (CC1352P-4 LaunchPad) udev rules\n'
    '# XDS110 CDC serial ports (Application/User UART + Aux) — VID:PID 0451:BEF3\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="bef3", '
    'MODE="0666", GROUP="dialout"\n'
    '# XDS110 USB debug interface\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="bef3", '
    'MODE="0666", GROUP="plugdev"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-ti-xds110.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_cc1352p4() -> bool:
    info("Scanning USB for TI CC1352P-4 LaunchPad (XDS110, VID:PID 0451:BEF3)…")
    return find_serial_port_by_vidpid(VID_PIDS) is not None


def _list_xds110_ports() -> list:
    """Return all CDC serial ports belonging to the XDS110 (0451:BEF3)."""
    ports = []
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.vid == 0x0451 and p.pid == 0xBEF3:
                ports.append(p)
    except Exception as e:
        warn(f"Could not enumerate XDS110 CDC ports via pyserial: {e}")
    return ports


def _probe_fw_version() -> dict:
    """Passive, read-only: query the running Sniffle firmware version over the
    XDS110 serial. No flashing, no config changes. Returns a dict:
      {"installed": bool, "version": str|None, "raw": str, "note": str}."""
    out = {"installed": False, "version": None, "raw": "", "note": ""}
    cli = get_firmware_dir("cc1352p4") / "Sniffle" / "python_cli"
    if not cli.exists():
        out["note"] = "Sniffle host tooling not present — run the firmware download first."
        return out
    if str(cli) not in sys.path:
        sys.path.insert(0, str(cli))
    try:
        from sniffle.sniffle_hw import SniffleHW
    except Exception as e:
        out["note"] = f"Sniffle Python package unavailable ({e})."
        return out
    # probe_fw_version() does a blocking desync read that never returns when the
    # board is NOT running Sniffle (its own 0.2s deadline is never re-checked).
    # Run it in a worker thread and hard-cap it, cancelling the read on timeout.
    import threading
    box = {"hw": None}

    def _worker():
        try:
            hw = SniffleHW(None, timeout=0.1)      # auto-detects the XDS110 port
            box["hw"] = hw
            ver = hw.probe_fw_version()
            if ver is not None:
                out["installed"] = True
                out["version"] = f"{ver.major}.{ver.minor}.{ver.revision}"
                out["raw"] = str(ver)
                out["note"] = f"Sniffle detected (API level {ver.api_level})."
            else:
                out["note"] = "Board reachable but not running Sniffle (no response)."
        except Exception as e:
            out["note"] = f"Board not detected / not running Sniffle ({e})."

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(4.0)
    if t.is_alive():
        hw = box.get("hw")
        if hw is not None:
            try: hw.cancel_recv()   # break the blocking read
            except Exception: pass
        t.join(1.0)
        if not out["note"]:
            out["note"] = "No Sniffle response (board likely not flashed) — probe timed out."
    try:
        if box.get("hw") is not None:
            box["hw"].ser.close()
    except Exception:
        pass
    return out


def probe_fw_version_json() -> None:
    """Print the passive probe result as one JSON line (used by the Firmware tab)."""
    import json
    print(json.dumps(_probe_fw_version()))


def _sniffle_dir() -> Path:
    """Location of the cloned Sniffle checkout for this tool."""
    return get_firmware_dir("cc1352p4") / "Sniffle"


def _prebuilt_hex() -> Path:
    """Newest downloaded Sniffle CC1352P1F3 prebuilt hex, or None.

    Fetched into firmware/cc1352p4/prebuilt/<tag>/ by firmware/download.py. The
    CC1352P-4 carries the CC1352P1F3 silicon, so this stock build applies."""
    pdir = get_firmware_dir("cc1352p4") / "prebuilt"
    if not pdir.exists():
        return None
    hexes = sorted(pdir.rglob("sniffle_cc1352p1*.hex"))
    return hexes[-1] if hexes else None


def _download_prebuilt_hex() -> Path:
    """Run the Quiver firmware downloader to fetch the CC1352P1F3 prebuilt hex."""
    dl = Path(__file__).resolve().parent / "firmware" / "download.py"
    if not dl.exists():
        warn(f"Firmware downloader not found at {dl}.")
        return None
    info("Fetching the Sniffle CC1352P1F3 prebuilt hex via the firmware downloader…")
    run_streaming(
        [sys.executable, str(dl), "--tools", "cc1352p4", "--yes"],
        on_line=lambda l: info(f"  download: {l}"),
        timeout=600,
    )
    return _prebuilt_hex()


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for the TI XDS110 on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for TI XDS110 (CC1352P-4)…")
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
        info("Unplug and replug the device to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Tool checks ───────────────────────────────────────────────────────────────

def _check_git():
    """Check for git (needed to clone Sniffle / crackle)."""
    info("Checking git (needed to clone Sniffle and crackle)…")
    if ensure_system_tool("git", "https://git-scm.com/downloads",
                          apt_pkg="git", brew_pkg="git"):
        ok("git found.")
        return True
    warn("git not found — install it before cloning Sniffle tooling.")
    return False


def _check_arm_toolchain():
    """Check for arm-none-eabi-gcc (needed to build Sniffle firmware)."""
    info("Checking arm-none-eabi-gcc (ARM cross-compiler for Sniffle firmware)…")
    path = run_output("which arm-none-eabi-gcc 2>/dev/null || true")
    if path and path.strip():
        ok(f"arm-none-eabi-gcc found: {path.strip()}")
        ver = run_output("arm-none-eabi-gcc --version 2>/dev/null | head -1 || true")
        if ver:
            info(f"  {ver.strip()}")
        return True
    warn("arm-none-eabi-gcc not found.")
    info("  Required to compile Sniffle firmware from source (make PLATFORM=CC1352P1F3).")
    flavor = get_os_flavor()
    if flavor == "macos":
        info("  macOS install: brew install --cask gcc-arm-embedded")
        info("    (or: brew install arm-none-eabi-gcc)")
        if confirm("Attempt to install the ARM toolchain via brew?", default=True):
            ensure_brew_packages(["arm-none-eabi-gcc"])
        if not (run_output("which arm-none-eabi-gcc 2>/dev/null || true") or "").strip():
            info("  If Homebrew itself is missing, run the Quiver installer once —")
            info("  it bootstraps Homebrew and the ARM toolchain:  python3 install.py")
    else:
        info("  Linux install: sudo apt-get install gcc-arm-none-eabi")
        if confirm("Attempt to install gcc-arm-none-eabi via apt?", default=True):
            ensure_apt_packages(["gcc-arm-none-eabi"])
    path2 = run_output("which arm-none-eabi-gcc 2>/dev/null || true")
    return bool(path2 and path2.strip())


def _check_uniflash():
    """Check for a TI flashing tool (UniFlash / dslite). Non-fatal."""
    info("Checking for a TI flash tool (UniFlash 'dslite' / 'uniflash')…")
    for tool in ("dslite", "uniflash", "dslite.sh", "DSLite"):
        path = run_output(f"which {tool} 2>/dev/null || true")
        if path and path.strip():
            ok(f"TI flash tool found: {path.strip()}")
            return tool
    warn("No TI flash tool (uniflash / dslite) found in PATH.")
    info("  TI UniFlash provides the 'dslite' CLI used to flash over XDS110.")
    info("  Download: https://www.ti.com/tool/UNIFLASH")
    info("  After install, add the UniFlash dir (contains 'dslite.sh') to PATH,")
    info("  or use the UniFlash GUI to flash the built .hex over XDS110.")
    return ""


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


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info("Identifying the connected TI CC1352P-4 LaunchPad and its XDS110 ports.")
    info("")
    info("BOARD: LAUNCHXL-CC1352P-4 (the '-4' variant)")
    info("  RF NOTE: 2.4 GHz is routed through the high-power PA antenna port,")
    info("  NOT the default 2.4 GHz path used by CC1352P1 / P-2 boards. Sniffle")
    info("  firmware MUST be built with PLATFORM=CC1352P1F3 or BLE reception fails.")
    info("")
    info("XDS110 onboard debugger — VID:PID 0451:BEF3")
    info("  Presents two CDC serial ports:")
    info("    • Application/User UART — used by Sniffle for BLE/Sub-1GHz capture")
    info("    • Aux Data port         — secondary, not used by Sniffle")
    info("")

    ports = _list_xds110_ports()
    if ports:
        info(f"Enumerated {len(ports)} XDS110 CDC port(s):")
        for i, p in enumerate(ports):
            role = "Application/User UART (likely Sniffle port)" if i == 0 else "Aux / secondary"
            info(f"  [{i}] {p.device}  — {role}")
            info(f"        Description : {p.description}")
            info(f"        Manufacturer: {p.manufacturer or 'N/A'}")
            vid = f"0x{p.vid:04X}" if p.vid else "N/A"
            pid = f"0x{p.pid:04X}" if p.pid else "N/A"
            info(f"        VID:PID     : {vid}:{pid}")
            info(f"        Serial No.  : {p.serial_number or 'N/A'}")
    else:
        warn("No XDS110 CDC ports enumerated — check the USB connection.")

    info("")
    info(f"Resolved primary serial port for Sniffle: {port}")
    info("  If capture fails, try the OTHER XDS110 /dev/ttyACM* port — the")
    info("  Application/User UART is not always the lowest ACM index.")
    ok("Device info complete.")


def op_install_sniffle():
    heading("Install Sniffle Tooling")
    info("Cloning NCC Group Sniffle — the BLE 5 / Sub-1GHz sniffer for TI CC13xx/CC26xx.")
    info("")
    info("Sniffle provides:")
    info("  • fw/               — the firmware source (build for PLATFORM=CC1352P1F3)")
    info("  • python_cli/       — sniff_receiver.py capture host script")
    info("  • sniffle_extcap    — Wireshark extcap integration")
    info("")
    info(f"Repository: {SNIFFLE_REPO_URL}")

    if not _check_git():
        return

    # pyserial is required by Sniffle's python_cli
    info("Ensuring pyserial (required by Sniffle's python_cli host scripts)…")
    ensure_pip_packages([("serial", "pyserial")])

    dest = _sniffle_dir()
    info(f"Target directory: {dest}")
    if dest.exists() and any(dest.iterdir()):
        ok(f"Sniffle already cloned at {dest}.")
        if confirm("Pull the latest changes (git pull)?", default=True):
            r = run(f"git -C {dest} pull --ff-only")
            if r.returncode == 0:
                ok("Sniffle updated to the latest revision.")
            else:
                warn("git pull failed — the local checkout may have local changes.")
                info(f"  Inspect manually: git -C {dest} status")
        return

    dest.parent.mkdir(parents=True, exist_ok=True)
    if not confirm(f"Clone Sniffle into {dest}?", default=True):
        info("Clone cancelled.")
        return

    info(f"Running: git clone {SNIFFLE_REPO_URL} {dest}")
    r = run(f"git clone {SNIFFLE_REPO_URL} {dest}")
    if r.returncode == 0 and dest.exists():
        ok(f"Sniffle cloned to {dest}.")
        info("  Next: build the firmware with 'Build Sniffle firmware (CC1352P1F3)'.")
    else:
        err("git clone failed.")
        info(f"  Manual: git clone {SNIFFLE_REPO_URL} {dest}")


def op_build_firmware():
    heading("Build Sniffle Firmware (PLATFORM=CC1352P1F3)")
    info("Building Sniffle firmware for the CC1352P-4's PA antenna path.")
    info("")
    info("WHY YOU MUST BUILD (do not flash a prebuilt image):")
    info("  The '-4' board routes 2.4 GHz through the high-power PA port. A")
    info("  prebuilt Sniffle hex (built for CC1352P1) listens on the wrong RF")
    info("  front-end and receives NOTHING on 2.4 GHz BLE. Building with")
    info("  PLATFORM=CC1352P1F3 configures the RF frontend for the -4 routing.")
    info("")
    info("BUILD REQUIREMENTS:")
    info("  • arm-none-eabi-gcc         — ARM cross-compiler")
    info("  • TI SimpleLink CC13xx/CC26xx SDK — provides the RF driver / frontend")
    info("      https://www.ti.com/tool/SIMPLELINK-CC13XX-CC26XX-SDK")
    info("  • GNU make")
    info("")
    info("BUILD STEPS (manual reference):")
    info("  cd <Sniffle>/fw")
    info("  make PLATFORM=CC1352P1F3")
    info("  # resulting hex lands under fw/  (e.g. sniffle.hex / PROJECT.hex)")
    info("")

    sniffle = _sniffle_dir()
    if not (sniffle.exists() and any(sniffle.iterdir())):
        err("Sniffle is not cloned yet.")
        info("  Run 'Install Sniffle tooling' first.")
        return
    fw_dir = sniffle / "fw"
    if not fw_dir.exists():
        err(f"Sniffle firmware directory not found: {fw_dir}")
        info("  The checkout may be incomplete — re-run 'Install Sniffle tooling'.")
        return

    have_gcc = _check_arm_toolchain()

    sdk_hint = os.environ.get("SIMPLELINK_SDK", "")
    if sdk_hint:
        info(f"SIMPLELINK_SDK from environment: {sdk_hint}")
    else:
        info("SIMPLELINK_SDK env var not set. Sniffle's Makefile expects the TI")
        info("  SimpleLink CC13xx/CC26xx SDK path. If the build cannot find the")
        info("  SDK, export it, e.g.:")
        info("    export SIMPLELINK_SDK=/opt/ti/simplelink_cc13xx_cc26xx_sdk_x_xx_xx_xx")

    if not have_gcc:
        warn("ARM toolchain missing — skipping the automatic build.")
        info("  Install arm-none-eabi-gcc and the TI SDK, then re-run this option,")
        info(f"  or build manually: cd {fw_dir} && make PLATFORM=CC1352P1F3")
        return

    if not confirm(f"Run 'make PLATFORM=CC1352P1F3' in {fw_dir} now?", default=True):
        info("Build cancelled.")
        info(f"  Manual: cd {fw_dir} && make PLATFORM=CC1352P1F3")
        return

    info(f"Running: make -C {fw_dir} PLATFORM=CC1352P1F3")
    info("  The build takes ~1-2 minutes. Watch for compiler/SDK path errors.")
    rc = run_streaming(
        ["make", "-C", str(fw_dir), "PLATFORM=CC1352P1F3"],
        on_line=lambda l: info(f"  make: {l}"),
        timeout=600,
    )
    if rc == 0:
        ok("Sniffle firmware built for PLATFORM=CC1352P1F3.")
        hexes = list(fw_dir.rglob("*.hex"))
        if hexes:
            info("  Built hex file(s):")
            for h in hexes:
                info(f"    {h}")
        info("  Next: flash it with 'Flash Sniffle firmware'.")
    else:
        err("Sniffle firmware build failed.")
        info("Troubleshooting:")
        info("  - Ensure the TI SimpleLink CC13xx/CC26xx SDK is installed and its")
        info("    path is set (SIMPLELINK_SDK or the Makefile's SDK variable).")
        info("  - Ensure arm-none-eabi-gcc is on PATH: arm-none-eabi-gcc --version")
        info("  - Read Sniffle's fw/README for the exact SDK version required.")
        info(f"  - Retry manually: cd {fw_dir} && make PLATFORM=CC1352P1F3")


def op_flash_firmware():
    heading("Flash Sniffle Firmware (over XDS110)")

    # ── Guard: confirm this XDS110 is the CC1352P-4, not the CC26X2R1 ─────────
    # (both share USB 0451:BEF3 — refuse/confirm before touching flash).
    if not verify_xds110_identity("cc1352p4"):
        return

    # ── Step 0: passive check — is the board already running Sniffle? ──────────
    info("Checking what firmware is currently on the board (read-only)…")
    cur = _probe_fw_version()
    if cur.get("installed"):
        ok(f"Board is ALREADY running Sniffle {cur['version']} ({cur.get('raw','')}).")
        info("  No need to flash unless you are changing versions.")
        if not confirm("Re-flash anyway?", default=False):
            info("Skipping flash — the board already has Sniffle firmware.")
            return
    elif cur.get("note"):
        info(f"  {cur['note']}")

    # ── Step 1: locate a hex — prefer the prebuilt (no TI SDK needed) ─────────
    # The CC1352P-4 carries the CC1352P1F3 silicon; current Sniffle has a single
    # build for it (there is NO separate "-4" build) and ships a prebuilt hex, so
    # flashing needs no from-source build. A source build is only for modifying
    # Sniffle. If 2.4 GHz capture is weak on your -4, see the note after flashing.
    info("")
    default_hex = ""
    prebuilt = _prebuilt_hex()
    if prebuilt:
        ok(f"Prebuilt Sniffle firmware ready: {prebuilt}")
        default_hex = str(prebuilt)
    else:
        # Fall back to a locally-built hex if one exists.
        fw_dir = _sniffle_dir() / "fw"
        built = sorted(fw_dir.rglob("*.hex")) if fw_dir.exists() else []
        if built:
            info(f"Using locally-built hex: {built[0]}")
            default_hex = str(built[0])
        else:
            warn("No Sniffle hex found (no prebuilt downloaded, none built).")
            if confirm("Download the Sniffle CC1352P1F3 prebuilt now?", default=True):
                prebuilt = _download_prebuilt_hex()
                if prebuilt:
                    ok(f"Downloaded: {prebuilt}")
                    default_hex = str(prebuilt)
            if not default_hex:
                info("  Or build from source (Menu → 'Build Sniffle firmware') — that")
                info("  path needs the TI SimpleLink SDK and is only for modifying Sniffle.")
                info(f"  Manual prebuilt: {SNIFFLE_REPO_URL}/releases  (sniffle_cc1352p1_cc2652p1.hex)")

    hex_path = prompt("Path to the Sniffle .hex to flash", default=default_hex)
    if not hex_path:
        warn("No firmware path provided. Aborting.")
        return
    hex_file = Path(hex_path)
    if not hex_file.exists():
        err(f"File not found: {hex_file}")
        info("  Build it first via 'Build Sniffle firmware (CC1352P1F3)'.")
        return

    if not confirm(f"Flash {hex_file.name} to the CC1352P-4 via XDS110?", default=True):
        info("Flash cancelled.")
        return

    # ── Step 2: flash via TI UniFlash/dslite ──────────────────────────────────
    # OpenOCD CANNOT flash CC13xx/CC26xx over the XDS110 (2-pin cJTAG limitation),
    # so UniFlash's dslite is the flasher. Auto-runs when a .ccxml is available;
    # otherwise guides the UniFlash GUI, which auto-detects and always works.
    result = flash_ti_uniflash(hex_file, device="CC1352P1F3", board_name="CC1352P-4")
    if result:
        info("NOTE (-4 board): this is the stock CC1352P1F3 build. Run a short")
        info("  'BLE Capture' to confirm 2.4 GHz reception. If captures are empty")
        info("  despite nearby BLE traffic, the -4's high-PA RF routing may need a")
        info("  Sniffle SysConfig tweak (advanced); reflashing is always recoverable.")


def op_ble_capture(port: str):
    heading("BLE Capture (Sniffle → pcap)")
    info("Capturing Bluetooth LE traffic with Sniffle and writing a pcap.")
    info("")
    info("PRE-FLIGHT CHECKLIST:")
    info("  • Sniffle firmware built with PLATFORM=CC1352P1F3 and flashed (this board")
    info("    will not receive 2.4 GHz BLE otherwise).")
    info("  • Using the Application/User UART XDS110 port (not the Aux port).")
    info(f"  • Baud rate {BAUD_RATE} (Sniffle default on this firmware).")
    info("")

    sniffle = _sniffle_dir()
    receiver = sniffle / "python_cli" / "sniff_receiver.py"
    if not receiver.exists():
        err(f"Sniffle receiver not found: {receiver}")
        info("  Run 'Install Sniffle tooling' first.")
        return

    ports = _list_xds110_ports()
    if len(ports) > 1:
        info("Multiple XDS110 CDC ports present — Sniffle needs the App/User UART:")
        for i, p in enumerate(ports):
            info(f"  [{i}] {p.device} — {p.description}")
        idx = numbered_menu("Select the Sniffle serial port",
                            [f"{p.device} — {p.description}" for p in ports])
        cap_port = ports[idx].device
    else:
        cap_port = port
    info(f"Using serial port: {cap_port}")

    default_pcap = str(get_firmware_dir("cc1352p4") / f"sniffle_{int(time.time())}.pcap")
    pcap_path = prompt("Output pcap path", default=default_pcap)
    if not pcap_path:
        warn("No output path provided. Aborting.")
        return
    pcap = Path(pcap_path)
    pcap.parent.mkdir(parents=True, exist_ok=True)

    info("")
    info("CAPTURE NOTES:")
    info("  • Sniffle follows connections and hops with the connection by default.")
    info("  • To sniff a specific advertiser, Sniffle supports -m <MAC> (see -h).")
    info("  • Press Ctrl-C to stop the capture; the pcap is finalised on exit.")
    info("")
    if not confirm(f"Start Sniffle capture on {cap_port} → {pcap.name}?", default=True):
        info("Capture cancelled.")
        return

    cmd = [
        sys.executable, str(receiver),
        "-s", cap_port,
        "-b", str(BAUD_RATE),
        "-o", str(pcap),
    ]
    info(f"Running: {' '.join(cmd)}")
    info("  Capturing… press Ctrl-C in the terminal to stop.")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(f"  sniffle: {l}"), timeout=86400)
        if rc == 0:
            ok(f"Capture complete: {pcap}")
        else:
            warn(f"sniff_receiver.py exited with code {rc}.")
        if pcap.exists():
            info(f"  pcap written: {pcap} ({pcap.stat().st_size // 1024} KB)")
            info("  Crack legacy pairing with 'Crack Pairing (crackle)', or open in")
            info("  Wireshark for analysis.")
    except KeyboardInterrupt:
        warn("Capture interrupted by user.")
        if pcap.exists():
            info(f"  Partial pcap written: {pcap}")
    except Exception as e:
        err(f"Capture error: {e}")
        info(f"  Debug: verify the port with dmesg | tail -20 and ls -la {cap_port}")


def op_crack_pairing():
    heading("Crack Pairing (crackle)")
    info("Using crackle to recover the BLE Long Term Key (LTK) from a captured pcap.")
    info("")
    info("SCOPE / LIMITATIONS:")
    info("  • crackle attacks BLE LEGACY pairing only (the LE Legacy key exchange).")
    info("  • It does NOT break LE Secure Connections (ECDH-based) pairing.")
    info("  • The pcap must contain the full pairing exchange (capture from before")
    info("    the two devices pair — start Sniffle first, then pair the devices).")
    info("  • On success crackle can decrypt the encrypted connection and write a")
    info("    decrypted pcap for analysis in Wireshark.")
    info("")

    if not ensure_system_tool("crackle",
                              "git clone https://github.com/mikeryan/crackle && cd crackle && make",
                              apt_pkg="crackle", brew_pkg="crackle"):
        warn("crackle not found and could not be auto-installed.")
        info("  Build from source:")
        info(f"    git clone {CRACKLE_REPO_URL}")
        info("    cd crackle && make")
        info("    sudo cp crackle /usr/local/bin/   (or run ./crackle in place)")
        if confirm("Clone and build crackle now?", default=True):
            dest = get_firmware_dir("cc1352p4") / "crackle"
            dest.parent.mkdir(parents=True, exist_ok=True)
            if not (dest.exists() and any(dest.iterdir())):
                run(f"git clone {CRACKLE_REPO_URL} {dest}")
            r = run(f"make -C {dest}")
            if r.returncode == 0:
                ok(f"crackle built at {dest / 'crackle'}.")
                info(f"  Add to PATH or run directly: {dest / 'crackle'}")
            else:
                err("crackle build failed. Ensure build-essential / make are installed.")
        return

    in_pcap = prompt("Path to the captured .pcap file")
    if not in_pcap:
        warn("No input pcap provided. Aborting.")
        return
    pcap = Path(in_pcap)
    if not pcap.exists():
        err(f"File not found: {pcap}")
        return

    out_default = str(pcap.with_name(pcap.stem + "_decrypted.pcap"))
    out_pcap = prompt("Output (decrypted) pcap path", default=out_default)

    if not confirm(f"Run crackle on {pcap.name}?", default=True):
        info("crackle cancelled.")
        return

    cmd = f"crackle -i {pcap} -o {out_pcap}"
    info(f"Running: {cmd}")
    try:
        r = run(cmd)
        if r.returncode == 0:
            ok("crackle completed.")
            info(f"  Decrypted output: {out_pcap}")
            info("  If crackle reported the LTK/TK, the legacy pairing was cracked.")
        else:
            warn("crackle returned a non-zero exit code.")
            info("Troubleshooting:")
            info("  - The pcap may not contain a complete LEGACY pairing exchange.")
            info("  - LE Secure Connections pairing cannot be cracked by crackle.")
            info("  - Re-capture: start Sniffle BEFORE the devices pair, then pair.")
    except FileNotFoundError:
        err("crackle disappeared from PATH. Reinstall or build from source.")
    except Exception as e:
        err(f"crackle error: {e}")


def op_wireshark_extcap():
    heading("Wireshark extcap Setup")
    info("Installing Sniffle's extcap plugin so 'Sniffle' appears as a live")
    info("capture interface inside Wireshark.")
    info("")
    info("WHAT extcap DOES:")
    info("  Wireshark's extcap mechanism lets external capture tools present")
    info("  themselves as interfaces. Sniffle ships 'sniffle_extcap' which drives")
    info("  the LaunchPad and streams BLE packets straight into Wireshark.")
    info("")

    sniffle = _sniffle_dir()
    extcap_src = None
    for cand in (sniffle / "python_cli" / "sniffle_extcap",
                 sniffle / "sniffle_extcap",
                 sniffle / "python_cli" / "sniffle_extcap.py"):
        if cand.exists():
            extcap_src = cand
            break
    if not extcap_src:
        err("sniffle_extcap not found in the Sniffle checkout.")
        info("  Run 'Install Sniffle tooling' first, then re-run this option.")
        info(f"  Expected under: {sniffle}/python_cli/sniffle_extcap")
        return
    info(f"Found extcap script: {extcap_src}")

    if get_os() == "macos":
        extcap_dir = Path.home() / ".config" / "wireshark" / "extcap"
        info(f"Target extcap dir (macOS): {extcap_dir}")
        info("  (Wireshark also honours the app-bundle extcap dir; the per-user")
        info("   ~/.config/wireshark/extcap/ path is simplest.)")
    else:
        extcap_dir = Path.home() / ".config" / "wireshark" / "extcap"
        info(f"Target extcap dir (Linux): {extcap_dir}")
        info("  System-wide alt: /usr/lib/x86_64-linux-gnu/wireshark/extcap/")

    extcap_dir.mkdir(parents=True, exist_ok=True)
    dest = extcap_dir / extcap_src.name
    if not confirm(f"Copy {extcap_src.name} to {extcap_dir}?", default=True):
        info("extcap setup cancelled.")
        return

    r = run(f"cp {extcap_src} {dest}")
    if r.returncode != 0:
        err("Failed to copy the extcap script.")
        info(f"  Manual: cp {extcap_src} {dest}")
        return
    run(f"chmod +x {dest}")
    ok(f"Sniffle extcap installed: {dest}")
    info("  Made executable (chmod +x).")
    info("")
    info("FINISH SETUP:")
    info("  1. Restart Wireshark (fully quit and reopen so it re-scans extcap/).")
    info("  2. The capture interface list will show 'Sniffle'.")
    info("  3. Click the Sniffle interface gear to set channel / target options.")
    info("  4. Start capture — BLE packets stream live into Wireshark.")
    info("")
    info("  Note: the extcap still needs the CC1352P1F3-built firmware flashed and")
    info("  pyserial installed for the host side to work.")
    pause("Press ENTER to continue.")


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking Sniffle tooling status and latest upstream release…")
    info("  Sniffle firmware carries no queryable on-device version string; the")
    info("  reference point is the cloned Sniffle git revision.")

    sniffle = _sniffle_dir()
    if sniffle.exists() and any(sniffle.iterdir()):
        rev = run_output(f"git -C {sniffle} rev-parse --short HEAD 2>/dev/null")
        if rev:
            info(f"  Local Sniffle revision: {rev.strip()}")
        desc = run_output(f"git -C {sniffle} describe --tags --always 2>/dev/null")
        if desc:
            info(f"  Local Sniffle describe : {desc.strip()}")
    else:
        info("  Sniffle is not cloned yet — use 'Install Sniffle tooling'.")

    info("Checking latest Sniffle release on GitHub…")
    latest, url = check_latest_github_release("nccgroup", "Sniffle")
    if latest:
        info(f"  Latest Sniffle release: {latest}")
        info(f"  Release: {url}")
    else:
        warn("Could not reach GitHub for the Sniffle version check.")


def op_identify_board():
    heading("Identify Board — CC1352P-4 vs CC26X2R1")
    info("Both LaunchPads present as XDS110 (USB 0451:BEF3) and can only be told")
    info("apart by the debug probe's serial number. Confirm the physical board")
    info("once and Quiver pins it, so autodetect and flashing are unambiguous.")
    info("")
    if verify_xds110_identity("cc1352p4"):
        ok("This debug probe is confirmed as the CC1352P-4.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial (USB CDC + Sniffle host scripts)
    info("Ensuring pyserial for USB CDC serial communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    # requests for GitHub API version checks
    info("Ensuring requests library for version checks…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Checking udev rules for TI XDS110 USB access…")
    _check_udev_rules()

    info("Checking git (for cloning Sniffle / crackle)…")
    _check_git()

    info("Detecting TI CC1352P-4 LaunchPad via USB VID:PID 0451:BEF3…")
    info("  XDS110 onboard debugger presents two CDC ports (App/User UART + Aux).")
    info("  REMINDER: this '-4' board needs Sniffle built with PLATFORM=CC1352P1F3")
    info("  or 2.4 GHz BLE reception will not work (PA antenna path routing).")

    found = web_detect_loop(detect_cc1352p4, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("TI CC1352P-4 LaunchPad not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"CC1352P-4 LaunchPad detected on {port}")
    info("  (This is the XDS110 Application/User UART — the port Sniffle uses.)")
    check_firmware_version()

    _check_dialout(port)

    MENU_OPTIONS = [
        "Device Info",
        "Install Sniffle tooling",
        "Build Sniffle firmware (CC1352P1F3)",
        "Flash Sniffle firmware",
        "BLE Capture (Sniffle → pcap)",
        "Crack Pairing (crackle)",
        "Wireshark extcap setup",
        "Identify this board (CC1352P-4 vs CC26X2R1)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("TI CC1352P-4 LaunchPad — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_install_sniffle()
        elif choice == 2:
            op_build_firmware()
        elif choice == 3:
            op_flash_firmware()
        elif choice == 4:
            op_ble_capture(port)
        elif choice == 5:
            op_crack_pairing()
        elif choice == 6:
            op_wireshark_extcap()
        elif choice == 7:
            op_identify_board()
        elif choice == 8:
            info("Goodbye.")
            break

        # Re-check port after operations (XDS110 may re-enumerate after flashing)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    if "--probe-fw-version" in sys.argv:
        probe_fw_version_json()
        sys.exit(0)
    main()
