#!/usr/bin/env python3
"""
TI CC26X2R1 LaunchPad Tool Manager
Handles device detection (onboard XDS110 debug probe), Bluetooth 5 / BLE
sniffing via NCC Group's Sniffle firmware, Sniffle tooling install, firmware
flashing (UniFlash/dslite or the ROM serial bootloader), pcap capture, and
BLE legacy pairing decryption via crackle.

Usage:
    python3 cc26x2r1.py

USB VID:PIDs:
    0x0451:0xBEF3 — TI XDS110 onboard debug probe (exposes TWO CDC serial ports)

Device notes:
    LAUNCHXL-CC26X2R1 — SimpleLink CC26x2R1 wireless MCU LaunchPad.
    The onboard XDS110 debug probe enumerates as a composite USB device that
    exposes TWO CDC ACM serial ports:
        Port 1 — XDS110 Class Application/User UART   (Sniffle uses THIS port)
        Port 2 — XDS110 Class Auxiliary Data Port     (aux data / not used)
    On Linux both appear as /dev/ttyACM* — the LOWER-numbered one is normally
    the Application/User UART. Confirm with 'Device Info'.

Sniffle (NCC Group):
    Open-source BLE 4.x / Bluetooth 5 sniffer firmware + host tooling for the
    TI CC13xx / CC26xx family.
    Repo: https://github.com/nccgroup/Sniffle
    The python_cli/ dir contains sniff_receiver.py (capture) and the Wireshark
    extcap plugin (sniffle_extcap). Sniffle runs the UART at 2 Mbaud.

Linux serial permissions:
    Devices appear as /dev/ttyACM* (USB CDC ACM).
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
    find_serial_port_by_vidpid, ensure_pip_packages,
    require_sudo, sudo_run,
    ensure_apt_packages,
    web_detect_loop, run_streaming,
    get_firmware_dir,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "TI CC26X2R1 LaunchPad"
DESCRIPTION = "LAUNCHXL-CC26X2R1 — Bluetooth 5 / BLE sniffer via Sniffle (XDS110)"

VID_PIDS = [
    (0x0451, 0xBEF3),  # TI XDS110 debug probe (dual CDC — App/User UART + Aux Data)
]

BAUD_RATE = 2000000  # Sniffle firmware runs the UART at 2 Mbaud

SNIFFLE_REPO = "https://github.com/nccgroup/Sniffle"
CRACKLE_REPO = "https://github.com/mikeryan/crackle"

CONNECT_INSTRUCTIONS = (
    "TI CC26X2R1 LaunchPad not detected.\n\n"
    "  1. Connect the LAUNCHXL-CC26X2R1 to USB via the onboard XDS110 debug\n"
    "     port (the micro-USB connector at the top edge of the board).\n"
    "  2. The XDS110 probe (VID:PID 0451:BEF3) exposes TWO CDC serial ports:\n"
    "       - XDS110 Class Application/User UART  (Sniffle uses THIS one)\n"
    "       - XDS110 Class Auxiliary Data Port    (aux — not used by Sniffle)\n"
    "     On Linux both appear as /dev/ttyACM* — the lower-numbered device is\n"
    "     normally the Application/User UART.\n"
    "  3. If the board is not detected: try a different USB port or cable.\n"
    "     Use a DATA cable, not a charge-only one.\n\n"
    "  Linux permissions:\n"
    "    sudo usermod -aG dialout $USER  (then re-login)\n"
    "    Check: dmesg | tail -20\n"
    "    Check: lsusb | grep -i 0451:bef3"
)

UDEV_RULES_CONTENT = (
    '# TI XDS110 (CC26X2R1 LaunchPad) udev rules\n'
    '# XDS110 debug probe — dual CDC ACM serial (VID:PID 0451:BEF3)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="bef3", '
    'MODE="0666", GROUP="dialout"\n'
    '# XDS110 USB device node — for UniFlash / dslite / cc2538-bsl access\n'
    'SUBSYSTEM=="usb", ATTRS{idVendor}=="0451", ATTRS{idProduct}=="bef3", '
    'MODE="0666", GROUP="plugdev"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-ti-xds110.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_cc26x2r1() -> bool:
    info("Scanning USB for TI XDS110 / CC26X2R1 (VID:PID 0451:BEF3)…")
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    """Install udev rules for the TI XDS110 probe on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        info("udev rules only needed on Linux — skipping.")
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for TI XDS110 (CC26X2R1 LaunchPad)…")
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
        info("Unplug and replug the board to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── Tool checks ───────────────────────────────────────────────────────────────

def probe_fw_version_json() -> None:
    """Passive: read the running Sniffle firmware version over serial and print
    JSON. Read-only — no flashing. Lets the Firmware tab show what's on the board
    before the operator prepares to flash."""
    import json
    out = {"installed": False, "version": None, "raw": "", "note": ""}
    cli = get_firmware_dir("cc26x2r1") / "Sniffle" / "python_cli"
    if not cli.exists():
        out["note"] = "Sniffle host tooling not present — run the firmware download first."
        print(json.dumps(out)); return
    if str(cli) not in sys.path:
        sys.path.insert(0, str(cli))
    try:
        from sniffle.sniffle_hw import SniffleHW
    except Exception as e:
        out["note"] = f"Sniffle Python package unavailable ({e})."
        print(json.dumps(out)); return
    hw = None
    try:
        hw = SniffleHW(None, timeout=0.1)          # auto-detects the XDS110 port
        ver = hw.probe_fw_version()
        if ver is not None:
            out["installed"] = True
            out["version"] = f"{ver.major}.{ver.minor}.{ver.revision}"
            out["raw"] = str(ver)
            out["note"] = f"Sniffle detected (API level {ver.api_level})."
        else:
            out["note"] = "Board reachable but not running Sniffle (no version response)."
    except Exception as e:
        out["note"] = f"Board not detected on serial / probe failed ({e})."
    finally:
        try:
            if hw is not None:
                hw.ser.close()
        except Exception:
            pass
    print(json.dumps(out))


def _sniffle_dir() -> Path:
    """Directory where the Sniffle repo is cloned for this tool."""
    return get_firmware_dir("cc26x2r1") / "Sniffle"


def _find_sniff_receiver() -> Path:
    """Return the path to sniff_receiver.py inside the cloned Sniffle repo."""
    return _sniffle_dir() / "python_cli" / "sniff_receiver.py"


def _prebuilt_hex() -> Path:
    """Newest downloaded Sniffle prebuilt hex for the CC2652R1, or None.

    Fetched into firmware/cc26x2r1/prebuilt/<tag>/ by firmware/download.py.
    """
    pdir = get_firmware_dir("cc26x2r1") / "prebuilt"
    if not pdir.exists():
        return None
    hexes = sorted(pdir.rglob("sniffle_cc2652r1*.hex"))
    return hexes[-1] if hexes else None


def _download_prebuilt_hex() -> Path:
    """Run the Quiver firmware downloader to fetch the CC2652R1 prebuilt hex."""
    dl = Path(__file__).resolve().parent / "firmware" / "download.py"
    if not dl.exists():
        warn(f"Firmware downloader not found at {dl}.")
        return None
    info("Fetching the Sniffle CC2652R1 prebuilt hex via the firmware downloader…")
    run_streaming(
        [sys.executable, str(dl), "--tools", "cc26x2r1", "--yes"],
        on_line=lambda l: info(f"  download: {l}"),
        timeout=600,
    )
    return _prebuilt_hex()


def _check_flash_tool() -> str:
    """Return 'uniflash', 'dslite', or '' depending on what's on PATH."""
    info("Checking for a TI flash tool (UniFlash / dslite) on PATH…")
    uniflash = run_output("which uniflash 2>/dev/null || true")
    if uniflash and uniflash.strip():
        ok(f"uniflash found: {uniflash.strip()}")
        return "uniflash"
    dslite = run_output("which dslite 2>/dev/null || true")
    if dslite and dslite.strip():
        ok(f"dslite found: {dslite.strip()}")
        return "dslite"
    warn("No TI flash tool (uniflash / dslite) found on PATH.")
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
    info("Enumerating the TI XDS110 CDC serial ports exposed by the LaunchPad.")
    info("")
    info("The XDS110 debug probe presents TWO CDC ACM serial ports:")
    info("  1. XDS110 Class Application/User UART — Sniffle capture UART (2 Mbaud)")
    info("  2. XDS110 Class Auxiliary Data Port   — aux data channel (unused here)")
    info("")
    info("On Linux the lower-numbered /dev/ttyACM* is usually the App/User UART.")
    info("On macOS look for /dev/tty.usbmodem* — the Application UART is the one")
    info("Sniffle's sniff_receiver.py should be pointed at with -s.")
    info("")

    info("USB serial ports matching the XDS110 (VID:PID 0451:BEF3):")
    matches = []
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.vid == 0x0451 and p.pid == 0xBEF3:
                matches.append(p)
                info(f"  Device      : {p.device}")
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                info(f"  Interface   : {p.interface or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
                info(f"  Serial No.  : {p.serial_number or 'N/A'}")
                info("")
    except Exception as e:
        warn(f"Could not enumerate USB ports via pyserial: {e}")

    if len(matches) >= 2:
        ok(f"Found {len(matches)} XDS110 CDC ports — the two-port layout is present.")
        info("  Point Sniffle at the Application/User UART (usually the lower ttyACM).")
    elif len(matches) == 1:
        warn("Only one XDS110 CDC port is visible.")
        info("  The second (aux) port may be claimed by another process, or the")
        info("  probe firmware exposes a single port — Sniffle will use this one.")
    else:
        warn("No XDS110 CDC ports enumerated — is the board connected?")

    info("")
    info(f"Auto-resolved capture port: {port}")
    ok("Device info complete.")


def op_install_sniffle():
    heading("Install Sniffle Tooling")
    info("Cloning NCC Group's Sniffle — BLE 4.x / Bluetooth 5 sniffer for the")
    info("TI CC13xx / CC26xx family.")
    info("")
    info(f"  Repo   : {SNIFFLE_REPO}")
    info(f"  Target : {_sniffle_dir()}")
    info("")
    info("The Sniffle repo contains:")
    info("  python_cli/sniff_receiver.py — host-side capture tool (writes pcap)")
    info("  python_cli/sniffle_extcap    — Wireshark extcap plugin ('Sniffle')")
    info("  fw/                          — firmware sources / build files")
    info("  The host tooling requires pyserial (2 Mbaud UART).")
    info("")

    dest = _sniffle_dir()
    if (dest / ".git").exists():
        ok(f"Sniffle already cloned at {dest}.")
        if confirm("Pull the latest changes?", default=True):
            info("Running: git -C <dest> pull")
            run_streaming(
                ["git", "-C", str(dest), "pull", "--ff-only"],
                on_line=lambda l: info(f"  git: {l}"),
                timeout=180,
            )
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        info(f"Running: git clone {SNIFFLE_REPO} {dest}")
        rc = run_streaming(
            ["git", "clone", SNIFFLE_REPO, str(dest)],
            on_line=lambda l: info(f"  git: {l}"),
            timeout=300,
        )
        if rc != 0:
            err("git clone failed.")
            info("  Ensure git is installed: sudo apt-get install -y git")
            info(f"  Manual: git clone {SNIFFLE_REPO} {dest}")
            return
        ok(f"Sniffle cloned to {dest}.")

    info("")
    info("Ensuring pyserial for the Sniffle host tooling…")
    if get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    sr = _find_sniff_receiver()
    if sr.exists():
        ok(f"sniff_receiver.py present: {sr}")
        info("  Capture with the 'BLE Capture (Sniffle -> pcap)' menu option.")
    else:
        warn("sniff_receiver.py not found in the expected location.")
        info(f"  Expected: {sr}")
        info("  The Sniffle repo layout may have changed — check python_cli/.")
    ok("Sniffle tooling install complete.")


def op_flash_firmware(port: str):
    heading("Flash Sniffle Firmware")
    info("Flashing the Sniffle sniffer firmware onto the CC26X2R1 LaunchPad.")
    info("The CC26X2R1 carries the CC2652R1, so Sniffle's prebuilt hex flashes")
    info("directly — no from-source build or ARM toolchain needed.")
    info("")

    # ── Locate the prebuilt hex (Quiver downloads it at deploy time) ──────────
    hex_file = _prebuilt_hex()
    if hex_file:
        ok(f"Prebuilt Sniffle firmware ready: {hex_file}")
    else:
        warn("Prebuilt Sniffle hex not found under firmware/cc26x2r1/prebuilt/.")
        if confirm("Download it now (Sniffle CC2652R1 prebuilt)?", default=True):
            hex_file = _download_prebuilt_hex()
        if hex_file:
            ok(f"Downloaded: {hex_file}")
        else:
            warn("No prebuilt hex available.")
            info(f"  Fetch manually: {SNIFFLE_REPO}/releases  (sniffle_cc2652r1.hex)")
            info("  or run: python3 firmware/download.py --tools cc26x2r1 --yes")

    # Let the operator override the path; default to the detected prebuilt hex.
    hex_path = prompt("Path to the Sniffle .hex to flash",
                      default=str(hex_file) if hex_file else "")
    if not hex_path:
        warn("No firmware path provided. Aborting.")
        return
    fw = Path(hex_path)
    if not fw.exists():
        err(f"File not found: {fw}")
        return

    # ── Flash over the onboard XDS110 (TI UniFlash / dslite) ──────────────────
    tool = _check_flash_tool()
    if tool == "dslite":
        if confirm(f"Flash {fw.name} to the CC26X2R1 via XDS110 (dslite)?", default=True):
            info(f"Running: dslite -f -v {fw}")
            info("  Do NOT unplug the LaunchPad during flashing.")
            rc = run_streaming(
                ["dslite", "-f", "-v", str(fw)],
                on_line=lambda l: info(f"  dslite: {l}"),
                timeout=300,
            )
            if rc == 0:
                ok("Sniffle firmware flashed — the board now runs Sniffle.")
                info("  Proceed to 'BLE Capture' (Sniffle speaks 2 Mbaud on the App UART).")
            else:
                err("dslite returned an error.")
                info("  dslite may need an explicit --config <target.ccxml>; the UniFlash")
                info("  GUI can export one for the CC2652R1, or load the hex in the GUI.")
        return
    if tool == "uniflash":
        info("UniFlash detected — flash via the GUI:")
        info(f"  Launch 'uniflash', pick CC2652R1, and load: {fw}")
        info("  (dslite CLI was not found on PATH; the GUI is the reliable path.)")
        pause("Press ENTER once flashed.")
        return

    warn("No TI flash tool (uniflash / dslite) on PATH.")
    info("  Install TI UniFlash (bundles dslite): https://www.ti.com/tool/UNIFLASH")
    info(f"  Then re-run this option — the hex is ready at: {fw}")
    info("  Alternative (Method B) — ROM serial bootloader via cc2538-bsl:")
    info(f"    git clone https://github.com/JelmerT/cc2538-bsl && "
         f"python3 cc2538-bsl/cc2538-bsl.py -p {port} -e -w -v {fw}")
    pause("Press ENTER to continue.")


def op_ble_capture(port: str):
    heading("BLE Capture (Sniffle -> pcap)")
    info("Capturing BLE traffic with Sniffle and writing it to a pcap file.")
    info("")
    info("This runs Sniffle's host tool:")
    info("  python3 <sniffle>/python_cli/sniff_receiver.py -s <port> -b 2000000 -o <pcap>")
    info("")
    info("USEFUL SNIFFLE FLAGS:")
    info("  -s <port>   Serial port of the XDS110 Application/User UART")
    info("  -b 2000000  UART baud rate (Sniffle firmware runs at 2 Mbaud)")
    info("  -o <pcap>   Output pcap file (BLE LINKTYPE for Wireshark)")
    info("  -c <chan>   Lock to a primary advertising channel (37 / 38 / 39)")
    info("  -a <MAC>    Follow a specific advertiser by BD_ADDR (targeted capture)")
    info("  -r <rssi>   Filter by minimum RSSI (drop weak/distant devices)")
    info("  Press Ctrl-C to stop the capture — the pcap is finalised on exit.")
    info("")

    sr = _find_sniff_receiver()
    if not sr.exists():
        err("sniff_receiver.py not found — install the Sniffle tooling first.")
        info(f"  Expected: {sr}")
        info("  Run the 'Install Sniffle tooling' menu option.")
        return

    default_pcap = str(Path.cwd() / f"sniffle_{time.strftime('%Y%m%d_%H%M%S')}.pcap")
    pcap_path = prompt("Output pcap path", default=default_pcap)
    if not pcap_path:
        warn("No output path provided. Aborting.")
        return
    pcap = Path(pcap_path)
    pcap.parent.mkdir(parents=True, exist_ok=True)

    info(f"Capture port : {port}")
    info(f"Output pcap  : {pcap}")
    if not confirm("Start the Sniffle capture now?", default=True):
        info("Capture cancelled.")
        return

    cmd = [sys.executable, str(sr), "-s", port, "-b", str(BAUD_RATE), "-o", str(pcap)]
    info(f"Running: {' '.join(cmd)}")
    info("  Sniffle is now capturing — press Ctrl-C in this terminal to stop.")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(f"  sniffle: {l}"), timeout=86400)
        if rc == 0:
            ok(f"Capture complete: {pcap}")
        else:
            warn(f"sniff_receiver.py exited with code {rc}.")
    except KeyboardInterrupt:
        info("Capture interrupted by user (Ctrl-C).")

    if pcap.exists() and pcap.stat().st_size > 0:
        ok(f"pcap saved: {pcap} ({pcap.stat().st_size // 1024} KB)")
        info("  Open it in Wireshark, or decrypt legacy pairing with the crackle option.")
    else:
        warn("No pcap data was written — was any BLE traffic seen?")
        info("  Verify the board is flashed with Sniffle and on the correct port.")
        info("  Try locking a channel with -c 37 and moving closer to the target.")


def op_crack_pairing():
    heading("Crack Pairing (crackle)")
    info("Decrypting BLE traffic captured during a legacy pairing exchange using")
    info("crackle by Mike Ryan.")
    info("")
    info("IMPORTANT — crackle only cracks BLE LEGACY pairing:")
    info("  - Works on: LE Legacy pairing (JustWorks, Passkey Entry)")
    info("  - Does NOT work on: LE Secure Connections (ECDH-based pairing)")
    info("  The capture MUST contain the full pairing handshake (the connection")
    info("  request through key distribution) — start Sniffle BEFORE pairing.")
    info("")
    info("crackle recovers the TK/STK/LTK, then decrypts the encrypted packets")
    info("and writes a cleartext pcap you can analyse in Wireshark.")
    info("")

    crackle = run_output("which crackle 2>/dev/null || true")
    if not (crackle and crackle.strip()):
        warn("crackle not found on PATH.")
        info("  Install it from source:")
        info(f"    git clone {CRACKLE_REPO}")
        info("    cd crackle && make")
        info("    sudo cp crackle /usr/local/bin/   (optional — put it on PATH)")
        info("  Debian/Kali may also package it: sudo apt-get install -y crackle")
        info("Not running crackle automatically — install it, then re-run this option.")
        return
    ok(f"crackle found: {crackle.strip()}")

    pcap_path = prompt("Path to the captured .pcap (must contain legacy pairing)")
    if not pcap_path:
        warn("No pcap provided. Aborting.")
        return
    pcap = Path(pcap_path)
    if not pcap.exists():
        err(f"File not found: {pcap}")
        return

    default_out = str(pcap.with_name(pcap.stem + "_decrypted.pcap"))
    out_path = prompt("Output decrypted pcap path", default=default_out)
    out_pcap = Path(out_path)

    if not confirm(f"Run crackle on {pcap.name}?", default=True):
        info("crackle run cancelled.")
        return

    cmd = ["crackle", "-i", str(pcap), "-o", str(out_pcap)]
    info(f"Running: {' '.join(cmd)}")
    rc = run_streaming(cmd, on_line=lambda l: info(f"  crackle: {l}"), timeout=600)
    if rc == 0 and out_pcap.exists():
        ok(f"Decrypted pcap written: {out_pcap}")
        info("  Open it in Wireshark — the ATT/GATT payloads are now cleartext.")
    else:
        warn(f"crackle exited with code {rc}.")
        info("Troubleshooting:")
        info("  - Ensure the capture contains a COMPLETE legacy pairing handshake")
        info("  - LE Secure Connections cannot be cracked (ECDH) — check the capture")
        info("  - Re-capture with Sniffle running BEFORE the devices pair")
        info("  - Try crackle -v for verbose output on what it found")


def op_wireshark_extcap():
    heading("Wireshark extcap Setup")
    info("Installing Sniffle's Wireshark extcap plugin so live BLE capture is")
    info("available directly from Wireshark's interface list.")
    info("")
    info("The plugin lets Wireshark drive Sniffle without the CLI — the LaunchPad")
    info("shows up as a capture interface named 'Sniffle'.")
    info("")

    sr_dir = _sniffle_dir() / "python_cli"
    extcap_src = sr_dir / "sniffle_extcap"
    if extcap_src.exists():
        ok(f"Sniffle extcap plugin found: {extcap_src}")
    else:
        warn("sniffle_extcap not found — install the Sniffle tooling first.")
        info(f"  Expected: {extcap_src}")

    os_name = get_os()
    if os_name == "macos":
        user_extcap = Path.home() / ".config" / "wireshark" / "extcap"
    else:
        user_extcap = Path.home() / ".config" / "wireshark" / "extcap"

    info("")
    info("SETUP STEPS:")
    info(f"  1. Create the Wireshark extcap dir:  mkdir -p {user_extcap}")
    info(f"  2. Copy the plugin into it:")
    info(f"       cp {extcap_src} {user_extcap}/")
    info(f"  3. Make it executable:               chmod +x {user_extcap}/sniffle_extcap")
    info("  4. Ensure sniffle_extcap can import the Sniffle python_cli modules")
    info("     (it lives beside sniff_receiver.py — keep the repo in place, or")
    info("      copy the whole python_cli/ dir alongside the plugin).")
    info("  5. Restart Wireshark.")
    info("")
    info("VERIFY:")
    info("  In Wireshark's interface list, an entry named 'Sniffle' appears.")
    info("  Click its gear icon to set channel / advertiser / RSSI filters,")
    info("  then start capturing straight into Wireshark.")
    info("")
    info(f"  Confirm Wireshark sees it:  wireshark --list-interfaces | grep -i sniffle")
    info("")

    if extcap_src.exists() and confirm("Copy + chmod the plugin now?", default=True):
        user_extcap.mkdir(parents=True, exist_ok=True)
        dest = user_extcap / "sniffle_extcap"
        r = run(f"cp {extcap_src} {dest}")
        if r.returncode == 0:
            run(f"chmod +x {dest}")
            ok(f"Installed extcap plugin: {dest}")
            info("  Restart Wireshark — the 'Sniffle' interface will appear.")
        else:
            err("Failed to copy the extcap plugin.")
            info(f"  Manual: cp {extcap_src} {dest} && chmod +x {dest}")
    else:
        pause("Press ENTER to continue.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    info(f"Detected OS flavor: {flavor}")

    # Ensure pyserial
    info("Ensuring pyserial for USB CDC serial communication…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        ensure_apt_packages(["python3-serial"])
    else:
        ensure_pip_packages([("serial", "pyserial")])

    # requests for GitHub / firmware download helpers
    info("Ensuring requests library for firmware/version helpers…")
    ensure_pip_packages([("requests", "requests")])

    print_banner(TOOL_NAME, DESCRIPTION)

    info("Checking udev rules for TI XDS110 USB access…")
    _check_udev_rules()

    info("Detecting CC26X2R1 LaunchPad via USB VID:PID 0451:BEF3…")
    info("  The XDS110 probe exposes two CDC ports — Sniffle uses the App/User UART.")

    found = web_detect_loop(detect_cc26x2r1, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("TI CC26X2R1 LaunchPad not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"CC26X2R1 LaunchPad detected on {port}")
    info("  This is the Application/User UART used by Sniffle (2 Mbaud).")
    info("  If captures fail, check 'Device Info' for the other XDS110 CDC port.")

    _check_dialout(port)

    MENU_OPTIONS = [
        "Device Info",
        "Install Sniffle tooling",
        "Flash Sniffle firmware",
        "BLE Capture (Sniffle -> pcap)",
        "Crack Pairing (crackle)",
        "Wireshark extcap setup",
        "Exit",
    ]

    while True:
        choice = numbered_menu("TI CC26X2R1 LaunchPad — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_install_sniffle()
        elif choice == 2:
            op_flash_firmware(port)
        elif choice == 3:
            op_ble_capture(port)
        elif choice == 4:
            op_crack_pairing()
        elif choice == 5:
            op_wireshark_extcap()
        elif choice == 6:
            info("Goodbye.")
            break

        # Re-check port after operations (device may re-enumerate after a flash)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    if "--probe-fw-version" in sys.argv:
        probe_fw_version_json()
        sys.exit(0)
    main()
