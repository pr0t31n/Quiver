#!/usr/bin/env python3
"""
Yardstick One Tool Manager
Controls the Yardstick One sub-GHz radio transceiver via the rfcat Python library.
Supports RF configuration, transmission, reception, spectrum scanning, and bootloader.

Usage:
    python3 yardstick_one.py
"""

import sys
import time

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    detect_usb_libusb,
    require_sudo, sudo_run, sudo_output,
    ensure_apt_packages, ensure_brew_packages, ensure_pip_packages,
    ensure_system_tool,
    web_detect_loop,
    check_latest_github_release, announce_firmware_update,
)

# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME   = "Yardstick One"
DESCRIPTION = "Sub-GHz RF transceiver — rfcat-based RF control"

VID_NORMAL     = 0x1D50
PID_NORMAL     = 0x605B
VID_BOOTLOADER = 0x1D50
PID_BOOTLOADER = 0x6002

MODULATIONS = ["ASK/OOK", "2-FSK", "GFSK", "MSK"]

COMMON_FREQS_MHZ = [315.0, 433.92, 868.0, 915.0]

CONNECT_INSTRUCTIONS = (
    "Yardstick One not detected.\n\n"
    "  1. Plug in Yardstick One via USB\n"
    "  2. Kali: sudo apt install rfcat python3-usb\n"
    "  3. Verify udev rules: ls /etc/udev/rules.d/ | grep rfcat\n"
    "     If missing: sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "  4. Add user to plugdev: sudo usermod -aG plugdev $USER (then re-login)\n"
    "  5. macOS: brew install libusb\n\n"
    "  VID:PID 1D50:605B (normal) | 1D50:6002 (bootloader)"
)

UDEV_RULES_PATH = "/etc/udev/rules.d/20-rfcat.rules"
UDEV_RULES_CONTENT = (
    '# Yardstick One udev rules\n'
    'SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="605b", MODE="0666", GROUP="plugdev"\n'
    'SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6002", MODE="0666", GROUP="plugdev"\n'
)


# ── Detection ──────────────────────────────────────────────────────────────────

def detect_yardstick() -> bool:
    return detect_usb_libusb(VID_NORMAL, PID_NORMAL)


# ── Firmware version check ─────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("Querying Yardstick One firmware version via rfcat…")
    current = None
    try:
        RfCat, _ = _import_rfcat()
        d = RfCat(idx=0)
        try:
            # rfcat exposes firmware build string
            ver = getattr(d, "getBuildType", None) or getattr(d, "firmwareVersion", None)
            if callable(ver):
                current = str(ver())
            elif ver:
                current = str(ver)
        finally:
            try:
                d.setModeIDLE()
                d.cleanup()
            except Exception:
                pass
    except Exception as e:
        warn(f"Could not query rfcat firmware version: {e}")

    if current:
        ok(f"Firmware version: {current}")
    else:
        info("Could not auto-detect Yardstick One firmware version.")
        info("To check manually: rfcat -r  or  rfcat --version")

    latest, url = check_latest_github_release("atlas0fd00m", "rfcat")
    if latest:
        announce_firmware_update(TOOL_NAME, current, latest, url)


# ── udev rules check ──────────────────────────────────────────────────────────

def _check_udev_rules():
    """Check for rfcat udev rules and install them if missing (Linux only)."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        return
    import shutil
    import os
    # Check if any rfcat-related rule file exists
    rules_dirs = ["/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"]
    found = False
    for rules_dir in rules_dirs:
        r = run_output(f"ls {rules_dir}/ 2>/dev/null | grep -i rfcat")
        if r:
            found = True
            ok(f"udev rules found in {rules_dir}: {r.strip()}")
            break
    if not found:
        warn("No rfcat udev rules found. Device may require sudo to open.")
        info("Installing udev rules for Yardstick One (VID:PID 1D50:605B, 1D50:6002)…")
        r = sudo_run(f"bash -c 'cat > {UDEV_RULES_PATH} <<EOF\n{UDEV_RULES_CONTENT}EOF'")
        if r.returncode == 0:
            sudo_run("udevadm control --reload-rules")
            sudo_run("udevadm trigger")
            ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
            info("You may need to unplug and replug the Yardstick One.")
        else:
            warn(f"Failed to write udev rules to {UDEV_RULES_PATH}.")
            info(f"Manual fix: sudo bash -c 'echo \"{UDEV_RULES_CONTENT}\" > {UDEV_RULES_PATH}'")
            info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── rfcat import helper ────────────────────────────────────────────────────────

def _import_rfcat():
    """Import RfCat and modulation constants. Returns (RfCat, mod_dict) or raises.

    Modulation constants explanation:
      ASK/OOK (MOD_ASK_OOK=3) — Amplitude Shift Keying / On-Off Keying.
        Used by many garage doors, key fobs, 433 MHz sensors.
        Simple on/off carrier; easy to decode with SDR.
      2-FSK (MOD_2FSK=0) — Binary Frequency Shift Keying.
        Two frequencies represent 0 and 1. Very common for data links.
        Used by many ISM-band sensors, weather stations.
      GFSK (MOD_GFSK=1) — Gaussian-filtered FSK.
        Smoother frequency transitions; used by Bluetooth, many protocols.
      MSK (MOD_MSK=7) — Minimum Shift Keying.
        Variant of FSK with minimal bandwidth; used in some trunked radio systems.
    """
    try:
        from rfcat import RfCat  # type: ignore
    except ImportError:
        raise ImportError(
            "rfcat Python library not found.\n"
            "  Kali: sudo apt install rfcat python3-usb\n"
            "  Fallback: pip install rfcat --break-system-packages\n"
            "  Verify: python3 -c 'from rfcat import RfCat'\n"
            "  Linux udev: check /etc/udev/rules.d/ for rfcat rules."
        )

    mods = {}
    try:
        from rfcat.chipcon_usb import MOD_2FSK, MOD_GFSK, MOD_ASK_OOK, MOD_MSK  # type: ignore
        mods = {
            "ASK/OOK": MOD_ASK_OOK,
            "2-FSK":   MOD_2FSK,
            "GFSK":    MOD_GFSK,
            "MSK":     MOD_MSK,
        }
    except ImportError:
        # Older rfcat versions may have different paths
        try:
            from rfcat import MOD_2FSK, MOD_GFSK, MOD_ASK_OOK, MOD_MSK  # type: ignore
            mods = {
                "ASK/OOK": MOD_ASK_OOK,
                "2-FSK":   MOD_2FSK,
                "GFSK":    MOD_GFSK,
                "MSK":     MOD_MSK,
            }
        except ImportError:
            warn("Could not import modulation constants; defaulting to numeric values.")
            warn("If using Kali apt rfcat, try: python3 -c 'from rfcat.chipcon_usb import MOD_2FSK'")
            mods = {"ASK/OOK": 3, "2-FSK": 0, "GFSK": 1, "MSK": 7}

    return RfCat, mods


def _open_device():
    """Open Yardstick One device. Returns (d, mods) or raises."""
    info("Opening Yardstick One device via rfcat…")
    info("Troubleshooting: if this hangs, check udev rules and replug device.")
    RfCat, mods = _import_rfcat()
    d = RfCat(idx=0)
    return d, mods


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Reading radio configuration from Yardstick One…")
    info("Troubleshooting: ensure rfcat is installed and udev rules are in place.")
    try:
        d, _ = _open_device()
        try:
            info("Radio Configuration:")
            config_str = d.reprRadioConfig()
            for line in str(config_str).splitlines():
                info(f"  {line}")
            d.setModeIDLE()
        finally:
            try:
                d.cleanup()
            except Exception:
                pass
    except Exception as e:
        err(f"Device info failed: {e}")
        info("Common causes:")
        info("  - rfcat Python library not installed (apt install rfcat)")
        info("  - udev rules missing — run this script as root or fix udev")
        info("  - Device not in normal mode (VID:PID 1D50:605B)")


def op_configure_radio():
    heading("Configure Radio")
    info("Set frequency, modulation, and data rate for the CC1111 radio chip.")
    info("Common presets: 315 MHz (US garage), 433.92 MHz (EU sensors), 868/915 MHz (ISM)")
    freq_str = prompt("Frequency (MHz)", "433.92")
    try:
        freq_mhz = float(freq_str)
    except ValueError:
        err("Invalid frequency.")
        return

    info("Modulation guide:")
    info("  ASK/OOK — garage doors, key fobs, simple 433 MHz sensors")
    info("  2-FSK   — weather stations, ISM data links")
    info("  GFSK    — Bluetooth-like signals, many proprietary protocols")
    info("  MSK     — trunked radio variants")
    mod_choice = numbered_menu("Modulation", MODULATIONS)
    mod_name = MODULATIONS[mod_choice]

    rate_str = prompt("Data rate (baud)", "4800")
    try:
        data_rate = int(rate_str)
    except ValueError:
        err("Invalid data rate.")
        return

    info(f"Configuring radio: {freq_mhz} MHz, {mod_name}, {data_rate} baud…")
    try:
        d, mods = _open_device()
        try:
            d.setModeIDLE()
            d.setFreq(int(freq_mhz * 1e6))
            d.setMdmModulation(mods[mod_name])
            d.setMdmDRate(data_rate)
            ok(f"Radio configured: {freq_mhz} MHz, {mod_name}, {data_rate} baud")
            d.setModeIDLE()
        finally:
            try:
                d.cleanup()
            except Exception:
                pass
    except Exception as e:
        err(f"Configure failed: {e}")
        info("Troubleshooting: check that device is plugged in and rfcat udev rules are loaded.")


def op_transmit_file():
    heading("Transmit File")
    info("Transmit raw bytes or hex-encoded data via the CC1111 radio.")
    info("File format: raw binary OR ASCII hex (spaces/newlines stripped).")
    info("Troubleshooting TX:")
    info("  - TX requires a proper antenna or 50-ohm terminator to avoid damage")
    info("  - Check local RF regulations — unlicensed TX may be restricted")
    info("  - If tx fails with USB error, replug device and retry")
    file_path = prompt("Path to hex or raw bytes file")
    if not file_path:
        warn("No path entered.")
        return

    from pathlib import Path
    p = Path(file_path).expanduser()
    if not p.exists():
        err(f"File not found: {p}")
        return

    raw = p.read_bytes()
    # If file content looks like hex text, decode it
    try:
        text = raw.decode("ascii").strip().replace(" ", "").replace("\n", "")
        if all(c in "0123456789abcdefABCDEF" for c in text):
            data = bytes.fromhex(text)
            info(f"Decoded as hex: {len(data)} bytes")
        else:
            data = raw
            info(f"Using raw binary: {len(data)} bytes")
    except UnicodeDecodeError:
        data = raw
        info(f"Using raw binary: {len(data)} bytes")

    freq_str = prompt("Frequency (MHz)", "433.92")
    try:
        freq_mhz = float(freq_str)
    except ValueError:
        err("Invalid frequency.")
        return

    mod_choice = numbered_menu("Modulation", MODULATIONS)
    mod_name = MODULATIONS[mod_choice]

    info(f"Preparing to transmit {len(data)} bytes at {freq_mhz} MHz ({mod_name})…")
    try:
        d, mods = _open_device()
        try:
            d.setModeIDLE()
            d.setFreq(int(freq_mhz * 1e6))
            d.setMdmModulation(mods[mod_name])
            d.setMaxPower()
            d.makePktFLEN(len(data))
            info(f"Transmitting {len(data)} bytes at {freq_mhz} MHz ({mod_name})…")
            d.RFxmit(data)
            d.setModeIDLE()
            ok("Transmission complete.")
        finally:
            try:
                d.cleanup()
            except Exception:
                pass
    except Exception as e:
        err(f"Transmit failed: {e}")
        info("If you see a USB error, try replugging the device.")


def op_receive_sniff():
    heading("Receive / Sniff")
    info("Sniff sub-GHz packets using the Yardstick One in RX mode.")
    info("Troubleshooting RX:")
    info("  - Ensure correct frequency and modulation for the target signal")
    info("  - ASK/OOK default is good for most 433 MHz sensors")
    info("  - RFrecv timeout=1000ms means 1s wait per poll cycle")
    info("  - If no packets: try ASK/OOK at 433.92 MHz with a nearby remote")
    freq_str = prompt("Frequency (MHz)", "433.92")
    try:
        freq_mhz = float(freq_str)
    except ValueError:
        err("Invalid frequency.")
        return

    duration_str = prompt("Duration (seconds)", "10")
    try:
        duration = float(duration_str)
    except ValueError:
        err("Invalid duration.")
        return

    info(f"Starting RX at {freq_mhz} MHz for {duration}s (ASK/OOK)…")
    try:
        d, mods = _open_device()
        try:
            d.setModeIDLE()
            d.setFreq(int(freq_mhz * 1e6))
            d.setMdmModulation(mods["ASK/OOK"])
            d.setModeRX()
            info(f"Receiving at {freq_mhz} MHz for {duration}s… (Ctrl+C to stop early)")
            deadline = time.time() + duration
            pkt_count = 0
            while time.time() < deadline:
                try:
                    pkt, ts = d.RFrecv(timeout=1000)
                    hex_str = pkt.hex() if pkt else ""
                    info(f"  [{pkt_count + 1}] ts={ts:.3f}  {hex_str}")
                    pkt_count += 1
                except Exception:
                    pass
            d.setModeIDLE()
            ok(f"Sniff complete. {pkt_count} packet(s) received.")
        finally:
            try:
                d.cleanup()
            except Exception:
                pass
    except KeyboardInterrupt:
        info("Interrupted.")
    except Exception as e:
        err(f"Receive failed: {e}")
        info("Troubleshooting: verify frequency and modulation match the target device.")


def op_spectrum_scan():
    heading("Spectrum Scan")
    info("RSSI sweep across a frequency range using the CC1111 radio.")
    info("Bar chart: each '#' = ~2 dBm above -100 dBm floor, max 40 chars wide.")
    info("Troubleshooting:")
    info("  - Wider step (0.1 MHz) = faster scan, narrower = more detail")
    info("  - RSSI=N/A means the chip could not measure at that frequency")
    info("  - Use narrow step around known signal to identify exact frequency")
    start_str = prompt("Start frequency (MHz)", "433.0")
    stop_str  = prompt("Stop frequency (MHz)",  "434.0")
    step_str  = prompt("Step (MHz)",             "0.01")
    try:
        start_mhz = float(start_str)
        stop_mhz  = float(stop_str)
        step_mhz  = float(step_str)
    except ValueError:
        err("Invalid frequency values.")
        return

    if start_mhz >= stop_mhz or step_mhz <= 0:
        err("Invalid range or step.")
        return

    info(f"Scanning {start_mhz}–{stop_mhz} MHz in {step_mhz} MHz steps…")
    try:
        d, _ = _open_device()
        try:
            d.setModeIDLE()
            freq = start_mhz
            while freq <= stop_mhz:
                try:
                    d.setFreq(int(freq * 1e6))
                    d.setModeIDLE()
                    rssi = d.getRSSI()
                    bar_len = max(0, int((rssi + 100) / 2))
                    bar = "#" * min(bar_len, 40)
                    info(f"  {freq:8.3f} MHz  RSSI={rssi:4d} dBm  {bar}")
                except Exception:
                    info(f"  {freq:8.3f} MHz  RSSI=N/A")
                freq = round(freq + step_mhz, 6)
            d.setModeIDLE()
            ok("Spectrum scan complete.")
        finally:
            try:
                d.cleanup()
            except Exception:
                pass
    except Exception as e:
        err(f"Spectrum scan failed: {e}")
        info("Troubleshooting: ensure rfcat device is open and not in use by another process.")


def op_print_radio_config():
    heading("Print Radio Config")
    info("Dumps the full CC1111 radio register configuration.")
    try:
        d, _ = _open_device()
        try:
            config = d.reprRadioConfig()
            for line in str(config).splitlines():
                info(line)
            d.setModeIDLE()
        finally:
            try:
                d.cleanup()
            except Exception:
                pass
    except Exception as e:
        err(f"Failed: {e}")


def op_enter_bootloader():
    heading("Enter Bootloader")
    warn("Device will re-enumerate as VID:PID 1D50:6002 (bootloader mode).")
    info("Bootloader mode is used for firmware updates via goodfet or rfcat tools.")
    if not confirm("Enter bootloader?", default=False):
        info("Cancelled.")
        return
    info("Sending bootloader command…")
    try:
        d, _ = _open_device()
        try:
            d.bootloader()
            ok("Bootloader command sent. Device re-enumerating…")
            info("To recover: replug device; it should return as VID:PID 1D50:605B.")
        finally:
            try:
                d.cleanup()
            except Exception:
                pass
    except Exception as e:
        err(f"Bootloader command failed: {e}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    # Prefer apt packages on Kali/Debian/Ubuntu
    info("Checking apt packages: rfcat, python3-usb…")
    ensure_apt_packages(["rfcat", "python3-usb"])
    ensure_brew_packages(["libusb"])

    # PIP fallback: if rfcat library import fails after apt, try pip
    try:
        _import_rfcat()
    except ImportError:
        warn("rfcat apt package installed but Python library not importable.")
        info("Attempting pip fallback for rfcat Python library…")
        ensure_pip_packages([("rfcat", "rfcat")])
        try:
            _import_rfcat()
        except ImportError as e:
            err(str(e))
            sys.exit(1)

    # Check udev rules
    info("Checking udev rules for Yardstick One…")
    _check_udev_rules()

    # Detection
    detected = web_detect_loop(detect_yardstick, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not detected:
        err("Yardstick One not detected. Exiting.")
        sys.exit(1)
    ok("Yardstick One detected.")

    check_firmware_version()

    MENU_OPTIONS = [
        "Device Info (radio config)",
        "Configure Radio (freq / modulation / data rate)",
        "Transmit File (hex or raw bytes)",
        "Receive / Sniff (loop RFrecv)",
        "Spectrum Scan (RSSI sweep + bar chart)",
        "Print Radio Config",
        "Enter Bootloader",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Yardstick One — Select Operation", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_configure_radio()
        elif choice == 2:
            op_transmit_file()
        elif choice == 3:
            op_receive_sniff()
        elif choice == 4:
            op_spectrum_scan()
        elif choice == 5:
            op_print_radio_config()
        elif choice == 6:
            op_enter_bootloader()
        elif choice == 7:
            ok("Goodbye.")
            sys.exit(0)


if __name__ == "__main__":
    main()
