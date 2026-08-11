#!/usr/bin/env python3
"""
HackRF One Tool Manager
Controls the HackRF One SDR via pyhackrf (Python library) and CLI tools
(hackrf_info, hackrf_transfer, hackrf_sweep, hackrf_spiflash).

Usage:
    python3 hackrf_one.py
"""

import sys
import subprocess
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    detect_usb_libusb,
    require_sudo, sudo_run, sudo_output,
    ensure_apt_packages, ensure_brew_packages, ensure_pip_packages,
    ensure_system_tool,
    web_detect_loop, run_streaming,
    check_latest_github_release, compare_versions, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    get_firmware_dir, download_firmware, get_github_release_asset_url,
)

# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME   = "HackRF One"
DESCRIPTION = "Software-defined radio: receive, transmit, spectrum sweep"

VID_NORMAL = 0x1D50
PID_NORMAL = 0x6089
VID_DFU    = 0x1FC9
PID_DFU    = 0x000C

CONNECT_INSTRUCTIONS = (
    "HackRF One not detected.\n\n"
    "  1. Connect HackRF One via USB cable\n"
    "  2. Install tools:\n"
    "     Kali/Linux: sudo apt install hackrf python3-usb\n"
    "     macOS: brew install hackrf\n"
    "  3. Linux udev rules — check /etc/udev/rules.d/ for hackrf rules\n"
    "     If missing: sudo cp /usr/share/hackrf/udev/53-hackrf.rules /etc/udev/rules.d/\n"
    "     Then: sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "  4. Add user to plugdev: sudo usermod -aG plugdev $USER (re-login required)\n\n"
    "  VID:PID 1D50:6089"
)

UDEV_RULE = (
    'SUBSYSTEM=="usb", ATTR{idVendor}=="1d50", ATTR{idProduct}=="6089", '
    'MODE="0666", GROUP="plugdev"'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/53-hackrf.rules"


# ── Firmware version check ────────────────────────────────────────────────────

def _get_current_version() -> str:
    """Return the firmware version from hackrf_info output, or ''."""
    try:
        result = subprocess.run(
            ["hackrf_info"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if line.strip().lower().startswith("firmware version:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip().split()[0]
        return ""
    except Exception:
        return ""


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking installed firmware version...")
    current = _get_current_version()
    if not current:
        warn("Could not determine installed firmware version.")
        info("Continuing without version check.")
        return
    ok(f"Installed firmware: {current}")

    info("Checking latest available version on GitHub...")
    latest, release_url = check_latest_github_release("greatscottgadgets", "hackrf")
    if not latest:
        warn("Could not reach GitHub. Skipping version check.")
        return

    wants_update = announce_firmware_update(TOOL_NAME, current, latest, release_url)
    if wants_update:
        op_firmware_update()


# ── Detection ──────────────────────────────────────────────────────────────────

def detect_hackrf() -> bool:
    return detect_usb_libusb(VID_NORMAL, PID_NORMAL)


# ── udev rules check ──────────────────────────────────────────────────────────

def _check_udev_rules():
    """Check HackRF udev rules on Linux; install if missing."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        return
    import shutil
    # Check all standard udev rule dirs
    for rules_dir in ["/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d"]:
        r = run_output(f"ls {rules_dir}/ 2>/dev/null | grep -i hackrf")
        if r:
            ok(f"HackRF udev rules found: {rules_dir}/{r.strip()}")
            return
    # Try to copy from hackrf package share
    pkg_rules = "/usr/share/hackrf/udev/53-hackrf.rules"
    if Path(pkg_rules).exists():
        info(f"Copying {pkg_rules} → {UDEV_RULES_PATH}…")
        r = sudo_run(f"cp {pkg_rules} {UDEV_RULES_PATH}")
    else:
        warn("No HackRF udev rules found. Installing minimal rule…")
        info(f"Rule: {UDEV_RULE}")
        r = sudo_run(f"bash -c 'echo \"{UDEV_RULE}\" > {UDEV_RULES_PATH}'")
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug HackRF One to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual fix: sudo bash -c 'echo \"{UDEV_RULE}\" > {UDEV_RULES_PATH}'")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")


# ── pyhackrf guard ─────────────────────────────────────────────────────────────

def _import_pyhackrf():
    """Import pyhackrf HackRF class or raise ImportError with install hint."""
    try:
        from hackrf import HackRF  # type: ignore
        return HackRF
    except ImportError:
        raise ImportError(
            "pyhackrf Python bindings not installed.\n"
            "  Install: pip install pyhackrf --break-system-packages\n"
            "  Also requires libhackrf (apt install hackrf / brew install hackrf)\n"
            "  Note: CLI tools (hackrf_info, hackrf_transfer) work without pyhackrf."
        )


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Running hackrf_info to query device firmware and board revision…")
    info("hackrf_info output explanation:")
    info("  Found HackRF One...     — device detected on USB bus")
    info("  Board ID Number         — hardware revision (e.g. 2 = HackRF One r9)")
    info("  Firmware Version        — current firmware (update if < 2021.03.1)")
    info("  Part ID Number          — LPC43xx MCU part identifier")
    info("  Serial Number           — unique 64-bit serial (useful for multi-device setups)")
    info("Troubleshooting:")
    info("  'hackrf_info: not found' → sudo apt install hackrf")
    info("  'USB error' / 'no device' → check udev rules and USB cable")
    info("  'HACKRF_ERROR_NOT_FOUND' → device not enumerated; try replugging")
    if not ensure_system_tool("hackrf_info", "sudo apt install hackrf  /  brew install hackrf",
                              apt_pkg="hackrf", brew_pkg="hackrf"):
        return
    rc = run_streaming(["hackrf_info"], on_line=lambda l: info(l), timeout=15)
    if rc != 0:
        warn(f"hackrf_info exited with code {rc}")
        info("Common errors:")
        info("  Exit 1 — device not found or permission denied")
        info("  Check: ls -la /dev/bus/usb/*/*  (look for HackRF entry)")
        info("  Check: groups (confirm 'plugdev' is listed)")


def op_receive_iq():
    heading("Receive IQ Samples")
    info("Capture raw IQ (I/Q) samples from the HackRF One to a file.")
    info("IQ file format: interleaved signed 8-bit samples (int8 pairs).")
    info("Use with GNU Radio, inspectrum, or SoapySDR for analysis.")
    freq_str = prompt("Center frequency (MHz)", "433.92")
    rate_str = prompt("Sample rate (MHz)", "10")
    dur_str  = prompt("Duration (seconds)", "5")
    out_file = prompt("Output file path", "/tmp/hackrf_rx.iq")

    try:
        freq_mhz = float(freq_str)
        rate_mhz = float(rate_str)
        duration = float(dur_str)
    except ValueError:
        err("Invalid numeric input.")
        return

    out_path = Path(out_file).expanduser()

    # Prefer pyhackrf for programmatic control; fall back to hackrf_transfer CLI
    try:
        HackRF = _import_pyhackrf()
        try:
            import numpy as np  # type: ignore
        except ImportError:
            np = None

        info(f"Receiving {rate_mhz} MSps at {freq_mhz} MHz for {duration}s via pyhackrf…")
        info("Troubleshooting pyhackrf: if it hangs, udev rules may be blocking access.")
        try:
            with HackRF() as hackrf:
                hackrf.sample_rate = rate_mhz * 1e6
                hackrf.center_freq = freq_mhz * 1e6
                hackrf.lna_gain    = 16
                hackrf.vga_gain    = 20
                num_samples = int(rate_mhz * 1e6 * duration)
                samples = hackrf.read_samples(num_samples)
            # Write as int8 pairs if numpy available, else raw
            if np is not None:
                iq = samples.view(np.int8)
                iq.tofile(str(out_path))
            else:
                with open(out_path, "wb") as fh:
                    fh.write(bytes(samples))
            ok(f"IQ data saved to {out_path}")
        except Exception as e:
            err(f"pyhackrf receive failed: {e}")
            info("Falling back to hackrf_transfer CLI…")
            raise ImportError("fallback")

    except ImportError:
        # CLI fallback
        info("Using hackrf_transfer CLI for IQ capture…")
        if not ensure_system_tool("hackrf_transfer",
                                  "sudo apt install hackrf  /  brew install hackrf",
                                  apt_pkg="hackrf", brew_pkg="hackrf"):
            return
        num_samples = int(rate_mhz * 1e6 * duration)
        cmd = [
            "hackrf_transfer",
            "-r", str(out_path),
            "-f", str(int(freq_mhz * 1e6)),
            "-s", str(int(rate_mhz * 1e6)),
            "-n", str(num_samples),
            "-l", "16",
            "-g", "20",
        ]
        info(f"Running: {' '.join(cmd)}")
        info("Troubleshooting hackrf_transfer:")
        info("  '-f' argument is Hz (not MHz) — double-check the value")
        info("  '-s' sample rate must be 2–20 MHz for HackRF One")
        info("  '-l' LNA gain: 0–40 dB in 8 dB steps")
        info("  '-g' VGA gain: 0–62 dB in 2 dB steps")
        rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=int(duration) + 30)
        if rc == 0:
            ok(f"IQ data saved to {out_path}")
        else:
            warn(f"hackrf_transfer exited with code {rc}")


def op_transmit_iq():
    heading("Transmit IQ File")
    info("Transmit a raw IQ file through the HackRF One.")
    info("WARNING: Ensure TX is legal on the chosen frequency in your jurisdiction.")
    info("File must be interleaved signed 8-bit IQ samples (hackrf_transfer -t format).")
    info("Troubleshooting TX:")
    info("  - HackRF TX power is modest (~10–15 dBm). Use an antenna for range.")
    info("  - TX VGA gain 0–47 dB in 1 dB steps. Start low (20 dB) and increase.")
    info("  - 'HACKRF_ERROR_INVALID_PARAM' — gain or sample rate out of range")
    if not ensure_system_tool("hackrf_transfer",
                              "sudo apt install hackrf  /  brew install hackrf",
                              apt_pkg="hackrf", brew_pkg="hackrf"):
        return

    in_file  = prompt("Input IQ file path")
    freq_str = prompt("Center frequency (MHz)", "433.92")
    rate_str = prompt("Sample rate (MHz)", "10")
    gain_str = prompt("TX VGA gain (0-47 dB)", "20")

    if not in_file:
        warn("No input file specified.")
        return

    in_path = Path(in_file).expanduser()
    if not in_path.exists():
        err(f"File not found: {in_path}")
        return

    try:
        freq_mhz = float(freq_str)
        rate_mhz = float(rate_str)
        tx_gain  = int(gain_str)
    except ValueError:
        err("Invalid numeric input.")
        return

    if not confirm(f"Transmit {in_path.name} at {freq_mhz} MHz?", default=False):
        info("Cancelled.")
        return

    cmd = [
        "hackrf_transfer",
        "-t", str(in_path),
        "-f", str(int(freq_mhz * 1e6)),
        "-s", str(int(rate_mhz * 1e6)),
        "-x", str(tx_gain),
    ]
    info(f"Running: {' '.join(cmd)}")
    rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=3600)
    if rc == 0:
        ok("Transmission complete.")
    else:
        warn(f"hackrf_transfer exited with code {rc}")


def op_spectrum_sweep():
    heading("Spectrum Sweep")
    info("Sweep a frequency range and report power spectral density via hackrf_sweep.")
    info("Output format: timestamp, start_hz, stop_hz, step_hz, num_samples, dB values…")
    info("Pipe output to hackrf_sweep → heatmap.py for a visual waterfall.")
    info("Troubleshooting:")
    info("  - Sweep range must be within HackRF limits: 1 MHz – 6 GHz")
    info("  - '-w' bin width (Hz): smaller = more frequency resolution, slower sweep")
    info("  - '-g' gain (0–40 dB): increase for weak signals")
    if not ensure_system_tool("hackrf_sweep",
                              "sudo apt install hackrf  /  brew install hackrf",
                              apt_pkg="hackrf", brew_pkg="hackrf"):
        return

    start_str = prompt("Start frequency (MHz)", "400")
    stop_str  = prompt("Stop frequency (MHz)",  "500")

    try:
        start_mhz = int(float(start_str))
        stop_mhz  = int(float(stop_str))
    except ValueError:
        err("Invalid frequency values.")
        return

    if start_mhz >= stop_mhz:
        err("Start must be less than stop.")
        return

    info(f"Sweeping {start_mhz}–{stop_mhz} MHz (Ctrl+C to stop)…")
    cmd = [
        "hackrf_sweep",
        "-f", f"{start_mhz}M:{stop_mhz}M",
        "-g", "20",
        "-w", "200000",
    ]
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=600)
        if rc not in (0, -2):
            warn(f"hackrf_sweep exited with code {rc}")
    except KeyboardInterrupt:
        info("Sweep interrupted.")


def op_firmware_update():
    heading("Firmware Update (SPI Flash)")
    info("Flash new firmware to the HackRF One SPI flash via hackrf_spiflash.")
    info("Firmware update steps:")
    info("  1. Download latest firmware from: https://github.com/greatscottgadgets/hackrf/releases")
    info("  2. File: hackrf_one_usb.bin (or .dfu for DFU mode)")
    info("  3. HackRF should be in normal USB mode (not DFU) for hackrf_spiflash")
    info("Troubleshooting firmware update:")
    info("  - 'HACKRF_ERROR_NOT_FOUND' → replug device and retry")
    info("  - After flash: HackRF will re-enumerate; wait 10s then run hackrf_info")
    info("  - Bricked? Enter DFU mode (hold DFU button on power-up) and use dfu-util")
    if not ensure_system_tool("hackrf_spiflash",
                              "sudo apt install hackrf  /  brew install hackrf",
                              apt_pkg="hackrf", brew_pkg="hackrf"):
        return

    fw_file = prompt("Path to firmware .bin file")
    if not fw_file:
        warn("No file specified.")
        return

    fw_path = Path(fw_file).expanduser()
    if not fw_path.exists():
        err(f"File not found: {fw_path}")
        return

    warn("Flashing firmware will overwrite the HackRF SPI flash.")
    if not confirm("Proceed with firmware update?", default=False):
        info("Cancelled.")
        return

    info(f"Flashing {fw_path.name}…")
    cmd = ["hackrf_spiflash", "-w", str(fw_path)]
    rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=120)
    if rc == 0:
        ok("Firmware flashed successfully. Replug the HackRF One.")
    else:
        warn(f"hackrf_spiflash exited with code {rc}")


# ── Firmware payload (main-page) ──────────────────────────────────────────────

def _hackrf_fw_dir() -> Path:
    return get_firmware_dir("hackrf_one")


def _find_hackrf_bin():
    """Newest downloaded/operator-supplied stock HackRF firmware bin, or None."""
    d = _hackrf_fw_dir()
    if not d.exists():
        return None
    bins = sorted(d.rglob("hackrf_one_usb.bin"))
    if bins:
        return bins[-1]
    other = sorted(d.glob("*.bin"))
    return other[-1] if other else None


def _download_hackrf_firmware():
    """Fetch the stock HackRF One firmware from the greatscottgadgets/hackrf
    release. Tries a direct hackrf_one_usb.bin asset, then the release tarball
    (extracting the prebuilt bin). Returns the bin Path or None.
    Source: https://github.com/greatscottgadgets/hackrf/releases"""
    d = _hackrf_fw_dir()
    d.mkdir(parents=True, exist_ok=True)

    url = get_github_release_asset_url("greatscottgadgets", "hackrf", "",
                                       r"hackrf_one_usb\.bin$")
    if url:
        dest = d / "hackrf_one_usb.bin"
        if download_firmware(url, dest, "HackRF One firmware"):
            return dest

    turl = get_github_release_asset_url("greatscottgadgets", "hackrf", "",
                                        r"hackrf-.*\.tar\.xz$")
    if turl:
        tar_dest = d / "hackrf-release.tar.xz"
        if download_firmware(turl, tar_dest, "HackRF release tarball"):
            try:
                import tarfile
                with tarfile.open(tar_dest) as tf:
                    for m in tf.getmembers():
                        if m.name.endswith("hackrf_one_usb.bin"):
                            m.name = "hackrf_one_usb.bin"
                            tf.extract(m, d)
                            return d / "hackrf_one_usb.bin"
                warn("hackrf_one_usb.bin not found inside the release tarball.")
            except Exception as e:
                warn(f"Could not extract firmware from tarball: {e}")
    return None


def _prep_hackrf_firmware() -> bool:
    """PREPARE step: ensure hackrf_spiflash is present and the stock firmware bin
    is downloaded so only the write remains. Returns True only when ready."""
    ready = True
    if not ensure_system_tool("hackrf_spiflash",
                              "sudo apt install hackrf  /  brew install hackrf",
                              apt_pkg="hackrf", brew_pkg="hackrf"):
        err("  hackrf_spiflash not available — cannot flash.")
        ready = False

    binf = _find_hackrf_bin() or _download_hackrf_firmware()
    if binf and Path(binf).exists():
        ok(f"  Firmware ready: {binf}")
    else:
        err("  Stock HackRF firmware could not be sourced automatically.")
        info(f"  Drop hackrf_one_usb.bin into: {_hackrf_fw_dir()}")
        info("  Source: https://github.com/greatscottgadgets/hackrf/releases")
        ready = False
    return ready


def _flash_hackrf_firmware():
    """FLASH step: reuse hackrf_spiflash -w (same writer as op_firmware_update)."""
    binf = _find_hackrf_bin()
    if not binf or not Path(binf).exists():
        err("Firmware bin missing at flash time — aborting.")
        return
    info(f"Flashing {Path(binf).name} via hackrf_spiflash…")
    cmd = ["hackrf_spiflash", "-w", str(binf)]
    rc = run_streaming(cmd, on_line=lambda l: info(l), timeout=120)
    if rc == 0:
        ok("Firmware flashed successfully. Replug the HackRF One.")
    else:
        warn(f"hackrf_spiflash exited with code {rc}")


def op_device_info_verbose():
    heading("Device Info — Verbose (all serials)")
    info("Lists all connected HackRF devices with serial numbers.")
    info("Useful when multiple HackRF devices are connected simultaneously.")
    if not ensure_system_tool("hackrf_info",
                              "sudo apt install hackrf  /  brew install hackrf",
                              apt_pkg="hackrf", brew_pkg="hackrf"):
        return
    rc = run_streaming(["hackrf_info", "-s"], on_line=lambda l: info(l), timeout=15)
    if rc != 0:
        warn(f"hackrf_info -s exited with code {rc}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    # Prefer apt packages on Kali/Debian/Ubuntu
    info("Checking apt packages: hackrf, python3-usb…")
    ensure_apt_packages(["hackrf", "python3-usb"])
    ensure_brew_packages(["hackrf"])

    # Optional pip: pyhackrf Python bindings (may not be in apt)
    info("Checking optional Python bindings (pyhackrf)…")
    ensure_pip_packages([("hackrf", "pyhackrf")])

    # Check udev rules
    info("Checking HackRF udev rules…")
    _check_udev_rules()

    # Detection
    detected = web_detect_loop(detect_hackrf, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not detected:
        err("HackRF One not detected. Exiting.")
        sys.exit(1)
    ok("HackRF One detected.")

    check_firmware_version()

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        run_firmware_payload(
            fw.get("label", "Firmware Update (hackrf_spiflash)"),
            info_fn=op_device_info,
            prepare_fn=_prep_hackrf_firmware,
            flash_fn=_flash_hackrf_firmware,
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                f"Firmware : {fw.get('firmware', 'Stock')} (hackrf_one_usb.bin)",
                "Flasher  : hackrf_spiflash -w (SPI flash, normal USB mode)",
                "NOTE     : This flashes STOCK HackRF firmware. PortaPack Mayhem",
                "           is a separate device/firmware and is NOT handled here.",
            ],
        )
        return

    MENU_OPTIONS = [
        "Device Info (hackrf_info)",
        "Receive IQ (save to file)",
        "Transmit IQ File",
        "Spectrum Sweep (hackrf_sweep)",
        "FIRMWARE - Firmware Update (hackrf_spiflash)",
        "Device Info Verbose (all serials)",
        "Exit",
    ]

    while True:
        choice = numbered_menu("HackRF One — Select Operation", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_receive_iq()
        elif choice == 2:
            op_transmit_iq()
        elif choice == 3:
            op_spectrum_sweep()
        elif choice == 4:
            op_firmware_update()
        elif choice == 5:
            op_device_info_verbose()
        elif choice == 6:
            ok("Goodbye.")
            sys.exit(0)


if __name__ == "__main__":
    if "--probe-fw-version" in sys.argv:
        import json
        _v = _get_current_version()
        print(json.dumps({
            "installed": bool(_v),
            "version": _v or None,
            "note": "hackrf_info firmware version." if _v
                    else "HackRF not detected (hackrf_info returned no version).",
        }))
        sys.exit(0)
    main()
