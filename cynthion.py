#!/usr/bin/env python3
"""
Cynthion Tool Manager
Handles firmware updates, FPGA bitstream loading, and Facedancer USB emulation.

USB VID:PID: 0x1D50:0x615C  (Apollo SAMD21 control interface)

Usage:
    python3 cynthion.py
"""

import os
import sys
import subprocess

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    find_serial_port_by_vidpid, detect_usb_libusb, detect_usb_libusb_any,
    ensure_apt_packages, ensure_pip_packages, ensure_system_tool,
    require_sudo, sudo_run,
    web_detect_loop, run_streaming,
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
)
import shutil

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "Cynthion"
DESCRIPTION = "Great Scott Gadgets Cynthion — USB multitool and Facedancer platform"

VID = 0x1D50
PID = 0x615C

CONNECT_INSTRUCTIONS = (
    "Cynthion not detected.\n\n"
    "  1. Connect Cynthion CONTROL port (USB-C) to this computer\n"
    "     NOT the TARGET-A or TARGET-C ports\n"
    "     CONTROL port is the one closest to the Apollo SAMD21 MCU (see board silkscreen)\n"
    "  2. Install software: pip install cynthion apollo-fpga facedancer --break-system-packages\n"
    "  3. Linux: install udev rules:\n"
    "     cynthion setup\n"
    "     sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "     Or add manually:\n"
    "       echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1d50\", ATTR{idProduct}==\"615c\", MODE=\"0666\", GROUP=\"plugdev\"' \\\n"
    "         | sudo tee /etc/udev/rules.d/99-cynthion.rules\n"
    "  4. macOS: no driver needed, libusb accesses directly\n\n"
    "  VID:PID 1D50:615C (Apollo SAMD21 control interface)\n\n"
    "  Board notes:\n"
    "    - CONTROL USB-C: used for firmware/bitstream updates and Facedancer host\n"
    "    - TARGET-A USB-A: emulated USB device port (plug into host under test)\n"
    "    - TARGET-C USB-C: second emulated USB device port\n"
    "    - FPGA: Lattice ECP5, used for USB PHY and LUNA gateware"
)

UDEV_NOTE = (
    "Cynthion udev rule for Linux (VID 1D50:615C):\n"
    "  echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1d50\", ATTR{idProduct}==\"615c\", MODE=\"0666\", GROUP=\"plugdev\"' \\\n"
    "    | sudo tee /etc/udev/rules.d/99-cynthion.rules\n"
    "  sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "  sudo usermod -aG plugdev $USER  (then log out/in)\n\n"
    "Alternatively, run 'cynthion setup' which installs udev rules automatically."
)

# ── Facedancer example scripts (inline) ───────────────────────────────────────

_FACEDANCER_HID_KBD = """\
import os
os.environ['BACKEND'] = 'cynthion'
from facedancer import main
from facedancer.devices.keyboard import USBKeyboardDevice
main(USBKeyboardDevice())
"""

_FACEDANCER_HID_MOUSE = """\
import os
os.environ['BACKEND'] = 'cynthion'
from facedancer import main
from facedancer.devices.mouse import USBMouseDevice
main(USBMouseDevice())
"""

_FACEDANCER_MSC = """\
import os
os.environ['BACKEND'] = 'cynthion'
from facedancer import main
from facedancer.devices.mass_storage import USBMassStorageDevice
main(USBMassStorageDevice())
"""

# ── Detection ─────────────────────────────────────────────────────────────────

def detect_cynthion() -> bool:
    return detect_usb_libusb(VID, PID)


# ── Firmware version check ────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("Reading Cynthion firmware version via 'cynthion info'…")
    current = None
    try:
        import subprocess as _sp
        result = _sp.run(
            ["cynthion", "info", "--force-offline"],
            capture_output=True, text=True, timeout=15,
        )
        for line in (result.stdout + result.stderr).splitlines():
            low = line.lower()
            if "firmware" in low and ("version" in low or ":" in low):
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    current = parts[1].strip()
                    break
    except Exception as e:
        warn(f"Could not run 'cynthion info': {e}")

    if current:
        ok(f"Firmware version: {current}")
    else:
        info("Could not detect Cynthion firmware version automatically.")

    latest, url = check_latest_github_release("greatscottgadgets", "cynthion")
    if latest:
        announce_firmware_update(TOOL_NAME, current, latest, url)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_cynthion_streaming(args: list, timeout: int = 60) -> int:
    cmd = ["cynthion"] + args
    info(f"Running: {' '.join(cmd)}")
    return run_streaming(cmd, on_line=lambda l: info(l), timeout=timeout)


def _run_facedancer_inline(script_code: str, label: str):
    """Run an inline Facedancer script via subprocess with BACKEND=cynthion."""
    import tempfile, pathlib
    info(f"Starting Facedancer: {label} (Ctrl-C to stop)...")
    info("Plug the TARGET-A or TARGET-C port into the host under test.")
    info("The host will see the emulated USB device appear on that port.")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, prefix="cynthion_fd_"
    ) as f:
        f.write(script_code)
        tmp_path = f.name
    env = {**os.environ, "BACKEND": "cynthion"}
    try:
        proc = subprocess.Popen(
            [sys.executable, tmp_path],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            info(line.rstrip())
        proc.wait()
        if proc.returncode == 0:
            ok(f"{label} session ended.")
        else:
            warn(f"{label} exited with code {proc.returncode}.")
    except KeyboardInterrupt:
        info(f"{label} stopped by user.")
        try:
            proc.terminate()
        except Exception:
            pass
    except FileNotFoundError:
        err("python3 not found in PATH.")
    finally:
        try:
            pathlib.Path(tmp_path).unlink()
        except Exception:
            pass


def _run_facedancer_script(script_path: str):
    """Run a user-supplied Facedancer .py script with BACKEND=cynthion."""
    env = {**os.environ, "BACKEND": "cynthion"}
    info(f"Running: python3 {script_path}  [BACKEND=cynthion]")
    info("Facedancer will emulate the USB device defined in the script on TARGET-A/C port.")
    try:
        proc = subprocess.Popen(
            [sys.executable, script_path],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            info(line.rstrip())
        proc.wait()
        if proc.returncode == 0:
            ok("Facedancer script completed.")
        else:
            warn(f"Script exited with code {proc.returncode}.")
    except KeyboardInterrupt:
        info("Script stopped by user.")
        try:
            proc.terminate()
        except Exception:
            pass
    except FileNotFoundError:
        err("python3 not found in PATH.")


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Reading Cynthion device info via 'cynthion info'.")
    info("Expected: firmware version, FPGA bitstream version, hardware revision.")
    info("The --force-offline flag reads info without connecting to the FPGA gateware.")
    rc = run_streaming(
        ["cynthion", "info", "--force-offline"],
        on_line=lambda l: info(l),
        timeout=30,
    )
    if rc == 0:
        ok("Device info retrieved.")
    else:
        warn(f"cynthion info exited with code {rc}.")
        info("Troubleshooting: ensure udev rules are installed and device is on CONTROL port.")


def op_update_firmware():
    heading("Update Firmware")
    info("This updates both the Apollo SAMD21 MCU firmware and the FPGA bitstream.")
    info("The update downloads the latest firmware from PyPI package metadata.")
    info("Device will reboot after update — reconnect if needed.")
    info("Expected duration: ~60-120 seconds.")
    if not confirm("Proceed with full firmware update?", default=True):
        info("Update cancelled.")
        return
    info("Running: cynthion update")
    info("Troubleshooting firmware update:")
    info("  - 'No device found': ensure CONTROL port is connected")
    info("  - 'DFU error': try power-cycling the device and retry")
    info("  - If update hangs: Ctrl-C, power-cycle Cynthion, retry")
    rc = _run_cynthion_streaming(["update"], timeout=300)
    if rc == 0:
        ok("Firmware update complete.")
        info("Reconnect CONTROL USB if device is not detected after update.")
    else:
        err(f"cynthion update exited with code {rc}.")


def op_update_mcu_only():
    heading("Update MCU Firmware Only")
    info("Updates only the Apollo SAMD21 MCU firmware, not the FPGA bitstream.")
    info("Use this if the FPGA bitstream is already correct but MCU firmware needs updating.")
    if not confirm("Update MCU firmware only (no FPGA bitstream)?", default=True):
        info("Cancelled.")
        return
    rc = _run_cynthion_streaming(["update", "--mcu-firmware"], timeout=180)
    if rc == 0:
        ok("MCU firmware update complete.")
    else:
        err(f"cynthion update --mcu-firmware exited with code {rc}.")


def op_update_bitstream():
    heading("Update FPGA Bitstream")
    info("Updates only the FPGA (ECP5) bitstream — the gateware that implements USB functionality.")
    info("The FPGA bitstream is stored in SPI flash and loaded at boot.")
    info("Use this to update LUNA gateware without changing the MCU firmware.")
    if not confirm("Update FPGA bitstream only?", default=True):
        info("Cancelled.")
        return
    info("Troubleshooting bitstream update:")
    info("  - 'FPGA configuration failed': check USB connection and try again")
    info("  - After bitstream update, FPGA will re-enumerate — wait a few seconds")
    rc = _run_cynthion_streaming(["update", "--bitstream"], timeout=180)
    if rc == 0:
        ok("FPGA bitstream update complete.")
    else:
        err(f"cynthion update --bitstream exited with code {rc}.")


def op_load_custom_bitstream():
    heading("Load Custom Bitstream")
    info("Loads a custom .bit bitstream file directly into the FPGA via the Apollo interface.")
    info("This is a volatile load — the custom bitstream is NOT stored in flash.")
    info("The stock bitstream will reload on next power cycle.")
    info("Use this for testing custom LUNA gateware without flashing to SPI.")
    bit_path = prompt("Path to .bit bitstream file")
    if not bit_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(bit_path).exists():
        err(f"File not found: {bit_path}")
        return
    info(f"Loading bitstream: {bit_path}")
    info("Running: apollo configure <bitstream>")
    info("Troubleshooting:")
    info("  - 'FPGA configuration error': check bitstream format (ECP5 .bit file)")
    info("  - 'No device': ensure CONTROL USB is connected")
    rc = run_streaming(
        ["apollo", "configure", bit_path],
        on_line=lambda l: info(l),
        timeout=60,
    )
    if rc == 0:
        ok("Bitstream loaded.")
    else:
        err(f"apollo configure exited with code {rc}.")


def op_install_udev():
    heading("Install udev Rules (Linux)")
    if get_os() != "linux":
        warn("udev rules are only applicable on Linux.")
        return
    info("Installing Cynthion udev rules via 'cynthion setup'.")
    info("This creates rules that allow non-root access to the Cynthion USB device.")
    info(UDEV_NOTE)
    if not confirm("Run 'cynthion setup' to install udev rules?", default=True):
        info("Cancelled.")
        return
    rc = run_streaming(["cynthion", "setup"], on_line=lambda l: info(l), timeout=30)
    if rc == 0:
        info("Reloading udev rules...")
        r = sudo_run("udevadm control --reload-rules && udevadm trigger")
        if r.returncode == 0:
            ok("udev rules installed and reloaded.")
        else:
            warn("udev rules installed but reload failed. Run manually:")
            warn("  sudo udevadm control --reload-rules")
        info("Unplug and reconnect the Cynthion CONTROL port.")
    else:
        err(f"cynthion setup exited with code {rc}.")
        info("Try installing the rule manually:")
        info(UDEV_NOTE)


def op_run_facedancer_script():
    heading("Run Facedancer Script")
    info("Facedancer turns the Cynthion into a USB device emulator.")
    info("Your script defines the USB device descriptor and behavior.")
    info("Connect TARGET-A or TARGET-C to the host you want to emulate a device on.")
    script_path = prompt("Path to Facedancer .py script")
    if not script_path:
        warn("No path provided. Aborting.")
        return
    import pathlib
    if not pathlib.Path(script_path).exists():
        err(f"File not found: {script_path}")
        return
    _run_facedancer_script(script_path)


def op_usb_emulation():
    heading("USB Emulation")
    info("Select a built-in Facedancer device type to emulate via Cynthion TARGET-A/C port.")
    info("The emulated device will appear to the connected host as a real USB device.")
    info("Troubleshooting Facedancer USB emulation:")
    info("  - 'Backend not found': ensure BACKEND=cynthion is set (handled automatically here)")
    info("  - 'Device not recognized': try a different TARGET port or USB cable")
    info("  - 'Permission denied' on host: check host-side udev rules for the emulated device")
    sub_options = [
        "HID Keyboard",
        "HID Mouse",
        "Mass Storage",
        "Cancel",
    ]
    choice = numbered_menu("USB Emulation — Device Type", sub_options)

    if choice == 0:
        _run_facedancer_inline(_FACEDANCER_HID_KBD, "HID Keyboard")
    elif choice == 1:
        _run_facedancer_inline(_FACEDANCER_HID_MOUSE, "HID Mouse")
    elif choice == 2:
        _run_facedancer_inline(_FACEDANCER_MSC, "Mass Storage")
    elif choice == 3:
        info("Cancelled.")


# ── Firmware payload wiring ────────────────────────────────────────────────────

def _prep_cynthion_firmware() -> bool:
    """Firmware-payload PREPARE: make sure the `cynthion` tooling (which fetches
    the firmware/bitstream from its packaged metadata at update time) is present
    and the device is on the CONTROL port. Returns True only when ready.
    The vendor `cynthion update` CLI downloads the actual images itself."""
    ok_ready = True
    if shutil.which("cynthion") is None:
        info("  'cynthion' CLI not on PATH — installing the update tooling…")
        ensure_pip_packages([
            ("cynthion",    "cynthion"),
            ("apollo_fpga", "apollo-fpga"),
        ])
    if shutil.which("cynthion") is None:
        err("  'cynthion' CLI still unavailable — install it: "
            "pip install cynthion apollo-fpga --break-system-packages")
        ok_ready = False
    else:
        ok("  'cynthion' update tooling present.")
    if not detect_cynthion():
        err("  Cynthion not detected on the CONTROL port — connect it before flashing.")
        ok_ready = False
    else:
        ok("  Cynthion detected on the CONTROL port.")
    return ok_ready


def _dispatch_firmware_payload(fw: dict):
    """Route the selected firmware payload to the right Cynthion update path,
    reusing the module's existing `cynthion update` streaming helper."""
    which = (fw.get("firmware") or "").strip().lower()
    label = fw.get("label", "Update Firmware")
    if which in ("mcu", "mcu-only", "mcu_firmware"):
        run_firmware_payload(
            label,
            info_fn=op_device_info,
            prepare_fn=_prep_cynthion_firmware,
            flash_fn=lambda: _run_cynthion_streaming(["update", "--mcu-firmware"], timeout=180),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : Apollo SAMD21 MCU only (no FPGA bitstream)",
                "Flasher  : cynthion update --mcu-firmware",
            ],
        )
    else:
        run_firmware_payload(
            label,
            info_fn=op_device_info,
            prepare_fn=_prep_cynthion_firmware,
            flash_fn=lambda: _run_cynthion_streaming(["update"], timeout=300),
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                "Firmware : Apollo SAMD21 MCU + ECP5 FPGA bitstream",
                "Flasher  : cynthion update",
            ],
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    info("Checking and installing required packages...")
    info("APT package: python3-usb (pyusb for USB detection)")
    ensure_apt_packages(["python3-usb"])

    info("PIP packages: cynthion (firmware update CLI), apollo-fpga (FPGA control),")
    info("  facedancer (USB emulation framework) — not available in apt")
    ensure_pip_packages([
        ("cynthion",    "cynthion"),
        ("apollo_fpga", "apollo-fpga"),
        ("facedancer",  "facedancer"),
        ("usb",         "pyusb"),
    ])

    if get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        info("Linux udev note for Cynthion:")
        info(UDEV_NOTE)

    print_banner(TOOL_NAME, DESCRIPTION)

    found = web_detect_loop(detect_cynthion, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("Cynthion not detected. Exiting.")
        sys.exit(1)

    ok("Cynthion detected (Apollo SAMD21 control interface).")

    check_firmware_version()

    # Firmware payload selected on the main page → auto-run (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw)
        return

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Update Firmware (MCU + FPGA)",
        "FIRMWARE - Update MCU Firmware Only",
        "Update FPGA Bitstream",
        "Load Custom Bitstream",
        "Install udev Rules (Linux)",
        "Run Facedancer Script",
        "USB Emulation",
        "Exit",
    ]

    while True:
        choice = numbered_menu("Cynthion — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_update_firmware()
        elif choice == 2:
            op_update_mcu_only()
        elif choice == 3:
            op_update_bitstream()
        elif choice == 4:
            op_load_custom_bitstream()
        elif choice == 5:
            op_install_udev()
        elif choice == 6:
            op_run_facedancer_script()
        elif choice == 7:
            op_usb_emulation()
        elif choice == 8:
            info("Goodbye.")
            break


if __name__ == "__main__":
    main()
