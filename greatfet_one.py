#!/usr/bin/env python3
"""
GreatFET One Tool Manager
Controls the GreatFET One hardware hacking platform via the greatfet Python library.
Supports GPIO, I2C, SPI, UART, ADC, LED control, firmware updates, and Facedancer USB emulation.

Usage:
    python3 greatfet_one.py
"""

import os
import subprocess
import sys
import time
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    WEB_MODE, wait_start, wait_status, wait_done, wait_timeout,
    detect_usb_libusb, ensure_apt_packages, ensure_pip_packages, ensure_system_tool,
    require_sudo, sudo_run,
    web_detect_loop, run_streaming,
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
)
import shutil

# ── Constants ──────────────────────────────────────────────────────────────────

TOOL_NAME   = "GreatFET One"
DESCRIPTION = "Hardware hacking platform — GPIO, I2C, SPI, UART, ADC, Facedancer USB emulation"

VID_NORMAL     = 0x1D50
PID_NORMAL     = 0x60E6
VID_DFU        = 0x1FC9
PID_DFU        = 0x000C

CONNECT_INSTRUCTIONS = (
    "GreatFET One not detected.\n\n"
    "  1. Connect GreatFET One CONTROL USB port to this computer\n"
    "  2. Install greatfet package: pip install greatfet facedancer --break-system-packages\n"
    "  3. Linux udev rules (from greatfet package):\n"
    "     pip show greatfet | grep Location\n"
    "     sudo cp <location>/greatfet/udev/50-greatfet.rules /etc/udev/rules.d/\n"
    "     sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "     (Use option 11 'Install udev Rules' to do this automatically)\n"
    "  4. macOS: brew install libusb  (if not already installed)\n\n"
    "  VID:PID 1D50:60E6\n\n"
    "  IMPORTANT: Firmware version must match Python package version.\n"
    "  Run option 2 (Update Firmware) after installing/upgrading the greatfet package.\n"
    "  Version mismatch is the most common cause of GreatFET errors.\n\n"
    "  J1A/J1B header pinout (outer rows):\n"
    "    J1A pin 1: 3.3V | J1A pin 2: GND\n"
    "    J1B pin 5: USB1 D+ | J1B pin 7: USB1 D- (for Facedancer)\n"
    "  Begonia add-on (Chipcon): connects to J2 expansion header"
)

FIRMWARE_MISMATCH_NOTE = (
    "Firmware version mismatch — the most common GreatFET issue:\n"
    "  The greatfet Python package version must match the firmware flashed on the device.\n"
    "  If you see 'GreatFETCommunicationError' or 'USB request failed', run:\n"
    "    gf fw --auto\n"
    "  or:\n"
    "    greatfet firmware --autoflash\n"
    "  This reflashes the firmware to match the installed Python package.\n\n"
    "  After firmware update, unplug and reconnect the GreatFET, then retry."
)

UDEV_NOTE = (
    "GreatFET udev rules:\n"
    "  The 50-greatfet.rules file is included in the greatfet Python package.\n"
    "  To install:\n"
    "    pip show greatfet | grep Location  (note the path)\n"
    "    sudo cp <path>/greatfet/udev/50-greatfet.rules /etc/udev/rules.d/\n"
    "    sudo udevadm control --reload-rules && sudo udevadm trigger\n"
    "    sudo usermod -aG plugdev $USER  (then log out/in)\n\n"
    "  Alternative minimal rule:\n"
    "    echo 'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"1d50\", ATTR{idProduct}==\"60e6\", MODE=\"0666\", GROUP=\"plugdev\"' \\\n"
    "      | sudo tee /etc/udev/rules.d/50-greatfet.rules"
)


# ── Detection ──────────────────────────────────────────────────────────────────

def detect_greatfet() -> bool:
    return detect_usb_libusb(VID_NORMAL, PID_NORMAL)


# ── Firmware version check ─────────────────────────────────────────────────────

def check_firmware_version():
    heading("Firmware Version Check")
    info("Reading GreatFET firmware version via 'greatfet info'…")
    current = None
    try:
        import subprocess as _sp
        result = _sp.run(
            ["greatfet", "info"],
            capture_output=True, text=True, timeout=15,
        )
        for line in (result.stdout + result.stderr).splitlines():
            if "firmware version" in line.lower():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current = parts[1].strip()
                    break
    except Exception as e:
        warn(f"Could not run 'greatfet info': {e}")

    if current:
        ok(f"Firmware version: {current}")
    else:
        info("Could not detect GreatFET firmware version automatically.")

    latest, url = check_latest_github_release("greatscottgadgets", "greatfet")
    if latest:
        announce_firmware_update(TOOL_NAME, current, latest, url)


# ── Device open helper ─────────────────────────────────────────────────────────

def _open_gf():
    """Import and open the first GreatFET. Returns gf instance or raises."""
    info("Opening GreatFET connection via greatfet library...")
    try:
        from greatfet import GreatFET  # type: ignore
    except ImportError:
        raise ImportError(
            "greatfet is not installed.\n"
            "  Install: pip install greatfet facedancer pyusb --break-system-packages"
        )
    return GreatFET()


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info():
    heading("Device Info")
    info("Reading GreatFET board info, firmware version, and serial number.")
    info("If this fails with a communication error, the firmware may need updating.")
    info(FIRMWARE_MISMATCH_NOTE)
    try:
        gf = _open_gf()
        try:
            info(f"Board name:       {gf.board_name()}")
            info(f"Board ID:         {gf.board_id()}")
            info(f"Firmware version: {gf.firmware_version()}")
            info(f"Serial number:    {gf.serial_number()}")
            ok("Device info retrieved.")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"Device info failed: {e}")
        info(FIRMWARE_MISMATCH_NOTE)


def _greatfet_flash_firmware():
    """Shared flash core: reflash the GreatFET firmware to match the installed
    greatfet Python package (via `gf fw --auto`, falling back to
    `greatfet firmware --autoflash`). Reused by the menu op and the payload."""
    info("Running: gf fw --auto")
    info("Expected: DFU mode entry, firmware download, reboot.")
    info("If the device disappears and reappears — that is normal behaviour.")
    try:
        run_streaming(
            ["gf", "fw", "--auto"],
            on_line=lambda l: info(l),
            timeout=120,
        )
        ok("Firmware update complete. Reconnect GreatFET if needed.")
    except FileNotFoundError:
        warn("'gf' CLI not found, trying 'greatfet firmware --autoflash'...")
        try:
            run_streaming(
                ["greatfet", "firmware", "--autoflash"],
                on_line=lambda l: info(l),
                timeout=120,
            )
            ok("Firmware update complete. Reconnect GreatFET if needed.")
        except Exception as e2:
            err(f"Firmware update failed: {e2}")
            info("Troubleshooting:")
            info("  - Ensure greatfet is installed: pip install greatfet --break-system-packages")
            info("  - Verify udev rules allow DFU mode access (VID 1FC9:000C)")
    except Exception as e:
        err(f"Firmware update failed: {e}")


def op_update_firmware():
    heading("Update Firmware")
    info("Reflashing the GreatFET firmware to match the installed Python package version.")
    info("This is required after installing or upgrading the greatfet pip package.")
    info("The device will reboot into DFU mode, flash, then reboot as normal GreatFET.")
    warn("This will flash firmware matching the installed greatfet Python package version.")
    if not confirm("Proceed with firmware update?", default=False):
        info("Cancelled.")
        return
    _greatfet_flash_firmware()


def _prep_greatfet_firmware() -> bool:
    """Firmware-payload PREPARE: ensure the greatfet package (which carries the
    matching firmware image flashed by `gf fw --auto`) is installed and the
    device is present. Returns True only when ready to flash."""
    ready = True
    if shutil.which("gf") is None and shutil.which("greatfet") is None:
        info("  GreatFET CLI not on PATH — installing the greatfet package…")
        ensure_pip_packages([("greatfet", "greatfet")])
    if shutil.which("gf") is None and shutil.which("greatfet") is None:
        err("  GreatFET CLI still unavailable — install it: "
            "pip install greatfet --break-system-packages")
        ready = False
    else:
        ok("  GreatFET firmware tooling present.")
    if not detect_greatfet():
        err("  GreatFET One not detected on USB — connect the CONTROL port before flashing.")
        ready = False
    else:
        ok("  GreatFET One detected.")
    return ready


# ── GPIO submenu ───────────────────────────────────────────────────────────────

def op_gpio():
    heading("GPIO Control")
    info("Controls GreatFET GPIO pins. Pins are referenced by (port, pin) number.")
    info("See GreatFET pinout: https://greatscottgadgets.com/greatfet/one/")
    GPIO_MENU = [
        "Set pin direction",
        "Write pin state",
        "Read pin state",
        "Back",
    ]
    while True:
        choice = numbered_menu("GPIO — Select Action", GPIO_MENU)
        if choice == 0:
            _gpio_set_direction()
        elif choice == 1:
            _gpio_write_pin()
        elif choice == 2:
            _gpio_read_pin()
        elif choice == 3:
            break


def _gpio_pin_prompt():
    port_str = prompt("Port number (e.g. 1)", "1")
    pin_str  = prompt("Pin number (e.g. 6)",  "6")
    try:
        return int(port_str), int(pin_str)
    except ValueError:
        err("Invalid port or pin.")
        return None, None


def _gpio_set_direction():
    heading("Set Pin Direction")
    port, pin = _gpio_pin_prompt()
    if port is None:
        return
    dir_choice = numbered_menu("Direction", ["Output", "Input"])
    try:
        gf = _open_gf()
        try:
            direction = gf.gpio.DIRECTION_OUT if dir_choice == 0 else gf.gpio.DIRECTION_IN
            gf.gpio.set_up_pin((port, pin), direction)
            dir_name = "OUTPUT" if dir_choice == 0 else "INPUT"
            ok(f"Pin ({port}, {pin}) set to {dir_name}.")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"GPIO direction failed: {e}")


def _gpio_write_pin():
    heading("Write Pin State")
    port, pin = _gpio_pin_prompt()
    if port is None:
        return
    state_str = prompt("State (0=LOW, 1=HIGH)", "1")
    try:
        state = int(state_str)
    except ValueError:
        err("Invalid state.")
        return
    try:
        gf = _open_gf()
        try:
            gf.gpio.set_up_pin((port, pin), gf.gpio.DIRECTION_OUT)
            gf.gpio.set_pin_state((port, pin), state)
            ok(f"Pin ({port}, {pin}) set to {'HIGH' if state else 'LOW'}.")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"GPIO write failed: {e}")


def _gpio_read_pin():
    heading("Read Pin State")
    port, pin = _gpio_pin_prompt()
    if port is None:
        return
    try:
        gf = _open_gf()
        try:
            gf.gpio.set_up_pin((port, pin), gf.gpio.DIRECTION_IN)
            state = gf.gpio.read_pin_state((port, pin))
            ok(f"Pin ({port}, {pin}) = {'HIGH (1)' if state else 'LOW (0)'}.")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"GPIO read failed: {e}")


# ── I2C submenu ────────────────────────────────────────────────────────────────

def op_i2c():
    heading("I2C Operations")
    info("GreatFET I2C uses the dedicated I2C pins on J1A.")
    info("  I2C0 SDA: J1A pin 15 | I2C0 SCL: J1A pin 16")
    I2C_MENU = [
        "Scan bus",
        "Write bytes",
        "Read bytes",
        "Back",
    ]
    while True:
        choice = numbered_menu("I2C — Select Action", I2C_MENU)
        if choice == 0:
            _i2c_scan()
        elif choice == 1:
            _i2c_write()
        elif choice == 2:
            _i2c_read()
        elif choice == 3:
            break


def _i2c_scan():
    heading("I2C Bus Scan")
    info("Scanning I2C bus for devices at addresses 0x00-0x7F...")
    try:
        gf = _open_gf()
        try:
            gf.i2c.init(speed=100000)
            devices = gf.i2c.scan()
            if devices:
                ok(f"Found {len(devices)} device(s):")
                for addr in devices:
                    info(f"  0x{addr:02X} ({addr})")
            else:
                warn("No I2C devices found.")
                info("Check SDA/SCL wiring and pull-up resistors (4.7kΩ to 3.3V).")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"I2C scan failed: {e}")


def _i2c_write():
    heading("I2C Write")
    addr_str = prompt("Device address (hex, e.g. 3C)", "3C")
    data_str = prompt("Hex bytes to write (e.g. 00AF)", "")
    try:
        addr = int(addr_str, 16)
        data = bytes.fromhex(data_str.replace(" ", ""))
    except ValueError:
        err("Invalid address or hex bytes.")
        return
    try:
        gf = _open_gf()
        try:
            gf.i2c.init(speed=100000)
            gf.i2c.write(addr, data)
            ok(f"Wrote {len(data)} byte(s) to 0x{addr:02X}.")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"I2C write failed: {e}")


def _i2c_read():
    heading("I2C Read")
    addr_str = prompt("Device address (hex, e.g. 3C)", "3C")
    count_str = prompt("Number of bytes to read", "2")
    try:
        addr  = int(addr_str, 16)
        count = int(count_str)
    except ValueError:
        err("Invalid address or count.")
        return
    try:
        gf = _open_gf()
        try:
            gf.i2c.init(speed=100000)
            data = gf.i2c.read(addr, count)
            hex_str = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
            ok(f"Read from 0x{addr:02X}: {hex_str}")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"I2C read failed: {e}")


# ── SPI transfer ───────────────────────────────────────────────────────────────

def op_spi_transfer():
    heading("SPI Transfer")
    info("GreatFET SPI0 pins: MOSI=J2 pin 4, MISO=J2 pin 6, SCK=J2 pin 8, CS=J2 pin 10")
    data_str = prompt("Hex bytes to transfer (e.g. 9F000000)", "9F000000")
    try:
        data = bytes.fromhex(data_str.replace(" ", ""))
    except ValueError:
        err("Invalid hex bytes.")
        return
    try:
        gf = _open_gf()
        try:
            gf.spi.init(speed=1000000, cpol=0, cpha=0)
            response = gf.spi.transfer(data)
            resp_hex = response.hex() if isinstance(response, (bytes, bytearray)) else str(response)
            ok(f"SPI response: {resp_hex}")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"SPI transfer failed: {e}")


# ── UART terminal ──────────────────────────────────────────────────────────────

def op_uart_terminal():
    heading("UART Terminal")
    info("GreatFET UART0 pins: TX=J1B pin 25, RX=J1B pin 27")
    baud_str = prompt("Baud rate", "115200")
    try:
        baud = int(baud_str)
    except ValueError:
        err("Invalid baud rate.")
        return

    warn("UART terminal is limited in web mode. For full interactive use, open a Shell tab.")
    send_str = prompt("Bytes to send (hex, e.g. 48656C6C6F0D0A)", "48656C6C6F0D0A")
    try:
        send_data = bytes.fromhex(send_str.replace(" ", ""))
    except ValueError:
        err("Invalid hex bytes.")
        return

    try:
        gf = _open_gf()
        try:
            gf.uart.init(baud_rate=baud)
            gf.uart.write(send_data)
            ok(f"Sent {len(send_data)} byte(s).")
            time.sleep(0.2)
            data = gf.uart.read()
            if data:
                recv_hex = data.hex() if isinstance(data, (bytes, bytearray)) else str(data)
                info(f"Received: {recv_hex}")
            else:
                info("No data received.")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"UART operation failed: {e}")


# ── ADC read ───────────────────────────────────────────────────────────────────

def op_adc_read():
    heading("ADC Read")
    info("GreatFET ADC input: J2 pin 3 (ADC0_0), Vref=3.3V, 12-bit resolution.")
    info("Maximum input voltage: 3.3V — do not exceed this or damage may occur.")
    try:
        gf = _open_gf()
        try:
            samples = gf.adc.read_samples(1)
            if samples:
                raw = samples[0] if isinstance(samples, (list, tuple)) else samples
                # GreatFET ADC is 12-bit, Vref ~3.3 V
                try:
                    voltage = (int(raw) / 4095.0) * 3.3
                    info(f"Raw ADC value: {raw}")
                    ok(f"Estimated voltage: {voltage:.3f} V  (Vref=3.3V, 12-bit)")
                except Exception:
                    ok(f"ADC samples: {samples}")
            else:
                warn("No samples returned.")
        finally:
            try:
                gf.close()
            except Exception:
                pass
    except Exception as e:
        err(f"ADC read failed: {e}")


# ── LED control ────────────────────────────────────────────────────────────────

def op_led_control():
    heading("LED Control")
    info("GreatFET One has 4 user-controllable LEDs (LED1-LED4) on the board.")
    LED_MENU = ["LED 1", "LED 2", "LED 3", "LED 4", "Back"]
    ACTION_MENU = ["On", "Off", "Toggle"]

    while True:
        led_choice = numbered_menu("Select LED", LED_MENU)
        if led_choice == 4:
            break
        led_index = led_choice + 1  # 1-based

        action_choice = numbered_menu(f"LED {led_index} — Action", ACTION_MENU)
        try:
            gf = _open_gf()
            try:
                led = gf.leds[led_index]
                if action_choice == 0:
                    led.on()
                    ok(f"LED {led_index} turned ON.")
                elif action_choice == 1:
                    led.off()
                    ok(f"LED {led_index} turned OFF.")
                elif action_choice == 2:
                    led.toggle()
                    ok(f"LED {led_index} toggled.")
            finally:
                try:
                    gf.close()
                except Exception:
                    pass
        except Exception as e:
            err(f"LED control failed: {e}")


# ── Chipcon programming info ───────────────────────────────────────────────────

def op_chipcon_info():
    heading("Chipcon Programming (CC1111/YS1)")
    info("Chipcon programming (CC1111, CC2540, CC2541) requires the Begonia neighbor board.")
    info("Begonia connects to GreatFET's J2 expansion header and provides the Chipcon debug wires.")
    info("")
    info("Begonia board:")
    info("  - Provides 2-wire debug interface (C2CK/C2D) for CC-series chips")
    info("  - Compatible with CC1111, CC2540, CC2541 (used in HackRF and YardStick One)")
    info("")
    info("Example commands (with Begonia attached):")
    info("  gf chipcon-spi  --help")
    info("  gf chipcon-spi  --identify             (read chip ID)")
    info("  gf chipcon-spi  --read-flash output.bin  (dump firmware)")
    info("  gf chipcon-spi  --write-flash firmware.bin  (flash firmware)")
    info("")
    info("More info: https://greatscottgadgets.com/greatfet/begonia/")
    pause()


# ── Facedancer USB emulation ───────────────────────────────────────────────────

def op_facedancer():
    heading("Facedancer USB Emulation")
    info("GreatFET's USB1 port acts as the TARGET port — the host under test sees")
    info("the emulated USB device on that port.")
    info("  USB1 D+: J1B pin 5 | USB1 D-: J1B pin 7")
    info("Connect USB1 to the target host you wish to emulate a USB device on.")
    info("")
    info("BACKEND=greatfet is set automatically. Your script must use standard Facedancer API.")
    info("Example scripts: https://github.com/greatscottgadgets/facedancer/tree/main/facedancer/devices")
    info("")

    script_path = prompt("Path to Facedancer script (.py)", default="")
    if not script_path:
        warn("No script path entered.")
        return

    p = Path(script_path).expanduser()
    if not p.exists():
        err(f"File not found: {p}")
        return

    info(f"Running Facedancer script: {p}")
    info("Troubleshooting Facedancer on GreatFET:")
    info("  - 'Backend not found': ensure BACKEND=greatfet is set")
    info("  - 'USB device not responding': check USB1 cable and target host")
    info("  - Firmware version mismatch may cause Facedancer errors — update firmware first")
    env = {**os.environ, "BACKEND": "greatfet"}
    try:
        proc = subprocess.Popen(
            ["python3", str(p)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            info(line.rstrip())
        proc.wait()
        if proc.returncode == 0:
            ok("Facedancer script finished.")
        else:
            warn(f"Facedancer script exited with code {proc.returncode}.")
    except Exception as e:
        err(f"Facedancer launch failed: {e}")


# ── Install udev rules (Linux) ─────────────────────────────────────────────────

def op_install_udev():
    heading("Install udev Rules (Linux)")
    if get_os() != "linux":
        warn("udev rules only apply on Linux.")
        return

    info("The greatfet package ships udev rules in its package directory.")
    info(UDEV_NOTE)

    try:
        location = run_output(["pip", "show", "greatfet"])
        pkg_location = None
        for line in location.splitlines():
            if line.startswith("Location:"):
                pkg_location = line.split(":", 1)[1].strip()
                break

        if not pkg_location:
            err("Could not determine greatfet package location via 'pip show greatfet'.")
            info("Locate it manually: pip show greatfet | grep Location")
            return

        rules_src = Path(pkg_location) / "greatfet" / "udev" / "50-greatfet.rules"
        if not rules_src.exists():
            err(f"udev rules file not found at: {rules_src}")
            info("Locate it manually: find $(pip show greatfet | grep Location | cut -d' ' -f2) -name '*.rules'")
            return

        rules_dst = Path("/etc/udev/rules.d/50-greatfet.rules")
        info(f"Source: {rules_src}")
        info(f"Destination: {rules_dst}")

        if not confirm("Copy rules with sudo and reload udevadm?", default=True):
            info("Cancelled.")
            return

        r = sudo_run(f"cp {rules_src} {rules_dst} && udevadm control --reload-rules && udevadm trigger")
        if r.returncode == 0:
            ok("udev rules installed. Reconnect GreatFET to apply.")
        else:
            err("sudo copy or udevadm failed.")
            err((r.stdout + r.stderr).strip()[:300])
    except Exception as e:
        err(f"udev install failed: {e}")


# ── Main ───────────────────────────────────────────────────────────────────────

MENU_OPTIONS = [
    "Device Info",
    "Update Firmware",
    "GPIO Control",
    "I2C Operations",
    "SPI Transfer",
    "UART Terminal",
    "ADC Read",
    "LED Control",
    "Chipcon Programming (CC1111/YS1) — Begonia board",
    "Facedancer USB Emulation",
    "Install udev Rules (Linux)",
    "Exit",
]


def main():
    require_sudo()

    info("Checking and installing required packages...")
    info("APT package: python3-usb (pyusb for USB detection)")
    ensure_apt_packages(["python3-usb"])

    info("PIP packages: greatfet (hardware control library), facedancer (USB emulation),")
    info("  pyusb (USB access) — not all available in apt")
    ensure_pip_packages([
        ("greatfet",  "greatfet"),
        ("facedancer","facedancer"),
        ("usb.core",  "pyusb"),
    ])

    if get_os_flavor() in ("kali", "debian", "ubuntu", "linux"):
        info("Linux udev note for GreatFET:")
        info(UDEV_NOTE)

    print_banner(TOOL_NAME, DESCRIPTION)

    detected = web_detect_loop(detect_greatfet, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not detected:
        err("GreatFET One not detected. Exiting.")
        sys.exit(1)
    ok("GreatFET One detected.")

    check_firmware_version()

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        run_firmware_payload(
            fw.get("label", "Update Firmware"),
            info_fn=op_device_info,
            prepare_fn=_prep_greatfet_firmware,
            flash_fn=_greatfet_flash_firmware,
            summary_lines=[
                f"Board    : {TOOL_NAME}",
                f"Firmware : {fw.get('firmware', 'greatfet')} (matches installed greatfet package)",
                "Flasher  : gf fw --auto (DFU) — falls back to greatfet firmware --autoflash",
            ],
        )
        return

    while True:
        choice = numbered_menu("GreatFET One — Select Operation", MENU_OPTIONS)

        if choice == 0:
            op_device_info()
        elif choice == 1:
            op_update_firmware()
        elif choice == 2:
            op_gpio()
        elif choice == 3:
            op_i2c()
        elif choice == 4:
            op_spi_transfer()
        elif choice == 5:
            op_uart_terminal()
        elif choice == 6:
            op_adc_read()
        elif choice == 7:
            op_led_control()
        elif choice == 8:
            op_chipcon_info()
        elif choice == 9:
            op_facedancer()
        elif choice == 10:
            op_install_udev()
        elif choice == 11:
            ok("Goodbye.")
            sys.exit(0)


if __name__ == "__main__":
    main()
