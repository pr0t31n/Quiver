#!/usr/bin/env python3
"""
ESP32-D Tool Manager
Handles device info, firmware flashing, MicroPython installation, and script upload
for generic ESP32-D development boards (ESP32-D0WD, ESP32-D0WDQ6, etc.).

Common USB-serial bridges on ESP32-D boards:
  CP2102 / CP2104 — VID:PID 10C4:EA60  (Silicon Labs)
  CH340G / CH340C — VID:PID 1A86:7523 / 1A86:7522
  CH9102          — VID:PID 1A86:55D4
  FT232RL         — VID:PID 0403:6001  (FTDI, some clones)

Linux serial access:
  The ESP32 USB-serial adapters appear as /dev/ttyUSB* (CH340/FT232) or
  /dev/ttyACM* (CP2102 on some kernels).  If you get 'Permission denied',
  run: sudo usermod -aG dialout $USER  then log out and back in.

Usage:
    python3 esp32d.py
"""

import subprocess
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
    web_detect_loop, run_streaming,
    check_latest_github_release, announce_firmware_update,
    selected_firmware_payload, run_firmware_payload,
    get_firmware_dir, get_github_release_asset_url, download_firmware,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "ESP32-D"
DESCRIPTION = "Generic ESP32-D dual-core development board (Xtensa LX6)"

VID_PIDS = [
    (0x10C4, 0xEA60),   # CP2102 / CP2104 (Silicon Labs)
    (0x1A86, 0x7523),   # CH340G
    (0x1A86, 0x7522),   # CH340C
    (0x1A86, 0x55D4),   # CH9102
    (0x0403, 0x6001),   # FTDI FT232RL
]

ESP_CHIP = "esp32"

CONNECT_INSTRUCTIONS = (
    "ESP32-D not detected.\n\n"
    "  1. Connect the board via USB cable\n"
    "  2. The device uses one of these USB-serial chips:\n"
    "       CP2102/CP2104 — VID:PID 10C4:EA60  (most common)\n"
    "       CH340G/CH340C — VID:PID 1A86:7523 or 1A86:7522\n"
    "       CH9102        — VID:PID 1A86:55D4\n"
    "       FT232RL       — VID:PID 0403:6001\n\n"
    "  3. Linux driver notes (should auto-load):\n"
    "       CP210x:  sudo modprobe cp210x\n"
    "       CH340:   sudo modprobe ch341\n"
    "       FT232:   sudo modprobe ftdi_sio\n\n"
    "  4. Permission issues:\n"
    "       Check: ls -la /dev/ttyUSB*  or  ls -la /dev/ttyACM*\n"
    "       Fix:   sudo usermod -aG dialout $USER  (then log out/in)\n"
    "       Quick: sudo chmod 666 /dev/ttyUSB0\n\n"
    "  5. macOS: CP2102 and CH340 drivers may need manual install:\n"
    "       CP2102: https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers\n"
    "       CH340:  https://github.com/adrianmihalko/ch340g-ch34g-ch34x-mac-os-x-driver\n"
    "       FT232:  https://ftdichip.com/drivers/vcp-drivers/"
)

# udev rules covering all common ESP32 USB-serial chips
UDEV_RULES_CONTENT = """\
# ESP32-D USB-serial chip udev rules
# CP2102 / CP2104 (VID:PID 10C4:EA60)
SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", MODE="0666", GROUP="dialout"
# CH340G (VID:PID 1A86:7523)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7523", MODE="0666", GROUP="dialout"
# CH340C (VID:PID 1A86:7522)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7522", MODE="0666", GROUP="dialout"
# CH9102 (VID:PID 1A86:55D4)
SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="55d4", MODE="0666", GROUP="dialout"
# FTDI FT232RL (VID:PID 0403:6001)
SUBSYSTEM=="tty", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6001", MODE="0666", GROUP="dialout"
"""
UDEV_RULES_PATH = "/etc/udev/rules.d/60-esp32d.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules ────────────────────────────────────────────────────────────────

def _check_udev_rules():
    flavor = get_os_flavor()
    if flavor not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for ESP32 USB-serial chips (CP210x, CH340, FT232)…")
    info("This allows non-root access to /dev/ttyUSB* and /dev/ttyACM* devices.")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules 2>/dev/null")
        sudo_run("udevadm trigger 2>/dev/null")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the ESP32-D to apply new permissions.")
    else:
        warn("Could not write udev rules automatically.")
        info(f"Manual fix: sudo tee {UDEV_RULES_PATH} << 'EOF'")
        info(UDEV_RULES_CONTENT)
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")
    # Load kernel modules
    for mod in ("cp210x", "ch341", "ftdi_sio"):
        out = run_output(f"lsmod 2>/dev/null | grep {mod}")
        if out:
            ok(f"Kernel module '{mod}' is loaded.")
        else:
            info(f"Loading kernel module '{mod}'…")
            r2 = sudo_run(f"modprobe {mod} 2>/dev/null")
            if r2.returncode == 0:
                ok(f"Module '{mod}' loaded.")
            else:
                info(f"Module '{mod}' not available (normal if your chip uses a different variant).")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_file(path_str: str, ext: str = None):
    if not path_str:
        warn("No file path provided. Aborting.")
        return None
    p = Path(path_str)
    if not p.exists():
        err(f"File not found: {p}")
        info("Tip: use an absolute path, e.g. /home/user/firmware.bin")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


def _run_esptool(args: list, timeout: int = 120):
    """Run esptool as a Python module with streaming output."""
    cmd = [sys.executable, "-m", "esptool"] + args
    info(f"Running: {' '.join(cmd)}")
    try:
        rc = run_streaming(cmd, on_line=lambda l: info(f"  esptool: {l}"), timeout=timeout)
        return rc
    except FileNotFoundError:
        err("esptool not found even after install attempt.")
        info("Manual install: pip install esptool --break-system-packages")
        return 1
    except Exception as e:
        err(f"esptool execution error: {e}")
        return 1


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info(f"Serial port : {port}")
    info(f"ESP chip    : {ESP_CHIP}")
    info("Running 'esptool chip_id' to query chip information…")
    info("Troubleshooting:")
    info("  'Failed to connect' → Hold IO0/BOOT button, press RST, release IO0/BOOT")
    info("  'Wrong chip ID'     → Ensure you have the correct chip variant selected")
    info("  'Permission denied' → Add user to dialout: sudo usermod -aG dialout $USER")
    info("")
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            if p.device == port:
                info(f"  Description : {p.description}")
                info(f"  Manufacturer: {p.manufacturer or 'N/A'}")
                vid = f"0x{p.vid:04X}" if p.vid else "N/A"
                pid = f"0x{p.pid:04X}" if p.pid else "N/A"
                info(f"  VID:PID     : {vid}:{pid}")
    except Exception as e:
        warn(f"Could not read serial port metadata: {e}")
    rc = _run_esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "115200", "chip_id"])
    if rc == 0:
        ok("Device info retrieved successfully.")
    else:
        err("chip_id failed. See troubleshooting notes above.")


def op_flash_app_firmware(port: str):
    heading("Flash Application Firmware")
    info("Flash a merged application binary (.bin) to the standard app offset (0x10000).")
    info("This is suitable for Arduino-framework and ESP-IDF 'merged' output binaries.")
    info("")
    info("Typical ESP32 partition layout (4 MB flash):")
    info("  0x1000  — bootloader.bin    (second-stage bootloader)")
    info("  0x8000  — partitions.bin    (partition table)")
    info("  0xe000  — boot_app0.bin     (OTA partition selection)")
    info("  0x10000 — app.bin           (application binary)")
    info("")
    info("Troubleshooting:")
    info("  'Failed to connect'  → Hold BOOT/IO0 button, press RST, release BOOT")
    info("  'MD5 mismatch'       → Bad USB cable/hub; use a direct USB port")
    info("  Slow flash (< 50KB/s) → Lower baud: change 921600 to 460800")
    firmware_path = prompt("Path to merged .bin firmware file")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return
    if not confirm(f"Flash {fw.name} to 0x10000 on {port}?"):
        info("Cancelled.")
        return
    info(f"Flashing {fw.name} at 460800 baud. The device will reset into flash mode…")
    info("(Hold BOOT button on the board if it does not reset automatically.)")
    rc = _run_esptool([
        "--chip", ESP_CHIP, "--port", port, "--baud", "921600",
        "write_flash", "--flash_mode", "dio", "--flash_size", "detect",
        "0x10000", str(fw),
    ], timeout=180)
    if rc == 0:
        ok("Application firmware flashed successfully.")
        info("The ESP32-D will reboot and run the new firmware.")
    else:
        err("Flash failed. See output above for details.")
        info("Retry: hold BOOT/IO0, press RST, release BOOT, then try again.")


def op_flash_full_partition_set(port: str):
    heading("Flash Full Partition Set")
    info("Flash all four partition binaries. Required when changing partition tables")
    info("or doing a clean install of ESP-IDF / Arduino framework firmware.")
    info("")
    info("You will be prompted for four .bin files:")
    info("  bootloader.bin → 0x1000  (from ESP-IDF build output)")
    info("  partitions.bin → 0x8000  (partition table CSV compiled to binary)")
    info("  boot_app0.bin  → 0xe000  (from ESP-IDF esp_idf_component: boot)")
    info("  app.bin        → 0x10000 (your application)")
    info("")
    info("Troubleshooting:")
    info("  Sizes matter: bootloader MUST fit before 0x8000 (max ~30KB)")
    info("  Partition table MUST fit before 0xe000 (max ~2KB)")
    bl_path = prompt("Path to bootloader.bin")
    bl = _require_file(bl_path, ".bin")
    if not bl:
        return
    pt_path = prompt("Path to partitions.bin")
    pt = _require_file(pt_path, ".bin")
    if not pt:
        return
    ba_path = prompt("Path to boot_app0.bin")
    ba = _require_file(ba_path, ".bin")
    if not ba:
        return
    ap_path = prompt("Path to app.bin")
    ap = _require_file(ap_path, ".bin")
    if not ap:
        return
    if not confirm(f"Flash all four partitions to {port}?"):
        info("Cancelled.")
        return
    info("Starting full partition flash (this may take 2–3 minutes)…")
    rc = _run_esptool([
        "--chip", ESP_CHIP, "--port", port, "--baud", "921600",
        "write_flash", "--flash_mode", "dio", "--flash_size", "detect",
        "0x1000",  str(bl),
        "0x8000",  str(pt),
        "0xe000",  str(ba),
        "0x10000", str(ap),
    ], timeout=300)
    if rc == 0:
        ok("Full partition set flashed successfully.")
    else:
        err("Full partition flash failed. Try lowering baud rate or using a different USB port.")


def op_flash_micropython(port: str):
    heading("Flash MicroPython")
    info("Erases all flash and installs MicroPython firmware.")
    info("MicroPython for ESP32: https://micropython.org/download/esp32/")
    info("  Look for the 'GENERIC' build: esp32-20241129-v1.24.1.bin (or similar)")
    info("  For boards with PSRAM: download the 'GENERIC_SPIRAM' variant")
    info("")
    info("After flashing, access the REPL:")
    info("  mpremote connect {port} repl")
    info("  OR: minicom -D {port} -b 115200  (Ctrl+A then X to exit)")
    firmware_path = prompt("Path to MicroPython .bin firmware")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return
    if not confirm(f"Erase all flash and install MicroPython from {fw.name} on {port}?"):
        info("Cancelled.")
        return
    info("Step 1/2: Erasing flash (takes ~10 seconds)…")
    info("  If this hangs: hold BOOT button, press RST, release BOOT, then it should proceed.")
    rc_erase = _run_esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "921600", "erase_flash"], timeout=60)
    if rc_erase != 0:
        err("Erase failed. Cannot proceed with MicroPython install.")
        info("Troubleshooting: check BOOT mode and serial port permissions.")
        return
    ok("Flash erased.")
    info("Step 2/2: Writing MicroPython firmware at offset 0x1000…")
    rc_flash = _run_esptool([
        "--chip", ESP_CHIP, "--port", port, "--baud", "460800",
        "write_flash", "--flash_mode", "dio", "--flash_size", "detect",
        "0x1000", str(fw),
    ], timeout=180)
    if rc_flash == 0:
        ok("MicroPython installed successfully.")
        info(f"Connect to REPL: mpremote connect {port} repl")
        info(f"Or:              minicom -D {port} -b 115200")
    else:
        err("MicroPython flash failed.")
        info("Try: lower baud to 115200, or try a different USB cable/port.")


def op_upload_micropython_script(port: str):
    heading("Upload MicroPython Script")
    info("Uploads a Python script to the ESP32-D's MicroPython filesystem via mpremote.")
    info("")
    info("mpremote quick reference:")
    info(f"  mpremote connect {port} repl          — interactive REPL (Ctrl+] to exit)")
    info(f"  mpremote connect {port} ls :/          — list filesystem root")
    info(f"  mpremote connect {port} cp file.py :/  — upload file")
    info(f"  mpremote connect {port} rm :/file.py   — delete file")
    info("")
    info("Troubleshooting:")
    info("  'mpremote: command not found' → Install: pip install mpremote --break-system-packages")
    info("  'Could not enter raw repl'    → Board is not running MicroPython; flash it first")
    info("  'serial.SerialException'      → Wrong port or another process has it open")
    local_path = prompt("Path to local .py file")
    local = _require_file(local_path, ".py")
    if not local:
        return
    remote_name = prompt(f"Remote filename on device (default: {local.name})")
    if not remote_name:
        remote_name = local.name
    info(f"Uploading {local.name} → :{remote_name} via mpremote…")
    try:
        import subprocess as sp
        result = sp.run(
            ["mpremote", "connect", port, "cp", str(local), f":{remote_name}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            ok(f"Uploaded: {remote_name}")
            info(f"To run: mpremote connect {port} run {remote_name}")
        else:
            err(f"Upload failed (exit {result.returncode})")
            if result.stderr:
                err(f"  stderr: {result.stderr.strip()[:400]}")
    except FileNotFoundError:
        err("mpremote not found.")
        info("Install: pip install mpremote --break-system-packages")
    except Exception as e:
        err(f"Upload error: {e}")


def op_run_micropython_script(port: str):
    heading("Run MicroPython Script")
    info("Execute a script on the ESP32-D via mpremote.")
    info("  'run' executes the script without storing it.")
    info("  To run on boot: upload as 'main.py' to the device root.")
    script = prompt("Remote script name to run (e.g. wifi_scan.py)")
    if not script:
        warn("No script name provided.")
        return
    info(f"Running {script} on device…  (Ctrl+C to interrupt)")
    try:
        import subprocess as sp
        sp.run(["mpremote", "connect", port, "run", script], check=True)
        ok("Script executed.")
    except FileNotFoundError:
        err("mpremote not found. Install: pip install mpremote --break-system-packages")
    except Exception as e:
        err(f"Run error: {e}")


def op_repl_info():
    heading("MicroPython REPL")
    info("Access the MicroPython interactive REPL on the ESP32-D.")
    info("")
    info("Option 1 — mpremote:")
    info("  mpremote connect <port> repl")
    info("  Ctrl+]  — exit mpremote REPL")
    info("  Ctrl+C  — KeyboardInterrupt (stop running code)")
    info("  Ctrl+D  — soft reset")
    info("")
    info("Option 2 — minicom:")
    info("  minicom -D <port> -b 115200")
    info("  Ctrl+A then X — exit minicom")
    info("")
    info("Option 3 — screen:")
    info("  screen <port> 115200")
    info("  Ctrl+A then K to kill session")
    info("")
    info("Option 4 — picocom:")
    info("  picocom <port> -b 115200")
    info("  Ctrl+A Ctrl+X — exit picocom")
    info("")
    info("Useful MicroPython one-liners:")
    info("  import os; os.listdir('/')              # list files")
    info("  import machine; machine.reset()         # reset board")
    info("  import network; print(network.country()) # WiFi country")


def check_firmware_version(port: str):
    heading("Firmware Version Check")
    info("Checking MicroPython version (if installed)...")
    info("  Note: This only works if MicroPython is flashed on the ESP32-D.")
    info("  For custom firmware, version checking requires the firmware to expose a version string.")
    current = None
    try:
        import subprocess as _sp
        r = _sp.run(
            ["mpremote", "connect", port, "exec",
             "import sys; print(sys.version.split()[0])"],
            capture_output=True, text=True, timeout=8,
        )
        if r.returncode == 0 and r.stdout.strip():
            # MicroPython version is like "3.4.0; MicroPython v1.24.1 on 2024-11-29"
            import re
            m = re.search(r'MicroPython\s+v?([\d.]+)', r.stdout)
            if m:
                current = m.group(1)
    except Exception as e:
        info(f"  MicroPython version query failed: {e}")

    if current:
        ok(f"Installed MicroPython version: {current}")
        info("Checking latest MicroPython for ESP32 on GitHub...")
        latest, url = check_latest_github_release("micropython", "micropython")
        if latest:
            announce_firmware_update(TOOL_NAME + " (MicroPython)", current, latest.lstrip("v"), url)
        else:
            warn("Could not reach GitHub for version check.")
    else:
        info("MicroPython not detected or not responding.")
        info("Install MicroPython via 'Flash MicroPython' menu option.")
        info("Latest MicroPython for ESP32: https://micropython.org/download/esp32/")


# ── Firmware payloads (main-page "FIRMWARE - ") ───────────────────────────────

MARAUDER_OWNER = "justcallmekoko"
MARAUDER_REPO  = "ESP32Marauder"


def _fw_user_dir() -> Path:
    """Directory where the operator drops firmware images for the payloads."""
    d = get_firmware_dir("esp32d") / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _download_release_asset(owner, repo, patterns, dest_dir, what):
    """Download the first GitHub release asset matching any of *patterns* (regex)."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    tag, _ = check_latest_github_release(owner, repo)
    for pat in patterns:
        url = get_github_release_asset_url(owner, repo, tag or "", pat)
        if url:
            fname = url.rsplit("/", 1)[-1]
            dest = dest_dir / fname
            if dest.exists() and dest.stat().st_size > 0:
                ok(f"  {what} already present: {dest.name}")
                return dest
            if download_firmware(url, dest, what):
                return dest
    return None


def _run_app_payload(fw, port):
    state = {}

    def prep():
        d = _fw_user_dir()
        f = d / "app.bin"
        if not f.exists():
            bins = sorted(d.glob("*.bin"))
            f = bins[0] if len(bins) == 1 else None
        if not f:
            err("  No application image found. Drop the merged app .bin as 'app.bin' into:")
            err(f"    {d}")
            return False
        state["fw"] = f
        ok(f"  Application firmware ready: {f}")
        return True

    def flash():
        _run_esptool([
            "--chip", ESP_CHIP, "--port", port, "--baud", "921600",
            "write_flash", "--flash_mode", "dio", "--flash_size", "detect",
            "0x10000", str(state["fw"]),
        ], timeout=180)

    run_firmware_payload(
        fw.get("label", "Flash application firmware"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep,
        flash_fn=flash,
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            "Firmware : operator-supplied merged app image → 0x10000",
            f"Port     : {port}",
        ],
    )


def _run_partition_payload(fw, port):
    state = {}
    layout = [("0x1000", "bootloader.bin"), ("0x8000", "partitions.bin"),
              ("0xe000", "boot_app0.bin"), ("0x10000", "app.bin")]

    def prep():
        d = _fw_user_dir()
        missing = [n for _, n in layout if not (d / n).exists()]
        if missing:
            err(f"  Missing partition image(s): {', '.join(missing)}")
            err("  Drop bootloader.bin, partitions.bin, boot_app0.bin and app.bin into:")
            err(f"    {d}")
            return False
        state["files"] = [(off, str(d / n)) for off, n in layout]
        ok("  All four partition images present.")
        return True

    def flash():
        args = ["--chip", ESP_CHIP, "--port", port, "--baud", "921600",
                "write_flash", "--flash_mode", "dio", "--flash_size", "detect"]
        for off, p in state["files"]:
            args += [off, p]
        _run_esptool(args, timeout=300)

    run_firmware_payload(
        fw.get("label", "Flash full partition set"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep,
        flash_fn=flash,
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            "Firmware : operator-supplied bootloader+partitions+boot_app0+app",
            f"Port     : {port}",
        ],
    )


def _run_marauder_payload(fw, port):
    state = {}
    dest = get_firmware_dir("esp32d") / "marauder"

    def prep():
        binf = _download_release_asset(
            MARAUDER_OWNER, MARAUDER_REPO,
            [r"esp32_marauder.*generic.*\.bin",
             r"esp32_marauder_v\d[^/]*\.bin",
             r"esp32_marauder[^/]*\.bin"],
            dest, "ESP32 Marauder firmware")
        if not binf:
            err("  Could not fetch an ESP32 Marauder firmware .bin from the latest release.")
            err(f"  Check https://github.com/{MARAUDER_OWNER}/{MARAUDER_REPO}/releases")
            err(f"  or drop the correct board .bin into {dest}.")
            return False
        blf = _download_release_asset(MARAUDER_OWNER, MARAUDER_REPO, [r"bootloader[^/]*\.bin"], dest, "bootloader")
        ptf = _download_release_asset(MARAUDER_OWNER, MARAUDER_REPO, [r"partitions[^/]*\.bin"], dest, "partitions")
        b0f = _download_release_asset(MARAUDER_OWNER, MARAUDER_REPO, [r"boot_app0[^/]*\.bin"], dest, "boot_app0")
        if blf and ptf and b0f:
            state["files"] = [("0x1000", str(blf)), ("0x8000", str(ptf)),
                              ("0xe000", str(b0f)), ("0x10000", str(binf))]
            ok("  Full Marauder image set ready (bootloader+partitions+boot_app0+firmware).")
        else:
            state["files"] = [("0x10000", str(binf))]
            warn("  Only the Marauder firmware image was available; flashing app slot at 0x10000.")
            warn("  A first-time/clean install may also require bootloader/partitions/boot_app0")
            warn("  (see the ESP32Marauder wiki 'Flashing with esptool').")
        return True

    def flash():
        args = ["--chip", ESP_CHIP, "--port", port, "--baud", "921600",
                "write_flash", "--flash_mode", "dio", "--flash_size", "detect"]
        for off, p in state["files"]:
            args += [off, p]
        _run_esptool(args, timeout=300)

    run_firmware_payload(
        fw.get("label", "Flash ESP32 Marauder"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep,
        flash_fn=flash,
        summary_lines=[
            f"Board    : {TOOL_NAME}",
            f"Firmware : ESP32 Marauder ({MARAUDER_OWNER}/{MARAUDER_REPO})",
            f"Port     : {port}",
        ],
    )


MESHTASTIC_OWNER = "meshtastic"
MESHTASTIC_REPO  = "firmware"


def _run_meshtastic_payload(fw, port):
    """Meshtastic on a generic ESP32. Meshtastic REQUIRES an attached LoRa radio
    (SX127x/SX126x) — a bare ESP32-D has none, so the flash succeeds but the mesh
    radio won't function. Because the ESP32 board variant is not fixed here, the
    operator selects the Meshtastic device variant for their actual board via
    QUIVER_MESHTASTIC_VARIANT (e.g. tlora-v2-1-1.6, tbeam, tlora-v2). Without it,
    prepare_fn aborts BEFORE the confirm rather than guessing."""
    state = {}
    dest = get_firmware_dir("esp32d") / "meshtastic"
    variant = os.environ.get("QUIVER_MESHTASTIC_VARIANT", "").strip()

    def prep():
        if not variant:
            err("  Meshtastic needs a board VARIANT — the generic ESP32-D has no")
            err("  fixed LoRa hardware. Set QUIVER_MESHTASTIC_VARIANT to your board's")
            err("  Meshtastic variant (e.g. tlora-v2-1-1.6, tbeam, tlora-v2) and re-run.")
            err("  NOTE: Meshtastic also requires an attached SX127x/SX126x LoRa radio.")
            return False
        pat = rf"firmware-{variant}-(?!.*update)(?!.*tft)(?!.*inkhud)[^/]*\.bin"
        binf = _download_release_asset(MESHTASTIC_OWNER, MESHTASTIC_REPO, [pat], dest,
                                       f"Meshtastic firmware ({variant})")
        if not binf:
            err(f"  Could not fetch the Meshtastic '{variant}' firmware .bin from the latest release.")
            err(f"  Check https://github.com/{MESHTASTIC_OWNER}/{MESHTASTIC_REPO}/releases for the exact variant slug.")
            return False
        state["fw"] = binf
        ok(f"  Meshtastic firmware ready: {binf.name}")
        return True

    def flash():
        # Meshtastic ESP32 device-install: erase then write the factory image at 0x0.
        _run_esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "921600",
                      "erase_flash"], timeout=60)
        _run_esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "921600",
                      "write_flash", "--flash_mode", "dio", "--flash_size", "detect",
                      "0x0", str(state["fw"])], timeout=300)

    run_firmware_payload(
        fw.get("label", "Flash Meshtastic"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep,
        flash_fn=flash,
        summary_lines=[
            f"Board    : {TOOL_NAME} (requires an attached SX127x/SX126x LoRa radio)",
            f"Firmware : Meshtastic {variant or '<set QUIVER_MESHTASTIC_VARIANT>'} "
            f"({MESHTASTIC_OWNER}/{MESHTASTIC_REPO}) → erase + 0x0",
            f"Port     : {port}",
        ],
    )


def _dispatch_firmware_payload(fw, port):
    name = fw.get("firmware", "")
    if name == "Marauder":
        _run_marauder_payload(fw, port)
    elif name == "Meshtastic":
        _run_meshtastic_payload(fw, port)
    elif name == "Application":
        _run_app_payload(fw, port)
    elif name == "PartitionSet":
        _run_partition_payload(fw, port)
    else:
        err(f"Unknown firmware payload '{name}' for {TOOL_NAME}.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()
    print_banner(TOOL_NAME, DESCRIPTION)

    # ── Dependency checks ─────────────────────────────────────────────────────
    heading("Dependency Check")
    flavor = get_os_flavor()

    info("Checking for esptool (required for firmware flashing)…")
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("  Trying apt: apt-get install esptool python3-serial")
        ensure_apt_packages(["esptool", "python3-serial"])
    elif flavor == "macos":
        info("  Trying brew: brew install esptool")
        ensure_brew_packages(["esptool"])
    info("  Checking pip fallback for esptool and pyserial…")
    ensure_pip_packages([("esptool", "esptool>=4.7"), ("serial", "pyserial")])

    info("Checking for mpremote (required for MicroPython script upload)…")
    ensure_pip_packages([("mpremote", "mpremote")])

    # ── Linux udev rules ──────────────────────────────────────────────────────
    _check_udev_rules()

    # ── Device detection ──────────────────────────────────────────────────────
    heading("Device Detection")
    info("Scanning for ESP32-D via VID:PID matching (CP210x / CH340 / FT232)…")
    info("Expected devices: /dev/ttyUSB* (Linux) or /dev/cu.usbserial* (macOS)")
    info("Check current ports: ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null")

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("ESP32-D not detected within timeout. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Device appeared but serial port could not be resolved. Exiting.")
        info("Debug: check 'dmesg | tail -20' or 'ls /dev/ttyUSB* /dev/ttyACM*'")
        sys.exit(1)

    ok(f"ESP32-D detected on {port}")
    check_firmware_version(port)

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw, port)
        return

    # ── Main menu ─────────────────────────────────────────────────────────────
    MENU_OPTIONS = [
        "Device Info (esptool chip_id)",
        "FIRMWARE - Flash Application Firmware (merged .bin → 0x10000)",
        "FIRMWARE - Flash Full Partition Set (bootloader + partitions + app)",
        "Flash MicroPython (erase + install)",
        "Upload MicroPython Script (mpremote cp)",
        "Run MicroPython Script (mpremote run)",
        "MicroPython REPL Info",
        "Exit",
    ]

    while True:
        choice = numbered_menu(f"{TOOL_NAME} — Main Menu", MENU_OPTIONS)

        if choice == 0:
            op_device_info(port)
        elif choice == 1:
            op_flash_app_firmware(port)
        elif choice == 2:
            op_flash_full_partition_set(port)
        elif choice == 3:
            op_flash_micropython(port)
        elif choice == 4:
            op_upload_micropython_script(port)
        elif choice == 5:
            op_run_micropython_script(port)
        elif choice == 6:
            op_repl_info()
        elif choice == 7:
            info("Goodbye.")
            break

        # Re-check port after flash operations (device may re-enumerate)
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
