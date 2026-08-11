#!/usr/bin/env python3
"""
LilyGo LoRa32 Tool Manager
Handles device info, application firmware flashing, full partition flashing,
MicroPython flashing, script upload, and script execution via mpremote.

ESP32 (classic) chip with SX1276 LoRa radio.
IMPORTANT: Remove the SD card before any flash operation.

Usage:
    python3 lilygo_lora32.py
"""

import subprocess
import sys
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
    selected_firmware_payload, run_firmware_payload,
    get_firmware_dir, check_latest_github_release,
    get_github_release_asset_url, download_firmware,
)

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME   = "LilyGo LoRa32"
DESCRIPTION = "ESP32 + SX1276 LoRa development board (v1.6.1)"

VID_PIDS = [
    (0x10C4, 0xEA60),  # CP2104
    (0x1A86, 0x55D4),  # CH9102
    (0x1A86, 0x7522),  # CH340C
    (0x1A86, 0x7523),  # CH340G
]

CONNECT_INSTRUCTIONS = (
    "LilyGo LoRa32 v1.6.1 not detected.\n\n"
    "  1. Connect via USB cable (CP2104 or CH340 bridge)\n"
    "  2. Linux kernel modules are usually auto-loaded:\n"
    "     CP210x: sudo modprobe cp210x\n"
    "     CH340:  sudo modprobe ch341\n"
    "  3. Add user to dialout: sudo usermod -aG dialout $USER (re-login)\n"
    "  4. IMPORTANT: Remove SD card before flashing\n"
    "  5. Flash mode: hold BOOT button, press RST, then release BOOT\n\n"
    "  VID:PID: 10C4:EA60 (CP2104) or 1A86:55D4 (CH9102)"
)

SD_CARD_WARNING = "Remove the SD card from the board before flashing."

# udev rules for USB-serial chips used on LoRa32
UDEV_RULES_CONTENT = (
    '# LilyGo LoRa32 USB-serial udev rules\n'
    '# CP210x / CP2104 (VID:PID 10C4:EA60)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", '
    'MODE="0666", GROUP="dialout"\n'
    '# CH9102 (VID:PID 1A86:55D4)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="55d4", '
    'MODE="0666", GROUP="dialout"\n'
    '# CH340C (VID:PID 1A86:7522)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7522", '
    'MODE="0666", GROUP="dialout"\n'
    '# CH340G (VID:PID 1A86:7523)\n'
    'SUBSYSTEM=="tty", ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7523", '
    'MODE="0666", GROUP="dialout"\n'
)
UDEV_RULES_PATH = "/etc/udev/rules.d/60-lilygo-lora32.rules"


# ── Detection ─────────────────────────────────────────────────────────────────

def detect_device() -> bool:
    return find_serial_port_by_vidpid(VID_PIDS) is not None


# ── udev rules check ──────────────────────────────────────────────────────────

def _check_udev_rules():
    """Check and install udev rules for CP210x and CH340 on Linux."""
    if get_os_flavor() not in ("kali", "debian", "ubuntu", "linux"):
        return
    if Path(UDEV_RULES_PATH).exists():
        ok(f"udev rules already present: {UDEV_RULES_PATH}")
        return
    info("Installing udev rules for CP210x and CH340 USB-serial chips…")
    import tempfile
    tmp = Path(tempfile.mktemp(suffix=".rules"))
    tmp.write_text(UDEV_RULES_CONTENT)
    r = sudo_run(f"cp {tmp} {UDEV_RULES_PATH}")
    tmp.unlink(missing_ok=True)
    if r.returncode == 0:
        sudo_run("udevadm control --reload-rules")
        sudo_run("udevadm trigger")
        ok(f"udev rules written to {UDEV_RULES_PATH} and reloaded.")
        info("Unplug and replug the LilyGo LoRa32 to apply new permissions.")
    else:
        warn("Failed to write udev rules automatically.")
        info(f"Manual fix: sudo nano {UDEV_RULES_PATH}")
        info("Then: sudo udevadm control --reload-rules && sudo udevadm trigger")

    # Check kernel modules
    info("Checking USB-serial kernel modules…")
    for mod in ("cp210x", "ch341"):
        out = run_output(f"lsmod 2>/dev/null | grep {mod}")
        if out:
            ok(f"Kernel module '{mod}' is loaded.")
        else:
            info(f"Module '{mod}' not loaded — attempting modprobe…")
            r = sudo_run(f"modprobe {mod}")
            if r.returncode == 0:
                ok(f"Module '{mod}' loaded.")
            else:
                info(f"Module '{mod}' not available (may not be needed for your chip variant).")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _require_file(file_path: str, ext: str = None) -> "Path | None":
    """Prompt and validate a file path. Returns Path or None."""
    if not file_path:
        warn("No file path provided. Aborting.")
        return None
    p = Path(file_path)
    if not p.exists():
        err(f"File not found: {p}")
        return None
    if ext and p.suffix.lower() != ext.lower():
        warn(f"Expected a {ext} file, got: {p.name}")
        if not confirm("Continue anyway?", default=False):
            return None
    return p


# ── Operations ────────────────────────────────────────────────────────────────

def op_device_info(port: str):
    heading("Device Info")
    info(f"Serial port: {port}")
    info("Troubleshooting device detection:")
    info("  - No /dev/ttyUSB* → check 'lsmod | grep cp210x' or 'lsmod | grep ch341'")
    info("  - Permission denied → 'sudo usermod -aG dialout $USER' then re-login")
    info("  - Multiple ports → SD card may create a second serial interface; remove it")
    from serial.tools import list_ports
    for p in list_ports.comports():
        if p.device == port:
            info(f"Description : {p.description}")
            info(f"Manufacturer: {p.manufacturer or 'N/A'}")
            vid = f"0x{p.vid:04X}" if p.vid else "N/A"
            pid = f"0x{p.pid:04X}" if p.pid else "N/A"
            info(f"VID:PID     : {vid}:{pid}")

    info("Running esptool chip_id...")
    info("Troubleshooting esptool connection:")
    info("  'Failed to connect' → hold BOOT, press RST, release BOOT to enter flash mode")
    info("  'Wrong chip' → ensure you connected the correct port")
    cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32",
        "--port", port,
        "chip_id",
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=30)
        ok("Device info complete.")
    except Exception as e:
        err(f"esptool chip_id failed: {e}")


def op_flash_app_firmware(port: str):
    heading("Flash Application Firmware")
    warn(SD_CARD_WARNING)
    info("Flash a merged application binary to offset 0x10000.")
    info("Partition layout for standard ESP32 (4MB flash):")
    info("  0x1000  — bootloader.bin")
    info("  0x8000  — partitions.bin (partition table)")
    info("  0xe000  — boot_app0.bin (OTA selection)")
    info("  0x10000 — app.bin (main application)")
    info("Use 'Flash Full Partition Set' if you have separate partition files.")
    info("Troubleshooting:")
    info("  'Failed to connect' → hold BOOT, press RST, release BOOT")
    info("  'MD5 mismatch' → bad USB cable or hub; try direct connection")
    info("  'ESP32-S3 detected' → wrong script; check board variant")
    firmware_path = prompt("Path to merged .bin firmware file")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return
    if not confirm(f"Flash {fw.name} to 0x10000 on {port}?"):
        info("Flash cancelled.")
        return

    info(f"Flashing application firmware: {fw.name}...")
    cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32",
        "--port", port,
        "--baud", "921600",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_size", "4MB",
        "0x10000", str(fw),
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=180)
        ok("Application firmware flash complete.")
    except Exception as e:
        err(f"Flash failed: {e}")


def op_flash_full_partition_set(port: str):
    heading("Flash Full Partition Set")
    warn(SD_CARD_WARNING)
    info("You will be prompted for four binary files:")
    info("  bootloader.bin  → 0x1000  (second-stage bootloader)")
    info("  partitions.bin  → 0x8000  (partition table, max 3KB)")
    info("  boot_app0.bin   → 0xe000  (OTA app selection, from ESP-IDF)")
    info("  app.bin         → 0x10000 (compiled application)")
    info("Troubleshooting:")
    info("  'A fatal error occurred' → esptool version mismatch; try apt install esptool")
    info("  Sizes matter: bootloader must fit before 0x8000")

    bootloader_path = prompt("Path to bootloader.bin")
    bootloader = _require_file(bootloader_path, ".bin")
    if not bootloader:
        return

    partitions_path = prompt("Path to partitions.bin")
    partitions = _require_file(partitions_path, ".bin")
    if not partitions:
        return

    boot_app0_path = prompt("Path to boot_app0.bin")
    boot_app0 = _require_file(boot_app0_path, ".bin")
    if not boot_app0:
        return

    app_path = prompt("Path to app.bin")
    app = _require_file(app_path, ".bin")
    if not app:
        return

    if not confirm(f"Flash all four partitions to {port}?"):
        info("Flash cancelled.")
        return

    info("Flashing full partition set...")
    cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32",
        "--port", port,
        "--baud", "921600",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_size", "4MB",
        "0x1000",  str(bootloader),
        "0x8000",  str(partitions),
        "0xe000",  str(boot_app0),
        "0x10000", str(app),
    ]
    try:
        run_streaming(cmd, on_line=lambda l: info(l), timeout=240)
        ok("Full partition flash complete.")
    except Exception as e:
        err(f"Full partition flash failed: {e}")


def op_flash_micropython(port: str):
    heading("Flash MicroPython")
    warn(SD_CARD_WARNING)
    info("MicroPython flash: erase all flash first, then write MicroPython at 0x1000.")
    info("MicroPython firmware for ESP32: https://micropython.org/download/esp32/")
    info("After flashing: connect to REPL via mpremote or minicom at 115200 baud.")
    info("LoRa library for MicroPython: https://github.com/lemariva/uPySensors")
    info("  Upload: mpremote connect <port> cp sx1276.py :/sx1276.py")
    firmware_path = prompt("Path to micropython.bin")
    fw = _require_file(firmware_path, ".bin")
    if not fw:
        return
    if not confirm(f"Erase flash and install MicroPython from {fw.name} on {port}?"):
        info("Flash cancelled.")
        return

    info("Erasing flash (this may take ~10s)...")
    info("Troubleshooting: if erase hangs, hold BOOT + RST then release BOOT")
    erase_cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32",
        "--port", port,
        "--baud", "921600",
        "erase_flash",
    ]
    try:
        run_streaming(erase_cmd, on_line=lambda l: info(l), timeout=60)
    except Exception as e:
        err(f"Erase failed: {e}")
        return

    info(f"Flashing MicroPython: {fw.name}...")
    flash_cmd = [
        sys.executable, "-m", "esptool",
        "--chip", "esp32",
        "--port", port,
        "--baud", "921600",
        "write_flash",
        "--flash_mode", "dio",
        "--flash_size", "4MB",
        "0x1000", str(fw),
    ]
    try:
        run_streaming(flash_cmd, on_line=lambda l: info(l), timeout=180)
        ok("MicroPython flash complete.")
        info("Access REPL: mpremote connect " + port + " repl")
        info("Or:          minicom -D " + port + " -b 115200")
    except Exception as e:
        err(f"MicroPython flash failed: {e}")


def op_upload_micropython_script(port: str):
    heading("Upload MicroPython Script")
    info("Upload a .py script to the MicroPython filesystem using mpremote.")
    info("mpremote REPL access: mpremote connect <port> repl")
    info("  Ctrl+] to exit REPL")
    info("  Ctrl+C to interrupt running script")
    info("Troubleshooting mpremote:")
    info("  'mpremote: command not found' → pip install mpremote --break-system-packages")
    info("  'Could not enter raw repl' → board not running MicroPython; flash it first")
    info("  'serial.SerialException' → wrong port or another process has it open")
    local_path = prompt("Path to local .py file")
    local = _require_file(local_path, ".py")
    if not local:
        return
    remote_name = prompt(f"Remote filename on device (default: {local.name})")
    if not remote_name:
        remote_name = local.name

    info(f"Uploading {local.name} → :{remote_name} via mpremote...")
    try:
        subprocess.run(
            ["mpremote", "connect", port, "cp", str(local), f":{remote_name}"],
            check=True,
        )
        ok(f"Uploaded: {remote_name}")
    except subprocess.CalledProcessError as e:
        err(f"Upload failed: {e}")
    except FileNotFoundError:
        err("mpremote not found.")
        info("Install: pip install mpremote --break-system-packages")


def op_run_micropython_script(port: str):
    heading("Run MicroPython Script")
    info("Execute a script already on the device via mpremote.")
    info("Note: 'run' executes the file without storing it; use 'upload' to persist.")
    info("To run main.py on boot: upload it as 'main.py' to the device root.")
    remote_name = prompt("Remote script name to run (e.g. main.py)")
    if not remote_name:
        warn("No script name provided. Aborting.")
        return
    info(f"Running {remote_name} on device via mpremote...")
    info("Press Ctrl+C to interrupt the script.")
    try:
        subprocess.run(
            ["mpremote", "connect", port, "run", remote_name],
            check=True,
        )
        ok("Script executed.")
    except subprocess.CalledProcessError as e:
        err(f"Run failed: {e}")
    except FileNotFoundError:
        err("mpremote not found.")
        info("Install: pip install mpremote --break-system-packages")


def op_micropython_repl():
    heading("MicroPython REPL")
    info("Interactive Python REPL on the ESP32 — access via mpremote or minicom.")
    info("mpremote REPL: mpremote connect <port> repl")
    info("  Ctrl+]  — exit mpremote REPL")
    info("  Ctrl+C  — KeyboardInterrupt (stop running code)")
    info("  Ctrl+D  — soft reset")
    info("  Ctrl+A/Ctrl+B — raw REPL / normal REPL toggle")
    info("minicom: minicom -D <port> -b 115200")
    info("  Ctrl+A then X — exit minicom")
    info("LoRa library install via REPL (after MicroPython flash):")
    info("  import upip; upip.install('micropython-uasyncio')  # if available")
    info("  Or upload LoRa driver manually: mpremote connect <port> cp lora.py :/lora.py")
    info("Install mpremote: pip install mpremote --break-system-packages")


# ── Firmware payloads (main-page "FIRMWARE - ") ───────────────────────────────

ESP_CHIP         = "esp32"
MESHTASTIC_OWNER = "meshtastic"
MESHTASTIC_REPO  = "firmware"
MESHTASTIC_VARIANT_PATTERNS = [r"firmware-tlora-v2-1-1[._]6-(?!.*update)[^/]*\.bin"]


def _fw_user_dir() -> Path:
    d = get_firmware_dir("lilygo_lora32") / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _esptool(args, timeout=180):
    cmd = [sys.executable, "-m", "esptool"] + args
    info(f"Running: {' '.join(cmd)}")
    return run_streaming(cmd, on_line=lambda l: info(l), timeout=timeout)


def _download_release_asset(owner, repo, patterns, dest_dir, what):
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
            err("  No merged app image found. Drop it as 'app.bin' into:")
            err(f"    {d}")
            return False
        state["fw"] = f
        ok(f"  Application firmware ready: {f}")
        return True

    def flash():
        _esptool([
            "--chip", ESP_CHIP, "--port", port, "--baud", "921600",
            "write_flash", "--flash_mode", "dio", "--flash_size", "4MB",
            "0x10000", str(state["fw"]),
        ], timeout=180)

    run_firmware_payload(
        fw.get("label", "Flash application firmware"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[f"Board    : {TOOL_NAME}", "SD card  : REMOVE before flashing",
                       "Firmware : operator-supplied merged app image → 0x10000",
                       f"Port     : {port}"])


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
                "write_flash", "--flash_mode", "dio", "--flash_size", "4MB"]
        for off, p in state["files"]:
            args += [off, p]
        _esptool(args, timeout=240)

    run_firmware_payload(
        fw.get("label", "Flash full partition set"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[f"Board    : {TOOL_NAME}", "SD card  : REMOVE before flashing",
                       "Firmware : operator-supplied bootloader+partitions+boot_app0+app",
                       f"Port     : {port}"])


def _run_micropython_payload(fw, port):
    state = {}

    def prep():
        d = _fw_user_dir()
        bins = sorted(d.glob("*micropython*.bin")) or sorted(d.glob("esp32-*.bin"))
        f = bins[0] if bins else None
        if not f:
            err("  No MicroPython image found. Download the ESP32 build from")
            err("  https://micropython.org/download/esp32/ and drop it into:")
            err(f"    {d}")
            return False
        state["fw"] = f
        ok(f"  MicroPython firmware ready: {f}")
        return True

    def flash():
        _esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "921600", "erase_flash"], timeout=60)
        _esptool([
            "--chip", ESP_CHIP, "--port", port, "--baud", "921600",
            "write_flash", "--flash_mode", "dio", "--flash_size", "4MB",
            "0x1000", str(state["fw"]),
        ], timeout=180)

    run_firmware_payload(
        fw.get("label", "Flash MicroPython"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[f"Board    : {TOOL_NAME}", "SD card  : REMOVE before flashing",
                       "Firmware : MicroPython for ESP32 (erase + 0x1000)",
                       f"Port     : {port}"])


def _run_meshtastic_payload(fw, port):
    state = {}
    dest = get_firmware_dir("lilygo_lora32") / "meshtastic"

    def prep():
        binf = _download_release_asset(MESHTASTIC_OWNER, MESHTASTIC_REPO,
                                       MESHTASTIC_VARIANT_PATTERNS, dest,
                                       "Meshtastic firmware (tlora-v2-1-1.6)")
        if not binf:
            err("  Could not fetch the Meshtastic tlora-v2-1-1.6 firmware .bin from the latest release.")
            err(f"  Check https://github.com/{MESHTASTIC_OWNER}/{MESHTASTIC_REPO}/releases")
            return False
        state["fw"] = binf
        ok(f"  Meshtastic firmware ready: {binf}")
        return True

    def flash():
        # Meshtastic device-install for ESP32: erase then write the factory image at 0x0.
        _esptool(["--chip", ESP_CHIP, "--port", port, "--baud", "921600", "erase_flash"], timeout=60)
        _esptool([
            "--chip", ESP_CHIP, "--port", port, "--baud", "921600",
            "write_flash", "--flash_mode", "dio", "--flash_size", "detect",
            "0x0", str(state["fw"]),
        ], timeout=240)

    run_firmware_payload(
        fw.get("label", "Flash Meshtastic"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[f"Board    : {TOOL_NAME}", "SD card  : REMOVE before flashing",
                       f"Firmware : Meshtastic tlora-v2-1-1.6 ({MESHTASTIC_OWNER}/{MESHTASTIC_REPO}) → erase + 0x0",
                       f"Port     : {port}"])


MARAUDER_OWNER = "justcallmekoko"
MARAUDER_REPO  = "ESP32Marauder"


def _run_marauder_payload(fw, port):
    """ESP32 Marauder (Wi-Fi/BLE) on the LilyGo LoRa32's ESP32. Generic ESP32 build."""
    state = {}
    dest = get_firmware_dir("lilygo_lora32") / "marauder"

    def prep():
        binf = _download_release_asset(
            MARAUDER_OWNER, MARAUDER_REPO,
            [r"esp32_marauder.*generic.*\.bin", r"esp32_marauder_v\d[^/]*\.bin",
             r"esp32_marauder[^/]*\.bin"], dest, "ESP32 Marauder firmware")
        if not binf:
            err("  Could not fetch an ESP32 Marauder firmware .bin from the latest release.")
            err(f"  Check https://github.com/{MARAUDER_OWNER}/{MARAUDER_REPO}/releases or drop the board .bin into {dest}.")
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
            warn("  A first-time/clean install may also need bootloader/partitions/boot_app0 (ESP32Marauder wiki).")
        return True

    def flash():
        args = ["--chip", ESP_CHIP, "--port", port, "--baud", "921600",
                "write_flash", "--flash_mode", "dio", "--flash_size", "detect"]
        for off, p in state["files"]:
            args += [off, p]
        _esptool(args, timeout=300)

    run_firmware_payload(
        fw.get("label", "Flash ESP32 Marauder"),
        info_fn=lambda: op_device_info(port),
        prepare_fn=prep, flash_fn=flash,
        summary_lines=[f"Board    : {TOOL_NAME}", "SD card  : REMOVE before flashing",
                       f"Firmware : ESP32 Marauder ({MARAUDER_OWNER}/{MARAUDER_REPO})",
                       f"Port     : {port}"])


def _dispatch_firmware_payload(fw, port):
    name = fw.get("firmware", "")
    if name == "Meshtastic":
        _run_meshtastic_payload(fw, port)
    elif name == "Marauder":
        _run_marauder_payload(fw, port)
    elif name == "Application":
        _run_app_payload(fw, port)
    elif name == "PartitionSet":
        _run_partition_payload(fw, port)
    elif name == "MicroPython":
        _run_micropython_payload(fw, port)
    else:
        err(f"Unknown firmware payload '{name}' for {TOOL_NAME}.")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    print_banner(TOOL_NAME, DESCRIPTION)

    # Prefer apt packages on Kali/Debian/Ubuntu
    info("Checking apt packages: esptool, python3-serial…")
    ensure_apt_packages(["esptool", "python3-serial"])
    ensure_brew_packages(["esptool"])

    # mpremote is not in apt; use pip
    info("Checking mpremote (pip install)…")
    ensure_pip_packages([
        ("mpremote", "mpremote"),
    ])

    # Check udev rules
    info("Checking udev rules for USB-serial chips (CP210x, CH340)…")
    _check_udev_rules()

    found = web_detect_loop(detect_device, TOOL_NAME, CONNECT_INSTRUCTIONS, timeout=1800)
    if not found:
        err("LilyGo LoRa32 not detected. Exiting.")
        sys.exit(1)

    port = find_serial_port_by_vidpid(VID_PIDS)
    if not port:
        err("Could not resolve serial port after detection. Exiting.")
        sys.exit(1)

    ok(f"Connected on {port}")

    # Firmware payload selected on the main page → auto-flash (no menu).
    fw = selected_firmware_payload()
    if fw:
        _dispatch_firmware_payload(fw, port)
        return

    MENU_OPTIONS = [
        "Device Info",
        "FIRMWARE - Flash Application Firmware",
        "FIRMWARE - Flash Full Partition Set",
        "FIRMWARE - Flash MicroPython",
        "Upload MicroPython Script",
        "Run MicroPython Script",
        "MicroPython REPL",
        "Exit",
    ]

    while True:
        choice = numbered_menu("LilyGo LoRa32 — Main Menu", MENU_OPTIONS)

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
            op_micropython_repl()
        elif choice == 7:
            info("Goodbye.")
            break

        # Re-check port after flash operations
        new_port = find_serial_port_by_vidpid(VID_PIDS)
        if new_port and new_port != port:
            port = new_port
            info(f"Serial port updated to {port}")


if __name__ == "__main__":
    main()
