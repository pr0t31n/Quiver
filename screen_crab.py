#!/usr/bin/env python3
"""
Screen Crab Tool Manager
Handles detection, MicroSD configuration, firmware updates, and config.txt
management for the Screen Crab.

The Screen Crab is a covert inline HDMI capture implant. It captures
screenshots or video and stores them on a MicroSD card, optionally
exfiltrating via WiFi to Cloud C2.

It has NO SSH interface, NO USB enumeration to host, and NO serial console.
All configuration is done via config.txt on the MicroSD card.

Usage:
    python3 screen_crab.py
"""

import re
import sys
import shutil
from pathlib import Path

from common import (
    print_banner, heading, ok, warn, err, info,
    confirm, prompt, pause, numbered_menu,
    get_os, get_os_flavor, run, run_output,
    sudo_run, sudo_output,
    require_sudo, ensure_apt_packages,
    find_mounted_drive,
    detection_loop,
    get_filesystem_type,
)


def check_firmware_version():
    heading("Firmware Version Check")
    info("Checking Screen Crab firmware version…")
    info("The Screen Crab has no SSH or serial console — firmware version cannot be read automatically.")
    info("To check the current firmware version: look for a VERSION or changelog file on the MicroSD card.")
    info("")
    info("Screen Crab firmware updates require a Hak5 account:")
    info("  1. Download firmware from: https://downloads.hak5.org/crab")
    info("  2. Copy upgrade.bin to the ROOT of the MicroSD card (do not rename)")
    info("  3. Insert the card into the Screen Crab and power on")
    info("  4. LED: Blue/Red alternating = upgrade in progress — do NOT power off")
    info("  5. upgrade.bin is automatically removed after successful flash")
    info("  6. Check Hak5 docs: https://docs.hak5.org/screen-crab/")

# ── Constants ─────────────────────────────────────────────────────────────────

TOOL_NAME    = "Screen Crab"
DESCRIPTION  = "Inline HDMI capture implant — MicroSD + WiFi exfiltration"
DRIVE_LABEL  = "SCREEN_CRAB"   # MicroSD volume label may vary
FIRMWARE_URL = "https://downloads.hak5.org/crab"

# Default config.txt parameters and their valid options
CONFIG_PARAMS = {
    "LED":              (["ON", "OFF"],                        "ON"),
    "CAPTURE_MODE":     (["IMAGE", "VIDEO", "OFF"],            "IMAGE"),
    "DEDUPLICATE":      (["ON", "OFF"],                        "ON"),
    "CAPTURE_INTERVAL": (None,                                 "5"),    # integer seconds
    "STORAGE":          (["FILL", "LOOP"],                     "FILL"),
    "BUTTON":           (["EJECT", "CAPTURE_MODE"],            "EJECT"),
    "VIDEO_BITRATE":    (["LOW", "MEDIUM", "HIGH"],            "MEDIUM"),
    "WIFI_SSID":        (None,                                 ""),
    "WIFI_PASS":        (None,                                 ""),
}

MODE_INSTRUCTIONS = """
Screen Crab MicroSD not detected.

  The Screen Crab is configured via a MicroSD card:
    1. Remove the MicroSD card from the Screen Crab (press to eject).
    2. Insert the MicroSD card into a card reader on this computer.
    3. The card should mount as a volume (FAT32 or ExFAT).
    4. If no config.txt exists yet, power on the Screen Crab first with an
       empty MicroSD card to auto-generate the default config.txt.
    5. Press the Screen Crab's button when the LED is solid green to safely eject.

  Supported card sizes: up to 128 GB (FAT32 or ExFAT).
  Format: FAT32 or ExFAT (not NTFS, not ext4).
"""

RESET_INSTRUCTIONS = """
Screen Crab Factory Reset:

  Configuration reset (most common):
    1. Remove the MicroSD card.
    2. Delete or rename config.txt on the card.
    3. The Screen Crab auto-generates a fresh config.txt with defaults on next boot.

  Full firmware reset:
    1. Download upgrade.bin from: https://downloads.hak5.org/crab
    2. Copy upgrade.bin to the ROOT of the MicroSD card (do not rename).
    3. Insert the card and power on.
    4. LED pattern: Blue/Red alternating = upgrade detected and starting.
       Blue/Magenta = framework upgrade in progress.
    5. Upgrade completes automatically; upgrade.bin is removed from the card.
    6. Wait 5-10 minutes. Do NOT power off during upgrade.
"""


# ── Detection ─────────────────────────────────────────────────────────────────

def find_screen_crab_card() -> tuple[bool, Path | None]:
    """
    Try to find the Screen Crab MicroSD card.
    Returns (found, path).
    """
    # Try common volume labels
    for label in ["SCREEN_CRAB", "SCREENCRAB", "HAK5", "SD_CARD", "NO NAME"]:
        drive = find_mounted_drive(label)
        if drive:
            # Verify it looks like a Screen Crab card (check for config.txt or known files)
            if (drive / "config.txt").exists() or (drive / "upgrade.bin").exists():
                return True, drive

    # Ask user for the mount path
    return False, None


def detect_screen_crab() -> bool:
    found, _ = find_screen_crab_card()
    return found


def find_card_interactively() -> Path | None:
    """Find the MicroSD mount path interactively."""
    found, drive = find_screen_crab_card()
    if found and drive:
        return drive

    # Show available drives and ask user
    os_name = get_os()
    info("Scanning for mounted drives…")
    if os_name == "macos":
        volumes = list(Path("/Volumes").iterdir())
        if volumes:
            print("\n  Mounted volumes:")
            for v in volumes:
                print(f"    • {v.name}  ({v})")
    elif os_name == "linux":
        out = run_output("lsblk -o NAME,LABEL,MOUNTPOINT 2>/dev/null")
        if out:
            print("\n  Block devices:")
            for ln in out.splitlines():
                if "/" in ln:
                    print(f"    {ln}")

    card_path = prompt("Enter full path to the MicroSD card mount point", "")
    if card_path:
        p = Path(card_path)
        if p.is_dir():
            # Check filesystem type — Screen Crab requires FAT32 or ExFAT
            fstype = get_filesystem_type(card_path)
            if fstype:
                info(f"MicroSD filesystem: {fstype}")
                if fstype in ("NTFS",):
                    warn("NTFS detected! Screen Crab requires FAT32 or ExFAT — reformat the card.")
                elif fstype.startswith("EXT"):
                    warn("ext filesystem detected! Screen Crab requires FAT32 or ExFAT — reformat the card.")
                elif "FAT" in fstype or "EXFAT" in fstype or "MSDOS" in fstype:
                    ok(f"{fstype} filesystem is compatible with Screen Crab.")
                else:
                    warn(f"Unknown filesystem '{fstype}' — verify the card is FAT32 or ExFAT.")
            return p
        warn(f"Not a valid directory: {card_path}")
    return None


# ── config.txt Management ─────────────────────────────────────────────────────

def parse_config(path: Path) -> dict[str, str]:
    """Parse a Screen Crab config.txt into a dict."""
    config = {}
    if not path.exists():
        return config
    for ln in path.read_text().splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        parts = ln.split(None, 1)
        if parts:
            key = parts[0].upper()
            value = parts[1] if len(parts) > 1 else ""
            config[key] = value
    return config


def validate_config(config: dict[str, str]) -> list[str]:
    """Validate a Screen Crab config dict. Returns list of issue strings."""
    issues = []

    for key, (valid_values, default) in CONFIG_PARAMS.items():
        if key in config:
            if valid_values and config[key].upper() not in valid_values:
                issues.append(f"WARNING: {key}={config[key]}  (valid: {', '.join(valid_values)})")
        # WIFI_SSID / WIFI_PASS: check they're paired
    if "WIFI_SSID" in config and "WIFI_PASS" not in config:
        issues.append("WARNING: WIFI_SSID set but WIFI_PASS not set")
    if "WIFI_PASS" in config and "WIFI_SSID" not in config:
        issues.append("WARNING: WIFI_PASS set but WIFI_SSID not set")

    if "CAPTURE_INTERVAL" in config:
        try:
            interval = int(config["CAPTURE_INTERVAL"])
            if interval < 1:
                issues.append(f"WARNING: CAPTURE_INTERVAL={interval} — must be a positive integer")
            elif interval > 3600:
                issues.append(f"INFO: CAPTURE_INTERVAL={interval} ({interval//60} min) — very long interval, intentional?")
        except ValueError:
            issues.append(f"ERROR: CAPTURE_INTERVAL must be an integer, got: {config['CAPTURE_INTERVAL']}")

    if config.get("CAPTURE_MODE", "IMAGE").upper() == "OFF":
        issues.append("INFO: CAPTURE_MODE=OFF — device will not capture anything")

    if config.get("DEDUPLICATE", "ON").upper() == "ON" and config.get("CAPTURE_MODE", "IMAGE").upper() == "VIDEO":
        issues.append("INFO: DEDUPLICATE=ON has no effect in VIDEO mode (image mode only)")

    return issues


def configure_screen_crab(card: Path) -> bool:
    """Interactive config.txt editor for Screen Crab."""
    heading("Screen Crab Configuration (config.txt)")

    config_path = card / "config.txt"
    config = parse_config(config_path)

    if config:
        info("Current configuration:")
        for k, v in sorted(config.items()):
            # Mask WiFi password
            display_v = "***" if k == "WIFI_PASS" else v
            print(f"    {k} = {display_v}")

    print()
    action = numbered_menu("What would you like to do?", [
        "Interactive configuration wizard",
        "Edit config.txt manually (open in editor)",
        "Validate current config.txt",
        "Show full config reference",
        "Skip (keep current config)",
    ])

    if action == 0:
        # Wizard
        new_config = {}

        capture_mode = numbered_menu("Capture mode:", ["IMAGE (screenshots)", "VIDEO", "OFF"])
        new_config["CAPTURE_MODE"] = ["IMAGE", "VIDEO", "OFF"][capture_mode]

        if new_config["CAPTURE_MODE"] == "IMAGE":
            interval = prompt("Capture interval in seconds", config.get("CAPTURE_INTERVAL", "5"))
            new_config["CAPTURE_INTERVAL"] = interval
            dedup = confirm("Enable deduplication (skip identical frames)?",
                           config.get("DEDUPLICATE", "ON") == "ON")
            new_config["DEDUPLICATE"] = "ON" if dedup else "OFF"
        elif new_config["CAPTURE_MODE"] == "VIDEO":
            bitrate = numbered_menu("Video bitrate:", ["LOW", "MEDIUM", "HIGH"])
            new_config["VIDEO_BITRATE"] = ["LOW", "MEDIUM", "HIGH"][bitrate]

        storage = numbered_menu("Storage behavior when full:", ["FILL (stop when full)", "LOOP (overwrite oldest)"])
        new_config["STORAGE"] = ["FILL", "LOOP"][storage]

        button = numbered_menu("Button function:", ["EJECT (safe SD eject)", "CAPTURE_MODE (toggle capture)"])
        new_config["BUTTON"] = ["EJECT", "CAPTURE_MODE"][button]

        led = confirm("Enable status LED?", config.get("LED", "ON") == "ON")
        new_config["LED"] = "ON" if led else "OFF"

        if confirm("Configure WiFi for exfiltration?"):
            new_config["WIFI_SSID"] = prompt("WiFi SSID", config.get("WIFI_SSID", ""))
            new_config["WIFI_PASS"] = prompt("WiFi Password", config.get("WIFI_PASS", ""))
            info("NOTE: Screen Crab supports 2.4 GHz WiFi ONLY — 5 GHz networks will not connect.")
            info("Ensure your router/AP broadcasts a 2.4 GHz band with the SSID you entered.")

        # Write config
        lines = [f"{k} {v}" for k, v in new_config.items()]
        config_path.write_text("\n".join(lines) + "\n")
        ok("config.txt written.")

        # Validate
        new_parsed = parse_config(config_path)
        issues = validate_config(new_parsed)
        if issues:
            warn(f"{len(issues)} issue(s):")
            for issue in issues:
                print(f"    {issue}")
        else:
            ok("Configuration is valid.")
        return True

    elif action == 1:
        editor = run_output("which nano || which vi || which vim || echo nano")
        run(f"{editor} {config_path}", capture=False)
        return True

    elif action == 2:
        issues = validate_config(config)
        if issues:
            warn(f"{len(issues)} issue(s):")
            for issue in issues:
                print(f"    {issue}")
        else:
            ok("Configuration is valid.")
        return True

    elif action == 3:
        print("""
  config.txt Reference:
    LED ON|OFF                  - Status LED toggle (default: ON)
    CAPTURE_MODE IMAGE|VIDEO|OFF - Capture type (default: IMAGE)
    DEDUPLICATE ON|OFF          - Skip identical frames, IMAGE only (default: ON)
    CAPTURE_INTERVAL <secs>     - Time between screenshots (default: 5)
    STORAGE FILL|LOOP           - Full-card behavior (default: FILL)
    BUTTON EJECT|CAPTURE_MODE   - Physical button function (default: EJECT)
    VIDEO_BITRATE LOW|MED|HIGH  - Video quality (default: MEDIUM)
    WIFI_SSID <ssid>            - WiFi network to join for exfil
    WIFI_PASS <password>        - WiFi password

  Cloud C2 integration requires the device.config file (from Cloud C2 portal).

  autoexec.txt: Optional script run at boot for diagnostics.
        """)
        return True

    else:
        info("Keeping current configuration.")
        return True


# ── Firmware Update ───────────────────────────────────────────────────────────

def firmware_update(card: Path) -> bool:
    heading("Step 8 — Firmware Update (MicroSD Method)")
    print(f"""
  Firmware is updated by placing upgrade.bin on the MicroSD card root.
  Download from: {FIRMWARE_URL}

  LED during upgrade:
    Blue/Red alternating  = upgrade detected, starting
    Blue/Magenta          = framework upgrade in progress
    Solid Red (permanent) = upgrade FAILED (do not power off)
    """)

    fw_path = prompt("Path to upgrade.bin (leave blank to skip)")
    if not fw_path:
        info("Skipping firmware update.")
        return True

    fw_path = Path(fw_path).expanduser()
    if not fw_path.exists():
        err(f"Not found: {fw_path}")
        return False

    if fw_path.name != "upgrade.bin":
        warn(f"File is named '{fw_path.name}'. The Screen Crab looks for 'upgrade.bin' exactly.")
        if confirm("Rename to upgrade.bin for deployment?"):
            new_path = fw_path.parent / "upgrade.bin"
            shutil.copy2(fw_path, new_path)
            fw_path = new_path

    dest = card / "upgrade.bin"
    info(f"Copying upgrade.bin to MicroSD card…")
    shutil.copy2(fw_path, dest)
    ok(f"upgrade.bin copied to {dest}")

    print("""
  Next steps:
    1. Safely eject the MicroSD card.
    2. Insert the MicroSD card into the Screen Crab.
    3. Power on the Screen Crab.
    4. LED: Blue/Red alternating = upgrade starting. Do NOT power off.
    5. upgrade.bin is automatically removed after successful flash.
    6. The device reboots clean after completion.
    """)
    return True


# ── Cloud C2 Setup ────────────────────────────────────────────────────────────

def configure_cloud_c2(card: Path):
    heading("Cloud C2 Configuration (Optional)")
    print("""
  Cloud C2 enables remote management of the Screen Crab via WiFi.
  To configure:
    1. Create a Cloud C2 account at: https://c2.hak5.org
    2. Add a device and download the device.config file.
    3. Place device.config on the root of the MicroSD card (next to config.txt).
    4. Ensure WIFI_SSID and WIFI_PASS are set in config.txt.
    """)
    if confirm("Copy a device.config file to the MicroSD card?"):
        c2_path = prompt("Path to device.config file")
        c2_path = Path(c2_path).expanduser()
        if c2_path.exists():
            shutil.copy2(c2_path, card / "device.config")
            ok("device.config copied to MicroSD card.")
        else:
            err(f"Not found: {c2_path}")


# ── Cleanup ───────────────────────────────────────────────────────────────────

def cleanup(card: Path):
    heading("Step 11 — Cleanup")
    print("""
  Before ejecting the MicroSD card:
    • Verify config.txt is correct.
    • If deploying firmware update: verify upgrade.bin is present.
    • Ensure no sensitive data needs to be removed.
    """)
    if get_os() == "macos":
        if confirm(f"Eject MicroSD card at {card}?"):
            run(f"diskutil eject '{card}' 2>/dev/null || true")
            ok("Card ejected.")
    elif get_os() == "linux":
        if confirm(f"Unmount MicroSD card at {card}?"):
            info(f"Unmounting {card} — you may be prompted for sudo…")
            sudo_run(f"umount '{card}' 2>/dev/null || true")
            ok("Card unmounted.")

    ok("Screen Crab is ready.")
    print("""
  Deployment:
    1. Insert MicroSD card into the Screen Crab.
    2. Connect HDMI cables: Source → Screen Crab IN → Display
    3. Power via USB-C (5V 1A).
    4. LED slow blink = capturing. Solid = idle.
    5. Button (when solid green LED) = safe eject.

  Important notes:
    • Screen Crab supports most resolutions below 1920x1080 (16:9).
    • HDCP-protected content will NOT be captured.
    • Connect to 2.4GHz WiFi only (5GHz not supported).
    """)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    require_sudo()

    flavor = get_os_flavor()
    if flavor in ("kali", "debian", "ubuntu", "linux"):
        info("Checking required apt packages (python3-requests)…")
        ensure_apt_packages(["python3-requests"])

    print_banner(TOOL_NAME, DESCRIPTION)

    heading("Step 1 — Insert MicroSD Card")
    print("""
  The Screen Crab is configured via a MicroSD card.
  There is NO SSH access and NO USB enumeration to the host computer.

  To configure:
    1. Remove the MicroSD card from the Screen Crab (or use a blank card).
    2. Insert the card into a MicroSD card reader on this computer.
    3. The card will mount as a drive.

  First time setup:
    • If the card has no config.txt: power on the Screen Crab with the blank card
      inserted to auto-generate a default config.txt, then remove and edit here.

  Expected LED states when Screen Crab is powered in the field:
    ● Solid RED            — Booting / initializing (~15-30 s)
    ● Solid GREEN          — Actively capturing video / recording ✓
    ● Blinking GREEN       — Writing captured data / uploading via WiFi
    ● LED off              — Idle (no HDMI signal, or capture disabled in config)
    ● Rapid RED blink      — Error — check: no MicroSD, filesystem error, or HDCP block
    ● ORANGE/AMBER         — Low storage warning (MicroSD nearly full)

  NOTE: When editing via card reader, the Screen Crab is NOT powered — no LED is visible.
    """)
    pause("Press ENTER once the MicroSD card is inserted in a card reader…")

    # Detect
    heading("Step 2 — MicroSD Detection")
    card = find_card_interactively()
    if not card:
        err("Could not find Screen Crab MicroSD card. Insert card and retry.")
        sys.exit(1)
    ok(f"MicroSD card found at: {card}")

    check_firmware_version()

    # Steps 3-6 (arming mode instructions if not found)
    if not (card / "config.txt").exists():
        warn("No config.txt on card. This may be a blank card or different device.")
        if not confirm("Continue treating this as a Screen Crab MicroSD card?"):
            sys.exit(0)

    # Step 4 — Interface confirmation
    heading("Step 4 — Interface Confirmation")
    info("Screen Crab has NO network interface — configuration is MicroSD only.")
    info("WiFi (for exfil) is configured in config.txt.")

    # Verify filesystem type now that we have the card path
    if card:
        fstype = get_filesystem_type(str(card))
        if fstype:
            info(f"MicroSD filesystem: {fstype}")
            if fstype in ("NTFS",) or fstype.startswith("EXT"):
                warn(f"Filesystem '{fstype}' is NOT supported by Screen Crab!")
                warn("Reformat the MicroSD card as FAT32 or ExFAT before use.")
            elif "FAT" in fstype or "EXFAT" in fstype or "MSDOS" in fstype:
                ok(f"{fstype} filesystem — compatible.")

    # Steps 5-6 — Not applicable (no connection issues for SD card)
    # Step 7 — Internet sharing — N/A (device handles WiFi independently)
    heading("Steps 7-8 — Internet Sharing & Firmware")
    info("Internet sharing not applicable — Screen Crab connects to WiFi independently.")
    info("Firmware update is done by placing upgrade.bin on the MicroSD card.")
    print("""
  Screen Crab known limitations:
    • Maximum capture resolution: 1920×1080 (1080p) — higher input is downscaled.
    • HDCP-protected content (streaming services, BluRay): capture is BLOCKED by HDCP.
    • WiFi: 2.4 GHz ONLY — 5 GHz not supported.
    • MicroSD: FAT32 or ExFAT only; max recommended 128 GB.
    • autoexec.txt: optional shell script run at boot for diagnostics/customisation.
    """)

    if confirm("\nUpdate firmware?"):
        info("Firmware update is done by copying upgrade.bin to the MicroSD root.")
        info("The Screen Crab detects and applies the update automatically on next boot.")
        info("Do NOT power off the Screen Crab during a firmware update — wait for the LED to settle.")
        firmware_update(card)

    # Steps 9-10 — "Payload" is config.txt
    heading("Steps 9-10 — Configuration & Payload (config.txt)")
    info("config.txt controls all Screen Crab behaviour: capture mode, interval, WiFi, storage policy.")
    info("Changes take effect on the NEXT boot — editing config.txt while the Screen Crab is running has no immediate effect.")
    info("To retrieve captured data: power off the Screen Crab, remove the MicroSD card, and read the 'captures/' folder.")
    configure_screen_crab(card)

    # Cloud C2
    if confirm("\nConfigure Cloud C2 remote management?", default=False):
        configure_cloud_c2(card)

    # Step 11
    cleanup(card)


if __name__ == "__main__":
    main()
