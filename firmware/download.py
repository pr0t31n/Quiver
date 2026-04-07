#!/usr/bin/env python3
"""
Quiver Firmware Downloader
Downloads the latest firmware for all supported Quiver tools that have
publicly available firmware via GitHub releases.

Usage:
    python3 firmware/download.py

The script queries the GitHub API for the latest release of each tool's
firmware repository, then downloads any assets matching the configured
pattern into firmware/<tool_id>/<subdir>/.

Tools with no publicly downloadable firmware (WiFi Pineapple, Bash Bunny,
Hak5 products, DWM3001CDK, BugBlat) are listed with instructions only.

Environment:
    GITHUB_TOKEN  — set to a personal access token to raise the API rate
                    limit from 60 to 5000 requests/hour.
"""

import re
import sys
from pathlib import Path

# Ensure the parent directory (quiver/) is on sys.path so we can import common.
_SCRIPT_DIR = Path(__file__).resolve().parent
_QUIVER_DIR = _SCRIPT_DIR.parent
if str(_QUIVER_DIR) not in sys.path:
    sys.path.insert(0, str(_QUIVER_DIR))

from common import (
    check_latest_github_release,
    get_github_release_asset_url,
    download_firmware,
    get_firmware_dir,
    info,
    ok,
    warn,
    err,
    heading,
    confirm,
)

# ── Firmware sources ───────────────────────────────────────────────────────────
#
# Each entry maps a tool_id to a dict with:
#   name     — human-readable tool name
#   sources  — list of source dicts, each with:
#       label           — short label shown to the user
#       github          — (owner, repo) tuple for the GitHub API
#       asset_pattern   — regex matched against release asset filenames
#       dest_subdir     — subdirectory under firmware/<tool_id>/ to save into

FIRMWARE_SOURCES = {
    "flipper_zero": {
        "name": "Flipper Zero",
        "sources": [
            {
                "label": "Official Release",
                "github": ("flipperdevices", "flipperzero-firmware"),
                "asset_pattern": r"\.tgz$",
                "dest_subdir": "release",
            },
            {
                "label": "Unleashed Custom Firmware",
                "github": ("DarkFlippers", "unleashed-firmware"),
                "asset_pattern": r"\.tgz$|\.zip$",
                "dest_subdir": "unleashed",
            },
        ],
    },
    "hackrf_one": {
        "name": "HackRF One",
        "sources": [
            {
                "label": "HackRF USB firmware",
                "github": ("greatscottgadgets", "hackrf"),
                "asset_pattern": r"hackrf_usb.*\.dfu$|hackrf_usb.*\.bin$",
                "dest_subdir": "hackrf_usb",
            }
        ],
    },
    "proxmark3": {
        "name": "Proxmark3 (RRG/Iceman)",
        "sources": [
            {
                "label": "RRG Iceman fork",
                "github": ("RfidResearchGroup", "proxmark3"),
                "asset_pattern": r"proxmark3.*\.zip$|proxmark3.*\.tar\.gz$",
                "dest_subdir": "rrg",
            }
        ],
    },
    "ubertooth_one": {
        "name": "Ubertooth One",
        "sources": [
            {
                "label": "Ubertooth release",
                "github": ("greatscottgadgets", "ubertooth"),
                "asset_pattern": r"ubertooth.*\.tar\.xz$|ubertooth.*\.zip$",
                "dest_subdir": "release",
            }
        ],
    },
    "chameleon_ultra": {
        "name": "Chameleon Ultra",
        "sources": [
            {
                "label": "ChameleonUltra release",
                "github": ("RfidResearchGroup", "ChameleonUltra"),
                "asset_pattern": r"\.zip$|application.*\.bin$",
                "dest_subdir": "release",
            }
        ],
    },
    "yardstick_one": {
        "name": "Yardstick One (RfCat)",
        "sources": [
            {
                "label": "rfcat release",
                "github": ("atlas0fd00m", "rfcat"),
                "asset_pattern": r"\.tar\.gz$|\.zip$",
                "dest_subdir": "rfcat",
            }
        ],
    },
    "greatfet_one": {
        "name": "GreatFET One",
        "sources": [
            {
                "label": "GreatFET release",
                "github": ("greatscottgadgets", "greatfet"),
                "asset_pattern": r"\.tar\.gz$|firmware.*\.bin$",
                "dest_subdir": "release",
            }
        ],
    },
    "cynthion": {
        "name": "Cynthion",
        "sources": [
            {
                "label": "Cynthion release",
                "github": ("greatscottgadgets", "cynthion"),
                "asset_pattern": r"\.tar\.gz$|\.zip$|firmware.*\.bin$",
                "dest_subdir": "release",
            }
        ],
    },
    "nordic_nrf52840": {
        "name": "Nordic nRF52840",
        "sources": [
            {
                "label": "nRF Sniffer for Bluetooth LE",
                "github": ("NordicSemiconductor", "nRF-Sniffer-for-Bluetooth-LE"),
                "asset_pattern": r"nRF_Sniffer.*\.zip$",
                "dest_subdir": "ble_sniffer",
            },
        ],
    },
    "bus_pirate_36": {
        "name": "Bus Pirate 3.6",
        "sources": [
            {
                "label": "Bus Pirate firmware",
                "github": ("BusPirate", "Bus_Pirate"),
                "asset_pattern": r"\.hex$|firmware.*\.zip$",
                "dest_subdir": "release",
            }
        ],
    },
    "evil_crow": {
        "name": "Evil Crow RF V2",
        "sources": [
            {
                "label": "EvilCrowRF-V2 release",
                "github": ("joelsernamoreno", "EvilCrowRF-V2"),
                "asset_pattern": r"EvilCrowRF.*\.bin$|EvilCrowRF.*\.zip$",
                "dest_subdir": "release",
            }
        ],
    },
    "cc2531": {
        "name": "CC2531",
        "sources": [
            {
                "label": "Z-Stack Coordinator firmware",
                "github": ("Koenkk", "Z-Stack-firmware"),
                "asset_pattern": r"CC2531.*coordinator.*\.zip$|CC2531.*coordinator.*\.hex$",
                "dest_subdir": "coordinator",
            },
            {
                "label": "Z-Stack Sniffer firmware",
                "github": ("Koenkko", "Z-Stack-firmware"),
                "asset_pattern": r"CC2531.*sniffer.*\.zip$|CC2531.*sniffer.*\.hex$",
                "dest_subdir": "sniffer",
            },
        ],
    },
    "sonoff_zbdongle_e": {
        "name": "Sonoff Zigbee Dongle-E",
        "sources": [
            {
                "label": "Z-Stack Coordinator for Sonoff",
                "github": ("Koenkk", "Z-Stack-firmware"),
                "asset_pattern": r"Sonoff.*coordinator.*\.zip$|sonoff.*coordinator.*\.hex$",
                "dest_subdir": "coordinator",
            }
        ],
    },
    "wifi_duck": {
        "name": "WiFi Duck",
        "sources": [
            {
                "label": "esp8266_wifi_duck release",
                "github": ("spacehuhn", "esp8266_wifi_duck"),
                "asset_pattern": r"\.bin$|firmware.*\.zip$",
                "dest_subdir": "release",
            }
        ],
    },
    "photon_2": {
        "name": "Particle Photon 2",
        "sources": [
            {
                "label": "Particle Device OS",
                "github": ("particle-iot", "device-os"),
                "asset_pattern": r"particle_device_os.*\.zip$",
                "dest_subdir": "device_os",
            }
        ],
    },
    "lilygo_tdeck": {
        "name": "LilyGo T-Deck",
        "sources": [
            {
                "label": "T-Deck release",
                "github": ("Xinyuan-LilyGO", "T-Deck"),
                "asset_pattern": r"\.bin$|firmware.*\.zip$|T-Deck.*\.zip$",
                "dest_subdir": "release",
            }
        ],
    },
}

# ── Tools with no public firmware ─────────────────────────────────────────────
#
# These tools require authentication, a separate account, or a closed portal
# to obtain firmware.  We print instructions only and skip download attempts.

MANUAL_FIRMWARE_TOOLS = {
    "wifi_pineapple": {
        "name": "WiFi Pineapple (Hak5)",
        "instructions": (
            "WiFi Pineapple firmware is distributed exclusively through the Hak5 portal.\n"
            "  1. Log in at: https://shop.hak5.org/account\n"
            "  2. Navigate to your order and locate the Firmware Download link.\n"
            "  3. Download the .bin file for your Pineapple model (Mark VII / Nano / Tetra).\n"
            "  4. Flash via the web UI: http://172.16.42.1 → Advanced → Upgrade.\n"
            "  Changelog: https://docs.hak5.org/wifi-pineapple/firmware-updates"
        ),
    },
    "bash_bunny": {
        "name": "Bash Bunny (Hak5)",
        "instructions": (
            "Bash Bunny firmware is available via the Hak5 downloads page.\n"
            "  1. Visit: https://downloads.hak5.org/bunny\n"
            "  2. Download the latest firmware .tar.gz.\n"
            "  3. Copy to the root of the Bash Bunny USB drive in storage mode.\n"
            "  4. Safely eject and unplug — firmware installs on next boot.\n"
            "  Docs: https://docs.hak5.org/bash-bunny/firmware-updates/upgrading-firmware"
        ),
    },
    "key_croc": {
        "name": "Key Croc (Hak5)",
        "instructions": (
            "Key Croc firmware is available via the Hak5 downloads page.\n"
            "  1. Visit: https://downloads.hak5.org/croc\n"
            "  2. Download the latest firmware .tar.gz.\n"
            "  3. Copy to the root of the Key Croc USB drive in arming mode.\n"
            "  4. Safely eject and unplug — firmware installs on next boot.\n"
            "  Docs: https://docs.hak5.org/key-croc"
        ),
    },
    "screen_crab": {
        "name": "Screen Crab (Hak5)",
        "instructions": (
            "Screen Crab firmware is available via the Hak5 downloads page.\n"
            "  1. Visit: https://downloads.hak5.org/crab\n"
            "  2. Download the latest firmware.\n"
            "  3. Follow the flashing procedure in the Hak5 documentation.\n"
            "  Docs: https://docs.hak5.org/screen-crab"
        ),
    },
    "packet_squirrel": {
        "name": "Packet Squirrel (Hak5)",
        "instructions": (
            "Packet Squirrel firmware is available via the Hak5 downloads page.\n"
            "  1. Visit: https://downloads.hak5.org/squirrel\n"
            "  2. Download the latest firmware .bin.\n"
            "  3. Place on the Squirrel USB drive, then update via the web UI.\n"
            "  Docs: https://docs.hak5.org/packet-squirrel"
        ),
    },
    "signal_owl": {
        "name": "Signal Owl (Hak5)",
        "instructions": (
            "Signal Owl firmware is available via the Hak5 downloads page.\n"
            "  1. Visit: https://downloads.hak5.org/owl\n"
            "  2. Download the latest firmware.\n"
            "  3. Follow the Hak5 flashing documentation.\n"
            "  Docs: https://docs.hak5.org/signal-owl"
        ),
    },
    "lan_turtle": {
        "name": "LAN Turtle (Hak5)",
        "instructions": (
            "LAN Turtle firmware is available via the Hak5 downloads page.\n"
            "  1. Visit: https://downloads.hak5.org/turtle\n"
            "  2. Download the latest OpenWRT-based .bin.\n"
            "  3. Flash via the Turtle web interface or sysupgrade command.\n"
            "  Docs: https://docs.hak5.org/lan-turtle"
        ),
    },
    "shark_jack": {
        "name": "Shark Jack (Hak5)",
        "instructions": (
            "Shark Jack firmware is available via the Hak5 downloads page.\n"
            "  1. Visit: https://downloads.hak5.org/shark\n"
            "  2. Download the latest firmware.\n"
            "  3. Flash via the Shark Jack web interface.\n"
            "  Docs: https://docs.hak5.org/shark-jack"
        ),
    },
    "dwm3001cdk": {
        "name": "DWM3001CDK (Qorvo)",
        "instructions": (
            "DWM3001CDK firmware is provided by Qorvo through their MyQorvo portal.\n"
            "  1. Register / log in at: https://www.qorvo.com/products/d/da008154\n"
            "  2. Download the DWM3001CDK SDK which includes pre-built firmware images.\n"
            "  3. Flash with nrfjprog or J-Link: nrfjprog --program <hex> --chiperase\n"
            "  SDK docs: https://www.qorvo.com/products/d/da008154"
        ),
    },
    "bugblat_minisniffer2": {
        "name": "BugBlat MiniSniffer2",
        "instructions": (
            "BugBlat MiniSniffer2 firmware is distributed via the BugBlat website.\n"
            "  1. Visit: https://www.bugblat.com/products/minisniffer/\n"
            "  2. Firmware updates are provided as part of the Windows GUI installer.\n"
            "  3. Run the installer on Windows to update firmware automatically.\n"
            "  There is no standalone public firmware binary for manual flashing."
        ),
    },
}


# ── Internal helpers ───────────────────────────────────────────────────────────

def _get_all_release_asset_urls(owner: str, repo: str, tag: str,
                                 asset_pattern: str) -> list:
    """
    Return a list of (asset_name, browser_download_url) for ALL assets in a
    GitHub release whose name matches *asset_pattern*.

    Falls back gracefully to an empty list on any network or API error.
    """
    api_url = (
        f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{tag}"
        if tag else
        f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    )
    import os as _os
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = _os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        try:
            import requests as _req
            resp = _req.get(api_url, headers=headers, timeout=10)
            resp.raise_for_status()
            data = resp.json()
        except ImportError:
            import urllib.request as _urlreq
            import json as _json
            req = _urlreq.Request(api_url, headers=headers)
            with _urlreq.urlopen(req, timeout=10) as r:
                data = _json.loads(r.read())

        matches = []
        for asset in data.get("assets", []):
            name = asset.get("name", "")
            if re.search(asset_pattern, name, re.IGNORECASE):
                matches.append((name, asset.get("browser_download_url", "")))
        return matches

    except Exception as e:
        warn(f"Could not list release assets for {owner}/{repo}: {e}")
        return []


def _print_manual_instructions():
    """Print firmware acquisition instructions for tools without public firmware."""
    heading("Tools Requiring Manual Firmware Download")
    info("The following tools do not provide publicly downloadable firmware.")
    info("Visit the indicated URLs to obtain firmware files manually.")
    info("")
    for tool_id, cfg in MANUAL_FIRMWARE_TOOLS.items():
        info(f"  {cfg['name']}")
        for line in cfg["instructions"].splitlines():
            info(f"    {line}")
        info("")


def _select_tools() -> list:
    """
    Ask the user whether to process all tools or pick specific ones.
    Returns a list of (tool_id, tool_cfg) tuples to process.
    """
    all_tools = list(FIRMWARE_SOURCES.items())
    total = len(all_tools)

    info(f"\nFound {total} tools with public firmware sources:")
    for idx, (tid, cfg) in enumerate(all_tools):
        src_count = len(cfg["sources"])
        src_word = "source" if src_count == 1 else "sources"
        info(f"  [{idx + 1:2d}] {cfg['name']} ({src_count} {src_word})")
    info("")

    choice = ""
    while choice not in ("a", "s", "q"):
        try:
            choice = input(
                "  (a) Download all  |  (s) Select specific tools  |  (q) Quit: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            info("\nAborted.")
            sys.exit(0)

    if choice == "q":
        info("Quitting.")
        sys.exit(0)

    if choice == "a":
        return all_tools

    # Interactive selection
    info("Enter tool numbers separated by spaces or commas (e.g. 1 3 5):")
    try:
        raw = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        info("\nAborted.")
        sys.exit(0)

    selected = []
    for token in re.split(r"[\s,]+", raw):
        token = token.strip()
        if not token:
            continue
        try:
            idx = int(token) - 1
            if 0 <= idx < total:
                selected.append(all_tools[idx])
            else:
                warn(f"  Ignoring out-of-range number: {token}")
        except ValueError:
            warn(f"  Ignoring non-numeric token: {token}")

    if not selected:
        warn("No valid tools selected. Exiting.")
        sys.exit(0)

    info(f"\nSelected {len(selected)} tool(s):")
    for tid, cfg in selected:
        info(f"  - {cfg['name']}")
    info("")
    return selected


# ── Per-source download logic ──────────────────────────────────────────────────

def _process_source(tool_id: str, tool_name: str, source: dict,
                    stats: dict) -> None:
    """
    Handle one firmware source entry: check latest release, then download
    all matching assets.

    Updates *stats* in-place with keys: downloaded, skipped, failed.
    """
    label = source["label"]
    owner, repo = source["github"]
    asset_pattern = source["asset_pattern"]
    dest_subdir = source["dest_subdir"]

    info(f"  Source : {label}")
    info(f"  Repo   : https://github.com/{owner}/{repo}")

    # ── Check latest release ──────────────────────────────────────────────────
    tag, release_url = check_latest_github_release(owner, repo)
    if not tag:
        warn(f"  Could not determine latest release for {owner}/{repo}. Skipping.")
        stats["failed"] += 1
        return

    info(f"  Latest : {tag}")
    if release_url:
        info(f"  URL    : {release_url}")

    # ── Resolve destination directory ─────────────────────────────────────────
    dest_dir = get_firmware_dir(tool_id) / dest_subdir / tag
    dest_dir.mkdir(parents=True, exist_ok=True)

    # ── Find matching assets ───────────────────────────────────────────────────
    assets = _get_all_release_asset_urls(owner, repo, tag, asset_pattern)
    if not assets:
        warn(f"  No assets matching pattern '{asset_pattern}' found in release {tag}.")
        warn(f"  Check manually: {release_url}")
        stats["skipped"] += 1
        return

    info(f"  Found {len(assets)} matching asset(s):")
    for asset_name, _ in assets:
        info(f"    - {asset_name}")

    # ── Download each asset ───────────────────────────────────────────────────
    for asset_name, asset_url in assets:
        dest_file = dest_dir / asset_name

        # Skip if already downloaded (same filename, non-zero size)
        if dest_file.exists() and dest_file.stat().st_size > 0:
            ok(f"  Already downloaded: {asset_name} — skipping.")
            stats["skipped"] += 1
            continue

        success = download_firmware(asset_url, dest_file, tool_name=tool_name)
        if success:
            stats["downloaded"] += 1
            ok(f"  Saved: {dest_file}")
        else:
            stats["failed"] += 1
            err(f"  Failed to download: {asset_name}")
            info(f"  Manual download: {asset_url}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    heading("Quiver Firmware Downloader")
    info("Downloads the latest firmware for all supported Quiver tools")
    info("that have publicly available GitHub releases.")
    info("")
    info("Firmware is saved to: firmware/<tool_id>/<subdir>/<tag>/")
    info("")
    info("Tip: Set the GITHUB_TOKEN environment variable to raise the API")
    info("     rate limit from 60 to 5000 requests/hour.")
    info("")

    # Print manual-only tools first so the user is aware
    _print_manual_instructions()

    # Let the user choose which tools to process
    selected_tools = _select_tools()

    # ── Processing loop ────────────────────────────────────────────────────────
    stats = {"downloaded": 0, "skipped": 0, "failed": 0}
    results = []  # list of (tool_name, source_label, status, detail)

    total_tools = len(selected_tools)
    for tool_idx, (tool_id, tool_cfg) in enumerate(selected_tools, start=1):
        tool_name = tool_cfg["name"]
        sources = tool_cfg["sources"]

        heading(f"[{tool_idx}/{total_tools}] {tool_name}")

        for src_idx, source in enumerate(sources, start=1):
            label = source["label"]
            owner, repo = source["github"]
            asset_pattern = source["asset_pattern"]
            dest_subdir = source["dest_subdir"]

            if len(sources) > 1:
                info(f"\n  [{src_idx}/{len(sources)}] {label}")
            else:
                info("")

            info(f"  Source : {label}")
            info(f"  Repo   : https://github.com/{owner}/{repo}")

            # ── Check latest release ──────────────────────────────────────────
            tag, release_url = check_latest_github_release(owner, repo)
            if not tag:
                warn(f"  Could not determine latest release for {owner}/{repo}. Skipping.")
                stats["failed"] += 1
                results.append((tool_name, label, "FAILED", "Could not reach GitHub API"))
                continue

            info(f"  Latest : {tag}")
            if release_url:
                info(f"  URL    : {release_url}")

            # ── Resolve destination directory ─────────────────────────────────
            dest_dir = get_firmware_dir(tool_id) / dest_subdir / tag
            dest_dir.mkdir(parents=True, exist_ok=True)

            # ── Find matching assets ──────────────────────────────────────────
            assets = _get_all_release_asset_urls(owner, repo, tag, asset_pattern)
            if not assets:
                warn(f"  No assets matching pattern '{asset_pattern}' in release {tag}.")
                if release_url:
                    warn(f"  Check manually: {release_url}")
                stats["skipped"] += 1
                results.append((tool_name, label, "SKIPPED", f"No matching assets in {tag}"))
                continue

            info(f"  Found {len(assets)} matching asset(s):")
            for asset_name, _ in assets:
                info(f"    - {asset_name}")

            # ── Download each asset ───────────────────────────────────────────
            src_downloaded = 0
            src_failed = 0

            for asset_name, asset_url in assets:
                dest_file = dest_dir / asset_name

                # Skip if already downloaded
                if dest_file.exists() and dest_file.stat().st_size > 0:
                    ok(f"  Already have: {asset_name} — skipping.")
                    stats["skipped"] += 1
                    continue

                success = download_firmware(asset_url, dest_file,
                                            tool_name=tool_name)
                if success:
                    src_downloaded += 1
                    stats["downloaded"] += 1
                    ok(f"  Saved: {dest_file.relative_to(_QUIVER_DIR)}")
                else:
                    src_failed += 1
                    stats["failed"] += 1
                    err(f"  Failed: {asset_name}")
                    info(f"  Manual: {asset_url}")

            # Record per-source result for summary
            if src_failed > 0 and src_downloaded == 0:
                results.append((tool_name, label, "FAILED",
                                 f"All {src_failed} asset(s) failed"))
            elif src_failed > 0:
                results.append((tool_name, label, "PARTIAL",
                                 f"{src_downloaded} downloaded, {src_failed} failed"))
            elif src_downloaded > 0:
                results.append((tool_name, label, "OK",
                                 f"{src_downloaded} file(s) → {dest_dir.relative_to(_QUIVER_DIR)}"))
            else:
                results.append((tool_name, label, "SKIPPED",
                                 "All files already present"))

    # ── Summary ────────────────────────────────────────────────────────────────
    heading("Download Summary")
    info(f"  Downloaded : {stats['downloaded']}")
    info(f"  Skipped    : {stats['skipped']}  (already present or no matching assets)")
    info(f"  Failed     : {stats['failed']}")
    info("")

    if results:
        col_tool  = max(len(r[0]) for r in results)
        col_src   = max(len(r[1]) for r in results)
        col_status = max(len(r[2]) for r in results)

        info(
            f"  {'Tool':<{col_tool}}  {'Source':<{col_src}}  "
            f"{'Status':<{col_status}}  Detail"
        )
        info("  " + "-" * (col_tool + col_src + col_status + 20))

        for tool_name, label, status, detail in results:
            if status == "OK":
                ok(f"  {tool_name:<{col_tool}}  {label:<{col_src}}  "
                   f"{status:<{col_status}}  {detail}")
            elif status == "SKIPPED":
                info(f"  {tool_name:<{col_tool}}  {label:<{col_src}}  "
                     f"{status:<{col_status}}  {detail}")
            elif status == "PARTIAL":
                warn(f"  {tool_name:<{col_tool}}  {label:<{col_src}}  "
                     f"{status:<{col_status}}  {detail}")
            else:
                err(f"  {tool_name:<{col_tool}}  {label:<{col_src}}  "
                    f"{status:<{col_status}}  {detail}")

    info("")
    if stats["failed"] == 0:
        ok("All firmware downloads completed successfully.")
    elif stats["downloaded"] > 0:
        warn("Some downloads failed. Check the summary above.")
        info("Re-run this script to retry failed downloads.")
    else:
        err("No firmware was downloaded. Check network connectivity and GitHub API access.")
        info("If you are being rate-limited, set the GITHUB_TOKEN environment variable:")
        info("  export GITHUB_TOKEN=<your_personal_access_token>")

    firmware_base = get_firmware_dir()
    info(f"\nFirmware directory: {firmware_base}")


if __name__ == "__main__":
    main()
