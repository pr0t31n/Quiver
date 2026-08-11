#!/usr/bin/env python3
"""Quiver community-payload importer.

Clones the canonical, PUBLICLY-maintained payload repositories for each supported
device into  payloads/<tool_id>/community/<repo>/  and indexes the payloads it
finds into  payloads/payloads.json  so they appear in that device's payload list
in the Quiver UI.

Nothing is bundled in Quiver: content is fetched from the upstream maintainers at
run time (shallow git clone) and belongs to those projects. Re-run any time to
pull updates — the importer is idempotent (git pull if the repo already exists,
and payloads.json entries are de-duplicated by path).

Usage:
    python3 import_community_payloads.py                 # all devices below
    python3 import_community_payloads.py --tools flipper_zero,key_croc
    python3 import_community_payloads.py --index-only     # re-index without cloning
    python3 import_community_payloads.py --list           # show the repo registry
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

PAYLOADS_DIR = Path(__file__).resolve().parent
INDEX = PAYLOADS_DIR / "payloads.json"

# Canonical public payload repos per device. Only dedicated payload collections
# are listed (not whole-firmware repos). "large" repos are shallow-cloned and the
# importer warns before pulling them.
REPOS = {
    "bash_bunny":       [("https://github.com/hak5/bashbunny-payloads", False)],
    "usb_rubber_ducky": [("https://github.com/hak5/usbrubberducky-payloads", False)],
    "rubber_ducky_3":   [("https://github.com/hak5/usbrubberducky-payloads", False)],
    "omg_cable":        [("https://github.com/O-MG/mg-payloads", False)],
    "packet_squirrel":  [("https://github.com/hak5/packetsquirrel-payloads", False)],
    "shark_jack":       [("https://github.com/hak5/sharkjack-payloads", False)],
    "signal_owl":       [("https://github.com/hak5/signalowl-payloads", False)],
    "lan_turtle":       [("https://github.com/hak5/lanturtle-payloads", False)],
    "key_croc":         [("https://github.com/hak5/keycroc-payloads", False)],
    "flipper_zero":     [("https://github.com/UberGuidoZ/Flipper", True)],  # very large
    # BadUSB: public Arduino attack SKETCHES (.ino source — compile with the board's
    # library before flashing; not directly flashable .hex).
    "badusb":           [("https://github.com/MTK911/Attiny85", False),
                         ("https://github.com/CedArctic/DigiSpark-Scripts", False)],
}

# Which files count as a "payload" per device — the index points at these.
INDEX_PATTERNS = {
    "bash_bunny":       ["payload.txt"],
    "usb_rubber_ducky": ["payload.txt"],
    "rubber_ducky_3":   ["payload.txt"],
    "omg_cable":        ["payload.txt", "*.dd"],
    "packet_squirrel":  ["payload.sh"],
    "shark_jack":       ["payload.sh"],
    "signal_owl":       ["payload.sh"],
    "lan_turtle":       ["payload.sh"],
    "key_croc":         ["payload.txt", "*.croc"],
    "flipper_zero":     ["*.sub", "*.ir", "*.nfc", "*.rfid", "*.txt"],
    "badusb":           ["*.ino"],   # Arduino sketches — compile before flashing
}

MAX_ENTRIES_PER_TOOL = 500   # safety cap so a giant repo can't bloat the index


def _run(cmd, cwd=None):
    print("  $ " + " ".join(cmd))
    return subprocess.run(cmd, cwd=cwd).returncode


def clone_or_update(url, dest, large=False):
    name = url.rstrip("/").split("/")[-1]
    target = dest / name
    if target.exists():
        print(f"  updating {name} …")
        _run(["git", "-C", str(target), "pull", "--ff-only"])
        return target
    if large:
        print(f"  NOTE: {name} is a large repository (shallow clone, may be big).")
    dest.mkdir(parents=True, exist_ok=True)
    print(f"  cloning {url} → {target} …")
    if _run(["git", "clone", "--depth", "1", url, str(target)]) != 0:
        print(f"  WARN: clone failed for {url}")
        return None
    return target


def index_tool(tool_id, entries_out):
    base = PAYLOADS_DIR / tool_id / "community"
    if not base.exists():
        return 0
    patterns = INDEX_PATTERNS.get(tool_id, ["payload.txt", "payload.sh"])
    found = []
    for pat in patterns:
        found += list(base.rglob(pat))
    found = sorted(set(found))[:MAX_ENTRIES_PER_TOOL]
    added = 0
    for f in found:
        rel = f.relative_to(PAYLOADS_DIR)
        # human name = payload's parent dir (or file stem for flat repos)
        label = f.parent.name if f.name in ("payload.txt", "payload.sh") else f.stem
        repo = rel.parts[2] if len(rel.parts) > 2 else "community"
        entries_out.setdefault(tool_id, []).append({
            "name": f"[community] {label}",
            "description": f"Community payload from {repo} ({f.name}). "
                           f"Publicly-maintained upstream collection imported via "
                           f"import_community_payloads.py.",
            "path": f"payloads/{rel.as_posix()}",
            "added": "2026-08-11T00:00:00Z",
        })
        added += 1
    return added


def merge_index(new_entries):
    d = json.loads(INDEX.read_text()) if INDEX.exists() else {}
    total = 0
    for tool, entries in new_entries.items():
        d.setdefault(tool, [])
        have = {e.get("path") for e in d[tool] if isinstance(e, dict)}
        for e in entries:
            if e["path"] in have:
                continue
            d[tool].append(e)
            have.add(e["path"])
            total += 1
    INDEX.write_text(json.dumps(d, indent=2, ensure_ascii=False))
    return total


def main():
    ap = argparse.ArgumentParser(description="Import community payload repos into Quiver")
    ap.add_argument("--tools", help="comma-separated tool ids (default: all)")
    ap.add_argument("--index-only", action="store_true", help="re-index without cloning")
    ap.add_argument("--list", action="store_true", help="print the repo registry and exit")
    args = ap.parse_args()

    if args.list:
        for t, repos in REPOS.items():
            for url, large in repos:
                print(f"  {t:20s} {url}{'  (large)' if large else ''}")
        return

    if not shutil.which("git") and not args.index_only:
        print("ERROR: git not found — install git or use --index-only.")
        sys.exit(1)

    tools = args.tools.split(",") if args.tools else list(REPOS)
    new_entries = {}
    for tool in tools:
        if tool not in REPOS:
            print(f"skip {tool}: not in registry")
            continue
        print(f"[{tool}]")
        if not args.index_only:
            for url, large in REPOS[tool]:
                clone_or_update(url, PAYLOADS_DIR / tool / "community", large)
        n = index_tool(tool, new_entries)
        print(f"  indexed {n} payload(s)")

    total = merge_index(new_entries)
    print(f"\nDone. Added {total} new payload index entries to payloads.json.")
    print("Restart Quiver (or refresh the device page) to see them.")


if __name__ == "__main__":
    main()
