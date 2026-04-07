#!/usr/bin/env python3
# ==============================================================================
#  wiegand.py
#  Description : Wiegand protocol card dump and replay for access control
#                systems. Interfaces with Proxmark3 via pm3 CLI subprocess.
#  Supports    : HID Prox, EM4100, Indala formats
#  Requires    : pm3 (Proxmark3 Iceman firmware client) in PATH
#  Usage       : python3 wiegand.py [--port /dev/ttyACM0]
# ==============================================================================

import subprocess
import argparse
import json
import sys
import os
import re
from datetime import datetime

LOOT_DIR = "./loot/wiegand"
os.makedirs(LOOT_DIR, exist_ok=True)


def run_pm3(command: str, port: str = "") -> str:
    """Run a pm3 -c command and return stdout."""
    cmd = ["pm3"]
    if port:
        cmd += ["-p", port]
    cmd += ["-c", command]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] pm3 command timed out"
    except FileNotFoundError:
        print("[!] pm3 not found. Install Proxmark3 Iceman firmware client and ensure pm3 is in PATH.")
        sys.exit(1)


def auto_detect(port: str = "") -> dict:
    """Run lf search and hf search to auto-detect card type."""
    print("[*] Running auto-detect (lf search + hf search)...")
    lf_out = run_pm3("lf search", port)
    hf_out = run_pm3("hf search", port)
    combined = lf_out + "\n" + hf_out

    detected = {"lf": None, "hf": None, "uid": None, "raw": combined}

    if "HID" in lf_out or "hid" in lf_out.lower():
        detected["lf"] = "HID Prox"
    elif "EM410" in lf_out or "em4100" in lf_out.lower():
        detected["lf"] = "EM4100"
    elif "Indala" in lf_out or "indala" in lf_out.lower():
        detected["lf"] = "Indala"
    elif "[+]" in lf_out:
        detected["lf"] = "Unknown LF"

    if "MIFARE" in hf_out:
        detected["hf"] = "MIFARE"
    elif "ISO 14443" in hf_out or "14a" in hf_out.lower():
        detected["hf"] = "ISO 14443-A"
    elif "[+]" in hf_out:
        detected["hf"] = "Unknown HF"

    uid_match = re.search(r"UID[:\s]+([0-9A-Fa-f\s]+)", combined)
    if uid_match:
        detected["uid"] = uid_match.group(1).strip().replace(" ", "")

    return detected


def scan_wiegand(port: str = "") -> dict:
    """Scan for Wiegand (HID Prox) cards and return card data."""
    print("[*] Scanning for Wiegand / HID Prox card...")
    output = run_pm3("lf hid read", port)
    print(output)

    card = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "format": None,
        "facility_code": None,
        "card_number": None,
        "raw_bits": None,
        "raw_output": output,
    }

    fc_match = re.search(r"[Ff]acility[^:]*:\s*(\d+)", output)
    cn_match = re.search(r"[Cc]ard[^:]*[Nn]umber[^:]*:\s*(\d+)", output)
    fmt_match = re.search(r"[Ff]ormat[^:]*:\s*([^\n]+)", output)
    raw_match = re.search(r"[Rr]aw[^:]*:\s*([0-9A-Fa-f]+)", output)

    if fc_match:
        card["facility_code"] = int(fc_match.group(1))
    if cn_match:
        card["card_number"] = int(cn_match.group(1))
    if fmt_match:
        card["format"] = fmt_match.group(1).strip()
    if raw_match:
        card["raw_bits"] = raw_match.group(1).strip()

    if card["facility_code"] is not None:
        print(f"[+] Detected HID Prox — FC: {card['facility_code']}, CN: {card['card_number']}, Format: {card['format']}")
    else:
        print("[!] No HID Prox card data parsed. Check raw output above.")

    return card


def scan_em4100(port: str = "") -> dict:
    """Scan for EM4100 / EM410x cards."""
    print("[*] Scanning for EM4100 / EM410x card...")
    output = run_pm3("lf em 410x reader", port)
    print(output)

    card = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "format": "EM4100",
        "uid": None,
        "raw_output": output,
    }

    uid_match = re.search(r"UID[:\s]+([0-9A-Fa-f]{10})", output)
    if uid_match:
        card["uid"] = uid_match.group(1).upper()
        print(f"[+] EM4100 UID: {card['uid']}")
    else:
        print("[!] No EM4100 UID parsed. Check raw output above.")

    return card


def scan_indala(port: str = "") -> dict:
    """Scan for Indala cards."""
    print("[*] Scanning for Indala card...")
    output = run_pm3("lf indala reader", port)
    print(output)

    card = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "format": "Indala",
        "uid": None,
        "raw_output": output,
    }

    uid_match = re.search(r"UID[:\s]+([0-9A-Fa-f\s]+)", output)
    if uid_match:
        card["uid"] = uid_match.group(1).strip().replace(" ", "").upper()
        print(f"[+] Indala UID: {card['uid']}")
    else:
        print("[!] No Indala UID parsed. Check raw output above.")

    return card


def save_card(card: dict, filename: str = None) -> str:
    """Save card data to JSON file in loot directory."""
    if filename is None:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fmt = card.get("format", "unknown") or "unknown"
        filename = f"card_{fmt.replace(' ', '_').lower()}_{ts}.json"

    filepath = os.path.join(LOOT_DIR, filename)
    with open(filepath, "w") as f:
        json.dump(card, f, indent=2)
    print(f"[+] Card data saved to: {filepath}")
    return filepath


def clone_to_t5577_hid(fc: int, cn: int, port: str = "") -> None:
    """Clone HID Prox data to T5577 blank card."""
    print(f"[*] Cloning HID Prox FC:{fc} CN:{cn} to T5577...")
    output = run_pm3(f"lf hid clone --fc {fc} --cn {cn}", port)
    print(output)

    print("[*] Verifying clone...")
    verify_out = run_pm3("lf hid read", port)
    print(verify_out)
    if str(fc) in verify_out and str(cn) in verify_out:
        print("[+] Clone VERIFIED — T5577 emitting correct FC/CN")
    else:
        print("[!] Clone verification inconclusive. Check output above.")


def clone_to_t5577_em4100(uid: str, port: str = "") -> None:
    """Clone EM4100 UID to T5577 blank card."""
    print(f"[*] Cloning EM4100 UID:{uid} to T5577...")
    output = run_pm3(f"lf em 410x clone --uid {uid}", port)
    print(output)

    print("[*] Verifying clone...")
    verify_out = run_pm3("lf em 410x reader", port)
    print(verify_out)
    if uid.lower() in verify_out.lower():
        print("[+] Clone VERIFIED — T5577 emitting correct UID")
    else:
        print("[!] Clone verification inconclusive. Check output above.")


def simulate_hid(fc: int, cn: int, port: str = "") -> None:
    """Simulate HID Prox card (soft replay via pm3 simulator)."""
    print(f"[*] Simulating HID Prox FC:{fc} CN:{cn}...")
    print("[!] WARNING: This transmits RF. Only use with explicit authorization.")
    output = run_pm3(f"lf hid sim --fc {fc} --cn {cn}", port)
    print(output)


def print_banner():
    print("=" * 60)
    print("  Wiegand / HID Access Card Tool — Proxmark3")
    print("  For authorized physical security testing only")
    print("=" * 60)
    print()


def menu(port: str = ""):
    print_banner()
    while True:
        print("\n[MENU]")
        print("  1. Auto-detect card type (lf search + hf search)")
        print("  2. Scan for Wiegand / HID Prox card (lf hid read)")
        print("  3. Scan for EM4100 card (lf em 410x reader)")
        print("  4. Scan for Indala card (lf indala reader)")
        print("  5. Clone HID Prox to T5577 blank")
        print("  6. Clone EM4100 to T5577 blank")
        print("  7. Simulate / Replay HID Prox card")
        print("  0. Exit")
        print()
        choice = input("Select option: ").strip()

        if choice == "1":
            result = auto_detect(port)
            print(f"\n[+] LF detected: {result['lf']}")
            print(f"[+] HF detected: {result['hf']}")
            if result["uid"]:
                print(f"[+] UID: {result['uid']}")
            save_card({"timestamp": datetime.utcnow().isoformat() + "Z", "auto_detect": result}, "auto_detect.json")

        elif choice == "2":
            card = scan_wiegand(port)
            save_card(card)

        elif choice == "3":
            card = scan_em4100(port)
            save_card(card)

        elif choice == "4":
            card = scan_indala(port)
            save_card(card)

        elif choice == "5":
            fc = input("  Enter Facility Code (FC): ").strip()
            cn = input("  Enter Card Number (CN): ").strip()
            if fc.isdigit() and cn.isdigit():
                clone_to_t5577_hid(int(fc), int(cn), port)
            else:
                print("[!] FC and CN must be integers.")

        elif choice == "6":
            uid = input("  Enter EM4100 UID (10 hex chars): ").strip()
            if re.match(r"^[0-9A-Fa-f]{10}$", uid):
                clone_to_t5577_em4100(uid, port)
            else:
                print("[!] UID must be exactly 10 hex characters.")

        elif choice == "7":
            fc = input("  Enter Facility Code (FC): ").strip()
            cn = input("  Enter Card Number (CN): ").strip()
            confirm = input(f"  Simulate HID FC:{fc} CN:{cn}? This transmits RF. [y/N]: ").strip().lower()
            if confirm == "y" and fc.isdigit() and cn.isdigit():
                simulate_hid(int(fc), int(cn), port)
            else:
                print("[*] Simulation cancelled.")

        elif choice == "0":
            print("[*] Exiting.")
            break
        else:
            print("[!] Invalid choice.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Wiegand card dump and replay via Proxmark3")
    parser.add_argument("--port", "-p", default="", help="Proxmark3 serial port (e.g. /dev/ttyACM0)")
    args = parser.parse_args()
    menu(args.port)
