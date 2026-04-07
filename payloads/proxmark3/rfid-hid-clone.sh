#!/usr/bin/env bash
# ==================================================================
#  rfid-hid-clone.sh
#  Description : Read HID Prox (26-bit H10301) LF access card and
#                clone to T5577. If FC/CN not supplied, reads first.
#  Requires    : pm3 (Proxmark3 Iceman client)
#  Usage       : ./rfid-hid-clone.sh [facility_code] [card_num] [pm3_port]
#  Example     : ./rfid-hid-clone.sh 101 12345
# ==================================================================

set -euo pipefail
FC="${1:-}"; CN="${2:-}"; PORT="${3:-}"
PM3_CMD="pm3"; [ -n "$PORT" ] && PM3_CMD="pm3 -p $PORT"
LOOT_DIR="./loot/hid-clone-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  Proxmark3 — HID Prox Clone"
echo " =================================================="

if [ -z "$FC" ] || [ -z "$CN" ]; then
    echo "[*] Reading HID Prox card..."
    READ_OUT=$($PM3_CMD -c "lf hid reader" 2>&1 | tee "${LOOT_DIR}/hid_read.txt")
    FC=$(echo "$READ_OUT" | grep -oiE 'Facility Code: [0-9]+' | awk '{print $NF}' | head -1 || true)
    CN=$(echo "$READ_OUT" | grep -oiE 'Card Number: [0-9]+' | awk '{print $NF}' | head -1 || true)
    if [ -z "$FC" ] || [ -z "$CN" ]; then
        echo "[!] Could not parse FC/CN from HID reader output."
        echo "    Raw output saved to ${LOOT_DIR}/hid_read.txt"
        exit 1
    fi
    echo "[+] FC=$FC CN=$CN"
fi

echo "[*] Cloning HID H10301 (FC=$FC, CN=$CN) to T5577..."
$PM3_CMD -c "lf hid clone --fc $FC --cn $CN" 2>&1 | tee "${LOOT_DIR}/hid_clone.txt"

echo "[*] Verifying clone..."
$PM3_CMD -c "lf hid reader" 2>&1 | tee "${LOOT_DIR}/hid_verify.txt"
echo "[+] Loot: $LOOT_DIR"
