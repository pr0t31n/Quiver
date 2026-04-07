#!/usr/bin/env bash
# ==================================================================
#  rfid-clone-em410x.sh
#  Description : Read EM4100 LF tag and clone to T5577 blank card.
#                If no UID supplied, reads from card first.
#  Requires    : pm3 (Proxmark3 Iceman client)
#  Usage       : ./rfid-clone-em410x.sh [uid_hex] [pm3_port]
#  Example     : ./rfid-clone-em410x.sh 1234567890
# ==================================================================

set -euo pipefail

UID_HEX="${1:-}"
PORT="${2:-}"
PM3_CMD="pm3"; [ -n "$PORT" ] && PM3_CMD="pm3 -p $PORT"
LOOT_DIR="./loot/rfid-em410x-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  Proxmark3 — EM4100 LF Clone"
echo " =================================================="

if [ -z "$UID_HEX" ]; then
    echo "[*] No UID supplied — reading from card..."
    READ_OUT=$($PM3_CMD -c "lf em 410x reader" 2>&1 | tee "${LOOT_DIR}/em410x_read.txt")
    # Extract UID from output
    UID_HEX=$(echo "$READ_OUT" | grep -oiE 'EM 410x ID: [0-9A-Fa-f]+' | awk '{print $NF}' | head -1 || true)
    if [ -z "$UID_HEX" ]; then
        echo "[!] Could not read EM4100 card. Ensure card is on antenna."
        exit 1
    fi
    echo "[+] Read UID: $UID_HEX"
fi

echo "[*] Cloning UID $UID_HEX to T5577..."
$PM3_CMD -c "lf em 410x clone --uid $UID_HEX" 2>&1 | tee "${LOOT_DIR}/em410x_clone.txt"

echo ""
echo "[+] Clone complete. Remove original card, present blank T5577 to reader."
echo "[*] Verify clone:"
$PM3_CMD -c "lf em 410x reader" 2>&1 | tee "${LOOT_DIR}/em410x_verify.txt"
echo "[+] Loot: $LOOT_DIR"
