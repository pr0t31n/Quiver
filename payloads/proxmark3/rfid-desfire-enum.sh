#!/usr/bin/env bash
# ==================================================================
#  rfid-desfire-enum.sh
#  Description : DESFire card enumeration — reads AID list, key
#                settings, and file inventory without cracking keys.
#  Requires    : pm3 (Proxmark3 Iceman client)
#  Usage       : ./rfid-desfire-enum.sh [pm3_port]
# ==================================================================

set -euo pipefail
PORT="${1:-}"; PM3_CMD="pm3"; [ -n "$PORT" ] && PM3_CMD="pm3 -p $PORT"
LOOT_DIR="./loot/desfire-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  Proxmark3 — DESFire Enumeration"
echo " =================================================="

echo "[*] Card info..."
$PM3_CMD -c "hf 14a reader" 2>&1 | tee "${LOOT_DIR}/card_info.txt"

echo "[*] DESFire card info (PICC level)..."
$PM3_CMD -c "hf mfdes info" 2>&1 | tee "${LOOT_DIR}/desfire_info.txt"

echo "[*] Application list (AID enumeration)..."
$PM3_CMD -c "hf mfdes getappids" 2>&1 | tee "${LOOT_DIR}/app_ids.txt"

# For each AID found, enumerate file list
APPS=$(grep -oE 'AID: [0-9A-Fa-f]+' "${LOOT_DIR}/app_ids.txt" | awk '{print $2}' 2>/dev/null || true)
for aid in $APPS; do
    echo "[*] Selecting AID $aid..."
    $PM3_CMD -c "hf mfdes selectapp --aid $aid; hf mfdes getfileids; hf mfdes getfilesettings" \
        2>&1 | tee "${LOOT_DIR}/aid_${aid}_files.txt"
done

echo ""
echo "[+] DESFire enumeration complete. Loot: $LOOT_DIR"
