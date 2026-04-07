#!/usr/bin/env bash
# ==================================================================
#  rfid-survey.sh
#  Description : Proxmark3 auto-detection RFID survey. Runs both
#                lf search and hf search to identify card type,
#                saves results to loot directory.
#  Requires    : pm3 (Proxmark3 Iceman client)
#  Usage       : ./rfid-survey.sh [pm3_port]
# ==================================================================

set -euo pipefail

PORT="${1:-}"
LOOT_DIR="./loot/rfid-survey-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOOT_DIR"

PM3_CMD="pm3"
[ -n "$PORT" ] && PM3_CMD="pm3 -p $PORT"

echo " =================================================="
echo "  Proxmark3 — RFID Survey"
echo " =================================================="

echo "[*] LF search (125 kHz)..."
$PM3_CMD -c "lf search" 2>&1 | tee "${LOOT_DIR}/lf_search.txt"

echo ""
echo "[*] HF search (13.56 MHz)..."
$PM3_CMD -c "hf search" 2>&1 | tee "${LOOT_DIR}/hf_search.txt"

echo ""
echo "[*] HF 14a reader (ISO 14443-A)..."
$PM3_CMD -c "hf 14a reader" 2>&1 | tee "${LOOT_DIR}/hf_14a.txt"

echo ""
echo "[*] LF EM 4x02 detection..."
$PM3_CMD -c "lf em 4x02 reader" 2>&1 | tee "${LOOT_DIR}/lf_em.txt"

echo ""
echo "[+] Survey complete. Results: $LOOT_DIR"
echo ""
echo "    Next steps:"
echo "    Mifare Classic : ./rfid-mifare-classic-audit.sh"
echo "    EM4100 clone   : ./rfid-clone-em410x.sh <UID>"
echo "    HID clone      : ./rfid-hid-clone.sh <FC> <CN>"
