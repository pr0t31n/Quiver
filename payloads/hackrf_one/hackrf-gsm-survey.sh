#!/usr/bin/env bash
# ==================================================================
#  hackrf-gsm-survey.sh
#  Description : Passive GSM channel survey using HackRF and grgsm.
#                Scans GSM 900/1800 bands, identifies base stations
#                (ARFCN, BSIC, MCC, MNC, LAC, CI) without decoding
#                content. For network asset mapping during physical
#                security assessments.
#  Requires    : grgsm_scanner or grgsm_livemon (gr-gsm package)
#  Usage       : ./hackrf-gsm-survey.sh [band] [duration_s]
#  Band        : GSM900 (default) | DCS1800 | PCS1900
# ==================================================================

set -euo pipefail
BAND="${1:-GSM900}"; DURATION="${2:-120}"
LOOT_DIR="./loot/gsm-survey-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
RESULT_FILE="${LOOT_DIR}/gsm_cells.csv"

echo " =================================================="
echo "  HackRF — GSM Cell Survey"
echo "  Band: $BAND | Duration: ${DURATION}s"
echo " =================================================="

if ! command -v grgsm_scanner >/dev/null 2>&1; then
    echo "[!] grgsm_scanner not found. Install gr-gsm:"
    echo "    pip install gr-gsm  OR  apt install gr-gsm"
    echo ""
    echo "    Alternatively, use grgsm_livemon for live display:"
    echo "    grgsm_livemon --args='hackrf=0'"
    exit 1
fi

echo "[*] Scanning $BAND with grgsm_scanner..."
timeout "$DURATION" grgsm_scanner --band "$BAND" --args "hackrf=0" \
    --output-file "$RESULT_FILE" 2>&1 | tee "${LOOT_DIR}/scan_log.txt" || true

if [ -f "$RESULT_FILE" ]; then
    CELL_COUNT=$(wc -l < "$RESULT_FILE" 2>/dev/null || echo 0)
    echo "[+] Base stations found: $CELL_COUNT"
    echo "[+] Results: $RESULT_FILE"
    echo ""
    echo "[*] Summary:"
    cat "$RESULT_FILE" | head -20
else
    echo "[*] No structured output. Check ${LOOT_DIR}/scan_log.txt"
fi
