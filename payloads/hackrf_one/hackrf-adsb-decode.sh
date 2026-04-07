#!/usr/bin/env bash
# ==================================================================
#  hackrf-adsb-decode.sh
#  Description : Aircraft ADS-B position decode using HackRF and
#                dump1090 (or rtl_adsb fallback). Logs position
#                reports to CSV and optionally serves web map.
#  Requires    : hackrf_transfer + dump1090 (or rtl_adsb)
#  Usage       : ./hackrf-adsb-decode.sh [duration_s]
#  Note        : dump1090 prefers RTL-SDR; use --ifile pipe for HackRF
# ==================================================================

set -euo pipefail
DURATION="${1:-300}"; LOOT_DIR="./loot/adsb-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
FREQ=1090000000; SAMPLE_RATE=2000000

echo " =================================================="
echo "  HackRF — ADS-B Aircraft Decode"
echo "  Frequency : 1090 MHz | Duration: ${DURATION}s"
echo " =================================================="

if command -v dump1090 >/dev/null 2>&1; then
    echo "[*] Using dump1090 via pipe..."
    echo "[*] Web interface: http://localhost:8080 (if supported)"
    timeout "$DURATION" hackrf_transfer -r - -f "$FREQ" -s "$SAMPLE_RATE" \
        -l 16 -g 20 2>/dev/null | \
    dump1090 --ifile - --iformat SC16 \
        --write-csv "${LOOT_DIR}/adsb_positions.csv" \
        --write-json "${LOOT_DIR}/" \
        --net --net-http-port 8080 \
        --quiet 2>/dev/null | tee "${LOOT_DIR}/dump1090.log" || true
else
    echo "[*] dump1090 not found — using rtl_adsb (IQ pipe)..."
    timeout "$DURATION" hackrf_transfer -r - -f "$FREQ" -s "$SAMPLE_RATE" \
        -l 16 -g 20 2>/dev/null | \
    rtl_adsb -S 2>/dev/null | \
    while IFS= read -r line; do
        echo "[$(date +%H:%M:%S)] $line" | tee -a "${LOOT_DIR}/adsb_raw.txt"
    done || true
fi

# Summary
AIRCRAFT=$(sort -u "${LOOT_DIR}/adsb_positions.csv" 2>/dev/null | wc -l || \
           grep -c "ICAO" "${LOOT_DIR}/adsb_raw.txt" 2>/dev/null || echo 0)
echo "[+] Aircraft observed: $AIRCRAFT"
echo "[+] Loot: $LOOT_DIR"
