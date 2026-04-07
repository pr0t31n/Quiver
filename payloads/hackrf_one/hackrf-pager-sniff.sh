#!/usr/bin/env bash
# ==================================================================
#  hackrf-pager-sniff.sh
#  Description : Passive POCSAG/FLEX pager message decode using HackRF.
#                Pipes IQ samples through multimon-ng for real-time
#                pager message extraction and saves decoded messages.
#  Requires    : hackrf_transfer, multimon-ng, sox (for resampling)
#  Usage       : ./hackrf-pager-sniff.sh [freq_hz] [duration_s]
#  Defaults    : 152.480 MHz POCSAG (US common), run until Ctrl+C
# ==================================================================

set -euo pipefail
FREQ="${1:-152480000}"; DURATION="${2:-0}"
LOOT_DIR="./loot/pager-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
MSGS_FILE="${LOOT_DIR}/pager_messages.txt"
SAMPLE_RATE=2000000

echo " =================================================="
echo "  HackRF — Pager Decode (POCSAG/FLEX)"
echo "  Frequency : $(echo "scale=3; $FREQ/1000000" | bc) MHz"
echo " =================================================="
echo "[*] Press Ctrl+C to stop"
echo ""

cleanup() { echo ""; echo "[+] Messages saved: $MSGS_FILE"; echo "[+] Count: $(wc -l < "$MSGS_FILE" 2>/dev/null || echo 0)"; }
trap cleanup EXIT INT TERM

HACKRF_CMD="hackrf_transfer -r - -f $FREQ -s $SAMPLE_RATE -l 16 -g 20 -a 0 2>/dev/null"
MULTIMON_CMD="multimon-ng -t raw -a POCSAG512 -a POCSAG1200 -a POCSAG2400 -a FLEX -"

if [ "$DURATION" -gt 0 ] 2>/dev/null; then
    timeout "$DURATION" bash -c "$HACKRF_CMD" | \
        sox -t raw -r "$SAMPLE_RATE" -e signed-integer -b 16 -c 2 - \
            -t raw -r 22050 -e signed-integer -b 16 -c 1 - 2>/dev/null | \
        $MULTIMON_CMD 2>/dev/null | \
        while IFS= read -r line; do
            echo "[$(date +%H:%M:%S)] $line" | tee -a "$MSGS_FILE"
        done
else
    $HACKRF_CMD | \
        sox -t raw -r "$SAMPLE_RATE" -e signed-integer -b 16 -c 2 - \
            -t raw -r 22050 -e signed-integer -b 16 -c 1 - 2>/dev/null | \
        $MULTIMON_CMD 2>/dev/null | \
        while IFS= read -r line; do
            echo "[$(date +%H:%M:%S)] $line" | tee -a "$MSGS_FILE"
        done
fi
