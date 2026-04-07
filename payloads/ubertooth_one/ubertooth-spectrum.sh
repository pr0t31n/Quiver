#!/usr/bin/env bash
# ==================================================================
#  ubertooth-spectrum.sh
#  Description : 2.4 GHz spectrum analysis using Ubertooth One.
#                Maps channel activity across WiFi, Bluetooth, and
#                Zigbee bands. Useful for identifying interference,
#                rogue BT devices, and crowded channels.
#  Requires    : ubertooth-specan
#  Usage       : ./ubertooth-spectrum.sh [duration_s]
# ==================================================================

set -euo pipefail
DURATION="${1:-60}"
LOOT_DIR="./loot/bt-spectrum-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
CSV="${LOOT_DIR}/spectrum_2400MHz.csv"

echo " =================================================="
echo "  Ubertooth One — 2.4 GHz Spectrum"
echo "  Duration: ${DURATION}s"
echo " =================================================="
echo "[*] Scanning 2400-2480 MHz..."

timeout "$DURATION" ubertooth-specan -l 2>/dev/null | tee "$CSV" || true

echo "[+] Spectrum data: $CSV"
SAMPLES=$(wc -l < "$CSV" 2>/dev/null || echo 0)
echo "[+] Samples collected: $SAMPLES"
echo ""
echo "    2.4 GHz channel map:"
echo "    WiFi ch1=2412, ch6=2437, ch11=2462"
echo "    BT uses 79 channels (2402-2480 MHz, 1 MHz spacing)"
echo "    Zigbee ch11=2405 through ch26=2480 (5 MHz spacing)"
