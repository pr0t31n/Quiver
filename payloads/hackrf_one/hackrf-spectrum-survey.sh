#!/usr/bin/env bash
# ==================================================================
#  hackrf-spectrum-survey.sh
#  Description : HackRF One spectrum survey. Sweeps a frequency range
#                and saves RSSI data to CSV. Optionally plots with
#                gnuplot if available.
#  Requires    : hackrf_sweep (hackrf tools), optionally gnuplot
#  Usage       : ./hackrf-spectrum-survey.sh [start_MHz] [stop_MHz] [bin_width_Hz]
#  Defaults    : 300 MHz to 1100 MHz, 1 MHz bins
# ==================================================================

set -euo pipefail
START="${1:-300}"; STOP="${2:-1100}"; BIN="${3:-1000000}"
LOOT_DIR="./loot/hackrf-spectrum-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
CSV="${LOOT_DIR}/spectrum_${START}-${STOP}MHz.csv"

echo " =================================================="
echo "  HackRF One — Spectrum Survey"
echo "  Range : ${START}-${STOP} MHz | Bin: ${BIN} Hz"
echo " =================================================="

echo "[*] Running hackrf_sweep... (Ctrl+C to stop)"
hackrf_sweep -f "${START}:${STOP}" -w "$BIN" -l 16 -g 0 -N 3 2>/dev/null | tee "$CSV"

echo "[+] CSV saved: $CSV"

# Optional plot
if command -v gnuplot >/dev/null 2>&1; then
    PNG="${LOOT_DIR}/spectrum.png"
    gnuplot <<-EOF
        set terminal png size 1600,600
        set output '$PNG'
        set title 'HackRF Spectrum ${START}-${STOP} MHz'
        set xlabel 'Frequency (Hz)'
        set ylabel 'Power (dBm)'
        set datafile separator ','
        plot '$CSV' using 3:6 with lines title 'RSSI'
EOF
    echo "[+] Plot saved: $PNG"
fi

# Show top 10 peaks
echo ""
echo "[*] Strongest signals:"
awk -F',' 'NR>1 {print $3, $6}' "$CSV" 2>/dev/null | sort -k2 -rn | head -10 || true
