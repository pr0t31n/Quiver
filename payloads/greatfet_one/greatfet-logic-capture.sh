#!/usr/bin/env bash
# ==================================================================
#  greatfet-logic-capture.sh
#  Description : 8-channel logic analyzer via GreatFET One using
#                the gf logic subcommand. Captures digital signals
#                (SPI, I2C, UART, GPIO) at up to 102 Msps.
#  Requires    : greatfet Python package (pip install greatfet)
#  Usage       : ./greatfet-logic-capture.sh [sample_rate_mhz] [duration_s] [outfile]
#  Defaults    : 10 MHz, 5 seconds
#  Note        : Connect J1/J2 pins to target signals. Max 3.3V.
# ==================================================================

set -euo pipefail
RATE_MHZ="${1:-10}"; DURATION="${2:-5}"
LOOT_DIR="./loot/greatfet-logic-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
OUTFILE="${3:-${LOOT_DIR}/logic_capture.sigrok}"

echo " =================================================="
echo "  GreatFET One — Logic Capture"
echo "  Rate: ${RATE_MHZ} MHz | Duration: ${DURATION}s"
echo "  Output: $OUTFILE"
echo " =================================================="
echo ""
echo "  Wiring: J1/J2 GPIO pins to target signals (max 3.3V)"
echo "  Channels: J1[0-7] = CH0-CH7"
echo ""

if ! command -v gf >/dev/null 2>&1 && ! python3 -c "import greatfet" 2>/dev/null; then
    echo "[!] GreatFET tools not found. Install with: pip install greatfet"
    exit 1
fi

SAMPLE_COUNT=$(echo "$RATE_MHZ * $DURATION * 1000000" | bc 2>/dev/null || echo "$((RATE_MHZ * DURATION * 1000000))")

echo "[*] Capturing ${SAMPLE_COUNT} samples at ${RATE_MHZ} MHz..."

# Use gf logic command
gf logic --capture "$SAMPLE_COUNT" --samplerate "${RATE_MHZ}000000" \
    --file "$OUTFILE" 2>&1 || \
python3 - <<EOF
from greatfet import GreatFET
import time

gf = GreatFET()
la = gf.logic_analyzer
la.start(sample_rate=${RATE_MHZ}000000)
print(f"[*] Capturing for ${DURATION}s...")
time.sleep($DURATION)
data = la.stop()
with open("$OUTFILE", 'wb') as f:
    f.write(bytes(data))
print(f"[+] Saved {len(data)} samples")
EOF

echo "[+] Capture: $OUTFILE"
echo ""
echo "    Decode with:"
echo "    sigrok-cli -i $OUTFILE -P spi:clk=0:miso=1:mosi=2"
echo "    pulseview $OUTFILE"
