#!/usr/bin/env bash
# ==================================================================
#  buspirate-uart-sniff.sh
#  Description : Transparent UART bridge via Bus Pirate 5. Opens
#                the Bus Pirate in UART mode at the specified baud
#                rate and logs all serial data to file + console.
#                Common targets: embedded devices, IoT gateways,
#                serial consoles on routers/switches/PLCs.
#  Requires    : Bus Pirate 5, screen or minicom or socat
#  Usage       : ./buspirate-uart-sniff.sh <device> <baud> [logfile]
#  Example     : ./buspirate-uart-sniff.sh /dev/ttyUSB0 115200
# ==================================================================

set -euo pipefail
DEVICE="${1:?Usage: $0 <device> <baud> [logfile]}"
BAUD="${2:-115200}"
LOOT_DIR="./loot/uart-sniff-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
LOGFILE="${3:-${LOOT_DIR}/uart_capture.txt}"

echo " =================================================="
echo "  Bus Pirate 5 — UART Sniff"
echo "  Device  : $DEVICE"
echo "  Baud    : $BAUD"
echo "  Log     : $LOGFILE"
echo " =================================================="
echo ""
echo "  Bus Pirate UART setup:"
echo "  1. Connect BP TX→target RX, BP RX→target TX, GND→GND"
echo "  2. Bus Pirate should be in UART mode (m → UART → $BAUD 8N1)"
echo "  3. Use auxiliary power: 3.3V or 5V from Bus Pirate if needed"
echo ""

if command -v socat >/dev/null 2>&1; then
    echo "[*] Using socat — logging to $LOGFILE (Ctrl+C to stop)"
    socat "$DEVICE,b${BAUD},raw,echo=0" \
        "STDOUT" | tee "$LOGFILE"
elif command -v screen >/dev/null 2>&1; then
    echo "[*] Using screen — log via screen logging (Ctrl+A, H to toggle)"
    screen -L -Logfile "$LOGFILE" "$DEVICE" "$BAUD"
else
    echo "[*] Using stty + cat pipeline..."
    stty -F "$DEVICE" "$BAUD" raw -echo cs8 -cstopb
    cat "$DEVICE" | tee "$LOGFILE"
fi
