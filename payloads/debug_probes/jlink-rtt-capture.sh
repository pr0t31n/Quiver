#!/usr/bin/env bash
# ==================================================================
#  jlink-rtt-capture.sh
#  Description : Capture SEGGER RTT (Real-Time Transfer) debug output
#                from an ARM target using J-Link EDU Mini.
#                RTT provides printf-style debug output over SWD
#                without a UART. Useful for firmware reverse engineering.
#  Requires    : JLinkExe (SEGGER J-Link software)
#  Usage       : ./jlink-rtt-capture.sh [device] [speed_khz] [duration_s]
#  Devices     : STM32F407VG (default), nRF52840, LPC1768, etc.
# ==================================================================

set -euo pipefail
DEVICE="${1:-STM32F407VG}"; SPEED="${2:-4000}"; DURATION="${3:-60}"
LOOT_DIR="./loot/rtt-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
RTT_LOG="${LOOT_DIR}/rtt_output.txt"
RTT_PORT=19021

echo " =================================================="
echo "  J-Link EDU Mini — RTT Capture"
echo "  Device   : $DEVICE"
echo "  Speed    : ${SPEED} kHz"
echo "  Duration : ${DURATION}s"
echo " =================================================="

if ! command -v JLinkExe >/dev/null 2>&1; then
    echo "[!] JLinkExe not found. Download SEGGER J-Link software from:"
    echo "    https://www.segger.com/downloads/jlink/"
    exit 1
fi

# Start JLink GDB server with RTT support
JLinkExe -device "$DEVICE" -speed "$SPEED" -if SWD \
    -autoconnect 1 -RTTTelnetPort "$RTT_PORT" \
    -JTAGConf -1,-1 &
JLINK_PID=$!
sleep 2

echo "[*] Connecting to RTT on port $RTT_PORT..."
echo "[*] Capturing for ${DURATION}s..."

cleanup() {
    kill "$JLINK_PID" 2>/dev/null || true
    echo "[+] RTT log: $RTT_LOG ($(wc -l < "$RTT_LOG" 2>/dev/null || echo 0) lines)"
}
trap cleanup EXIT INT TERM

timeout "$DURATION" nc -q 0 127.0.0.1 "$RTT_PORT" 2>/dev/null | \
    while IFS= read -r line; do
        echo "[$(date +%H:%M:%S.%N | cut -c1-12)] $line" | tee -a "$RTT_LOG"
    done || true
