#!/usr/bin/env bash
# ================================================================
#  Plunder Bug — capture-full
#  Description : Full PCAP capture session. Auto-detects Plunder Bug
#                interface by MAC OUI (00:13:37), captures all traffic
#                until Ctrl+C, saves to timestamped loot directory.
#  Host OS     : Linux/macOS (attacker machine)
#  Requires    : tcpdump (sudo), Plunder Bug connected via USB-C
#  Usage       : sudo ./capture.sh [duration_seconds]
#                sudo ./capture.sh          # run until Ctrl+C
#                sudo ./capture.sh 300      # capture 300 seconds
# ================================================================

set -euo pipefail

DURATION="${1:-0}"   # 0 = run indefinitely until Ctrl+C
LOOT_DIR="./loot/$(date +%Y%m%d_%H%M%S)_full"
mkdir -p "$LOOT_DIR"

# ---- Auto-detect Plunder Bug interface by OUI -------------------
detect_iface() {
    # Linux
    if command -v ip >/dev/null 2>&1; then
        ip link | awk '/00:13:37/{sub(/:$/,"",$0); prev=prev; print prev}
                       {prev=$2}' 2>/dev/null | head -1 | tr -d ':' || true
        # More reliable: scan ethtool / /sys
        for iface in /sys/class/net/*/address; do
            addr=$(cat "$iface" 2>/dev/null || true)
            if [[ "${addr,,}" == 00:13:37* ]]; then
                basename "$(dirname "$iface")"
                return
            fi
        done
    fi
    # macOS
    if command -v ifconfig >/dev/null 2>&1; then
        ifconfig | awk '/00:13:37/{found=1} found && /^[a-z]/{print $1; exit}
                        /^[a-z]/{iface=$1} /00:13:37/{print iface; exit}' \
            | tr -d ':' | head -1 || true
    fi
}

IFACE="${PLUNDERBUG_IFACE:-$(detect_iface)}"

if [ -z "$IFACE" ]; then
    echo "[!] Plunder Bug interface not found. Connect device and retry."
    echo "    Override with: PLUNDERBUG_IFACE=eth1 ./capture.sh"
    exit 1
fi

echo " =================================================="
echo "  Plunder Bug — Full Capture"
echo " =================================================="
echo "  Interface : $IFACE"
echo "  Loot Dir  : $LOOT_DIR"
echo "  Duration  : ${DURATION}s (0 = until Ctrl+C)"
echo "  Started   : $(date)"
echo " =================================================="
echo ""

OUTFILE="${LOOT_DIR}/capture_full.pcap"

# Trap Ctrl+C for clean shutdown
cleanup() {
    echo ""
    echo "[+] Capture stopped. $(date)"
    echo "[+] PCAP saved to: $OUTFILE"
    SIZE=$(du -sh "$OUTFILE" 2>/dev/null | cut -f1)
    echo "[+] File size: $SIZE"
    echo ""
    echo "    Suggested analysis:"
    echo "    wireshark $OUTFILE"
    echo "    tshark -r $OUTFILE -Y 'http.request' -T fields -e http.host -e http.request.uri"
    echo "    tshark -r $OUTFILE -Y dns -T fields -e dns.qry.name | sort -u"
}
trap cleanup EXIT INT TERM

echo "[*] Starting capture on $IFACE..."

if [ "$DURATION" -gt 0 ] 2>/dev/null; then
    sudo tcpdump -i "$IFACE" -w "$OUTFILE" --buffer-size=4096 \
        -G "$DURATION" -W 1 2>/dev/null
else
    sudo tcpdump -i "$IFACE" -w "$OUTFILE" --buffer-size=4096 2>/dev/null
fi
