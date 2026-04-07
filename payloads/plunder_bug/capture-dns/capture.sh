#!/usr/bin/env bash
# ================================================================
#  Plunder Bug — capture-dns
#  Description : DNS-only capture with live plaintext extraction.
#                Saves filtered PCAP of all DNS traffic and
#                simultaneously extracts query names to a text file
#                for immediate review. Reveals internal DNS names,
#                cloud service usage, shadow IT, and browsing patterns.
#  Host OS     : Linux/macOS
#  Requires    : tcpdump (sudo), optionally tshark for live decode
#  Usage       : sudo ./capture.sh [interface] [duration_seconds]
# ================================================================

set -euo pipefail

IFACE="${1:-}"
DURATION="${2:-0}"
LOOT_DIR="./loot/$(date +%Y%m%d_%H%M%S)_dns"
mkdir -p "$LOOT_DIR"

detect_iface() {
    for iface in /sys/class/net/*/address; do
        addr=$(cat "$iface" 2>/dev/null || true)
        [[ "${addr,,}" == 00:13:37* ]] && basename "$(dirname "$iface")" && return
    done
    # macOS fallback
    command -v ifconfig >/dev/null 2>&1 && \
        ifconfig | awk '/00:13:37/{p=1} p && /^\t/ && /inet /{print $2; p=0}' | head -1 || true
}
[ -z "$IFACE" ] && IFACE=$(detect_iface)
[ -z "$IFACE" ] && { echo "[!] Plunder Bug not found. Set IFACE manually: $0 eth2"; exit 1; }

DNS_PCAP="${LOOT_DIR}/dns_queries.pcap"
DNS_TXT="${LOOT_DIR}/dns_queries.txt"
DNS_RESP="${LOOT_DIR}/dns_responses.txt"

echo " =================================================="
echo "  Plunder Bug — DNS Capture"
echo " =================================================="
echo "  Interface : $IFACE"
echo "  DNS PCAP  : $DNS_PCAP"
echo "  Live text : $DNS_TXT"
echo " =================================================="
echo ""

# Capture DNS PCAP in background
if [ "$DURATION" -gt 0 ] 2>/dev/null; then
    sudo tcpdump -i "$IFACE" -w "$DNS_PCAP" 'port 53' \
        -G "$DURATION" -W 1 2>/dev/null &
else
    sudo tcpdump -i "$IFACE" -w "$DNS_PCAP" 'port 53' 2>/dev/null &
fi
TCPDUMP_PID=$!

# Live text extraction (if tshark available for structured decode)
if command -v tshark >/dev/null 2>&1; then
    echo "[*] Live DNS query stream (Ctrl+C to stop):"
    echo ""
    tshark -i "$IFACE" -Y 'dns.flags.response == 0' \
        -T fields -e frame.time_relative -e ip.src -e dns.qry.name -e dns.qry.type \
        -E separator='|' 2>/dev/null | while IFS='|' read -r ts src name qtype; do
            printf "  %-8s %-16s %s (%s)\n" "$ts" "$src" "$name" "$qtype"
            printf '%s|%s|%s|%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$ts" "$src" "$name" >> "$DNS_TXT"
        done &
    TSHARK_PID=$!
else
    echo "[*] tshark not found — capturing PCAP only. Post-process with:"
    echo "    tshark -r $DNS_PCAP -Y 'dns.flags.response == 0' -T fields -e dns.qry.name | sort -u"
fi

cleanup() {
    kill "$TCPDUMP_PID" 2>/dev/null || true
    [ -n "${TSHARK_PID:-}" ] && kill "$TSHARK_PID" 2>/dev/null || true
    echo ""
    echo "[+] Capture complete."
    # Post-process: unique domains
    if command -v tshark >/dev/null 2>&1 && [ -f "$DNS_PCAP" ]; then
        tshark -r "$DNS_PCAP" -Y 'dns.flags.response == 0' \
            -T fields -e dns.qry.name 2>/dev/null | \
            sort -u > "${LOOT_DIR}/unique_domains.txt"
        DOMAIN_COUNT=$(wc -l < "${LOOT_DIR}/unique_domains.txt")
        echo "[+] Unique domains queried: $DOMAIN_COUNT"
        echo "    See: ${LOOT_DIR}/unique_domains.txt"
        # Flag internal / potentially sensitive domains
        grep -iE '\.(corp|internal|local|intranet|lan|ad\.|dc\.|sccm|sharepoint|confluence)' \
            "${LOOT_DIR}/unique_domains.txt" > "${LOOT_DIR}/internal_domains.txt" 2>/dev/null || true
        INT_COUNT=$(wc -l < "${LOOT_DIR}/internal_domains.txt" 2>/dev/null || echo 0)
        [ "$INT_COUNT" -gt 0 ] && echo "[+] Internal domain indicators: $INT_COUNT (see internal_domains.txt)"
    fi
    echo "[+] Full PCAP: $DNS_PCAP"
}
trap cleanup EXIT INT TERM

[ "$DURATION" -gt 0 ] 2>/dev/null && sleep "$DURATION" && exit 0
wait "$TCPDUMP_PID"
