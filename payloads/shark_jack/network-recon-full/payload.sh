#!/bin/bash
# ================================================================
#  Shark Jack — network-recon-full
#  Description : Comprehensive network reconnaissance on plug-in.
#                Performs ARP host discovery, nmap service scan on
#                discovered hosts, SMB enumeration, SNMP community
#                check, DNS resolver interrogation, and saves all
#                findings to structured loot directory.
#                Designed to complete within ~90 seconds while
#                the Shark Jack is plugged into an active port.
#  Device      : Shark Jack (Debian-based)
#  Author      : <operator>
#  Deploy      : Save as /root/payload.sh on Shark Jack
#                (Transfer via SCP in Arming Mode to root@172.16.24.1)
# ================================================================

LED SETUP

LOOT_DIR=/root/loot/recon-$(date +%Y%m%d_%H%M%S)
mkdir -p "$LOOT_DIR"
LOG="${LOOT_DIR}/recon.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

log "Shark Jack — Full Network Recon"
log "Loot: $LOOT_DIR"

# ── Wait for DHCP ─────────────────────────────────────────────────
sleep 5

GATEWAY=$(ip route | awk '/default/{print $3; exit}')
MY_IP=$(ip addr show eth0 | awk '/inet /{print $2; exit}' | cut -d/ -f1)
SUBNET=$(ip route | awk '!/default/ && /eth0/{print $1; exit}')

log "Gateway   : ${GATEWAY:-unknown}"
log "My IP     : ${MY_IP:-unknown}"
log "Subnet    : ${SUBNET:-unknown}"

{
    echo "=== HOSTNAME ===" && hostname
    echo "=== INTERFACES ===" && ip addr
    echo "=== ROUTES ===" && ip route
    echo "=== DNS ===" && cat /etc/resolv.conf
    echo "=== DHCP LEASE ===" && cat /var/lib/dhcp/dhclient.leases 2>/dev/null || true
    echo "=== ARP TABLE ===" && arp -n
} > "${LOOT_DIR}/host_info.txt"

LED ATTACK

# ── ARP host discovery ────────────────────────────────────────────
log "Running ARP scan..."
if command -v arp-scan >/dev/null 2>&1; then
    arp-scan --localnet --retry=2 --timeout=500 2>/dev/null \
        | tee "${LOOT_DIR}/arp_scan.txt"
else
    # Fallback: nmap ARP ping
    nmap -sn -PR "$SUBNET" -oN "${LOOT_DIR}/arp_scan.txt" 2>/dev/null || true
fi

# Extract live IPs (exclude Shark Jack's own IP)
LIVE_IPS=$(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${LOOT_DIR}/arp_scan.txt" \
    | grep -v "^172\.16\.24\." | sort -u)
IP_COUNT=$(echo "$LIVE_IPS" | grep -c . 2>/dev/null || echo 0)
log "Live hosts: $IP_COUNT"
echo "$LIVE_IPS" > "${LOOT_DIR}/live_hosts.txt"

# ── nmap service scan on discovered hosts ─────────────────────────
if [ -n "$LIVE_IPS" ] && command -v nmap >/dev/null 2>&1; then
    log "Running service scan on $IP_COUNT hosts..."
    # Common ports: SSH, Telnet, SMTP, DNS, HTTP, SMB, RDP, WinRM, SNMP
    TARGETS=$(echo "$LIVE_IPS" | tr '\n' ' ')
    nmap -sV --open -p 21,22,23,25,53,80,110,139,143,389,443,445,3389,5985,5986,8080,8443 \
        --script=banner \
        -T4 --max-retries=1 --host-timeout=30s \
        -oN "${LOOT_DIR}/service_scan.txt" \
        -oX "${LOOT_DIR}/service_scan.xml" \
        $TARGETS 2>/dev/null || true
    log "Service scan complete."
fi

# ── SMB enumeration ───────────────────────────────────────────────
log "Checking SMB on discovered hosts..."
SMB_HOSTS=$(grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' "${LOOT_DIR}/service_scan.txt" \
    2>/dev/null | sort -u || true)

for ip in $SMB_HOSTS; do
    if nmap -p445 --open "$ip" 2>/dev/null | grep -q "445/tcp open"; then
        echo "" >> "${LOOT_DIR}/smb_enum.txt"
        echo "=== $ip ===" >> "${LOOT_DIR}/smb_enum.txt"
        # Null session share enumeration
        smbclient -L "//$ip" -N 2>/dev/null \
            >> "${LOOT_DIR}/smb_enum.txt" || true
        # SMB version/signing check via nmap
        nmap -p445 --script smb-security-mode,smb2-security-mode,smb-os-discovery \
            "$ip" 2>/dev/null >> "${LOOT_DIR}/smb_enum.txt" || true
    fi
done
log "SMB enum complete."

# ── SNMP community string check ───────────────────────────────────
log "Checking SNMP (public/private communities)..."
{
    for ip in $LIVE_IPS; do
        for community in public private community manager; do
            result=$(snmpwalk -v2c -c "$community" -t 1 -r 1 \
                "$ip" sysDescr.0 2>/dev/null | head -1 || true)
            if [ -n "$result" ]; then
                echo "$ip community='$community' : $result"
            fi
        done
    done
} > "${LOOT_DIR}/snmp_check.txt" 2>/dev/null || true
SNMP_HITS=$(grep -c "community=" "${LOOT_DIR}/snmp_check.txt" 2>/dev/null || echo 0)
[ "$SNMP_HITS" -gt 0 ] && log "SNMP accessible hosts: $SNMP_HITS"

# ── DNS enumeration ───────────────────────────────────────────────
log "DNS resolver info..."
{
    DNS_SERVER=$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)
    echo "DNS Server: $DNS_SERVER"
    # Reverse lookup on discovered hosts
    for ip in $LIVE_IPS; do
        result=$(host "$ip" "$DNS_SERVER" 2>/dev/null | grep "domain name pointer" | head -1 || true)
        [ -n "$result" ] && echo "$result"
    done
    # Zone transfer attempt on gateway domain
    DOMAIN=$(awk '/^domain|^search/{print $2; exit}' /etc/resolv.conf)
    if [ -n "$DOMAIN" ]; then
        echo ""
        echo "=== Zone Transfer Attempt: $DOMAIN ==="
        dig axfr "$DOMAIN" @"$DNS_SERVER" 2>/dev/null | head -50 || true
    fi
} > "${LOOT_DIR}/dns_enum.txt" 2>/dev/null || true

# ── Summary ───────────────────────────────────────────────────────
log "==============================="
log "Recon complete."
log "Live hosts   : $IP_COUNT"
log "Loot dir     : $LOOT_DIR"
log "==============================="

LED FINISH
