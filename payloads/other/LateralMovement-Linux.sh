#!/usr/bin/env bash
# ==================================================================
#  LateralMovement-Linux.sh
#  Description : Network lateral movement surface assessment for Linux.
#                Identifies attack paths and weak controls that enable
#                an attacker to pivot from the compromised host to
#                other systems on the network.
#  Author      : [Operator]
#  Compatible  : Debian/Ubuntu, RHEL/CentOS/Fedora; bash 4+
#  Privileges  : Run as root for full results. User-level run gives
#                partial results (may miss system-wide configs).
#  Output      : /tmp/LateralMovement/LateralMovement_<HOST>_<TS>.xml
#
#  Sections:
#    1. SSHTrustRelationships  — authorized_keys and known_hosts analysis
#    2. NFSExports             — no_root_squash and world-accessible shares
#    3. SambaSigning           — SMB signing requirements
#    4. KerberosTickets        — TGT/TGS presence and keytab files
#    5. LLMNRNBTNSStatus       — LLMNR/NBT-NS poisoning surface
#    6. RshRloginStatus        — legacy trusted-host protocols
#    7. DatabaseRemoteAccess   — MySQL/PostgreSQL/Redis/Mongo open binds
#    8. DockerAPIExposure      — unauthenticated Docker socket/API
#    9. RootAuthorizedKeys     — root SSH authorized keys
#   10. HostsEquiv             — /etc/hosts.equiv trust entries
#   11. WritableNetworkServices — writable service configs
#   12. CachedCredentials      — SSSD/winbind cached domain creds
#   13. Findings               — consolidated risk-rated findings
# ==================================================================

set -uo pipefail

AUDIT_DIR="/tmp/LateralMovement"
mkdir -p "$AUDIT_DIR"

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
XMLTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
CURRENT_USER=$(id -un)
OUTFILE="${AUDIT_DIR}/LateralMovement_${HOSTNAME_VAL}_${TIMESTAMP}.xml"
FINDINGS_TMP=$(mktemp)
FINDING_COUNT=0

printf '' > "$OUTFILE"

echo ""
echo " ===================================================="
echo "  LateralMovement-Linux.sh - Lateral Movement Audit"
echo " ===================================================="
echo "  Host      : ${HOSTNAME_VAL}"
echo "  User      : $(id)"
echo "  Timestamp : ${XMLTS}"
echo "  Output    : ${OUTFILE}"
echo " ===================================================="
echo ""

# ==================================================================
# XML HELPERS
# ==================================================================
xml_safe() {
    local s="$*"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    printf '%s' "$s"
}
xml_elem()  { local p="$1" t="$2"; printf '%s<%s>%s</%s>\n' "$p" "$t" "$(xml_safe "$3")" "$t" >> "$OUTFILE"; }
xml_open()  { printf '%s<%s>\n' "$1" "$2" >> "$OUTFILE"; }
xml_close() { printf '%s</%s>\n' "$1" "$2" >> "$OUTFILE"; }

add_finding() {
    local risk="$1" cat="$2" detail="$3" evidence="${4:-}"
    FINDING_COUNT=$((FINDING_COUNT + 1))
    {
        printf '    <Finding risk="%s">\n' "$risk"
        printf '      <Category>%s</Category>\n' "$(xml_safe "$cat")"
        printf '      <Detail>%s</Detail>\n' "$(xml_safe "$detail")"
        [ -n "$evidence" ] && printf '      <Evidence>%s</Evidence>\n' "$(xml_safe "$evidence")"
        printf '    </Finding>\n'
    } >> "$FINDINGS_TMP"
}

# ==================================================================
# XML DOCUMENT HEADER
# ==================================================================
{
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<LateralMovementReport>\n'
    printf '  <Meta>\n'
    printf '    <Script>LateralMovement-Linux.sh</Script>\n'
    printf '    <Host>%s</Host>\n' "$(xml_safe "$HOSTNAME_VAL")"
    printf '    <OS>%s</OS>\n' "$(xml_safe "$(uname -srm)")"
    printf '    <User>%s</User>\n' "$(xml_safe "$(id)")"
    printf '    <Timestamp>%s</Timestamp>\n' "$XMLTS"
    printf '  </Meta>\n'
} >> "$OUTFILE"

# ==================================================================
# 1. SSH TRUST RELATIONSHIPS
# ==================================================================
echo "[1/12] SSH Trust Relationships..."
xml_open "  " "SSHTrustRelationships"

# Enumerate all home directories + root
ALL_HOMES=$(awk -F: '$7 !~ /nologin|false/ && $6 ~ /^\// {print $6}' /etc/passwd 2>/dev/null | sort -u)
for home_dir in $ALL_HOMES /root; do
    [ -d "$home_dir" ] || continue
    AK_FILE="$home_dir/.ssh/authorized_keys"
    KH_FILE="$home_dir/.ssh/known_hosts"
    OWNER=$(basename "$home_dir")

    if [ -f "$AK_FILE" ] && [ -r "$AK_FILE" ]; then
        KEY_COUNT=$(wc -l < "$AK_FILE" 2>/dev/null || echo 0)
        # Check for keys from multiple sources (indicates trust from multiple systems)
        xml_open "    " "AuthorizedKeys"
        xml_elem "      " "User" "$OWNER"
        xml_elem "      " "File" "$AK_FILE"
        xml_elem "      " "KeyCount" "$KEY_COUNT"
        xml_elem "      " "Permissions" "$(stat -c '%a %U' "$AK_FILE" 2>/dev/null || true)"
        xml_close "    " "AuthorizedKeys"
        if [ "$KEY_COUNT" -gt 0 ]; then
            add_finding "HIGH" "SSHTrustRelationships" \
                "SSH authorized_keys for ${OWNER}: ${KEY_COUNT} inbound trust(s) — hosts with matching private keys can authenticate" \
                "$AK_FILE"
        fi
    fi

    if [ -f "$KH_FILE" ] && [ -r "$KH_FILE" ]; then
        KH_COUNT=$(wc -l < "$KH_FILE" 2>/dev/null || echo 0)
        xml_open "    " "KnownHosts"
        xml_elem "      " "User" "$OWNER"
        xml_elem "      " "File" "$KH_FILE"
        xml_elem "      " "HostCount" "$KH_COUNT"
        xml_close "    " "KnownHosts"
        if [ "$KH_COUNT" -gt 0 ]; then
            add_finding "INFO" "SSHTrustRelationships" \
                "SSH known_hosts for ${OWNER}: ${KH_COUNT} reachable hosts (lateral movement targets)" \
                "$KH_FILE"
        fi
    fi

    # StrictHostKeyChecking=no in user SSH config
    if grep -qiE 'StrictHostKeyChecking\s+no' "$home_dir/.ssh/config" 2>/dev/null; then
        add_finding "MEDIUM" "SSHTrustRelationships" \
            "SSH config for ${OWNER} has StrictHostKeyChecking=no — MITM risk" \
            "$home_dir/.ssh/config"
    fi
done

# SSH server config — check for risky settings
if [ -f /etc/ssh/sshd_config ]; then
    xml_open "    " "SSHDConfig"
    for setting in "PermitRootLogin\|PasswordAuthentication\|PubkeyAuthentication\|AuthorizedKeysFile\|PermitEmptyPasswords\|AllowAgentForwarding\|AllowTcpForwarding"; do
        VAL=$(grep -iE "^$setting" /etc/ssh/sshd_config 2>/dev/null | head -1 || true)
        [ -n "$VAL" ] && xml_elem "      " "SSHDSetting" "$VAL"
    done
    xml_close "    " "SSHDConfig"
    # Dangerous settings
    grep -qi "^PermitRootLogin yes" /etc/ssh/sshd_config && \
        add_finding "HIGH" "SSHTrustRelationships" "SSHD: PermitRootLogin=yes — root can authenticate directly via SSH" ""
    grep -qi "^PasswordAuthentication yes" /etc/ssh/sshd_config && \
        add_finding "MEDIUM" "SSHTrustRelationships" "SSHD: Password authentication enabled — brute force / spray possible" ""
    grep -qi "^PermitEmptyPasswords yes" /etc/ssh/sshd_config && \
        add_finding "CRITICAL" "SSHTrustRelationships" "SSHD: Empty passwords permitted — any user with empty passwd can SSH in" ""
fi

xml_close "  " "SSHTrustRelationships"

# ==================================================================
# 2. NFS EXPORTS
# ==================================================================
echo "[2/12] NFS Exports..."
xml_open "  " "NFSExports"

if [ -f /etc/exports ]; then
    EXPORTS=$(cat /etc/exports 2>/dev/null)
    xml_elem "    " "ExportsFile" "$EXPORTS"

    while IFS= read -r line; do
        [[ "$line" =~ ^# ]] && continue
        if echo "$line" | grep -q "no_root_squash"; then
            add_finding "CRITICAL" "NFSExports" \
                "NFS export with no_root_squash — remote root can write files as local root: ${line}" \
                "$line"
        fi
        if echo "$line" | grep -qE "\*\s|\*\)"; then
            add_finding "HIGH" "NFSExports" \
                "NFS export accessible by all hosts (*): ${line}" "$line"
        fi
    done <<< "$EXPORTS"
fi

# Active NFS mounts
NFS_MOUNTS=$(mount | grep -i nfs 2>/dev/null || true)
xml_elem "    " "NFSMounts" "${NFS_MOUNTS:-none}"
[ -n "$NFS_MOUNTS" ] && add_finding "INFO" "NFSExports" \
    "Active NFS mounts — pivoting possible via file placement" "$NFS_MOUNTS"

xml_close "  " "NFSExports"

# ==================================================================
# 3. SAMBA SIGNING
# ==================================================================
echo "[3/12] Samba/SMB Signing..."
xml_open "  " "SambaSigning"

if command -v testparm >/dev/null 2>&1 && [ -f /etc/samba/smb.conf ]; then
    SERVER_SIGNING=$(testparm -s 2>/dev/null | grep -i "server signing" | head -1 || true)
    CLIENT_SIGNING=$(testparm -s 2>/dev/null | grep -i "client signing" | head -1 || true)
    xml_elem "    " "ServerSigning" "${SERVER_SIGNING:-not found}"
    xml_elem "    " "ClientSigning" "${CLIENT_SIGNING:-not found}"

    if echo "$SERVER_SIGNING" | grep -qiE "disabled|no\b|auto\b"; then
        add_finding "HIGH" "SambaSigning" \
            "Samba server signing is not required — SMB relay attacks possible" \
            "$SERVER_SIGNING"
    fi
    if echo "$CLIENT_SIGNING" | grep -qiE "disabled|no\b"; then
        add_finding "HIGH" "SambaSigning" \
            "Samba client signing is disabled — MITM of outbound SMB connections possible" \
            "$CLIENT_SIGNING"
    fi
fi

# Check if SMB ports are listening
SMB_LISTEN=$(ss -tlnp 2>/dev/null | grep -E ':445|:139' || netstat -tlnp 2>/dev/null | grep -E ':445|:139' || true)
xml_elem "    " "SMBListening" "${SMB_LISTEN:-not listening}"

xml_close "  " "SambaSigning"

# ==================================================================
# 4. KERBEROS TICKETS AND KEYTAB
# ==================================================================
echo "[4/12] Kerberos..."
xml_open "  " "KerberosTickets"

KLIST_OUT=$(klist 2>/dev/null || echo "No Kerberos credentials found")
xml_elem "    " "KlistOutput" "$KLIST_OUT"
if echo "$KLIST_OUT" | grep -q "krbtgt\|Credentials cache"; then
    add_finding "HIGH" "KerberosTickets" \
        "Active Kerberos TGT — can authenticate to any Kerberized service" \
        "$KLIST_OUT"
fi

# Keytab files — can be used for passwordless Kerberos auth
while IFS= read -r -d '' ktab; do
    xml_open "    " "Keytab"
    xml_elem "      " "Path" "$ktab"
    xml_elem "      " "Permissions" "$(stat -c '%a %U:%G' "$ktab" 2>/dev/null || true)"
    xml_close "    " "Keytab"
    add_finding "CRITICAL" "KerberosTickets" \
        "Keytab file accessible — can authenticate as associated principal without password: ${ktab}" ""
done < <(find / -maxdepth 6 -name "*.keytab" -o -name "krb5.keytab" \
    -print0 2>/dev/null | head -z -n 20)

xml_close "  " "KerberosTickets"

# ==================================================================
# 5. LLMNR / NBT-NS STATUS
# ==================================================================
echo "[5/12] LLMNR / NBT-NS / mDNS..."
xml_open "  " "LLMNRNBTNSStatus"

# LLMNR via systemd-resolved
if [ -f /etc/systemd/resolved.conf ]; then
    LLMNR_VAL=$(grep -i "LLMNR" /etc/systemd/resolved.conf 2>/dev/null | head -1 || echo "LLMNR=yes (default)")
    xml_elem "    " "SystemdResolvedLLMNR" "$LLMNR_VAL"
    if echo "$LLMNR_VAL" | grep -qiE "yes|resolve|default"; then
        add_finding "HIGH" "LLMNRNBTNSStatus" \
            "LLMNR is enabled in systemd-resolved — susceptible to Responder LLMNR poisoning" \
            "$LLMNR_VAL"
    fi
fi

# nmbd (NetBIOS Name Service)
if pgrep -x nmbd >/dev/null 2>&1 || systemctl is-active nmbd >/dev/null 2>&1; then
    add_finding "HIGH" "LLMNRNBTNSStatus" \
        "nmbd (NetBIOS Name Service) is running — NBT-NS poisoning (Responder) possible" ""
    xml_elem "    " "NmbdRunning" "YES"
fi

# avahi-daemon (mDNS)
if pgrep -x avahi-daemon >/dev/null 2>&1; then
    xml_elem "    " "AvahiRunning" "YES"
    add_finding "MEDIUM" "LLMNRNBTNSStatus" \
        "avahi-daemon (mDNS/Bonjour) is running — mDNS poisoning possible on local segment" ""
fi

xml_close "  " "LLMNRNBTNSStatus"

# ==================================================================
# 6. RSH / RLOGIN
# ==================================================================
echo "[6/12] Rsh/Rlogin Legacy Protocols..."
xml_open "  " "RshRloginStatus"

for svc in rsh rlogin rexec; do
    if systemctl is-active "$svc" >/dev/null 2>&1 || \
       ss -tlnp 2>/dev/null | grep -q ":514\|:513\|:512"; then
        add_finding "CRITICAL" "RshRloginStatus" \
            "Legacy trusted-host service active: ${svc} — no encryption, trivially exploitable" ""
        xml_elem "    " "LegacyServiceActive" "$svc"
    fi
done

if [ -f /etc/hosts.equiv ]; then
    EQ_CONTENT=$(cat /etc/hosts.equiv 2>/dev/null)
    xml_elem "    " "HostsEquiv" "$EQ_CONTENT"
    if [ -n "$EQ_CONTENT" ]; then
        add_finding "CRITICAL" "RshRloginStatus" \
            "/etc/hosts.equiv exists with trusted hosts — passwordless rsh/rlogin from listed hosts" \
            "$EQ_CONTENT"
    fi
fi

xml_close "  " "RshRloginStatus"

# ==================================================================
# 7. DATABASE REMOTE ACCESS
# ==================================================================
echo "[7/12] Database Remote Access..."
xml_open "  " "DatabaseRemoteAccess"

declare -A DB_PORTS=(
    ["MySQL/MariaDB"]=3306
    ["PostgreSQL"]=5432
    ["Redis"]=6379
    ["MongoDB"]=27017
    ["Cassandra"]=9042
    ["Elasticsearch"]=9200
    ["CouchDB"]=5984
    ["InfluxDB"]=8086
)

for db in "${!DB_PORTS[@]}"; do
    port="${DB_PORTS[$db]}"
    # Check if listening on 0.0.0.0 (all interfaces)
    LISTEN=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -v "127.0.0.1\|::1" || true)
    if [ -n "$LISTEN" ]; then
        xml_open "    " "RemoteDatabase"
        xml_elem "      " "Service" "$db"
        xml_elem "      " "Port" "$port"
        xml_elem "      " "Listen" "$LISTEN"
        xml_close "    " "RemoteDatabase"

        RISK="HIGH"
        # Redis and MongoDB historically default to no auth
        { [ "$db" = "Redis" ] || [ "$db" = "MongoDB" ] || [ "$db" = "Elasticsearch" ]; } && RISK="CRITICAL"
        add_finding "$RISK" "DatabaseRemoteAccess" \
            "${db} is listening on all interfaces (port ${port}) — check for authentication" \
            "$LISTEN"
    fi
done

# Redis-specific: check for no auth
if command -v redis-cli >/dev/null 2>&1; then
    REDIS_PING=$(redis-cli -h 127.0.0.1 ping 2>/dev/null || true)
    xml_elem "    " "RedisPingTest" "${REDIS_PING:-N/A}"
    if [ "$REDIS_PING" = "PONG" ]; then
        add_finding "CRITICAL" "DatabaseRemoteAccess" \
            "Redis responds to unauthenticated PING — no password set, RCE via CONFIG SET dir/dbfilename" \
            "redis-cli ping → PONG"
    fi
fi

xml_close "  " "DatabaseRemoteAccess"

# ==================================================================
# 8. DOCKER API EXPOSURE
# ==================================================================
echo "[8/12] Docker API Exposure..."
xml_open "  " "DockerAPIExposure"

# Unix socket
if [ -S /var/run/docker.sock ] && [ -r /var/run/docker.sock ]; then
    SOCK_PERMS=$(stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null || true)
    xml_elem "    " "DockerSockPermissions" "$SOCK_PERMS"
    add_finding "CRITICAL" "DockerAPIExposure" \
        "Docker Unix socket is readable by current user — root equivalent via: docker run -v /:/mnt --rm alpine chroot /mnt sh" \
        "/var/run/docker.sock permissions: $SOCK_PERMS"
fi

# TCP API
DOCKER_TCP=$(ss -tlnp 2>/dev/null | grep ":2375\|:2376" | grep -v "127.0.0.1" || true)
if [ -n "$DOCKER_TCP" ]; then
    xml_elem "    " "DockerTCPListen" "$DOCKER_TCP"
    add_finding "CRITICAL" "DockerAPIExposure" \
        "Docker TCP API exposed on network — unauthenticated remote code execution as root" \
        "$DOCKER_TCP"
fi

xml_close "  " "DockerAPIExposure"

# ==================================================================
# 9. ROOT AUTHORIZED KEYS
# ==================================================================
echo "[9/12] Root SSH Authorized Keys..."
xml_open "  " "RootAuthorizedKeys"

ROOT_AK="/root/.ssh/authorized_keys"
if [ -f "$ROOT_AK" ] && [ -r "$ROOT_AK" ]; then
    ROOT_KEY_COUNT=$(wc -l < "$ROOT_AK" 2>/dev/null || echo 0)
    xml_elem "    " "RootKeyCount" "$ROOT_KEY_COUNT"
    add_finding "HIGH" "RootAuthorizedKeys" \
        "Root SSH authorized_keys has ${ROOT_KEY_COUNT} entry/entries — any matching key = direct root SSH" \
        "$ROOT_AK"
fi

# Check if root login is even permitted (already covered in SSH section, but cross-reference)
ROOT_LOGIN=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | head -1 || echo "PermitRootLogin not explicitly set")
xml_elem "    " "PermitRootLogin" "$ROOT_LOGIN"

xml_close "  " "RootAuthorizedKeys"

# ==================================================================
# 10. WRITABLE NETWORK SERVICE CONFIGS
# ==================================================================
echo "[10/12] Writable Network Service Configs..."
xml_open "  " "WritableNetworkServices"

declare -a SVCCONFIGS=(
    "/etc/ssh/sshd_config"
    "/etc/samba/smb.conf"
    "/etc/nginx/nginx.conf"
    "/etc/apache2/apache2.conf"
    "/etc/httpd/conf/httpd.conf"
    "/etc/haproxy/haproxy.cfg"
    "/etc/vsftpd.conf"
    "/etc/proftpd/proftpd.conf"
    "/etc/postfix/main.cf"
    "/etc/cron.d"
    "/etc/crontab"
)

for cfg in "${SVCCONFIGS[@]}"; do
    if [ -e "$cfg" ] && [ -w "$cfg" ]; then
        xml_open "    " "WritableServiceConfig"
        xml_elem "      " "Path" "$cfg"
        xml_close "    " "WritableServiceConfig"
        add_finding "CRITICAL" "WritableNetworkServices" \
            "Privileged service configuration is writable: ${cfg}" \
            "Modify to add backdoor credentials, insert commands, or redirect logging"
    fi
done

xml_close "  " "WritableNetworkServices"

# ==================================================================
# 11. SSSD / WINBIND CACHED DOMAIN CREDENTIALS
# ==================================================================
echo "[11/12] Cached Domain Credentials..."
xml_open "  " "CachedCredentials"

if [ -d /var/lib/sss/db ] && [ -r /var/lib/sss/db ]; then
    SSSD_FILES=$(ls -la /var/lib/sss/db/ 2>/dev/null)
    xml_elem "    " "SSSDBDirectory" "$SSSD_FILES"
    add_finding "HIGH" "CachedCredentials" \
        "SSSD cache database accessible — may contain cached Kerberos tickets or hashed domain passwords" \
        "/var/lib/sss/db/"
fi

if [ -d /var/lib/samba/private ] && [ -r /var/lib/samba/private ]; then
    WINBIND=$(ls /var/lib/samba/private/ 2>/dev/null | grep -E "secrets|tdb" || true)
    [ -n "$WINBIND" ] && add_finding "HIGH" "CachedCredentials" \
        "Winbind secrets database accessible — may contain domain machine account credentials" \
        "/var/lib/samba/private/: $WINBIND"
fi

xml_close "  " "CachedCredentials"

# ==================================================================
# 12. CUPS / PRINTING SERVICE (CVE-2024-47176)
# ==================================================================
echo "[12/12] CUPS / Printing Service..."
xml_open "  " "CUPSService"

CUPS_LISTEN=$(ss -ulnp 2>/dev/null | grep ":631" | grep -v "127.0.0.1\|::1" || true)
CUPS_ACTIVE=$(systemctl is-active cups 2>/dev/null || pgrep -x cupsd >/dev/null 2>&1 && echo "active" || echo "inactive")
xml_elem "    " "CUPSStatus" "$CUPS_ACTIVE"
xml_elem "    " "CUPSUDPListen" "${CUPS_LISTEN:-loopback only}"

if [ -n "$CUPS_LISTEN" ]; then
    CUPS_VERSION=$(cups-config --version 2>/dev/null || true)
    add_finding "CRITICAL" "CUPSService" \
        "CUPS is listening on all interfaces UDP/631 — CVE-2024-47176: unauthenticated RCE via malicious IPP printer URL (CUPS < 2.4.11)" \
        "Version: ${CUPS_VERSION:-unknown} | Listener: $CUPS_LISTEN"
elif [ "$CUPS_ACTIVE" = "active" ]; then
    add_finding "INFO" "CUPSService" "CUPS active but listening on loopback only" ""
fi

xml_close "  " "CUPSService"

# ==================================================================
# FINDINGS SUMMARY
# ==================================================================
echo "[+] Writing findings..."
{
    printf '  <Findings total="%s">\n' "$FINDING_COUNT"
    for risk in CRITICAL HIGH MEDIUM INFO; do
        grep -A4 "risk=\"${risk}\"" "$FINDINGS_TMP" 2>/dev/null || true
    done
    printf '  </Findings>\n'
    printf '</LateralMovementReport>\n'
} >> "$OUTFILE"

rm -f "$FINDINGS_TMP"

echo ""
echo " ===================================================="
echo "  LateralMovement-Linux complete."
echo "  Findings : ${FINDING_COUNT}"
echo "  Output   : ${OUTFILE}"
echo " ===================================================="
