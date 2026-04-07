#!/usr/bin/env bash
# ==================================================================
#  CredExposure-macOS.sh
#  Description : Credential exposure assessment for macOS systems.
#                Finds credentials accessible without cracking:
#                Keychain entries, SSH private keys, shell history
#                patterns, cloud credential files, .env files,
#                Git credential stores, browser login databases,
#                MDM profiles, Kerberos tickets, and more.
#  Author      : [Operator]
#  Compatible  : macOS 11+ (Big Sur and later); bash 3.2+
#  Privileges  : Run as target user for their exposure profile.
#                Run as root for complete system-wide picture.
#  Output      : /tmp/CredExposure/CredExposure_<HOST>_<TS>.xml
#
#  Sections:
#    1. KeychainExposure       — accessible Keychain secrets
#    2. SSHPrivateKeys         — unencrypted SSH private keys
#    3. ShellHistory           — credentials typed on command line
#    4. CloudCredentials       — AWS/GCP/Azure credential files
#    5. EnvFiles               — .env files with potential secrets
#    6. GitCredentials         — git credential stores and configs
#    7. DockerCredentials      — Docker registry auth configs
#    8. KubernetesCredentials  — kubeconfig and service account tokens
#    9. BrowserLoginData       — browser credential database presence
#   10. MDMProfiles            — Mobile Device Management profiles
#   11. KerberosTickets        — active Kerberos TGT presence
#   12. RCFileExposure         — plaintext creds in shell RC files
#   13. NetrcFiles             — .netrc with embedded credentials
#   14. Findings               — consolidated risk-rated findings
# ==================================================================

set -uo pipefail

# ==================================================================
# PATHS AND TIMESTAMP
# ==================================================================
AUDIT_DIR="/tmp/CredExposure"
mkdir -p "$AUDIT_DIR"

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
XMLTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
CURRENT_USER=$(id -un)
OUTFILE="${AUDIT_DIR}/CredExposure_${HOSTNAME_VAL}_${TIMESTAMP}.xml"
FINDINGS_TMP=$(mktemp)
FINDING_COUNT=0

printf '' > "$OUTFILE"

echo ""
echo " ===================================================="
echo "  CredExposure-macOS.sh - macOS Credential Audit"
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
    printf '<CredExposureReport>\n'
    printf '  <Meta>\n'
    printf '    <Script>CredExposure-macOS.sh</Script>\n'
    printf '    <Host>%s</Host>\n' "$(xml_safe "$HOSTNAME_VAL")"
    printf '    <OS>%s</OS>\n' "$(xml_safe "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)")"
    printf '    <User>%s</User>\n' "$(xml_safe "$(id)")"
    printf '    <Timestamp>%s</Timestamp>\n' "$XMLTS"
    printf '  </Meta>\n'
} >> "$OUTFILE"

# ==================================================================
# 1. KEYCHAIN EXPOSURE
# ==================================================================
echo "[1/13] Keychain Exposure..."
xml_open "  " "KeychainExposure"

# List all keychains for current user
KEYCHAINS=$(security list-keychains 2>/dev/null || true)
xml_elem "    " "ListedKeychains" "$KEYCHAINS"

# Check if login keychain is unlocked (can dump secrets without password prompt)
KEYCHAIN_STATUS=$(security show-keychain-info 2>&1 || true)
xml_elem "    " "LoginKeychainStatus" "$KEYCHAIN_STATUS"
if echo "$KEYCHAIN_STATUS" | grep -q "unlocked"; then
    add_finding "HIGH" "KeychainExposure" \
        "Login keychain is currently unlocked — secrets may be accessible via 'security find-generic-password -g'" \
        "$KEYCHAIN_STATUS"
fi

# Count internet passwords (don't dump — just enumerate count)
INET_COUNT=$(security dump-keychain 2>/dev/null | grep -c "inet" || echo 0)
xml_elem "    " "InternetPasswordCount" "$INET_COUNT"
[ "$INET_COUNT" -gt 0 ] && add_finding "MEDIUM" "KeychainExposure" \
    "Keychain contains ${INET_COUNT} internet password entries accessible to current user" \
    "Use: security find-internet-password -ga <account>"

# Check for generic passwords
GENERIC_COUNT=$(security dump-keychain 2>/dev/null | grep -c "genp" || echo 0)
xml_elem "    " "GenericPasswordCount" "$GENERIC_COUNT"

# Check for certificate private keys in keychain
CERT_COUNT=$(security find-identity -v 2>/dev/null | grep -c "valid" || echo 0)
xml_elem "    " "SigningIdentitiesCount" "$CERT_COUNT"
[ "$CERT_COUNT" -gt 0 ] && add_finding "INFO" "KeychainExposure" \
    "${CERT_COUNT} code-signing identity/identities in keychain" ""

# Check for security find-generic-password accessibility (no password prompt)
TEST_RESULT=$(security find-generic-password -a "$CURRENT_USER" 2>&1 | head -3 || true)
xml_elem "    " "GenericPasswordTest" "$TEST_RESULT"

xml_close "  " "KeychainExposure"

# ==================================================================
# 2. SSH PRIVATE KEYS
# ==================================================================
echo "[2/13] SSH Private Keys..."
xml_open "  " "SSHPrivateKeys"

HOME_USER="${HOME:-/Users/$CURRENT_USER}"

while IFS= read -r -d '' keyfile; do
    first_line=$(head -1 "$keyfile" 2>/dev/null || true)
    if [[ "$first_line" == *"PRIVATE KEY"* ]]; then
        encrypted=$(grep -l "ENCRYPTED\|Proc-Type:.*ENCRYPTED\|AES-[0-9]*-CBC" "$keyfile" 2>/dev/null || true)
        xml_open "    " "SSHKey"
        xml_elem "      " "Path" "$keyfile"
        xml_elem "      " "Type" "$first_line"
        xml_elem "      " "Permissions" "$(stat -f '%Sp %Su' "$keyfile" 2>/dev/null || true)"
        if [ -z "$encrypted" ]; then
            xml_elem "      " "Encrypted" "NO"
            add_finding "HIGH" "SSHPrivateKeys" \
                "Unencrypted SSH private key found: ${keyfile}" \
                "First line: $first_line"
        else
            xml_elem "      " "Encrypted" "YES"
            add_finding "INFO" "SSHPrivateKeys" \
                "Passphrase-protected SSH private key: ${keyfile}" ""
        fi
        xml_close "    " "SSHKey"
    fi
done < <(find "$HOME_USER/.ssh" /etc/ssh /root/.ssh 2>/dev/null \
    -maxdepth 3 -type f -name "id_*" -not -name "*.pub" \
    -print0 2>/dev/null || true)

# SSH agent socket (could be used to authenticate without keys)
if [ -n "${SSH_AUTH_SOCK:-}" ]; then
    AGENT_KEYS=$(ssh-add -l 2>/dev/null | head -10 || echo "none")
    xml_elem "    " "SSHAgentKeys" "$AGENT_KEYS"
    if [ "$AGENT_KEYS" != "The agent has no identities." ] && [ "$AGENT_KEYS" != "none" ]; then
        add_finding "MEDIUM" "SSHPrivateKeys" \
            "SSH agent is active with loaded keys — can authenticate to any host in known_hosts" \
            "$AGENT_KEYS"
    fi
fi

# known_hosts reveals reachable targets
KNOWN_HOSTS="$HOME_USER/.ssh/known_hosts"
if [ -f "$KNOWN_HOSTS" ]; then
    KH_COUNT=$(wc -l < "$KNOWN_HOSTS" 2>/dev/null || echo 0)
    xml_elem "    " "KnownHostsCount" "$KH_COUNT"
    [ "$KH_COUNT" -gt 0 ] && add_finding "INFO" "SSHPrivateKeys" \
        "known_hosts contains ${KH_COUNT} entries — lateral movement targets" \
        "$KNOWN_HOSTS"
fi

xml_close "  " "SSHPrivateKeys"

# ==================================================================
# 3. SHELL HISTORY
# ==================================================================
echo "[3/13] Shell History..."
xml_open "  " "ShellHistory"

CRED_PATTERNS='-P "password[=: ]|passwd[=: ]|pass[=: ]|secret[=: ]|token[=: ]|api.?key[=: ]|PASS=|PASSWORD=|SECRET=|AWS_SECRET|mysql.*-p|psql.*-W|sshpass|curl.*-u |wget.*--password"'

for histfile in \
    "$HOME_USER/.bash_history" \
    "$HOME_USER/.zsh_history" \
    "$HOME_USER/.sh_history" \
    "$HOME_USER/.zhistory" \
    "$HOME_USER/.local/share/fish/fish_history"; do
    if [ -f "$histfile" ]; then
        HIT_COUNT=$(grep -iEc 'password[=: ]|passwd[=: ]|secret[=: ]|token[=: ]|api.?key[=: ]|AWS_SECRET|mysql.*-p|sshpass' \
            "$histfile" 2>/dev/null || echo 0)
        xml_open "    " "HistoryFile"
        xml_elem "      " "Path" "$histfile"
        xml_elem "      " "Lines" "$(wc -l < "$histfile" 2>/dev/null || echo 0)"
        xml_elem "      " "CredentialPatternHits" "$HIT_COUNT"
        xml_close "    " "HistoryFile"
        if [ "$HIT_COUNT" -gt 0 ]; then
            add_finding "HIGH" "ShellHistory" \
                "Shell history at ${histfile} contains ${HIT_COUNT} credential-like pattern(s)" \
                "Review manually — value counts only, not echoed"
        fi
    fi
done

xml_close "  " "ShellHistory"

# ==================================================================
# 4. CLOUD CREDENTIALS
# ==================================================================
echo "[4/13] Cloud Credentials..."
xml_open "  " "CloudCredentials"

declare -a CLOUD_FILES=(
    "$HOME_USER/.aws/credentials"
    "$HOME_USER/.aws/config"
    "$HOME_USER/.config/gcloud/credentials.db"
    "$HOME_USER/.config/gcloud/application_default_credentials.json"
    "$HOME_USER/.config/gcloud/legacy_credentials"
    "$HOME_USER/.azure/accessTokens.json"
    "$HOME_USER/.azure/azureProfile.json"
    "$HOME_USER/.config/op/config"
    "$HOME_USER/.1password/config"
    "$HOME_USER/.config/doctl/config.yaml"
    "$HOME_USER/.config/heroku/credentials.json"
    "$HOME_USER/.config/stripe/config.toml"
    "$HOME_USER/.npmrc"
    "$HOME_USER/.pypirc"
    "$HOME_USER/.m2/settings.xml"
    "$HOME_USER/.gradle/gradle.properties"
)

for cfile in "${CLOUD_FILES[@]}"; do
    if [ -f "$cfile" ]; then
        FILESIZE=$(wc -c < "$cfile" 2>/dev/null || echo 0)
        HAS_KEY=false
        case "$cfile" in
            *aws/credentials*)   grep -qiE 'aws_access_key_id|aws_secret' "$cfile" 2>/dev/null && HAS_KEY=true ;;
            *gcloud*)            grep -qiE '"token"|"access_token"|"client_secret"' "$cfile" 2>/dev/null && HAS_KEY=true ;;
            *azure*)             grep -qiE '"accessToken"|"refreshToken"' "$cfile" 2>/dev/null && HAS_KEY=true ;;
            *npmrc*|*pypirc*)    grep -qiE 'authToken|password|_auth' "$cfile" 2>/dev/null && HAS_KEY=true ;;
            *)                   [ "$FILESIZE" -gt 10 ] && HAS_KEY=true ;;
        esac

        xml_open "    " "CloudCredFile"
        xml_elem "      " "Path" "$cfile"
        xml_elem "      " "Bytes" "$FILESIZE"
        xml_elem "      " "ContainsKeyMaterial" "$([ "$HAS_KEY" = "true" ] && echo YES || echo UNKNOWN)"
        xml_close "    " "CloudCredFile"

        if [ "$HAS_KEY" = "true" ]; then
            add_finding "CRITICAL" "CloudCredentials" \
                "Cloud credential file with key material: ${cfile}" \
                "Size: ${FILESIZE} bytes"
        else
            add_finding "MEDIUM" "CloudCredentials" \
                "Cloud credential file present: ${cfile}" ""
        fi
    fi
done

# GCP Application Default Credentials (ADC) — very common in developer environments
if gcloud auth list 2>/dev/null | grep -q "ACTIVE"; then
    ACTIVE_ACCOUNT=$(gcloud config get-value account 2>/dev/null || true)
    add_finding "HIGH" "CloudCredentials" \
        "Active gcloud authentication found: ${ACTIVE_ACCOUNT}" \
        "gcloud auth list"
fi

xml_close "  " "CloudCredentials"

# ==================================================================
# 5. ENV FILES
# ==================================================================
echo "[5/13] .env Files..."
xml_open "  " "EnvFiles"

while IFS= read -r -d '' envfile; do
    HIT_COUNT=$(grep -ciE 'password|passwd|secret|token|api.?key|private.?key|access.?key' \
        "$envfile" 2>/dev/null || echo 0)
    if [ "$HIT_COUNT" -gt 0 ]; then
        xml_open "    " "EnvFile"
        xml_elem "      " "Path" "$envfile"
        xml_elem "      " "CredentialPatternHits" "$HIT_COUNT"
        xml_close "    " "EnvFile"
        add_finding "HIGH" "EnvFiles" \
            ".env file with ${HIT_COUNT} credential-like key(s): ${envfile}" ""
    fi
done < <(find "$HOME_USER" /etc /opt /srv /var/www 2>/dev/null \
    -maxdepth 6 -name ".env" -o -name ".env.local" -o -name ".env.prod" \
    -print0 2>/dev/null | head -z -n 50)

xml_close "  " "EnvFiles"

# ==================================================================
# 6. GIT CREDENTIALS
# ==================================================================
echo "[6/13] Git Credentials..."
xml_open "  " "GitCredentials"

# git credential.helper = store (plaintext)
GIT_HELPER=$(git config --global credential.helper 2>/dev/null || true)
xml_elem "    " "GlobalCredentialHelper" "${GIT_HELPER:-not set}"

if [ "$GIT_HELPER" = "store" ]; then
    STORE_FILE="${HOME_USER}/.git-credentials"
    if [ -f "$STORE_FILE" ]; then
        CRED_COUNT=$(wc -l < "$STORE_FILE")
        add_finding "CRITICAL" "GitCredentials" \
            "git credential.helper=store — ${CRED_COUNT} plaintext credential(s) in ~/.git-credentials" \
            "File: $STORE_FILE"
        xml_elem "    " "GitCredentialStoreCount" "$CRED_COUNT"
    fi
elif [ "$GIT_HELPER" = "osxkeychain" ]; then
    xml_elem "    " "GitCredentialHelper" "osxkeychain (keychain-backed — safer)"
    add_finding "INFO" "GitCredentials" "git credential helper is osxkeychain (keychain-backed)" ""
elif [ -n "$GIT_HELPER" ]; then
    add_finding "MEDIUM" "GitCredentials" \
        "Non-standard git credential helper: ${GIT_HELPER}" ""
fi

# .git-credentials file
if [ -f "$HOME_USER/.git-credentials" ]; then
    GCRED_COUNT=$(wc -l < "$HOME_USER/.git-credentials")
    add_finding "CRITICAL" "GitCredentials" \
        "Plaintext git credential store exists with ${GCRED_COUNT} entries" \
        "$HOME_USER/.git-credentials"
fi

# Search for .git/config with embedded credentials
while IFS= read -r -d '' gitconf; do
    if grep -qE 'url = https?://.+:.+@' "$gitconf" 2>/dev/null; then
        add_finding "CRITICAL" "GitCredentials" \
            "Embedded credentials in git remote URL: ${gitconf}" \
            "$(grep -E 'url = https?://.+:.+@' "$gitconf" 2>/dev/null | head -3)"
    fi
done < <(find "$HOME_USER" /opt /srv 2>/dev/null \
    -maxdepth 8 -name "config" -path "*/.git/*" \
    -print0 2>/dev/null | head -z -n 30)

xml_close "  " "GitCredentials"

# ==================================================================
# 7. DOCKER CREDENTIALS
# ==================================================================
echo "[7/13] Docker Credentials..."
xml_open "  " "DockerCredentials"

DOCKER_CONFIG="$HOME_USER/.docker/config.json"
if [ -f "$DOCKER_CONFIG" ]; then
    xml_elem "    " "DockerConfigPath" "$DOCKER_CONFIG"
    if grep -q '"auth"' "$DOCKER_CONFIG" 2>/dev/null; then
        AUTH_COUNT=$(grep -c '"auth"' "$DOCKER_CONFIG" 2>/dev/null || echo 0)
        add_finding "HIGH" "DockerCredentials" \
            "Docker config.json contains ${AUTH_COUNT} base64-encoded registry credential(s)" \
            "Decode with: cat $DOCKER_CONFIG | jq '.auths' | base64 -D"
        xml_elem "    " "EmbeddedAuthCount" "$AUTH_COUNT"
    fi
    CRED_STORE=$(python3 -c "import json,sys; d=json.load(open('$DOCKER_CONFIG')); print(d.get('credsStore',''))" 2>/dev/null || true)
    xml_elem "    " "CredsStore" "${CRED_STORE:-none}"
fi

xml_close "  " "DockerCredentials"

# ==================================================================
# 8. KUBERNETES CREDENTIALS
# ==================================================================
echo "[8/13] Kubernetes Credentials..."
xml_open "  " "KubernetesCredentials"

KUBECONFIG_FILE="${KUBECONFIG:-$HOME_USER/.kube/config}"
if [ -f "$KUBECONFIG_FILE" ]; then
    CONTEXT=$(kubectl config current-context 2>/dev/null || grep "current-context" "$KUBECONFIG_FILE" | head -1 | awk '{print $2}')
    xml_elem "    " "KubeConfigPath" "$KUBECONFIG_FILE"
    xml_elem "    " "CurrentContext" "${CONTEXT:-unknown}"
    xml_elem "    " "FileSize" "$(wc -c < "$KUBECONFIG_FILE" 2>/dev/null || echo 0)"

    # Check for embedded credentials vs external auth
    if grep -qE 'token:|client-certificate-data:|client-key-data:' "$KUBECONFIG_FILE" 2>/dev/null; then
        add_finding "CRITICAL" "KubernetesCredentials" \
            "kubeconfig contains embedded credentials (token/cert/key data)" \
            "Context: ${CONTEXT:-unknown} | File: $KUBECONFIG_FILE"
    else
        add_finding "MEDIUM" "KubernetesCredentials" \
            "kubeconfig present (may reference external auth)" \
            "Context: ${CONTEXT:-unknown}"
    fi
fi

xml_close "  " "KubernetesCredentials"

# ==================================================================
# 9. BROWSER LOGIN DATA
# ==================================================================
echo "[9/13] Browser Login Databases..."
xml_open "  " "BrowserLoginData"

declare -A BROWSER_DBS=(
    ["Chrome"]="$HOME_USER/Library/Application Support/Google/Chrome/Default/Login Data"
    ["Chromium"]="$HOME_USER/Library/Application Support/Chromium/Default/Login Data"
    ["Brave"]="$HOME_USER/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data"
    ["Edge"]="$HOME_USER/Library/Application Support/Microsoft Edge/Default/Login Data"
    ["Firefox (profiles)"]="$HOME_USER/Library/Application Support/Firefox/Profiles"
    ["Safari Passwords"]="$HOME_USER/Library/Passwords"
)

for browser in "${!BROWSER_DBS[@]}"; do
    dbpath="${BROWSER_DBS[$browser]}"
    if [ -e "$dbpath" ]; then
        SIZE=$(du -sh "$dbpath" 2>/dev/null | cut -f1)
        xml_open "    " "BrowserDB"
        xml_elem "      " "Browser" "$browser"
        xml_elem "      " "Path" "$dbpath"
        xml_elem "      " "Size" "$SIZE"
        xml_close "    " "BrowserDB"
        add_finding "HIGH" "BrowserLoginData" \
            "${browser} credential database present (${SIZE}): ${dbpath}" \
            "Decryption requires macOS Keychain access (current user session)"
    fi
done

xml_close "  " "BrowserLoginData"

# ==================================================================
# 10. MDM PROFILES
# ==================================================================
echo "[10/13] MDM Profiles..."
xml_open "  " "MDMProfiles"

PROFILES_OUTPUT=$(profiles list 2>/dev/null || true)
xml_elem "    " "ProfilesOutput" "$PROFILES_OUTPUT"

if echo "$PROFILES_OUTPUT" | grep -qi "com.apple.mdm\|MDM\|ManagementURL"; then
    add_finding "MEDIUM" "MDMProfiles" \
        "Device is enrolled in MDM — MDM server may push additional profiles or monitor activity" \
        "$(echo "$PROFILES_OUTPUT" | head -20)"
fi

# Check for configuration profiles that might weaken security
if profiles list 2>/dev/null | grep -qi "proxy\|VPN\|certificate\|WiFi"; then
    add_finding "INFO" "MDMProfiles" \
        "MDM-installed network/cert profiles present — review for MITM or monitoring vectors" ""
fi

xml_close "  " "MDMProfiles"

# ==================================================================
# 11. KERBEROS TICKETS
# ==================================================================
echo "[11/13] Kerberos Tickets..."
xml_open "  " "KerberosTickets"

KLIST_OUTPUT=$(klist 2>/dev/null || echo "No Kerberos credentials found")
xml_elem "    " "KlistOutput" "$KLIST_OUTPUT"

if echo "$KLIST_OUTPUT" | grep -q "Credentials cache\|krbtgt"; then
    PRINCIPAL=$(echo "$KLIST_OUTPUT" | grep "Principal:" | head -1 | awk '{print $NF}')
    add_finding "HIGH" "KerberosTickets" \
        "Active Kerberos TGT present for ${PRINCIPAL} — can authenticate to domain services" \
        "$(echo "$KLIST_OUTPUT" | head -10)"
fi

xml_close "  " "KerberosTickets"

# ==================================================================
# 12. RC FILE EXPOSURE
# ==================================================================
echo "[12/13] RC File Credential Exposure..."
xml_open "  " "RCFileExposure"

for rcfile in \
    "$HOME_USER/.bashrc" \
    "$HOME_USER/.bash_profile" \
    "$HOME_USER/.bash_login" \
    "$HOME_USER/.zshrc" \
    "$HOME_USER/.zprofile" \
    "$HOME_USER/.zshenv" \
    "$HOME_USER/.profile" \
    "$HOME_USER/.config/fish/config.fish"; do
    if [ -f "$rcfile" ]; then
        HIT_COUNT=$(grep -ciE \
            'export (AWS_|GCP_|AZURE_|API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)' \
            "$rcfile" 2>/dev/null || echo 0)
        if [ "$HIT_COUNT" -gt 0 ]; then
            xml_open "    " "RCFile"
            xml_elem "      " "Path" "$rcfile"
            xml_elem "      " "CredExportPatternHits" "$HIT_COUNT"
            xml_close "    " "RCFile"
            add_finding "CRITICAL" "RCFileExposure" \
                "Shell RC file exports credential-like variables: ${rcfile} (${HIT_COUNT} match(es))" \
                "Review: grep -iE 'SECRET|PASSWORD|TOKEN|API_KEY' ${rcfile}"
        fi
    fi
done

xml_close "  " "RCFileExposure"

# ==================================================================
# 13. NETRC FILES
# ==================================================================
echo "[13/13] .netrc Files..."
xml_open "  " "NetrcFiles"

for netrcfile in "$HOME_USER/.netrc" /root/.netrc; do
    if [ -f "$netrcfile" ]; then
        ENTRY_COUNT=$(grep -c "machine" "$netrcfile" 2>/dev/null || echo 0)
        xml_open "    " "NetrcFile"
        xml_elem "      " "Path" "$netrcfile"
        xml_elem "      " "MachineEntries" "$ENTRY_COUNT"
        xml_elem "      " "Permissions" "$(stat -f '%Sp' "$netrcfile" 2>/dev/null || true)"
        xml_close "    " "NetrcFile"
        add_finding "CRITICAL" "NetrcFiles" \
            ".netrc file with ${ENTRY_COUNT} plaintext credential entries: ${netrcfile}" ""
    fi
done

xml_close "  " "NetrcFiles"

# ==================================================================
# FINDINGS SUMMARY
# ==================================================================
echo "[+] Writing findings..."
{
    printf '  <Findings total="%s">\n' "$FINDING_COUNT"
    # Emit in risk order: CRITICAL, HIGH, MEDIUM, INFO
    for risk in CRITICAL HIGH MEDIUM INFO; do
        grep -A4 "risk=\"${risk}\"" "$FINDINGS_TMP" 2>/dev/null || true
    done
    printf '  </Findings>\n'
    printf '</CredExposureReport>\n'
} >> "$OUTFILE"

rm -f "$FINDINGS_TMP"

echo ""
echo " ===================================================="
echo "  CredExposure-macOS complete."
echo "  Findings : ${FINDING_COUNT}"
echo "  Output   : ${OUTFILE}"
echo " ===================================================="
