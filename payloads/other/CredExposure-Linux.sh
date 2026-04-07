#!/usr/bin/env bash
# ==================================================================
#  CredExposure-Linux.sh
#  Description : Credential exposure assessment for Linux systems.
#                Finds credentials accessible without cracking:
#                exposed private keys, shell history, cloud creds,
#                .env files, container/k8s configs, and more.
#  Author      : [Operator]
#  Compatible  : Linux (Debian/Red Hat/any); bash 4+
#  Privileges  : Run as target user for their exposure profile.
#                Run as root for complete system-wide picture.
#  Output      : /tmp/CredExposure/CredExposure_<HOST>_<TS>.xml
#
#  Sections:
#    1. SSHPrivateKeys     — unencrypted SSH private keys
#    2. ShadowAccess       — /etc/shadow readable by current user
#    3. ShellHistory       — credentials typed on command line
#    4. CloudCredentials   — AWS/GCP/Azure credential files
#    5. EnvFiles           — .env files with potential secrets
#    6. GitCredentials     — git credential stores and configs
#    7. DockerCredentials  — Docker registry auth configs
#    8. KubernetesCredentials — kubeconfig and service account tokens
#    9. RCFileExposure     — plaintext creds in shell RC files
#   10. NetrcFiles         — .netrc files with embedded credentials
#   11. Findings           — consolidated risk-rated findings
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
OUTFILE="${AUDIT_DIR}/CredExposure_${HOSTNAME_VAL}_${TIMESTAMP}.xml"
FINDINGS_TMP=$(mktemp)
FINDING_COUNT=0

printf '' > "$OUTFILE"

echo ""
echo " ===================================================="
echo "  CredExposure-Linux.sh - Linux Credential Audit"
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
# DOCUMENT OPEN + METADATA
# ==================================================================
printf '<?xml version="1.0" encoding="UTF-8"?>\n' >> "$OUTFILE"
xml_open '' 'CredentialExposure'
xml_open '  ' 'Metadata'
xml_elem '    ' 'Hostname'   "$HOSTNAME_VAL"
xml_elem '    ' 'CurrentUser' "$(id)"
xml_elem '    ' 'IsRoot'     "$([ "$(id -u)" -eq 0 ] && echo true || echo false)"
xml_elem '    ' 'Timestamp'  "$XMLTS"
xml_elem '    ' 'Kernel'     "$(uname -r)"
xml_close '  ' 'Metadata'

# ==================================================================
# 1. SSH PRIVATE KEYS
# ==================================================================
echo '[*] Scanning for SSH private keys...'
xml_open '  ' 'SSHPrivateKeys'

# Search directories: all home dirs + /root (if accessible) + common locations
SEARCH_DIRS=()
if [ "$(id -u)" -eq 0 ]; then
    while IFS=: read -r _ _ _ _ _ home _; do
        [ -d "$home" ] && SEARCH_DIRS+=("$home")
    done < /etc/passwd
else
    SEARCH_DIRS+=("$HOME")
fi

while IFS= read -r keyfile; do
    [ -f "$keyfile" ] || continue
    first_line=$(head -1 "$keyfile" 2>/dev/null || true)
    # Must look like a PEM private key header
    [[ "$first_line" == *"PRIVATE KEY"* ]] || continue
    # Determine if encrypted (passphrase-protected)
    is_encrypted=false
    grep -q 'ENCRYPTED\|Proc-Type.*ENCRYPTED' "$keyfile" 2>/dev/null && is_encrypted=true
    owner=$(stat -c '%U' "$keyfile" 2>/dev/null || stat -f '%Su' "$keyfile" 2>/dev/null || echo 'unknown')
    perms=$(stat -c '%a' "$keyfile" 2>/dev/null || stat -f '%Mp%Lp' "$keyfile" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'Key'
    xml_elem '      ' 'Path'      "$keyfile"
    xml_elem '      ' 'Owner'     "$owner"
    xml_elem '      ' 'Perms'     "$perms"
    xml_elem '      ' 'Encrypted' "$is_encrypted"
    xml_close '    ' 'Key'
    if [ "$is_encrypted" = "false" ]; then
        add_finding 'CRITICAL' 'UnencryptedSSHKey' \
            "Unprotected SSH private key (no passphrase): $keyfile" "$keyfile"
    fi
done < <(find "${SEARCH_DIRS[@]}" -name 'id_*' -not -name '*.pub' \
         -not -name 'id_*.pub' 2>/dev/null | sort -u)

# Also catch keys in non-standard names
while IFS= read -r keyfile; do
    [ -f "$keyfile" ] || continue
    first_line=$(head -1 "$keyfile" 2>/dev/null || true)
    [[ "$first_line" == *"PRIVATE KEY"* ]] || continue
    is_encrypted=false
    grep -q 'ENCRYPTED' "$keyfile" 2>/dev/null && is_encrypted=true
    owner=$(stat -c '%U' "$keyfile" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'Key'
    xml_elem '      ' 'Path'      "$keyfile"
    xml_elem '      ' 'Owner'     "$owner"
    xml_elem '      ' 'Encrypted' "$is_encrypted"
    xml_open '      ' 'Note'
    printf 'Non-standard key name' >> "$OUTFILE"
    xml_close '' 'Note'
    xml_close '    ' 'Key'
    if [ "$is_encrypted" = "false" ]; then
        add_finding 'CRITICAL' 'UnencryptedSSHKey' \
            "Unprotected SSH private key (non-standard name): $keyfile" "$keyfile"
    fi
done < <(find "${SEARCH_DIRS[@]}" -name '*.pem' -o -name '*.key' 2>/dev/null | sort -u)

xml_close '  ' 'SSHPrivateKeys'

# ==================================================================
# 2. /etc/shadow READABILITY
# ==================================================================
echo '[*] Checking /etc/shadow access...'
xml_open '  ' 'ShadowAccess'
if [ -r /etc/shadow ]; then
    shadow_count=$(wc -l < /etc/shadow 2>/dev/null || echo 0)
    # Count entries with non-empty, non-locked password hashes
    hashed=$(grep -v '^\s*$\|^[^:]*:[*!]' /etc/shadow 2>/dev/null | wc -l || echo 0)
    xml_elem '    ' 'Readable'    'true'
    xml_elem '    ' 'TotalLines'  "$shadow_count"
    xml_elem '    ' 'HashedEntries' "$hashed"
    add_finding 'CRITICAL' 'ShadowReadable' \
        "/etc/shadow is readable by current user — password hashes accessible for offline cracking" '/etc/shadow'
else
    xml_elem '    ' 'Readable' 'false'
fi
# Also check /etc/passwd for any non-'x' password fields (direct hash in passwd)
while IFS=: read -r uname pass rest; do
    if [[ "$pass" =~ ^\$[0-9a-z]+\$.+ ]]; then
        xml_elem '    ' 'PasswdHashEntry' "$uname has hash in /etc/passwd"
        add_finding 'CRITICAL' 'PasswdHashExposed' \
            "User '$uname' has password hash in /etc/passwd (world-readable)" "/etc/passwd"
    fi
done < /etc/passwd 2>/dev/null
xml_close '  ' 'ShadowAccess'

# ==================================================================
# 3. SHELL HISTORY CREDENTIAL EXPOSURE
# ==================================================================
echo '[*] Scanning shell history for credential patterns...'
xml_open '  ' 'ShellHistoryExposure'

# Patterns that commonly indicate credentials were typed on command line
CRED_PATTERNS=(
    'sshpass'
    'password\s*='
    '\-p\s*[A-Za-z0-9!@#$%]'
    'Authorization:\|Bearer\|Basic '
    'AWS_SECRET\|AWS_ACCESS\|aws_access_key\|aws_secret'
    'GITHUB_TOKEN\|GH_TOKEN\|GITLAB_TOKEN'
    'mysql.*\-p[A-Za-z0-9]'
    'psql.*password'
    'curl.*-u [^ :]*:'
    'wget.*--password'
    'SECRET\|TOKEN\|API_KEY\|PRIVATE_KEY'
    'ldapsearch.*-w '
    'kinit.*-p'
)

for histfile in "${SEARCH_DIRS[@]}"; do
    for hf in "$histfile/.bash_history" "$histfile/.zsh_history" \
              "$histfile/.sh_history" "$histfile/.history" \
              "$histfile/.ksh_history" "$histfile/.fish_history"; do
        [ -f "$hf" ] && [ -r "$hf" ] || continue
        total_lines=$(wc -l < "$hf" 2>/dev/null || echo 0)
        hit_count=0
        hit_types=()
        for pattern in "${CRED_PATTERNS[@]}"; do
            cnt=$(grep -ic "$pattern" "$hf" 2>/dev/null || echo 0)
            if [ "$cnt" -gt 0 ]; then
                hit_count=$((hit_count + cnt))
                hit_types+=("$pattern($cnt)")
            fi
        done
        owner=$(stat -c '%U' "$hf" 2>/dev/null || echo 'unknown')
        world_read=$([ -r "$hf" ] && stat -c '%a' "$hf" 2>/dev/null | grep -q '[0-9][0-9][4-7]' && echo true || echo false)
        xml_open '    ' 'HistoryFile'
        xml_elem '      ' 'Path'        "$hf"
        xml_elem '      ' 'Owner'       "$owner"
        xml_elem '      ' 'TotalLines'  "$total_lines"
        xml_elem '      ' 'SuspiciousHits' "$hit_count"
        xml_elem '      ' 'WorldReadable' "$world_read"
        xml_elem '      ' 'Patterns'   "$(IFS=, ; echo "${hit_types[*]}")"
        xml_close '    ' 'HistoryFile'
        if [ "$hit_count" -gt 0 ]; then
            add_finding 'HIGH' 'CredentialInHistory' \
                "Shell history '$hf' contains $hit_count line(s) matching credential patterns" "$hf"
        fi
        if [ "$world_read" = "true" ]; then
            add_finding 'MEDIUM' 'WorldReadableHistory' \
                "Shell history '$hf' is world-readable — accessible to any local user" "$hf"
        fi
    done
done
xml_close '  ' 'ShellHistoryExposure'

# ==================================================================
# 4. CLOUD CREDENTIALS
# ==================================================================
echo '[*] Checking cloud credential files...'
xml_open '  ' 'CloudCredentials'

declare -A CLOUD_FILES=(
    ["AWS credentials"]="$HOME/.aws/credentials"
    ["AWS config (may contain keys)"]="$HOME/.aws/config"
    ["GCP app-default creds"]="$HOME/.config/gcloud/application_default_credentials.json"
    ["GCP credentials.db"]="$HOME/.config/gcloud/credentials.db"
    ["GCP legacy credentials"]="$HOME/.config/gcloud/legacy_credentials"
    ["Azure profile"]="$HOME/.azure/azureProfile.json"
    ["Azure token cache"]="$HOME/.azure/msal_token_cache.json"
    ["Azure service principal"]="$HOME/.azure/service_principal_entries.json"
    ["Kubernetes config"]="$HOME/.kube/config"
    ["Docker config"]="$HOME/.docker/config.json"
    ["Terraform credentials"]="$HOME/.terraform.d/credentials.tfrc.json"
    ["Vault token"]="$HOME/.vault-token"
    ["DigitalOcean config"]="$HOME/.config/doctl/config.yaml"
    ["Heroku netrc"]="$HOME/.netrc"
)

# Root-level cloud creds
if [ "$(id -u)" -eq 0 ]; then
    CLOUD_FILES["/etc/boto.cfg"]="/etc/boto.cfg"
    CLOUD_FILES["System AWS config"]="/etc/aws/credentials"
fi

for desc in "${!CLOUD_FILES[@]}"; do
    f="${CLOUD_FILES[$desc]}"
    [ -f "$f" ] || continue
    size=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
    perms=$(stat -c '%a' "$f" 2>/dev/null || echo 'unknown')
    owner=$(stat -c '%U' "$f" 2>/dev/null || echo 'unknown')
    # Sniff for actual key material presence (don't extract values)
    has_key=false
    grep -qiE 'aws_access_key_id|aws_secret|client_secret|refresh_token|access_token|private_key|password|token' "$f" 2>/dev/null && has_key=true
    xml_open '    ' 'CredentialFile'
    xml_elem '      ' 'Description' "$desc"
    xml_elem '      ' 'Path'        "$f"
    xml_elem '      ' 'Owner'       "$owner"
    xml_elem '      ' 'Perms'       "$perms"
    xml_elem '      ' 'SizeBytes'   "$size"
    xml_elem '      ' 'ContainsKeyMaterial' "$has_key"
    xml_close '    ' 'CredentialFile'
    risk='MEDIUM'
    [ "$has_key" = "true" ] && risk='CRITICAL'
    add_finding "$risk" 'CloudCredentialFile' \
        "Cloud credential file found: $f ($desc)" "$f"
done
xml_close '  ' 'CloudCredentials'

# ==================================================================
# 5. .env FILES
# ==================================================================
echo '[*] Scanning for .env files with secrets...'
xml_open '  ' 'EnvFiles'

while IFS= read -r envfile; do
    [ -f "$envfile" ] || continue
    # Check for non-empty, non-comment lines with = signs (actual key=value)
    kv_count=$(grep -cvE '^\s*(#|$)' "$envfile" 2>/dev/null || echo 0)
    # Check for sensitive variable names
    has_secret=false
    grep -qiE '^[A-Z_]*(SECRET|PASSWORD|TOKEN|KEY|CREDENTIAL|PRIVATE|API)[A-Z_]*\s*=' "$envfile" 2>/dev/null && has_secret=true
    owner=$(stat -c '%U' "$envfile" 2>/dev/null || echo 'unknown')
    perms=$(stat -c '%a' "$envfile" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'EnvFile'
    xml_elem '      ' 'Path'          "$envfile"
    xml_elem '      ' 'Owner'         "$owner"
    xml_elem '      ' 'Perms'         "$perms"
    xml_elem '      ' 'KeyValueCount' "$kv_count"
    xml_elem '      ' 'HasSecretVars' "$has_secret"
    xml_close '    ' 'EnvFile'
    if [ "$has_secret" = "true" ]; then
        add_finding 'HIGH' 'EnvFileWithSecrets' \
            ".env file contains secret-named variables: $envfile" "$envfile"
    fi
done < <(find "${SEARCH_DIRS[@]}" -maxdepth 5 -name '.env' -o -name '.env.local' \
         -o -name '.env.production' -o -name '.env.staging' 2>/dev/null | sort -u)

xml_close '  ' 'EnvFiles'

# ==================================================================
# 6. GIT CREDENTIALS
# ==================================================================
echo '[*] Checking git credential stores...'
xml_open '  ' 'GitCredentials'

for dir in "${SEARCH_DIRS[@]}"; do
    # .git-credentials (plaintext store)
    gcf="$dir/.git-credentials"
    if [ -f "$gcf" ]; then
        line_count=$(wc -l < "$gcf" 2>/dev/null || echo 0)
        owner=$(stat -c '%U' "$gcf" 2>/dev/null || echo 'unknown')
        xml_open '    ' 'PlaintextStore'
        xml_elem '      ' 'Path'       "$gcf"
        xml_elem '      ' 'Owner'      "$owner"
        xml_elem '      ' 'EntryCount' "$line_count"
        xml_close '    ' 'PlaintextStore'
        [ "$line_count" -gt 0 ] && add_finding 'CRITICAL' 'GitPlaintextCredentials' \
            "Git plaintext credential store with $line_count entries: $gcf" "$gcf"
    fi
    # .gitconfig — check credential.helper
    gitcfg="$dir/.gitconfig"
    if [ -f "$gitcfg" ]; then
        helper=$(grep -i 'helper\s*=' "$gitcfg" 2>/dev/null | head -5 || true)
        owner=$(stat -c '%U' "$gitcfg" 2>/dev/null || echo 'unknown')
        xml_open '    ' 'GitConfig'
        xml_elem '      ' 'Path'            "$gitcfg"
        xml_elem '      ' 'Owner'           "$owner"
        xml_elem '      ' 'CredentialHelper' "$helper"
        xml_close '    ' 'GitConfig'
        # 'store' helper = plaintext on disk; 'cache' = memory only (safer)
        echo "$helper" | grep -qi 'store' && add_finding 'HIGH' 'GitCredentialHelper' \
            "Git configured with plaintext 'store' credential helper: $gitcfg" "$gitcfg"
    fi
done
xml_close '  ' 'GitCredentials'

# ==================================================================
# 7. DOCKER CREDENTIALS
# ==================================================================
echo '[*] Checking Docker credential config...'
xml_open '  ' 'DockerCredentials'

for dir in "${SEARCH_DIRS[@]}"; do
    dcf="$dir/.docker/config.json"
    [ -f "$dcf" ] || continue
    has_auth=false
    grep -q '"auth"' "$dcf" 2>/dev/null && has_auth=true
    registry_count=$(grep -c '"https://' "$dcf" 2>/dev/null || echo 0)
    owner=$(stat -c '%U' "$dcf" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'DockerConfig'
    xml_elem '      ' 'Path'          "$dcf"
    xml_elem '      ' 'Owner'         "$owner"
    xml_elem '      ' 'HasBase64Auth' "$has_auth"
    xml_elem '      ' 'RegistryCount' "$registry_count"
    xml_close '    ' 'DockerConfig'
    if [ "$has_auth" = "true" ]; then
        add_finding 'HIGH' 'DockerRegistryCredentials' \
            "Docker config.json contains base64-encoded registry credentials (decode to reveal user:pass): $dcf" "$dcf"
    fi
done
xml_close '  ' 'DockerCredentials'

# ==================================================================
# 8. KUBERNETES CREDENTIALS
# ==================================================================
echo '[*] Checking Kubernetes configs...'
xml_open '  ' 'KubernetesCredentials'

for dir in "${SEARCH_DIRS[@]}"; do
    kcf="$dir/.kube/config"
    [ -f "$kcf" ] || continue
    cluster_count=$(grep -c 'cluster:' "$kcf" 2>/dev/null || echo 0)
    has_token=false; grep -q 'token:' "$kcf" 2>/dev/null && has_token=true
    has_cert=false;  grep -q 'client-certificate-data:' "$kcf" 2>/dev/null && has_cert=true
    owner=$(stat -c '%U' "$kcf" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'KubeConfig'
    xml_elem '      ' 'Path'         "$kcf"
    xml_elem '      ' 'Owner'        "$owner"
    xml_elem '      ' 'Clusters'     "$cluster_count"
    xml_elem '      ' 'HasToken'     "$has_token"
    xml_elem '      ' 'HasClientCert' "$has_cert"
    xml_close '    ' 'KubeConfig'
    risk='MEDIUM'
    { [ "$has_token" = "true" ] || [ "$has_cert" = "true" ]; } && risk='CRITICAL'
    add_finding "$risk" 'KubernetesCredentials' \
        "Kubernetes config with cluster credentials: $kcf (clusters: $cluster_count)" "$kcf"
done

# In-cluster service account token
SA_TOKEN='/var/run/secrets/kubernetes.io/serviceaccount/token'
if [ -f "$SA_TOKEN" ] && [ -r "$SA_TOKEN" ]; then
    xml_elem '    ' 'InClusterToken' "$SA_TOKEN"
    add_finding 'HIGH' 'InClusterServiceAccountToken' \
        "Kubernetes in-cluster service account token readable — check RBAC permissions via kubectl auth can-i" "$SA_TOKEN"
fi
xml_close '  ' 'KubernetesCredentials'

# ==================================================================
# 9. RC FILE EXPOSURE
# ==================================================================
echo '[*] Checking shell RC files for embedded credentials...'
xml_open '  ' 'RCFileExposure'

RC_FILES=(
    .bashrc .bash_profile .profile .zshrc .zprofile
    .bash_aliases .aliases .exports
)
for dir in "${SEARCH_DIRS[@]}"; do
    for rcname in "${RC_FILES[@]}"; do
        rcf="$dir/$rcname"
        [ -f "$rcf" ] || continue
        # Look for export statements with credential-like names
        hit_count=$(grep -icE 'export\s+[A-Z_]*(PASSWORD|SECRET|TOKEN|KEY|PASS|CRED|API)[A-Z_]*=' "$rcf" 2>/dev/null || echo 0)
        [ "$hit_count" -eq 0 ] && continue
        owner=$(stat -c '%U' "$rcf" 2>/dev/null || echo 'unknown')
        xml_open '    ' 'RCFile'
        xml_elem '      ' 'Path'      "$rcf"
        xml_elem '      ' 'Owner'     "$owner"
        xml_elem '      ' 'SensitiveExports' "$hit_count"
        xml_close '    ' 'RCFile'
        add_finding 'HIGH' 'CredentialInRCFile' \
            "Shell RC file '$rcf' contains $hit_count export(s) with credential-named variables" "$rcf"
    done
done
xml_close '  ' 'RCFileExposure'

# ==================================================================
# 10. .netrc FILES
# ==================================================================
echo '[*] Checking .netrc files...'
xml_open '  ' 'NetrcFiles'

for dir in "${SEARCH_DIRS[@]}"; do
    nf="$dir/.netrc"
    [ -f "$nf" ] || continue
    entry_count=$(grep -c 'machine ' "$nf" 2>/dev/null || echo 0)
    has_password=$(grep -c 'password ' "$nf" 2>/dev/null || echo 0)
    owner=$(stat -c '%U' "$nf" 2>/dev/null || echo 'unknown')
    perms=$(stat -c '%a' "$nf" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'NetrcFile'
    xml_elem '      ' 'Path'          "$nf"
    xml_elem '      ' 'Owner'         "$owner"
    xml_elem '      ' 'Perms'         "$perms"
    xml_elem '      ' 'MachineCount'  "$entry_count"
    xml_elem '      ' 'PasswordLines' "$has_password"
    xml_close '    ' 'NetrcFile'
    [ "$has_password" -gt 0 ] && add_finding 'CRITICAL' 'NetrcPlaintextPassword' \
        ".netrc file with $has_password plaintext password entries: $nf" "$nf"
done
xml_close '  ' 'NetrcFiles'

# ==================================================================
# 11. CONSOLIDATED FINDINGS
# ==================================================================
printf '  <Findings count="%d">\n' "$FINDING_COUNT" >> "$OUTFILE"
cat "$FINDINGS_TMP" >> "$OUTFILE"
printf '  </Findings>\n' >> "$OUTFILE"
rm -f "$FINDINGS_TMP"

xml_close '' 'CredentialExposure'

echo ''
echo " Findings : ${FINDING_COUNT}"
echo " Output   : ${OUTFILE}"
