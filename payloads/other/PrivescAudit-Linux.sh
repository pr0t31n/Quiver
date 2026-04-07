#!/usr/bin/env bash
# ==================================================================
#  PrivescAudit-Linux.sh
#  Description : Local privilege escalation vector assessment for Linux.
#                Enumerates and risk-rates escalation paths available
#                to the current user.
#  Author      : [Operator]
#  Compatible  : Debian/Ubuntu, RHEL/CentOS/Fedora; bash 4+
#  Privileges  : Run as the TARGET USER (not pre-elevated) to
#                accurately reflect what that account can escalate with.
#  Output      : /tmp/PrivescAudit/PrivescAudit_<HOST>_<TS>.xml
#
#  Sections:
#    1. SudoRules              — NOPASSWD or dangerous sudo commands
#    2. SUIDFiles              — SUID binaries (GTFOBins cross-reference)
#    3. SGIDFiles              — SGID binaries of note
#    4. Capabilities           — Linux capabilities on executables
#    5. WritableCronScripts    — cron jobs pointing to writable files
#    6. WritablePATHDirs       — writable directories in PATH
#    7. NFSExports             — no_root_squash exports
#    8. DangerousGroupMembership — docker, lxd, disk, sudo, shadow
#    9. SensitiveFilePerms     — writable /etc/passwd, /etc/shadow, etc.
#   10. Findings               — consolidated risk-rated findings
# ==================================================================

set -uo pipefail

# ==================================================================
# PATHS AND TIMESTAMP
# ==================================================================
AUDIT_DIR="/tmp/PrivescAudit"
mkdir -p "$AUDIT_DIR"

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
XMLTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
CURRENT_USER=$(id -un)
CURRENT_GROUPS=$(id -Gn)
OUTFILE="${AUDIT_DIR}/PrivescAudit_${HOSTNAME_VAL}_${TIMESTAMP}.xml"
FINDINGS_TMP=$(mktemp)
FINDING_COUNT=0

printf '' > "$OUTFILE"

echo ""
echo " ===================================================="
echo "  PrivescAudit-Linux.sh - Linux Privilege Escalation Audit"
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
xml_open '' 'PrivescAudit'
xml_open '  ' 'Metadata'
xml_elem '    ' 'Hostname'      "$HOSTNAME_VAL"
xml_elem '    ' 'CurrentUser'   "$CURRENT_USER"
xml_elem '    ' 'UID'           "$(id -u)"
xml_elem '    ' 'Groups'        "$CURRENT_GROUPS"
xml_elem '    ' 'Timestamp'     "$XMLTS"
xml_elem '    ' 'Kernel'        "$(uname -r)"
xml_elem '    ' 'Distribution'  "$(grep -m1 'PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || cat /etc/issue 2>/dev/null | head -1)"
xml_close '  ' 'Metadata'

# ==================================================================
# 1. SUDO RULES
# ==================================================================
echo '[*] Checking sudo rules...'
xml_open '  ' 'SudoRules'

sudo_output=$(sudo -l 2>/dev/null || true)
if [ -n "$sudo_output" ]; then
    xml_elem '    ' 'RawOutput' "$sudo_output"
    # NOPASSWD = can run without password
    if echo "$sudo_output" | grep -qi 'NOPASSWD'; then
        NOPASSWD_CMDS=$(echo "$sudo_output" | grep -i 'NOPASSWD' || true)
        xml_elem '    ' 'NOPASSWDEntries' "$NOPASSWD_CMDS"
        # Check for dangerous NOPASSWD commands
        DANGER_CMDS='bash\|sh\|python\|perl\|ruby\|node\|vim\|vi\|nano\|less\|more\|man\|find\|awk\|sed\|tar\|zip\|cp\|mv\|chmod\|chown\|dd\|tee\|curl\|wget\|nc\|netcat\|socat\|nmap\|tcpdump\|strace\|gdb\|ALL'
        if echo "$NOPASSWD_CMDS" | grep -qi "$DANGER_CMDS"; then
            MATCHED=$(echo "$NOPASSWD_CMDS" | grep -oi "$DANGER_CMDS" | head -5 | tr '\n' ',')
            add_finding 'CRITICAL' 'SudoNOPASSWD' \
                "NOPASSWD sudo rule for dangerous command(s): $MATCHED — direct SYSTEM/root escalation via GTFOBins technique" \
                "$NOPASSWD_CMDS"
        else
            add_finding 'HIGH' 'SudoNOPASSWD' \
                "NOPASSWD sudo rule present — may permit escalation depending on allowed command" "$NOPASSWD_CMDS"
        fi
    fi
    # (ALL) ALL = full sudo
    if echo "$sudo_output" | grep -q '(ALL.*) ALL$\|(ALL) ALL$\|(ALL.*) ALL$'; then
        add_finding 'CRITICAL' 'SudoAllAll' \
            "User has '(ALL) ALL' sudo rule — direct root access via 'sudo -s' or 'sudo bash'" 'sudo -l shows (ALL) ALL'
    fi
    # ALL with password still powerful
    if echo "$sudo_output" | grep -qi '(ALL)' && ! echo "$sudo_output" | grep -qi 'NOPASSWD'; then
        add_finding 'MEDIUM' 'SudoAllWithPassword' \
            "User has broad sudo access with password — if password is weak or known, full root available" 'sudo -l shows (ALL) with password'
    fi
else
    xml_elem '    ' 'Note' 'No sudo rules for current user (or sudo not available)'
fi
xml_close '  ' 'SudoRules'

# ==================================================================
# 2. SUID FILES (GTFOBins cross-reference)
# ==================================================================
echo '[*] Finding SUID binaries...'
xml_open '  ' 'SUIDFiles'

# High-value GTFOBins SUID targets
GTFO_SUID='bash|dash|sh|zsh|ksh|fish|python[23]?|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|node|lua[0-9.]*|gawk|nawk|awk|find|vim|vi|nano|pico|ed|nmap|less|more|tail|head|cat|tee|dd|cp|mv|tar|gzip|zip|unzip|curl|wget|nc|netcat|ncat|socat|ssh|ftp|tftp|git|svn|screen|tmux|man|env|xargs|strace|ltrace|openssl|base64|rsync|pkexec|newgrp|chsh|chfn|expect|make|nice|timeout|taskset|setarch|chroot|nsenter|ionice|mount|umount|chmod|chown|sed|xxd|jq|python3'

SUID_COUNT=0
while IFS= read -r suid_file; do
    [ -f "$suid_file" ] || continue
    SUID_COUNT=$((SUID_COUNT + 1))
    basename_f=$(basename "$suid_file")
    # Strip version numbers for matching: python3.11 → python3
    basename_clean=$(echo "$basename_f" | sed 's/[0-9][0-9.]*$//')
    is_gtfo=false
    if echo "$basename_f" | grep -qiE "^($GTFO_SUID)$" || echo "$basename_clean" | grep -qiE "^($GTFO_SUID)$"; then
        is_gtfo=true
    fi
    owner=$(stat -c '%U' "$suid_file" 2>/dev/null || echo 'unknown')
    perms=$(stat -c '%a' "$suid_file" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'SUIDFile'
    xml_elem '      ' 'Path'      "$suid_file"
    xml_elem '      ' 'Owner'     "$owner"
    xml_elem '      ' 'Perms'     "$perms"
    xml_elem '      ' 'GTFOBins'  "$is_gtfo"
    xml_close '    ' 'SUIDFile'
    if [ "$is_gtfo" = "true" ] && [ "$owner" = "root" ]; then
        add_finding 'CRITICAL' 'SUIDGTFOBin' \
            "Root-owned SUID binary in GTFOBins: $suid_file — direct root shell available, see gtfobins.github.io" "$suid_file"
    fi
done < <(find / -perm -4000 -type f 2>/dev/null | sort)

xml_close '  ' 'SUIDFiles'
printf '      ' >> /dev/null  # just to use SUID_COUNT
xml_open '  ' 'SGIDFiles'

# ==================================================================
# 3. SGID FILES
# ==================================================================
SGID_DANGER='docker|lxd|lxc|disk|shadow|cdrom|tape|video|dialout|dip'
while IFS= read -r sgid_file; do
    [ -f "$sgid_file" ] || continue
    basename_f=$(basename "$sgid_file")
    group_owner=$(stat -c '%G' "$sgid_file" 2>/dev/null || echo 'unknown')
    xml_open '    ' 'SGIDFile'
    xml_elem '      ' 'Path'       "$sgid_file"
    xml_elem '      ' 'GroupOwner' "$group_owner"
    xml_close '    ' 'SGIDFile'
    if echo "$group_owner" | grep -qiE "^($SGID_DANGER)$"; then
        add_finding 'HIGH' 'SGIDDangerousGroup' \
            "SGID binary owned by sensitive group '$group_owner': $sgid_file" "$sgid_file"
    fi
done < <(find / -perm -2000 -type f 2>/dev/null | sort)
xml_close '  ' 'SGIDFiles'

# ==================================================================
# 4. LINUX CAPABILITIES
# ==================================================================
echo '[*] Checking Linux capabilities...'
xml_open '  ' 'Capabilities'

DANGEROUS_CAPS='cap_setuid|cap_setgid|cap_net_raw|cap_sys_admin|cap_sys_ptrace|cap_dac_read_search|cap_dac_override|cap_chown|cap_fowner|cap_sys_module|cap_net_bind_service|cap_audit_write'

if command -v getcap >/dev/null 2>&1; then
    while IFS= read -r cap_line; do
        [ -z "$cap_line" ] || {
            cap_file=$(echo "$cap_line" | awk '{print $1}')
            cap_vals=$(echo "$cap_line" | cut -d' ' -f2-)
            xml_open '    ' 'Capability'
            xml_elem '      ' 'File'         "$cap_file"
            xml_elem '      ' 'Capabilities' "$cap_vals"
            xml_close '    ' 'Capability'
            if echo "$cap_vals" | grep -qiE "$DANGEROUS_CAPS"; then
                add_finding 'CRITICAL' 'DangerousCapability' \
                    "Binary has dangerous capability set — potential root/privilege escalation: $cap_line" "$cap_file"
            fi
        }
    done < <(getcap -r / 2>/dev/null)
else
    xml_elem '    ' 'Note' 'getcap not found — cannot enumerate capabilities'
fi
xml_close '  ' 'Capabilities'

# ==================================================================
# 5. WRITABLE CRON JOB SCRIPTS
# ==================================================================
echo '[*] Checking cron jobs for writable scripts...'
xml_open '  ' 'WritableCronScripts'

# Collect all cron scripts from system locations
CRON_FILES=()
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* \
          /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*; do
    [ -f "$f" ] && CRON_FILES+=("$f")
done

for cronfile in "${CRON_FILES[@]}"; do
    [ -r "$cronfile" ] || continue
    while IFS= read -r cronline; do
        # Skip comments and empty lines
        [[ "$cronline" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$cronline" ]] && continue
        # Extract the command portion (after timing fields or @reboot etc.)
        cmd=$(echo "$cronline" | awk '{
            # Handle @reboot, @hourly etc.
            if ($1 ~ /^@/) { for(i=2;i<=NF;i++) printf $i" "; print ""; next }
            # Handle user field in /etc/crontab format: min hour day month dow USER cmd
            if ($6 ~ /^[a-z]/) { for(i=7;i<=NF;i++) printf $i" "; print ""; next }
            # Standard: min hour day month dow cmd
            for(i=6;i<=NF;i++) printf $i" "; print ""
        }')
        # Extract script path (first token of command)
        script=$(echo "$cmd" | awk '{print $1}')
        [ -z "$script" ] || [[ "$script" != /* ]] && continue
        if [ -f "$script" ] && [ -w "$script" ]; then
            xml_open '    ' 'VulnerableCronEntry'
            xml_elem '      ' 'CronFile' "$cronfile"
            xml_elem '      ' 'Entry'    "$cronline"
            xml_elem '      ' 'Script'   "$script"
            xml_close '    ' 'VulnerableCronEntry'
            add_finding 'CRITICAL' 'WritableCronScript' \
                "Cron job in '$cronfile' executes '$script' which is writable by current user — inject commands for arbitrary execution" "$script"
        fi
    done < "$cronfile"
done
xml_close '  ' 'WritableCronScripts'

# ==================================================================
# 6. WRITABLE PATH DIRECTORIES
# ==================================================================
echo '[*] Checking PATH for writable directories...'
xml_open '  ' 'WritablePATHDirectories'
WRITABLE_PATH_COUNT=0

IFS=: read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    [ -z "$dir" ] && continue
    is_writable=false
    [ -d "$dir" ] && [ -w "$dir" ] && is_writable=true
    xml_open '    ' 'Directory'
    xml_elem '      ' 'Path'     "$dir"
    xml_elem '      ' 'Writable' "$is_writable"
    xml_close '    ' 'Directory'
    if [ "$is_writable" = "true" ]; then
        WRITABLE_PATH_COUNT=$((WRITABLE_PATH_COUNT + 1))
        add_finding 'HIGH' 'WritablePATHDirectory' \
            "PATH directory '$dir' is writable — plant malicious binary to hijack any command executed as root via sudo/cron" "$dir"
    fi
done
xml_close '  ' 'WritablePATHDirectories'

# ==================================================================
# 7. NFS EXPORTS (no_root_squash)
# ==================================================================
echo '[*] Checking NFS exports...'
xml_open '  ' 'NFSExports'

if [ -f /etc/exports ] && [ -r /etc/exports ]; then
    while IFS= read -r exportline; do
        [[ "$exportline" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$exportline" ]] && continue
        xml_elem '    ' 'Export' "$exportline"
        if echo "$exportline" | grep -qi 'no_root_squash'; then
            add_finding 'CRITICAL' 'NFSNoRootSquash' \
                "NFS export with no_root_squash — remote root can create SUID binaries on the share: $exportline" "$exportline"
        fi
        if echo "$exportline" | grep -qi 'no_all_squash\|*('; then
            add_finding 'HIGH' 'NFSWidespreadExport' \
                "NFS export accessible to all hosts (*) or without squash restrictions: $exportline" "$exportline"
        fi
    done < /etc/exports
else
    xml_elem '    ' 'Note' '/etc/exports not readable or not present'
fi
xml_close '  ' 'NFSExports'

# ==================================================================
# 8. DANGEROUS GROUP MEMBERSHIP
# ==================================================================
echo '[*] Checking group memberships...'
xml_open '  ' 'DangerousGroupMembership'

declare -A GROUP_RISKS=(
    ["docker"]="CRITICAL:Docker group membership = root — 'docker run -v /:/mnt ...' mounts host filesystem as root"
    ["lxd"]="CRITICAL:LXD group membership = root — launch privileged container with host disk mount"
    ["lxc"]="CRITICAL:LXC group membership = root via privileged container"
    ["disk"]="CRITICAL:Disk group = direct raw read/write of block devices — read /etc/shadow directly with debugfs"
    ["shadow"]="HIGH:Shadow group — can read /etc/shadow for offline cracking"
    ["sudo"]="HIGH:Sudo group member — check 'sudo -l' for what is permitted"
    ["wheel"]="HIGH:Wheel group — typically has sudo access; check 'sudo -l'"
    ["adm"]="MEDIUM:Adm group — can read system log files, may reveal sensitive data"
    ["video"]="MEDIUM:Video group — can read /dev/fb0 (framebuffer) for screen capture"
    ["staff"]="MEDIUM:Staff group — can write to /usr/local on some distros"
)

for group in "${!GROUP_RISKS[@]}"; do
    if id -nG 2>/dev/null | grep -qw "$group"; then
        IFS=: read -r risk_level risk_detail <<< "${GROUP_RISKS[$group]}"
        xml_open '    ' 'DangerousGroup'
        xml_elem '      ' 'GroupName'  "$group"
        xml_elem '      ' 'Risk'       "$risk_level"
        xml_elem '      ' 'Detail'     "$risk_detail"
        xml_close '    ' 'DangerousGroup'
        add_finding "$risk_level" 'DangerousGroupMembership' \
            "Current user is member of '$group': $risk_detail" "id -nG | grep $group"
    fi
done
xml_close '  ' 'DangerousGroupMembership'

# ==================================================================
# 9. SENSITIVE FILE PERMISSIONS
# ==================================================================
echo '[*] Checking sensitive file permissions...'
xml_open '  ' 'SensitiveFilePermissions'

declare -A SENSITIVE_FILES=(
    ["/etc/passwd"]="World-writable /etc/passwd — add root-equivalent user directly"
    ["/etc/shadow"]="Writable /etc/shadow — overwrite password hashes"
    ["/etc/sudoers"]="Writable /etc/sudoers — grant arbitrary sudo rules"
    ["/etc/crontab"]="Writable /etc/crontab — add root cron job"
    ["/etc/hosts"]="Writable /etc/hosts — DNS spoofing"
    ["/etc/ld.so.conf"]="Writable ld.so.conf — library hijacking"
    ["/etc/ld.so.conf.d"]="Writable ld.so.conf.d — library hijacking"
    ["/etc/environment"]="Writable /etc/environment — inject env vars for all sessions"
    ["/etc/profile"]="Writable /etc/profile — inject commands for all logins"
    ["/etc/profile.d"]="Writable /etc/profile.d — inject commands for all logins"
    ["/etc/rc.local"]="Writable /etc/rc.local — inject commands at boot (runs as root)"
    ["/etc/init.d"]="Writable /etc/init.d — modify service startup scripts"
    ["/lib/systemd/system"]="Writable systemd unit directory"
    ["/etc/systemd/system"]="Writable systemd unit directory"
)

for f in "${!SENSITIVE_FILES[@]}"; do
    [ -e "$f" ] || continue
    if [ -w "$f" ]; then
        perms=$(stat -c '%a %U %G' "$f" 2>/dev/null || echo 'unknown')
        xml_open '    ' 'WritableSensitiveFile'
        xml_elem '      ' 'Path'   "$f"
        xml_elem '      ' 'Perms'  "$perms"
        xml_elem '      ' 'Impact' "${SENSITIVE_FILES[$f]}"
        xml_close '    ' 'WritableSensitiveFile'
        add_finding 'CRITICAL' 'WritableSensitiveFile' "${SENSITIVE_FILES[$f]}: $f" "$f"
    fi
done

# Check /etc/passwd for write-all (not just current user)
if [ -f /etc/passwd ]; then
    world_write=$(stat -c '%a' /etc/passwd 2>/dev/null || true)
    if [[ "$world_write" =~ [2367]$ ]]; then
        add_finding 'CRITICAL' 'WorldWritablePasswd' \
            '/etc/passwd is world-writable — add uid=0 user without root password requirement' '/etc/passwd'
    fi
fi
xml_close '  ' 'SensitiveFilePermissions'

# ==================================================================
# 10. CONSOLIDATED FINDINGS
# ==================================================================
printf '  <Findings count="%d">\n' "$FINDING_COUNT" >> "$OUTFILE"
cat "$FINDINGS_TMP" >> "$OUTFILE"
printf '  </Findings>\n' >> "$OUTFILE"
rm -f "$FINDINGS_TMP"

xml_close '' 'PrivescAudit'

echo ''
echo " Findings : ${FINDING_COUNT}"
echo " Output   : ${OUTFILE}"
