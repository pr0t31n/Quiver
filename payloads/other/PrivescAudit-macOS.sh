#!/usr/bin/env bash
# ==================================================================
#  PrivescAudit-macOS.sh
#  Description : Local privilege escalation vector assessment for macOS.
#                Checks macOS-specific escalation paths: SIP status,
#                TCC database, writable Launch Daemons, SUID binaries,
#                sudo rules, dylib hijacking opportunities, Gatekeeper
#                bypass vectors, and more.
#  Author      : [Operator]
#  Compatible  : macOS 11+ (Big Sur and later); bash 3.2+
#  Privileges  : Run as the target user (not pre-elevated) to
#                accurately reflect what that account can escalate with.
#                Some checks require root to return full results.
#  Output      : /tmp/PrivescAudit/PrivescAudit_<HOST>_<TS>.xml
#
#  Sections:
#    1. SIPStatus              — System Integrity Protection state
#    2. SecureBootStatus       — T2/Apple Silicon Secure Boot
#    3. GatekeeperStatus       — app execution controls
#    4. SudoRules              — NOPASSWD or dangerous sudo commands
#    5. SUIDFiles              — SUID binaries (GTFOBins cross-reference)
#    6. WritableLaunchDaemons  — LaunchDaemon plists writable by non-root
#    7. WritableLaunchAgents   — LaunchAgent plists writable by user
#    8. PeriodicScripts        — Writable periodic maintenance scripts
#    9. DylibHijacking         — Writable dylib paths in app bundles
#   10. WritablePATHDirs       — writable directories in PATH
#   11. TCCStatus              — Transparency, Consent, Control state
#   12. MDMEnrollment          — MDM management and bypass surface
#   13. KernelExtensions       — Loaded kernel extensions (unsigned)
#   14. Findings               — consolidated risk-rated findings
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
echo "  PrivescAudit-macOS.sh - macOS Privilege Escalation Audit"
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
    printf '<PrivescAuditReport>\n'
    printf '  <Meta>\n'
    printf '    <Script>PrivescAudit-macOS.sh</Script>\n'
    printf '    <Host>%s</Host>\n' "$(xml_safe "$HOSTNAME_VAL")"
    printf '    <OS>%s</OS>\n' "$(xml_safe "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)")"
    printf '    <User>%s</User>\n' "$(xml_safe "$(id)")"
    printf '    <Groups>%s</Groups>\n' "$(xml_safe "$CURRENT_GROUPS")"
    printf '    <Timestamp>%s</Timestamp>\n' "$XMLTS"
    printf '  </Meta>\n'
} >> "$OUTFILE"

# ==================================================================
# 1. SYSTEM INTEGRITY PROTECTION
# ==================================================================
echo "[1/13] System Integrity Protection..."
xml_open "  " "SIPStatus"

SIP_STATUS=$(csrutil status 2>/dev/null || echo "csrutil not available")
xml_elem "    " "StatusOutput" "$SIP_STATUS"

if echo "$SIP_STATUS" | grep -q "disabled"; then
    add_finding "CRITICAL" "SIPStatus" \
        "SIP is DISABLED — system files, daemons, and protected paths are modifiable" \
        "$SIP_STATUS"
elif echo "$SIP_STATUS" | grep -q "enabled"; then
    add_finding "INFO" "SIPStatus" "SIP is enabled" "$SIP_STATUS"
fi

# Check for SIP partial disables (individual flags)
SIP_DETAIL=$(csrutil status --verbose 2>/dev/null || true)
xml_elem "    " "DetailedStatus" "${SIP_DETAIL:-not available}"
if echo "$SIP_DETAIL" | grep -qE "debugging.*disabled|fs protections.*disabled|kext.*disabled"; then
    add_finding "HIGH" "SIPStatus" \
        "SIP has partial protections disabled" \
        "$SIP_DETAIL"
fi

xml_close "  " "SIPStatus"

# ==================================================================
# 2. SECURE BOOT STATUS
# ==================================================================
echo "[2/13] Secure Boot Status..."
xml_open "  " "SecureBootStatus"

BPUTIL_OUTPUT=$(bputil -d 2>/dev/null || echo "bputil not available (Intel?)")
xml_elem "    " "BputilOutput" "$BPUTIL_OUTPUT"

if echo "$BPUTIL_OUTPUT" | grep -qi "reduced security\|permissive security"; then
    add_finding "HIGH" "SecureBootStatus" \
        "Non-full Secure Boot policy: kernel extensions and unsigned code may load" \
        "$BPUTIL_OUTPUT"
elif echo "$BPUTIL_OUTPUT" | grep -qi "full security"; then
    add_finding "INFO" "SecureBootStatus" "Full Secure Boot active" ""
fi

xml_close "  " "SecureBootStatus"

# ==================================================================
# 3. GATEKEEPER STATUS
# ==================================================================
echo "[3/13] Gatekeeper Status..."
xml_open "  " "GatekeeperStatus"

GK_STATUS=$(spctl --status 2>/dev/null || echo "spctl not available")
xml_elem "    " "SpctlStatus" "$GK_STATUS"

if echo "$GK_STATUS" | grep -q "disabled\|assessments disabled"; then
    add_finding "HIGH" "GatekeeperStatus" \
        "Gatekeeper is DISABLED — unsigned and unnotarized apps run without prompts" \
        "$GK_STATUS"
fi

xml_close "  " "GatekeeperStatus"

# ==================================================================
# 4. SUDO RULES
# ==================================================================
echo "[4/13] Sudo Rules..."
xml_open "  " "SudoRules"

SUDO_L=$(sudo -l 2>/dev/null || echo "sudo -l failed (no sudo access or requires password)")
xml_elem "    " "SudoLOutput" "$SUDO_L"

if echo "$SUDO_L" | grep -qiE "NOPASSWD.*ALL|NOPASSWD.*bash|NOPASSWD.*sh\b|NOPASSWD.*python|NOPASSWD.*perl|NOPASSWD.*ruby|NOPASSWD.*vim|NOPASSWD.*tee|NOPASSWD.*cp\b|NOPASSWD.*chmod|NOPASSWD.*chown"; then
    add_finding "CRITICAL" "SudoRules" \
        "NOPASSWD sudo rule for shell/scripting interpreter — trivial privesc" \
        "$SUDO_L"
elif echo "$SUDO_L" | grep -q "NOPASSWD"; then
    add_finding "HIGH" "SudoRules" \
        "NOPASSWD sudo rule present — review for exploit potential" \
        "$SUDO_L"
fi

if echo "$SUDO_L" | grep -q "(ALL) ALL"; then
    add_finding "CRITICAL" "SudoRules" \
        "Unrestricted sudo (ALL) ALL available for current user" \
        "$SUDO_L"
fi

# Sudo timestamp — how long does the ticket last?
SUDO_TS=$(sudo -V 2>/dev/null | grep "Authentication timestamp" || echo "Timestamp: 5 min (default)")
xml_elem "    " "SudoTimestamp" "$SUDO_TS"

xml_close "  " "SudoRules"

# ==================================================================
# 5. SUID FILES
# ==================================================================
echo "[5/13] SUID Files..."
xml_open "  " "SUIDFiles"

# macOS GTFOBins candidates
GTFOBINS_PATTERN='bash|dash|sh|python[23]?|perl[0-9.]*|ruby|find|vim|vi|nano|nmap|more|less|man|awk|gawk|tee|cp\b|mv\b|chmod|chown|rsync|env|node|php|lua|tcl|expect|screen|tmux|sed|zip|tar|curl|wget|ssh\b|socat|nc\b|netcat|openssl|strace|gdb|jq|xargs'

xml_open "    " "SUIDList"
while IFS= read -r -d '' suid_file; do
    fname=$(basename "$suid_file")
    xml_open "      " "SUIDFile"
    xml_elem "        " "Path" "$suid_file"

    if echo "$fname" | grep -qiE "$GTFOBINS_PATTERN"; then
        xml_elem "        " "GTFOBins" "YES"
        add_finding "CRITICAL" "SUIDFiles" \
            "SUID binary in GTFOBins — trivial root escalation: ${suid_file}" ""
    else
        xml_elem "        " "GTFOBins" "no"
        add_finding "MEDIUM" "SUIDFiles" \
            "SUID binary (review for exploit): ${suid_file}" ""
    fi
    xml_close "      " "SUIDFile"
done < <(find / -xdev -perm -4000 -type f -print0 2>/dev/null | \
    grep -vzE '^/(System|private/var/db/mds|Library/Apple)' | head -z -n 100)
xml_close "    " "SUIDList"

xml_close "  " "SUIDFiles"

# ==================================================================
# 6. WRITABLE LAUNCH DAEMONS
# ==================================================================
echo "[6/13] Writable Launch Daemons..."
xml_open "  " "WritableLaunchDaemons"

# LaunchDaemons run as root — if plist or referenced binary is writable, = privesc
for daemon_dir in /Library/LaunchDaemons /System/Library/LaunchDaemons; do
    [ -d "$daemon_dir" ] || continue
    while IFS= read -r -d '' plist; do
        # Check plist writability
        if [ -w "$plist" ]; then
            xml_open "    " "WritableDaemon"
            xml_elem "      " "PlistPath" "$plist"
            xml_elem "      " "Writable" "YES"
            xml_close "    " "WritableDaemon"
            add_finding "CRITICAL" "WritableLaunchDaemons" \
                "LaunchDaemon plist writable by current user (runs as root): ${plist}" ""
        fi
        # Check if the referenced binary is writable
        PROGRAM=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || \
                  /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || true)
        if [ -n "$PROGRAM" ] && [ -f "$PROGRAM" ] && [ -w "$PROGRAM" ]; then
            xml_open "    " "WritableDaemonBinary"
            xml_elem "      " "PlistPath" "$plist"
            xml_elem "      " "BinaryPath" "$PROGRAM"
            xml_close "    " "WritableDaemonBinary"
            add_finding "CRITICAL" "WritableLaunchDaemons" \
                "LaunchDaemon references writable binary (runs as root): ${PROGRAM}" \
                "Plist: ${plist}"
        fi
    done < <(find "$daemon_dir" -name "*.plist" -print0 2>/dev/null)
done

xml_close "  " "WritableLaunchDaemons"

# ==================================================================
# 7. WRITABLE LAUNCH AGENTS
# ==================================================================
echo "[7/13] Writable Launch Agents (user persistence)..."
xml_open "  " "WritableLaunchAgents"

HOME_USER="${HOME:-/Users/$CURRENT_USER}"
for agent_dir in \
    "/Library/LaunchAgents" \
    "$HOME_USER/Library/LaunchAgents"; do
    [ -d "$agent_dir" ] || continue
    while IFS= read -r -d '' plist; do
        PROGRAM=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || \
                  /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || true)
        if [ -n "$PROGRAM" ] && [ -f "$PROGRAM" ] && [ -w "$PROGRAM" ]; then
            xml_open "    " "WritableAgentBinary"
            xml_elem "      " "PlistPath" "$plist"
            xml_elem "      " "BinaryPath" "$PROGRAM"
            xml_close "    " "WritableAgentBinary"
            add_finding "HIGH" "WritableLaunchAgents" \
                "LaunchAgent references writable binary: ${PROGRAM}" \
                "Plist: ${plist}"
        fi
    done < <(find "$agent_dir" -name "*.plist" -print0 2>/dev/null)
done

xml_close "  " "WritableLaunchAgents"

# ==================================================================
# 8. PERIODIC MAINTENANCE SCRIPTS
# ==================================================================
echo "[8/13] Periodic Scripts..."
xml_open "  " "PeriodicScripts"

for period_dir in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly \
                  /usr/local/etc/periodic/daily /usr/local/etc/periodic/weekly; do
    [ -d "$period_dir" ] || continue
    while IFS= read -r -d '' script; do
        if [ -w "$script" ]; then
            xml_open "    " "WritablePeriodicScript"
            xml_elem "      " "Path" "$script"
            xml_close "    " "WritablePeriodicScript"
            add_finding "HIGH" "PeriodicScripts" \
                "Periodic maintenance script writable by current user: ${script}" \
                "Runs as root by launchd periodic subsystem"
        fi
    done < <(find "$period_dir" -type f -print0 2>/dev/null)
done

xml_close "  " "PeriodicScripts"

# ==================================================================
# 9. DYLIB HIJACKING
# ==================================================================
echo "[9/13] Dylib Hijacking Opportunities..."
xml_open "  " "DylibHijacking"

# Search for @rpath or @loader_path dylib references in app bundles
# that could be hijacked if a writable directory is in the rpath
DYLIB_HITS=0
while IFS= read -r app_bin; do
    RPATHS=$(otool -l "$app_bin" 2>/dev/null | grep -A2 "LC_RPATH" | grep "path" | awk '{print $2}' || true)
    for rpath in $RPATHS; do
        # Expand @executable_path
        case "$rpath" in
            @executable_path*)
                rpath="${app_bin%/*}${rpath#@executable_path}"
                ;;
            @loader_path*)
                rpath="${app_bin%/*}${rpath#@loader_path}"
                ;;
        esac
        if [ -d "$rpath" ] && [ -w "$rpath" ]; then
            xml_open "    " "WritableRPath"
            xml_elem "      " "Binary" "$app_bin"
            xml_elem "      " "WritableRPath" "$rpath"
            xml_close "    " "WritableRPath"
            add_finding "HIGH" "DylibHijacking" \
                "App binary has writable rpath directory — dylib hijacking possible: ${app_bin}" \
                "Writable rpath: $rpath"
            DYLIB_HITS=$((DYLIB_HITS + 1))
            break
        fi
    done
    [ "$DYLIB_HITS" -ge 10 ] && break
done < <(find /Applications /usr/local /opt 2>/dev/null \
    -type f -perm -0111 -not -path "*.app/Contents/Frameworks/*" \
    -print | head -200)

xml_close "  " "DylibHijacking"

# ==================================================================
# 10. WRITABLE PATH DIRECTORIES
# ==================================================================
echo "[10/13] Writable PATH Directories..."
xml_open "  " "WritablePATHDirs"

IFS=':' read -ra PATH_DIRS <<< "$PATH"
for dir in "${PATH_DIRS[@]}"; do
    [ -z "$dir" ] && continue
    real_dir=$(readlink -f "$dir" 2>/dev/null || echo "$dir")
    if [ -d "$real_dir" ] && [ -w "$real_dir" ]; then
        xml_open "    " "WritablePathDir"
        xml_elem "      " "Dir" "$dir"
        xml_close "    " "WritablePathDir"
        add_finding "HIGH" "WritablePATHDirs" \
            "Writable PATH directory — place malicious binary to hijack privileged commands: ${dir}" ""
    fi
done

xml_close "  " "WritablePATHDirs"

# ==================================================================
# 11. TCC STATUS
# ==================================================================
echo "[11/13] TCC (Transparency, Consent, Control)..."
xml_open "  " "TCCStatus"

# Check user TCC database (readable without root for user entries)
USER_TCC="$HOME_USER/Library/Application Support/com.apple.TCC/TCC.db"
SYSTEM_TCC="/Library/Application Support/com.apple.TCC/TCC.db"

if [ -f "$USER_TCC" ] && [ -r "$USER_TCC" ]; then
    TCC_ENTRIES=$(sqlite3 "$USER_TCC" "SELECT service,client,allowed FROM access WHERE allowed=1" 2>/dev/null | head -30 || echo "sqlite3 not available or access denied")
    xml_elem "    " "UserTCCEntries" "$TCC_ENTRIES"
    # Check for FDA (kTCCServiceSystemPolicyAllFiles)
    if echo "$TCC_ENTRIES" | grep -q "kTCCServiceSystemPolicyAllFiles"; then
        FDA_APPS=$(echo "$TCC_ENTRIES" | grep "kTCCServiceSystemPolicyAllFiles" | cut -d'|' -f2)
        add_finding "CRITICAL" "TCCStatus" \
            "App(s) with Full Disk Access (FDA) in user TCC: ${FDA_APPS}" \
            "FDA bypasses per-file permissions — abuse to read protected files"
    fi
else
    xml_elem "    " "UserTCCEntries" "not readable (normal on macOS 12+)"
fi

# Check for TCC bypass tools
for tcc_bypass_tool in /usr/bin/python3 /usr/local/bin/python3; do
    if [ -f "$tcc_bypass_tool" ]; then
        # Check if Terminal or iTerm2 has Accessibility access (enables TCC bypass via AppleScript)
        xml_elem "    " "PythonPresent" "$tcc_bypass_tool"
    fi
done

xml_close "  " "TCCStatus"

# ==================================================================
# 12. MDM ENROLLMENT
# ==================================================================
echo "[12/13] MDM Enrollment..."
xml_open "  " "MDMEnrollment"

PROFILES_OUT=$(profiles status -type enrollment 2>/dev/null || profiles list 2>/dev/null || echo "profiles not available")
xml_elem "    " "ProfilesStatus" "$PROFILES_OUT"

# Check for device supervision (MDM can push arbitrary certs/proxies)
if echo "$PROFILES_OUT" | grep -qi "Supervised: Yes\|DEP enrolled\|supervision"; then
    add_finding "HIGH" "MDMEnrollment" \
        "Device is MDM-supervised — MDM server has privileged management capabilities" \
        "$PROFILES_OUT"
elif echo "$PROFILES_OUT" | grep -qi "Enrolled\|MDM"; then
    add_finding "MEDIUM" "MDMEnrollment" \
        "Device is MDM-enrolled (user-enrolled, not supervised)" \
        "$PROFILES_OUT"
fi

xml_close "  " "MDMEnrollment"

# ==================================================================
# 13. KERNEL EXTENSIONS
# ==================================================================
echo "[13/13] Kernel Extensions..."
xml_open "  " "KernelExtensions"

KEXT_LIST=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || echo "kextstat not available")
xml_elem "    " "ThirdPartyKexts" "$KEXT_LIST"

if [ -n "$KEXT_LIST" ] && [ "$KEXT_LIST" != "kextstat not available" ]; then
    KEXT_COUNT=$(echo "$KEXT_LIST" | grep -c "." || echo 0)
    [ "$KEXT_COUNT" -gt 0 ] && add_finding "MEDIUM" "KernelExtensions" \
        "${KEXT_COUNT} third-party kernel extension(s) loaded — review for vulnerable kexts" \
        "$KEXT_LIST"
fi

# Check for unsigned kexts (should be impossible with SIP, but check)
UNSIGNED_KEXTS=$(kextstat 2>/dev/null | awk '!/ com\.apple\./ && !/Sign/{print $6}' | head -10 || true)
xml_elem "    " "PossiblyUnsignedKexts" "${UNSIGNED_KEXTS:-none}"

xml_close "  " "KernelExtensions"

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
    printf '</PrivescAuditReport>\n'
} >> "$OUTFILE"

rm -f "$FINDINGS_TMP"

echo ""
echo " ===================================================="
echo "  PrivescAudit-macOS complete."
echo "  Findings : ${FINDING_COUNT}"
echo "  Output   : ${OUTFILE}"
echo " ===================================================="
