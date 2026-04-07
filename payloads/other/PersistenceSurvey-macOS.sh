#!/usr/bin/env bash
# ==================================================================
#  PersistenceSurvey-macOS.sh
#  Description : Persistence mechanism survey for macOS systems.
#                Enumerates LaunchDaemons/Agents, Login Items, MDM
#                profiles, cron, shell RC files, DYLD injection,
#                kernel extensions, periodic scripts, and more.
#  Author      : [Operator]
#  Compatible  : macOS 11+ (Big Sur and later); bash 3.2+
#  Privileges  : Run as root for complete results.
#  Output      : /tmp/PersistenceSurvey/PersistenceSurvey_<HOST>_<TS>.xml
#
#  Sections:
#    1. LaunchDaemons          — /Library/LaunchDaemons (root)
#    2. LaunchAgents           — System + user LaunchAgents
#    3. LoginItems             — Login Items (LSSharedFileList)
#    4. MDMProfiles            — Mobile Device Management profiles
#    5. CronJobs               — System and user crontabs
#    6. PeriodicScripts        — /etc/periodic maintenance scripts
#    7. ShellRCFiles           — shell startup file modifications
#    8. DYLDInjection          — DYLD_INSERT_LIBRARIES persistence
#    9. LoginHooks             — com.apple.loginwindow hooks
#   10. KernelExtensions       — Third-party kexts
#   11. StartupItems           — Legacy /Library/StartupItems
#   12. XPCServices            — Writable XPC service bundles
#   13. Findings               — consolidated risk-rated findings
# ==================================================================

set -uo pipefail

AUDIT_DIR="/tmp/PersistenceSurvey"
mkdir -p "$AUDIT_DIR"

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
XMLTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
CURRENT_USER=$(id -un)
HOME_USER="${HOME:-/Users/$CURRENT_USER}"
OUTFILE="${AUDIT_DIR}/PersistenceSurvey_${HOSTNAME_VAL}_${TIMESTAMP}.xml"
FINDINGS_TMP=$(mktemp)
FINDING_COUNT=0

printf '' > "$OUTFILE"

echo ""
echo " ===================================================="
echo "  PersistenceSurvey-macOS.sh"
echo " ===================================================="
echo "  Host      : ${HOSTNAME_VAL}"
echo "  User      : $(id)"
echo "  Timestamp : ${XMLTS}"
echo "  Output    : ${OUTFILE}"
echo " ===================================================="
echo ""

xml_safe() { local s="$*"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"; printf '%s' "$s"; }
xml_elem()  { printf '%s<%s>%s</%s>\n' "$1" "$2" "$(xml_safe "$3")" "$2" >> "$OUTFILE"; }
xml_open()  { printf '%s<%s>\n' "$1" "$2" >> "$OUTFILE"; }
xml_close() { printf '%s</%s>\n' "$1" "$2" >> "$OUTFILE"; }
add_finding() {
    local risk="$1" cat="$2" detail="$3" evidence="${4:-}"
    FINDING_COUNT=$((FINDING_COUNT + 1))
    { printf '    <Finding risk="%s">\n' "$risk"
      printf '      <Category>%s</Category>\n' "$(xml_safe "$cat")"
      printf '      <Detail>%s</Detail>\n' "$(xml_safe "$detail")"
      [ -n "$evidence" ] && printf '      <Evidence>%s</Evidence>\n' "$(xml_safe "$evidence")"
      printf '    </Finding>\n'; } >> "$FINDINGS_TMP"
}

{ printf '<?xml version="1.0" encoding="UTF-8"?>\n<PersistenceSurveyReport>\n'
  printf '  <Meta><Script>PersistenceSurvey-macOS.sh</Script>'
  printf '<Host>%s</Host><OS>%s</OS><User>%s</User><Timestamp>%s</Timestamp></Meta>\n' \
    "$(xml_safe "$HOSTNAME_VAL")" \
    "$(xml_safe "$(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)")" \
    "$(xml_safe "$(id)")" "$XMLTS"; } >> "$OUTFILE"

# Helper: inspect a plist for ExecStart/Program and check writability
inspect_plist() {
    local plist="$1"
    local label
    label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || basename "$plist" .plist)
    local program
    program=$(/usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null || \
              /usr/libexec/PlistBuddy -c "Print :ProgramArguments:0" "$plist" 2>/dev/null || true)
    local run_at_load
    run_at_load=$(/usr/libexec/PlistBuddy -c "Print :RunAtLoad" "$plist" 2>/dev/null || echo "false")
    local keep_alive
    keep_alive=$(/usr/libexec/PlistBuddy -c "Print :KeepAlive" "$plist" 2>/dev/null || echo "false")
    local mtime
    mtime=$(stat -f '%Sm' -t '%Y-%m-%d' "$plist" 2>/dev/null || true)

    printf '      <Label>%s</Label>\n' "$(xml_safe "$label")" >> "$OUTFILE"
    printf '      <Program>%s</Program>\n' "$(xml_safe "${program:-unknown}")" >> "$OUTFILE"
    printf '      <RunAtLoad>%s</RunAtLoad>\n' "$run_at_load" >> "$OUTFILE"
    printf '      <KeepAlive>%s</KeepAlive>\n' "$keep_alive" >> "$OUTFILE"
    printf '      <LastModified>%s</LastModified>\n' "$mtime" >> "$OUTFILE"
    printf '      <PlistWritable>%s</PlistWritable>\n' "$([ -w "$plist" ] && echo YES || echo no)" >> "$OUTFILE"

    if [ -n "$program" ] && [ -f "$program" ] && [ -w "$program" ]; then
        printf '      <BinaryWritable>YES</BinaryWritable>\n' >> "$OUTFILE"
        echo "$program $plist"  # signal caller
    else
        printf '      <BinaryWritable>no</BinaryWritable>\n' >> "$OUTFILE"
    fi
}

# ==================================================================
# 1. LAUNCH DAEMONS (system-wide, run as root)
# ==================================================================
echo "[1/12] LaunchDaemons..."
xml_open "  " "LaunchDaemons"

for daemon_dir in /Library/LaunchDaemons /System/Library/LaunchDaemons; do
    [ -d "$daemon_dir" ] || continue
    xml_open "    " "DaemonDirectory"
    xml_elem "      " "Path" "$daemon_dir"
    PLIST_COUNT=$(find "$daemon_dir" -name "*.plist" 2>/dev/null | wc -l)
    xml_elem "      " "Count" "$PLIST_COUNT"

    while IFS= read -r -d '' plist; do
        # Skip Apple's own daemons unless recently modified
        if [[ "$plist" == *"com.apple."* ]]; then
            AGE=$(( ($(date +%s) - $(stat -f '%m' "$plist" 2>/dev/null || echo 0)) / 86400 ))
            [ "$AGE" -gt 30 ] && continue
        fi

        xml_open "      " "LaunchDaemon"
        xml_elem "        " "PlistPath" "$plist"
        WRITABLE_BIN=$(inspect_plist "$plist")
        xml_close "      " "LaunchDaemon"

        if [ -w "$plist" ]; then
            add_finding "CRITICAL" "LaunchDaemons" \
                "LaunchDaemon plist writable by current user (runs as root): ${plist}" ""
        fi
        if [ -n "$WRITABLE_BIN" ]; then
            add_finding "CRITICAL" "LaunchDaemons" \
                "LaunchDaemon references writable binary: ${WRITABLE_BIN%% *}" \
                "Plist: ${WRITABLE_BIN##* }"
        fi
    done < <(find "$daemon_dir" -name "*.plist" -print0 2>/dev/null)

    xml_close "    " "DaemonDirectory"
done

# Currently loaded daemons
LOADED_DAEMONS=$(launchctl list 2>/dev/null | grep -v "^PID\|-\s" | head -40 || true)
xml_elem "    " "CurrentlyLoadedDaemons" "$LOADED_DAEMONS"

xml_close "  " "LaunchDaemons"

# ==================================================================
# 2. LAUNCH AGENTS
# ==================================================================
echo "[2/12] LaunchAgents..."
xml_open "  " "LaunchAgents"

for agent_dir in \
    /Library/LaunchAgents \
    "$HOME_USER/Library/LaunchAgents"; do
    [ -d "$agent_dir" ] || continue
    xml_open "    " "AgentDirectory"
    xml_elem "      " "Path" "$agent_dir"

    while IFS= read -r -d '' plist; do
        [[ "$plist" == *"com.apple."* ]] && continue
        xml_open "      " "LaunchAgent"
        xml_elem "        " "PlistPath" "$plist"
        WRITABLE_BIN=$(inspect_plist "$plist")
        xml_close "      " "LaunchAgent"

        LABEL=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null || true)
        add_finding "MEDIUM" "LaunchAgents" \
            "Third-party LaunchAgent: ${LABEL:-$(basename "$plist")} — review for unexpected persistence" \
            "$plist"
        if [ -n "$WRITABLE_BIN" ]; then
            add_finding "HIGH" "LaunchAgents" \
                "LaunchAgent references writable binary: ${WRITABLE_BIN%% *}" \
                "Plist: $plist"
        fi
    done < <(find "$agent_dir" -name "*.plist" -not -name "com.apple.*" -print0 2>/dev/null)

    xml_close "    " "AgentDirectory"
done

xml_close "  " "LaunchAgents"

# ==================================================================
# 3. LOGIN ITEMS
# ==================================================================
echo "[3/12] Login Items..."
xml_open "  " "LoginItems"

LOGIN_ITEMS=$(osascript -e 'tell application "System Events" to get name of login items' 2>/dev/null || \
             sfltool dump-login-items 2>/dev/null | head -40 || \
             echo "Could not enumerate login items (may require Full Disk Access)")
xml_elem "    " "LoginItemList" "$LOGIN_ITEMS"
if [ -n "$LOGIN_ITEMS" ] && [ "$LOGIN_ITEMS" != "Could not enumerate login items"* ]; then
    add_finding "MEDIUM" "LoginItems" \
        "Login items present — run at user login" "$LOGIN_ITEMS"
fi

# Background Login Items (macOS 13+ SMAppService)
BG_ITEMS=$(pluginkit -m -v 2>/dev/null | grep -i "login\|bg" | head -20 || true)
xml_elem "    " "BackgroundLoginItems" "${BG_ITEMS:-none found}"

xml_close "  " "LoginItems"

# ==================================================================
# 4. MDM PROFILES
# ==================================================================
echo "[4/12] MDM Profiles..."
xml_open "  " "MDMProfiles"

ALL_PROFILES=$(profiles list -all 2>/dev/null || profiles list 2>/dev/null || echo "not available")
xml_elem "    " "AllProfiles" "$ALL_PROFILES"

PROFILE_COUNT=$(echo "$ALL_PROFILES" | grep -c "profileIdentifier\|Attribute" 2>/dev/null || echo 0)
xml_elem "    " "ProfileCount" "$PROFILE_COUNT"

if [ "$PROFILE_COUNT" -gt 0 ]; then
    add_finding "MEDIUM" "MDMProfiles" \
        "${PROFILE_COUNT} configuration profile(s) installed — MDM or manual" \
        "profiles list -all"
fi

# Check for device enrollment
ENROLLMENT=$(profiles status -type enrollment 2>/dev/null || true)
xml_elem "    " "EnrollmentStatus" "${ENROLLMENT:-unknown}"
if echo "$ENROLLMENT" | grep -qi "enrolled\|MDM"; then
    add_finding "HIGH" "MDMProfiles" \
        "Device is MDM-enrolled — MDM server can push additional plists, certs, or restrictions" \
        "$ENROLLMENT"
fi

xml_close "  " "MDMProfiles"

# ==================================================================
# 5. CRON JOBS
# ==================================================================
echo "[5/12] Cron Jobs..."
xml_open "  " "CronJobs"

# System crontab
if [ -f /etc/crontab ] && [ -s /etc/crontab ]; then
    CONTENT=$(grep -v "^#\|^$" /etc/crontab 2>/dev/null | head -20)
    xml_elem "    " "SystemCrontab" "$CONTENT"
    [ -n "$CONTENT" ] && add_finding "MEDIUM" "CronJobs" \
        "/etc/crontab has entries" "$CONTENT"
fi

# User crontab
USER_CRON=$(crontab -l 2>/dev/null | grep -v "^#\|^$" | head -20 || true)
if [ -n "$USER_CRON" ]; then
    xml_elem "    " "UserCrontab" "$USER_CRON"
    add_finding "MEDIUM" "CronJobs" \
        "User crontab entries for current user" "$USER_CRON"
fi

xml_close "  " "CronJobs"

# ==================================================================
# 6. PERIODIC SCRIPTS
# ==================================================================
echo "[6/12] Periodic Scripts..."
xml_open "  " "PeriodicScripts"

for period_dir in /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly \
                  /usr/local/etc/periodic/daily /usr/local/etc/periodic/weekly; do
    [ -d "$period_dir" ] || continue
    while IFS= read -r -d '' script; do
        xml_open "    " "PeriodicScript"
        xml_elem "      " "Path" "$script"
        xml_elem "      " "Writable" "$([ -w "$script" ] && echo YES || echo no)"
        xml_close "    " "PeriodicScript"
        if [ -w "$script" ]; then
            add_finding "HIGH" "PeriodicScripts" \
                "Periodic script writable by current user (runs as root): ${script}" ""
        fi
    done < <(find "$period_dir" -type f -print0 2>/dev/null)
done

xml_close "  " "PeriodicScripts"

# ==================================================================
# 7. SHELL RC FILES
# ==================================================================
echo "[7/12] Shell RC Files (modified < 30 days)..."
xml_open "  " "ShellRCFiles"

RECENT=$(find "$HOME_USER" /etc 2>/dev/null \
    \( -name ".bashrc" -o -name ".bash_profile" -o -name ".zshrc" \
    -o -name ".zprofile" -o -name ".zshenv" -o -name ".profile" \
    -o -name "zshrc" -o -name "zshenv" \) \
    -mtime -30 -print 2>/dev/null | head -20 || true)

if [ -n "$RECENT" ]; then
    xml_elem "    " "RecentlyModifiedRCFiles" "$RECENT"
    echo "$RECENT" | while IFS= read -r rcfile; do
        add_finding "MEDIUM" "ShellRCFiles" \
            "Shell RC file modified within last 30 days: ${rcfile}" ""
    done
fi

xml_close "  " "ShellRCFiles"

# ==================================================================
# 8. DYLD INJECTION PATHS
# ==================================================================
echo "[8/12] DYLD Injection..."
xml_open "  " "DYLDInjection"

# DYLD_INSERT_LIBRARIES in environment
if [ -n "${DYLD_INSERT_LIBRARIES:-}" ]; then
    xml_elem "    " "DYLD_INSERT_LIBRARIES" "$DYLD_INSERT_LIBRARIES"
    add_finding "CRITICAL" "DYLDInjection" \
        "DYLD_INSERT_LIBRARIES set in current environment: ${DYLD_INSERT_LIBRARIES}" \
        "All dynamic binaries will load this library (if SIP disabled or library is pre-SIP)"
fi

# DYLD_INSERT_LIBRARIES in launchd plists
while IFS= read -r -d '' plist; do
    if /usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:DYLD_INSERT_LIBRARIES" \
        "$plist" 2>/dev/null | grep -q .; then
        DYLD_PATH=$(/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables:DYLD_INSERT_LIBRARIES" "$plist" 2>/dev/null)
        add_finding "CRITICAL" "DYLDInjection" \
            "LaunchDaemon/Agent sets DYLD_INSERT_LIBRARIES: ${DYLD_PATH}" \
            "Plist: $plist"
        xml_open "    " "PlistDYLD"
        xml_elem "      " "Plist" "$plist"
        xml_elem "      " "Library" "$DYLD_PATH"
        xml_close "    " "PlistDYLD"
    fi
done < <(find /Library/LaunchDaemons /Library/LaunchAgents \
    "$HOME_USER/Library/LaunchAgents" -name "*.plist" -print0 2>/dev/null)

xml_close "  " "DYLDInjection"

# ==================================================================
# 9. LOGIN HOOKS
# ==================================================================
echo "[9/12] Login Hooks..."
xml_open "  " "LoginHooks"

LOGIN_HOOK=$(defaults read com.apple.loginwindow LoginHook 2>/dev/null || echo "none")
LOGOUT_HOOK=$(defaults read com.apple.loginwindow LogoutHook 2>/dev/null || echo "none")
xml_elem "    " "LoginHook" "$LOGIN_HOOK"
xml_elem "    " "LogoutHook" "$LOGOUT_HOOK"

if [ "$LOGIN_HOOK" != "none" ]; then
    add_finding "HIGH" "LoginHooks" \
        "LoginHook set — runs as root at user login: ${LOGIN_HOOK}" ""
fi
if [ "$LOGOUT_HOOK" != "none" ]; then
    add_finding "HIGH" "LoginHooks" \
        "LogoutHook set — runs at user logout: ${LOGOUT_HOOK}" ""
fi

xml_close "  " "LoginHooks"

# ==================================================================
# 10. KERNEL EXTENSIONS
# ==================================================================
echo "[10/12] Kernel Extensions..."
xml_open "  " "KernelExtensions"

THIRD_PARTY_KEXTS=$(kextstat 2>/dev/null | grep -v "com.apple" | tail -n +2 || true)
xml_elem "    " "ThirdPartyKexts" "${THIRD_PARTY_KEXTS:-none}"

KEXT_COUNT=$(echo "$THIRD_PARTY_KEXTS" | grep -c "." 2>/dev/null || echo 0)
[ "$KEXT_COUNT" -gt 0 ] && add_finding "MEDIUM" "KernelExtensions" \
    "${KEXT_COUNT} third-party kext(s) loaded — review for malicious modules" \
    "$THIRD_PARTY_KEXTS"

xml_close "  " "KernelExtensions"

# ==================================================================
# 11. STARTUP ITEMS (LEGACY)
# ==================================================================
echo "[11/12] Legacy StartupItems..."
xml_open "  " "StartupItems"

if [ -d /Library/StartupItems ] && [ "$(ls -A /Library/StartupItems 2>/dev/null)" ]; then
    ITEMS=$(ls /Library/StartupItems 2>/dev/null)
    xml_elem "    " "StartupItemsList" "$ITEMS"
    add_finding "HIGH" "StartupItems" \
        "Legacy /Library/StartupItems present — deprecated but still executes at boot: ${ITEMS}" ""
fi

xml_close "  " "StartupItems"

# ==================================================================
# 12. XPC SERVICES
# ==================================================================
echo "[12/12] XPC Services..."
xml_open "  " "XPCServices"

# User-writable XPC service bundles could be hijacked
while IFS= read -r -d '' xpc; do
    if [ -w "$(dirname "$xpc")" ]; then
        add_finding "HIGH" "XPCServices" \
            "XPC service bundle in writable directory: ${xpc}" ""
        xml_open "    " "WritableXPC"
        xml_elem "      " "Path" "$xpc"
        xml_close "    " "WritableXPC"
    fi
done < <(find /Library /Applications -name "*.xpc" -maxdepth 8 -print0 2>/dev/null | head -z -n 50)

xml_close "  " "XPCServices"

# ==================================================================
# FINDINGS SUMMARY
# ==================================================================
{   printf '  <Findings total="%s">\n' "$FINDING_COUNT"
    for risk in CRITICAL HIGH MEDIUM INFO; do
        grep -A4 "risk=\"${risk}\"" "$FINDINGS_TMP" 2>/dev/null || true
    done
    printf '  </Findings>\n</PersistenceSurveyReport>\n'; } >> "$OUTFILE"

rm -f "$FINDINGS_TMP"
echo ""
echo " ===================================================="
echo "  PersistenceSurvey-macOS complete."
echo "  Findings : ${FINDING_COUNT} | Output: ${OUTFILE}"
echo " ===================================================="
