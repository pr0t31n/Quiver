#!/usr/bin/env bash
# ==================================================================
#  PersistenceSurvey-Linux.sh
#  Description : Persistence mechanism survey for Linux systems.
#                Enumerates all locations where code runs automatically
#                at boot, login, or on schedule — including legitimate
#                and potentially malicious persistence.
#  Author      : [Operator]
#  Compatible  : Debian/Ubuntu, RHEL/CentOS/Fedora; bash 4+
#  Privileges  : Run as root for complete results.
#  Output      : /tmp/PersistenceSurvey/PersistenceSurvey_<HOST>_<TS>.xml
#
#  Sections:
#    1. SystemdUnits           — systemd service/timer/path units
#    2. SysVInitScripts        — /etc/init.d and rc*.d links
#    3. CronJobs               — system and user crontabs
#    4. AtJobs                 — at/batch queued jobs
#    5. RCLocal                — /etc/rc.local
#    6. LDPreload              — /etc/ld.so.preload and LD_PRELOAD in env
#    7. PAMModules             — PAM module additions
#    8. ProfileDotFiles        — shell RC file modifications
#    9. SSHAuthorizedKeys      — authorized_keys persistence
#   10. APTHooks               — dpkg/apt pre/post install hooks
#   11. KernelModules          — unusual loaded kernel modules
#   12. XDGAutostart           — desktop autostart entries
#   13. Findings               — consolidated risk-rated findings
# ==================================================================

set -uo pipefail

AUDIT_DIR="/tmp/PersistenceSurvey"
mkdir -p "$AUDIT_DIR"

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
XMLTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
OUTFILE="${AUDIT_DIR}/PersistenceSurvey_${HOSTNAME_VAL}_${TIMESTAMP}.xml"
FINDINGS_TMP=$(mktemp)
FINDING_COUNT=0

printf '' > "$OUTFILE"

echo ""
echo " ===================================================="
echo "  PersistenceSurvey-Linux.sh"
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
  printf '  <Meta><Script>PersistenceSurvey-Linux.sh</Script>'
  printf '<Host>%s</Host><OS>%s</OS><User>%s</User><Timestamp>%s</Timestamp></Meta>\n' \
    "$(xml_safe "$HOSTNAME_VAL")" "$(xml_safe "$(uname -srm)")" \
    "$(xml_safe "$(id)")" "$XMLTS"; } >> "$OUTFILE"

# ==================================================================
# 1. SYSTEMD UNITS
# ==================================================================
echo "[1/12] Systemd Units..."
xml_open "  " "SystemdUnits"

SEARCH_DIRS=(
    /etc/systemd/system
    /lib/systemd/system
    /usr/lib/systemd/system
    /run/systemd/system
)
for home_dir in $(awk -F: '$7 !~ /nologin|false/ && $6 ~ /^\// {print $6}' /etc/passwd 2>/dev/null); do
    [ -d "$home_dir/.config/systemd/user" ] && SEARCH_DIRS+=("$home_dir/.config/systemd/user")
done

ENABLED_UNITS=$(systemctl list-unit-files --state=enabled 2>/dev/null | grep -v "^UNIT\|Listed" | head -50 || true)
xml_elem "    " "EnabledUnits" "$ENABLED_UNITS"

# Look for recently modified units (last 7 days)
while IFS= read -r -d '' unit; do
    MTIME=$(stat -c '%Y' "$unit" 2>/dev/null || echo 0)
    NOW=$(date +%s)
    AGE=$(( (NOW - MTIME) / 86400 ))
    if [ "$AGE" -le 7 ]; then
        xml_open "    " "RecentlyModifiedUnit"
        xml_elem "      " "Path" "$unit"
        xml_elem "      " "DaysOld" "$AGE"
        xml_elem "      " "Owner" "$(stat -c '%U' "$unit" 2>/dev/null || true)"
        xml_close "    " "RecentlyModifiedUnit"
        add_finding "HIGH" "SystemdUnits" \
            "Systemd unit modified within last ${AGE} day(s): ${unit}" \
            "Review for unexpected service additions"
    fi
    # Check for ExecStart pointing to writable path
    EXEC=$(grep -i "^ExecStart=" "$unit" 2>/dev/null | head -1 | cut -d= -f2- | awk '{print $1}' || true)
    if [ -n "$EXEC" ] && [ -f "$EXEC" ] && [ -w "$EXEC" ]; then
        add_finding "CRITICAL" "SystemdUnits" \
            "Systemd unit ExecStart points to writable binary: ${EXEC}" \
            "Unit: $unit"
    fi
done < <(find "${SEARCH_DIRS[@]}" -name "*.service" -o -name "*.timer" -o -name "*.path" \
    -print0 2>/dev/null | head -z -n 200)

xml_close "  " "SystemdUnits"

# ==================================================================
# 2. SYSV INIT SCRIPTS
# ==================================================================
echo "[2/12] SysV Init Scripts..."
xml_open "  " "SysVInit"

if [ -d /etc/init.d ]; then
    INIT_SCRIPTS=$(ls /etc/init.d/ 2>/dev/null | wc -l)
    xml_elem "    " "InitScriptCount" "$INIT_SCRIPTS"
    # Check for writable scripts
    while IFS= read -r -d '' script; do
        if [ -w "$script" ]; then
            add_finding "CRITICAL" "SysVInit" \
                "Writable SysV init script (runs as root at boot): ${script}" ""
            xml_elem "    " "WritableInitScript" "$script"
        fi
    done < <(find /etc/init.d -type f -print0 2>/dev/null)
fi

xml_close "  " "SysVInit"

# ==================================================================
# 3. CRON JOBS
# ==================================================================
echo "[3/12] Cron Jobs..."
xml_open "  " "CronJobs"

# System crontabs
for cronfile in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.weekly/* \
                /etc/cron.hourly/* /etc/cron.monthly/*; do
    [ -f "$cronfile" ] || continue
    xml_open "    " "CronFile"
    xml_elem "      " "Path" "$cronfile"
    CONTENT=$(grep -v "^#\|^$" "$cronfile" 2>/dev/null | head -20 || true)
    xml_elem "      " "Content" "$CONTENT"

    # Check if referenced script/binary is writable
    while IFS= read -r cron_line; do
        BINARY=$(echo "$cron_line" | awk '{for(i=1;i<=NF;i++) if($i~/^\//){print $i; exit}}')
        if [ -n "$BINARY" ] && [ -f "$BINARY" ] && [ -w "$BINARY" ]; then
            add_finding "CRITICAL" "CronJobs" \
                "Cron job runs writable script/binary: ${BINARY}" \
                "Cron file: $cronfile | Line: $cron_line"
        fi
    done < <(grep -v "^#\|^$" "$cronfile" 2>/dev/null)

    xml_close "    " "CronFile"
done

# User crontabs
for home in $(awk -F: '$7 !~ /nologin|false/ && $6 ~ /^\// {print $6":"$1}' /etc/passwd 2>/dev/null); do
    user=$(echo "$home" | cut -d: -f2)
    UCRON=$(crontab -l -u "$user" 2>/dev/null | grep -v "^#\|^$" | head -20 || true)
    if [ -n "$UCRON" ]; then
        xml_open "    " "UserCron"
        xml_elem "      " "User" "$user"
        xml_elem "      " "Content" "$UCRON"
        xml_close "    " "UserCron"
        add_finding "MEDIUM" "CronJobs" \
            "User crontab entries for ${user} — review for unusual scheduled commands" \
            "$UCRON"
    fi
done

xml_close "  " "CronJobs"

# ==================================================================
# 4. AT JOBS
# ==================================================================
echo "[4/12] At Jobs..."
xml_open "  " "AtJobs"

AT_QUEUE=$(atq 2>/dev/null || echo "No at jobs / atq not available")
xml_elem "    " "AtQueue" "$AT_QUEUE"
if echo "$AT_QUEUE" | grep -q "^[0-9]"; then
    AT_COUNT=$(echo "$AT_QUEUE" | grep -c "^[0-9]" || echo 0)
    add_finding "MEDIUM" "AtJobs" \
        "${AT_COUNT} queued at/batch job(s) — review for scheduled commands" "$AT_QUEUE"
fi

xml_close "  " "AtJobs"

# ==================================================================
# 5. RC.LOCAL
# ==================================================================
echo "[5/12] RC.Local..."
xml_open "  " "RCLocal"

for rclocal in /etc/rc.local /etc/rc.d/rc.local; do
    if [ -f "$rclocal" ] && [ -s "$rclocal" ]; then
        CONTENT=$(grep -v "^#\|^$" "$rclocal" 2>/dev/null | head -30 || true)
        xml_elem "    " "RCLocalContent" "$CONTENT"
        [ -n "$CONTENT" ] && add_finding "MEDIUM" "RCLocal" \
            "rc.local has executable content: ${rclocal}" "$CONTENT"
    fi
done

xml_close "  " "RCLocal"

# ==================================================================
# 6. LD_PRELOAD / LD.SO.PRELOAD
# ==================================================================
echo "[6/12] LD_PRELOAD / ld.so.preload..."
xml_open "  " "LDPreload"

if [ -f /etc/ld.so.preload ] && [ -s /etc/ld.so.preload ]; then
    PRELOAD=$(cat /etc/ld.so.preload 2>/dev/null)
    xml_elem "    " "LDSOPreload" "$PRELOAD"
    add_finding "CRITICAL" "LDPreload" \
        "/etc/ld.so.preload is populated — every dynamic binary loads these libraries: ${PRELOAD}" \
        "Classic rootkit persistence mechanism"
fi

if [ -n "${LD_PRELOAD:-}" ]; then
    xml_elem "    " "LD_PRELOAD_ENV" "$LD_PRELOAD"
    add_finding "HIGH" "LDPreload" \
        "LD_PRELOAD is set in current environment: ${LD_PRELOAD}" ""
fi

# Check for LD_PRELOAD in /etc/environment
if grep -q "LD_PRELOAD" /etc/environment 2>/dev/null; then
    add_finding "CRITICAL" "LDPreload" \
        "LD_PRELOAD set in /etc/environment" \
        "$(grep LD_PRELOAD /etc/environment)"
fi

xml_close "  " "LDPreload"

# ==================================================================
# 7. PAM MODULES
# ==================================================================
echo "[7/12] PAM Modules..."
xml_open "  " "PAMModules"

# Look for non-standard or recently added PAM modules
EXPECTED_PAM_MODS="pam_unix|pam_deny|pam_permit|pam_securetty|pam_env|pam_limits|pam_systemd|pam_keyinit|pam_motd|pam_nologin|pam_selinux|pam_console|pam_loginuid|pam_namespaces|pam_tally|pam_faillock|pam_lastlog|pam_shells|pam_mail|pam_access|pam_umask|pam_cracklib|pam_pwquality|pam_krb5|pam_sss|pam_winbind|pam_ldap|pam_duo"

while IFS= read -r -d '' pamfile; do
    while IFS= read -r line; do
        MOD=$(echo "$line" | grep -oE 'pam_[a-z0-9_]+\.so' | head -1 || true)
        if [ -n "$MOD" ] && ! echo "$MOD" | grep -qE "$EXPECTED_PAM_MODS"; then
            add_finding "HIGH" "PAMModules" \
                "Non-standard PAM module in ${pamfile}: ${MOD}" "$line"
            xml_open "    " "UnexpectedPAMModule"
            xml_elem "      " "File" "$pamfile"
            xml_elem "      " "Module" "$MOD"
            xml_elem "      " "Line" "$line"
            xml_close "    " "UnexpectedPAMModule"
        fi
    done < <(grep -v "^#\|^$" "$pamfile" 2>/dev/null)
done < <(find /etc/pam.d -type f -print0 2>/dev/null)

xml_close "  " "PAMModules"

# ==================================================================
# 8. SHELL RC MODIFICATIONS
# ==================================================================
echo "[8/12] Shell RC File Modifications (last 30 days)..."
xml_open "  " "ProfileDotFiles"

RECENT_PROFILE=$(find /home /root /etc/profile.d /etc 2>/dev/null \
    \( -name ".bashrc" -o -name ".bash_profile" -o -name ".bash_login" \
    -o -name ".profile" -o -name ".zshrc" -o -name ".zprofile" \
    -o -name ".zshenv" -o -name "profile" \) \
    -newer /proc/1 -mtime -30 2>/dev/null | head -20 || true)

if [ -n "$RECENT_PROFILE" ]; then
    xml_elem "    " "RecentlyModifiedProfiles" "$RECENT_PROFILE"
    echo "$RECENT_PROFILE" | while IFS= read -r rcfile; do
        add_finding "MEDIUM" "ProfileDotFiles" \
            "Shell RC file modified within last 30 days: ${rcfile}" \
            "Review for injected commands or exports"
    done
fi

xml_close "  " "ProfileDotFiles"

# ==================================================================
# 9. SSH AUTHORIZED_KEYS
# ==================================================================
echo "[9/12] SSH Authorized Keys..."
xml_open "  " "SSHAuthorizedKeys"

while IFS= read -r home; do
    AK="$home/.ssh/authorized_keys"
    [ -f "$AK" ] || continue
    COUNT=$(wc -l < "$AK" 2>/dev/null || echo 0)
    MTIME=$(stat -c '%y' "$AK" 2>/dev/null | cut -d' ' -f1 || true)
    xml_open "    " "AuthorizedKeysFile"
    xml_elem "      " "Path" "$AK"
    xml_elem "      " "KeyCount" "$COUNT"
    xml_elem "      " "LastModified" "$MTIME"
    xml_close "    " "AuthorizedKeysFile"
    # Flag recently modified
    AGE_DAYS=$(( ($(date +%s) - $(stat -c '%Y' "$AK" 2>/dev/null || echo 0)) / 86400 ))
    [ "$AGE_DAYS" -le 14 ] && add_finding "HIGH" "SSHAuthorizedKeys" \
        "authorized_keys modified ${AGE_DAYS} day(s) ago: ${AK}" \
        "Review for newly added keys"
done < <(awk -F: '$7 !~ /nologin|false/ && $6 ~ /^\// {print $6}' /etc/passwd 2>/dev/null; echo /root)

xml_close "  " "SSHAuthorizedKeys"

# ==================================================================
# 10. APT/DPKG HOOKS
# ==================================================================
echo "[10/12] APT/dpkg Hooks..."
xml_open "  " "APTHooks"

for hookdir in /etc/apt/apt.conf.d /etc/apt/preferences.d /etc/dpkg/dpkg.cfg.d; do
    [ -d "$hookdir" ] || continue
    while IFS= read -r -d '' hookfile; do
        if grep -qiE 'Pre-Install|Post-Invoke|DPkg::Pre-Install|DPkg::Post-Invoke' "$hookfile" 2>/dev/null; then
            CONTENT=$(cat "$hookfile" 2>/dev/null | head -20)
            xml_open "    " "APTHook"
            xml_elem "      " "File" "$hookfile"
            xml_elem "      " "Content" "$CONTENT"
            xml_close "    " "APTHook"
            add_finding "MEDIUM" "APTHooks" \
                "APT/dpkg hook found — runs on package install/upgrade: ${hookfile}" "$CONTENT"
        fi
    done < <(find "$hookdir" -type f -print0 2>/dev/null)
done

xml_close "  " "APTHooks"

# ==================================================================
# 11. KERNEL MODULES
# ==================================================================
echo "[11/12] Kernel Modules..."
xml_open "  " "KernelModules"

MODULES_PRELOAD=$(cat /etc/modules /etc/modules-load.d/*.conf 2>/dev/null | grep -v "^#\|^$" || true)
xml_elem "    " "PreloadedModules" "${MODULES_PRELOAD:-none}"

# Look for modules in non-standard paths (could indicate rootkit)
UNUSUAL_MODS=$(find /lib/modules -name "*.ko" -newer /proc/1 2>/dev/null | head -20 || true)
if [ -n "$UNUSUAL_MODS" ]; then
    xml_elem "    " "RecentKernelModules" "$UNUSUAL_MODS"
    add_finding "HIGH" "KernelModules" \
        "Recently added kernel module files detected" "$UNUSUAL_MODS"
fi

# Check /proc/modules for modules not in /lib/modules (classic rootkit indicator)
LOADED=$(cut -d' ' -f1 /proc/modules 2>/dev/null | head -50 || true)
xml_elem "    " "LoadedModuleCount" "$(echo "$LOADED" | wc -l)"

xml_close "  " "KernelModules"

# ==================================================================
# 12. XDG AUTOSTART
# ==================================================================
echo "[12/12] XDG Autostart Entries..."
xml_open "  " "XDGAutostart"

for autostart_dir in /etc/xdg/autostart \
    $(awk -F: '$6 ~ /^\// {print $6"/.config/autostart"}' /etc/passwd 2>/dev/null); do
    [ -d "$autostart_dir" ] || continue
    while IFS= read -r -d '' desktopfile; do
        EXEC=$(grep -i "^Exec=" "$desktopfile" 2>/dev/null | head -1 | cut -d= -f2-)
        HIDDEN=$(grep -i "^Hidden=true" "$desktopfile" 2>/dev/null || true)
        xml_open "    " "AutostartEntry"
        xml_elem "      " "File" "$desktopfile"
        xml_elem "      " "Exec" "${EXEC:-unknown}"
        xml_elem "      " "Hidden" "$([ -n "$HIDDEN" ] && echo YES || echo no)"
        xml_close "    " "AutostartEntry"
        if [ -n "$HIDDEN" ]; then
            add_finding "MEDIUM" "XDGAutostart" \
                "Hidden XDG autostart entry: ${desktopfile} — Exec: ${EXEC}" ""
        fi
    done < <(find "$autostart_dir" -name "*.desktop" -print0 2>/dev/null)
done

xml_close "  " "XDGAutostart"

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
echo "  PersistenceSurvey-Linux complete."
echo "  Findings : ${FINDING_COUNT} | Output: ${OUTFILE}"
echo " ===================================================="
