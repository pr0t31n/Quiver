#!/usr/bin/env bash
# ==================================================================
#  SysAudit_macos.sh
#  Description : System Configuration Audit Tool — macOS
#  Author      : [Operator]
#  Compatible  : macOS 10.13 High Sierra and later
#  Requires    : Root / sudo privileges for full data collection
#  Output      : ~/Desktop/SysAudit/SystemAudit_<HOST>_<TIMESTAMP>.xml
#
#  Sections:
#    1. OperatingSystem   - sw_vers, kernel, uptime, hostname
#    2. Hardware          - system_profiler: CPU, RAM, disks, network
#    3. InstalledUpdates  - softwareupdate history, pending updates
#    4. Security          - FileVault, Gatekeeper, SIP, App Firewall,
#                           XProtect, MDM profiles, TCC, pf rules
#    5. SecurityPolicy    - MDM profiles, sudoers, password policy,
#                           PAM configuration
#    6. LocalUsers        - dscl user/group enumeration, last logins
#    7. InstalledSoftware - .app bundles (/Applications, ~/Applications,
#                           /System/Applications), pkgutil receipts,
#                           Homebrew formulae + casks, Mac App Store
# ==================================================================

set -euo pipefail

# ==================================================================
# PRIVILEGE CHECK
# ==================================================================
if [[ $EUID -ne 0 ]]; then
    echo "[WARN] Not running as root. Some data may be incomplete."
    echo "       Re-run with: sudo $0"
    # Continue anyway — many macOS tools work without root
fi

# ==================================================================
# PATHS AND TIMESTAMP
# ==================================================================
AUDIT_DIR="${HOME}/Desktop/SysAudit"
mkdir -p "$AUDIT_DIR"

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
XMLTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(scutil --get ComputerName 2>/dev/null || hostname)
OUTFILE="${AUDIT_DIR}/SystemAudit_${HOSTNAME_VAL// /_}_${TIMESTAMP}.xml"

# macOS bash ships as 3.2; check for adequate version
BASH_MAJOR="${BASH_VERSINFO[0]:-0}"
if [[ "$BASH_MAJOR" -lt 3 ]]; then
    echo "[ERROR] bash 3.0+ required." >&2; exit 1
fi

echo ""
echo " ===================================================="
echo "  SysAudit_macos.sh - macOS System Audit"
echo " ===================================================="
echo "  Computer  : ${HOSTNAME_VAL}"
echo "  Timestamp : ${XMLTS}"
echo "  Output    : ${OUTFILE}"
echo " ===================================================="
echo ""

# ==================================================================
# XML HELPER FUNCTIONS
# ==================================================================

xml_safe() {
    local s="$*"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    printf '%s' "$s"
}

xml_elem() {
    local indent="$1" tag="$2"
    local val; val="$(xml_safe "$3")"
    printf '%s<%s>%s</%s>\n' "$indent" "$tag" "$val" "$tag" >> "$OUTFILE"
}

xml_open()  { printf '%s<%s>\n'  "$1" "$2" >> "$OUTFILE"; }
xml_close() { printf '%s</%s>\n' "$1" "$2" >> "$OUTFILE"; }

xml_open_attr() {
    local indent="$1" tag="$2" attr="$3"
    local aval; aval="$(xml_safe "$4")"
    printf '%s<%s %s="%s">\n' "$indent" "$tag" "$attr" "$aval" >> "$OUTFILE"
}

xml_cdata() {
    local indent="$1" tag="$2"
    printf '%s<%s><![CDATA[\n' "$indent" "$tag" >> "$OUTFILE"
    cat >> "$OUTFILE"
    printf '\n%s]]></%s>\n' "$indent" "$tag" >> "$OUTFILE"
}

# Read a key from an app's Info.plist using PlistBuddy
plist_read() {
    local plist="$1" key="$2"
    /usr/libexec/PlistBuddy -c "Print $key" "$plist" 2>/dev/null || true
}

# ==================================================================
# WRITE XML HEADER AND ROOT ELEMENT
# ==================================================================
{
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<SystemAudit\n'
    printf '    Hostname="%s"\n'    "$(xml_safe "$HOSTNAME_VAL")"
    printf '    GeneratedAt="%s"\n' "$XMLTS"
    printf '    AuditTool="SysAudit_macos.sh">\n\n'
} > "$OUTFILE"

# ==================================================================
# SECTION 1 — OPERATING SYSTEM
# ==================================================================
echo "[1/7] Collecting OS information..."
xml_open "  " "OperatingSystem"

xml_elem "    " "ProductName"    "$(sw_vers -productName    2>/dev/null)"
xml_elem "    " "ProductVersion" "$(sw_vers -productVersion 2>/dev/null)"
xml_elem "    " "BuildVersion"   "$(sw_vers -buildVersion   2>/dev/null)"
xml_elem "    " "Kernel"         "$(uname -r)"
xml_elem "    " "KernelFull"     "$(uname -a)"
xml_elem "    " "Architecture"   "$(uname -m)"
xml_elem "    " "ComputerName"   "$HOSTNAME_VAL"
xml_elem "    " "LocalHostname"  "$(scutil --get LocalHostname 2>/dev/null || hostname)"
xml_elem "    " "Uptime"         "$(uptime)"
xml_elem "    " "Timezone"       "$(sudo systemsetup -gettimezone 2>/dev/null | awk -F': ' '{print $2}' || date +%Z)"
xml_elem "    " "LastReboot"     "$(sysctl -n kern.boottime 2>/dev/null | awk '{print $4,$5,$6,$7,$8,$9}' | tr -d ',')"

# System Integrity Protection status
xml_elem "    " "SIPStatus" "$(csrutil status 2>/dev/null | sed 's/System Integrity Protection status: //')"

xml_close "  " "OperatingSystem"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 2 — HARDWARE
# ==================================================================
echo "[2/7] Collecting hardware information..."
xml_open "  " "Hardware"

# Core hardware via sysctl
xml_open "    " "CPU"
xml_elem "      " "Brand"        "$(sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model 2>/dev/null)"
xml_elem "      " "PhysicalCores" "$(sysctl -n hw.physicalcpu 2>/dev/null)"
xml_elem "      " "LogicalCores" "$(sysctl -n hw.logicalcpu 2>/dev/null)"
xml_elem "      " "FrequencyHz"  "$(sysctl -n hw.cpufrequency 2>/dev/null || echo 'N/A')"
xml_close "    " "CPU"

xml_open "    " "Memory"
mem_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
mem_gb=$(echo "scale=1; $mem_bytes / 1073741824" | bc 2>/dev/null || echo "N/A")
xml_elem "      " "TotalBytes" "$mem_bytes"
xml_elem "      " "TotalGB"    "$mem_gb"
xml_elem "      " "PageSize"   "$(sysctl -n hw.pagesize 2>/dev/null)"
xml_close "    " "Memory"

# Hardware model
xml_elem "    " "Model"         "$(sysctl -n hw.model 2>/dev/null)"
xml_elem "    " "SerialNumber"  "$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Serial Number/ {print $NF}')"
xml_elem "    " "BoardID"       "$(system_profiler SPHardwareDataType 2>/dev/null | awk '/Board ID/ {print $NF}')"

# Storage
xml_open "    " "Storage"
diskutil list 2>/dev/null | xml_cdata "      " "DiskutilList"
df -h 2>/dev/null         | xml_cdata "      " "DiskUsage"
xml_close "    " "Storage"

# Network
xml_open "    " "Network"
ifconfig 2>/dev/null              | xml_cdata "      " "Ifconfig"
netstat -rn 2>/dev/null           | xml_cdata "      " "RoutingTable"
networksetup -listallhardwareports 2>/dev/null | xml_cdata "      " "HardwarePorts"
xml_elem "      " "DNSServers" \
    "$(networksetup -getdnsservers Wi-Fi 2>/dev/null | tr '\n' ' ' || \
       networksetup -getdnsservers Ethernet 2>/dev/null | tr '\n' ' ')"
xml_close "    " "Network"

xml_close "  " "Hardware"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 3 — INSTALLED UPDATES
# ==================================================================
echo "[3/7] Collecting update information..."
xml_open "  " "InstalledUpdates"

# Pending updates
xml_open "    " "AvailableUpdates"
softwareupdate -l 2>&1 | xml_cdata "      " "SoftwareUpdateList"
xml_close "    " "AvailableUpdates"

# Update history
xml_open "    " "UpdateHistory"
if [[ -f /Library/Receipts/InstallHistory.plist ]]; then
    # Last 50 entries from install history plist
    /usr/libexec/PlistBuddy -c "Print" /Library/Receipts/InstallHistory.plist \
        2>/dev/null | tail -200 | xml_cdata "      " "InstallHistoryPlist"
fi
system_profiler SPInstallHistoryDataType 2>/dev/null | tail -200 \
    | xml_cdata "      " "SystemProfilerHistory"
xml_close "    " "UpdateHistory"

xml_close "  " "InstalledUpdates"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 4 — SECURITY
# ==================================================================
echo "[4/7] Collecting security status..."
xml_open "  " "Security"

# FileVault (full-disk encryption)
xml_open "    " "FileVault"
xml_elem "      " "Status" "$(fdesetup status 2>/dev/null)"
xml_close "    " "FileVault"

# Gatekeeper
xml_open "    " "Gatekeeper"
xml_elem "      " "Status" "$(spctl --status 2>/dev/null)"
xml_close "    " "Gatekeeper"

# System Integrity Protection
xml_open "    " "SIP"
xml_elem "      " "Status" "$(csrutil status 2>/dev/null)"
xml_close "    " "SIP"

# macOS Application Firewall (socketfilterfw)
xml_open "    " "ApplicationFirewall"
AFW="/usr/libexec/ApplicationFirewall/socketfilterfw"
if [[ -x "$AFW" ]]; then
    xml_elem "      " "GlobalState"      "$("$AFW" --getglobalstate 2>/dev/null)"
    xml_elem "      " "StealthMode"      "$("$AFW" --getstealthmode 2>/dev/null)"
    xml_elem "      " "BlockAllIncoming"  "$("$AFW" --getblockall 2>/dev/null)"
    "$AFW" --listapps 2>/dev/null | xml_cdata "      " "AppExceptions"
fi
xml_close "    " "ApplicationFirewall"

# pf (packet filter) — low-level firewall
xml_open "    " "PacketFilter"
xml_elem "      " "Enabled" "$(pfctl -s info 2>/dev/null | grep 'Status:' | awk '{print $2}' || echo 'N/A')"
pfctl -sr 2>/dev/null | xml_cdata "      " "Rules"
xml_close "    " "PacketFilter"

# XProtect and MRT
xml_open "    " "XProtect"
xp_plist="/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist"
mrt_app="/Library/Apple/System/Library/CoreServices/MRT.app"
if [[ -f "$xp_plist" ]]; then
    ver=$(/usr/libexec/PlistBuddy -c "Print Version" "$xp_plist" 2>/dev/null)
    xml_elem "      " "Version" "$ver"
fi
[[ -d "$mrt_app" ]] && xml_elem "      " "MRTPresent" "true" || xml_elem "      " "MRTPresent" "false"
xml_close "    " "XProtect"

# Transparency, Consent, and Control (TCC) — privacy permissions DB
xml_open "    " "TCC"
tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
if [[ -f "$tcc_db" ]] && command -v sqlite3 &>/dev/null; then
    sqlite3 "$tcc_db" "SELECT client, service, auth_value FROM access ORDER BY service, client;" \
        2>/dev/null | head -100 | xml_cdata "      " "TCCAccess"
else
    xml_elem "      " "Note" "TCC.db requires full-disk-access permission to read."
fi
xml_close "    " "TCC"

# SSH configuration
xml_open "    " "SSH"
if [[ -f /etc/ssh/sshd_config ]]; then
    xml_elem "      " "PermitRootLogin"         "$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "PasswordAuthentication"   "$(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "ChallengeResponseAuth"    "$(grep -i '^ChallengeResponseAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
fi
xml_close "    " "SSH"

xml_close "  " "Security"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 5 — SECURITY POLICY
# (MDM profiles, sudoers, password policies, PAM)
# ==================================================================
echo "[5/7] Collecting security policy..."
xml_open "  " "SecurityPolicy"

# MDM / Configuration Profiles
xml_open "    " "MDMProfiles"
xml_elem "      " "Note" "Lists installed configuration profiles (MDM-managed settings)"
profiles list 2>/dev/null | xml_cdata "      " "ProfileList"
profiles show 2>/dev/null | xml_cdata "      " "ProfileDetail"
xml_close "    " "MDMProfiles"

# Password policy
xml_open "    " "PasswordPolicy"
pwpolicy -getaccountpolicies 2>/dev/null | xml_cdata "      " "AccountPolicies"
# systemsetup password policy (require password after sleep)
sudo systemsetup -getdisablesleep 2>/dev/null | xml_cdata "      " "DisableSleep"
sudo systemsetup -getrequirerestart 2>/dev/null | xml_cdata "      " "RequireRestart"
xml_close "    " "PasswordPolicy"

# Sudoers
xml_open "    " "Sudoers"
grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^[[:space:]]*$' \
    | xml_cdata "      " "sudoers"
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        fname=$(basename "$f")
        grep -v '^#' "$f" 2>/dev/null | grep -v '^[[:space:]]*$' \
            | xml_cdata "      " "sudoers_d_${fname}"
    done
fi
xml_close "    " "Sudoers"

# PAM configuration
xml_open "    " "PAM"
for pam_file in /etc/pam.d/authorization /etc/pam.d/login \
                /etc/pam.d/screensaver /etc/pam.d/sudo; do
    [[ -f "$pam_file" ]] || continue
    fname=$(basename "$pam_file")
    xml_open "      " "$fname"
    grep -v '^#' "$pam_file" 2>/dev/null | grep -v '^[[:space:]]*$' \
        | xml_cdata "        " "Content"
    xml_close "      " "$fname"
done
xml_close "    " "PAM"

xml_close "  " "SecurityPolicy"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 6 — LOCAL USERS
# ==================================================================
echo "[6/7] Enumerating local users..."
xml_open "  " "LocalUsers"

# dscl user enumeration
xml_open "    " "Accounts"
while IFS= read -r uname; do
    [[ -z "$uname" ]] && continue
    # Skip system accounts (UID < 500 on macOS)
    uid=$(dscl . -read "/Users/$uname" UniqueID 2>/dev/null | awk '{print $2}')
    xml_open "      " "User"
    xml_elem "        " "Username"   "$uname"
    xml_elem "        " "UID"        "$uid"
    xml_elem "        " "RealName"   "$(dscl . -read "/Users/$uname" RealName 2>/dev/null | tail -1 | xargs)"
    xml_elem "        " "Shell"      "$(dscl . -read "/Users/$uname" UserShell 2>/dev/null | awk '{print $2}')"
    xml_elem "        " "HomeDir"    "$(dscl . -read "/Users/$uname" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
    xml_close "      " "User"
done < <(dscl . list /Users 2>/dev/null | grep -v '^_')
xml_close "    " "Accounts"

# Admin group membership
xml_open "    " "AdminGroup"
dscl . -read /Groups/admin GroupMembership 2>/dev/null \
    | xml_cdata "      " "Members"
xml_close "    " "AdminGroup"

# Local groups
xml_open "    " "Groups"
dscl . list /Groups 2>/dev/null | grep -v '^_' | head -50 \
    | xml_cdata "      " "GroupList"
xml_close "    " "Groups"

last -n 50 2>/dev/null | xml_cdata "    " "RecentLogins"
who 2>/dev/null        | xml_cdata "    " "CurrentlyLoggedIn"

xml_close "  " "LocalUsers"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 7 — INSTALLED SOFTWARE
#
# Sources:
#   Applications     : .app bundles in /Applications, ~/Applications,
#                      /System/Applications, /System/Library/CoreServices
#                      Each entry reads CFBundleName, CFBundleShortVersionString,
#                      CFBundleIdentifier from Info.plist via PlistBuddy.
#
#   SystemPackages   : pkgutil --pkgs (macOS installer package receipts)
#                      Lists all packages ever installed via .pkg/.mpkg.
#
#   HomebrewFormulae : brew list --versions (if Homebrew is installed)
#   HomebrewCasks    : brew list --cask --versions (GUI apps via Homebrew)
#
#   MasApps          : mas list (Mac App Store; requires 'mas' CLI tool)
#
# Note on .app enumeration: PlistBuddy is called 3 times per app.
# On systems with 200+ apps this section runs for ~30-60 seconds.
# ==================================================================
echo "[7/7] Enumerating installed software..."
echo "      (app bundle scan may take 30-60 seconds)"

# Count total apps for the attribute
app_dirs=("/Applications" "/System/Applications" "$HOME/Applications")
app_count=0
for d in "${app_dirs[@]}"; do
    [[ -d "$d" ]] && app_count=$(( app_count + $(find "$d" -maxdepth 1 -name "*.app" -type d 2>/dev/null | wc -l | tr -d '[:space:]') ))
done

xml_open_attr "  " "InstalledSoftware" "appBundleCount" "$app_count"

# --- Application bundles ---
xml_open "    " "Applications"

for search_dir in "/Applications" "/System/Applications" \
                  "/System/Library/CoreServices" "$HOME/Applications"; do
    [[ -d "$search_dir" ]] || continue
    src_label=$(basename "$search_dir")

    for app in "$search_dir"/*.app; do
        [[ -d "$app" ]] || continue
        plist="$app/Contents/Info.plist"
        [[ -f "$plist" ]] || continue

        name=$(plist_read "$plist" "CFBundleName")
        [[ -z "$name" ]] && name=$(basename "$app" .app)

        version=$(plist_read "$plist" "CFBundleShortVersionString")
        [[ -z "$version" ]] && version=$(plist_read "$plist" "CFBundleVersion")

        bundle_id=$(plist_read "$plist" "CFBundleIdentifier")
        min_os=$(plist_read "$plist" "LSMinimumSystemVersion")

        xml_open "      " "Application"
        xml_elem "        " "Name"           "$name"
        xml_elem "        " "Version"        "${version:-N/A}"
        xml_elem "        " "BundleID"       "${bundle_id:-}"
        xml_elem "        " "MinOSVersion"   "${min_os:-}"
        xml_elem "        " "Path"           "$app"
        xml_elem "        " "Source"         "$src_label"
        xml_close "      " "Application"
    done
done

xml_close "    " "Applications"

# --- macOS installer package receipts (pkgutil) ---
xml_open "    " "SystemPackages"
xml_elem "      " "Note" "Package receipts from macOS installer (.pkg/.mpkg). Version may show 0.0 for metapackages."

while IFS= read -r pkg; do
    [[ -z "$pkg" ]] && continue
    pkg_info=$(pkgutil --pkg-info "$pkg" 2>/dev/null)
    ver=$(printf '%s' "$pkg_info" | awk '/version:/{print $2}')
    idate=$(printf '%s' "$pkg_info" | awk '/install-time:/{print $2}')
    loc=$(printf '%s' "$pkg_info" | awk '/volume:/{print $2}')

    xml_open "      " "Package"
    xml_elem "        " "PackageID"   "$pkg"
    xml_elem "        " "Version"     "${ver:-N/A}"
    xml_elem "        " "InstallTime" "${idate:-}"
    xml_elem "        " "Volume"      "${loc:-}"
    xml_close "      " "Package"
done < <(pkgutil --pkgs 2>/dev/null | sort)

xml_close "    " "SystemPackages"

# --- Homebrew formulae ---
if command -v brew &>/dev/null; then
    echo "      Scanning Homebrew formulae..."
    xml_open "    " "HomebrewFormulae"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(awk '{print $1}' <<< "$line")
        ver=$(awk '{$1=""; print $0}' <<< "$line" | xargs)
        xml_open "      " "Formula"
        xml_elem "        " "Name"    "$pkg"
        xml_elem "        " "Version" "$ver"
        xml_close "      " "Formula"
    done < <(brew list --versions 2>/dev/null)
    xml_close "    " "HomebrewFormulae"

    echo "      Scanning Homebrew casks (GUI apps)..."
    xml_open "    " "HomebrewCasks"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(awk '{print $1}' <<< "$line")
        ver=$(awk '{$1=""; print $0}' <<< "$line" | xargs)
        xml_open "      " "Cask"
        xml_elem "        " "Name"    "$pkg"
        xml_elem "        " "Version" "$ver"
        xml_close "      " "Cask"
    done < <(brew list --cask --versions 2>/dev/null)
    xml_close "    " "HomebrewCasks"
fi

# --- Mac App Store apps (requires 'mas' CLI: brew install mas) ---
if command -v mas &>/dev/null; then
    xml_open "    " "MacAppStore"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        app_id=$(awk '{print $1}' <<< "$line")
        app_name=$(awk '{$1=""; NF--; print $0}' <<< "$line" | xargs)
        app_ver=$(awk '{print $NF}' <<< "$line" | tr -d '()')
        xml_open "      " "App"
        xml_elem "        " "AppStoreID" "$app_id"
        xml_elem "        " "Name"       "$app_name"
        xml_elem "        " "Version"    "$app_ver"
        xml_close "      " "App"
    done < <(mas list 2>/dev/null)
    xml_close "    " "MacAppStore"
fi

# --- Python pip (system or user) ---
for pip_cmd in pip3 pip; do
    command -v "$pip_cmd" &>/dev/null || continue
    xml_open "    " "PipPackages"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(awk '{print $1}' <<< "$line")
        ver=$(awk '{print $2}' <<< "$line")
        xml_open "      " "Package"
        xml_elem "        " "Name"    "$pkg"
        xml_elem "        " "Version" "$ver"
        xml_close "      " "Package"
    done < <("$pip_cmd" list --format=columns 2>/dev/null | tail -n +3)
    xml_close "    " "PipPackages"
    break   # only need one pip variant
done

xml_close "  " "InstalledSoftware"
printf '\n' >> "$OUTFILE"

# ==================================================================
# CLOSE ROOT ELEMENT
# ==================================================================
printf '</SystemAudit>\n' >> "$OUTFILE"

if command -v xmllint &>/dev/null; then
    if xmllint --noout "$OUTFILE" 2>/dev/null; then
        echo "  [OK] XML validated by xmllint."
    else
        echo "  [WARN] xmllint reports the XML may not be well-formed."
    fi
fi

# ==================================================================
# SUMMARY
# ==================================================================
echo ""
echo " ===================================================="
echo "  Audit Complete"
echo " ===================================================="
echo ""
echo "  Report    : ${OUTFILE}"
echo "  App count : ${app_count} (.app bundles)"
echo ""
[[ -f "$OUTFILE" ]] && echo "  [OK] Audit XML written." \
                     || echo "  [ERR] Output file missing."
echo ""
echo "  Files saved to: ${AUDIT_DIR}"
echo ""
