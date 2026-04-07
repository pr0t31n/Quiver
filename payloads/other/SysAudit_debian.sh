#!/usr/bin/env bash
# ==================================================================
#  SysAudit_debian.sh
#  Description : System Configuration Audit Tool — Debian/Ubuntu
#  Author      : [Operator]
#  Compatible  : Debian 8+ / Ubuntu 16.04+; requires bash 4+
#  Requires    : Root privileges (sudo or direct root)
#  Output      : /var/log/sysaudit/SystemAudit_<HOST>_<TIMESTAMP>.xml
#
#  Sections:
#    1. OperatingSystem   - OS release, kernel, hostname, uptime
#    2. Hardware          - BIOS/DMI, CPU, memory, disks, network
#    3. InstalledUpdates  - apt/dpkg history, available upgrades
#    4. Security          - UFW/iptables, AppArmor, PAM, login policy
#    5. SecurityPolicy    - sudoers, password policy, login.defs
#    6. LocalUsers        - Accounts, sudo members, last logins
#    7. InstalledSoftware - dpkg packages, snap, pip3
# ==================================================================

set -euo pipefail

# ==================================================================
# PRIVILEGE CHECK
# ==================================================================
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Root privileges required. Run with: sudo $0" >&2
    exit 1
fi

# ==================================================================
# PATHS AND TIMESTAMP
# ==================================================================
AUDIT_DIR="/var/log/sysaudit"
mkdir -p "$AUDIT_DIR"

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%S')
XMLTS=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
OUTFILE="${AUDIT_DIR}/SystemAudit_${HOSTNAME_VAL}_${TIMESTAMP}.xml"

echo ""
echo " ===================================================="
echo "  SysAudit_debian.sh - Debian/Ubuntu System Audit"
echo " ===================================================="
echo "  Host      : ${HOSTNAME_VAL}"
echo "  Timestamp : ${XMLTS}"
echo "  Output    : ${OUTFILE}"
echo " ===================================================="
echo ""

# ==================================================================
# XML HELPER FUNCTIONS
# ==================================================================

# Escape a string for safe embedding as XML text content.
# Uses bash parameter expansion — no subshell/process spawn.
xml_safe() {
    local s="$*"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    printf '%s' "$s"
}

# Write a single-value XML element: <tag>value</tag>
xml_elem() {
    local indent="$1" tag="$2"
    local val; val="$(xml_safe "$3")"
    printf '%s<%s>%s</%s>\n' "$indent" "$tag" "$val" "$tag" >> "$OUTFILE"
}

# Open a tag
xml_open() { printf '%s<%s>\n' "$1" "$2" >> "$OUTFILE"; }

# Open a tag with one attribute
xml_open_attr() {
    local indent="$1" tag="$2" attr="$3"
    local aval; aval="$(xml_safe "$4")"
    printf '%s<%s %s="%s">\n' "$indent" "$tag" "$attr" "$aval" >> "$OUTFILE"
}

# Close a tag
xml_close() { printf '%s</%s>\n' "$1" "$2" >> "$OUTFILE"; }

# Write a CDATA block; reads content from stdin.
# Usage: some_command 2>/dev/null | xml_cdata "  " "TagName"
xml_cdata() {
    local indent="$1" tag="$2"
    printf '%s<%s><![CDATA[\n' "$indent" "$tag" >> "$OUTFILE"
    cat >> "$OUTFILE"
    printf '\n%s]]></%s>\n' "$indent" "$tag" >> "$OUTFILE"
}

# ==================================================================
# WRITE XML HEADER AND ROOT ELEMENT
# ==================================================================
{
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<SystemAudit\n'
    printf '    Hostname="%s"\n' "$(xml_safe "$HOSTNAME_VAL")"
    printf '    GeneratedAt="%s"\n' "$XMLTS"
    printf '    AuditTool="SysAudit_debian.sh">\n\n'
} > "$OUTFILE"

# ==================================================================
# SECTION 1 — OPERATING SYSTEM
# ==================================================================
echo "[1/7] Collecting OS information..."
xml_open "  " "OperatingSystem"

# Key-value fields from os-release
if [[ -f /etc/os-release ]]; then
    while IFS='=' read -r key val; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        val="${val%\"}"
        val="${val#\"}"
        xml_elem "    " "$key" "$val"
    done < /etc/os-release
fi

xml_elem "    " "Kernel"       "$(uname -r)"
xml_elem "    " "KernelFull"   "$(uname -a)"
xml_elem "    " "Architecture" "$(uname -m)"
xml_elem "    " "Hostname"     "$HOSTNAME_VAL"
xml_elem "    " "Uptime"       "$(uptime)"
xml_elem "    " "Timezone"     "$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)"

if command -v hostnamectl &>/dev/null; then
    hostnamectl 2>/dev/null | xml_cdata "    " "Hostnamectl"
fi

xml_close "  " "OperatingSystem"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 2 — HARDWARE
# ==================================================================
echo "[2/7] Collecting hardware information..."
xml_open "  " "Hardware"

# DMI / BIOS (dmidecode requires root and the package installed)
if command -v dmidecode &>/dev/null; then
    xml_open "    " "BIOS"
    xml_elem "      " "Vendor"      "$(dmidecode -s bios-vendor 2>/dev/null)"
    xml_elem "      " "Version"     "$(dmidecode -s bios-version 2>/dev/null)"
    xml_elem "      " "ReleaseDate" "$(dmidecode -s bios-release-date 2>/dev/null)"
    xml_close "    " "BIOS"

    xml_open "    " "System"
    xml_elem "      " "Manufacturer" "$(dmidecode -s system-manufacturer 2>/dev/null)"
    xml_elem "      " "ProductName"  "$(dmidecode -s system-product-name 2>/dev/null)"
    xml_elem "      " "SerialNumber" "$(dmidecode -s system-serial-number 2>/dev/null)"
    xml_elem "      " "UUID"         "$(dmidecode -s system-uuid 2>/dev/null)"
    xml_close "    " "System"
else
    xml_elem "    " "BIOSNote" "dmidecode not installed; install with: apt install dmidecode"
fi

# CPU
xml_open "    " "Processors"
lscpu 2>/dev/null | xml_cdata "      " "LscpuOutput"
xml_elem "      " "PhysicalCores" "$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 'N/A')"
xml_close "    " "Processors"

# Memory
xml_open "    " "Memory"
xml_elem "      " "MemTotal"     "$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
xml_elem "      " "MemFree"      "$(grep MemFree /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
xml_elem "      " "MemAvailable" "$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
xml_elem "      " "SwapTotal"    "$(grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
if command -v dmidecode &>/dev/null; then
    dmidecode --type memory 2>/dev/null | xml_cdata "      " "PhysicalModules"
fi
xml_close "    " "Memory"

# Disks
xml_open "    " "Storage"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,VENDOR 2>/dev/null | xml_cdata "      " "BlockDevices"
df -h 2>/dev/null | xml_cdata "      " "DiskUsage"
xml_close "    " "Storage"

# Network
xml_open "    " "Network"
ip -br link show 2>/dev/null | xml_cdata "      " "Interfaces"
ip -br addr show 2>/dev/null | xml_cdata "      " "Addresses"
ip route show 2>/dev/null    | xml_cdata "      " "Routes"
xml_elem "      " "DNSResolver" "$(cat /etc/resolv.conf 2>/dev/null | grep nameserver | tr '\n' ' ')"
xml_close "    " "Network"

xml_close "  " "Hardware"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 3 — INSTALLED UPDATES
# ==================================================================
echo "[3/7] Collecting update information..."
xml_open "  " "InstalledUpdates"

# Last successful apt update timestamp
if [[ -f /var/lib/apt/periodic/update-success-stamp ]]; then
    xml_elem "    " "LastAptUpdate" \
        "$(stat -c '%y' /var/lib/apt/periodic/update-success-stamp 2>/dev/null)"
elif [[ -f /var/cache/apt/pkgcache.bin ]]; then
    xml_elem "    " "LastAptCacheRefresh" \
        "$(stat -c '%y' /var/cache/apt/pkgcache.bin 2>/dev/null)"
fi

# Recent installs and upgrades from dpkg log
if [[ -f /var/log/dpkg.log ]]; then
    xml_open "    " "RecentActivity"
    { grep " install \| upgrade " /var/log/dpkg.log 2>/dev/null | tail -100; } \
        | xml_cdata "      " "DpkgLog"
    xml_close "    " "RecentActivity"
fi

# apt history log
if [[ -f /var/log/apt/history.log ]]; then
    tail -200 /var/log/apt/history.log 2>/dev/null \
        | xml_cdata "    " "AptHistoryLog"
fi

# Packages with available upgrades
xml_open "    " "AvailableUpgrades"
apt list --upgradable 2>/dev/null | tail -n +2 \
    | xml_cdata "      " "AptUpgradable"
xml_close "    " "AvailableUpgrades"

xml_close "  " "InstalledUpdates"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 4 — SECURITY
# ==================================================================
echo "[4/7] Collecting security status..."
xml_open "  " "Security"

# UFW (Uncomplicated Firewall)
xml_open "    " "Firewall"
if command -v ufw &>/dev/null; then
    xml_elem "      " "UFWInstalled" "true"
    ufw status verbose 2>/dev/null | xml_cdata "      " "UFWStatus"
else
    xml_elem "      " "UFWInstalled" "false"
fi

# iptables rules (both IPv4 and IPv6)
iptables  -L -n -v --line-numbers 2>/dev/null | xml_cdata "      " "IPTables"
ip6tables -L -n -v --line-numbers 2>/dev/null | xml_cdata "      " "IP6Tables"
xml_close "    " "Firewall"

# AppArmor
xml_open "    " "AppArmor"
if command -v apparmor_status &>/dev/null || command -v aa-status &>/dev/null; then
    xml_elem "      " "Installed" "true"
    { apparmor_status 2>/dev/null || aa-status 2>/dev/null; } \
        | xml_cdata "      " "Status"
else
    xml_elem "      " "Installed" "false"
fi
xml_close "    " "AppArmor"

# Known AV / security tools (check if packages are installed)
xml_open "    " "SecurityTools"
for tool in clamav rkhunter chkrootkit aide fail2ban lynis auditd; do
    if dpkg -l "$tool" &>/dev/null; then
        ver=$(dpkg-query -W -f='${Version}' "$tool" 2>/dev/null)
        xml_elem "      " "$tool" "$ver"
    fi
done
xml_close "    " "SecurityTools"

# SSH config (key settings)
xml_open "    " "SSH"
if [[ -f /etc/ssh/sshd_config ]]; then
    xml_elem "      " "PermitRootLogin"       "$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "PasswordAuthentication" "$(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "PubkeyAuthentication"   "$(grep -i '^PubkeyAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "Port"                   "$(grep -i '^Port' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo '22 (default)')"
fi
xml_close "    " "SSH"

xml_close "  " "Security"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 5 — SECURITY POLICY
# (Linux equivalent of Windows Group Policy)
# ==================================================================
echo "[5/7] Collecting security policy..."
xml_open "  " "SecurityPolicy"

# Password and account policy from login.defs
xml_open "    " "LoginDefs"
grep -v '^#' /etc/login.defs 2>/dev/null | grep -v '^[[:space:]]*$' \
    | xml_cdata "      " "Settings"
xml_close "    " "LoginDefs"

# PAM configuration (common-auth, common-password)
xml_open "    " "PAM"
for pam_file in /etc/pam.d/common-auth /etc/pam.d/common-password \
                /etc/pam.d/common-account /etc/pam.d/common-session; do
    [[ -f "$pam_file" ]] || continue
    fname=$(basename "$pam_file")
    xml_open "      " "$fname"
    grep -v '^#' "$pam_file" 2>/dev/null | grep -v '^[[:space:]]*$' \
        | xml_cdata "        " "Content"
    xml_close "      " "$fname"
done
xml_close "    " "PAM"

# Sudoers
xml_open "    " "Sudoers"
cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$' \
    | xml_cdata "      " "sudoers"
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        fname=$(basename "$f")
        cat "$f" 2>/dev/null | grep -v '^#' | grep -v '^[[:space:]]*$' \
            | xml_cdata "      " "sudoers_d_${fname}"
    done
fi
xml_close "    " "Sudoers"

# Security limits
if [[ -f /etc/security/limits.conf ]]; then
    grep -v '^#' /etc/security/limits.conf 2>/dev/null | grep -v '^[[:space:]]*$' \
        | xml_cdata "    " "SecurityLimits"
fi

xml_close "  " "SecurityPolicy"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 6 — LOCAL USERS
# ==================================================================
echo "[6/7] Enumerating local users..."
xml_open "  " "LocalUsers"

# All system and human accounts
xml_open "    " "Accounts"
while IFS=: read -r uname _ uid gid gecos home shell; do
    xml_open "      " "User"
    xml_elem "        " "Username" "$uname"
    xml_elem "        " "UID"      "$uid"
    xml_elem "        " "GID"      "$gid"
    xml_elem "        " "GECOS"    "$gecos"
    xml_elem "        " "Home"     "$home"
    xml_elem "        " "Shell"    "$shell"
    xml_close "      " "User"
done < <(getent passwd 2>/dev/null | sort -t: -k3 -n)
xml_close "    " "Accounts"

# Sudo / admin group membership
xml_open "    " "PrivilegedGroups"
for grp in sudo admin wheel; do
    members=$(getent group "$grp" 2>/dev/null | cut -d: -f4)
    [[ -n "$members" ]] && xml_elem "      " "$grp" "$members"
done
xml_close "    " "PrivilegedGroups"

# Recent logins
last -n 50 2>/dev/null | xml_cdata "    " "RecentLogins"

# Currently logged in
w 2>/dev/null | xml_cdata "    " "CurrentlyLoggedIn"

# Users with empty passwords (security risk)
xml_open "    " "EmptyPasswordAccounts"
awk -F: '($2=="") {print $1}' /etc/shadow 2>/dev/null \
    | while read -r u; do xml_elem "      " "Account" "$u"; done
xml_close "    " "EmptyPasswordAccounts"

xml_close "  " "LocalUsers"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 7 — INSTALLED SOFTWARE
#
# Sources:
#   DebianPackages : dpkg-query (all installed .deb packages)
#   SnapPackages   : snap list (if snapd is installed)
#   PipPackages    : pip3 list --format=columns (if pip3 installed)
#
# Each dpkg entry is a structured <Package> element with
# Name, Version, Architecture, and Status fields.
# ==================================================================
echo "[7/7] Enumerating installed software..."

sw_count=$(dpkg-query --show 2>/dev/null | wc -l | tr -d '[:space:]')
xml_open_attr "  " "InstalledSoftware" "dpkgCount" "$sw_count"

# --- Debian packages (dpkg) ---
xml_open "    " "DebianPackages"

while IFS='|' read -r pkg ver arch status; do
    [[ -z "$pkg" ]] && continue
    xml_open "      " "Package"
    xml_elem "        " "Name"         "$pkg"
    xml_elem "        " "Version"      "$ver"
    xml_elem "        " "Architecture" "$arch"
    xml_elem "        " "Status"       "$status"
    xml_close "      " "Package"
done < <(dpkg-query --show \
    --showformat='${Package}|${Version}|${Architecture}|${db:Status-Status}\n' \
    2>/dev/null | sort)

xml_close "    " "DebianPackages"

# --- Snap packages ---
if command -v snap &>/dev/null; then
    xml_open "    " "SnapPackages"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(awk '{print $1}' <<< "$line")
        ver=$(awk '{print $2}' <<< "$line")
        [[ "$pkg" == "Name" ]] && continue    # skip header
        xml_open "      " "Package"
        xml_elem "        " "Name"    "$pkg"
        xml_elem "        " "Version" "$ver"
        xml_close "      " "Package"
    done < <(snap list 2>/dev/null | tail -n +2)
    xml_close "    " "SnapPackages"
fi

# --- Python pip packages ---
if command -v pip3 &>/dev/null; then
    xml_open "    " "PipPackages"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(awk '{print $1}' <<< "$line")
        ver=$(awk '{print $2}' <<< "$line")
        xml_open "      " "Package"
        xml_elem "        " "Name"    "$pkg"
        xml_elem "        " "Version" "$ver"
        xml_close "      " "Package"
    done < <(pip3 list --format=columns 2>/dev/null | tail -n +3)
    xml_close "    " "PipPackages"
fi

# --- Flatpak packages ---
if command -v flatpak &>/dev/null; then
    xml_open "    " "FlatpakPackages"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(awk '{print $1}' <<< "$line")
        ver=$(awk '{print $3}' <<< "$line")
        [[ "$pkg" == "Name" || "$pkg" == "Ref" ]] && continue
        xml_open "      " "Package"
        xml_elem "        " "Name"    "$pkg"
        xml_elem "        " "Version" "$ver"
        xml_close "      " "Package"
    done < <(flatpak list --columns=name,application,version 2>/dev/null | tail -n +1)
    xml_close "    " "FlatpakPackages"
fi

xml_close "  " "InstalledSoftware"
printf '\n' >> "$OUTFILE"

# ==================================================================
# CLOSE ROOT ELEMENT
# ==================================================================
printf '</SystemAudit>\n' >> "$OUTFILE"

# Optional: validate if xmllint is available
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
echo "  Report  : ${OUTFILE}"
echo "  Packages: ${sw_count} (dpkg)"
echo ""
[[ -f "$OUTFILE" ]] && echo "  [OK] Audit XML written." \
                     || echo "  [ERR] Output file missing."
echo ""
echo "  Files saved to: ${AUDIT_DIR}"
echo ""
