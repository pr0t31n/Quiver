#!/usr/bin/env bash
# ==================================================================
#  SysAudit_redhat.sh
#  Description : System Configuration Audit Tool — RHEL/CentOS/Fedora
#  Author      : [Operator]
#  Compatible  : RHEL/CentOS 7+, Fedora 28+, Rocky/AlmaLinux 8+
#  Requires    : Root privileges (sudo or direct root)
#  Output      : /var/log/sysaudit/SystemAudit_<HOST>_<TIMESTAMP>.xml
#
#  Sections:
#    1. OperatingSystem   - OS release, kernel, hostname, uptime
#    2. Hardware          - BIOS/DMI, CPU, memory, disks, network
#    3. InstalledUpdates  - yum/dnf history, available upgrades
#    4. Security          - firewalld/iptables, SELinux, PAM, SSH
#    5. SecurityPolicy    - sudoers, pwquality, login.defs, authselect
#    6. LocalUsers        - Accounts, wheel members, last logins
#    7. InstalledSoftware - rpm packages, dnf/yum groups, pip3
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

# Detect package manager: dnf (RHEL 8+/Fedora) or yum (RHEL 7/CentOS 7)
if command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
else
    PKG_MGR="none"
fi

echo ""
echo " ===================================================="
echo "  SysAudit_redhat.sh - RHEL/CentOS/Fedora System Audit"
echo " ===================================================="
echo "  Host      : ${HOSTNAME_VAL}"
echo "  Timestamp : ${XMLTS}"
echo "  Pkg Mgr   : ${PKG_MGR}"
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

xml_open()      { printf '%s<%s>\n'  "$1" "$2"       >> "$OUTFILE"; }
xml_close()     { printf '%s</%s>\n' "$1" "$2"       >> "$OUTFILE"; }

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

# ==================================================================
# WRITE XML HEADER AND ROOT ELEMENT
# ==================================================================
{
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<SystemAudit\n'
    printf '    Hostname="%s"\n' "$(xml_safe "$HOSTNAME_VAL")"
    printf '    GeneratedAt="%s"\n' "$XMLTS"
    printf '    AuditTool="SysAudit_redhat.sh">\n\n'
} > "$OUTFILE"

# ==================================================================
# SECTION 1 — OPERATING SYSTEM
# ==================================================================
echo "[1/7] Collecting OS information..."
xml_open "  " "OperatingSystem"

# Parse /etc/os-release
if [[ -f /etc/os-release ]]; then
    while IFS='=' read -r key val; do
        [[ -z "$key" || "$key" == \#* ]] && continue
        val="${val%\"}"
        val="${val#\"}"
        xml_elem "    " "$key" "$val"
    done < /etc/os-release
fi

# RHEL/CentOS-specific release file
[[ -f /etc/redhat-release ]] && xml_elem "    " "RedHatRelease" "$(cat /etc/redhat-release)"
[[ -f /etc/centos-release ]] && xml_elem "    " "CentosRelease" "$(cat /etc/centos-release)"

xml_elem "    " "Kernel"           "$(uname -r)"
xml_elem "    " "KernelFull"       "$(uname -a)"
xml_elem "    " "Architecture"     "$(uname -m)"
xml_elem "    " "Hostname"         "$HOSTNAME_VAL"
xml_elem "    " "Uptime"           "$(uptime)"
xml_elem "    " "Timezone"         "$(timedatectl show --property=Timezone --value 2>/dev/null || date +%Z)"
xml_elem "    " "PackageManager"   "$PKG_MGR"

# RHEL subscription status (if applicable)
if command -v subscription-manager &>/dev/null; then
    xml_elem "    " "RHELSubscription" \
        "$(subscription-manager status 2>/dev/null | grep 'Overall Status' | cut -d: -f2 | xargs || echo 'N/A')"
fi

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
    xml_elem "    " "BIOSNote" "dmidecode not installed; install with: yum install dmidecode"
fi

xml_open "    " "Processors"
lscpu 2>/dev/null | xml_cdata "      " "LscpuOutput"
xml_elem "      " "LogicalCores" "$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 'N/A')"
xml_close "    " "Processors"

xml_open "    " "Memory"
xml_elem "      " "MemTotal"     "$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
xml_elem "      " "MemFree"      "$(grep MemFree /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
xml_elem "      " "MemAvailable" "$(grep MemAvailable /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
xml_elem "      " "SwapTotal"    "$(grep SwapTotal /proc/meminfo 2>/dev/null | awk '{print $2" "$3}')"
if command -v dmidecode &>/dev/null; then
    dmidecode --type memory 2>/dev/null | xml_cdata "      " "PhysicalModules"
fi
xml_close "    " "Memory"

xml_open "    " "Storage"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,VENDOR 2>/dev/null | xml_cdata "      " "BlockDevices"
df -h 2>/dev/null | xml_cdata "      " "DiskUsage"
xml_close "    " "Storage"

xml_open "    " "Network"
ip -br link show 2>/dev/null | xml_cdata "      " "Interfaces"
ip -br addr show 2>/dev/null | xml_cdata "      " "Addresses"
ip route show 2>/dev/null    | xml_cdata "      " "Routes"
xml_elem "      " "DNSResolver" \
    "$(grep ^nameserver /etc/resolv.conf 2>/dev/null | tr '\n' ' ')"
xml_close "    " "Network"

xml_close "  " "Hardware"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 3 — INSTALLED UPDATES
# ==================================================================
echo "[3/7] Collecting update information..."
xml_open "  " "InstalledUpdates"

# yum/dnf history
if [[ "$PKG_MGR" != "none" ]]; then
    "$PKG_MGR" history list 2>/dev/null | head -30 \
        | xml_cdata "    " "PackageManagerHistory"
fi

# Available updates
xml_open "    " "AvailableUpdates"
if [[ "$PKG_MGR" != "none" ]]; then
    # --quiet suppresses metadata refresh output; 2>/dev/null catches "no updates"
    "$PKG_MGR" check-update --quiet 2>/dev/null \
        | xml_cdata "      " "CheckUpdateOutput"
fi
xml_close "    " "AvailableUpdates"

# Security advisories (dnf only)
if [[ "$PKG_MGR" == "dnf" ]]; then
    xml_open "    " "SecurityAdvisories"
    dnf updateinfo list security 2>/dev/null \
        | xml_cdata "      " "DnfSecurityList"
    xml_close "    " "SecurityAdvisories"
fi

# RPM last-installed packages (sorted by install time, most recent first)
xml_open "    " "RecentlyInstalledPackages"
rpm -qa --queryformat '%{INSTALLTIME} %{INSTALLTIME:date} %{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' \
    2>/dev/null | sort -rn | head -50 | awk '{$1=""; print $0}' \
    | xml_cdata "      " "RpmRecentInstalls"
xml_close "    " "RecentlyInstalledPackages"

xml_close "  " "InstalledUpdates"
printf '\n' >> "$OUTFILE"

# ==================================================================
# SECTION 4 — SECURITY
# ==================================================================
echo "[4/7] Collecting security status..."
xml_open "  " "Security"

# Firewall — firewalld (RHEL 7+) with iptables fallback
xml_open "    " "Firewall"
if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
    xml_elem "      " "FirewalldActive" "true"
    firewall-cmd --list-all 2>/dev/null | xml_cdata "      " "DefaultZone"
    firewall-cmd --list-all-zones 2>/dev/null | xml_cdata "      " "AllZones"
else
    xml_elem "      " "FirewalldActive" "false"
fi
iptables  -L -n -v --line-numbers 2>/dev/null | xml_cdata "      " "IPTables"
ip6tables -L -n -v --line-numbers 2>/dev/null | xml_cdata "      " "IP6Tables"
xml_close "    " "Firewall"

# SELinux — standard on RHEL/CentOS
xml_open "    " "SELinux"
if command -v sestatus &>/dev/null; then
    xml_elem "      " "Installed" "true"
    xml_elem "      " "Mode"      "$(getenforce 2>/dev/null || echo 'N/A')"
    sestatus 2>/dev/null | xml_cdata "      " "SEStatusDetail"
    [[ -f /etc/selinux/config ]] && \
        grep -v '^#' /etc/selinux/config | grep -v '^[[:space:]]*$' \
        | xml_cdata "      " "SELinuxConfig"
else
    xml_elem "      " "Installed" "false"
fi
xml_close "    " "SELinux"

# FIPS mode
xml_elem "    " "FIPSEnabled" \
    "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null || echo 'N/A')"

# Known security tools
xml_open "    " "SecurityTools"
for tool in clamav rkhunter aide fail2ban auditd ossec-hids tripwire; do
    if rpm -q "$tool" &>/dev/null; then
        ver=$(rpm -q --queryformat '%{VERSION}' "$tool" 2>/dev/null)
        xml_elem "      " "$tool" "$ver"
    fi
done
# auditd status
if command -v auditctl &>/dev/null; then
    xml_elem "      " "AuditdStatus" \
        "$(systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null | head -1)"
    auditctl -s 2>/dev/null | xml_cdata "      " "AuditRules"
fi
xml_close "    " "SecurityTools"

# SSH configuration
xml_open "    " "SSH"
if [[ -f /etc/ssh/sshd_config ]]; then
    xml_elem "      " "PermitRootLogin"        "$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "PasswordAuthentication"  "$(grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "PubkeyAuthentication"    "$(grep -i '^PubkeyAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo 'not set')"
    xml_elem "      " "Port"                    "$(grep -i '^Port' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo '22 (default)')"
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

# Password quality requirements (RHEL 7+ via pwquality)
xml_open "    " "PasswordQuality"
if [[ -f /etc/security/pwquality.conf ]]; then
    grep -v '^#' /etc/security/pwquality.conf 2>/dev/null | grep -v '^[[:space:]]*$' \
        | xml_cdata "      " "pwquality_conf"
fi
grep -v '^#' /etc/login.defs 2>/dev/null | grep -v '^[[:space:]]*$' \
    | xml_cdata "      " "login_defs"
xml_close "    " "PasswordQuality"

# PAM configuration
xml_open "    " "PAM"
for pam_file in /etc/pam.d/system-auth /etc/pam.d/password-auth \
                /etc/pam.d/sshd /etc/pam.d/su; do
    [[ -f "$pam_file" ]] || continue
    fname=$(basename "$pam_file")
    xml_open "      " "$fname"
    grep -v '^#' "$pam_file" 2>/dev/null | grep -v '^[[:space:]]*$' \
        | xml_cdata "        " "Content"
    xml_close "      " "$fname"
done
xml_close "    " "PAM"

# authselect (RHEL 8+) or authconfig (RHEL 7)
xml_open "    " "AuthConfiguration"
if command -v authselect &>/dev/null; then
    authselect current 2>/dev/null | xml_cdata "      " "AuthselectCurrent"
elif command -v authconfig &>/dev/null; then
    authconfig --test 2>/dev/null | xml_cdata "      " "AuthconfigTest"
fi
xml_close "    " "AuthConfiguration"

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

# Privileged group members
xml_open "    " "PrivilegedGroups"
for grp in wheel sudo root; do
    members=$(getent group "$grp" 2>/dev/null | cut -d: -f4)
    [[ -n "$members" ]] && xml_elem "      " "$grp" "$members"
done
xml_close "    " "PrivilegedGroups"

last -n 50 2>/dev/null | xml_cdata "    " "RecentLogins"
w 2>/dev/null           | xml_cdata "    " "CurrentlyLoggedIn"

# Accounts with empty passwords
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
#   RpmPackages  : rpm -qa (all installed RPM packages with version,
#                  release, arch, and install timestamp)
#   YumGroups    : installed package groups (yum/dnf grouplist)
#   PipPackages  : pip3 list (if pip3 installed)
#
# rpm -qa with --queryformat provides structured, per-package data.
# ==================================================================
echo "[7/7] Enumerating installed software..."

rpm_count=$(rpm -qa --queryformat '%{NAME}\n' 2>/dev/null | wc -l | tr -d '[:space:]')
xml_open_attr "  " "InstalledSoftware" "rpmCount" "$rpm_count"

# --- RPM packages ---
xml_open "    " "RpmPackages"

while IFS='|' read -r name ver arch idate summary; do
    [[ -z "$name" ]] && continue
    xml_open "      " "Package"
    xml_elem "        " "Name"        "$name"
    xml_elem "        " "Version"     "$ver"
    xml_elem "        " "Architecture" "$arch"
    xml_elem "        " "InstallDate" "$idate"
    xml_elem "        " "Summary"     "$summary"
    xml_close "      " "Package"
done < <(rpm -qa --queryformat \
    '%{NAME}|%{VERSION}-%{RELEASE}|%{ARCH}|%{INSTALLTIME:date}|%{SUMMARY}\n' \
    2>/dev/null | sort -f)

xml_close "    " "RpmPackages"

# --- Package groups ---
if [[ "$PKG_MGR" != "none" ]]; then
    xml_open "    " "PackageGroups"
    "$PKG_MGR" grouplist --installed 2>/dev/null \
        | xml_cdata "      " "InstalledGroups"
    xml_close "    " "PackageGroups"
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
    done < <(flatpak list --columns=name,application,version 2>/dev/null)
    xml_close "    " "FlatpakPackages"
fi

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
echo "  Report   : ${OUTFILE}"
echo "  Packages : ${rpm_count} (rpm)"
echo ""
[[ -f "$OUTFILE" ]] && echo "  [OK] Audit XML written." \
                     || echo "  [ERR] Output file missing."
echo ""
echo "  Files saved to: ${AUDIT_DIR}"
echo ""
