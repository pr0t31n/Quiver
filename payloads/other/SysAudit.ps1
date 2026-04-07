<#
.SYNOPSIS
    Windows System Configuration Audit Tool - PowerShell
.DESCRIPTION
    Collects hardware, OS, updates, security software, group policy,
    users, and installed software. Outputs a structured UTF-8 XML report.
    Uses System.Xml.XmlDocument — all values are automatically XML-safe;
    no CDATA or manual escaping required.
.PARAMETER OutputDir
    Directory for output files. Default: C:\SysAudit
.PARAMETER SkipMsiProducts
    Skip Win32_Product WMI query. That query triggers Windows Installer
    reconfiguration and can take 5+ minutes on large systems.
.NOTES
    Compatible : PowerShell 2.0+ / Windows 7 SP1 and later (x86/x64)
    Requires   : Administrator privileges
    Output     : <OutputDir>\SystemAudit_<HOST>_<TIMESTAMP>.xml
                 <OutputDir>\GroupPolicy_<HOST>_<TIMESTAMP>.xml
    Sections   :
        1. OperatingSystem   - Caption, version, arch, install/boot times
        2. Hardware          - BIOS, CPU(s), memory, disks, network adapters
        3. InstalledUpdates  - QFE hotfixes from Win32_QuickFixEngineering
        4. Security          - Firewall profiles, AV/FW/AS products, UAC
        5. GroupPolicy       - gpresult /X companion file + reference
        6. LocalUsers        - Accounts, groups, net user detail
        7. InstalledSoftware - Registry Uninstall keys (HKLM x64/x86, HKCU)
                               + optional Win32_Product MSI cross-reference
#>
[CmdletBinding()]
param(
    [string]$OutputDir       = "C:\SysAudit",
    [switch]$SkipMsiProducts
)

$ErrorActionPreference = "SilentlyContinue"

# ==================================================================
# PRIVILEGE CHECK
# ==================================================================
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Administrator privileges required. Run PowerShell as Administrator."
    exit 1
}

# ==================================================================
# XML HELPER FUNCTIONS
# ==================================================================
# $script:XDoc is set in main body; helpers reference it so they can
# be defined before the document is created.
$script:XDoc = $null

function New-XElem {
    <#
    Creates a child XML element. If -Text is supplied, InnerText is set
    (XmlDocument auto-escapes &, <, >, etc. — no CDATA needed).
    Returns the new element so the caller can chain further operations.
    #>
    param(
        [System.Xml.XmlNode]$Parent,
        [string]$Tag,
        [string]$Text = $null
    )
    $el = $script:XDoc.CreateElement($Tag)
    if ($null -ne $Text) { $el.InnerText = $Text }
    $Parent.AppendChild($el) | Out-Null
    return $el
}

function Add-Props {
    <#
    Adds a selected list of WMI object properties as child elements of $Parent.
    Array-valued properties (e.g. IPAddress) are joined with "; ".
    #>
    param(
        [System.Xml.XmlNode]$Parent,
        $Obj,
        [string[]]$Fields
    )
    if ($null -eq $Obj) { return }
    foreach ($f in $Fields) {
        $v   = $Obj.$f
        $str = if ($null -eq $v) { "" }
               elseif ($v -is [array]) { $v -join "; " }
               else { [string]$v }
        New-XElem -Parent $Parent -Tag $f -Text $str | Out-Null
    }
}

# ==================================================================
# SETUP — PATHS AND TIMESTAMP
# ==================================================================
if (-not (Test-Path $OutputDir)) {
    New-Item $OutputDir -ItemType Directory | Out-Null
}

$ts       = Get-Date
$xmlTs    = $ts.ToString("yyyy-MM-ddTHH:mm:ss")
$fileTs   = $ts.ToString("yyyyMMdd_HHmmss")
$hostname = $env:COMPUTERNAME
$outFile  = Join-Path $OutputDir "SystemAudit_${hostname}_${fileTs}.xml"
$gprFile  = Join-Path $OutputDir "GroupPolicy_${hostname}_${fileTs}.xml"

Write-Host ""
Write-Host " ===================================================="
Write-Host "  SysAudit.ps1 - Windows System Audit"
Write-Host " ===================================================="
Write-Host "  Host      : $hostname"
Write-Host "  Timestamp : $xmlTs"
Write-Host "  Audit XML : $outFile"
Write-Host "  GP XML    : $gprFile"
Write-Host " ===================================================="
Write-Host ""

# ==================================================================
# INITIALISE XML DOCUMENT
# ==================================================================
$script:XDoc = New-Object System.Xml.XmlDocument
$script:XDoc.AppendChild(
    $script:XDoc.CreateXmlDeclaration("1.0", "UTF-8", $null)
) | Out-Null

$root = $script:XDoc.CreateElement("SystemAudit")
$root.SetAttribute("ComputerName", $hostname)
$root.SetAttribute("GeneratedAt",  $xmlTs)
$root.SetAttribute("AuditTool",    "SysAudit.ps1")
$script:XDoc.AppendChild($root) | Out-Null

# ==================================================================
# SECTION 1 — OPERATING SYSTEM
# ==================================================================
Write-Host "[1/7] Collecting OS information..."
$osEl = New-XElem $root "OperatingSystem"

$wmiOs = Get-WmiObject -Class Win32_OperatingSystem
if ($wmiOs) {
    Add-Props $osEl $wmiOs @(
        "Caption", "Version", "BuildNumber", "OSArchitecture", "CSDVersion",
        "InstallDate", "LastBootUpTime", "CSName", "RegisteredUser",
        "Organization", "SerialNumber", "FreePhysicalMemory",
        "TotalVisibleMemorySize", "SystemDirectory", "WindowsDirectory"
    )
}

# ==================================================================
# SECTION 2 — HARDWARE
# ==================================================================
Write-Host "[2/7] Collecting hardware information..."
$hwEl = New-XElem $root "Hardware"

# Computer system
$csEl = New-XElem $hwEl "ComputerSystem"
$wmiCs = Get-WmiObject -Class Win32_ComputerSystem
if ($wmiCs) {
    Add-Props $csEl $wmiCs @(
        "Manufacturer", "Model", "SystemType", "TotalPhysicalMemory",
        "NumberOfProcessors", "DNSHostName", "Domain", "PartOfDomain", "UserName"
    )
}

# BIOS
$biosEl = New-XElem $hwEl "BIOS"
$wmiBios = Get-WmiObject -Class Win32_BIOS
if ($wmiBios) {
    Add-Props $biosEl $wmiBios @(
        "Manufacturer", "Name", "SMBIOSBIOSVersion", "ReleaseDate", "SerialNumber"
    )
}

# Processors (one element per physical CPU)
$cpusEl = New-XElem $hwEl "Processors"
Get-WmiObject -Class Win32_Processor | ForEach-Object {
    $cpuEl = New-XElem $cpusEl "Processor"
    Add-Props $cpuEl $_ @(
        "DeviceID", "Name", "MaxClockSpeed", "CurrentClockSpeed",
        "NumberOfCores", "NumberOfLogicalProcessors",
        "Architecture", "AddressWidth", "L2CacheSize", "L3CacheSize"
    )
}

# Physical disks
$pdEl = New-XElem $hwEl "PhysicalDisks"
Get-WmiObject -Class Win32_DiskDrive | ForEach-Object {
    $dEl = New-XElem $pdEl "Disk"
    Add-Props $dEl $_ @("DeviceID", "Model", "Size", "InterfaceType",
                         "MediaType", "SerialNumber", "Partitions")
}

# Logical volumes
$ldEl = New-XElem $hwEl "LogicalDisks"
Get-WmiObject -Class Win32_LogicalDisk | ForEach-Object {
    $lEl = New-XElem $ldEl "Volume"
    Add-Props $lEl $_ @("DeviceID", "FileSystem", "Size", "FreeSpace",
                         "VolumeName", "DriveType")
}

# Network adapters and IP configuration
$netEl  = New-XElem $hwEl "Network"
$adpEl  = New-XElem $netEl "Adapters"
Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetEnabled=True" | ForEach-Object {
    $aEl = New-XElem $adpEl "Adapter"
    Add-Props $aEl $_ @("DeviceID", "Name", "MACAddress", "Speed",
                         "NetConnectionID", "Manufacturer")
}

$ipcEl = New-XElem $netEl "IPConfiguration"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | ForEach-Object {
    $iEl = New-XElem $ipcEl "Interface"
    Add-Props $iEl $_ @(
        "Description", "IPAddress", "IPSubnet", "DefaultIPGateway",
        "DNSServerSearchOrder", "DHCPEnabled", "DHCPServer"
    )
}

# ==================================================================
# SECTION 3 — INSTALLED UPDATES
# ==================================================================
Write-Host "[3/7] Collecting installed updates..."
$updEl = New-XElem $root "InstalledUpdates"

Get-WmiObject -Class Win32_QuickFixEngineering | ForEach-Object {
    $qEl = New-XElem $updEl "HotFix"
    Add-Props $qEl $_ @("HotFixID", "Description", "InstalledOn", "InstalledBy", "Caption")
}

# ==================================================================
# SECTION 4 — SECURITY
# ==================================================================
Write-Host "[4/7] Collecting security software status..."
$secEl = New-XElem $root "Security"

# Windows Firewall
# Note: Get-NetFirewallProfile requires PS 3.0+ (NetSecurity module).
# Use netsh for PS 2.0 / Windows 7 compatibility.
$fwEl = New-XElem $secEl "WindowsFirewall"
(New-XElem $fwEl "ProfileStates").InnerText =
    (& netsh advfirewall show allprofiles state 2>&1 | Out-String).Trim()
(New-XElem $fwEl "DetailedSettings").InnerText =
    (& netsh advfirewall show allprofiles 2>&1 | Out-String).Trim()

# Third-party security products via SecurityCenter2
# SecurityCenter2 is a client Windows feature — absent on Server editions.
$sc2Ns = "root\SecurityCenter2"

$avEl = New-XElem $secEl "AntiVirusProducts"
Get-WmiObject -Namespace $sc2Ns -Class AntiVirusProduct | ForEach-Object {
    $pEl = New-XElem $avEl "Product"
    Add-Props $pEl $_ @("displayName", "productState", "pathToSignedProductExe")
}

$fwPEl = New-XElem $secEl "FirewallProducts"
Get-WmiObject -Namespace $sc2Ns -Class FirewallProduct | ForEach-Object {
    $pEl = New-XElem $fwPEl "Product"
    Add-Props $pEl $_ @("displayName", "productState")
}

$aspEl = New-XElem $secEl "AntiSpywareProducts"
Get-WmiObject -Namespace $sc2Ns -Class AntiSpywareProduct | ForEach-Object {
    $pEl = New-XElem $aspEl "Product"
    Add-Props $pEl $_ @("displayName", "productState")
}

# UAC from registry
$uacReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$uacEl  = New-XElem $secEl "UAC"

$enableLua = if ($null -ne $uacReg) { [int]$uacReg.EnableLUA } else { -1 }
$admBehav  = if ($null -ne $uacReg) { [int]$uacReg.ConsentPromptBehaviorAdmin } else { -1 }
$usrBehav  = if ($null -ne $uacReg) { [int]$uacReg.ConsentPromptBehaviorUser }  else { -1 }

$uacStatus   = if ($enableLua -eq 1) { "Enabled" } elseif ($enableLua -eq 0) { "Disabled" } else { "Unknown" }
$admDescMap  = @{ 0="Elevate without prompting"; 1="Prompt for credentials (secure desktop)";
                  2="Prompt for consent (secure desktop)"; 3="Prompt for credentials";
                  4="Prompt for consent"; 5="Prompt for consent (non-Windows binaries)" }
$usrDescMap  = @{ 0="Automatically deny elevation requests";
                  1="Prompt for credentials (secure desktop)"; 3="Prompt for credentials" }
$admDesc = if ($admDescMap.ContainsKey($admBehav)) { $admDescMap[$admBehav] } else { "Unknown" }
$usrDesc = if ($usrDescMap.ContainsKey($usrBehav)) { $usrDescMap[$usrBehav] } else { "Unknown" }

New-XElem $uacEl "Status"                     $uacStatus                          | Out-Null
New-XElem $uacEl "EnableLUA"                  ([string]$enableLua)                | Out-Null
New-XElem $uacEl "ConsentPromptBehaviorAdmin" "$admBehav - $admDesc"              | Out-Null
New-XElem $uacEl "ConsentPromptBehaviorUser"  "$usrBehav - $usrDesc"              | Out-Null

# ==================================================================
# SECTION 5 — GROUP POLICY
# ==================================================================
Write-Host "[5/7] Exporting group policy (gpresult)..."
$gpEl = New-XElem $root "GroupPolicy"
New-XElem $gpEl "ReportFile" $gprFile | Out-Null
New-XElem $gpEl "Note" "See companion GroupPolicy XML for full RSoP report." | Out-Null

& gpresult /X $gprFile /F 2>&1 | Out-Null
if (-not (Test-Path $gprFile)) {
    Set-Content $gprFile '<?xml version="1.0"?><GroupPolicyResult><Error>gpresult returned no output</Error></GroupPolicyResult>'
    New-XElem $gpEl "Warning" "gpresult produced no output; placeholder written." | Out-Null
}

# ==================================================================
# SECTION 6 — LOCAL USERS
# ==================================================================
Write-Host "[6/7] Enumerating local user accounts..."
$usersEl = New-XElem $root "LocalUsers"

(New-XElem $usersEl "AdministratorsGroup").InnerText =
    (& net localgroup administrators 2>&1 | Out-String).Trim()

(New-XElem $usersEl "LocalGroups").InnerText =
    (& net localgroup 2>&1 | Out-String).Trim()

Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True" | ForEach-Object {
    $uEl = New-XElem $usersEl "User"
    $uEl.SetAttribute("name", $_.Name)
    Add-Props $uEl $_ @(
        "Name", "FullName", "Disabled", "Lockout", "PasswordExpires",
        "PasswordRequired", "PasswordChangeable", "SID", "AccountType", "Description"
    )
    (New-XElem $uEl "NetUserDetail").InnerText =
        (& net user $_.Name 2>&1 | Out-String).Trim()
}

# ==================================================================
# SECTION 7 — INSTALLED SOFTWARE
#
# Primary source: registry Uninstall keys (covers virtually all
# installed software regardless of installer technology).
#
# Three registry locations are queried:
#   HKLM_x64 : native 64-bit apps (or all apps on 32-bit OS)
#   HKLM_x86 : 32-bit apps on a 64-bit OS (WOW6432Node)
#   HKCU     : per-user installs for the account running the script
#
# Secondary source (optional, -SkipMsiProducts to disable):
#   Win32_Product : MSI-installed packages via WMI.
#   WARNING — this query triggers Windows Installer reconfiguration
#   on each enumerated product and can take several minutes.
#   Use as a cross-reference only; registry source is more complete.
# ==================================================================
Write-Host "[7/7] Enumerating installed software..."
$swEl    = New-XElem $root "InstalledSoftware"
$swCount = 0

$regSources = @(
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";               Source = "HKLM_x64" },
    @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";   Source = "HKLM_x86" },
    @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";               Source = "HKCU" }
)

foreach ($src in $regSources) {
    if (-not (Test-Path $src.Path)) { continue }
    Write-Host "  Scanning $($src.Source)..."

    Get-ChildItem $src.Path -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if (-not ($props -and $props.DisplayName)) { return }   # skip nameless GUIDs

        $appEl = New-XElem $swEl "Application"
        $appEl.SetAttribute("source", $src.Source)
        New-XElem $appEl "Name"            ([string]$props.DisplayName)     | Out-Null
        New-XElem $appEl "Version"         ([string]$props.DisplayVersion)  | Out-Null
        New-XElem $appEl "Publisher"       ([string]$props.Publisher)       | Out-Null
        New-XElem $appEl "InstallDate"     ([string]$props.InstallDate)     | Out-Null
        New-XElem $appEl "InstallLocation" ([string]$props.InstallLocation) | Out-Null
        $swCount++
    }
}

if (-not $SkipMsiProducts) {
    Write-Host "  Querying Win32_Product (MSI packages; may take several minutes)..."
    $msiEl = New-XElem $swEl "MsiProducts"
    Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | ForEach-Object {
        if (-not $_.Name) { return }
        $pEl = New-XElem $msiEl "Product"
        Add-Props $pEl $_ @("Name", "Version", "Vendor", "InstallDate",
                              "InstallLocation", "PackageName")
    }
}

$swEl.SetAttribute("total", [string]$swCount)
Write-Host "  Found $swCount applications (registry sources)."

# ==================================================================
# SAVE XML — UTF-8, indented, no BOM
# ==================================================================
Write-Host ""
Write-Host "  Saving XML report..."

$xmlSettings              = New-Object System.Xml.XmlWriterSettings
$xmlSettings.Indent       = $true
$xmlSettings.IndentChars  = "  "
$xmlSettings.Encoding     = New-Object System.Text.UTF8Encoding($false)   # no BOM

$xmlWriter = [System.Xml.XmlWriter]::Create($outFile, $xmlSettings)
$script:XDoc.Save($xmlWriter)
$xmlWriter.Flush()
$xmlWriter.Close()

# ==================================================================
# SUMMARY
# ==================================================================
Write-Host ""
Write-Host " ===================================================="
Write-Host "  Audit Complete"
Write-Host " ===================================================="
Write-Host ""
Write-Host "  Audit Report : $outFile"
Write-Host "  Group Policy : $gprFile"
Write-Host "  Applications : $swCount enumerated"
Write-Host ""
if (Test-Path $outFile) { Write-Host "  [OK]   Audit XML written successfully." }
else                    { Write-Host "  [ERR]  Audit XML not created. Check permissions on $OutputDir" }
if (Test-Path $gprFile) { Write-Host "  [OK]   Group Policy XML written successfully." }
else                    { Write-Host "  [WARN] Group Policy XML not created (no policies or not domain-joined)." }
Write-Host ""
Write-Host "  Files saved to: $OutputDir"
Write-Host ""
