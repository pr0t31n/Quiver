<#
.SYNOPSIS
    PrivescAudit-Windows.ps1 — Local privilege escalation vector assessment
.DESCRIPTION
    Enumerates and risk-rates local privilege escalation vectors.
    Run as the TARGET USER (not pre-elevated) to accurately reflect what
    that account can exploit. Elevation reveals fewer privesc paths.
    Outputs structured UTF-8 XML.
.PARAMETER OutDir
    Output directory. Default: C:\PrivescAudit
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File PrivescAudit-Windows.ps1
.NOTES
    Target     : Windows 7 SP1+ / Server 2008 R2+ (PowerShell 3.0+)
    Author     : [Operator]
    Risk scale : CRITICAL > HIGH > MEDIUM > INFO
    Sections   :
        1. TokenPrivileges          — dangerous token privs held by current user
        2. UACConfiguration         — UAC bypass surface assessment
        3. AlwaysInstallElevated    — MSI elevation vulnerability
        4. UnquotedServicePaths     — services with writable intermediate paths
        5. WeakServiceBinaryPerms   — service executables writable by current user
        6. WritablePATHDirectories  — DLL/EXE hijacking via PATH
        7. ScheduledTaskVulns       — tasks with writable executables
        8. AutoRuns                 — writable autorun entries
        9. Findings                 — consolidated risk-rated findings
#>
[CmdletBinding()]
param([string]$OutDir = 'C:\PrivescAudit')

$ErrorActionPreference = 'SilentlyContinue'

# ==================================================================
# XML HELPERS
# ==================================================================
$script:XDoc     = $null
$script:Findings = [System.Collections.Generic.List[object]]::new()

function New-XElem {
    param([System.Xml.XmlNode]$Parent, [string]$Tag, [string]$Text = $null)
    $el = $script:XDoc.CreateElement($Tag)
    if ($null -ne $Text) { $el.InnerText = $Text }
    $Parent.AppendChild($el) | Out-Null
    return $el
}

function Add-Finding {
    param([string]$Risk, [string]$Category, [string]$Detail, [string]$Evidence = '')
    $script:Findings.Add([PSCustomObject]@{
        Risk = $Risk; Category = $Category; Detail = $Detail; Evidence = $Evidence
    })
}

# Try to write a temp file to test directory writability.
function Test-DirWritable {
    param([string]$Path)
    if (-not (Test-Path $Path -PathType Container)) { return $false }
    $t = Join-Path $Path ("__pea_" + [guid]::NewGuid().ToString('N') + ".tmp")
    try {
        [IO.File]::WriteAllText($t, '')
        Remove-Item $t -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}

# Try to open a file for write (without truncating) to test writability.
function Test-FileWritable {
    param([string]$Path)
    if (-not (Test-Path $Path -PathType Leaf)) { return $false }
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open,
                              [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $fs.Close(); return $true
    } catch { return $false }
}

# Strip args from a service/task path and return just the .exe
function Resolve-ExePath {
    param([string]$Raw)
    $r = $Raw.Trim()
    if ($r -match '^"([^"]+\.exe)"') { return $matches[1] }
    if ($r -match '^([A-Za-z]:[^\s"]*\.exe)') { return $matches[1] }
    return $r
}

# ==================================================================
# INITIALISE XML DOCUMENT
# ==================================================================
$script:XDoc = New-Object System.Xml.XmlDocument
$script:XDoc.AppendChild($script:XDoc.CreateXmlDeclaration('1.0', 'UTF-8', $null)) | Out-Null
$root = $script:XDoc.CreateElement('PrivescAudit')
$script:XDoc.AppendChild($root) | Out-Null

# ==================================================================
# METADATA
# ==================================================================
Write-Host ' =================================================='
Write-Host '  PrivescAudit-Windows.ps1'
Write-Host ' =================================================='
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Warning 'Running as Administrator — some privesc paths may not reflect a standard user context.'
}

$metaEl = New-XElem $root 'Metadata'
New-XElem $metaEl 'Hostname'   $env:COMPUTERNAME           | Out-Null
New-XElem $metaEl 'Domain'     $env:USERDOMAIN             | Out-Null
New-XElem $metaEl 'Username'   $identity.Name              | Out-Null
New-XElem $metaEl 'IsAdmin'    ([string]$isAdmin)          | Out-Null
New-XElem $metaEl 'Timestamp'  (Get-Date -Format 'o')      | Out-Null
New-XElem $metaEl 'PSVersion'  $PSVersionTable.PSVersion.ToString() | Out-Null
$os = Get-WmiObject Win32_OperatingSystem
New-XElem $metaEl 'OS' "$($os.Caption) $($os.OSArchitecture)" | Out-Null

# ==================================================================
# 1. TOKEN PRIVILEGES
# ==================================================================
Write-Host '[*] Checking token privileges...'
$privEl = New-XElem $root 'TokenPrivileges'

# Risk map: priv → risk level (CRITICAL = direct SYSTEM, HIGH = indirect)
$privRisk = @{
    'SeImpersonatePrivilege'         = 'CRITICAL'   # JuicyPotato, PrintSpoofer, etc.
    'SeAssignPrimaryTokenPrivilege'  = 'CRITICAL'   # Assign SYSTEM token to new process
    'SeDebugPrivilege'               = 'CRITICAL'   # Read/write any process memory incl. LSASS
    'SeCreateTokenPrivilege'         = 'CRITICAL'   # Forge arbitrary access token
    'SeTcbPrivilege'                 = 'CRITICAL'   # Act as part of the OS
    'SeBackupPrivilege'              = 'HIGH'        # Read any file bypassing DACL
    'SeRestorePrivilege'             = 'HIGH'        # Write any file bypassing DACL
    'SeLoadDriverPrivilege'          = 'HIGH'        # Load unsigned kernel driver
    'SeTakeOwnershipPrivilege'       = 'HIGH'        # Take ownership of any securable object
    'SeManageVolumePrivilege'        = 'HIGH'        # Arbitrary writes to disk volume
    'SeRelabelPrivilege'             = 'HIGH'        # Downgrade integrity of any object
}

$privOutput = & whoami /priv 2>$null
foreach ($line in $privOutput) {
    if ($line -match '^(Se\w+)\s+.*?\s+(Enabled|Disabled)\s*$') {
        $pName    = $matches[1]
        $pState   = $matches[2]
        $pDanger  = $privRisk.ContainsKey($pName)
        $pRisk    = if ($privRisk.ContainsKey($pName)) { $privRisk[$pName] } else { 'INFO' }
        $pEl      = New-XElem $privEl 'Privilege'
        $pEl.SetAttribute('name',      $pName)
        $pEl.SetAttribute('state',     $pState)
        $pEl.SetAttribute('dangerous', [string]$pDanger)
        if ($pDanger -and $pState -eq 'Enabled') {
            Add-Finding $pRisk 'TokenPrivilege' \
                "$pName is Enabled — local escalation to SYSTEM via token manipulation" $pName
        }
    }
}

# ==================================================================
# 2. UAC CONFIGURATION
# ==================================================================
Write-Host '[*] Checking UAC configuration...'
$uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$uacEl   = New-XElem $root 'UACConfiguration'

$uacProps = Get-ItemProperty $uacPath -ErrorAction SilentlyContinue
$uacFields = @(
    'EnableLUA','ConsentPromptBehaviorAdmin','ConsentPromptBehaviorUser',
    'LocalAccountTokenFilterPolicy','FilterAdministratorToken','PromptOnSecureDesktop'
)
foreach ($f in $uacFields) {
    $v = if ($uacProps) { $uacProps.$f } else { $null }
    New-XElem $uacEl $f ([string]$v) | Out-Null
}

$enableLUA = if ($uacProps) { $uacProps.EnableLUA } else { 1 }
$cPBA      = if ($uacProps) { $uacProps.ConsentPromptBehaviorAdmin } else { 5 }
$lATFP     = if ($uacProps) { $uacProps.LocalAccountTokenFilterPolicy } else { 0 }
$fAT       = if ($uacProps) { $uacProps.FilterAdministratorToken } else { 0 }
$pOSD      = if ($uacProps) { $uacProps.PromptOnSecureDesktop } else { 1 }

if ($enableLUA -eq 0) {
    Add-Finding 'CRITICAL' 'UAC' 'UAC fully disabled (EnableLUA=0) — all processes run with full admin token' 'EnableLUA=0'
}
if ($cPBA -eq 0) {
    Add-Finding 'HIGH' 'UAC' 'ConsentPromptBehaviorAdmin=0 — admin processes auto-elevate without UAC prompt' 'ConsentPromptBehaviorAdmin=0'
}
if ($lATFP -eq 1) {
    Add-Finding 'HIGH' 'UAC' 'LocalAccountTokenFilterPolicy=1 — remote admin logins get full token; PtH/NTLM relay more viable' 'LocalAccountTokenFilterPolicy=1'
}
if ($fAT -eq 0) {
    Add-Finding 'MEDIUM' 'UAC' 'FilterAdministratorToken=0 — built-in Administrator account bypasses UAC prompts' 'FilterAdministratorToken=0'
}
if ($pOSD -eq 0) {
    Add-Finding 'MEDIUM' 'UAC' 'PromptOnSecureDesktop=0 — UAC prompt shown on normal desktop; susceptible to UI spoofing' 'PromptOnSecureDesktop=0'
}

# ==================================================================
# 3. ALWAYSINSTALLELEVATED
# ==================================================================
Write-Host '[*] Checking AlwaysInstallElevated...'
$aiePath = 'SOFTWARE\Policies\Microsoft\Windows\Installer'
$aieHKLM = (Get-ItemProperty "HKLM:\$aiePath" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
$aieHKCU = (Get-ItemProperty "HKCU:\$aiePath" -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated
$aieVuln = ($aieHKLM -eq 1) -and ($aieHKCU -eq 1)

$aieEl = New-XElem $root 'AlwaysInstallElevated'
New-XElem $aieEl 'HKLM'       ([string]$aieHKLM) | Out-Null
New-XElem $aieEl 'HKCU'       ([string]$aieHKCU) | Out-Null
New-XElem $aieEl 'Vulnerable' ([string]$aieVuln) | Out-Null

if ($aieVuln) {
    Add-Finding 'CRITICAL' 'AlwaysInstallElevated' \
        'Both HKLM and HKCU AlwaysInstallElevated=1 — any crafted MSI installs as SYSTEM' \
        'HKLM + HKCU SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated=1'
}

# ==================================================================
# 4. UNQUOTED SERVICE PATHS
# ==================================================================
Write-Host '[*] Scanning unquoted service paths...'
$uqEl       = New-XElem $root 'UnquotedServicePaths'
$allServices = Get-WmiObject Win32_Service
$uqTotal    = 0

foreach ($svc in $allServices) {
    if (-not $svc.PathName) { continue }
    $raw = $svc.PathName.Trim()
    # Skip: already quoted, no spaces, or disabled
    if ($raw -match '^"' -or $raw -notmatch ' ' -or $svc.StartMode -eq 'Disabled') { continue }
    $exePath = Resolve-ExePath $raw
    $uqTotal++

    # Check each space-separated segment for a writable parent directory
    $writableDir = $null
    $parts = $exePath -split ' '
    for ($i = 1; $i -lt $parts.Length; $i++) {
        $candidate = ($parts[0..($i-1)] -join ' ')
        $parent    = Split-Path $candidate -Parent -ErrorAction SilentlyContinue
        if ($parent -and (Test-DirWritable $parent)) { $writableDir = $parent; break }
    }

    $svcEl = New-XElem $uqEl 'Service'
    New-XElem $svcEl 'Name'                 $svc.Name         | Out-Null
    New-XElem $svcEl 'Path'                 $exePath          | Out-Null
    New-XElem $svcEl 'StartMode'            $svc.StartMode    | Out-Null
    New-XElem $svcEl 'State'                $svc.State        | Out-Null
    New-XElem $svcEl 'RunAs'                $svc.StartName    | Out-Null
    New-XElem $svcEl 'WritableIntermediate' ([string]($null -ne $writableDir)) | Out-Null
    if ($writableDir) {
        New-XElem $svcEl 'WritableDir' $writableDir | Out-Null
        $r = if ($svc.StartName -match 'SYSTEM|LocalSystem') { 'CRITICAL' } else { 'HIGH' }
        Add-Finding $r 'UnquotedServicePath' \
            "Service '$($svc.Name)' unquoted path — writable intermediate dir '$writableDir' (runs as $($svc.StartName))" $exePath
    }
}
$uqEl.SetAttribute('total', [string]$uqTotal)

# ==================================================================
# 5. WEAK SERVICE BINARY PERMISSIONS
# ==================================================================
Write-Host '[*] Checking service binary write permissions...'
$wsbEl    = New-XElem $root 'WeakServiceBinaryPermissions'
$wsbCount = 0

foreach ($svc in $allServices) {
    if (-not $svc.PathName -or $svc.StartMode -eq 'Disabled') { continue }
    $exePath = Resolve-ExePath $svc.PathName
    if (-not (Test-Path $exePath -PathType Leaf)) { continue }
    if (Test-FileWritable $exePath) {
        $svcEl = New-XElem $wsbEl 'Service'
        New-XElem $svcEl 'Name'       $svc.Name      | Out-Null
        New-XElem $svcEl 'Binary'     $exePath       | Out-Null
        New-XElem $svcEl 'StartMode'  $svc.StartMode | Out-Null
        New-XElem $svcEl 'RunAs'      $svc.StartName | Out-Null
        $r = if ($svc.StartName -match 'SYSTEM|LocalSystem') { 'CRITICAL' } else { 'HIGH' }
        Add-Finding $r 'WeakServiceBinaryPermission' \
            "Service '$($svc.Name)' binary writable by current user — replace to execute as $($svc.StartName)" $exePath
        $wsbCount++
    }
}
$wsbEl.SetAttribute('count', [string]$wsbCount)

# ==================================================================
# 6. WRITABLE PATH DIRECTORIES
# ==================================================================
Write-Host '[*] Checking PATH for writable directories...'
$pathEl = New-XElem $root 'WritablePATHDirectories'
$writablePathCount = 0

$pathDirs = ($env:PATH -split ';') | Where-Object { $_.Trim() } | Select-Object -Unique
foreach ($dir in $pathDirs) {
    $dir = $dir.Trim('"').Trim()
    $writable = Test-DirWritable $dir
    $dEl = New-XElem $pathEl 'Directory'
    $dEl.SetAttribute('writable', [string]$writable)
    $dEl.InnerText = $dir
    if ($writable) {
        $writablePathCount++
        Add-Finding 'HIGH' 'WritablePATHDirectory' \
            "PATH entry '$dir' is writable — plant malicious DLL/EXE for DLL hijacking or binary replacement" $dir
    }
}
$pathEl.SetAttribute('writableCount', [string]$writablePathCount)

# ==================================================================
# 7. SCHEDULED TASK VULNERABILITIES
# ==================================================================
Write-Host '[*] Scanning scheduled tasks...'
$stEl    = New-XElem $root 'ScheduledTaskVulnerabilities'
$stCount = 0

try {
    # schtasks /fo CSV /v works on all Windows versions including 7
    $rawTasks = & schtasks /query /fo CSV /v 2>$null
    if ($rawTasks) {
        $tasks = $rawTasks | ConvertFrom-Csv -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            $action = $t.'Task To Run'
            $runAs  = $t.'Run As User'
            if (-not $action -or $action -eq 'N/A' -or $action -eq 'COM handler') { continue }
            $exePath = Resolve-ExePath $action
            if (-not (Test-Path $exePath -PathType Leaf)) { continue }
            if (Test-FileWritable $exePath) {
                $tEl = New-XElem $stEl 'Task'
                New-XElem $tEl 'Name'        $t.TaskName | Out-Null
                New-XElem $tEl 'Action'      $action     | Out-Null
                New-XElem $tEl 'RunAs'       $runAs      | Out-Null
                New-XElem $tEl 'NextRun'     $t.'Next Run Time' | Out-Null
                New-XElem $tEl 'WritableBinary' 'true'   | Out-Null
                $r = if ($runAs -match 'SYSTEM|Administrator') { 'CRITICAL' } else { 'HIGH' }
                Add-Finding $r 'WritableScheduledTaskBinary' \
                    "Task '$($t.TaskName)' executable writable (runs as $runAs)" $exePath
                $stCount++
            }
        }
    }
} catch {}
$stEl.SetAttribute('vulnerableCount', [string]$stCount)

# ==================================================================
# 8. AUTORUNS SURVEY
# ==================================================================
Write-Host '[*] Enumerating autorun locations...'
$arEl = New-XElem $root 'AutoRuns'

$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($regPath in $runKeys) {
    $props = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        $rawVal  = [string]$_.Value
        $exePath = Resolve-ExePath $rawVal
        $writable = Test-FileWritable $exePath
        $eEl = New-XElem $arEl 'RegistryEntry'
        $eEl.SetAttribute('location', $regPath)
        $eEl.SetAttribute('name',     $_.Name)
        $eEl.SetAttribute('writable', [string]$writable)
        $eEl.InnerText = $rawVal
        if ($writable) {
            Add-Finding 'HIGH' 'WritableAutoRunBinary' \
                "AutoRun '$($_.Name)' at $regPath points to writable binary" $exePath
        }
    }
}

# Startup folders
@(
    [Environment]::GetFolderPath('Startup'),
    [Environment]::GetFolderPath('CommonStartup')
) | Where-Object { $_ } | ForEach-Object {
    $folderPath = $_
    $writable   = Test-DirWritable $folderPath
    $sfEl = New-XElem $arEl 'StartupFolder'
    $sfEl.SetAttribute('path',     $folderPath)
    $sfEl.SetAttribute('writable', [string]$writable)
    Get-ChildItem $folderPath -ErrorAction SilentlyContinue | ForEach-Object {
        New-XElem $sfEl 'Item' $_.FullName | Out-Null
    }
    if ($writable) {
        Add-Finding 'HIGH' 'WritableStartupFolder' \
            "Startup folder writable — drop executable or shortcut for persistence/elevation" $folderPath
    }
}

# ==================================================================
# 9. WRITE CONSOLIDATED FINDINGS
# ==================================================================
$riskOrder = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'LOW'=3; 'INFO'=4 }
$sorted    = $script:Findings | Sort-Object { $riskOrder[$_.Risk] }

$findEl = New-XElem $root 'Findings'
$findEl.SetAttribute('count', [string]$script:Findings.Count)
foreach ($f in $sorted) {
    $fe = New-XElem $findEl 'Finding'
    $fe.SetAttribute('risk', $f.Risk)
    New-XElem $fe 'Category' $f.Category | Out-Null
    New-XElem $fe 'Detail'   $f.Detail   | Out-Null
    if ($f.Evidence) { New-XElem $fe 'Evidence' $f.Evidence | Out-Null }
}

# ==================================================================
# SAVE OUTPUT
# ==================================================================
if (-not (Test-Path $OutDir)) { New-Item $OutDir -ItemType Directory -Force | Out-Null }
$ts      = Get-Date -Format 'yyyyMMdd_HHmmss'
$outFile = Join-Path $OutDir "PrivescAudit_$($env:COMPUTERNAME)_${ts}.xml"

$xmlSettings          = New-Object System.Xml.XmlWriterSettings
$xmlSettings.Encoding = New-Object System.Text.UTF8Encoding($false)
$xmlSettings.Indent   = $true
$xmlWriter            = [System.Xml.XmlWriter]::Create($outFile, $xmlSettings)
$script:XDoc.Save($xmlWriter)
$xmlWriter.Close()

Write-Host ''
Write-Host " Findings: $($script:Findings.Count)"
foreach ($r in @('CRITICAL','HIGH','MEDIUM','INFO')) {
    $c = ($script:Findings | Where-Object { $_.Risk -eq $r }).Count
    if ($c -gt 0) { Write-Host "   $r : $c" }
}
Write-Host " Output  : $outFile"
