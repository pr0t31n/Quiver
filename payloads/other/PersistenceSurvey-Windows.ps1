<#
.SYNOPSIS
    PersistenceSurvey-Windows.ps1 — Comprehensive autorun and persistence mechanism survey
.DESCRIPTION
    Documents all persistence mechanisms present on the system: registry autorun
    keys, startup folders, scheduled tasks, services, WMI subscriptions, LSA
    packages, COM hijacking opportunities, and boot-level persistence.
    Flags non-standard entries and writable targets as findings.
.PARAMETER OutDir
    Output directory. Default: C:\PersistenceSurvey
.NOTES
    Target   : Windows 7 SP1+ / Server 2008 R2+ (PowerShell 3.0+)
    Author   : [Operator]
    Run as Administrator for full WMI subscription and service enumeration.
    Sections :
        1. RegistryRunKeys     — Run/RunOnce (HKLM + HKCU, 64/32-bit)
        2. StartupFolders      — per-user and all-users startup directories
        3. ScheduledTasks      — all tasks with action, principal, trigger
        4. Services            — non-Microsoft auto-start services
        5. WMISubscriptions    — persistent WMI event consumers
        6. LSAPackages         — authentication and notification packages
        7. AppInitDLLs         — DLLs injected into every user-mode process
        8. WinlogonValues      — Userinit and Shell hijack points
        9. IFEOEntries         — Image File Execution Options debugger hooks
       10. BootExecute         — pre-boot persistence via Session Manager
       11. COMHijacking        — user-scope COM registrations (HKCU\CLSID)
       12. Findings            — consolidated risk-rated findings
#>
[CmdletBinding()]
param([string]$OutDir = 'C:\PersistenceSurvey')

$ErrorActionPreference = 'SilentlyContinue'

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

function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try { return (Get-ItemProperty $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $Default }
}

function Test-FileWritable {
    param([string]$Path)
    if (-not (Test-Path $Path -PathType Leaf)) { return $false }
    try {
        $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
        $fs.Close(); return $true
    } catch { return $false }
}

function Test-DirWritable {
    param([string]$Path)
    if (-not (Test-Path $Path -PathType Container)) { return $false }
    $t = Join-Path $Path ("__ps_" + [guid]::NewGuid().ToString('N') + ".tmp")
    try { [IO.File]::WriteAllText($t, ''); Remove-Item $t -Force; return $true }
    catch { return $false }
}

function Resolve-ExePath {
    param([string]$Raw)
    $r = $Raw.Trim()
    if ($r -match '^"([^"]+\.exe)"') { return $matches[1] }
    if ($r -match '^([A-Za-z]:[^\s"]*\.exe)') { return $matches[1] }
    return $r
}

$script:XDoc = New-Object System.Xml.XmlDocument
$script:XDoc.AppendChild($script:XDoc.CreateXmlDeclaration('1.0', 'UTF-8', $null)) | Out-Null
$root = $script:XDoc.CreateElement('PersistenceSurvey')
$script:XDoc.AppendChild($root) | Out-Null

Write-Host ' =================================================='
Write-Host '  PersistenceSurvey-Windows.ps1'
Write-Host ' =================================================='

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$metaEl   = New-XElem $root 'Metadata'
New-XElem $metaEl 'Hostname'  $env:COMPUTERNAME | Out-Null
New-XElem $metaEl 'Username'  $identity.Name    | Out-Null
New-XElem $metaEl 'Timestamp' (Get-Date -Format 'o') | Out-Null
$os = Get-WmiObject Win32_OperatingSystem
New-XElem $metaEl 'OS' $os.Caption | Out-Null

# Expected baseline values for Winlogon — deviations are flagged
$EXPECTED_USERINIT = 'C:\Windows\system32\userinit.exe,'
$EXPECTED_SHELL    = 'explorer.exe'

# ==================================================================
# 1. REGISTRY RUN KEYS
# ==================================================================
Write-Host '[*] Enumerating registry Run/RunOnce keys...'
$rrEl = New-XElem $root 'RegistryRunKeys'

$runPaths = @(
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';    Scope='HKLM 64-bit' }
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';Scope='HKLM 64-bit (once)' }
    @{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';    Scope='HKCU' }
    @{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce';Scope='HKCU (once)' }
    @{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';    Scope='HKLM 32-bit' }
    @{ Path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce';Scope='HKLM 32-bit (once)' }
    @{ Path='HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run';    Scope='HKCU 32-bit' }
    # Additional persistence locations often missed
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices';         Scope='HKLM Services' }
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run';Scope='HKLM Policy Run' }
    @{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run';Scope='HKCU Policy Run' }
)

foreach ($rp in $runPaths) {
    $props = Get-ItemProperty $rp.Path -ErrorAction SilentlyContinue
    if (-not $props) { continue }
    $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
        $rawVal    = [string]$_.Value
        $exePath   = Resolve-ExePath $rawVal
        $isWritable = Test-FileWritable $exePath
        $eEl = New-XElem $rrEl 'Entry'
        $eEl.SetAttribute('scope', $rp.Scope)
        $eEl.SetAttribute('name', $_.Name)
        $eEl.SetAttribute('writable', [string]$isWritable)
        New-XElem $eEl 'RegistryPath' $rp.Path  | Out-Null
        New-XElem $eEl 'Value'        $rawVal    | Out-Null
        New-XElem $eEl 'ResolvedExe'  $exePath   | Out-Null
        if ($isWritable) {
            Add-Finding 'HIGH' 'WritableRunKeyBinary' \
                "Run key '$($_.Name)' at $($rp.Scope) points to writable binary — modify for arbitrary execution on next login" $exePath
        }
        # Flag obviously suspicious paths
        if ($rawVal -match 'Temp|AppData\\Roaming|Downloads|C:\\Users\\Public') {
            Add-Finding 'MEDIUM' 'SuspiciousRunKeyLocation' \
                "Run key '$($_.Name)' at $($rp.Scope) points to potentially suspicious location: $rawVal" $rawVal
        }
    }
}

# ==================================================================
# 2. STARTUP FOLDERS
# ==================================================================
Write-Host '[*] Checking startup folders...'
$sfEl = New-XElem $root 'StartupFolders'

$startupPaths = @(
    [Environment]::GetFolderPath('Startup'),
    [Environment]::GetFolderPath('CommonStartup'),
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup"
) | Select-Object -Unique

foreach ($sfPath in $startupPaths) {
    if (-not (Test-Path $sfPath -ErrorAction SilentlyContinue)) { continue }
    $sfDirEl = New-XElem $sfEl 'StartupDirectory'
    $sfDirEl.SetAttribute('path', $sfPath)
    $sfDirEl.SetAttribute('writable', [string](Test-DirWritable $sfPath))
    $items = Get-ChildItem $sfPath -ErrorAction SilentlyContinue
    foreach ($item in $items) {
        $iEl = New-XElem $sfDirEl 'Item'
        New-XElem $iEl 'Name' $item.Name         | Out-Null
        New-XElem $iEl 'Path' $item.FullName      | Out-Null
        New-XElem $iEl 'LastWrite' ([string]$item.LastWriteTime) | Out-Null
    }
    if (Test-DirWritable $sfPath) {
        Add-Finding 'HIGH' 'WritableStartupFolder' \
            "Startup folder is writable — drop .lnk or .exe for persistence on next user login" $sfPath
    }
}

# ==================================================================
# 3. SCHEDULED TASKS
# ==================================================================
Write-Host '[*] Enumerating scheduled tasks...'
$stEl     = New-XElem $root 'ScheduledTasks'
$nonMsCount = 0

try {
    $rawTasks = & schtasks /query /fo CSV /v 2>$null
    if ($rawTasks) {
        $tasks = $rawTasks | ConvertFrom-Csv -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            $name   = $t.TaskName
            $action = $t.'Task To Run'
            $runAs  = $t.'Run As User'
            $trigger = $t.'Scheduled Task State'
            $nextRun = $t.'Next Run Time'
            $lastRun = $t.'Last Run Time'
            $status  = $t.Status

            if (-not $name -or $action -eq 'N/A') { continue }
            # Flag non-Microsoft tasks more prominently
            $isMicrosoft = $name -match '\\Microsoft\\' -or $name -match '^\\\Microsoft'
            if (-not $isMicrosoft) { $nonMsCount++ }

            $exePath   = Resolve-ExePath $action
            $isWritable = Test-FileWritable $exePath

            $tEl = New-XElem $stEl 'Task'
            $tEl.SetAttribute('microsoft', [string]$isMicrosoft)
            $tEl.SetAttribute('writableBinary', [string]$isWritable)
            New-XElem $tEl 'Name'    $name    | Out-Null
            New-XElem $tEl 'Action'  $action  | Out-Null
            New-XElem $tEl 'RunAs'   $runAs   | Out-Null
            New-XElem $tEl 'Status'  $status  | Out-Null
            New-XElem $tEl 'NextRun' $nextRun | Out-Null
            New-XElem $tEl 'LastRun' $lastRun | Out-Null

            if ($isWritable) {
                $r = if ($runAs -match 'SYSTEM|Administrator') { 'CRITICAL' } else { 'HIGH' }
                Add-Finding $r 'WritableTaskBinary' \
                    "Task '$name' binary is writable (runs as $runAs) — modify binary for elevated execution" $exePath
            }
            if (-not $isMicrosoft -and $action -match 'Temp|AppData\\Roaming|Downloads|Public') {
                Add-Finding 'MEDIUM' 'SuspiciousTaskLocation' \
                    "Non-Microsoft scheduled task '$name' runs from suspicious path: $action" $name
            }
        }
    }
} catch {}
$stEl.SetAttribute('nonMicrosoftCount', [string]$nonMsCount)

# ==================================================================
# 4. SERVICES (non-Microsoft auto-start)
# ==================================================================
Write-Host '[*] Enumerating non-Microsoft auto-start services...'
$svcEl = New-XElem $root 'Services'

# Known-Microsoft publisher paths for basic filtering
$msBasePaths = @(
    'C:\Windows\', 'C:\Program Files\Windows', 'C:\Program Files (x86)\Windows',
    'C:\Program Files\Microsoft', 'C:\Program Files (x86)\Microsoft'
)

$services = Get-WmiObject Win32_Service | Where-Object {
    $_.StartMode -in @('Auto','Automatic') -and $_.PathName
}
$thirdPartyCount = 0
foreach ($svc in $services) {
    $exePath    = Resolve-ExePath $svc.PathName
    $isMicrosoft = $msBasePaths | Where-Object { $exePath -like "$_*" }
    if ($isMicrosoft) { continue }
    $thirdPartyCount++
    $isWritable = Test-FileWritable $exePath
    $svcItemEl  = New-XElem $svcEl 'Service'
    $svcItemEl.SetAttribute('writableBinary', [string]$isWritable)
    New-XElem $svcItemEl 'Name'      $svc.Name      | Out-Null
    New-XElem $svcItemEl 'Binary'    $exePath        | Out-Null
    New-XElem $svcItemEl 'StartMode' $svc.StartMode  | Out-Null
    New-XElem $svcItemEl 'State'     $svc.State      | Out-Null
    New-XElem $svcItemEl 'RunAs'     $svc.StartName  | Out-Null
    if ($isWritable) {
        $r = if ($svc.StartName -match 'SYSTEM|LocalSystem') { 'CRITICAL' } else { 'HIGH' }
        Add-Finding $r 'WritableThirdPartyServiceBinary' \
            "Third-party auto-start service '$($svc.Name)' binary is writable (runs as $($svc.StartName))" $exePath
    }
}
$svcEl.SetAttribute('thirdPartyAutoStartCount', [string]$thirdPartyCount)

# ==================================================================
# 5. WMI SUBSCRIPTIONS
# ==================================================================
Write-Host '[*] Enumerating WMI event subscriptions...'
$wmiEl = New-XElem $root 'WMISubscriptions'

$filters  = @(Get-WmiObject -Namespace 'root\subscription' -Class __EventFilter  -ErrorAction SilentlyContinue)
$consumers = @(Get-WmiObject -Namespace 'root\subscription' -Class CommandLineEventConsumer  -ErrorAction SilentlyContinue)
$consumers += @(Get-WmiObject -Namespace 'root\subscription' -Class ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
$bindings  = @(Get-WmiObject -Namespace 'root\subscription' -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue)

New-XElem $wmiEl 'FilterCount'   ([string]$filters.Count)   | Out-Null
New-XElem $wmiEl 'ConsumerCount' ([string]$consumers.Count) | Out-Null
New-XElem $wmiEl 'BindingCount'  ([string]$bindings.Count)  | Out-Null

foreach ($f in $filters) {
    $fEl = New-XElem $wmiEl 'EventFilter'
    New-XElem $fEl 'Name'  $f.Name  | Out-Null
    New-XElem $fEl 'Query' $f.Query | Out-Null
}
foreach ($c in $consumers) {
    $cEl = New-XElem $wmiEl 'Consumer'
    New-XElem $cEl 'Name'        $c.Name        | Out-Null
    New-XElem $cEl 'Type'        $c.__CLASS     | Out-Null
    New-XElem $cEl 'CommandLine' ($c.CommandLineTemplate) | Out-Null
    New-XElem $cEl 'Script'      ($c.ScriptText) | Out-Null
}

if ($filters.Count -gt 0 -or $consumers.Count -gt 0) {
    Add-Finding 'CRITICAL' 'WMIPersistentSubscription' \
        "$($filters.Count) WMI event filter(s) and $($consumers.Count) consumer(s) found — persistent WMI subscriptions survive reboots and are often missed by AV/EDR" \
        "root\subscription: $($filters.Count) filters, $($consumers.Count) consumers, $($bindings.Count) bindings"
}

# ==================================================================
# 6. LSA PACKAGES
# ==================================================================
Write-Host '[*] Checking LSA authentication/notification packages...'
$lsaEl   = New-XElem $root 'LSAPackages'
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$authPkgs    = Get-RegValue $lsaPath 'Authentication Packages' @()
$secPkgs     = Get-RegValue $lsaPath 'Security Packages'       @()
$notifyPkgs  = Get-RegValue $lsaPath 'Notification Packages'   @()

# Standard expected values
$expectedAuth   = @('msv1_0')
$expectedNotify = @('rassfm','scecli')

foreach ($pkg in $authPkgs) {
    $pEl = New-XElem $lsaEl 'AuthPackage'
    $pEl.InnerText = $pkg
    if ($pkg -and $pkg -notin $expectedAuth) {
        Add-Finding 'HIGH' 'NonStandardLSAAuthPackage' \
            "Non-standard LSA Authentication Package: '$pkg' — could be a password filter DLL or SSP for credential harvesting" $pkg
    }
}
foreach ($pkg in $secPkgs) {
    if (-not $pkg -or $pkg -eq '""') { continue }
    New-XElem $lsaEl 'SecurityPackage' $pkg | Out-Null
}
foreach ($pkg in $notifyPkgs) {
    $pEl = New-XElem $lsaEl 'NotificationPackage'
    $pEl.InnerText = $pkg
    if ($pkg -and $pkg -notin $expectedNotify -and $pkg -ne '""') {
        Add-Finding 'HIGH' 'NonStandardLSANotifyPackage' \
            "Non-standard LSA Notification Package: '$pkg' — notification packages receive plaintext passwords during change/authentication events" $pkg
    }
}

# ==================================================================
# 7. APPINIT_DLLs
# ==================================================================
Write-Host '[*] Checking AppInit_DLLs...'
$aiEl = New-XElem $root 'AppInitDLLs'

$aiPath64 = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$aiPath32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'

foreach ($aiPath in @($aiPath64, $aiPath32)) {
    $aiDlls = Get-RegValue $aiPath 'AppInit_DLLs' ''
    $aiLoad = Get-RegValue $aiPath 'LoadAppInit_DLLs' 0
    $aiBit  = if ($aiPath -match 'WOW') { '32-bit' } else { '64-bit' }
    $aiEl2  = New-XElem $aiEl 'Hive'
    $aiEl2.SetAttribute('bits', $aiBit)
    New-XElem $aiEl2 'DLLs'       $aiDlls        | Out-Null
    New-XElem $aiEl2 'LoadEnabled' ([string]$aiLoad) | Out-Null
    if ($aiLoad -eq 1 -and $aiDlls) {
        Add-Finding 'CRITICAL' 'AppInitDLLsLoaded' \
            "AppInit_DLLs ($aiBit) loaded and non-empty: '$aiDlls' — these DLLs are injected into every process that loads User32.dll" $aiDlls
    }
}

# ==================================================================
# 8. WINLOGON VALUES
# ==================================================================
Write-Host '[*] Checking Winlogon persistence values...'
$wlEl   = New-XElem $root 'WinlogonValues'
$wlPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

$userinit  = Get-RegValue $wlPath 'Userinit' ''
$shell     = Get-RegValue $wlPath 'Shell' ''
$taskman   = Get-RegValue $wlPath 'Taskman' ''

New-XElem $wlEl 'Userinit' $userinit | Out-Null
New-XElem $wlEl 'Shell'    $shell    | Out-Null
New-XElem $wlEl 'Taskman'  ([string]$taskman) | Out-Null

if ($userinit -and $userinit -ne $EXPECTED_USERINIT) {
    Add-Finding 'CRITICAL' 'WinlogonUserinit' \
        "Winlogon Userinit modified: '$userinit' (expected '$EXPECTED_USERINIT') — additional executables run on every login" $userinit
}
if ($shell -and $shell -ne $EXPECTED_SHELL) {
    Add-Finding 'CRITICAL' 'WinlogonShell' \
        "Winlogon Shell modified: '$shell' (expected '$EXPECTED_SHELL') — replacement shell runs instead of (or alongside) Explorer" $shell
}
if ($taskman) {
    Add-Finding 'HIGH' 'WinlogonTaskman' \
        "Winlogon Taskman key set to '$taskman' — launched when Ctrl+Shift+Esc is pressed (Task Manager replacement)" $taskman
}

# Also check HKCU Winlogon
$wlHKCU = Get-RegValue 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' $null
if ($wlHKCU) {
    New-XElem $wlEl 'HKCUShell' $wlHKCU | Out-Null
    Add-Finding 'HIGH' 'HKCUWinlogonShell' \
        "HKCU Winlogon Shell set to '$wlHKCU' — runs for this user's sessions instead of Explorer" $wlHKCU
}

# ==================================================================
# 9. IMAGE FILE EXECUTION OPTIONS (IFEO) DEBUGGER HOOKS
# ==================================================================
Write-Host '[*] Scanning IFEO for debugger hooks...'
$ifeoEl   = New-XElem $root 'IFEOEntries'
$ifeoPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'

Get-ChildItem $ifeoPath -ErrorAction SilentlyContinue | ForEach-Object {
    $debugger  = Get-RegValue $_.PSPath 'Debugger' $null
    $globalFlag = Get-RegValue $_.PSPath 'GlobalFlag' $null
    if ($debugger -or $globalFlag) {
        $exeName = $_.PSChildName
        $iEl = New-XElem $ifeoEl 'IFEOEntry'
        New-XElem $iEl 'Executable' $exeName           | Out-Null
        New-XElem $iEl 'Debugger'   ([string]$debugger) | Out-Null
        New-XElem $iEl 'GlobalFlag' ([string]$globalFlag) | Out-Null
        # Legitimate debuggers: ntsd.exe, cdb.exe, devenv.exe, etc.
        $suspiciousDebugger = $debugger -and $debugger -notmatch 'ntsd|cdb|windbg|devenv|vsjitdebugger' -and $debugger.Trim()
        if ($suspiciousDebugger) {
            Add-Finding 'CRITICAL' 'IFEODebuggerHook' \
                "IFEO debugger hook on '$exeName' → '$debugger' — every launch of $exeName executes $debugger instead/first (Accessibility Feature bypass pattern)" $exeName
        }
    }
}

# ==================================================================
# 10. BOOT EXECUTE
# ==================================================================
Write-Host '[*] Checking BootExecute...'
$beEl      = New-XElem $root 'BootExecute'
$bePath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$bootExec  = Get-RegValue $bePath 'BootExecute' @()
$expected  = 'autocheck autochk *'

foreach ($be in $bootExec) {
    $beItemEl = New-XElem $beEl 'Entry'
    $beItemEl.InnerText = $be
    if ($be -and $be -ne $expected -and $be.Trim()) {
        Add-Finding 'CRITICAL' 'NonStandardBootExecute' \
            "Non-standard BootExecute entry: '$be' — executes before user login, runs as kernel/SYSTEM before security software" $be
    }
}
$beEl.SetAttribute('count', [string]@($bootExec).Count)

# ==================================================================
# 11. COM HIJACKING (HKCU\CLSID overrides)
# ==================================================================
Write-Host '[*] Checking HKCU COM registrations (hijacking opportunities)...'
$comEl    = New-XElem $root 'COMHijacking'
$hkcuClsids = Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue
$comCount = 0

foreach ($clsid in $hkcuClsids) {
    $inproc  = Get-RegValue "$($clsid.PSPath)\InprocServer32" '(default)' $null
    $localSrv = Get-RegValue "$($clsid.PSPath)\LocalServer32"  '(default)' $null
    $val = if ($inproc) { $inproc } elseif ($localSrv) { $localSrv } else { $null }
    if (-not $val) { continue }
    $comCount++
    $cEl = New-XElem $comEl 'UserCOMEntry'
    New-XElem $cEl 'CLSID'     $clsid.PSChildName | Out-Null
    New-XElem $cEl 'Value'     $val               | Out-Null
    New-XElem $cEl 'Type'      (if ($inproc) { 'InprocServer32' } else { 'LocalServer32' }) | Out-Null
    # HKCU COM registrations override HKLM — any application loading this CLSID will use this DLL
    Add-Finding 'MEDIUM' 'UserScopeCOMRegistration' \
        "HKCU COM registration for CLSID $($clsid.PSChildName) → '$val' — user-scope override of HKLM COM object; applications loading this CLSID will use this DLL" $val
}
$comEl.SetAttribute('count', [string]$comCount)
if ($comCount -gt 5) {
    Add-Finding 'HIGH' 'HighCOMRegistrationCount' \
        "$comCount HKCU COM overrides — elevated count may indicate application installation or deliberate COM hijacking persistence" \
        "HKCU\Software\Classes\CLSID: $comCount entries"
}

# ==================================================================
# 12. CONSOLIDATED FINDINGS
# ==================================================================
$riskOrder = @{ 'CRITICAL'=0; 'HIGH'=1; 'MEDIUM'=2; 'LOW'=3; 'INFO'=4 }
$sorted    = $script:Findings | Sort-Object { $riskOrder[$_.Risk] }
$findEl    = New-XElem $root 'Findings'
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
$outFile = Join-Path $OutDir "PersistenceSurvey_$($env:COMPUTERNAME)_${ts}.xml"

$xmlSettings          = New-Object System.Xml.XmlWriterSettings
$xmlSettings.Encoding = New-Object System.Text.UTF8Encoding($false)
$xmlSettings.Indent   = $true
$xmlWriter            = [System.Xml.XmlWriter]::Create($outFile, $xmlSettings)
$script:XDoc.Save($xmlWriter)
$xmlWriter.Close()

Write-Host ''
Write-Host " Findings : $($script:Findings.Count)"
foreach ($r in @('CRITICAL','HIGH','MEDIUM','INFO')) {
    $c = ($script:Findings | Where-Object { $_.Risk -eq $r }).Count
    if ($c -gt 0) { Write-Host "   $r : $c" }
}
Write-Host " Output   : $outFile"
