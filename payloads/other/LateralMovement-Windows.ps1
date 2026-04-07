<#
.SYNOPSIS
    LateralMovement-Windows.ps1 — Network lateral movement surface assessment
.DESCRIPTION
    Enumerates and risk-rates network attack surface that enables lateral movement:
    SMB relay opportunities, LLMNR/NBT-NS poisoning, NTLMv1, RDP/WinRM exposure,
    share permissions, and pass-the-hash mitigations.
.PARAMETER OutDir
    Output directory. Default: C:\LateralMovement
.NOTES
    Target   : Windows 7 SP1+ / Server 2008 R2+ (PowerShell 3.0+)
    Author   : [Operator]
    Best run as Administrator — some registry paths require elevation.
    Sections :
        1. SMBConfiguration     — signing, version, NTLM settings
        2. PoisoningVectors     — LLMNR, NBT-NS, mDNS, WPAD
        3. IPv6Exposure         — SLAAC/DHCPv6 attack surface
        4. RDPConfiguration     — NLA, encryption, restricted admin
        5. WinRMConfiguration   — remote management status + auth
        6. NetworkShares        — accessible shares + admin shares
        7. CachedCredentials    — domain credential caching
        8. PTHMitigations       — Credential Guard, Protected Users
        9. DomainContext        — domain trust visibility, lockout policy
       10. Findings             — consolidated risk-rated findings
#>
[CmdletBinding()]
param([string]$OutDir = 'C:\LateralMovement')

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
    try { $v = (Get-ItemProperty $Path -Name $Name -ErrorAction Stop).$Name; return $v }
    catch { return $Default }
}

$script:XDoc = New-Object System.Xml.XmlDocument
$script:XDoc.AppendChild($script:XDoc.CreateXmlDeclaration('1.0', 'UTF-8', $null)) | Out-Null
$root = $script:XDoc.CreateElement('LateralMovementAudit')
$script:XDoc.AppendChild($root) | Out-Null

Write-Host ' =================================================='
Write-Host '  LateralMovement-Windows.ps1'
Write-Host ' =================================================='

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning 'Not running as Administrator — some registry reads may fail.' }

$metaEl = New-XElem $root 'Metadata'
New-XElem $metaEl 'Hostname'     $env:COMPUTERNAME | Out-Null
New-XElem $metaEl 'Domain'       $env:USERDOMAIN   | Out-Null
New-XElem $metaEl 'Username'     $identity.Name    | Out-Null
New-XElem $metaEl 'IsAdmin'      ([string]$isAdmin) | Out-Null
New-XElem $metaEl 'Timestamp'    (Get-Date -Format 'o') | Out-Null
$cs = Get-WmiObject Win32_ComputerSystem
New-XElem $metaEl 'DomainJoined' ([string]$cs.PartOfDomain) | Out-Null
New-XElem $metaEl 'DomainName'   $cs.Domain | Out-Null

# ==================================================================
# 1. SMB CONFIGURATION
# ==================================================================
Write-Host '[*] Checking SMB configuration...'
$smbEl = New-XElem $root 'SMBConfiguration'

# SMB Signing
$srvBase    = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$wksBase    = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$srvSign    = Get-RegValue $srvBase 'RequireSecuritySignature' 0
$wksSign    = Get-RegValue $wksBase 'RequireSecuritySignature' 0
$srvEnable  = Get-RegValue $srvBase 'EnableSecuritySignature' 0
$wksEnable  = Get-RegValue $wksBase 'EnableSecuritySignature' 0

$smbSignEl = New-XElem $smbEl 'Signing'
New-XElem $smbSignEl 'ServerRequired'  ([string]$srvSign)   | Out-Null
New-XElem $smbSignEl 'ServerEnabled'   ([string]$srvEnable) | Out-Null
New-XElem $smbSignEl 'ClientRequired'  ([string]$wksSign)   | Out-Null
New-XElem $smbSignEl 'ClientEnabled'   ([string]$wksEnable) | Out-Null

if ($srvSign -ne 1) {
    Add-Finding 'CRITICAL' 'SMBSigningNotRequired' \
        "SMB server does not require signing (RequireSecuritySignature=0) — NTLM relay attacks possible (Responder + ntlmrelayx)" \
        'HKLM\...\LanmanServer\Parameters\RequireSecuritySignature=0'
}
if ($wksSign -ne 1) {
    Add-Finding 'HIGH' 'SMBClientSigningNotRequired' \
        "SMB client does not require signing — client will connect to rogue SMB servers without signature verification" \
        'HKLM\...\LanmanWorkstation\Parameters\RequireSecuritySignature=0'
}

# SMBv1 (EternalBlue + general insecurity)
$smb1 = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' $null
# On older systems (Win7), SMBv1 is enabled by default with no registry key
$smb1Enabled = ($null -eq $smb1 -or $smb1 -ne 0)
New-XElem $smbEl 'SMBv1Enabled' ([string]$smb1Enabled) | Out-Null
if ($smb1Enabled) {
    Add-Finding 'CRITICAL' 'SMBv1Enabled' \
        "SMBv1 is enabled — unencrypted, deprecated, and vulnerable to EternalBlue (MS17-010) if unpatched" \
        'SMB1 not disabled via registry or feature removal'
}

# NTLM Authentication settings
$lsaPath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lmCompat   = Get-RegValue $lsaPath 'LmCompatibilityLevel' $null
$ntlmEl     = New-XElem $smbEl 'NTLMSettings'
New-XElem $ntlmEl 'LmCompatibilityLevel' ([string]$lmCompat) | Out-Null

$ntlmDesc = switch ($lmCompat) {
    0 { 'LM + NTLM — send LM/NTLM responses; accept LM/NTLM/NTLMv2 (most permissive, very insecure)' }
    1 { 'NTLM — use NTLM v2 session security if negotiated; send LM/NTLM' }
    2 { 'NTLM only — send NTLM response only; accept LM/NTLM/NTLMv2' }
    3 { 'NTLMv2 — send NTLMv2 only; accept LM/NTLM/NTLMv2' }
    4 { 'NTLMv2 — send NTLMv2 only; domain controllers refuse LM' }
    5 { 'NTLMv2 only — send NTLMv2 only; refuse LM/NTLM (most secure)' }
    default { "Unknown level $lmCompat (or not configured — default behavior varies by OS)" }
}
New-XElem $ntlmEl 'Description' $ntlmDesc | Out-Null

if ($null -eq $lmCompat -or $lmCompat -lt 3) {
    Add-Finding 'CRITICAL' 'NTLMv1Allowed' \
        "LmCompatibilityLevel=$lmCompat — NTLMv1 accepted; hashes crackable with precomputed rainbow tables in seconds" \
        "LmCompatibilityLevel=$lmCompat (should be 5)"
}

# ==================================================================
# 2. POISONING VECTORS (LLMNR, NBT-NS, mDNS, WPAD)
# ==================================================================
Write-Host '[*] Checking name resolution poisoning vectors...'
$poisonEl = New-XElem $root 'PoisoningVectors'

# LLMNR — Link-Local Multicast Name Resolution
$llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$llmnr     = Get-RegValue $llmnrPath 'EnableMulticast' $null
# No policy set = LLMNR enabled by default
$llmnrEnabled = ($null -eq $llmnr -or $llmnr -ne 0)
$llmnrEl  = New-XElem $poisonEl 'LLMNR'
New-XElem $llmnrEl 'PolicyValue' ([string]$llmnr) | Out-Null
New-XElem $llmnrEl 'Enabled'     ([string]$llmnrEnabled) | Out-Null
if ($llmnrEnabled) {
    Add-Finding 'HIGH' 'LLMNREnabled' \
        "LLMNR enabled (no DisableMulticast policy) — Responder can poison link-local multicast resolution to capture NTLMv2 hashes" \
        'HKLM\SOFTWARE\Policies\...\DNSClient\EnableMulticast not set to 0'
}

# NBT-NS — NetBIOS Name Service
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
$nbtnsAny = $false
$nbtEl    = New-XElem $poisonEl 'NBTNS'
foreach ($a in $adapters) {
    $nbt = $a.TcpipNetbiosOptions
    # 0 = via DHCP, 1 = enabled, 2 = disabled
    $nbtEnabled = ($nbt -ne 2)
    if ($nbtEnabled) { $nbtnsAny = $true }
    $adEl = New-XElem $nbtEl 'Adapter'
    New-XElem $adEl 'Description' $a.Description      | Out-Null
    New-XElem $adEl 'NBTOption'   ([string]$nbt)       | Out-Null
    New-XElem $adEl 'Enabled'     ([string]$nbtEnabled) | Out-Null
}
if ($nbtnsAny) {
    Add-Finding 'HIGH' 'NBTNSEnabled' \
        "NBT-NS enabled on one or more adapters — Responder can respond to NetBIOS name queries to capture NTLMv2 hashes" \
        'Win32_NetworkAdapterConfiguration TcpipNetbiosOptions != 2'
}

# mDNS (Windows 10/11 feature)
$mdnsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
$mdns     = Get-RegValue $mdnsPath 'EnableMDNS' $null
$mdnsEl   = New-XElem $poisonEl 'mDNS'
New-XElem $mdnsEl 'Value'   ([string]$mdns) | Out-Null
New-XElem $mdnsEl 'Enabled' ([string]($null -eq $mdns -or $mdns -ne 0)) | Out-Null

# WPAD — Web Proxy Auto-Detection
$wpadIE    = Get-RegValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' 'AutoDetect' 1
$wpadPolicy = Get-RegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' 'AutoDetect' $null
$wpadEl    = New-XElem $poisonEl 'WPAD'
New-XElem $wpadEl 'IEAutoDetect'    ([string]$wpadIE)      | Out-Null
New-XElem $wpadEl 'PolicyAutoDetect' ([string]$wpadPolicy) | Out-Null
if ($wpadIE -eq 1 -or ($null -eq $wpadPolicy)) {
    Add-Finding 'HIGH' 'WPADEnabled' \
        "WPAD auto-detection enabled — rogue WPAD server can proxy all HTTP/S traffic (mitm6 or Responder WPAD attacks)" \
        'IE AutoDetect=1 or no policy disabling it'
}

# ==================================================================
# 3. IPv6 EXPOSURE
# ==================================================================
Write-Host '[*] Checking IPv6 configuration...'
$ipv6El = New-XElem $root 'IPv6Exposure'

$ipv6Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {
    $_.IPEnabled -and $_.IPAddress -match ':'
}
New-XElem $ipv6El 'IPv6AdapterCount' ([string]@($ipv6Adapters).Count) | Out-Null

# Check DisabledComponents registry key
$ipv6Disabled = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' 'DisabledComponents' $null
New-XElem $ipv6El 'DisabledComponents' ([string]$ipv6Disabled) | Out-Null

if (@($ipv6Adapters).Count -gt 0 -and $ipv6Disabled -ne 0xFF) {
    Add-Finding 'HIGH' 'IPv6Enabled' \
        "IPv6 active on $(@($ipv6Adapters).Count) adapter(s) — mitm6 attack: rogue DHCPv6 server can set attacker as IPv6 DNS, poisoning WPAD/domain lookups for NTLM relay" \
        "IPv6 active; DisabledComponents=$ipv6Disabled"
}

# ==================================================================
# 4. RDP CONFIGURATION
# ==================================================================
Write-Host '[*] Checking RDP configuration...'
$rdpBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpEl   = New-XElem $root 'RDPConfiguration'

$rdpEnabled    = Get-RegValue $rdpBase 'fDenyTSConnections' 1
$nlaRequired   = Get-RegValue "$rdpBase\WinStations\RDP-Tcp" 'UserAuthentication' 0
$encLevel      = Get-RegValue "$rdpBase\WinStations\RDP-Tcp" 'MinEncryptionLevel' 0
$rdpPort       = Get-RegValue "$rdpBase\WinStations\RDP-Tcp" 'PortNumber' 3389
$restrictAdmin = Get-RegValue 'HKLM:\System\CurrentControlSet\Control\Lsa' 'DisableRestrictedAdmin' 1

New-XElem $rdpEl 'Enabled'             ([string]($rdpEnabled -eq 0)) | Out-Null
New-XElem $rdpEl 'Port'                ([string]$rdpPort)            | Out-Null
New-XElem $rdpEl 'NLARequired'         ([string]$nlaRequired)        | Out-Null
New-XElem $rdpEl 'MinEncryptionLevel'  ([string]$encLevel)           | Out-Null
New-XElem $rdpEl 'RestrictedAdminMode' ([string]($restrictAdmin -eq 0)) | Out-Null

if ($rdpEnabled -eq 0) {
    if ($nlaRequired -ne 1) {
        Add-Finding 'HIGH' 'RDPNoNLA' \
            "RDP enabled without NLA (UserAuthentication=0) — pre-authentication attacks possible (e.g. BlueKeep on unpatched systems, credential brute force without account lockout)" \
            'fDenyTSConnections=0, UserAuthentication=0'
    }
    if ($restrictAdmin -ne 0) {
        Add-Finding 'MEDIUM' 'RDPRestrictedAdminDisabled' \
            "RestrictedAdmin RDP mode not enabled — credentials sent to remote host during RDP login (harvestable if host is compromised)" \
            'DisableRestrictedAdmin=1'
    }
    if ($encLevel -lt 3) {
        Add-Finding 'MEDIUM' 'RDPWeakEncryption' \
            "RDP MinEncryptionLevel=$encLevel — below High (3); traffic may be captured and downgrade attacks possible" \
            "MinEncryptionLevel=$encLevel"
    }
}

# ==================================================================
# 5. WINRM CONFIGURATION
# ==================================================================
Write-Host '[*] Checking WinRM...'
$winrmEl = New-XElem $root 'WinRMConfiguration'

$winrmSvc = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq 'WinRM' }
$winrmRunning = $winrmSvc -and $winrmSvc.State -eq 'Running'
New-XElem $winrmEl 'ServiceState' ($winrmSvc.State) | Out-Null
New-XElem $winrmEl 'Running'      ([string]$winrmRunning) | Out-Null

if ($winrmRunning) {
    $winrmCfg = & winrm get winrm/config/service 2>$null
    $winrmCfgStr = $winrmCfg -join "`n"
    $allowUnencrypted = $winrmCfgStr -match 'AllowUnencrypted\s*=\s*true'
    New-XElem $winrmEl 'AllowUnencrypted' ([string]$allowUnencrypted) | Out-Null
    New-XElem $winrmEl 'Config' ($winrmCfgStr) | Out-Null
    Add-Finding 'MEDIUM' 'WinRMEnabled' \
        "WinRM (PSRemoting) service is running — lateral movement via Enter-PSSession/Invoke-Command if credentials obtained" \
        'WinRM service Running'
    if ($allowUnencrypted) {
        Add-Finding 'HIGH' 'WinRMUnencrypted' \
            "WinRM configured to allow unencrypted connections — credentials and session data transmitted in cleartext" \
            'AllowUnencrypted=true'
    }
}

# ==================================================================
# 6. NETWORK SHARES
# ==================================================================
Write-Host '[*] Enumerating network shares...'
$sharesEl = New-XElem $root 'NetworkShares'

$shares = Get-WmiObject Win32_Share
foreach ($share in $shares) {
    $shareEl = New-XElem $sharesEl 'Share'
    New-XElem $shareEl 'Name'        $share.Name        | Out-Null
    New-XElem $shareEl 'Path'        $share.Path        | Out-Null
    New-XElem $shareEl 'Description' $share.Description | Out-Null
    New-XElem $shareEl 'Type'        ([string]$share.Type) | Out-Null
    # Type: 0=disk, 1=print, 2=comm device, 2147483648=special, 2147483651=IPC
    $isAdmin = $share.Name -match '^\w\$|^ADMIN\$|^IPC\$'
    $shareEl.SetAttribute('admin', [string]$isAdmin)
    if ($isAdmin) {
        Add-Finding 'INFO' 'AdminSharePresent' \
            "Default admin share '$($share.Name)' active — accessible to admins for lateral movement (PsExec, WMI)" $share.Name
    }
}

# ==================================================================
# 7. CACHED DOMAIN CREDENTIALS
# ==================================================================
Write-Host '[*] Checking cached domain credential count...'
$cachedEl = New-XElem $root 'CachedCredentials'

$cachedCount = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'CachedLogonsCount' 10
New-XElem $cachedEl 'CachedLogonsCount' ([string]$cachedCount) | Out-Null

if ([int]$cachedCount -gt 0) {
    Add-Finding 'MEDIUM' 'DomainCredentialsCached' \
        "CachedLogonsCount=$cachedCount — domain credential hashes stored locally; extractable from HKLM\SECURITY hive (requires SYSTEM)" \
        "CachedLogonsCount=$cachedCount"
}
if ([int]$cachedCount -eq 0) {
    New-XElem $cachedEl 'Note' 'CachedLogonsCount=0 — no domain credentials cached locally (hardened)' | Out-Null
}

# ==================================================================
# 8. PASS-THE-HASH MITIGATIONS
# ==================================================================
Write-Host '[*] Checking PtH mitigations...'
$pthEl = New-XElem $root 'PTHMitigations'

# Credential Guard
$lsaCfg  = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LsaCfgFlags' 0
$vbsOn   = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' 'EnableVirtualizationBasedSecurity' 0
$cgActive = ($lsaCfg -ge 1) -and ($vbsOn -eq 1)
New-XElem $pthEl 'CredentialGuardActive'   ([string]$cgActive)  | Out-Null
New-XElem $pthEl 'LsaCfgFlags'             ([string]$lsaCfg)    | Out-Null
New-XElem $pthEl 'VBSEnabled'              ([string]$vbsOn)     | Out-Null

if (-not $cgActive) {
    Add-Finding 'HIGH' 'CredentialGuardInactive' \
        "Credential Guard not active — NTLM hashes in LSASS are accessible for Pass-the-Hash after dump (Mimikatz, Pypykatz)" \
        'LsaCfgFlags or VBS not configured'
}

# Protected Users group (requires domain query)
$protectedUsersNote = 'Protected Users group check requires domain connectivity and RSAT'
New-XElem $pthEl 'ProtectedUsersNote' $protectedUsersNote | Out-Null

# Local account PtH: KB2871997 — disable local account PtH for non-RID500 accounts
$laTFP = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy' $null
New-XElem $pthEl 'LocalAccountTokenFilterPolicy' ([string]$laTFP) | Out-Null
if ($laTFP -eq 1) {
    Add-Finding 'HIGH' 'LocalAccountPTHEnabled' \
        "LocalAccountTokenFilterPolicy=1 — remote Pass-the-Hash using local admin hashes is unrestricted; any local admin hash grants full remote access" \
        'LocalAccountTokenFilterPolicy=1'
}

# ==================================================================
# 9. DOMAIN CONTEXT
# ==================================================================
Write-Host '[*] Gathering domain context...'
$domEl = New-XElem $root 'DomainContext'

if ($cs.PartOfDomain) {
    # Domain password/lockout policy
    $netAccountsOut = & net accounts /domain 2>$null
    $domPolicyStr = $netAccountsOut -join "`n"
    New-XElem $domEl 'AccountPolicy' $domPolicyStr | Out-Null

    # Parse lockout threshold for spray assessment
    $lockoutThreshold = if ($domPolicyStr -match 'Lockout threshold:\s*(\d+|Never)') { $matches[1] } else { 'Unknown' }
    $lockoutWindow    = if ($domPolicyStr -match 'Lockout observation window.*?:\s*(\d+)') { $matches[1] } else { 'Unknown' }
    New-XElem $domEl 'LockoutThreshold'       $lockoutThreshold | Out-Null
    New-XElem $domEl 'LockoutObservationMins' $lockoutWindow    | Out-Null

    if ($lockoutThreshold -eq 'Never' -or $lockoutThreshold -eq '0') {
        Add-Finding 'CRITICAL' 'NoAccountLockout' \
            "Domain has no account lockout policy — unlimited password spray / brute force attempts without lockout risk" \
            'Lockout threshold: Never'
    }

    # Domain trust info
    $trustOut = & nltest /domain_trusts 2>$null
    if ($trustOut) {
        New-XElem $domEl 'DomainTrusts' ($trustOut -join "`n") | Out-Null
    }
} else {
    New-XElem $domEl 'Note' 'Machine is not domain-joined — domain-specific checks skipped' | Out-Null
}

# ==================================================================
# 10. CONSOLIDATED FINDINGS
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
$outFile = Join-Path $OutDir "LateralMovement_$($env:COMPUTERNAME)_${ts}.xml"

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
