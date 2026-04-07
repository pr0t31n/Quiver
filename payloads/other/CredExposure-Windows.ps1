<#
.SYNOPSIS
    CredExposure-Windows.ps1 — Credential exposure assessment for Windows
.DESCRIPTION
    Finds credentials already accessible without cracking: Credential Manager,
    registry-embedded passwords (WDigest, AutoLogon), unattend files, GPP
    cpassword in SYSVOL, unprotected SSH keys, cloud credentials, git stores,
    and browser credential profile indicators.
    Run as the TARGET USER — not pre-elevated — for their exposure profile.
.PARAMETER OutDir
    Output directory. Default: C:\CredExposure
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File CredExposure-Windows.ps1
.NOTES
    Target  : Windows 7 SP1+ (PowerShell 3.0+)
    Author  : [Operator]
    Sections:
        1. CredentialManager    — cmdkey entries
        2. RegistryExposure     — WDigest, AutoLogon, LSA protection, LAPS
        3. UnattendFiles        — sysprep/unattend XML with embedded passwords
        4. GPPPasswords         — Group Policy Preferences cpassword in SYSVOL
        5. SSHPrivateKeys       — unencrypted keys in %USERPROFILE%\.ssh
        6. CloudCredentials     — AWS/GCP/Azure credential files
        7. GitCredentials       — .git-credentials and credential helper config
        8. BrowserProfiles      — credential store existence indicators
        9. Findings             — consolidated risk-rated findings
#>
[CmdletBinding()]
param([string]$OutDir = 'C:\CredExposure')

$ErrorActionPreference = 'SilentlyContinue'

# ==================================================================
# XML HELPERS  (same pattern as SysAudit.ps1)
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

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}

# ==================================================================
# INITIALISE XML DOCUMENT
# ==================================================================
$script:XDoc = New-Object System.Xml.XmlDocument
$script:XDoc.AppendChild($script:XDoc.CreateXmlDeclaration('1.0', 'UTF-8', $null)) | Out-Null
$root = $script:XDoc.CreateElement('CredentialExposure')
$script:XDoc.AppendChild($root) | Out-Null

Write-Host ' =================================================='
Write-Host '  CredExposure-Windows.ps1'
Write-Host ' =================================================='

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$metaEl   = New-XElem $root 'Metadata'
New-XElem $metaEl 'Hostname'   $env:COMPUTERNAME | Out-Null
New-XElem $metaEl 'Domain'     $env:USERDOMAIN   | Out-Null
New-XElem $metaEl 'Username'   $identity.Name    | Out-Null
New-XElem $metaEl 'Timestamp'  (Get-Date -Format 'o') | Out-Null
$os = Get-WmiObject Win32_OperatingSystem
New-XElem $metaEl 'OS' "$($os.Caption)" | Out-Null
$isDomain = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
New-XElem $metaEl 'DomainJoined' ([string]$isDomain) | Out-Null

# ==================================================================
# 1. WINDOWS CREDENTIAL MANAGER
# ==================================================================
Write-Host '[*] Enumerating Windows Credential Manager...'
$cmEl = New-XElem $root 'CredentialManager'
$cmdkeyOut = & cmdkey /list 2>$null
$cmTarget  = $null
$cmCount   = 0
foreach ($line in $cmdkeyOut) {
    if ($line -match 'Target:\s*(.+)') {
        $cmTarget = $matches[1].Trim()
    } elseif ($line -match 'Type:\s*(.+)' -and $cmTarget) {
        $cmType = $matches[1].Trim()
        $entEl  = New-XElem $cmEl 'Entry'
        New-XElem $entEl 'Target' $cmTarget | Out-Null
        New-XElem $entEl 'Type'   $cmType   | Out-Null
        $cmCount++
        Add-Finding 'HIGH' 'CredentialManagerEntry' \
            "Stored credential: '$cmTarget' ($cmType) — may be extractable via Mimikatz dpapi::cred or PowerShell SecretManagement" $cmTarget
        $cmTarget = $null
    }
}
$cmEl.SetAttribute('count', [string]$cmCount)

# ==================================================================
# 2. REGISTRY EXPOSURE
# ==================================================================
Write-Host '[*] Checking registry for credential exposure...'
$regEl = New-XElem $root 'RegistryExposure'

# 2a. WDigest — if enabled, Windows caches cleartext password in LSASS
$wdigestVal = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
$wdigEl = New-XElem $regEl 'WDigest'
New-XElem $wdigEl 'UseLogonCredential' ([string]$wdigestVal) | Out-Null
$wdigEnabled = $wdigestVal -eq 1
New-XElem $wdigEl 'PlaintextInLSASS' ([string]$wdigEnabled) | Out-Null
if ($wdigEnabled) {
    Add-Finding 'CRITICAL' 'WDigestEnabled' \
        'WDigest UseLogonCredential=1 — current user plaintext password is cached in LSASS memory; extractable via Mimikatz sekurlsa::wdigest' \
        'HKLM\SYSTEM\...\WDigest\UseLogonCredential=1'
} else {
    New-XElem $wdigEl 'Note' 'WDigest disabled (UseLogonCredential=0 or not set) — no plaintext in LSASS via WDigest' | Out-Null
}

# 2b. AutoLogon — may store cleartext password in registry
$winlogonPath   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$autoAdminLogon = Get-RegValue $winlogonPath 'AutoAdminLogon'
$defaultUser    = Get-RegValue $winlogonPath 'DefaultUserName'
$defaultDomain  = Get-RegValue $winlogonPath 'DefaultDomainName'
$defaultPass    = Get-RegValue $winlogonPath 'DefaultPassword'
$altPass        = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AltDefaultPassword'

$alEl = New-XElem $regEl 'AutoLogon'
New-XElem $alEl 'AutoAdminLogon'   ([string]$autoAdminLogon)  | Out-Null
New-XElem $alEl 'DefaultUserName'  ([string]$defaultUser)     | Out-Null
New-XElem $alEl 'DefaultDomain'    ([string]$defaultDomain)   | Out-Null
New-XElem $alEl 'PasswordPresent'  ([string]($null -ne $defaultPass -and $defaultPass -ne '')) | Out-Null

if ($autoAdminLogon -eq '1') {
    Add-Finding 'HIGH' 'AutoLogonEnabled' \
        "AutoAdminLogon=1 for user '$defaultUser' — anyone with physical or local access can read the plaintext password from registry" \
        'HKLM\...\Winlogon\AutoAdminLogon=1'
}
if ($null -ne $defaultPass -and $defaultPass -ne '') {
    Add-Finding 'CRITICAL' 'AutoLogonPlaintextPassword' \
        "AutoLogon DefaultPassword value is populated in registry — plaintext credential present" \
        'HKLM\...\Winlogon\DefaultPassword'
}

# 2c. LSA Protection (RunAsPPL) — if absent/0, LSASS can be dumped
$lsaPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$runAsPPL = Get-RegValue $lsaPath 'RunAsPPL'
$lsaEl    = New-XElem $regEl 'LSAProtection'
New-XElem $lsaEl 'RunAsPPL' ([string]$runAsPPL) | Out-Null
if ($runAsPPL -ne 1) {
    New-XElem $lsaEl 'Note' 'LSA not running as Protected Process Light — LSASS memory dump possible (e.g. Task Manager, procdump, Mimikatz)' | Out-Null
    Add-Finding 'HIGH' 'LSAProtectionDisabled' \
        'RunAsPPL not enabled — LSASS process can be memory-dumped for credential extraction' \
        'HKLM\SYSTEM\...\Lsa\RunAsPPL not set to 1'
} else {
    New-XElem $lsaEl 'Note' 'LSA Protected Process Light active — standard LSASS dump methods blocked' | Out-Null
}

# 2d. Credential Guard
$cgPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsaCfg   = Get-RegValue $cgPath 'LsaCfgFlags'
$vbsPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$vbsEnabled = Get-RegValue $vbsPath 'EnableVirtualizationBasedSecurity'
$cgEl     = New-XElem $regEl 'CredentialGuard'
New-XElem $cgEl 'LsaCfgFlags'  ([string]$lsaCfg)    | Out-Null
New-XElem $cgEl 'VBSEnabled'   ([string]$vbsEnabled) | Out-Null
$cgActive = ($lsaCfg -eq 1 -or $lsaCfg -eq 2) -and ($vbsEnabled -eq 1)
New-XElem $cgEl 'Active' ([string]$cgActive) | Out-Null
if (-not $cgActive) {
    Add-Finding 'MEDIUM' 'CredentialGuardInactive' \
        'Credential Guard not active — NTLM hashes and Kerberos tickets in LSASS are accessible if process can be dumped' \
        'LsaCfgFlags + EnableVirtualizationBasedSecurity not both set'
}

# 2e. LAPS deployment indicator
$lapsPath    = 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
$lapsDllPath = 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
$lapsEnabled = (Get-RegValue $lapsPath 'AdmPwdEnabled') -eq 1
$lapsDll     = Test-Path $lapsDllPath
$lapsEl      = New-XElem $regEl 'LAPS'
New-XElem $lapsEl 'PolicyEnabled' ([string]$lapsEnabled) | Out-Null
New-XElem $lapsEl 'DLLPresent'    ([string]$lapsDll)     | Out-Null
if (-not $lapsEnabled -and -not $lapsDll) {
    Add-Finding 'HIGH' 'LAPSNotDeployed' \
        'LAPS not detected — local Administrator password is likely static and shared across machines (pass-the-hash/spray risk)' \
        'No AdmPwd.dll or AdmPwdEnabled policy'
}

# 2f. LocalAccountTokenFilterPolicy (already flagged in PrivescAudit but relevant here too)
$lATFP = Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'LocalAccountTokenFilterPolicy'
New-XElem $regEl 'LocalAccountTokenFilterPolicy' ([string]$lATFP) | Out-Null

# ==================================================================
# 3. UNATTEND / SYSPREP FILES
# ==================================================================
Write-Host '[*] Searching for unattend/sysprep files...'
$uaEl = New-XElem $root 'UnattendFiles'

$unattendPaths = @(
    'C:\Windows\Panther\Unattend.xml',
    'C:\Windows\Panther\Unattended.xml',
    'C:\Windows\Panther\unattend\Unattend.xml',
    'C:\Windows\system32\sysprep\sysprep.xml',
    'C:\Windows\system32\sysprep\Unattended.xml',
    'C:\Windows\system32\sysprep\panther\Unattend.xml',
    'C:\Windows\setup\scripts\setup.cmd',
    'C:\sysprep\sysprep.xml',
    'C:\sysprep\sysprep.inf',
    'C:\sysprep.inf'
)

foreach ($p in $unattendPaths) {
    if (-not (Test-Path $p -PathType Leaf)) { continue }
    $content      = Get-Content $p -Raw -ErrorAction SilentlyContinue
    $hasPassword  = $content -match 'Password|AutoLogon|AdministratorPassword' 2>$null
    $fEl          = New-XElem $uaEl 'File'
    New-XElem $fEl 'Path'        $p                   | Out-Null
    New-XElem $fEl 'HasPassword' ([string]$hasPassword) | Out-Null
    if ($hasPassword) {
        Add-Finding 'CRITICAL' 'UnattendFileWithPassword' \
            "Sysprep/Unattend file contains password-related fields — may have plaintext admin password (base64 or clear): $p" $p
    } else {
        Add-Finding 'MEDIUM' 'UnattendFilePresent' \
            "Sysprep/Unattend file found (no obvious password fields): $p" $p
    }
}

# ==================================================================
# 4. GPP PASSWORDS (cpassword in SYSVOL)
# ==================================================================
Write-Host '[*] Searching SYSVOL for GPP cpassword...'
$gppEl = New-XElem $root 'GPPPasswords'
$gppCount = 0

if ($isDomain) {
    $domain    = $env:USERDNSDOMAIN
    $sysvolPath = "\\$domain\SYSVOL"
    if (Test-Path $sysvolPath) {
        $gppFiles = @('Groups.xml','Services.xml','ScheduledTasks.xml',
                      'DataSources.xml','Printers.xml','Drives.xml')
        foreach ($fname in $gppFiles) {
            $found = Get-ChildItem $sysvolPath -Recurse -Filter $fname -ErrorAction SilentlyContinue
            foreach ($f in $found) {
                $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
                if ($content -match 'cpassword="([^"]+)"') {
                    $gppEl2 = New-XElem $gppEl 'GPPFile'
                    New-XElem $gppEl2 'Path'      $f.FullName | Out-Null
                    New-XElem $gppEl2 'Type'      $fname      | Out-Null
                    New-XElem $gppEl2 'HasCpassword' 'true'   | Out-Null
                    Add-Finding 'CRITICAL' 'GPPCpassword' \
                        "GPP cpassword found in '$($f.FullName)' — AES-256 key is publicly known; decrypt with gpp-decrypt or PowerSploit Get-GPPPassword" \
                        $f.FullName
                    $gppCount++
                }
            }
        }
    } else {
        New-XElem $gppEl 'Note' "SYSVOL unreachable at $sysvolPath" | Out-Null
    }
} else {
    New-XElem $gppEl 'Note' 'Not domain-joined — SYSVOL check skipped' | Out-Null
}
$gppEl.SetAttribute('count', [string]$gppCount)

# ==================================================================
# 5. SSH PRIVATE KEYS
# ==================================================================
Write-Host '[*] Scanning SSH directory for private keys...'
$sshEl  = New-XElem $root 'SSHPrivateKeys'
$sshDir = Join-Path $env:USERPROFILE '.ssh'

if (Test-Path $sshDir) {
    $keyFiles = Get-ChildItem $sshDir -File | Where-Object {
        $_.Name -notlike '*.pub' -and $_.Name -ne 'known_hosts' -and $_.Name -ne 'config'
    }
    foreach ($kf in $keyFiles) {
        $content     = Get-Content $kf.FullName -ErrorAction SilentlyContinue
        $isKey       = ($content -join '') -match 'PRIVATE KEY'
        if (-not $isKey) { continue }
        $isEncrypted = ($content -join '') -match 'ENCRYPTED|Proc-Type.*ENCRYPTED'
        $kEl = New-XElem $sshEl 'Key'
        New-XElem $kEl 'Path'      $kf.FullName         | Out-Null
        New-XElem $kEl 'Name'      $kf.Name              | Out-Null
        New-XElem $kEl 'Encrypted' ([string]$isEncrypted) | Out-Null
        if (-not $isEncrypted) {
            Add-Finding 'CRITICAL' 'UnencryptedSSHKey' \
                "SSH private key has no passphrase — usable immediately: $($kf.FullName)" $kf.FullName
        }
    }
} else {
    New-XElem $sshEl 'Note' '.ssh directory not found' | Out-Null
}

# ==================================================================
# 6. CLOUD CREDENTIALS
# ==================================================================
Write-Host '[*] Checking cloud credential files...'
$cloudEl = New-XElem $root 'CloudCredentials'

$cloudFiles = [ordered]@{
    'AWS credentials'           = "$env:USERPROFILE\.aws\credentials"
    'AWS config'                = "$env:USERPROFILE\.aws\config"
    'GCP app-default creds'     = "$env:APPDATA\gcloud\application_default_credentials.json"
    'GCP credentials'           = "$env:APPDATA\gcloud\credentials.json"
    'Azure profile'             = "$env:USERPROFILE\.azure\azureProfile.json"
    'Azure token cache'         = "$env:USERPROFILE\.azure\msal_token_cache.json"
    'Terraform credentials'     = "$env:APPDATA\terraform.d\credentials.tfrc.json"
    'Vault token'               = "$env:USERPROFILE\.vault-token"
    'DigitalOcean config'       = "$env:USERPROFILE\.config\doctl\config.yaml"
}

foreach ($desc in $cloudFiles.Keys) {
    $f = $cloudFiles[$desc]
    if (-not (Test-Path $f -PathType Leaf)) { continue }
    $content   = Get-Content $f -Raw -ErrorAction SilentlyContinue
    $hasKey    = $content -match 'aws_access_key|aws_secret|client_secret|refresh_token|access_token|private_key|password|token'
    $sizeBytes = (Get-Item $f).Length
    $cfEl      = New-XElem $cloudEl 'CredentialFile'
    New-XElem $cfEl 'Description' $desc           | Out-Null
    New-XElem $cfEl 'Path'        $f              | Out-Null
    New-XElem $cfEl 'SizeBytes'   ([string]$sizeBytes) | Out-Null
    New-XElem $cfEl 'ContainsKeyMaterial' ([string]$hasKey) | Out-Null
    $risk = if ($hasKey) { 'CRITICAL' } else { 'MEDIUM' }
    Add-Finding $risk 'CloudCredentialFile' "Cloud credential file found: $f ($desc)" $f
}

# ==================================================================
# 7. GIT CREDENTIALS
# ==================================================================
Write-Host '[*] Checking git credential stores...'
$gitEl = New-XElem $root 'GitCredentials'

$gitCreds = @(
    "$env:USERPROFILE\.git-credentials",
    "$env:APPDATA\.git-credentials"
)
foreach ($gcf in $gitCreds) {
    if (-not (Test-Path $gcf -PathType Leaf)) { continue }
    $lines = (Get-Content $gcf -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
    $gcEl  = New-XElem $gitEl 'PlaintextStore'
    New-XElem $gcEl 'Path'       $gcf          | Out-Null
    New-XElem $gcEl 'EntryCount' ([string]$lines) | Out-Null
    if ($lines -gt 0) {
        Add-Finding 'CRITICAL' 'GitPlaintextCredentials' \
            "Git plaintext credential store with $lines entr(ies) — contains https://user:PAT@github.com style credentials: $gcf" $gcf
    }
}

$gitConfigPaths = @("$env:USERPROFILE\.gitconfig", "$env:PROGRAMDATA\Git\config")
foreach ($gcfg in $gitConfigPaths) {
    if (-not (Test-Path $gcfg)) { continue }
    $content = Get-Content $gcfg -Raw -ErrorAction SilentlyContinue
    $helper  = if ($content -match 'helper\s*=\s*(.+)') { $matches[1].Trim() } else { '' }
    $gcfgEl  = New-XElem $gitEl 'GitConfig'
    New-XElem $gcfgEl 'Path'             $gcfg   | Out-Null
    New-XElem $gcfgEl 'CredentialHelper' $helper  | Out-Null
    if ($helper -match 'store') {
        Add-Finding 'HIGH' 'GitCredentialStoreHelper' \
            "Git configured with 'store' credential helper (plaintext on disk): $gcfg" $gcfg
    }
}

# ==================================================================
# 8. BROWSER CREDENTIAL PROFILE INDICATORS
# ==================================================================
Write-Host '[*] Checking browser credential stores...'
$browEl = New-XElem $root 'BrowserProfiles'

$browsers = [ordered]@{
    'Chrome'          = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data"
    'Edge'            = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data"
    'Firefox (profiles)' = "$env:APPDATA\Mozilla\Firefox\Profiles"
    'Brave'           = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
    'Opera'           = "$env:APPDATA\Opera Software\Opera Stable\Login Data"
}
foreach ($b in $browsers.Keys) {
    $p = $browsers[$b]
    if (-not (Test-Path $p)) { continue }
    $bEl = New-XElem $browEl 'Browser'
    New-XElem $bEl 'Name' $b | Out-Null
    New-XElem $bEl 'Path' $p | Out-Null
    Add-Finding 'MEDIUM' 'BrowserCredentialStore' \
        "Browser '$b' credential store present — extractable with tools (e.g. SharpChrome, HackBrowserData) if DPAPI master key accessible: $p" $p
}

# ==================================================================
# 9. CONSOLIDATED FINDINGS
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
$outFile = Join-Path $OutDir "CredExposure_$($env:COMPUTERNAME)_${ts}.xml"

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
