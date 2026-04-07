# =============================================================================
#  Script    : kbtest_win.ps1
#  Purpose   : Staged Windows helper for keyboard-id-spoof-test payload.
#              Reads current spoofed identity from BashBunny:\current_test.txt,
#              enumerates HID / keyboard devices via WMI, and writes the result
#              to BashBunny:\results\<VID>_<PID>.txt.
#  Invoked   : By BB payload.txt via HID keystroke injection (RunAs + direct).
# =============================================================================

# ── Locate BashBunny drive ────────────────────────────────────────────────────
$bb = $null
try {
    $vol = Get-WmiObject Win32_Volume |
           Where-Object { $_.Label -eq 'BashBunny' } |
           Select-Object -First 1
    if ($vol) { $bb = $vol.Name }   # e.g. "E:\"
} catch {}

if (-not $bb) {
    # Fallback: scan drive letters for current_test.txt
    foreach ($l in ([char[]]([char]'D'..[char]'Z'))) {
        $p = "${l}:\current_test.txt"
        if (Test-Path $p) { $bb = "${l}:\"; break }
    }
}

if (-not $bb) { exit 1 }

# ── Read identity written by BB payload ───────────────────────────────────────
$identLine = Get-Content "$bb`current_test.txt" -ErrorAction SilentlyContinue
if (-not $identLine) { $identLine = "UNKNOWN UNKNOWN Unknown Unknown Unknown UNKNOWN" }
$fields    = $identLine -split '\s+'
$vid       = $fields[0]; $pid  = $fields[1]
$mfr       = $fields[2]; $prod = $fields[3]
$ser       = $fields[4]; $mode = if ($fields[5]) { $fields[5] } else { "SPOOFED" }

# ── Query Windows for USB / HID / Keyboard devices ────────────────────────────
$hidDevices = Get-WmiObject Win32_PnPEntity |
              Where-Object { $_.DeviceID -like 'HID\*' -or $_.PNPClass -eq 'Keyboard' } |
              Select-Object Name, DeviceID, Status, Manufacturer, PNPClass |
              Sort-Object PNPClass

$keyboards  = Get-WmiObject Win32_Keyboard |
              Select-Object Description, DeviceID, Layout, Name, Status

$usbCtrlrs  = Get-WmiObject Win32_USBController |
              Select-Object Name, DeviceID, Manufacturer, Status

# ── Build output ──────────────────────────────────────────────────────────────
$ts  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$out = @"
=== Keyboard HID Spoof Validation (Windows) ===
Spoofed VID : $vid
Spoofed PID : $pid
Manufacturer: $mfr
Product     : $prod
Serial      : $ser
Mode        : $mode
Hostname    : $($env:COMPUTERNAME)
Username    : $($env:USERDOMAIN)\$($env:USERNAME)
Timestamp   : $ts
OS          : $((Get-WmiObject Win32_OperatingSystem).Caption)

--- HID / Keyboard PnP Entities ---
$($hidDevices | Format-List | Out-String)

--- Win32_Keyboard Objects ---
$($keyboards | Format-List | Out-String)

--- USB Controllers ---
$($usbCtrlrs | Format-List | Out-String)
"@

# ── Write result to BB STORAGE ─────────────────────────────────────────────────
$resultsDir = "$bb`results"
$null = New-Item -ItemType Directory -Path $resultsDir -Force -ErrorAction SilentlyContinue
$outFile = Join-Path $resultsDir "${vid}_${pid}.txt"
$out | Out-File -FilePath $outFile -Encoding UTF8 -Force
