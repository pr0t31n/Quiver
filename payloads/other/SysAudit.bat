@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1

REM ================================================================
REM  SysAudit.bat
REM  Description : Windows System Configuration Audit Tool
REM  Author      : [Operator]
REM  Compatible  : Windows 7 SP1 and later (x86/x64)
REM  Privileges  : Runs in both elevated and non-elevated contexts.
REM                Admin-only sections are skipped gracefully when
REM                not elevated; errors are annotated in the output.
REM  Output      : C:\SysAudit\SystemAudit_<HOST>_<TIMESTAMP>.xml
REM                C:\SysAudit\GroupPolicy_<HOST>_<TIMESTAMP>.xml
REM
REM  Sections:
REM    1. Operating System & Hardware
REM    2. Installed Updates (QFE/Hotfixes)
REM    3. Security Software (Firewall, AV, UAC)
REM    4. Group Policy (gpresult /X companion file + reference)
REM    5. Local User Accounts
REM    6. Network Adapters & IP Configuration
REM    7. Installed Software
REM         - Registry: HKLM (x64), HKLM (x86/WOW6432Node), HKCU
REM         - WMI: MSI-installed products (wmic product)
REM         Each application record includes: Name, Version,
REM         Publisher, InstallDate, InstallLocation, Source
REM ================================================================

title SysAudit - Windows System Audit

REM ----------------------------------------------------------------
REM PRIVILEGE CHECK
REM ----------------------------------------------------------------
REM Primary method: check for High Mandatory Level SID (S-1-16-12288)
REM which is set when a process is genuinely elevated. This is more
REM reliable than "net session" which can be blocked by security policy.
set "IS_ADMIN=0"
whoami /groups 2>nul | findstr /i "S-1-16-12288" >nul 2>&1
if %errorlevel% equ 0 set "IS_ADMIN=1"

REM Fallback: try net session (may be blocked by Group Policy on some systems)
if "!IS_ADMIN!"=="0" (
    net session >nul 2>&1
    if !errorlevel! equ 0 set "IS_ADMIN=1"
)

REM ----------------------------------------------------------------
REM INITIALISE PATHS
REM ----------------------------------------------------------------
set "AUDIT_ROOT=%~d0\SysAudit"
if not exist "%AUDIT_ROOT%" mkdir "%AUDIT_ROOT%"

REM Use a random suffix to avoid collisions on concurrent runs
set "TMP_D=%TEMP%\sysaudit_%RANDOM%"
mkdir "%TMP_D%" 2>nul

REM Locale-independent timestamp via WMI (format: yyyymmddHHMMSS.ffffff+zzz)
set "TS="
for /f "usebackq skip=1 tokens=1" %%T in (`wmic os get LocalDateTime 2^>nul`) do (
    if not defined TS if not "%%T"=="" set "TS=%%T"
)
if not defined TS set "TS=20000101000000"

set "XMLTS=%TS:~0,4%-%TS:~4,2%-%TS:~6,2%T%TS:~8,2%:%TS:~10,2%:%TS:~12,2%"
set "FILESTAMP=%TS:~0,8%_%TS:~8,6%"

set "OUTFILE=%AUDIT_ROOT%\SystemAudit_%COMPUTERNAME%_%FILESTAMP%.xml"
set "GPRFILE=%AUDIT_ROOT%\GroupPolicy_%COMPUTERNAME%_%FILESTAMP%.xml"
set "LSPFILE=%AUDIT_ROOT%\LocalSecPolicy_%COMPUTERNAME%_%FILESTAMP%.xml"

echo.
echo  ====================================================
echo   SysAudit - Windows System Configuration Audit
echo  ====================================================
echo   Host      : %COMPUTERNAME%
echo   Timestamp : %XMLTS%
echo   Audit XML : %OUTFILE%
echo   GP XML    : %GPRFILE%
echo   LSP XML   : %LSPFILE%
if "!IS_ADMIN!"=="1" (
    echo   Privileges: ELEVATED (full audit)
) else (
    echo   Privileges: STANDARD (partial audit - rerun as admin for full data)
)
echo  ====================================================
echo.

REM ================================================================
REM PHASE 1 - DATA COLLECTION
REM ================================================================

echo [1/8] Collecting OS and hardware information...

wmic os get Caption,Version,BuildNumber,OSArchitecture,CSDVersion,^
    InstallDate,LastBootUpTime,CSName,RegisteredUser,Organization,^
    SerialNumber,FreePhysicalMemory,TotalVisibleMemorySize,^
    SystemDirectory,WindowsDirectory ^
    /format:value > "%TMP_D%\os.txt" 2>nul

wmic computersystem get Manufacturer,Model,SystemType,^
    TotalPhysicalMemory,NumberOfProcessors,^
    DNSHostName,Domain,PartOfDomain,UserName ^
    /format:value > "%TMP_D%\cs.txt" 2>nul

wmic bios get Manufacturer,Name,SMBIOSBIOSVersion,^
    ReleaseDate,SerialNumber ^
    /format:value > "%TMP_D%\bios.txt" 2>nul

REM Multi-record: collected as raw text for CDATA embedding
wmic cpu get DeviceID,Name,MaxClockSpeed,CurrentClockSpeed,^
    NumberOfCores,NumberOfLogicalProcessors,Architecture,^
    AddressWidth,L2CacheSize,L3CacheSize ^
    /format:value > "%TMP_D%\cpu.txt" 2>nul

wmic diskdrive get DeviceID,Model,Size,InterfaceType,^
    MediaType,SerialNumber,Partitions ^
    /format:value > "%TMP_D%\disk.txt" 2>nul

wmic logicaldisk get DeviceID,FileSystem,Size,FreeSpace,^
    VolumeName,DriveType ^
    /format:value > "%TMP_D%\logicaldisk.txt" 2>nul

wmic nic where "NetEnabled=True" get DeviceID,Name,MACAddress,^
    Speed,NetConnectionID,Manufacturer ^
    /format:value > "%TMP_D%\nic.txt" 2>nul

wmic nicconfig where "IPEnabled=True" get Description,IPAddress,^
    IPSubnet,DefaultIPGateway,DNSServerSearchOrder,^
    DHCPEnabled,DHCPServer ^
    /format:value > "%TMP_D%\nicconfig.txt" 2>nul

echo [2/8] Collecting installed updates...

wmic qfe get HotFixID,Description,InstalledOn,InstalledBy,Caption ^
    /format:value > "%TMP_D%\updates.txt" 2>nul

echo [3/8] Collecting security software status...

REM Windows built-in firewall (netsh advfirewall requires admin)
if "!IS_ADMIN!"=="1" netsh advfirewall show allprofiles state > "%TMP_D%\fw_state.txt" 2>nul
if "!IS_ADMIN!"=="1" netsh advfirewall show allprofiles > "%TMP_D%\fw_detail.txt" 2>nul
if "!IS_ADMIN!"=="0" echo ACCESS_DENIED: netsh advfirewall requires administrator privileges. > "%TMP_D%\fw_state.txt"
if "!IS_ADMIN!"=="0" echo ACCESS_DENIED: netsh advfirewall requires administrator privileges. > "%TMP_D%\fw_detail.txt"
if "!IS_ADMIN!"=="0" echo   [WARN] Firewall state collection skipped - not elevated.

REM Third-party security products via SecurityCenter2 WMI namespace
REM Note: SecurityCenter2 is a client Windows feature; not present on Server editions
REM Wmic commands placed on single lines - ^ continuation does not work inside if blocks
if "!IS_ADMIN!"=="0" goto :_secc_skip
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState,pathToSignedProductExe /format:value > "%TMP_D%\av.txt" 2>nul
wmic /namespace:\\root\SecurityCenter2 path FirewallProduct get displayName,productState /format:value > "%TMP_D%\fwprod.txt" 2>nul
wmic /namespace:\\root\SecurityCenter2 path AntiSpywareProduct get displayName,productState /format:value > "%TMP_D%\asp.txt" 2>nul
goto :_secc_done
:_secc_skip
echo ACCESS_DENIED: SecurityCenter2 WMI namespace requires administrator privileges. > "%TMP_D%\av.txt"
echo ACCESS_DENIED: SecurityCenter2 WMI namespace requires administrator privileges. > "%TMP_D%\fwprod.txt"
echo ACCESS_DENIED: SecurityCenter2 WMI namespace requires administrator privileges. > "%TMP_D%\asp.txt"
echo   [WARN] Security product enumeration skipped - not elevated.
:_secc_done

REM UAC registry settings (HKLM policy keys are readable without admin)
REM for /f commands on single lines - multi-line in() is unreliable on some Windows builds
set "UAC_LUA=N/A"
set "UAC_ADMIN=N/A"
set "UAC_USER=N/A"

for /f "tokens=3" %%V in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA 2^>nul ^| findstr "0x"') do set "UAC_LUA=%%V"

for /f "tokens=3" %%V in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin 2^>nul ^| findstr "0x"') do set "UAC_ADMIN=%%V"

for /f "tokens=3" %%V in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser 2^>nul ^| findstr "0x"') do set "UAC_USER=%%V"

REM Translate EnableLUA raw value to human-readable status
set "UAC_STATUS=Unknown"
if "!UAC_LUA!"=="0x1" set "UAC_STATUS=Enabled"
if "!UAC_LUA!"=="0x0" set "UAC_STATUS=Disabled"

REM Translate ConsentPromptBehaviorAdmin
REM   0x0 = Elevate without prompting
REM   0x1 = Prompt for credentials on secure desktop
REM   0x2 = Prompt for consent on secure desktop
REM   0x3 = Prompt for credentials
REM   0x4 = Prompt for consent
REM   0x5 = Prompt for consent for non-Windows binaries (Windows default)
set "UAC_ADMIN_DESC=Unknown"
if "!UAC_ADMIN!"=="0x0" set "UAC_ADMIN_DESC=Elevate without prompting"
if "!UAC_ADMIN!"=="0x1" set "UAC_ADMIN_DESC=Prompt for credentials (secure desktop)"
if "!UAC_ADMIN!"=="0x2" set "UAC_ADMIN_DESC=Prompt for consent (secure desktop)"
if "!UAC_ADMIN!"=="0x3" set "UAC_ADMIN_DESC=Prompt for credentials"
if "!UAC_ADMIN!"=="0x4" set "UAC_ADMIN_DESC=Prompt for consent"
if "!UAC_ADMIN!"=="0x5" set "UAC_ADMIN_DESC=Prompt for consent (non-Windows binaries)"

REM Translate ConsentPromptBehaviorUser
REM   0x0 = Automatically deny elevation requests
REM   0x1 = Prompt for credentials on secure desktop
REM   0x3 = Prompt for credentials (Windows default)
set "UAC_USER_DESC=Unknown"
if "!UAC_USER!"=="0x0" set "UAC_USER_DESC=Automatically deny elevation requests"
if "!UAC_USER!"=="0x1" set "UAC_USER_DESC=Prompt for credentials (secure desktop)"
if "!UAC_USER!"=="0x3" set "UAC_USER_DESC=Prompt for credentials"

echo [4/8] Exporting group policy (gpresult)...

if "!IS_ADMIN!"=="0" goto :_gpr_skip
gpresult /X "%GPRFILE%" /F >nul 2>&1
if exist "%GPRFILE%" goto :_gpr_done
echo   [WARN] gpresult produced no output. Writing placeholder.
(
    echo ^<?xml version="1.0" encoding="UTF-8"?^>
    echo ^<GroupPolicyResult^>
    echo   ^<Error^>gpresult returned no output. No policies may be applied or^</Error^>
    echo   ^<Error^>this system may not be domain-joined.^</Error^>
    echo ^</GroupPolicyResult^>
) > "%GPRFILE%"
goto :_gpr_done
:_gpr_skip
echo   [WARN] gpresult skipped (not elevated). Writing placeholder.
(
    echo ^<?xml version="1.0" encoding="UTF-8"?^>
    echo ^<GroupPolicyResult^>
    echo   ^<Error^>ACCESS_DENIED: gpresult /X requires administrator privileges.^</Error^>
    echo   ^<Error^>Re-run SysAudit.bat as administrator to capture Group Policy data.^</Error^>
    echo ^</GroupPolicyResult^>
) > "%GPRFILE%"
:_gpr_done

echo [5/8] Enumerating local security policy...

set "SECINF=%TMP_D%\secpol.inf"
set "AUDPOL=%TMP_D%\auditpol.txt"
set "NETACC=%TMP_D%\netaccounts.txt"

REM net accounts works without elevation
net accounts > "%NETACC%" 2>nul

REM secedit and auditpol require elevation
if "!IS_ADMIN!"=="0" goto :_lsp_skip
secedit /export /cfg "%SECINF%" /quiet 2>nul
auditpol /get /category:* > "%AUDPOL%" 2>nul
goto :_lsp_done
:_lsp_skip
echo ACCESS_DENIED: secedit /export requires administrator privileges. > "%SECINF%"
echo ACCESS_DENIED: auditpol requires administrator privileges. > "%AUDPOL%"
echo   [WARN] Local security policy export skipped - not elevated.
:_lsp_done

echo [6/8] Enumerating local user accounts...

REM Get the Name-only list (used for per-user net user queries below)
wmic useraccount where "LocalAccount=True" get Name ^
    /format:value > "%TMP_D%\usernames.txt" 2>nul

REM Full WMI user account property dump
wmic useraccount get Name,FullName,Disabled,Lockout,^
    PasswordExpires,PasswordRequired,PasswordChangeable,^
    SID,LocalAccount,AccountType,Description ^
    /format:value > "%TMP_D%\users.txt" 2>nul

REM Administrators group membership requires elevation
if "!IS_ADMIN!"=="0" goto :_admins_skip
net localgroup administrators > "%TMP_D%\admins.txt" 2>nul
goto :_admins_done
:_admins_skip
echo ACCESS_DENIED: net localgroup administrators requires administrator privileges. > "%TMP_D%\admins.txt"
echo   [WARN] Administrators group membership skipped - not elevated.
:_admins_done

REM Local group list does not require elevation
net localgroup > "%TMP_D%\groups.txt" 2>nul

REM ----------------------------------------------------------------
echo [7/8] Enumerating installed software...
echo         (registry enumeration may take 1-3 minutes)
REM ----------------------------------------------------------------

REM Prep the software XML fragment file; subroutine appends into it
set "SW_XML=%TMP_D%\sw_entries.xml"
echo. > "%SW_XML%"

REM Track total across all three sources
set "SW_TOTAL=0"

REM Source 1: HKLM native (64-bit apps on x64; all apps on x86)
echo         Scanning HKLM x64 apps...
call :CollectRegApps "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "HKLM_x64"
set /a "SW_TOTAL+=%SW_COUNT%"

REM Source 2: HKLM WOW6432Node (32-bit apps on a 64-bit OS)
if not exist "%SystemRoot%\SysWOW64\cmd.exe" goto :_wow64_skip
echo         Scanning HKLM WOW6432Node 32-bit app entries...
call :CollectRegApps "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" "HKLM_x86"
set /a "SW_TOTAL+=%SW_COUNT%"
:_wow64_skip

REM Source 3: HKCU per-user installations (current user running the script)
echo         Scanning HKCU per-user apps...
call :CollectRegApps "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" "HKCU"
set /a "SW_TOTAL+=%SW_COUNT%"

REM Source 4: WMI product list (MSI-installed apps - structured but less complete)
REM Used as a cross-reference; embedded as CDATA in the XML section.
echo         Querying WMI MSI product list...
wmic product get Name,Version,Vendor,InstallDate,InstallLocation,PackageName ^
    /format:value > "%TMP_D%\sw_msi.txt" 2>nul

echo         Total applications enumerated: %SW_TOTAL%

echo [8/8] Building XML and policy reports...

REM ================================================================
REM PHASE 2 - BUILD XML OUTPUT
REM
REM Strategy:
REM   - Single-record WMI sections (OS, ComputerSystem, BIOS):
REM     parsed key=value lines => individual XML child elements,
REM     values wrapped in CDATA to safely handle any special chars.
REM     NOTE: Uses delayed-expansion variable assignment before echo
REM     so that values containing & | ^ etc. do not trigger the
REM     command parser.
REM   - Multi-record / raw text sections (CPU, Disks, NICs, Updates,
REM     AV, Firewall detail, Users):
REM     embedded verbatim inside <![CDATA[ ... ]]> blocks.
REM   - Installed Software: per-app <Application> elements written by
REM     :CollectRegApps to a fragment file, typed into the section.
REM     WMI MSI list appended as a CDATA cross-reference.
REM   - Group Policy: saved as companion XML; path referenced here.
REM ================================================================

REM --- XML declaration and root element ---------------------------
(
    echo ^<?xml version="1.0" encoding="UTF-8"?^>
    echo ^<SystemAudit
    echo     ComputerName="%COMPUTERNAME%"
    echo     GeneratedAt="%XMLTS%"
    echo     AuditTool="SysAudit.bat"
    echo     Elevated="!IS_ADMIN!"^>
    echo.
) > "%OUTFILE%"

REM ================================================================
REM SECTION 1 - OPERATING SYSTEM
REM ================================================================
echo   ^<OperatingSystem^> >> "%OUTFILE%"

for /f "tokens=1,* delims==" %%K in ('type "%TMP_D%\os.txt" 2^>nul ^| findstr "="') do (
    set "V=%%L"
    if not "!V!"=="" (
        echo     ^<%%K^>^<![CDATA[!V!]]^>^</%%K^> >> "%OUTFILE%"
    )
)

echo   ^</OperatingSystem^> >> "%OUTFILE%"
echo. >> "%OUTFILE%"

REM ================================================================
REM SECTION 2 - HARDWARE
REM ================================================================
echo   ^<Hardware^> >> "%OUTFILE%"

echo     ^<ComputerSystem^> >> "%OUTFILE%"
for /f "tokens=1,* delims==" %%K in ('type "%TMP_D%\cs.txt" 2^>nul ^| findstr "="') do (
    set "V=%%L"
    if not "!V!"=="" (
        echo       ^<%%K^>^<![CDATA[!V!]]^>^</%%K^> >> "%OUTFILE%"
    )
)
echo     ^</ComputerSystem^> >> "%OUTFILE%"

echo     ^<BIOS^> >> "%OUTFILE%"
for /f "tokens=1,* delims==" %%K in ('type "%TMP_D%\bios.txt" 2^>nul ^| findstr "="') do (
    set "V=%%L"
    if not "!V!"=="" (
        echo       ^<%%K^>^<![CDATA[!V!]]^>^</%%K^> >> "%OUTFILE%"
    )
)
echo     ^</BIOS^> >> "%OUTFILE%"

REM Multi-record sections use CDATA verbatim blocks
(
    echo     ^<Processors^>^<![CDATA[
    type "%TMP_D%\cpu.txt" 2>nul
    echo     ]]^>^</Processors^>
) >> "%OUTFILE%"

(
    echo     ^<PhysicalDisks^>^<![CDATA[
    type "%TMP_D%\disk.txt" 2>nul
    echo     ]]^>^</PhysicalDisks^>
) >> "%OUTFILE%"

(
    echo     ^<LogicalDisks^>^<![CDATA[
    type "%TMP_D%\logicaldisk.txt" 2>nul
    echo     ]]^>^</LogicalDisks^>
) >> "%OUTFILE%"

echo   ^</Hardware^> >> "%OUTFILE%"
echo. >> "%OUTFILE%"

REM ================================================================
REM SECTION 3 - NETWORK
REM ================================================================
(
    echo   ^<Network^>
    echo     ^<Adapters^>^<![CDATA[
    type "%TMP_D%\nic.txt" 2>nul
    echo     ]]^>^</Adapters^>
    echo     ^<IPConfiguration^>^<![CDATA[
    type "%TMP_D%\nicconfig.txt" 2>nul
    echo     ]]^>^</IPConfiguration^>
    echo   ^</Network^>
    echo.
) >> "%OUTFILE%"

REM ================================================================
REM SECTION 4 - INSTALLED UPDATES
REM ================================================================
(
    echo   ^<InstalledUpdates^>^<![CDATA[
    type "%TMP_D%\updates.txt" 2>nul
    echo   ]]^>^</InstalledUpdates^>
    echo.
) >> "%OUTFILE%"

REM ================================================================
REM SECTION 5 - SECURITY
REM ================================================================
echo   ^<Security^> >> "%OUTFILE%"

REM 5a. Windows Firewall (netsh) - admin only
echo     ^<WindowsFirewall^> >> "%OUTFILE%"
if "!IS_ADMIN!"=="0" echo       ^<AccessError^>ACCESS_DENIED: netsh advfirewall requires administrator privileges. Re-run as administrator for firewall data.^</AccessError^> >> "%OUTFILE%"
(
    echo       ^<ProfileStates^>^<![CDATA[
    type "%TMP_D%\fw_state.txt" 2>nul
    echo       ]]^>^</ProfileStates^>
    echo       ^<DetailedSettings^>^<![CDATA[
    type "%TMP_D%\fw_detail.txt" 2>nul
    echo       ]]^>^</DetailedSettings^>
    echo     ^</WindowsFirewall^>
) >> "%OUTFILE%"

REM 5b. Third-party security products (SecurityCenter2 WMI) - admin only
if "!IS_ADMIN!"=="0" echo     ^<SecurityCenterError^>ACCESS_DENIED: SecurityCenter2 WMI namespace requires administrator privileges. Re-run as administrator for AV/Firewall/Antispyware product data.^</SecurityCenterError^> >> "%OUTFILE%"
(
    echo     ^<AntiVirusProducts^>^<![CDATA[
    type "%TMP_D%\av.txt" 2>nul
    echo     ]]^>^</AntiVirusProducts^>
    echo     ^<FirewallProducts^>^<![CDATA[
    type "%TMP_D%\fwprod.txt" 2>nul
    echo     ]]^>^</FirewallProducts^>
    echo     ^<AntiSpywareProducts^>^<![CDATA[
    type "%TMP_D%\asp.txt" 2>nul
    echo     ]]^>^</AntiSpywareProducts^>
) >> "%OUTFILE%"

REM 5c. UAC settings (structured, values from registry - readable without admin)
(
    echo     ^<UAC^>
    echo       ^<Status^>%UAC_STATUS%^</Status^>
    echo       ^<EnableLUA raw="%UAC_LUA%"^>%UAC_STATUS%^</EnableLUA^>
    echo       ^<ConsentPromptBehaviorAdmin raw="%UAC_ADMIN%"^>%UAC_ADMIN_DESC%^</ConsentPromptBehaviorAdmin^>
    echo       ^<ConsentPromptBehaviorUser raw="%UAC_USER%"^>%UAC_USER_DESC%^</ConsentPromptBehaviorUser^>
    echo     ^</UAC^>
) >> "%OUTFILE%"

echo   ^</Security^> >> "%OUTFILE%"
echo. >> "%OUTFILE%"

REM ================================================================
REM SECTION 6 - GROUP POLICY
REM ================================================================
REM gpresult /X writes UTF-16 XML; saved as a companion file to
REM preserve encoding fidelity. The full path is referenced here.
echo   ^<GroupPolicy^> >> "%OUTFILE%"
echo     ^<ReportFile^>%GPRFILE%^</ReportFile^> >> "%OUTFILE%"
if "!IS_ADMIN!"=="0" echo     ^<AccessError^>ACCESS_DENIED: gpresult /X requires administrator privileges. Re-run as administrator to capture Group Policy data.^</AccessError^> >> "%OUTFILE%"
echo     ^<Note^>See the companion GroupPolicy XML file for the full RSoP report.^</Note^> >> "%OUTFILE%"
echo   ^</GroupPolicy^> >> "%OUTFILE%"
echo. >> "%OUTFILE%"

REM ================================================================
REM SECTION 7 - LOCAL USERS
REM ================================================================
echo   ^<LocalUsers^> >> "%OUTFILE%"

REM Administrators group membership - admin only
echo     ^<AdministratorsGroup^> >> "%OUTFILE%"
if "!IS_ADMIN!"=="0" echo       ^<AccessError^>ACCESS_DENIED: net localgroup administrators requires administrator privileges. Re-run as administrator to enumerate admin group membership.^</AccessError^> >> "%OUTFILE%"
(
    echo       ^<![CDATA[
    type "%TMP_D%\admins.txt" 2>nul
    echo       ]]^>
    echo     ^</AdministratorsGroup^>
) >> "%OUTFILE%"

REM Local group listing (no admin required)
(
    echo     ^<LocalGroups^>^<![CDATA[
    type "%TMP_D%\groups.txt" 2>nul
    echo     ]]^>^</LocalGroups^>
) >> "%OUTFILE%"

REM Per-user detail: iterate usernames, run net user for each
REM Net user output is embedded verbatim in CDATA per user record.
for /f "tokens=1,* delims==" %%K in ('type "%TMP_D%\usernames.txt" 2^>nul ^| findstr /i "Name="') do (
    set "UNAME=%%L"
    REM Strip leading/trailing spaces from username
    for /f "tokens=* delims= " %%X in ("!UNAME!") do set "UNAME=%%X"
    if not "!UNAME!"=="" (
        echo     ^<User name="!UNAME!"^> >> "%OUTFILE%"
        call :_user_detail
        echo     ^</User^> >> "%OUTFILE%"
    )
)

REM Full WMI property dump for all user accounts (no admin required)
(
    echo     ^<WmiUserAccountProperties^>^<![CDATA[
    type "%TMP_D%\users.txt" 2>nul
    echo     ]]^>^</WmiUserAccountProperties^>
) >> "%OUTFILE%"

echo   ^</LocalUsers^> >> "%OUTFILE%"
echo. >> "%OUTFILE%"

REM ================================================================
REM SECTION 8 - INSTALLED SOFTWARE
REM
REM Structure:
REM   <InstalledSoftware total="N">
REM     One <Application> per registry entry with DisplayName
REM     <Application source="HKLM_x64|HKLM_x86|HKCU">
REM       <Name>        - DisplayName registry value
REM       <Version>     - DisplayVersion registry value
REM       <Publisher>   - Publisher registry value
REM       <InstallDate> - InstallDate registry value (yyyymmdd)
REM       <InstallLocation> - InstallLocation registry value
REM     </Application>
REM     ...
REM     MSI product list from WMI as a cross-reference
REM     <MsiProducts> CDATA block from wmic product </MsiProducts>
REM   </InstalledSoftware>
REM
REM Sources:
REM   HKLM_x64   : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
REM   HKLM_x86   : HKLM\SOFTWARE\WOW6432Node\...\Uninstall (64-bit OS only)
REM   HKCU       : HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
REM   MsiProducts: wmic product (MSI-installed apps, cross-reference only)
REM
REM Note: Registry sources cover virtually all installed software.
REM       MSI source covers only Windows Installer packages but
REM       provides structured data and is useful for cross-validation.
REM ================================================================
(
    echo   ^<InstalledSoftware total="%SW_TOTAL%"^>
) >> "%OUTFILE%"

type "%SW_XML%" >> "%OUTFILE%"

(
    echo     ^<MsiProducts^>^<![CDATA[
    type "%TMP_D%\sw_msi.txt" 2>nul
    echo     ]]^>^</MsiProducts^>
    echo   ^</InstalledSoftware^>
    echo.
) >> "%OUTFILE%"

REM --- Close root element -----------------------------------------
echo ^</SystemAudit^> >> "%OUTFILE%"

REM ================================================================
REM BUILD LOCAL SECURITY POLICY XML
REM
REM Structure:
REM   <LocalSecurityPolicy ...>
REM     <AccountPolicies>
REM       <PasswordPolicy source="net accounts">     structured fields
REM       <SeceditSystemAccess source="secedit">     structured fields
REM     </AccountPolicies>
REM     <AuditPolicy source="auditpol">              CDATA verbatim
REM     <RawPolicyExport source="secedit /export">   CDATA verbatim
REM   </LocalSecurityPolicy>
REM
REM net accounts runs without elevation.
REM secedit /export and auditpol require elevation; fields show N/A if skipped.
REM secedit may export UTF-16; all reads pipe through "type" for conversion.
REM ================================================================

REM --- Parse net accounts for structured password and lockout values ---
set "NA_LOGOFF=N/A"
set "NA_MINAGE=N/A"
set "NA_MAXAGE=N/A"
set "NA_MINLEN=N/A"
set "NA_HISTORY=N/A"
set "NA_LOCKTHRESH=N/A"
set "NA_LOCKDUR=N/A"
set "NA_LOCKOBS=N/A"
set "NA_ROLE=N/A"

for /f "tokens=2 delims=:" %%V in ('findstr /i "logoff" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_LOGOFF=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "Minimum password age" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_MINAGE=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "Maximum password age" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_MAXAGE=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "Minimum password length" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_MINLEN=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "password history" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_HISTORY=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "Lockout threshold" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_LOCKTHRESH=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "Lockout duration" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_LOCKDUR=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "observation window" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_LOCKOBS=%%W"
for /f "tokens=2 delims=:" %%V in ('findstr /i "Computer role" "%NETACC%" 2^>nul') do for /f "tokens=* delims= " %%W in ("%%V") do set "NA_ROLE=%%W"

REM --- Parse secedit [System Access] for structured security settings ---
REM Keys are unique across sections so no section scoping is needed.
REM Pipe through "type" to handle potential UTF-16 INF encoding.
set "SEC_MINPWDAGE=N/A"
set "SEC_MAXPWDAGE=N/A"
set "SEC_MINPWDLEN=N/A"
set "SEC_PWDCMPLX=N/A"
set "SEC_PWDHIST=N/A"
set "SEC_CLEARTEXT=N/A"
set "SEC_LOCKBAD=N/A"
set "SEC_RESETLOCK=N/A"
set "SEC_LOCKDUR_SEC=N/A"
set "SEC_REQLOGON=N/A"
set "SEC_FORCELOGOFF=N/A"
set "SEC_LSAANON=N/A"
set "SEC_ENABLEADMIN=N/A"
set "SEC_ENABLEGUEST=N/A"

if exist "%SECINF%" (
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "MinimumPasswordAge = "') do set "SEC_MINPWDAGE=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "MaximumPasswordAge = "') do set "SEC_MAXPWDAGE=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "MinimumPasswordLength = "') do set "SEC_MINPWDLEN=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "PasswordComplexity = "') do set "SEC_PWDCMPLX=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "PasswordHistorySize = "') do set "SEC_PWDHIST=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "ClearTextPassword = "') do set "SEC_CLEARTEXT=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "LockoutBadCount = "') do set "SEC_LOCKBAD=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "ResetLockoutCount = "') do set "SEC_RESETLOCK=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "LockoutDuration = "') do set "SEC_LOCKDUR_SEC=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "RequireLogonToChangePassword = "') do set "SEC_REQLOGON=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "ForceLogoffWhenHourExpire = "') do set "SEC_FORCELOGOFF=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "LSAAnonymousNameLookup = "') do set "SEC_LSAANON=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "EnableAdminAccount = "') do set "SEC_ENABLEADMIN=%%V"
    for /f "tokens=3" %%V in ('type "%SECINF%" 2^>nul ^| findstr /i "EnableGuestAccount = "') do set "SEC_ENABLEGUEST=%%V"
)

REM --- Write LSP XML header ---
(
    echo ^<?xml version="1.0" encoding="UTF-8"?^>
    echo ^<LocalSecurityPolicy
    echo     ComputerName="%COMPUTERNAME%"
    echo     GeneratedAt="%XMLTS%"
    echo     AuditTool="SysAudit.bat"
    echo     Elevated="!IS_ADMIN!"^>
    echo.
) > "%LSPFILE%"

REM --- Account Policies section ---
echo   ^<AccountPolicies^> >> "%LSPFILE%"

REM Password policy from net accounts
(
    echo     ^<PasswordPolicy source="net accounts"^>
    echo       ^<ForceLogoffAfterExpiry^>!NA_LOGOFF!^</ForceLogoffAfterExpiry^>
    echo       ^<MinPasswordAge unit="days"^>!NA_MINAGE!^</MinPasswordAge^>
    echo       ^<MaxPasswordAge unit="days"^>!NA_MAXAGE!^</MaxPasswordAge^>
    echo       ^<MinPasswordLength^>!NA_MINLEN!^</MinPasswordLength^>
    echo       ^<PasswordHistorySize^>!NA_HISTORY!^</PasswordHistorySize^>
    echo       ^<LockoutThreshold^>!NA_LOCKTHRESH!^</LockoutThreshold^>
    echo       ^<LockoutDuration unit="minutes"^>!NA_LOCKDUR!^</LockoutDuration^>
    echo       ^<LockoutObservationWindow unit="minutes"^>!NA_LOCKOBS!^</LockoutObservationWindow^>
    echo       ^<ComputerRole^>!NA_ROLE!^</ComputerRole^>
    echo     ^</PasswordPolicy^>
) >> "%LSPFILE%"

REM Structured secedit [System Access] values
REM PasswordComplexity: 1=Enabled, 0=Disabled
REM ClearTextPassword: 1=Enabled (insecure), 0=Disabled
REM LockoutDuration: -1=Forever until admin unlocks, 0=No lockout, N=minutes
REM EnableAdminAccount/EnableGuestAccount: 1=Enabled, 0=Disabled
(
    echo     ^<SeceditSystemAccess source="secedit /export"^>
    echo       ^<Note^>N/A indicates value not found or export skipped. Requires elevation.^</Note^>
    echo       ^<MinimumPasswordAge unit="days"^>!SEC_MINPWDAGE!^</MinimumPasswordAge^>
    echo       ^<MaximumPasswordAge unit="days"^>!SEC_MAXPWDAGE!^</MaximumPasswordAge^>
    echo       ^<MinimumPasswordLength^>!SEC_MINPWDLEN!^</MinimumPasswordLength^>
    echo       ^<PasswordComplexity raw="!SEC_PWDCMPLX!"^>!SEC_PWDCMPLX!^</PasswordComplexity^>
    echo       ^<PasswordHistorySize^>!SEC_PWDHIST!^</PasswordHistorySize^>
    echo       ^<ClearTextPassword raw="!SEC_CLEARTEXT!"^>!SEC_CLEARTEXT!^</ClearTextPassword^>
    echo       ^<LockoutBadCount^>!SEC_LOCKBAD!^</LockoutBadCount^>
    echo       ^<ResetLockoutCount unit="minutes"^>!SEC_RESETLOCK!^</ResetLockoutCount^>
    echo       ^<LockoutDuration unit="minutes" note="-1=permanent until admin unlock"^>!SEC_LOCKDUR_SEC!^</LockoutDuration^>
    echo       ^<RequireLogonToChangePassword^>!SEC_REQLOGON!^</RequireLogonToChangePassword^>
    echo       ^<ForceLogoffWhenHourExpire^>!SEC_FORCELOGOFF!^</ForceLogoffWhenHourExpire^>
    echo       ^<LSAAnonymousNameLookup^>!SEC_LSAANON!^</LSAAnonymousNameLookup^>
    echo       ^<EnableAdminAccount^>!SEC_ENABLEADMIN!^</EnableAdminAccount^>
    echo       ^<EnableGuestAccount^>!SEC_ENABLEGUEST!^</EnableGuestAccount^>
    echo     ^</SeceditSystemAccess^>
) >> "%LSPFILE%"

echo   ^</AccountPolicies^> >> "%LSPFILE%"
echo. >> "%LSPFILE%"

REM --- Audit Policy section (auditpol - requires elevation) ---
if "!IS_ADMIN!"=="0" echo   ^<AuditPolicy^>^<AccessError^>ACCESS_DENIED: auditpol requires administrator privileges. Re-run as administrator for audit policy data.^</AccessError^>^</AuditPolicy^> >> "%LSPFILE%"
if "!IS_ADMIN!"=="1" (
    echo   ^<AuditPolicy source="auditpol /get /category:*"^>^<![CDATA[ >> "%LSPFILE%"
    type "%AUDPOL%" >> "%LSPFILE%" 2>nul
    echo   ]]^>^</AuditPolicy^> >> "%LSPFILE%"
)
echo. >> "%LSPFILE%"

REM --- Raw secedit export embedded as CDATA ---
if "!IS_ADMIN!"=="0" echo   ^<RawPolicyExport^>^<AccessError^>ACCESS_DENIED: secedit /export requires administrator privileges. Re-run as administrator for full policy export.^</AccessError^>^</RawPolicyExport^> >> "%LSPFILE%"
if "!IS_ADMIN!"=="1" (
    echo   ^<RawPolicyExport source="secedit /export /cfg"^>^<![CDATA[ >> "%LSPFILE%"
    type "%SECINF%" >> "%LSPFILE%" 2>nul
    echo   ]]^>^</RawPolicyExport^> >> "%LSPFILE%"
)
echo. >> "%LSPFILE%"

echo ^</LocalSecurityPolicy^> >> "%LSPFILE%"

REM ================================================================
REM CLEANUP
REM ================================================================
rd /s /q "%TMP_D%" 2>nul

REM ================================================================
REM SUMMARY
REM ================================================================
echo.
echo  ====================================================
echo   Audit Complete
echo  ====================================================
echo.
echo   Audit Report : %OUTFILE%
echo   Group Policy : %GPRFILE%
echo   Local SecPol : %LSPFILE%
echo   Applications : %SW_TOTAL% enumerated
if "!IS_ADMIN!"=="1" goto :_warn_done
echo.
echo   [WARN] Audit ran without administrator privileges.
echo          The following sections have partial or no data:
echo            - Windows Firewall state
echo            - Security Center products - AV, Firewall, Antispyware
echo            - Group Policy - gpresult
echo            - Administrators group membership
echo            - Per-user account details - net user
echo            - Local security policy - secedit, auditpol
echo          Re-run as administrator for a complete audit.
:_warn_done
echo.

REM Verify files were written
if exist "%OUTFILE%" (
    echo   [OK] Audit XML written successfully.
) else (
    echo   [ERROR] Audit XML was not created. Check permissions on %AUDIT_ROOT%
)

if exist "%GPRFILE%" (
    echo   [OK] Group Policy XML written successfully.
) else (
    echo   [WARN] Group Policy XML was not created (system may not have policies).
)

if exist "%LSPFILE%" (
    echo   [OK] Local Security Policy XML written successfully.
) else (
    echo   [ERROR] Local Security Policy XML was not created. Check permissions on %AUDIT_ROOT%
)

echo.
echo   Files saved to: %AUDIT_ROOT%
echo.

endlocal
exit /b 0

REM ================================================================
REM SUBROUTINE: _user_detail
REM
REM Writes per-user net user detail XML into %OUTFILE%.
REM Called from within the per-user FOR loop to avoid nested
REM parenthesized-block redirect issues in CMD.
REM Requires: UNAME, IS_ADMIN, OUTFILE set in parent scope.
REM ================================================================
:_user_detail
if "!IS_ADMIN!"=="0" goto :_ud_noadmin
(
    echo       ^<Detail^>^<![CDATA[
    net user "!UNAME!" 2>nul
    echo       ]]^>^</Detail^>
) >> "%OUTFILE%"
goto :eof
:_ud_noadmin
echo       ^<Detail^>^<AccessError^>ACCESS_DENIED: net user detail requires administrator privileges. Re-run as administrator for per-user account details.^</AccessError^>^</Detail^> >> "%OUTFILE%"
goto :eof

REM ================================================================
REM SUBROUTINE: CollectRegApps
REM
REM Iterates all immediate subkeys of a given Uninstall registry
REM root and writes an <Application> XML element for each entry
REM that has a DisplayName value defined.
REM
REM Parameters:
REM   %~1  Registry key path (the Uninstall root to enumerate)
REM   %~2  Source label written to the source="..." XML attribute
REM
REM Output:
REM   Appends <Application> elements to %SW_XML% (inherited from
REM   parent scope via setlocal).
REM
REM Returns (via SW_COUNT):
REM   Sets SW_COUNT in the parent scope via endlocal trick so the
REM   caller can accumulate a total.
REM
REM Per-app query strategy:
REM   One "reg query KEY" call dumps all values for a subkey to a
REM   temp file. Five findstr passes over that file extract the
REM   fields. This is faster than five separate reg query calls
REM   because findstr reads a local file rather than spawning
REM   additional registry processes.
REM ================================================================
:CollectRegApps
setlocal enabledelayedexpansion
set "REGROOT=%~1"
set "SOURCE=%~2"
set "APPTMP=%TMP_D%\app_cur.txt"
set "COUNT=0"

for /f "tokens=*" %%K in ('reg query "%REGROOT%" 2^>nul') do (
    REM Dump all values for this subkey to a temp file (one process per app)
    reg query "%%K" > "!APPTMP!" 2>nul

    set "APPNAME=" & set "APPVER=" & set "APPPUB=" & set "APPDATE=" & set "APPLOC="

    REM Parse DisplayName -- first token is the value name, skip REG_SZ type token
    for /f "tokens=1,2,*" %%A in ('findstr /i "DisplayName" "!APPTMP!" 2^>nul') do (
        if /i "%%A"=="DisplayName" set "APPNAME=%%C"
    )

    REM Only proceed if this subkey has a display name (skip system/component GUIDs)
    if defined APPNAME (
        for /f "tokens=1,2,*" %%A in ('findstr /i "DisplayVersion" "!APPTMP!" 2^>nul') do (
            if /i "%%A"=="DisplayVersion" set "APPVER=%%C"
        )
        for /f "tokens=1,2,*" %%A in ('findstr /i "Publisher" "!APPTMP!" 2^>nul') do (
            if /i "%%A"=="Publisher" set "APPPUB=%%C"
        )
        for /f "tokens=1,2,*" %%A in ('findstr /i "InstallDate" "!APPTMP!" 2^>nul') do (
            if /i "%%A"=="InstallDate" set "APPDATE=%%C"
        )
        for /f "tokens=1,2,*" %%A in ('findstr /i "InstallLocation" "!APPTMP!" 2^>nul') do (
            if /i "%%A"=="InstallLocation" set "APPLOC=%%C"
        )

        set /a "COUNT+=1"

        >> "%SW_XML%" echo     ^<Application source="!SOURCE!"^>
        >> "%SW_XML%" echo       ^<Name^>^<![CDATA[!APPNAME!]]^>^</Name^>
        >> "%SW_XML%" echo       ^<Version^>^<![CDATA[!APPVER!]]^>^</Version^>
        >> "%SW_XML%" echo       ^<Publisher^>^<![CDATA[!APPPUB!]]^>^</Publisher^>
        >> "%SW_XML%" echo       ^<InstallDate^>^<![CDATA[!APPDATE!]]^>^</InstallDate^>
        >> "%SW_XML%" echo       ^<InstallLocation^>^<![CDATA[!APPLOC!]]^>^</InstallLocation^>
        >> "%SW_XML%" echo     ^</Application^>
    )
)

REM Return COUNT to the caller via the endlocal variable-tunnelling trick
endlocal & set "SW_COUNT=%COUNT%"
goto :eof
