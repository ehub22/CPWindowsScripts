<#
.SYNOPSIS
    CyberPatriot Windows hardening for training images (Windows 10 / 11 and
    Windows Server 2019 / 2022 / 2025), audit-first and penalty-averse.

.DESCRIPTION
    Design rules of this script (in priority order):
      1. NEVER lose points: forensics gate first, README-driven allow-lists,
         the scoring service / VM tools / current user / service accounts /
         domain controllers are hard-protected, every change is backed up
         first, nothing is deleted silently, and the script never reboots.
      2. Gain points: applies the controls CyberPatriot scores (users,
         password + lockout policy, security options, audit policy,
         firewall, Defender, insecure services, remote access, SMB,
         shares, prohibited software/files, updates) using values aligned
         with CIS Benchmarks and current Microsoft security baselines.
      3. Be transparent: -Mode Audit changes nothing, everything is logged,
         and docs/RESEARCH_AND_SAFETY.md explains every single fix.

    RULES WARNING: Competition rules change every season and restrict AI
    tools, AI-made scripts and pre-written scripts in scored rounds and at
    National Finals. Read the CURRENT CyberPatriot Rules Book and treat
    this toolkit as TRAINING material that your own team must understand,
    test on practice images, and re-author as required by those rules.

.EXAMPLE
    .\secure.ps1 -Mode Audit        (read-only: reports + pass/fail table)
    .\secure.ps1                     (interactive, the normal way)
    .\secure.ps1 -Mode ApplySafe -ForensicsDone -ReadmeConfigured
    .\secure.ps1 -Rollback           (restore the newest backup)
#>
[CmdletBinding()]
param(
    [ValidateSet('Interactive','Audit','ApplySafe')]
    [string]$Mode = 'Interactive',
    [switch]$ForensicsDone,
    [switch]$ReadmeConfigured,
    [switch]$Rollback,
    [string]$RollbackPath = '',
    [switch]$ShowAIPrompt,
    [switch]$NoElevate,

    # Account policy values (CIS / Microsoft baseline aligned, see docs).
    [int]$MinPasswordLength = 14,
    [int]$PasswordHistorySize = 24,
    [int]$MaxPasswordAgeDays = 60,
    [int]$MinPasswordAgeDays = 1,
    [int]$LockoutThreshold = 5,
    [int]$LockoutDurationMin = 15,
    [int]$LockoutResetMin = 15
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
try { [Console]::Title = 'CyberPatriot Windows Hardening (2026)' } catch {}

# ----------------------------------------------------------------------------
# Paths and globals
# ----------------------------------------------------------------------------
$script:Root = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:Root)) { $script:Root = (Get-Location).Path }
$script:Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogDir = Join-Path $script:Root 'Logs'
$script:ReportDir = Join-Path $script:Root ("Reports\" + $script:Stamp)
$script:BackupDir = Join-Path $script:Root ("Backups\" + $script:Stamp)
$script:AuditOnly = ($Mode -eq 'Audit')
$script:ApplySafe = ($Mode -eq 'ApplySafe')
$script:Changes = New-Object System.Collections.ArrayList
$script:Warnings = New-Object System.Collections.ArrayList
$script:CurrentUser = [Environment]::UserName
$script:IsServer = $false
$script:IsDC = $false
$script:DomainJoined = $false
$script:OSCaption = 'Unknown Windows'
$script:TeamPassword = $null
$script:KeepEntries = @()
$script:AuthorizedUsers = @()
$script:AuthorizedAdmins = @()
$script:RdpUsers = @()
$script:BuiltInUsers = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
$script:FileSharingCritical = $false
$script:RdpCritical = $false

foreach ($dirPath in @($script:LogDir, $script:ReportDir)) {
    if (-not (Test-Path $dirPath)) { New-Item -ItemType Directory -Path $dirPath -Force | Out-Null }
}
try { Start-Transcript -Path (Join-Path $script:LogDir ("secure_" + $script:Stamp + ".log")) -Force | Out-Null } catch {}

# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
function Write-Banner {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host ("[*] " + $Text)
}

function Write-Good {
    param([string]$Text)
    Write-Host ("[+] " + $Text) -ForegroundColor Green
    [void]$script:Changes.Add($Text)
}

function Write-WarnLine {
    param([string]$Text)
    Write-Host ("[!] " + $Text) -ForegroundColor Yellow
    [void]$script:Warnings.Add($Text)
}

function Ask-YesNo {
    param([string]$Question, [bool]$DefaultYes = $true)
    if ($script:ApplySafe -or $script:AuditOnly) { return $DefaultYes }
    $suffix = ' [Y/n]'
    if (-not $DefaultYes) { $suffix = ' [y/N]' }
    try {
        $answer = Read-Host ($Question + $suffix)
    } catch {
        return $DefaultYes
    }
    if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultYes }
    $answer = $answer.Trim().ToLower()
    if ($answer -eq 'c' -or $answer -eq 'q') { throw 'User cancelled.' }
    return ($answer -eq 'y' -or $answer -eq 'yes')
}

function Wait-Enter {
    param([string]$Text = 'Press ENTER to continue...')
    if ($script:ApplySafe) { return }
    try { Read-Host $Text | Out-Null } catch {}
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-CommandExists {
    param([string]$Name)
    return ($null -ne (Get-Command $Name -ErrorAction SilentlyContinue))
}

function Get-TextList {
    param([string]$Path)
    $items = @()
    if (-not (Test-Path $Path)) { return $items }
    foreach ($line in (Get-Content $Path -ErrorAction SilentlyContinue)) {
        $t = $line.Trim()
        if ($t.Length -eq 0) { continue }
        if ($t.StartsWith('#')) { continue }
        $items += $t
    }
    return $items
}

function Test-FileEdited {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $raw = Get-Content $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $raw) { return $false }
    return ($raw -notmatch 'EDIT_ME')
}

function Add-Report {
    param([string]$File, [string]$Heading, [object]$Content)
    $path = Join-Path $script:ReportDir $File
    try {
        Add-Content $path ''
        Add-Content $path ('----- ' + $Heading + ' -----')
        if ($null -eq $Content) { Add-Content $path '(none found)' }
        else { ($Content | Out-String -Width 250) | Add-Content $path }
    } catch {}
}

function Set-RegValue {
    param(
        [string]$Path, [string]$Name, [object]$Value,
        [ValidateSet('DWord','String','MultiString','ExpandString')]
        [string]$Type = 'DWord',
        [string]$Why = ''
    )
    # Path uses HKLM\... form; convert to a PowerShell drive path.
    $psPath = $Path -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\'
    try {
        $before = $null
        $keyExists = Test-Path $psPath
        if ($keyExists) {
            $item = Get-ItemProperty $psPath -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $item) { $before = $item.$Name }
        }
        if ($null -ne $before -and "$before" -eq "$Value") {
            Write-Step ("Already set : " + $Path + '\' + $Name + ' = ' + $Value)
            return $true
        }
        if ($script:AuditOnly) {
            Write-Host ("[AUDIT] Would set " + $Path + '\' + $Name + ' = ' + $Value + ' (now: ' + $before + ')')
            return $false
        }
        if (-not $keyExists) { New-Item -Path $psPath -Force | Out-Null }
        New-ItemProperty -Path $psPath -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
        Write-Good ("Set " + $Path + '\' + $Name + ' = ' + $Value + ' (was: ' + $before + ')  ' + $Why)
        return $true
    } catch {
        Write-WarnLine ("Could not set " + $Path + '\' + $Name + ' : ' + $_.Exception.Message)
        return $false
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $psPath = $Path -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\'
    try {
        $item = Get-ItemProperty $psPath -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Export-RegKey {
    param([string]$RegPath, [string]$OutFile)
    try { & reg.exe export $RegPath $OutFile /y 2>$null | Out-Null } catch {}
}

# ----------------------------------------------------------------------------
# Keep-service (critical service) protection
# ----------------------------------------------------------------------------
$script:KeepTokenMap = @{
    'RDP'      = @('TermService','UmRdpService','SessionEnv','RemoteRegistry')
    'REMOTEDESKTOP' = @('TermService','UmRdpService','SessionEnv')
    'REMOTE DESKTOP' = @('TermService','UmRdpService','SessionEnv')
    'REMOTE'   = @('TermService','UmRdpService','SessionEnv','WinRM')
    'IIS'      = @('W3SVC','WAS','IISADMIN','WMSVC')
    'WEB'      = @('W3SVC','WAS','IISADMIN','WMSVC','Apache2.4','Apache','nginx')
    'APACHE'   = @('Apache2.4','Apache')
    'FTP'      = @('FTPSVC','MSFTPSVC')
    'DNS'      = @('DNS')
    'DHCP'     = @('DHCPServer','Dhcp')
    'AD'       = @('NTDS','DNS','Kdc','Netlogon','DFSR','IsmServ','LanmanServer','ADWS','W32Time')
    'DOMAIN'   = @('NTDS','DNS','Kdc','Netlogon','DFSR','IsmServ','LanmanServer','ADWS','W32Time')
    'SMB'      = @('LanmanServer','LanmanWorkstation','fdPHost','FDResPub')
    'FILES'    = @('LanmanServer','LanmanWorkstation','fdPHost','FDResPub')
    'FILE'     = @('LanmanServer','LanmanWorkstation','fdPHost','FDResPub')
    'SHARES'   = @('LanmanServer','LanmanWorkstation','fdPHost','FDResPub')
    'PRINT'    = @('Spooler')
    'PRINTING' = @('Spooler')
    'SQL'      = @('MSSQLSERVER','SQLSERVERAGENT','MySQL','MySQL80','postgresql-x64-16')
    'SSH'      = @('sshd','ssh-agent')
    'WINRM'    = @('WinRM')
    'EMAIL'    = @('SMTPSVC','MSExchangeTransport','POP3Svc','IMAP4Svc')
    'SMTP'     = @('SMTPSVC','MSExchangeTransport')
    'VPN'      = @('RemoteAccess','RasMan','RasAuto','SstpSvc','IKEEXT','PolicyAgent')
    'SNMP'     = @('SNMP','SNMPTrap')
    'BLUETOOTH'= @('bthserv')
    'FAX'      = @('Fax')
    'SMARTCARD'= @('SCardSvr')
    'TELNET'   = @('TlntSvr')
}

$script:ProtectedServices = @(
    'WinDefend','SecurityHealthService','Sense','MpsSvc','BFE','EventLog',
    'RpcSs','RpcEptMapper','DcomLaunch','LSM','BrokerInfrastructure','SamSs',
    'gpsvc','PlugPlay','Power','ProfSvc','Schedule','Winmgmt','W32Time',
    'Dhcp','Dnscache','netprofm','NlaSvc','LanmanWorkstation','CryptSvc',
    'KeyIso','UserManager','Appinfo','CoreMessagingRegistrar','wuauserv',
    'BITS','UsoSvc','TrustedInstaller','msiserver','StateRepository',
    'TokenBroker','DPS','DusmSvc'
)

$script:ProtectedPatterns = 'CyberPatriot|Scoring|CCSClient|CCS|VMware|VMTools|VBox|VirtualBox|QEMU|qemu|Hyper-V|vmickvpexchange|vmicguestinterface'

function Test-ServiceProtected {
    param([string]$Name, [string]$DisplayName)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    foreach ($p in $script:ProtectedServices) {
        if ($Name -ieq $p) { return $true }
    }
    if ($Name -match $script:ProtectedPatterns) { return $true }
    if (-not [string]::IsNullOrWhiteSpace($DisplayName) -and $DisplayName -match $script:ProtectedPatterns) { return $true }
    if ($script:IsDC) {
        foreach ($p in @('DNS','NTDS','Kdc','Netlogon','DFSR','IsmServ','LanmanServer','ADWS')) {
            if ($Name -ieq $p) { return $true }
        }
    }
    if ($script:DomainJoined -and $Name -ieq 'Netlogon') { return $true }
    return $false
}

function Test-ServiceKept {
    param([string]$Name, [string]$DisplayName)
    if (Test-ServiceProtected -Name $Name -DisplayName $DisplayName) { return $true }
    foreach ($entry in $script:KeepEntries) {
        $e = $entry.Trim()
        if ($e.Length -eq 0) { continue }
        if ($Name -ieq $e) { return $true }
        if (-not [string]::IsNullOrWhiteSpace($DisplayName) -and $DisplayName -ieq $e) { return $true }
        $key = $e.ToUpper()
        if ($script:KeepTokenMap.ContainsKey($key)) {
            foreach ($mapped in $script:KeepTokenMap[$key]) {
                if ($Name -ieq $mapped) { return $true }
            }
        }
        if ($e.Length -ge 3) {
            if ($Name.ToLower().Contains($e.ToLower())) { return $true }
            if (-not [string]::IsNullOrWhiteSpace($DisplayName) -and $DisplayName.ToLower().Contains($e.ToLower())) { return $true }
        }
    }
    return $false
}

function Test-TokenKept {
    param([string[]]$Tokens)
    foreach ($entry in $script:KeepEntries) {
        foreach ($t in $Tokens) {
            if ($entry -ieq $t) { return $true }
        }
    }
    return $false
}

# ----------------------------------------------------------------------------
# AI paragraph (printed FIRST, as requested) + rules warning
# ----------------------------------------------------------------------------
function Show-AIPrompt {
    $marker = Join-Path $script:Root '.ai_prompt_acknowledged'
    if ((Test-Path $marker) -and -not $ShowAIPrompt) { return }
    Write-Banner 'STEP 0 OF 12 - PROTECT CRITICAL SERVICES (READ THIS FIRST)'
    Write-Host 'Disabling a service the scenario needs, or deleting an authorized user,' -ForegroundColor Yellow
    Write-Host 'LOSES points. Before this script touches anything, identify the critical' -ForegroundColor Yellow
    Write-Host 'services from the README that sits on the image desktop.'
    Write-Host ''
    Write-Host 'TRAINING HELP: the paragraph between the lines below is a prompt for an' -ForegroundColor Yellow
    Write-Host 'AI model. Copy it, then paste the image README immediately after it.' -ForegroundColor Yellow
    Write-Host 'It also lives in AI_PROMPT.txt next to this script. Paste the AI output' -ForegroundColor Yellow
    Write-Host 'into keep_services.txt / authorizedusers.txt / admins.txt / rdpusers.txt' -ForegroundColor Yellow
    Write-Host 'and then VERIFY EVERY LINE YOURSELF against the original README.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host 'RULES WARNING: current CyberPatriot rules restrict using AI tools and' -ForegroundColor Red
    Write-Host 'AI-made scripts DURING scored competition rounds (paid AI tools may be' -ForegroundColor Red
    Write-Host 'banned in connection with the competition entirely). Use this prompt for' -ForegroundColor Red
    Write-Host 'TRAINING and practice images only, and always follow the CURRENT Rules' -ForegroundColor Red
    Write-Host 'Book. In a scored round, do the same job by hand: read the README, fill' -ForegroundColor Red
    Write-Host 'in the same four .txt files yourself. The script protects whatever you list.' -ForegroundColor Red
    Write-Host ''
    Write-Host '------------------------- COPY FROM HERE -------------------------' -ForegroundColor White
    $promptFile = Join-Path $script:Root 'AI_PROMPT.txt'
    if (Test-Path $promptFile) {
        Get-Content $promptFile | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host 'List every critical / necessary service in the README pasted below that must NOT be disabled, with Windows service names, ports and dependencies, then give paste-ready lists for keep_services.txt, authorizedusers.txt, admins.txt and rdpusers.txt. The README is:'
    }
    Write-Host '------------------------- COPY TO HERE ---------------------------' -ForegroundColor White
    Write-Host ''
    Wait-Enter 'Copy the paragraph now if you need it, then press ENTER to continue ...'
    try { Set-Content $marker (Get-Date -Format s) -Force } catch {}
}

# ----------------------------------------------------------------------------
# Rollback
# ----------------------------------------------------------------------------
function Invoke-Rollback {
    param([string]$Path)
    Write-Banner 'ROLLBACK - restore a previous backup'
    $base = Join-Path $script:Root 'Backups'
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $dirs = @(Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        if ($dirs.Count -eq 0) { Write-WarnLine 'No backups found.'; return }
        $Path = $dirs[0].FullName
    }
    Write-Step ("Backup folder: " + $Path)
    if (-not (Ask-YesNo 'Restore from this backup now?' $false)) { return }

    $cfg = Join-Path $Path 'secedit-backup.cfg'
    if (Test-Path $cfg) {
        if (Ask-YesNo 'Restore account / security policy from backup (secedit)?' $true) {
            try {
                $db = Join-Path $env:TEMP 'cp-rollback.sdb'
                & secedit.exe /configure /db $db /cfg $cfg /areas SECURITYPOLICY /quiet | Out-Null
                Write-Good 'Restored security policy from backup.'
            } catch { Write-WarnLine ("secedit restore failed: " + $_.Exception.Message) }
        }
    }
    $audit = Join-Path $Path 'auditpol-backup.csv'
    if (Test-Path $audit) {
        if (Ask-YesNo 'Restore audit policy from backup (auditpol)?' $true) {
            try { & auditpol.exe /restore "/file:$audit" | Out-Null; Write-Good 'Restored audit policy from backup.' }
            catch { Write-WarnLine ("auditpol restore failed: " + $_.Exception.Message) }
        }
    }
    $fw = Join-Path $Path 'firewall-backup.wfw'
    if (Test-Path $fw) {
        if (Ask-YesNo 'Restore Windows Firewall policy from backup?' $true) {
            try { & netsh.exe advfirewall import $fw | Out-Null; Write-Good 'Restored firewall policy from backup.' }
            catch { Write-WarnLine ("Firewall restore failed: " + $_.Exception.Message) }
        }
    }
    $svcCsv = Join-Path $Path 'services-backup.csv'
    if (Test-Path $svcCsv) {
        if (Ask-YesNo 'Restore original service start types from backup?' $true) {
            Import-Csv $svcCsv | ForEach-Object {
                $start = "$($_.StartType)"
                $svcName = "$($_.Name)"
                try {
                    if ($start -eq 'AutomaticDelayedStart') { & sc.exe config $svcName 'start=' 'delayed-auto' | Out-Null }
                    elseif ($start -in @('Automatic','Manual','Disabled')) { Set-Service -Name $svcName -StartupType $start -ErrorAction Stop }
                } catch {}
            }
            Write-Good 'Restored service start types (services are not auto-started; reboot or start them manually).'
        }
    }
    foreach ($reg in @(Get-ChildItem $Path -Filter '*.reg' -ErrorAction SilentlyContinue)) {
        if (Ask-YesNo ("Import registry backup " + $reg.Name + '?') $false) {
            try { & reg.exe import $reg.FullName | Out-Null; Write-Good ("Imported " + $reg.Name) }
            catch { Write-WarnLine ("Registry import failed for " + $reg.Name) }
        }
    }
    $hostsBak = Join-Path $Path 'hosts-backup'
    if (Test-Path $hostsBak) {
        if (Ask-YesNo 'Restore the hosts file from backup?' $false) {
            try {
                Copy-Item $hostsBak (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Force
                Write-Good 'Restored hosts file.'
            } catch { Write-WarnLine 'Hosts restore failed.' }
        }
    }
    Write-Host 'Note: deleted user accounts and deleted files cannot be fully undone.'
    Write-Host 'The backup folder contains user/group exports so accounts can be re-created,'
    Write-Host 'and quarantined (not deleted) files can be moved back from C:\CP-Quarantine.'
}

# ----------------------------------------------------------------------------
# Preflight
# ----------------------------------------------------------------------------
function Invoke-Preflight {
    Write-Banner 'STEP 1 OF 12 - PREFLIGHT (read-only checks)'
    if (-not (Test-Admin)) {
        if (-not $NoElevate) {
            Write-WarnLine 'Not running as Administrator. Relaunching with elevation ...'
            try {
                $elevArgs = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Mode ' + $Mode + ' -NoElevate'
                if ($ForensicsDone) { $elevArgs += ' -ForensicsDone' }
                if ($ReadmeConfigured) { $elevArgs += ' -ReadmeConfigured' }
                Start-Process powershell.exe -ArgumentList $elevArgs -WorkingDirectory $script:Root -Verb RunAs
                return $false
            } catch { Write-WarnLine ("Elevation failed: " + $_.Exception.Message) }
        }
        Write-WarnLine 'Please right-click secure.bat and choose "Run as administrator".'
        return $false
    }
    Write-Good 'Running as Administrator.'

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $script:OSCaption = $os.Caption
        $build = $os.BuildNumber
        $productType = $os.ProductType  # 1=workstation, 2=domain controller, 3=server
        $script:IsServer = ($productType -ne 1)
        if ($productType -eq 2) { $script:IsDC = $true }
        $cs = Get-CimInstance Win32_ComputerSystem
        $script:DomainJoined = [bool]$cs.PartofDomain
        Write-Step ("OS: " + $script:OSCaption + "  build " + $build)
        $role = 'Workstation'
        if ($script:IsDC) { $role = 'DOMAIN CONTROLLER' }
        elseif ($script:IsServer) { $role = 'Server (member or standalone)' }
        Write-Step ("Role: " + $role + "   Domain joined: " + $script:DomainJoined)
        Write-Step ("Computer: " + $env:COMPUTERNAME + "   You are signed in as: " + $script:CurrentUser + " (always protected)")
        if ($script:IsDC) {
            Write-WarnLine 'Domain Controller detected: NO domain users will be created/deleted by'
            Write-WarnLine 'this script (report only), and AD/DNS/Kerberos services are protected.'
        }
    } catch { Write-WarnLine 'Could not fully detect the OS role; continuing carefully.' }

    $scoreSvcs = @(Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match $script:ProtectedPatterns -or $_.DisplayName -match $script:ProtectedPatterns
    })
    foreach ($s in $scoreSvcs) {
        Write-Step ("Protected service seen: " + $s.Name + " (" + $s.DisplayName + ") - " + $s.Status)
    }
    if ($scoreSvcs.Count -eq 0) {
        Write-WarnLine 'No CyberPatriot/CCS/VM-tools service was detected by name. That can be'
        Write-WarnLine 'normal, but NEVER stop anything inside C:\CyberPatriot and keep the'
        Write-WarnLine 'image connected to the scoring server (outbound port 80/443).'
    }

    # Load the README-driven lists in every mode (in Audit they make the
    # dry-run accurate; the same lines run again below for apply modes).
    $script:KeepEntries = @(Get-TextList (Join-Path $script:Root 'keep_services.txt') | Where-Object { $_ -ne 'EDIT_ME' })
    $script:AuthorizedUsers = @(Get-TextList (Join-Path $script:Root 'authorizedusers.txt') | Where-Object { $_ -ne 'EDIT_ME' })
    $script:AuthorizedAdmins = @(Get-TextList (Join-Path $script:Root 'admins.txt') | Where-Object { $_ -ne 'EDIT_ME' })
    $script:RdpUsers = @(Get-TextList (Join-Path $script:Root 'rdpusers.txt') | Where-Object { $_ -ne 'EDIT_ME' })
    $script:FileSharingCritical = Test-TokenKept @('SMB','FILES','FILE','SHARES')
    $script:RdpCritical = Test-TokenKept @('RDP','REMOTEDESKTOP','REMOTE DESKTOP','REMOTE')

    if ($script:AuditOnly) {
        Write-Step 'Mode = Audit: every module runs as a read-only dry-run; nothing is changed.'
        return $true
    }

    Write-Host ''
    Write-Host 'GOLDEN RULES before hardening:' -ForegroundColor Yellow
    Write-Host '  1. Open the Scoring Report and leave it visible. Note your starting score.'
    Write-Host '  2. Answer ALL Forensic Questions first - hardening/deleting can destroy evidence.'
    Write-Host '  3. Fill in keep_services.txt, authorizedusers.txt, admins.txt (and rdpusers.txt'
    Write-Host '     if Remote Desktop is critical) from the README and delete each EDIT_ME line.'
    Write-Host '  4. If your coach and rules allow it, snapshot the VM now.'
    Write-Host '  5. This script never reboots the machine. Any reboot is your choice, later.'
    Write-Host ''

    if (-not $ForensicsDone) {
        if (-not (Ask-YesNo 'Have you finished ALL Forensic Questions (and seen the points)?' $false)) {
            Write-WarnLine 'Stopping before any changes. Re-run with -Mode Audit for read-only reports,'
            Write-WarnLine 'or finish the forensics questions and run the script again.'
            return $false
        }
    }

    $keepFile = Join-Path $script:Root 'keep_services.txt'
    $usersFile = Join-Path $script:Root 'authorizedusers.txt'
    $adminsFile = Join-Path $script:Root 'admins.txt'
    $unedited = @()
    if (-not (Test-FileEdited $keepFile)) { $unedited += 'keep_services.txt' }
    if (-not (Test-FileEdited $usersFile)) { $unedited += 'authorizedusers.txt' }
    if (-not (Test-FileEdited $adminsFile)) { $unedited += 'admins.txt' }
    if ($unedited.Count -gt 0 -and -not $ReadmeConfigured) {
        Write-WarnLine ("These files still contain EDIT_ME (not yet filled in from the README): " + ($unedited -join ', '))
        Write-WarnLine 'Modules that depend on them will be SKIPPED (services, users, groups,'
        Write-WarnLine 'remote desktop hardening). Safe modules can still run.'
    }

    $script:KeepEntries = @(Get-TextList $keepFile | Where-Object { $_ -ne 'EDIT_ME' })
    $script:AuthorizedUsers = @(Get-TextList $usersFile | Where-Object { $_ -ne 'EDIT_ME' })
    $script:AuthorizedAdmins = @(Get-TextList $adminsFile | Where-Object { $_ -ne 'EDIT_ME' })
    $script:RdpUsers = @(Get-TextList (Join-Path $script:Root 'rdpusers.txt') | Where-Object { $_ -ne 'EDIT_ME' })
    $script:FileSharingCritical = Test-TokenKept @('SMB','FILES','FILE','SHARES')
    $script:RdpCritical = Test-TokenKept @('RDP','REMOTEDESKTOP','REMOTE DESKTOP','REMOTE')
    Write-Step ("Critical-service entries loaded: " + ($script:KeepEntries -join ', '))
    if ($script:FileSharingCritical) { Write-Step 'File sharing (SMB) is marked critical - server service and shares are protected.' }
    if ($script:RdpCritical) { Write-Step 'Remote Desktop is marked critical - it will be SECURED, not disabled.' }
    return $true
}

function Test-ConfigReady {
    # True when the README-driven files have actually been edited.
    if ($ReadmeConfigured) { return $true }
    $ok = (Test-FileEdited (Join-Path $script:Root 'keep_services.txt')) -and
          (Test-FileEdited (Join-Path $script:Root 'authorizedusers.txt')) -and
          (Test-FileEdited (Join-Path $script:Root 'admins.txt'))
    return $ok
}

# ----------------------------------------------------------------------------
# Backup
# ----------------------------------------------------------------------------
function Invoke-Backup {
    if ($script:AuditOnly) { return }
    Write-Banner 'STEP 2 OF 12 - BACKUP (everything changed is backed up first)'
    if (-not (Test-Path $script:BackupDir)) { New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null }
    Write-Step ("Backup folder: " + $script:BackupDir)
    try { & secedit.exe /export /cfg (Join-Path $script:BackupDir 'secedit-backup.cfg') /quiet | Out-Null } catch {}
    try { $auditFile = Join-Path $script:BackupDir 'auditpol-backup.csv'; & auditpol.exe /backup "/file:$auditFile" | Out-Null } catch {}
    try { & netsh.exe advfirewall export (Join-Path $script:BackupDir 'firewall-backup.wfw') | Out-Null } catch {}
    try {
        Get-Service | Select-Object 'Name','DisplayName','Status','StartType' |
            Export-Csv (Join-Path $script:BackupDir 'services-backup.csv') -NoTypeInformation
    } catch {}
    Export-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows' (Join-Path $script:BackupDir 'reg-policies-windows.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' (Join-Path $script:BackupDir 'reg-lsa.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' (Join-Path $script:BackupDir 'reg-lanmanserver.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' (Join-Path $script:BackupDir 'reg-lanmanworkstation.reg')
    Export-RegKey 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' (Join-Path $script:BackupDir 'reg-policies-system.reg')
    try { Copy-Item (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') (Join-Path $script:BackupDir 'hosts-backup') -Force -ErrorAction SilentlyContinue } catch {}
    try {
        if ($script:IsDC) { & net.exe user /domain | Out-File (Join-Path $script:BackupDir 'domain-users.txt') }
        elseif (Test-CommandExists 'Get-LocalUser') {
            Get-LocalUser -ErrorAction SilentlyContinue | Out-File (Join-Path $script:BackupDir 'local-users.txt')
            Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
                $g = $_
                ("== " + $g.Name) | Out-File (Join-Path $script:BackupDir 'local-groups.txt') -Append
                Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Out-String | Out-File (Join-Path $script:BackupDir 'local-groups.txt') -Append
            }
        }
    } catch {}
    $lgpo = Join-Path $script:Root 'LGPO.exe'
    if (Test-Path $lgpo) {
        try { & $lgpo /b $script:BackupDir /n 'CP-Backup' | Out-Null } catch {}
    }
    Write-Good 'Backup complete. Undo everything later with: .\secure.ps1 -Rollback'
}

# ----------------------------------------------------------------------------
# Recon reports (always read-only)
# ----------------------------------------------------------------------------
function Get-InstalledPrograms {
    $keys = @(
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = @()
    foreach ($k in $keys) {
        try {
            $apps += Get-ItemProperty $k -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object 'DisplayName','DisplayVersion','Publisher','UninstallString'
        } catch {}
    }
    return @($apps | Sort-Object DisplayName -Unique)
}

function Get-LocalUserNamesSafe {
    $names = @()
    if ($script:IsDC) { return $names }
    if (Test-CommandExists 'Get-LocalUser') {
        try { $names = @(Get-LocalUser -ErrorAction Stop | Select-Object -ExpandProperty Name); return $names } catch {}
    }
    try {
        $dir = [ADSI]('WinNT://' + $env:COMPUTERNAME)
        foreach ($child in $dir.Children) {
            if ($child.SchemaClassName -eq 'User') { $names += $child.Name }
        }
    } catch {}
    return $names
}

function Get-ServiceLogonAccounts {
    $accts = @()
    try {
        foreach ($svc in (Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $startName = "$($svc.StartName)"
            if ($startName -and $startName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT Service\\)') {
                $short = ($startName -split '\\')[-1]
                if ($short -and $accts -notcontains $short) { $accts += $short }
            }
        }
    } catch {}
    return $accts
}

function Invoke-Recon {
    Write-Banner 'STEP 3 OF 12 - RECON REPORTS (read-only; use these to hunt points)'
    $report = 'recon.txt'
    Write-Step ("Writing reports to " + $script:ReportDir)

    try { Add-Report $report 'Local users' (Get-LocalUser -ErrorAction SilentlyContinue | Format-Table 'Name','Enabled','PasswordLastSet','UserMayChangePassword','PasswordExpires' -AutoSize | Out-String) } catch {}
    try {
        $members = @()
        foreach ($gName in @('Administrators','Users','Guests','Remote Desktop Users','Backup Operators','Hyper-V Administrators','Remote Management Users','Print Operators','Server Operators','Account Operators')) {
            try {
                $mem = @(Get-LocalGroupMember $gName -ErrorAction Stop | Select-Object -ExpandProperty Name)
                $members += ($gName + ': ' + ($mem -join ', '))
            } catch {}
        }
        Add-Report $report 'Important local group membership' ($members -join "`r`n")
    } catch {}

    try {
        $hidden = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' -ErrorAction SilentlyContinue
        Add-Report $report 'Hidden-at-logon accounts (SpecialAccounts UserList)' $hidden
    } catch {}

    try {
        $svcLogons = @(Get-ServiceLogonAccounts)
        Add-Report $report 'Accounts that Windows services sign in with (NEVER change their passwords)' ($svcLogons -join ', ')
    } catch {}

    try {
        $shares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object 'Name','Path','Description'
        Add-Report $report 'SMB shares' $shares
        foreach ($sh in @($shares)) {
            try { Add-Report $report ("Share access: " + $sh.Name) (Get-SmbShareAccess $sh.Name -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String) } catch {}
        }
    } catch {}

    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Select-Object 'LocalAddress','LocalPort','OwningProcess'
        $rows = foreach ($l in $listeners) {
            $procName = ''
            try { $procName = (Get-Process -Id $l.OwningProcess -ErrorAction Stop).Name } catch {}
            [PSCustomObject]@{ Address = $l.LocalAddress; Port = $l.LocalPort; PID = $l.OwningProcess; Process = $procName }
        }
        Add-Report $report 'Listening TCP ports' ($rows | Sort-Object Port | Format-Table -AutoSize | Out-String)
    } catch {}

    try { Add-Report $report 'Installed programs (scan this list against the README)' (Get-InstalledPrograms | Format-Table 'DisplayName','DisplayVersion','Publisher' -AutoSize | Out-String) } catch {}
    try {
        $auto = Get-Service | Where-Object { $_.StartType -match 'Automatic' } | Select-Object 'Name','DisplayName','Status'
        Add-Report $report 'Automatic-start services' $auto
        $weird = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -and $_.PathName -notlike '*\Windows\*' } |
            Select-Object 'Name','State','StartName','PathName'
        Add-Report $report 'Services running from outside the Windows folder (check these by hand)' ($weird | Format-List | Out-String)
        $unquoted = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -match '\s.*\.exe' } |
            Select-Object 'Name','PathName'
        Add-Report $report 'Possibly unquoted service paths (fix by hand only, with care)' $unquoted
    } catch {}

    try {
        $runs = @()
        foreach ($rk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
            try {
                $props = Get-ItemProperty $rk -ErrorAction Stop
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -notmatch '^PS') { $runs += ($rk + ' :: ' + $prop.Name + ' = ' + $prop.Value) }
                }
            } catch {}
        }
        Add-Report $report 'Run / RunOnce autostart entries' ($runs -join "`r`n")
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            Select-Object 'TaskPath','TaskName','State'
        Add-Report $report 'Non-Microsoft scheduled tasks (check each action by hand)' $tasks
        $ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $ifeo = @()
        foreach ($sub in @(Get-ChildItem $ifeoBase -ErrorAction SilentlyContinue)) {
            $dbg = Get-ItemProperty $sub.PSPath -Name Debugger -ErrorAction SilentlyContinue
            if ($null -ne $dbg) { $ifeo += ($sub.PSChildName + ' Debugger = ' + $dbg.Debugger) }
        }
        Add-Report $report 'Image File Execution Options DEBUGGERS (sethc/utilman entries here = Sticky Keys backdoor)' ($ifeo -join "`r`n")
        $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
        Add-Report $report 'Winlogon Shell/Userinit/AutoAdminLogon (Shell must be explorer.exe)' (
            'Shell=' + $wl.Shell + "`r`nUserinit=" + $wl.Userinit + "`r`nAutoAdminLogon=" + $wl.AutoAdminLogon + "`r`nDefaultUserName=" + $wl.DefaultUserName)
        $hostsLines = Get-Content (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -ErrorAction SilentlyContinue |
            Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') }
        Add-Report $report 'Active hosts-file lines (anything beyond localhost needs a reason from the README)' ($hostsLines -join "`r`n")
        $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses } | Select-Object 'InterfaceAlias','ServerAddresses'
        Add-Report $report 'DNS servers (confirm these match the README / your school network)' $dns
        $wmiPersist = @()
        try {
            $wmiPersist = Get-CimInstance -Namespace 'root\subscription' -ClassName __EventFilter -ErrorAction Stop |
                Select-Object 'Name','Query'
        } catch {}
        Add-Report $report 'WMI event subscriptions (persistence technique - should normally be empty)' $wmiPersist
    } catch {}

    Write-Good ("Recon saved (recon.txt). Skim it now - unexplained listeners, autostarts and IFEO debuggers are points AND forensics clues. Nothing was changed.")
}

# ----------------------------------------------------------------------------
# Passwords (runs BEFORE the password-age policy is applied)
# ----------------------------------------------------------------------------
function Test-PasswordStrength {
    param([string]$Plain)
    if ($Plain.Length -lt 14) { return $false }
    $classes = 0
    if ($Plain -cmatch '[A-Z]') { $classes++ }
    if ($Plain -cmatch '[a-z]') { $classes++ }
    if ($Plain -match '[0-9]') { $classes++ }
    if ($Plain -match '[^A-Za-z0-9]') { $classes++ }
    return ($classes -ge 3)
}

function Set-UserPasswordSafe {
    param([string]$User, [Security.SecureString]$Password)
    try {
        if (Test-CommandExists 'Set-LocalUser') {
            Set-LocalUser -Name $User -Password $Password -ErrorAction Stop
            return $true
        }
    } catch { Write-WarnLine ("Set-LocalUser failed for " + $User + ': ' + $_.Exception.Message) }
    try {
        $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        & net.exe user $User $plain | Out-Null
        $plain = $null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Invoke-Passwords {
    Write-Banner 'STEP 4 OF 12 - CHANGE WEAK/DEFAULT PASSWORDS (before password policy)'
    if ($script:IsDC) {
        Write-WarnLine 'Domain Controller: domain passwords are NOT bulk-changed here (that would'
        Write-WarnLine 'break services across the domain). Change specific domain users by hand'
        Write-WarnLine 'with Active Directory Users and Computers, guided by the README.'
        return
    }
    if (-not (Ask-YesNo 'Change passwords for authorized local users (NOT you, not built-ins, not service accounts)?' $true)) { return }
    if ($script:AuditOnly) {
        $auditLogons = @(Get-ServiceLogonAccounts)
        foreach ($auditName in @(Get-LocalUserNamesSafe)) {
            if ($auditName -ieq $script:CurrentUser) { Write-Host ("[AUDIT] Password step would SKIP you (" + $auditName + ")"); continue }
            if ($script:BuiltInUsers -contains $auditName) { Write-Host ("[AUDIT] Password step would SKIP built-in " + $auditName); continue }
            if ($auditLogons -contains $auditName) { Write-Host ("[AUDIT] Password step would SKIP service account " + $auditName); continue }
            Write-Host ("[AUDIT] Password step would offer to reset: " + $auditName)
        }
        return
    }

    Write-Host 'Choose ONE new strong password for the team to use on this image.'
    Write-Host 'It must be at least 14 characters with upper, lower, digit or symbol (3 of 4 kinds).'
    Write-Host 'Write it down OFFLINE now - you will need it after any reboot.'
    while ($true) {
        $pw1 = Read-Host 'New password (typing is hidden)' -AsSecureString
        $pw2 = Read-Host 'New password again' -AsSecureString
        $ptr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1)
        $plain1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr1)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr1)
        $ptr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2)
        $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr2)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr2)
        $match = ($plain1 -ceq $plain2)
        $strong = Test-PasswordStrength $plain1
        $plain1 = $null; $plain2 = $null
        if (-not $match) { Write-WarnLine 'The two passwords did not match. Try again.'; continue }
        if (-not $strong) { Write-WarnLine 'Too weak or short (need 14+ characters and 3 of 4 character kinds).'; continue }
        $script:TeamPassword = $pw1
        break
    }

    $serviceLogons = @(Get-ServiceLogonAccounts)
    $names = @(Get-LocalUserNamesSafe)
    foreach ($name in $names) {
        if ($name -ieq $script:CurrentUser) { Write-Step ("Skipping you (" + $name + ") - handled at the very end if you choose."); continue }
        if ($script:BuiltInUsers -contains $name) { Write-Step ("Skipping built-in account " + $name + "."); continue }
        if ($serviceLogons -contains $name) { Write-WarnLine ("Skipping service account " + $name + " (changing it would break its service)."); continue }
        if ($script:AuthorizedUsers.Count -gt 0) {
            $allowed = $false
            foreach ($a in $script:AuthorizedUsers) { if ($a -ieq $name) { $allowed = $true } }
            if (-not $allowed) { Write-Step ("Skipping " + $name + " - not in authorizedusers.txt (user-audit step decides its fate)."); continue }
        }
        if (Set-UserPasswordSafe -User $name -Password $script:TeamPassword) {
            Write-Good ("Changed password for " + $name + ".")
            try { if (Test-CommandExists 'Unlock-LocalUser') { Unlock-LocalUser -Name $name -ErrorAction SilentlyContinue } } catch {}
        } else {
            Write-WarnLine ("Could NOT change the password for " + $name + " - note it and try by hand in lusrmgr.")
        }
    }
    Write-Host 'If a user will sign in during the round, their password is now the one you just chose.'
}

# ----------------------------------------------------------------------------
# Account policy + user rights (secedit)
# ----------------------------------------------------------------------------
function Invoke-SecurityTemplate {
    param([string[]]$Lines, [string]$Label)
    $infPath = Join-Path $env:TEMP ('cp-' + $Label + '.inf')
    $dbPath = Join-Path $env:TEMP ('cp-' + $Label + '.sdb')
    $content = @('[Unicode]','Unicode=yes','[Version]','signature="$CHICAGO$"','Revision=1') + $Lines
    try {
        $content | Out-File $infPath -Encoding Unicode -Force
        & secedit.exe /configure /db $dbPath /cfg $infPath /areas SECURITYPOLICY /quiet | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Good ("Applied security template: " + $Label); return $true }
        Write-WarnLine ("secedit returned code " + $LASTEXITCODE + " for " + $Label + ' (see Logs / %windir%\security\logs\scesrv.log).')
        return $false
    } catch {
        Write-WarnLine ("Could not apply template " + $Label + ': ' + $_.Exception.Message)
        return $false
    }
}

function Invoke-AccountPolicy {
    Write-Banner 'STEP 5 OF 12 - PASSWORD + LOCKOUT POLICY (CIS / Microsoft baseline values)'
    if (-not (Ask-YesNo ("Apply: min length " + $MinPasswordLength + ", history " + $PasswordHistorySize + ", max age " + $MaxPasswordAgeDays + " days, min age " + $MinPasswordAgeDays + ", lockout " + $LockoutThreshold + "/" + $LockoutDurationMin + "/" + $LockoutResetMin + " ?") $true)) { return }
    if ($script:IsDC) {
        Write-WarnLine 'On a Domain Controller this sets LOCAL policy; the effective domain'
        Write-WarnLine 'password policy lives in the Default Domain Policy GPO. If the score'
        Write-WarnLine 'does not move, set the same values in Group Policy Management.'
    }
    $lines = @(
        '[System Access]',
        ('MinimumPasswordLength = ' + $MinPasswordLength),
        ('PasswordHistorySize = ' + $PasswordHistorySize),
        ('MaximumPasswordAge = ' + $MaxPasswordAgeDays),
        ('MinimumPasswordAge = ' + $MinPasswordAgeDays),
        'PasswordComplexity = 1',
        'ClearTextPassword = 0',
        ('LockoutBadCount = ' + $LockoutThreshold),
        ('LockoutDuration = ' + $LockoutDurationMin),
        ('ResetLockoutCount = ' + $LockoutResetMin),
        'LSAAnonymousNameLookup = 0'
    )
    if ($script:AuditOnly) { Write-Host '[AUDIT] Would apply the account-policy template and the conservative user-rights template (see function Invoke-AccountPolicy / docs).'; return }
    [void](Invoke-SecurityTemplate -Lines $lines -Label 'accountpolicy')
    Write-Step 'Reminder: passwords were changed BEFORE this policy, so nobody is instantly expired.'

    # ---- conservative user-rights subset ----
    if (Ask-YesNo 'Apply conservative User Rights (deny Guests, strip dangerous privileges, admin-only backup/debug/etc.)?' $true) {
        $rights = @(
            '[Privilege Rights]',
            'SeCreateTokenPrivilege =',
            'SeTcbPrivilege =',
            'SeCreatePermanentPrivilege =',
            'SeTrustedCredManAccessPrivilege =',
            'SeLockMemoryPrivilege =',
            'SeEnableDelegationPrivilege =',
            'SeBackupPrivilege = *S-1-5-32-544',
            'SeRestorePrivilege = *S-1-5-32-544',
            'SeDebugPrivilege = *S-1-5-32-544',
            'SeLoadDriverPrivilege = *S-1-5-32-544',
            'SeSecurityPrivilege = *S-1-5-32-544',
            'SeTakeOwnershipPrivilege = *S-1-5-32-544',
            'SeCreatePagefilePrivilege = *S-1-5-32-544',
            'SeProfileSingleProcessPrivilege = *S-1-5-32-544',
            'SeSystemEnvironmentPrivilege = *S-1-5-32-544',
            'SeManageVolumePrivilege = *S-1-5-32-544',
            'SeRemoteShutdownPrivilege = *S-1-5-32-544'
        )
        $denyGuests = '*S-1-5-32-546'
        $rights += ('SeDenyInteractiveLogonRight = ' + $denyGuests)
        $rights += ('SeDenyBatchLogonRight = ' + $denyGuests)
        $rights += ('SeDenyServiceLogonRight = ' + $denyGuests)
        $denyNetwork = $denyGuests
        if (-not $script:FileSharingCritical) {
            # Also deny "Local account" over the network ONLY when local users
            # do not need SMB shares on this machine.
            $denyNetwork += ',*S-1-5-113'
        }
        $rights += ('SeDenyNetworkLogonRight = ' + $denyNetwork)
        $denyRemote = $denyGuests
        if (-not $script:RdpCritical) { $denyRemote += ',*S-1-5-113' }
        $rights += ('SeDenyRemoteInteractiveLogonRight = ' + $denyRemote)
        if ($script:IsServer) { $rights += 'SeShutdownPrivilege = *S-1-5-32-544' }
        [void](Invoke-SecurityTemplate -Lines $rights -Label 'userrights')
        Write-Step 'Deliberately NOT reassigning "Access this computer from the network" or'
        Write-Step '"Allow log on locally": getting those wrong can lock out critical users.'
    }
}

# ----------------------------------------------------------------------------
# Security options (registry)
# ----------------------------------------------------------------------------
function Invoke-SecurityOptions {
    Write-Banner 'STEP 6A OF 12 - SECURITY OPTIONS (LSA, UAC, logon, SMB signing, sessions)'
    if (-not (Ask-YesNo 'Apply security options (each value is logged, defaults follow CIS / Microsoft baselines)?' $true)) { return }

    $systemPol = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-RegValue $systemPol 'dontdisplaylastusername' 1 'DWord' 'Do not display last signed-in user'
    Set-RegValue $systemPol 'DontDisplayLockedUserId' 3 'DWord' 'Do not display user info on lock screen'
    Set-RegValue $systemPol 'DisableCAD' 0 'DWord' 'Require Ctrl+Alt+Del'
    Set-RegValue $systemPol 'InactivityTimeoutSecs' 900 'DWord' 'Machine inactivity lock (15 min)'
    Set-RegValue $systemPol 'EnableLUA' 1 'DWord' 'UAC on'
    Set-RegValue $systemPol 'ConsentPromptBehaviorAdmin' 2 'DWord' 'UAC prompt for consent on secure desktop'
    Set-RegValue $systemPol 'ConsentPromptBehaviorUser' 0 'DWord' 'UAC automatically deny standard users'
    Set-RegValue $systemPol 'PromptOnSecureDesktop' 1 'DWord' 'UAC switch to secure desktop'
    Set-RegValue $systemPol 'EnableInstallerDetection' 1 'DWord' ''
    Set-RegValue $systemPol 'EnableSecureUIAPaths' 1 'DWord' ''
    Set-RegValue $systemPol 'EnableVirtualization' 1 'DWord' 'UAC file/registry virtualization'
    Set-RegValue $systemPol 'FilterAdministratorToken' 1 'DWord' 'Admin Approval Mode for built-in Administrator'
    Set-RegValue $systemPol 'ValidateAdminCodeSignatures' 0 'DWord' 'CIS: do not require signed-only elevation (keeps tools working)'
    Set-RegValue $systemPol 'LocalAccountTokenFilterPolicy' 0 'DWord' 'Remote UAC token filtering on'
    Set-RegValue $systemPol 'undockwithoutlogon' 0 'DWord' ''
    Set-RegValue ($systemPol + '\CredSSP\Parameters') 'AllowEncryptionOracle' 0 'DWord' 'CredSSP encryption oracle = Force Updated Clients'

    $lsa = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-RegValue $lsa 'LmCompatibilityLevel' 5 'DWord' 'NTLMv2 only, refuse LM and NTLMv1'
    Set-RegValue $lsa 'NoLMHash' 1 'DWord' 'Do not store LAN Manager hash'
    Set-RegValue $lsa 'RestrictAnonymous' 1 'DWord' 'Restrict anonymous access to named pipes/shares'
    Set-RegValue $lsa 'RestrictAnonymousSAM' 1 'DWord' 'Do not allow anonymous enumeration of SAM accounts'
    Set-RegValue $lsa 'EveryoneIncludesAnonymous' 0 'DWord' 'Let Everyone permissions apply to anonymous = OFF'
    Set-RegValue $lsa 'LimitBlankPasswordUse' 1 'DWord' 'Blank passwords: console logon only'
    Set-RegValue $lsa 'DisableDomainCreds' 1 'DWord' 'Do not allow storage of passwords for network auth'
    Set-RegValue $lsa 'CrashOnAuditFail' 0 'DWord' 'Never halt the system if audits cannot be logged'
    Set-RegValue $lsa 'AuditBaseObjects' 0 'DWord' 'CIS: global system object auditing OFF (undoes 2019 script)'
    Set-RegValue $lsa 'FullPrivilegeAuditing' 0 'DWord' 'CIS: backup/restore privilege auditing OFF (undoes 2019 script)'
    Set-RegValue $lsa 'SCENoApplyLegacyAuditPolicy' 1 'DWord' 'Force advanced audit subcategories'
    Set-RegValue $lsa 'RunAsPPL' 1 'DWord' 'LSASS protected-process (takes effect at reboot)'
    Set-RegValue $lsa 'RestrictRemoteSAM' 'O:BAG:BAD:(A;;RC;;;BA)' 'String' 'Restrict remote SAM calls to Administrators'
    Set-RegValue ($lsa + '\MSV1_0') 'NTLMMinClientSec' 537395200 'DWord' 'Require NTLMv2 session security + 128-bit (client)'
    Set-RegValue ($lsa + '\MSV1_0') 'NTLMMinServerSec' 537395200 'DWord' 'Require NTLMv2 session security + 128-bit (server)'
    Set-RegValue ($lsa + '\MSV1_0') 'AllowNullSessionFallback' 0 'DWord' ''
    Set-RegValue ($lsa + '\MSV1_0') 'UseMachineId' 1 'DWord' 'Allow Local System to use computer identity for NTLM'
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' 'UseLogonCredential' 0 'DWord' 'WDigest must not keep plaintext passwords in memory'
    $lsassIfeo = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe'
    Set-RegValue $lsassIfeo 'AuditLevel' 8 'DWord' 'Audit LSASS read attempts'

    $netlogon = 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    Set-RegValue $netlogon 'DisablePasswordChange' 0 'DWord' 'Machine account password changes ALLOWED (fixes 2019 script value of 1)'
    Set-RegValue $netlogon 'MaximumPasswordAge' 30 'DWord' 'Machine account password max age 30 days'
    Set-RegValue $netlogon 'RequireStrongKey' 1 'DWord' ''
    Set-RegValue $netlogon 'RequireSignOrSeal' 1 'DWord' ''
    Set-RegValue $netlogon 'SignSecureChannel' 1 'DWord' ''
    Set-RegValue $netlogon 'SealSecureChannel' 1 'DWord' ''
    Set-RegValue $netlogon 'RefusePasswordChange' 0 'DWord' ''

    $smbAsk = Ask-YesNo 'Require SMB signing (client and server)? Choose NO only if this machine must talk to a very old non-Windows file device.' $true
    $srv = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    Set-RegValue $srv 'AutoDisconnect' 15 'DWord' 'Disconnect idle SMB sessions after 15 minutes'
    Set-RegValue $srv 'EnableSecuritySignature' 1 'DWord' 'SMB server signing enabled (fixes 2019 script value of 0)'
    Set-RegValue $srv 'RestrictNullSessAccess' 1 'DWord' 'Restrict null-session access'
    $wks = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    Set-RegValue $wks 'EnablePlainTextPassword' 0 'DWord' 'Never send unencrypted passwords to third-party SMB servers'
    Set-RegValue $wks 'EnableSecuritySignature' 1 'DWord' 'SMB client signing enabled'
    if ($smbAsk) {
        Set-RegValue $srv 'RequireSecuritySignature' 1 'DWord' 'SMB server requires signing'
        Set-RegValue $wks 'RequireSecuritySignature' 1 'DWord' 'SMB client requires signing'
    }
    if (-not $script:IsDC) {
        Set-RegValue $srv 'NullSessionShares' @('') 'MultiString' 'No shares reachable by null sessions'
        Set-RegValue $srv 'NullSessionPipes' @('') 'MultiString' 'No named pipes reachable by null sessions (not applied on DCs)'
    } else {
        Write-Step 'DC: leaving NullSessionPipes/Shares at domain-safe defaults (report only).'
    }
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' 'AllowInsecureGuestAuth' 0 'DWord' 'Block insecure guest SMB logons'

    $winlogon = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-RegValue $winlogon 'AllocateCDRoms' '1' 'String' 'Restrict CD-ROM to locally signed-in user'
    Set-RegValue $winlogon 'AllocateFloppies' '1' 'String' 'Restrict floppy to locally signed-in user'
    Set-RegValue $winlogon 'CachedLogonsCount' '4' 'String' 'Cache at most 4 previous domain logons'
    Set-RegValue $winlogon 'ScRemoveOption' '1' 'String' 'Smart-card removal locks the workstation'

    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Services\LDAP' 'LDAPClientIntegrity' 1 'DWord' 'LDAP client signing (negotiate)'
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' 'AddPrinterDrivers' 1 'DWord' 'Prevent users from installing printer drivers'
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' 1 'DWord' ''
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1 'DWord' ''
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'DisableExceptionChainValidation' 0 'DWord' 'SEHOP enabled'
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' 'Machine' @('') 'MultiString' 'No remotely accessible registry paths'
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths' 'Machine' @('') 'MultiString' 'No remotely accessible registry sub-paths'

    $explorerPol = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Set-RegValue $explorerPol 'NoDriveTypeAutoRun' 255 'DWord' 'Turn off AutoPlay on all drives'
    Set-RegValue $explorerPol 'NoAutoRun' 1 'DWord' 'Default AutoRun behavior: do not execute'
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CDROM') {
        Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Services\CDROM' 'AutoRun' 0 'DWord' 'CD AutoRun disabled (fixes 2019 wrong-hive value)'
    }

    # Help the human hunt: show hidden files, extensions (current user only).
    Set-RegValue 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'Hidden' 1 'DWord' 'Show hidden files for hunting'
    Set-RegValue 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ShowSuperHidden' 1 'DWord' 'Show protected OS files for hunting'
    Set-RegValue 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'HideFileExt' 0 'DWord' 'Always show file extensions'

    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowUnsolicited' 0 'DWord' 'No unsolicited Remote Assistance'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' 'fAllowToGetHelp' 0 'DWord' 'No solicited Remote Assistance'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1 'DWord' 'PowerShell script-block logging'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic' 0 'DWord' 'WinRM client: no Basic auth'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencryptedTraffic' 0 'DWord' 'WinRM client: no unencrypted traffic'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencryptedTraffic' 0 'DWord' 'WinRM service: no unencrypted traffic'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen' 1 'DWord' 'Windows SmartScreen on'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' 'ShellSmartScreenLevel' 'Warn' 'String' 'SmartScreen warns (not hard-block) so competition tools still run'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenEnabled' 1 'DWord' 'Edge SmartScreen on'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Edge' 'SmartScreenPuaEnabled' 1 'DWord' 'Edge blocks potentially unwanted apps'

    if (-not $script:AuditOnly) {
        if (Ask-YesNo 'Set Data Execution Prevention (DEP) to OptOut (all programs, applies at reboot)?' $true) {
            try { & bcdedit.exe /set '{current}' nx OptOut | Out-Null; Write-Good 'DEP set to OptOut via bcdedit.' }
            catch { Write-WarnLine 'bcdedit DEP change failed.' }
        }
        if (Ask-YesNo 'Set a logon banner? Only if the README asks for one (you will type the exact text).' $false) {
            $caption = Read-Host 'Banner caption (title)'
            $text = Read-Host 'Banner text'
            Set-RegValue $systemPol 'legalnoticecaption' $caption 'String' 'Interactive logon banner title'
            Set-RegValue $systemPol 'legalnoticetext' $text 'String' 'Interactive logon banner text'
        }
        Write-Step 'Deliberately NOT enabling "Clear pagefile at shutdown": it can add many'
        Write-Step 'minutes to shutdown inside a timed 4-hour round. See CHECKLIST.md.'
    }
}

# ----------------------------------------------------------------------------
# Audit policy + event logs
# ----------------------------------------------------------------------------
function Invoke-AuditPolicy {
    Write-Banner 'STEP 6B OF 12 - ADVANCED AUDIT POLICY + EVENT LOG SIZES'
    if (-not (Ask-YesNo 'Enable Success+Failure auditing for all categories and enlarge the event logs?' $true)) { return }
    $logPath = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog'
    Set-RegValue ($logPath + '\Security') 'MaxSize' 196608 'DWord' 'Security log at least 192 MB (policy)'
    Set-RegValue ($logPath + '\System') 'MaxSize' 32768 'DWord' 'System log at least 32 MB (policy)'
    Set-RegValue ($logPath + '\Application') 'MaxSize' 32768 'DWord' 'Application log at least 32 MB (policy)'
    Set-RegValue ($logPath + '\Setup') 'MaxSize' 32768 'DWord' 'Setup log at least 32 MB (policy)'
    Set-RegValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1 'DWord' 'Include command line in process-creation events'
    if ($script:AuditOnly) { return }
    foreach ($pair in @(@('Security', 201326592), @('System', 33554432), @('Application', 33554432), @('Setup', 33554432))) {
        try { & wevtutil.exe sl $pair[0] ('/ms:' + $pair[1]) /rt:false 2>$null | Out-Null } catch {}
    }
    try {
        & auditpol.exe /set /category:* /failure:enable /success:enable | Out-Null
        Write-Good 'Advanced audit policy: every subcategory now audits Success and Failure.'
        Write-Step 'That superset satisfies Success-only and Failure-only checks. Logs were enlarged first.'
    } catch { Write-WarnLine 'auditpol failed - check the transcript.' }
}

# ----------------------------------------------------------------------------
# Defender
# ----------------------------------------------------------------------------
function Invoke-Defender {
    Write-Banner 'STEP 7 OF 12 - MICROSOFT DEFENDER ANTIVIRUS'
    if (-not (Test-CommandExists 'Get-MpComputerStatus')) {
        Write-WarnLine 'Defender PowerShell cmdlets are not available (third-party AV or Server Core?).'
        Write-WarnLine 'Check the installed antivirus by hand: it must be on, updated, and must NOT'
        Write-WarnLine 'scan/quarantine the C:\CyberPatriot scoring folder.'
        return
    }
    try {
        $status = Get-MpComputerStatus
        Write-Step ("Antivirus enabled: " + $status.AntivirusEnabled + "  Real-time: " + $status.RealTimeProtectionEnabled + "  Tamper-protected: " + $status.IsTamperProtected)
        Write-Step ("Signatures: " + $status.AntivirusSignatureVersion + "  Last update: " + $status.AntivirusSignatureLastUpdated)
        if ($status.IsTamperProtected) {
            Write-WarnLine 'Tamper Protection is ON (good for safety). If any Defender change below does'
            Write-WarnLine 'not stick, temporarily turn Tamper Protection off in Windows Security,'
            Write-WarnLine 're-apply, then turn it back ON.'
        }
    } catch {}
    if (-not (Ask-YesNo 'Harden Defender (remove planted exclusions, enable cloud/PUA/script scanning, safe ASR)?' $true)) { return }

    try {
        $pref = Get-MpPreference
        $allExclusions = @()
        foreach ($kind in @('ExclusionPath','ExclusionProcess','ExclusionExtension')) {
            foreach ($val in @($pref.$kind)) {
                if ($val) { $allExclusions += [PSCustomObject]@{ Kind = $kind; Value = $val } }
            }
        }
        if ($allExclusions.Count -gt 0) {
            Write-Step 'Current Defender exclusions (planted exclusions are a classic scored vulnerability):'
            $allExclusions | ForEach-Object { Write-Host ('    ' + $_.Kind + ' : ' + $_.Value) }
            foreach ($ex in $allExclusions) {
                if ($ex.Value -match 'CyberPatriot|CCS') {
                    Write-WarnLine ("KEEPING scoring-related exclusion (protecting the scoring client): " + $ex.Value)
                    continue
                }
                $confirmed = $true
                if (-not $script:ApplySafe) { $confirmed = Ask-YesNo ("Remove exclusion " + $ex.Kind + ' "' + $ex.Value + '"?') $true }
                if ($confirmed -and -not $script:AuditOnly) {
                    try {
                        if ($ex.Kind -eq 'ExclusionPath') { Remove-MpPreference -ExclusionPath $ex.Value -ErrorAction Stop }
                        if ($ex.Kind -eq 'ExclusionProcess') { Remove-MpPreference -ExclusionProcess $ex.Value -ErrorAction Stop }
                        if ($ex.Kind -eq 'ExclusionExtension') { Remove-MpPreference -ExclusionExtension $ex.Value -ErrorAction Stop }
                        Write-Good ("Removed Defender exclusion: " + $ex.Value)
                    } catch { Write-WarnLine ("Could not remove exclusion " + $ex.Value + ' : ' + $_.Exception.Message) }
                }
            }
        } else {
            Write-Step 'No Defender exclusions present (good).'
        }
    } catch { Write-WarnLine ("Could not read Defender exclusions: " + $_.Exception.Message) }

    if ($script:AuditOnly) { return }
    $actions = @(
        @{ Script = { Set-MpPreference -DisableRealtimeMonitoring:$false }; Label = 'Real-time monitoring on' },
        @{ Script = { Set-MpPreference -DisableBehaviorMonitoring:$false }; Label = 'Behavior monitoring on' },
        @{ Script = { Set-MpPreference -DisableIOAVProtection:$false }; Label = 'Scan downloaded files/attachments on' },
        @{ Script = { Set-MpPreference -DisableScriptScanning:$false }; Label = 'Script scanning on' },
        @{ Script = { Set-MpPreference -DisableBlockAtFirstSeen:$false }; Label = 'Block at first sight on' },
        @{ Script = { Set-MpPreference -DisableArchiveScanning:$false }; Label = 'Archive scanning on' },
        @{ Script = { Set-MpPreference -DisableRemovableDriveScanning:$false }; Label = 'Removable-drive scanning on' },
        @{ Script = { Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan:$false }; Label = 'Mapped drives included in full scans' },
        @{ Script = { Set-MpPreference -MAPSReporting Advanced }; Label = 'Cloud protection (MAPS) Advanced' },
        @{ Script = { Set-MpPreference -SubmitSamplesConsent SendSafeSamples }; Label = 'Send safe samples automatically' },
        @{ Script = { Set-MpPreference -PUAProtection Enabled }; Label = 'Potentially-Unwanted-App blocking on' },
        @{ Script = { Set-MpPreference -CloudBlockLevel High }; Label = 'Cloud block level High' },
        @{ Script = { Set-MpPreference -CloudExtendedTimeout 50 }; Label = 'Cloud extended timeout 50s' },
        @{ Script = { Set-MpPreference -EnableControlledFolderAccess AuditMode }; Label = 'Controlled Folder Access = AUDIT (Block would break apps)' }
    )
    foreach ($a in $actions) {
        try { & $a.Script; Write-Good $a.Label }
        catch { Write-WarnLine ($a.Label + ' failed: ' + $_.Exception.Message) }
    }
    try { Set-MpPreference -EnableNetworkProtection AuditMode; Write-Good 'Network Protection = AUDIT (Block can cut off required sites; audit scores the setting without the risk)' }
    catch { Write-WarnLine 'Network Protection setting failed on this edition.' }

    # ASR: Microsoft's three Standard Protection rules in Block; the rest in
    # Audit so they score as "configured" without breaking a critical app.
    $asrBlock = @{
        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    }
    $asrAudit = @{
        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email/webmail'
        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executables unless prevalence/age/trusted'
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JS/VBScript launching downloaded executables'
        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from injecting code'
        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Outlook from creating child processes'
        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations from PSExec/WMI'
        '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted/unsigned processes from USB'
        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block copied or impersonated system tools'
        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Advanced protection against ransomware'
    }
    foreach ($id in $asrBlock.Keys) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
            Write-Good ("ASR BLOCK : " + $asrBlock[$id])
        } catch { Write-WarnLine ("ASR failed (" + $asrBlock[$id] + '): ' + $_.Exception.Message) }
    }
    foreach ($id in $asrAudit.Keys) {
        try {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions AuditMode -ErrorAction Stop
            Write-Good ("ASR AUDIT : " + $asrAudit[$id])
        } catch { Write-WarnLine ("ASR failed (" + $asrAudit[$id] + '): ' + $_.Exception.Message) }
    }
    Write-Step 'ASR note: only Microsoft''s three Standard Protection rules BLOCK. The rest'
    Write-Step 'AUDIT, which cannot break a critical service or the scoring client.'

    try { Update-MpSignature -ErrorAction Stop; Write-Good 'Defender signatures updated.' }
    catch { Write-WarnLine 'Signature update failed (check internet / Windows Update service).' }
    if (Ask-YesNo 'Run a Defender QUICK scan now? (Full scans are too slow for a 4-hour round.)' $true) {
        try { Start-MpScan -ScanType QuickScan; Write-Good 'Defender quick scan finished. Check Windows Security > Protection history.' }
        catch { Write-WarnLine 'Quick scan failed to start.' }
    }
}

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
function Invoke-Firewall {
    Write-Banner 'STEP 8 OF 12 - WINDOWS FIREWALL (on, block inbound, ALLOW outbound)'
    if (-not (Ask-YesNo 'Turn on all firewall profiles with secure defaults and logging?' $true)) { return }
    if (-not $script:AuditOnly) {
        try {
            Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules True -AllowLocalFirewallRules True -NotifyOnListen False -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction Stop
            Write-Good 'Firewall: all profiles ON, inbound BLOCK, outbound ALLOW (outbound must stay open for scoring + updates).'
            foreach ($prof in @('Domain','Private','Public')) {
                try { Set-NetFirewallProfile -Profile $prof -LogFileName ("%SystemRoot%\System32\LogFiles\Firewall\pfirewall-" + $prof.ToLower() + '.log') -ErrorAction SilentlyContinue } catch {}
            }
        } catch {
            Write-WarnLine 'NetSecurity cmdlets failed; falling back to netsh.'
            & netsh.exe advfirewall set allprofiles state on | Out-Null
            & netsh.exe advfirewall set allprofiles firewallpolicy 'blockinbound,allowoutbound' | Out-Null
            Write-Good 'Firewall enabled via netsh.'
        }
    }
    try { Get-NetFirewallProfile | Format-Table 'Name','Enabled','DefaultInboundAction','DefaultOutboundAction' -AutoSize | Out-String | Write-Host } catch {}
    Write-Step 'Listing ENABLED inbound ALLOW rules that expose risky ports (per-rule choice follows).'
    try {
        $riskyPorts = @('21','23','69','135','137','138','139','445','3389','5900','5800','5985','5986','22','80','443','53','25','110','143','3306','1433','1723','8080')
        $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue
        $hits = @()
        foreach ($rule in $rules) {
            try {
                $pf = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                $lp = "$($pf.LocalPort)"
                if ($riskyPorts -contains $lp -or $lp -eq 'Any') {
                    $hits += [PSCustomObject]@{ Name = $rule.DisplayName; Port = $lp; Profile = $rule.Profile }
                }
            } catch {}
        }
        Add-Report 'firewall.txt' 'Enabled inbound allow rules for risky ports (or Any)' ($hits | Format-Table -AutoSize | Out-String)
        foreach ($hit in $hits) {
            $keepIt = $false
            foreach ($k in $script:KeepEntries) {
                if ($k.Length -ge 3 -and $hit.Name.ToLower().Contains($k.ToLower())) { $keepIt = $true }
            }
            if ($script:RdpCritical -and $hit.Port -eq '3389') { $keepIt = $true }
            if ((Test-TokenKept @('IIS','WEB','APACHE')) -and ($hit.Port -eq '80' -or $hit.Port -eq '443')) { $keepIt = $true }
            if ((Test-TokenKept @('FTP')) -and $hit.Port -eq '21') { $keepIt = $true }
            if ((Test-TokenKept @('SSH')) -and $hit.Port -eq '22') { $keepIt = $true }
            if ((Test-TokenKept @('DNS')) -and $hit.Port -eq '53') { $keepIt = $true }
            if ($script:FileSharingCritical -and ($hit.Port -in @('445','139','137','138'))) { $keepIt = $true }
            if ($hit.Name -match $script:ProtectedPatterns) { $keepIt = $true }
            if ($keepIt) { Write-Step ("Keeping firewall rule (critical service): " + $hit.Name + ' port ' + $hit.Port); continue }
            Write-Host ("    Inbound allow: " + $hit.Name + "  port " + $hit.Port + "  profile " + $hit.Profile)
        }
        if ($hits.Count -gt 0 -and -not $script:AuditOnly) {
            Write-Host 'Firewall rules are NOT bulk-deleted (they may belong to critical services).'
            Write-Host 'Disable individual rules in wf.msc after checking the README, or re-run and use the report.'
            if (Ask-YesNo 'Open Windows Firewall with Advanced Security (wf.msc) now for manual review?' $false) {
                try { Start-Process wf.msc } catch {}
            }
        }
    } catch { Write-WarnLine 'Could not enumerate firewall rules on this system.' }
}

# ----------------------------------------------------------------------------
# Services + optional features
# ----------------------------------------------------------------------------
function Disable-ServiceSafe {
    param([string]$Name, [string]$Why)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return }
    if (Test-ServiceKept -Name $svc.Name -DisplayName $svc.DisplayName) {
        Write-Step ("PROTECTED (critical / keep list): " + $svc.Name + " (" + $svc.DisplayName + ")")
        return
    }
    $dependents = @()
    try { $dependents = @($svc.DependentServices | Where-Object { $_.Status -eq 'Running' }) } catch {}
    if ($dependents.Count -gt 0) {
        Write-WarnLine ("Skipping " + $Name + " - running services depend on it: " + (($dependents | Select-Object -ExpandProperty Name) -join ', '))
        return
    }
    if ($svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped') {
        Write-Step ("Already disabled: " + $Name)
        return
    }
    if ($script:AuditOnly) { Write-Host ("[AUDIT] Would stop+disable " + $Name + ' - ' + $Why); return }
    try { Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop } catch {
        Write-WarnLine ("Could not set " + $Name + " to Disabled: " + $_.Exception.Message)
        return
    }
    if ($svc.Status -ne 'Stopped') {
        try { Stop-Service -Name $Name -Force -ErrorAction Stop } catch {
            Write-WarnLine ("Set " + $Name + " to Disabled but could not stop it now: " + $_.Exception.Message)
            return
        }
    }
    Write-Good ("Stopped + disabled " + $Name + " (" + $svc.DisplayName + ') - ' + $Why)
}

function Invoke-Services {
    Write-Banner 'STEP 9A OF 12 - INSECURE SERVICES (README allow-list always wins)'
    $configReady = Test-ConfigReady
    if (-not $configReady) {
        Write-WarnLine 'keep_services.txt has not been edited from the README, so the service'
        Write-WarnLine 'module is restricted to a per-service manual walk (no bulk disabling).'
    }
    $autoList = @(
        @{ Name='TlntSvr';       Why='Telnet server (plaintext credentials)' },
        @{ Name='FTPSVC';        Why='IIS FTP service (plaintext credentials)' },
        @{ Name='MSFTPSVC';      Why='Legacy FTP publishing service' },
        @{ Name='W3SVC';         Why='IIS web server (disable only when no website is required)' },
        @{ Name='WAS';           Why='IIS process activation (goes with W3SVC)' },
        @{ Name='IISADMIN';      Why='IIS admin service' },
        @{ Name='SMTPSVC';       Why='Legacy IIS SMTP service' },
        @{ Name='SNMP';          Why='SNMP (weak community strings)' },
        @{ Name='SNMPTrap';      Why='SNMP trap receiver' },
        @{ Name='RemoteRegistry';Why='Remote Registry' },
        @{ Name='RpcLocator';    Why='RPC Locator (legacy)' },
        @{ Name='SSDPSRV';       Why='SSDP / UPnP discovery' },
        @{ Name='upnphost';      Why='UPnP device host' },
        @{ Name='Fax';           Why='Fax service' },
        @{ Name='bthserv';       Why='Bluetooth support (VMs have no Bluetooth)' },
        @{ Name='RemoteAccess';  Why='Routing and Remote Access' },
        @{ Name='simptcp';       Why='Simple TCP/IP services (echo/daytime etc.)' },
        @{ Name='Browser';       Why='Computer Browser (SMB1-era, deprecated)' },
        @{ Name='XblAuthManager';Why='Xbox Live Auth Manager' },
        @{ Name='XblGameSave';   Why='Xbox Live Game Save' },
        @{ Name='XboxNetApiSvc'; Why='Xbox Live Networking' },
        @{ Name='XboxGipSvc';    Why='Xbox Accessory Management' },
        @{ Name='sshd';          Why='OpenSSH Server (disable only when SSH is not a critical service)' }
    )
    $askList = @(
        @{ Name='Spooler';       Why='Print Spooler (PrintNightmare). Keep only if printing is critical' },
        @{ Name='LanmanServer';  Why='SMB Server / file sharing. Keep if shares are used' },
        @{ Name='fdPHost';       Why='Function Discovery Provider Host (keeps network discovery working)' },
        @{ Name='FDResPub';      Why='Function Discovery Resource Publication' },
        @{ Name='SharedAccess';  Why='Internet Connection Sharing' },
        @{ Name='RasMan';        Why='Remote Access Connection Manager (needed for VPN)' },
        @{ Name='RasAuto';       Why='Remote Access Auto Connection Manager' },
        @{ Name='SCardSvr';      Why='Smart Card (needed for smart-card sign-in)' },
        @{ Name='seclogon';      Why='Secondary Logon (needed for Run-as - you may want it)' },
        @{ Name='TrkWks';        Why='Distributed Link Tracking Client' },
        @{ Name='lmhosts';       Why='TCP/IP NetBIOS Helper (needed for NetBIOS name resolution)' },
        @{ Name='ssh-agent';     Why='OpenSSH Authentication Agent' }
    )

    Write-Step 'Group 1: classic insecure services.'
    $modeMsg = 'Disable Group 1 services that are present (skipping anything in keep_services.txt)?'
    if (-not $configReady) { $modeMsg = 'keep_services.txt is unedited. Walk Group 1 one-by-one with a question per service?' }
    if (Ask-YesNo $modeMsg $configReady) {
        foreach ($item in $autoList) {
            $svc = Get-Service -Name $item.Name -ErrorAction SilentlyContinue
            if ($null -eq $svc) { continue }
            if (Test-ServiceKept -Name $svc.Name -DisplayName $svc.DisplayName) {
                Write-Step ("PROTECTED (critical / keep list): " + $svc.Name + " (" + $svc.DisplayName + ")")
                continue
            }
            if (-not $configReady -and -not $script:AuditOnly) {
                if (-not (Ask-YesNo ("Disable " + $svc.Name + " (" + $svc.DisplayName + ')? ' + $item.Why) $false)) {
                    Write-Step ("Keeping " + $svc.Name + " at your choice.")
                    continue
                }
            }
            Disable-ServiceSafe -Name $item.Name -Why $item.Why
        }
    }

    Write-Step 'Group 2: judgment-call services (asked one-by-one, default KEEP).'
    foreach ($item in $askList) {
        $svc = Get-Service -Name $item.Name -ErrorAction SilentlyContinue
        if ($null -eq $svc) { continue }
        if (Test-ServiceKept -Name $svc.Name -DisplayName $svc.DisplayName) {
            Write-Step ("PROTECTED (critical / keep list): " + $svc.Name + " (" + $svc.DisplayName + ")")
            continue
        }
        if ($script:AuditOnly) { Write-Host ("[AUDIT] Judgment-call service present: " + $item.Name + ' - ' + $item.Why); continue }
        $defaultDisable = $false
        # Print Spooler on a Domain Controller: Microsoft/STIG guidance is to disable it.
        if ($item.Name -eq 'Spooler' -and $script:IsDC) { $defaultDisable = $true }
        if ($script:ApplySafe) {
            if ($defaultDisable) { Disable-ServiceSafe -Name $item.Name -Why $item.Why }
            else { Write-Step ("Keeping judgment-call service in ApplySafe mode: " + $item.Name) }
            continue
        }
        if (Ask-YesNo ("Disable " + $svc.Name + " (" + $svc.DisplayName + ')? ' + $item.Why) $defaultDisable) {
            Disable-ServiceSafe -Name $item.Name -Why $item.Why
        } else {
            Write-Step ("Keeping " + $svc.Name + " at your choice.")
        }
    }
    Write-Step 'Remote Desktop and WinRM are handled in the next module - not here.'

    # Optional Windows features that shrink attack surface without a service.
    if (-not $script:AuditOnly -and (Test-CommandExists 'Get-WindowsOptionalFeature')) {
        foreach ($feat in @('MicrosoftWindowsPowerShellV2Root','MicrosoftWindowsPowerShellV2','TelnetClient','TFTP')) {
            try {
                $state = (Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction Stop).State
                if ("$state" -eq 'Enabled') {
                    if (Ask-YesNo ("Disable Windows feature " + $feat + " (enabled now)? May need a reboot to finish.") $false) {
                        Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop | Out-Null
                        Write-Good ("Disabled feature: " + $feat)
                    }
                }
            } catch {}
        }
    }
}

# ----------------------------------------------------------------------------
# Remote access (RDP / Remote Assistance / WinRM)
# ----------------------------------------------------------------------------
function Invoke-RemoteAccess {
    Write-Banner 'STEP 9B OF 12 - REMOTE ACCESS (disable it, or secure it if it is critical)'
    $rdpRequired = $script:RdpCritical
    if (-not $rdpRequired) {
        $rdpRequired = Ask-YesNo 'Does the README REQUIRE Remote Desktop (RDP) on this machine?' $false
    }
    $tsKey = 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $tsPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    if ($rdpRequired) {
        Write-Step 'Securing Remote Desktop (it stays ON because the scenario needs it).'
        Set-RegValue $tsKey 'fDenyTSConnections' 0 'DWord' 'Allow Remote Desktop (critical service)'
        Set-RegValue $tsPol 'fDenyTSConnections' 0 'DWord' ''
        Set-RegValue ($tsKey + '\WinStations\RDP-Tcp') 'UserAuthentication' 1 'DWord' 'Require Network Level Authentication'
        Set-RegValue ($tsKey + '\WinStations\RDP-Tcp') 'SecurityLayer' 2 'DWord' 'Require SSL/TLS for RDP'
        Set-RegValue ($tsKey + '\WinStations\RDP-Tcp') 'MinEncryptionLevel' 3 'DWord' 'RDP encryption level High'
        Set-RegValue $tsPol 'MinEncryptionLevel' 3 'DWord' ''
        Set-RegValue $tsPol 'fPromptForPassword' 1 'DWord' 'Always prompt for password on RDP connect'
        if (-not $script:AuditOnly) {
            try { Set-Service TermService -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service TermService -ErrorAction SilentlyContinue } catch {}
            try { Enable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue } catch {}
            Write-Good 'Remote Desktop enabled with NLA. Restrict the Remote Desktop Users group in the user-audit step (rdpusers.txt).'
        }
    } else {
        Write-Step 'Disabling Remote Desktop (not required by the scenario).'
        Set-RegValue $tsKey 'fDenyTSConnections' 1 'DWord' 'Deny Remote Desktop connections'
        Set-RegValue $tsPol 'fDenyTSConnections' 1 'DWord' ''
        if (-not $script:AuditOnly) {
            foreach ($n in @('TermService','UmRdpService','SessionEnv')) { Disable-ServiceSafe -Name $n -Why 'Remote Desktop not required' }
            try { Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue } catch {}
        }
    }
    try {
        $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        if ($null -ne $winrm) {
            if (Test-ServiceKept -Name 'WinRM' -DisplayName 'Windows Remote Management (WS-Management)') {
                Write-Step 'PROTECTED (keep list): WinRM left running.'
            } else {
                if (Ask-YesNo 'Disable WinRM (Windows Remote Management) service? Keep it if the scenario manages servers remotely.' (-not $script:IsServer)) {
                    Disable-ServiceSafe -Name 'WinRM' -Why 'Remote management not required'
                } else {
                    Write-Step 'Keeping WinRM. Basic/unencrypted WinRM was already blocked in security options.'
                }
            }
        }
    } catch {}
}

# ----------------------------------------------------------------------------
# Network protocols: SMBv1, LLMNR, NetBIOS, TLS, hosts
# ----------------------------------------------------------------------------
function Invoke-NetworkProtocols {
    Write-Banner 'STEP 9C OF 12 - NETWORK PROTOCOLS (SMBv1, LLMNR, NetBIOS, TLS, hosts)'
    if (Ask-YesNo 'Disable SMBv1 (server + client driver)? It is the WannaCry-era protocol.' $true) {
        if (-not $script:AuditOnly) {
            try {
                if (Test-CommandExists 'Set-SmbServerConfiguration') {
                    Set-SmbServerConfiguration -EnableSMB1Protocol:$false -Force -ErrorAction Stop
                    Write-Good 'SMB1 server protocol disabled.'
                }
            } catch { Write-WarnLine 'Could not change the SMB1 server setting via cmdlet.' }
            Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 'DWord' 'SMB1 server off (registry check path)'
            if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10') {
                Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4 'DWord' 'SMB1 client driver disabled at next reboot'
            }
        } else {
            Write-Host '[AUDIT] Would disable SMBv1.'
        }
    }
    if (Ask-YesNo 'Disable LLMNR (Link-Local Multicast Name Resolution, a credential-theft favorite)?' $true) {
        Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 'DWord' 'LLMNR off'
    }
    if (Ask-YesNo 'Disable NetBIOS over TCP/IP on every adapter? Say NO if old-style file sharing / name resolution is critical.' $false) {
        $ifaceBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        foreach ($sub in @(Get-ChildItem $ifaceBase -ErrorAction SilentlyContinue)) {
            Set-RegValue ($sub.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM') 'NetbiosOptions' 2 'DWord' 'NetBIOS over TCP/IP disabled'
        }
    }
    if (Ask-YesNo 'Disable SSL 2.0 / SSL 3.0 / TLS 1.0 / TLS 1.1 and require modern .NET crypto (TLS 1.2+ stays on)?' $true) {
        $protoOff = @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')
        foreach ($p in $protoOff) {
            foreach ($side in @('Client','Server')) {
                $path = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\' + $p + '\' + $side
                Set-RegValue $path 'Enabled' 0 'DWord' ($p + ' ' + $side + ' disabled')
                Set-RegValue $path 'DisabledByDefault' 1 'DWord' ''
            }
        }
        foreach ($side in @('Client','Server')) {
            $path12 = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\' + $side
            Set-RegValue $path12 'Enabled' 1 'DWord' ('TLS 1.2 ' + $side + ' enabled')
            Set-RegValue $path12 'DisabledByDefault' 0 'DWord' ''
        }
        foreach ($dotnet in @('HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319','HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
            Set-RegValue $dotnet 'SchUseStrongCrypto' 1 'DWord' '.NET strong crypto'
            Set-RegValue $dotnet 'SystemDefaultTlsVersions' 1 'DWord' '.NET uses OS-default TLS versions'
        }
        Write-Step 'Note: cipher-suite ORDER is intentionally untouched (breaking it can cut off updates/scoring).'
    }

    # Hosts file: report first; only offer a reset when odd entries exist.
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $active = @(Get-Content $hostsPath -ErrorAction SilentlyContinue | Where-Object {
        $_.Trim() -and -not $_.Trim().StartsWith('#')
    })
    if ($active.Count -gt 0) {
        Write-WarnLine 'Active hosts-file entries found. Planted redirects are a classic image trick:'
        $active | ForEach-Object { Write-Host ('    ' + $_) }
        if (-not $script:AuditOnly -and (Ask-YesNo 'Reset the hosts file to the Microsoft default (original is in the backup)?' $false)) {
            $defaultHosts = @(
                '# Copyright (c) 1993-2009 Microsoft Corp.',
                '# localhost name resolution is handled within DNS itself.',
                '# 127.0.0.1       localhost',
                '# ::1             localhost'
            )
            try {
                $defaultHosts | Set-Content $hostsPath -Force -ErrorAction Stop
                Write-Good 'Hosts file reset to default.'
            } catch { Write-WarnLine 'Could not rewrite the hosts file (Defender may protect it - edit by hand).' }
        }
    } else {
        Write-Step 'Hosts file is clean (no active entries).'
    }
    Write-Step 'DNS/proxy review: compare the DNS servers in recon.txt with the README.'
    Write-Step 'This script never disables IPv6 and never touches the Windows Time service.'
}

# ----------------------------------------------------------------------------
# Shares
# ----------------------------------------------------------------------------
function Invoke-Shares {
    Write-Banner 'STEP 9D OF 12 - FILE SHARES + PERMISSIONS'
    $shares = @()
    try { $shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$') }) } catch {
        Write-WarnLine 'Get-SmbShare is unavailable here; check shares with fsmgmt.msc.'
        return
    }
    $protectedShareNames = @('SYSVOL','NETLOGON')
    foreach ($share in $shares) {
        $accessText = ''
        $everyoneOpen = $false
        try {
            $acc = @(Get-SmbShareAccess $share.Name -ErrorAction Stop)
            $accessText = (($acc | ForEach-Object { $_.AccountName + '=' + $_.AccessRight }) -join ', ')
            foreach ($a in $acc) {
                if ($a.AccountName -match '^(Everyone|ANONYMOUS LOGON)$' -and "$($a.AccessRight)" -match 'Full|Change') { $everyoneOpen = $true }
            }
        } catch {}
        Write-Host ("  Share " + $share.Name + " -> " + $share.Path + "  [" + $accessText + "]")
        if ($protectedShareNames -contains $share.Name) {
            Write-Step '    PROTECTED: domain SYSVOL/NETLOGON share - left alone.'
            continue
        }
        $kept = $script:FileSharingCritical
        foreach ($k in $script:KeepEntries) { if ($k.Length -ge 3 -and $share.Name.ToLower().Contains($k.ToLower())) { $kept = $true } }
        if ($script:AuditOnly) { continue }
        if ($kept) {
            if ($everyoneOpen) {
                if (Ask-YesNo ("  Share '" + $share.Name + "' is critical but Everyone/Full. Revoke Everyone from it (share itself stays)?") $false) {
                    try { Revoke-SmbShareAccess -Name $share.Name -AccountName 'Everyone' -Force -ErrorAction Stop; Write-Good ("Removed Everyone from share " + $share.Name) }
                    catch { Write-WarnLine ("Could not change access on " + $share.Name) }
                }
            } else {
                Write-Step '    Critical per README - left as-is.'
            }
            continue
        }
        Write-Host '    Choices: [R]emove this share, [F]ix by revoking Everyone only, [K]eep (default)'
        $choice = 'k'
        try { $choice = (Read-Host '    Your choice').Trim().ToLower() } catch {}
        if ($choice -eq 'r') {
            try { Remove-SmbShare -Name $share.Name -Force -ErrorAction Stop; Write-Good ("Removed share " + $share.Name + " (folder itself is untouched)") }
            catch { Write-WarnLine ("Could not remove share " + $share.Name) }
        } elseif ($choice -eq 'f') {
            try { Revoke-SmbShareAccess -Name $share.Name -AccountName 'Everyone' -Force -ErrorAction Stop; Write-Good ("Revoked Everyone from share " + $share.Name) }
            catch { Write-WarnLine ("Could not revoke Everyone from " + $share.Name) }
        } else {
            Write-Step '    Kept at your choice.'
        }
    }
    Write-Step 'Default admin shares (C$, ADMIN$, IPC$) are reported in recon.txt but not'
    Write-Step 'auto-removed: management tools expect them and removing them mid-round'
    Write-Step 'buys little. See CHECKLIST.md if your scenario forbids them.'
}

# ----------------------------------------------------------------------------
# Users and groups
# ----------------------------------------------------------------------------
function Test-NameInList {
    param([string]$Name, [string[]]$List)
    foreach ($x in @($List)) { if ($x -ieq $Name) { return $true } }
    return $false
}

function Get-GroupMemberShortNames {
    param([string]$Group)
    $out = @()
    try {
        foreach ($m in @(Get-LocalGroupMember $Group -ErrorAction Stop)) {
            $n = "$($m.Name)"
            $short = ($n -split '\\')[-1]
            $out += [PSCustomObject]@{ Full = $n; Short = $short; ObjectClass = "$($m.ObjectClass)" }
        }
    } catch {}
    return $out
}

function Invoke-UsersAndGroups {
    Write-Banner 'STEP 10 OF 12 - USERS + GROUPS (README-driven, preview before any change)'
    if ($script:IsDC) {
        Write-WarnLine 'Domain Controller: this module only REPORTS. Use Active Directory Users'
        Write-WarnLine 'and Computers for domain accounts, guided by the README. The built-in'
        Write-WarnLine 'domain Administrator is never bulk-disabled here (lockout risk).'
        try { & net.exe user /domain | Out-File (Join-Path $script:ReportDir 'domain-users.txt') } catch {}
        Write-Step 'Domain user list saved to the Reports folder.'
        return
    }
    if (-not (Test-ConfigReady)) {
        Write-WarnLine 'authorizedusers.txt / admins.txt still contain EDIT_ME. Skipping all'
        Write-WarnLine 'account changes (deleting the wrong user is the fastest way to lose points).'
        return
    }
    if ($script:AuthorizedUsers.Count -eq 0) { Write-WarnLine 'authorizedusers.txt is empty - skipping.'; return }

    $localUsers = @()
    try { $localUsers = @(Get-LocalUser -ErrorAction Stop) } catch {
        Write-WarnLine 'Get-LocalUser is unavailable; manage accounts with lusrmgr.msc.'
        return
    }
    $serviceLogons = @(Get-ServiceLogonAccounts)
    $presentNames = @($localUsers | Select-Object -ExpandProperty Name)
    $unauthorized = @($localUsers | Where-Object {
        -not (Test-NameInList $_.Name $script:AuthorizedUsers) -and
        -not (Test-NameInList $_.Name $script:BuiltInUsers) -and
        $_.Name -ine $script:CurrentUser -and
        -not (Test-NameInList $_.Name $serviceLogons)
    })
    $missing = @($script:AuthorizedUsers | Where-Object {
        -not (Test-NameInList $_ $presentNames) -and -not (Test-NameInList $_ $script:BuiltInUsers)
    })
    $adminMembers = @(Get-GroupMemberShortNames 'Administrators')
    $unauthAdmins = @($adminMembers | Where-Object {
        -not (Test-NameInList $_.Short $script:AuthorizedAdmins) -and
        $_.Short -ine $script:CurrentUser -and $_.Short -ine 'Administrator'
    })
    $adminShortNames = @($adminMembers | Select-Object -ExpandProperty Short)
    $missingAdmins = @($script:AuthorizedAdmins | Where-Object {
        -not (Test-NameInList $_ $adminShortNames) -and $_ -ine 'Administrator'
    })

    Write-Host ("Unauthorized users present : " + (@($unauthorized | Select-Object -ExpandProperty Name) -join ', '))
    Write-Host ("Authorized users missing   : " + ($missing -join ', '))
    Write-Host ("Unauthorized admins        : " + (@($unauthAdmins | Select-Object -ExpandProperty Full) -join ', '))
    Write-Host ("Authorized admins missing  : " + ($missingAdmins -join ', '))
    if ($script:AuditOnly) { return }

    foreach ($name in $missing) {
        if (Ask-YesNo ("Create missing authorized user '" + $name + "'?") $true) {
            try {
                if ($null -ne $script:TeamPassword) {
                    New-LocalUser -Name $name -Password $script:TeamPassword -PasswordNeverExpires:$false -ErrorAction Stop | Out-Null
                } else {
                    New-LocalUser -Name $name -NoPassword -ErrorAction Stop | Out-Null
                    Write-WarnLine ("Created " + $name + " with NO password because the password step was skipped - set one now by hand.")
                }
                Add-LocalGroupMember -Group 'Users' -Member $name -ErrorAction SilentlyContinue
                Write-Good ("Created user " + $name)
            } catch { Write-WarnLine ("Could not create " + $name + ': ' + $_.Exception.Message) }
        }
    }
    foreach ($name in $missingAdmins) {
        if (Ask-YesNo ("Add '" + $name + "' to Administrators?") $true) {
            try { Add-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction Stop; Write-Good ("Added admin " + $name) }
            catch { Write-WarnLine ("Could not add admin " + $name + ' (does the account exist?)') }
        }
    }
    foreach ($entry in $unauthAdmins) {
        if (Ask-YesNo ("Remove '" + $entry.Full + "' from Administrators (account itself stays)?") $true) {
            try { Remove-LocalGroupMember -Group 'Administrators' -Member $entry.Full -ErrorAction Stop; Write-Good ("Removed admin rights from " + $entry.Full) }
            catch { Write-WarnLine ("Could not remove admin rights from " + $entry.Full) }
        }
    }

    if ($unauthorized.Count -gt 0) {
        Write-Host ''
        Write-Host 'For unauthorized users, DELETE is what scoring usually expects, but DELETE is'
        Write-Host 'permanent and destroys that user''s profile files. DISABLE is reversible but'
        Write-Host 'may not score. You already passed the forensics gate, so choose per account:'
        foreach ($u in $unauthorized) {
            Write-Host ("  Account: " + $u.Name + "  Enabled=" + $u.Enabled + "  PasswordLastSet=" + $u.PasswordLastSet)
            $choice = 'k'
            try { $choice = (Read-Host '    [D]elete forever, dis[A]ble (reversible), [K]eep (default)').Trim().ToLower() } catch {}
            if ($choice -eq 'd') {
                $typed = ''
                try { $typed = Read-Host ("    Type DELETE to permanently delete " + $u.Name) } catch {}
                if ($typed -ceq 'DELETE') {
                    try {
                        ($u | Format-List * | Out-String) | Out-File (Join-Path $script:BackupDir ('deleted-user-' + $u.Name + '.txt'))
                        Remove-LocalUser -Name $u.Name -ErrorAction Stop
                        Write-Good ("Deleted unauthorized user " + $u.Name + " (details saved in Backups; profile folder is left on disk)")
                    } catch { Write-WarnLine ("Could not delete " + $u.Name) }
                } else { Write-Step '    Not deleted (confirmation not typed).' }
            } elseif ($choice -eq 'a') {
                try { Disable-LocalUser -Name $u.Name -ErrorAction Stop; Write-Good ("Disabled user " + $u.Name) }
                catch { Write-WarnLine ("Could not disable " + $u.Name) }
            } else {
                Write-Step '    Kept at your choice.'
            }
        }
    }

    # Guest can always be disabled safely; built-in Administrator only with care.
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        if ($guest.Enabled) {
            if (Ask-YesNo 'Disable the Guest account?' $true) { Disable-LocalUser -Name 'Guest'; Write-Good 'Guest account disabled.' }
        } else { Write-Step 'Guest is already disabled.' }
    } catch {}
    try {
        $adminAcct = Get-LocalUser -ErrorAction Stop | Where-Object { "$($_.SID)" -like '*-500' } | Select-Object -First 1
        if ($null -ne $adminAcct) {
            if ($adminAcct.Name -ieq $script:CurrentUser) {
                Write-WarnLine ('You are signed in as the built-in Administrator (' + $adminAcct.Name + '). It will NOT be disabled (lockout protection).')
            } elseif (-not $adminAcct.Enabled) {
                Write-Step ('Built-in Administrator (' + $adminAcct.Name + ') is already disabled.')
            } else {
                $otherAdmins = @($adminMembers | Where-Object { $_.Short -ine $adminAcct.Name })
                if ($otherAdmins.Count -ge 1) {
                    if (Ask-YesNo ("Disable the built-in Administrator account (" + $adminAcct.Name + ")? Another admin exists (" + $otherAdmins[0].Full + "). Make sure you KNOW that admin's password first!") $false) {
                        Disable-LocalUser -Name $adminAcct.Name; Write-Good 'Built-in Administrator disabled.'
                    }
                } else {
                    Write-WarnLine 'Built-in Administrator is the ONLY admin - refusing to disable it.'
                }
            }
        }
    } catch {}

    # Remote Desktop Users cleanup, only when RDP is in use.
    if ($script:RdpCritical -and (Test-FileEdited (Join-Path $script:Root 'rdpusers.txt'))) {
        $rdpMembers = @(Get-GroupMemberShortNames 'Remote Desktop Users')
        foreach ($m in $rdpMembers) {
            $ok = (Test-NameInList $m.Short $script:RdpUsers) -or (Test-NameInList $m.Short $script:AuthorizedAdmins)
            if (-not $ok -and $m.Short -ine $script:CurrentUser) {
                if (Ask-YesNo ("Remove '" + $m.Full + "' from Remote Desktop Users?") $true) {
                    try { Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $m.Full; Write-Good ("Removed RDP access for " + $m.Full) } catch {}
                }
            }
        }
        foreach ($want in $script:RdpUsers) {
            $have = Test-NameInList $want @($rdpMembers | Select-Object -ExpandProperty Short)
            if (-not $have) {
                if (Ask-YesNo ("Add '" + $want + "' to Remote Desktop Users?") $true) {
                    try { Add-LocalGroupMember -Group 'Remote Desktop Users' -Member $want; Write-Good ("Granted RDP access to " + $want) } catch {}
                }
            }
        }
    }

    # Report members of other powerful groups - judgement calls stay manual.
    foreach ($grp in @('Backup Operators','Hyper-V Administrators','Remote Management Users','Print Operators','Server Operators','Account Operators','Guests')) {
        $mem = @(Get-GroupMemberShortNames $grp)
        if ($mem.Count -gt 0) {
            Write-Step ("Review group " + $grp + ": " + (($mem | Select-Object -ExpandProperty Full) -join ', '))
            Write-Step '  (Anyone here who is not in the README usually should be removed by hand in lusrmgr.)'
        }
    }
    Write-Step 'Tip: unlock any authorized account that got locked out with Unlock-LocalUser or lusrmgr.'
}

# ----------------------------------------------------------------------------
# Prohibited software + media (report / quarantine, never bulk-delete)
# ----------------------------------------------------------------------------
function Invoke-SoftwareAndFiles {
    Write-Banner 'STEP 11 OF 12 - PROHIBITED SOFTWARE + FILES (report first, you decide)'
    $badList = @(Get-TextList (Join-Path $script:Root 'prohibited_software.txt'))
    $apps = @(Get-InstalledPrograms)
    $flaggedApps = @()
    foreach ($app in $apps) {
        foreach ($bad in $badList) {
            if ($bad.Length -ge 3 -and $app.DisplayName.ToLower().Contains($bad.ToLower())) {
                $flaggedApps += $app; break
            }
        }
    }
    if ($flaggedApps.Count -eq 0) {
        Write-Step 'No installed program matches prohibited_software.txt.'
    } else {
        Add-Report 'prohibited-software.txt' 'Programs matching prohibited_software.txt' ($flaggedApps | Format-Table 'DisplayName','DisplayVersion','Publisher' -AutoSize | Out-String)
        foreach ($app in $flaggedApps) {
            Write-Host ("  Found: " + $app.DisplayName + ' ' + $app.DisplayVersion + ' (' + $app.Publisher + ')')
            if ($script:AuditOnly) { continue }
            if ([string]::IsNullOrWhiteSpace("$($app.UninstallString)")) {
                Write-WarnLine '    No uninstall command recorded - remove it via Settings > Apps.'
                continue
            }
            if (Ask-YesNo ("  Launch the uninstaller for " + $app.DisplayName + " now? (Follow its prompts; do NOT reboot if it asks - choose Later)") $false) {
                try {
                    $uninstall = "$($app.UninstallString)" -replace '/I\{', '/X{'
                    Start-Process cmd.exe -ArgumentList ('/c ' + $uninstall) -Wait
                    Write-Good ("Ran uninstaller for " + $app.DisplayName)
                } catch { Write-WarnLine '    Uninstaller failed to launch - use Settings > Apps.' }
            }
        }
    }

    Write-Step 'Media / prohibited-file scan (this changed the most from the 2019 script):'
    Write-Step 'scans REPORT first, then MOVES files into C:\CP-Quarantine (reversible).'
    Write-Step 'Deletion is a separate, second, typed decision. Program files under'
    Write-Step 'AppData are excluded by default, as are CyberPatriot and Forensics folders.'
    if (-not (Ask-YesNo 'Scan C:\Users for music/video files now?' $true)) { return }
    $includeImages = Ask-YesNo 'Also scan IMAGE files (jpg/png/gif)? Say YES only if the README prohibits images (a photography business must keep them).' $false
    $includeAppData = Ask-YesNo 'Also scan inside AppData (slower; may list program assets)?' $false
    $extensions = @('.mp3','.flac','.m4a','.ogg','.wma','.aac','.mp4','.mov','.avi','.mkv','.wmv','.mpg','.mpeg','.flv','.m4v','.webm','.3gp')
    if ($includeImages) { $extensions += @('.jpg','.jpeg','.png','.gif','.bmp','.tif','.tiff') }
    $scanRoot = 'C:\Users'
    if (-not (Test-Path $scanRoot)) { Write-WarnLine 'C:\Users not found - skipping the media scan.'; return }
    Write-Step 'Scanning ... (large profiles can take a few minutes)'
    $found = @()
    try {
        $found = @(Get-ChildItem $scanRoot -Recurse -File -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $extensions -contains $_.Extension.ToLower() -and
                $_.FullName -notmatch '\\CyberPatriot\\' -and
                $_.FullName -notmatch '\\Forensic' -and
                ($includeAppData -or $_.FullName -notmatch '\\AppData\\') -and
                (-not $_.FullName.StartsWith($script:Root, [StringComparison]::OrdinalIgnoreCase))
            } | Select-Object 'FullName','Length','Extension')
    } catch { Write-WarnLine 'The media scan hit an error; see the transcript.' }
    Write-Step ("Files found: " + $found.Count)
    $found | Export-Csv (Join-Path $script:ReportDir 'media-found.csv') -NoTypeInformation
    if ($found.Count -eq 0 -or $script:AuditOnly) { return }

    $byExt = $found | Group-Object Extension
    $quarantineRoot = 'C:\CP-Quarantine\' + $script:Stamp
    $movedLog = @()
    foreach ($grp in $byExt) {
        Write-Host ("  " + $grp.Name + " : " + $grp.Count + " file(s)")
        if (Ask-YesNo ("  QUARANTINE (move, not delete) all " + $grp.Name + " files into C:\CP-Quarantine?") $false) {
            foreach ($file in $grp.Group) {
                try {
                    $relative = $file.FullName.Substring(3)  # strip C:\
                    $dest = Join-Path $quarantineRoot $relative
                    $destDir = Split-Path $dest -Parent
                    if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                    Move-Item $file.FullName $dest -Force -ErrorAction Stop
                    $movedLog += [PSCustomObject]@{ From = $file.FullName; To = $dest }
                } catch { Write-WarnLine ("Could not move " + $file.FullName) }
            }
            Write-Good ("Quarantined " + $grp.Name + " files.")
        }
    }
    if ($movedLog.Count -gt 0) {
        $movedLog | Export-Csv (Join-Path $script:ReportDir 'quarantine-log.csv') -NoTypeInformation
        Write-Host 'Check the Scoring Report. If removing a file cost points, move it back'
        Write-Host ('from ' + $quarantineRoot + ' to its original path (see quarantine-log.csv).')
        Write-Host 'Empty the quarantine only when you are sure: scoring usually checks that'
        Write-Host 'prohibited files are gone from user folders, and a quarantine OUTSIDE'
        Write-Host 'C:\Users keeps them recoverable until the round ends.'
    }
}

# ----------------------------------------------------------------------------
# Updates
# ----------------------------------------------------------------------------
function Invoke-Updates {
    Write-Banner 'STEP 12A OF 12 - UPDATES (Windows + apps; this script never reboots)'
    $au = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-RegValue $au 'NoAutoUpdate' 0 'DWord' 'Automatic Updates on'
    Set-RegValue $au 'AUOptions' 4 'DWord' 'Auto-download and schedule install'
    Set-RegValue $au 'AutoInstallMinorUpdates' 1 'DWord' ''
    Set-RegValue $au 'IncludeRecommendedUpdates' 1 'DWord' ''
    Set-RegValue $au 'NoAutoRebootWithLoggedOnUsers' 1 'DWord' 'Never auto-restart while someone is signed in (round safety)'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DisableWindowsUpdateAccess' 0 'DWord' ''
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ElevateNonAdmins' 0 'DWord' 'Only administrators approve updates'
    Set-RegValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions' 4 'DWord' ''
    if (-not $script:AuditOnly) {
        foreach ($svcName in @('wuauserv','BITS','UsoSvc')) {
            try {
                $svc = Get-Service $svcName -ErrorAction Stop
                if ($svc.StartType -eq 'Disabled') {
                    Set-Service $svcName -StartupType Manual
                    Write-Good ("Re-enabled update service (was Disabled): " + $svcName)
                }
            } catch {}
        }
        try { & UsoClient.exe StartScan | Out-Null; Write-Step 'Triggered an update scan (UsoClient StartScan).' } catch {}
        if (Ask-YesNo 'Search for Windows updates with the Update API and optionally install them? (Can take a long time; any reboot stays YOUR decision afterwards.)' $false) {
            try {
                $session = New-Object -ComObject Microsoft.Update.Session
                $searcher = $session.CreateUpdateSearcher()
                Write-Step 'Searching for updates ...'
                $result = $searcher.Search("IsInstalled=0 and Type='Software'")
                Write-Step ("Updates found: " + $result.Updates.Count)
                foreach ($u in $result.Updates) { Write-Host ('    - ' + $u.Title) }
                if ($result.Updates.Count -gt 0 -and (Ask-YesNo 'Download and install all of these updates now?' $false)) {
                    $toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
                    foreach ($u in $result.Updates) { if ($u.EulaAccepted -eq $false) { $u.AcceptEula() }; [void]$toDownload.Add($u) }
                    $downloader = $session.CreateUpdateDownloader()
                    $downloader.Updates = $toDownload
                    [void]$downloader.Download()
                    Write-Good 'Downloads complete. Installing ...'
                    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                    foreach ($u in $result.Updates) { if ($u.IsDownloaded) { [void]$toInstall.Add($u) } }
                    $installer = $session.CreateUpdateInstaller()
                    $installer.Updates = $toInstall
                    $installResult = $installer.Install()
                    Write-Good ("Install finished. Result code: " + $installResult.ResultCode + "  Reboot required: " + $installResult.RebootRequired)
                    if ($installResult.RebootRequired) {
                        Write-WarnLine 'A reboot is pending. Reboot ONCE, late in the round, after writing down'
                        Write-WarnLine 'every password and testing a lock/unlock with the new password.'
                    }
                }
            } catch { Write-WarnLine ("Windows Update API failed (" + $_.Exception.Message + "). Use Settings > Windows Update instead - start it now and let it run in parallel.") }
        } else {
            Write-Host 'FASTEST RELIABLE PATH: open Settings > Windows Update > Check for updates NOW'
            Write-Host 'and let it work while you continue. "Majority of updates installed" is scored.'
            if (Ask-YesNo 'Open the Windows Update settings page now?' $true) {
                try { Start-Process 'ms-settings:windowsupdate' } catch {}
            }
        }
    }
    # Browser / app versions for the manual update checklist.
    $browserInfo = @()
    foreach ($candidate in @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
        "$env:ProgramFiles\Notepad++\notepad++.exe"
    )) {
        if ($candidate -and (Test-Path $candidate)) {
            try { $browserInfo += ($candidate + '  version ' + (Get-Item $candidate).VersionInfo.FileVersion) } catch {}
        }
    }
    if ($browserInfo.Count -gt 0) {
        Add-Report 'app-versions.txt' 'Browser/editor versions (update these apps from their own Help > About menus)' ($browserInfo -join "`r`n")
        Write-Step 'Browser/editor versions recorded in the Reports folder (updates for these are scored too).'
    }
    if ((Test-CommandExists 'winget') -and -not $script:AuditOnly) {
        Write-Step 'winget is available for REPORTING outdated apps:'
        try { & winget upgrade --accept-source-agreements 2>$null | Out-String | Write-Host } catch {}
        Write-Step 'winget bulk-upgrade is NOT run automatically: upgrading a required app'
        Write-Step 'mid-round can break the scenario. Update browsers first, by hand.'
    }
}

# ----------------------------------------------------------------------------
# Legacy 2018 GPOs - optional and heavily guarded
# ----------------------------------------------------------------------------
function Invoke-LegacyGPO {
    Write-Banner 'STEP 12B OF 12 - LEGACY 2018 GPO BACKUPS (OPTIONAL, default: skip)'
    Write-Host 'The Policies folder holds Microsoft Security Baseline GPO backups from'
    Write-Host 'November 2018 (Windows 10 1809 / Server 2019). The 2019 script applied'
    Write-Host 'ALL of them to every machine - including Domain Controller, BitLocker and'
    Write-Host 'Credential Guard GPOs on plain workstations. That can break a VM, which is'
    Write-Host 'why this step is now optional and ROLE-specific. Equivalent modern settings'
    Write-Host 'were already applied directly by the earlier steps.'
    Write-Host 'For 2026, download the current baselines instead (see docs/UPDATE_BASELINES_2026.md):'
    Write-Host 'Microsoft Security Compliance Toolkit - Windows 11 and Windows Server 2025.'
    Write-Host ''
    $table = @(
        '{1BB77C55-578B-49B6-AE60-7D4CB8AD29AF}  MSFT Windows 10 1809 - Computer',
        '{927474CF-1D45-4982-A637-9CA95E8817A4}  MSFT Windows 10 1809 - User',
        '{C92CC433-A4EA-47B1-8B24-6FF732940E0E}  MSFT Windows Server 2019 - Member Server',
        '{FEFBD334-CF33-4078-8829-4B00DC1D164B}  MSFT Windows Server 2019 - Domain Controller',
        '{B9263530-926F-46F3-8382-832C31EC81B5}  MSFT Windows 10 1809 / Server 2019 - Domain Security (password/lockout/Kerberos)',
        '{FEE76283-957E-4B25-9380-2F737E13E972}  MSFT Defender Antivirus',
        '{ABFB52F2-1560-4100-9103-8C10F57DC9DE}  MSFT Internet Explorer 11 - Computer (IE is retired - skip)',
        '{E913422C-4F06-4D37-A739-2CD2B701978E}  MSFT Internet Explorer 11 - User (skip)',
        '{3D4EEBCD-E6C0-4ADC-BAD4-0B1691A6396A}  MSFT BitLocker (DO NOT auto-apply in a VM)',
        '{7D41EEC9-3F30-4473-9447-E77D6EEF0E17}  Credential Guard (DO NOT auto-apply in a VM - needs UEFI/VBS + reboot)',
        '{7EA149BF-56B3-42CF-AF68-3FC789510ADD}  DC Virtualization Based Security (DO NOT auto-apply)'
    )
    $table | ForEach-Object { Write-Host ('  ' + $_) }
    if ($script:AuditOnly) { return }
    if (-not (Ask-YesNo 'Apply ONE role-appropriate legacy GPO set anyway (not recommended for Windows 11 / Server 2022+ images)?' $false)) {
        Write-Step 'Skipped legacy GPOs (the right call on modern images).'
        return
    }
    $lgpo = Join-Path $script:Root 'LGPO.exe'
    if (-not (Test-Path $lgpo)) { Write-WarnLine 'LGPO.exe not found next to the script.'; return }
    $pick = @()
    if ($script:IsDC) {
        $pick = @('{FEFBD334-CF33-4078-8829-4B00DC1D164B}','{B9263530-926F-46F3-8382-832C31EC81B5}','{FEE76283-957E-4B25-9380-2F737E13E972}')
    } elseif ($script:IsServer) {
        $pick = @('{C92CC433-A4EA-47B1-8B24-6FF732940E0E}','{B9263530-926F-46F3-8382-832C31EC81B5}','{FEE76283-957E-4B25-9380-2F737E13E972}')
    } else {
        $pick = @('{1BB77C55-578B-49B6-AE60-7D4CB8AD29AF}','{927474CF-1D45-4982-A637-9CA95E8817A4}','{B9263530-926F-46F3-8382-832C31EC81B5}','{FEE76283-957E-4B25-9380-2F737E13E972}')
    }
    $stage = Join-Path $env:TEMP 'CP-LegacyGPO-stage'
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    New-Item -ItemType Directory -Path $stage | Out-Null
    foreach ($guid in $pick) {
        $src = Join-Path $script:Root ('Policies\' + $guid)
        if (Test-Path $src) { Copy-Item $src $stage -Recurse }
    }
    Write-WarnLine ("About to run: LGPO.exe /g " + $stage + "  (GPOs: " + ($pick -join ', ') + ')')
    if (Ask-YesNo 'Proceed with the role-appropriate LGPO import?' $false) {
        try {
            & $lgpo /g $stage
            Write-Good 'Legacy GPO import finished. Watch the Scoring Report closely.'
            Write-WarnLine 'If the score DROPS, run .\secure.ps1 -Rollback and re-check gpedit.msc by hand.'
        } catch { Write-WarnLine 'LGPO failed to run.' }
    }
}

# ----------------------------------------------------------------------------
# Current-user password + auto-logon (last, deliberately)
# ----------------------------------------------------------------------------
function Invoke-FinalAccountSafety {
    Write-Banner 'FINAL ACCOUNT SAFETY - your own password + automatic logon'
    $wl = Get-RegValue 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
    $hasAutoLogon = ("$wl" -eq '1')
    if ($null -ne $script:TeamPassword) {
        if (Ask-YesNo ("Set YOUR OWN account (" + $script:CurrentUser + ") to the new team password now? Only say YES if it is written down.") $false) {
            if (Set-UserPasswordSafe -User $script:CurrentUser -Password $script:TeamPassword) {
                Write-Good ("Your password (" + $script:CurrentUser + ") was changed. Lock (Win+L) and unlock NOW to prove it works, before any reboot.")
                Wait-Enter 'Press ENTER after you have tested lock/unlock ...'
                if ($hasAutoLogon) {
                    if (Ask-YesNo 'Automatic logon is ON for this image (scored as insecure, but convenient). Disable it now that your password is known and tested?' $false) {
                        Set-RegValue 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' '0' 'String' 'Automatic logon off'
                        try { Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue } catch {}
                        Write-Good 'Automatic logon disabled and any stored DefaultPassword removed.'
                    }
                }
            } else {
                Write-WarnLine 'Your password was NOT changed (error). Do not disable auto-logon.'
            }
        } else {
            Write-Step 'Your password is unchanged. If it is weak/blank, change it by hand before the round ends.'
        }
    } elseif ($hasAutoLogon) {
        Write-WarnLine 'Automatic logon is ON, but your password was never set/verified in this run.'
        Write-WarnLine 'It will NOT be disabled here (reboot lockout risk). Set a known password,'
        Write-WarnLine 'test Win+L unlock, then turn AutoAdminLogon off by hand if the README allows.'
    }
    # Clear the in-memory password.
    if ($null -ne $script:TeamPassword) { $script:TeamPassword.Dispose(); $script:TeamPassword = $null }
}

# ----------------------------------------------------------------------------
# Verification (pass/fail table; used by Audit and at the end)
# ----------------------------------------------------------------------------
function Invoke-Verification {
    Write-Banner 'VERIFICATION - pass/fail snapshot (fix FAILs that your README expects)'
    $rows = New-Object System.Collections.ArrayList
    function Test-Row {
        param([string]$Check, [bool]$Ok, [string]$Detail)
        $state = 'FAIL'; if ($Ok) { $state = 'PASS' }
        [void]$rows.Add([PSCustomObject]@{ Check = $Check; State = $state; Detail = $Detail })
    }
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($fp in $fwProfiles) { Test-Row ("Firewall " + $fp.Name + " enabled") ([bool]$fp.Enabled) ("Inbound=" + $fp.DefaultInboundAction + " Outbound=" + $fp.DefaultOutboundAction) }
    } catch { Test-Row 'Firewall profiles readable' $false 'Get-NetFirewallProfile failed' }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Test-Row 'Defender real-time protection' ([bool]$mp.RealTimeProtectionEnabled) ("AV=" + $mp.AntivirusEnabled)
    } catch { Test-Row 'Defender status readable' $false 'Defender cmdlets unavailable' }
    $lm = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
    Test-Row 'LAN Manager level = 5 (NTLMv2 only)' ("$lm" -eq '5') ("value=" + $lm)
    $nolm = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'NoLMHash'
    Test-Row 'NoLMHash = 1' ("$nolm" -eq '1') ("value=" + $nolm)
    $blankLim = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse'
    Test-Row 'Blank passwords console-only' ("$blankLim" -eq '1') ("value=" + $blankLim)
    $anonSam = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' 'RestrictAnonymousSAM'
    Test-Row 'No anonymous SAM enumeration' ("$anonSam" -eq '1') ("value=" + $anonSam)
    $lua = Get-RegValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA'
    Test-Row 'UAC enabled (EnableLUA=1)' ("$lua" -eq '1') ("value=" + $lua)
    $lastUser = Get-RegValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'dontdisplaylastusername'
    Test-Row 'Do not display last user name' ("$lastUser" -eq '1') ("value=" + $lastUser)
    $cad = Get-RegValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'DisableCAD'
    Test-Row 'Ctrl+Alt+Del required (DisableCAD=0)' ("$cad" -eq '0') ("value=" + $cad)
    $llmnr = Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    Test-Row 'LLMNR disabled' ("$llmnr" -eq '0') ("value=" + $llmnr)
    $wdigest = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' 'UseLogonCredential'
    Test-Row 'WDigest plaintext credentials off' ("$wdigest" -eq '0') ("value=" + $wdigest)
    $noAutoUpd = Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
    Test-Row 'Automatic Updates on' ("$noAutoUpd" -eq '0') ("NoAutoUpdate=" + $noAutoUpd)
    $denyTs = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($script:RdpCritical) {
        $nla = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        Test-Row 'RDP is critical: enabled WITH NLA' (("$denyTs" -eq '0') -and ("$nla" -eq '1')) ("fDenyTS=" + $denyTs + " NLA=" + $nla)
    } else {
        Test-Row 'RDP denied (fDenyTSConnections=1)' ("$denyTs" -eq '1') ("value=" + $denyTs + " (FAIL here is correct ONLY if RDP must stay on)")
    }
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction Stop
        Test-Row 'Guest account disabled' (-not $guest.Enabled) ("Enabled=" + $guest.Enabled)
    } catch {}
    try {
        $cfgTmp = Join-Path $env:TEMP 'cp-verify.cfg'
        & secedit.exe /export /cfg $cfgTmp /quiet | Out-Null
        $cfgText = Get-Content $cfgTmp -Raw
        foreach ($pair in @(
            @('MinimumPasswordLength','Minimum password length >= 14'),
            @('PasswordHistorySize','Password history >= 5'),
            @('PasswordComplexity','Password complexity = 1'),
            @('LockoutBadCount','Lockout threshold is set (not 0)')
        )) {
            if ($cfgText -match ($pair[0] + '\s*=\s*(\d+)')) {
                $val = [int]$matches[1]
                $ok = $false
                if ($pair[0] -eq 'MinimumPasswordLength') { $ok = ($val -ge 14) }
                if ($pair[0] -eq 'PasswordHistorySize') { $ok = ($val -ge 5) }
                if ($pair[0] -eq 'PasswordComplexity') { $ok = ($val -eq 1) }
                if ($pair[0] -eq 'LockoutBadCount') { $ok = ($val -ge 1 -and $val -le 10) }
                Test-Row $pair[1] $ok ("value=" + $val)
            } else {
                Test-Row $pair[1] $false 'not present in secedit export'
            }
        }
    } catch { Test-Row 'secedit export for verification' $false $_.Exception.Message }
    try {
        $auditText = & auditpol.exe /get /category:* 2>$null | Out-String
        $noAuditCount = ([regex]::Matches($auditText, 'No Auditing')).Count
        Test-Row 'All audit subcategories enabled' ($noAuditCount -eq 0) ("subcategories with No Auditing: " + $noAuditCount)
    } catch {}
    try {
        $smb1 = $null
        if (Test-CommandExists 'Get-SmbServerConfiguration') { $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol }
        Test-Row 'SMB1 server protocol disabled' ("$smb1" -eq 'False') ("EnableSMB1Protocol=" + $smb1)
    } catch {}
    $table = $rows | Format-Table 'Check','State','Detail' -AutoSize | Out-String -Width 250
    Write-Host $table
    Add-Report 'verification.txt' 'Verification table' $table
    Write-Host 'Now compare with the live Scoring Report. Green increases = keep going.'
    Write-Host 'Any DROP right after a step = that step conflicted with the scenario: undo it'
    Write-Host 'first (.\secure.ps1 -Rollback, or re-enable that one service/user/share).'
    Write-Host 'Penalty points come back when the conflicting change is undone.'
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
function Invoke-Main {
    Write-Banner 'CyberPatriot Windows Hardening - 2026 edition (Windows 10/11, Server 2019/2022/2025)'
    Write-Host 'Audit-first, backup-always, never-auto-reboot. Rules change every season:'
    Write-Host 'this is TRAINING material for your own team - verify what the CURRENT'
    Write-Host 'Rules Book allows before using any script or AI tool in a scored round.'
    Show-AIPrompt

    if ($Rollback) {
        if (-not (Test-Admin)) { Write-WarnLine 'Rollback needs Administrator. Re-run elevated.'; return }
        Invoke-Rollback -Path $RollbackPath
        return
    }

    $ready = Invoke-Preflight
    if (-not $ready) {
        Write-Host ''
        Write-Host 'Stopped before making changes (see warnings above). Nothing was modified.'
        return
    }

    if ($script:AuditOnly) {
        try {
            Invoke-Recon
            Invoke-Passwords
            Invoke-AccountPolicy
            Invoke-SecurityOptions
            Invoke-AuditPolicy
            Invoke-Defender
            Invoke-Firewall
            Invoke-Services
            Invoke-RemoteAccess
            Invoke-NetworkProtocols
            Invoke-Shares
            Invoke-UsersAndGroups
            Invoke-SoftwareAndFiles
            Invoke-Updates
            Invoke-LegacyGPO
        } catch {
            Write-WarnLine ("Audit stopped early: " + $_.Exception.Message)
        }
        Invoke-Verification
        Write-Host ''
        Write-Host 'Audit complete. NO settings were changed. Reports are in the Reports folder.'
        return
    }

    if ($script:ApplySafe -and (-not $ForensicsDone -or -not $ReadmeConfigured)) {
        Write-WarnLine 'ApplySafe requires BOTH -ForensicsDone and -ReadmeConfigured (proof you did'
        Write-WarnLine 'the two manual gates). Refusing to run unattended without them.'
        return
    }

    try {
        Invoke-Backup
        Invoke-Recon
        Invoke-Passwords
        Invoke-AccountPolicy
        Invoke-SecurityOptions
        Invoke-AuditPolicy
        Invoke-Defender
        Invoke-Firewall
        Invoke-Services
        Invoke-RemoteAccess
        Invoke-NetworkProtocols
        Invoke-Shares
        Invoke-UsersAndGroups
        Invoke-SoftwareAndFiles
        Invoke-Updates
        Invoke-LegacyGPO
        Invoke-FinalAccountSafety
    } catch {
        if ($_.Exception.Message -eq 'User cancelled.') {
            Write-WarnLine 'Cancelled by user. Changes already made are listed below and backed up.'
        } else {
            Write-WarnLine ("Unexpected stop: " + $_.Exception.Message)
            Write-WarnLine 'Completed changes are listed below; the machine was left in a consistent state.'
        }
    }

    Invoke-Verification

    Write-Banner 'SUMMARY'
    Write-Host ("Changes made : " + $script:Changes.Count)
    Write-Host ("Warnings     : " + $script:Warnings.Count)
    Write-Host ("Backups      : " + $script:BackupDir)
    Write-Host ("Reports      : " + $script:ReportDir)
    $summaryPath = Join-Path $script:ReportDir 'summary.txt'
    @(
        ('Date: ' + (Get-Date -Format s)),
        ('Computer: ' + $env:COMPUTERNAME + '  OS: ' + $script:OSCaption),
        '',
        '--- CHANGES ---'
    ) + @($script:Changes) + @('', '--- WARNINGS ---') + @($script:Warnings) |
        Out-File $summaryPath -Force
    Write-Host ''
    Write-Host 'FINAL MANUAL LAP (see CHECKLIST.md):' -ForegroundColor Yellow
    Write-Host '  1. Refresh the Scoring Report. Investigate every point DROP immediately.'
    Write-Host '  2. Re-read the README top to bottom - verify critical services are RUNNING.'
    Write-Host '  3. Re-check Forensic Questions (new findings often appear while hardening).'
    Write-Host '  4. Finish Windows/browser/app updates; reboot ONCE only when updates demand'
    Write-Host '     it, after password lock/unlock testing, well before time expires.'
    Write-Host '  5. Sweep the recon report: unknown listeners, scheduled tasks, Run keys,'
    Write-Host '     IFEO debuggers, hosts entries and odd services are the last hidden points.'
    Write-Host '  6. Never touch C:\CyberPatriot or the scoring service. Keep the network up.'
    Write-Host 'Good luck - slow is smooth, and smooth scores 100.'
}

try { Invoke-Main } finally {
    try { Stop-Transcript | Out-Null } catch {}
}
