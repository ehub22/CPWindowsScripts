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
    'WEBDAV'   = @('W3SVC','WAS','IISADMIN')
    'APACHE'   = @('Apache2.4','Apache')
    'NGINX'    = @('nginx')
    'FTP'      = @('FTPSVC','MSFTPSVC')
    'ANONYMOUSFTP' = @('FTPSVC','MSFTPSVC')
    'PUBLICFTP'   = @('FTPSVC','MSFTPSVC')
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

function Test-ServiceScenarioKept {
    # True only when the SCENARIO says this service must stay: an entry in
    # keep_services.txt (by exact name, token map, or name-substring), or the
    # operator explicitly chose to keep it during this run.
    param([string]$Name, [string]$DisplayName)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    foreach ($k in $script:KeptByChoice) {
        if ($Name -ieq [string]$k) { return $true }
    }
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
# Service dependency graph: dependencies are NEVER removed.
# Test-ServiceKeptDirect = protected core services + scenario-kept services.
# Test-ServiceKept additionally protects every service those services depend
# on (transitively), so disabling can never strand a service that must stay.
# ----------------------------------------------------------------------------
function Test-ServiceKeptDirect {
    param([string]$Name, [string]$DisplayName)
    if (Test-ServiceProtected -Name $Name -DisplayName $DisplayName) { return $true }
    return (Test-ServiceScenarioKept -Name $Name -DisplayName $DisplayName)
}

function Test-ServiceKept {
    param([string]$Name, [string]$DisplayName)
    if (Test-ServiceKeptDirect -Name $Name -DisplayName $DisplayName) { return $true }
    Initialize-ServiceGraph
    Update-KeptDependencyClosure
    if ([string]::IsNullOrWhiteSpace($Name)) { return $true }
    return $script:KeptClosureLower.ContainsKey($Name.ToLower())
}

function Initialize-ServiceGraph {
    if ($script:ServiceGraphReady) { return }
    $script:ServiceCanonByLower = @{}
    $script:ServiceDisplayByLower = @{}
    $script:ServiceDependsOnLower = @{}
    $script:ServiceDependentsOfLower = @{}
    $all = @()
    try { $all = @(Get-Service -ErrorAction Stop) } catch {}
    foreach ($s in $all) {
        $lower = $s.Name.ToLower()
        $script:ServiceCanonByLower[$lower] = $s.Name
        $script:ServiceDisplayByLower[$lower] = $s.DisplayName
        $deps = @()
        try { $deps = @($s.ServicesDependedOn | Select-Object -ExpandProperty Name) } catch {}
        $script:ServiceDependsOnLower[$lower] = @($deps)
    }
    foreach ($lower in @($script:ServiceDependsOnLower.Keys)) {
        foreach ($dep in @($script:ServiceDependsOnLower[$lower])) {
            $dl = "$dep".ToLower()
            if (-not $script:ServiceDependentsOfLower.ContainsKey($dl)) { $script:ServiceDependentsOfLower[$dl] = @() }
            $script:ServiceDependentsOfLower[$dl] = @($script:ServiceDependentsOfLower[$dl]) + [string]$script:ServiceCanonByLower[$lower]
        }
    }
    $script:ServiceGraphReady = $true
    Update-KeptDependencyClosure
}

function Update-KeptDependencyClosure {
    if (-not $script:ServiceGraphReady) { return }
    $closure = @{}
    $queue = New-Object System.Collections.ArrayList
    foreach ($lower in @($script:ServiceCanonByLower.Keys)) {
        $canon = [string]$script:ServiceCanonByLower[$lower]
        $disp = [string]$script:ServiceDisplayByLower[$lower]
        if (Test-ServiceKeptDirect -Name $canon -DisplayName $disp) {
            if (-not $closure.ContainsKey($lower)) {
                $closure[$lower] = ''
                [void]$queue.Add($canon)
            }
        }
    }
    $i = 0
    while ($i -lt $queue.Count) {
        $current = [string]$queue[$i]
        $i++
        $seed = [string]$closure[$current.ToLower()]
        if ([string]::IsNullOrEmpty($seed)) { $seed = $current }
        $key = $current.ToLower()
        if (-not $script:ServiceDependsOnLower.ContainsKey($key)) { continue }
        foreach ($dep in @($script:ServiceDependsOnLower[$key])) {
            $dl = "$dep".ToLower()
            if (-not $closure.ContainsKey($dl)) {
                $closure[$dl] = $seed
                [void]$queue.Add([string]$dep)
            }
        }
    }
    $script:KeptClosureLower = $closure
}

function Add-KeptService {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return }
    foreach ($k in $script:KeptByChoice) {
        if ([string]$k -ieq $Name) { return }
    }
    [void]$script:KeptByChoice.Add($Name)
    if ($script:ServiceGraphReady) { Update-KeptDependencyClosure }
}

function Get-TransitiveDependents {
    param([string]$Name)
    Initialize-ServiceGraph
    $seen = @{}
    $seen[$Name.ToLower()] = $true
    $result = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.ArrayList
    [void]$queue.Add($Name)
    $i = 0
    while ($i -lt $queue.Count) {
        $current = [string]$queue[$i]
        $i++
        $key = $current.ToLower()
        if (-not $script:ServiceDependentsOfLower.ContainsKey($key)) { continue }
        foreach ($dep in @($script:ServiceDependentsOfLower[$key])) {
            $dl = "$dep".ToLower()
            if (-not $seen.ContainsKey($dl)) {
                $seen[$dl] = $true
                [void]$result.Add([string]$dep)
                [void]$queue.Add([string]$dep)
            }
        }
    }
    return @($result)
}

function Get-TransitiveDependencies {
    param([string]$Name)
    Initialize-ServiceGraph
    $seen = @{}
    $seen[$Name.ToLower()] = $true
    $result = New-Object System.Collections.ArrayList
    $queue = New-Object System.Collections.ArrayList
    [void]$queue.Add($Name)
    $i = 0
    while ($i -lt $queue.Count) {
        $current = [string]$queue[$i]
        $i++
        $key = $current.ToLower()
        if (-not $script:ServiceDependsOnLower.ContainsKey($key)) { continue }
        foreach ($dep in @($script:ServiceDependsOnLower[$key])) {
            $dl = "$dep".ToLower()
            if (-not $seen.ContainsKey($dl)) {
                $seen[$dl] = $true
                [void]$result.Add([string]$dep)
                [void]$queue.Add([string]$dep)
            }
        }
    }
    return @($result)
}

function Get-BlockingDependents {
    # A dependent blocks disabling when it is running right now, is itself a
    # keep-list/protected service, or is set to start automatically (it would
    # fail at the next boot if its dependency were Disabled). States are read
    # FRESH for every candidate, so a dependent disabled earlier in the same
    # run no longer blocks (e.g. disabling W3SVC first, then WAS, is fine).
    param([string]$Name)
    $blocking = @()
    foreach ($depName in @(Get-TransitiveDependents -Name $Name)) {
        $fresh = Get-Service -Name $depName -ErrorAction SilentlyContinue
        if ($null -eq $fresh) { continue }
        $start = "$($fresh.StartType)"
        if ($fresh.Status -eq 'Running' -or $start -match '^Automatic' -or (Test-ServiceKeptDirect -Name $fresh.Name -DisplayName $fresh.DisplayName)) {
            $blocking += ($fresh.Name + ' [' + $fresh.Status + '/' + $start + ']')
        }
    }
    return $blocking
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
    # The dependency shield lives here. A service is NEVER disabled when:
    #  - it is protected / on the keep list / kept by operator choice, or
    #  - it is a (transitive) dependency of any such service, or
    #  - anything that depends on it is running, auto-starting, or kept.
    # Disabling stops the service WITHOUT -Force first, so dependents can
    # never be force-stopped by accident. If the stop fails, the startup type
    # is left unchanged. Dependencies of the candidate itself are never
    # touched, and a service is never deleted anywhere in this script.
    param([string]$Name, [string]$Why)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $svc) { return }
    if (Test-ServiceKeptDirect -Name $svc.Name -DisplayName $svc.DisplayName) {
        Write-Step ("PROTECTED (critical / keep list): " + $svc.Name + " (" + $svc.DisplayName + ")")
        return
    }
    if (Test-ServiceKept -Name $svc.Name -DisplayName $svc.DisplayName) {
        $seed = [string]$script:KeptClosureLower[$svc.Name.ToLower()]
        Write-Step ("PROTECTED (dependency of critical service " + $seed + " - dependencies are never removed): " + $svc.Name + " (" + $svc.DisplayName + ")")
        return
    }
    $blocking = @(Get-BlockingDependents -Name $svc.Name)
    if ($blocking.Count -gt 0) {
        Write-WarnLine ("Skipping " + $Name + " - other services still need it: " + ($blocking -join ', ') + ". Disable those first if the README allows, then re-run.")
        return
    }
    if ($svc.StartType -eq 'Disabled' -and $svc.Status -eq 'Stopped') {
        Write-Step ("Already disabled: " + $Name)
        return
    }
    if ($script:AuditOnly) { Write-Host ("[AUDIT] Would stop+disable " + $Name + ' - ' + $Why); return }
    if ($svc.Status -ne 'Stopped') {
        try { Stop-Service -Name $Name -ErrorAction Stop } catch {
            Write-WarnLine ("Could not stop " + $Name + " cleanly (" + $_.Exception.Message + ") - startup type left unchanged so nothing breaks.")
            return
        }
    }
    try { Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop } catch {
        Write-WarnLine ("Stopped " + $Name + " but could not set it to Disabled: " + $_.Exception.Message)
        return
    }
    Write-Good ("Stopped + disabled " + $Name + " (" + $svc.DisplayName + ') - ' + $Why + ". Its own dependencies were left untouched.")
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
            else {
                Add-KeptService $item.Name
                Write-Step ("Keeping judgment-call service in ApplySafe mode (will be hardened later): " + $item.Name)
            }
            continue
        }
        if (Ask-YesNo ("Disable " + $svc.Name + " (" + $svc.DisplayName + ')? ' + $item.Why) $defaultDisable) {
            Disable-ServiceSafe -Name $item.Name -Why $item.Why
        } else {
            Add-KeptService $svc.Name
            Write-Step ("Keeping " + $svc.Name + " at your choice - it will be hardened in the kept-service hardening step.")
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
# Kept-service hardening: a service that is MEANT to be on this computer is
# hardened additionally (it is not merely left alone), and its dependencies
# are never removed. "Meant to stay" means: named in keep_services.txt, or
# the operator chose to keep it earlier in this run, or - in Interactive mode
# only - it looks intended (running + Automatic) and the operator confirms.
# Hardening never disables the kept service, never changes its service
# account, never removes listeners, and never forces encryption modes that
# need certificates or break older clients without an explicit opt-in.
# ----------------------------------------------------------------------------
function Test-ServiceIntended {
    param([string]$Label, [string[]]$ServiceNames, [string[]]$Tokens)
    if (Test-TokenKept $Tokens) { return $true }
    foreach ($n in $ServiceNames) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($null -ne $s -and (Test-ServiceScenarioKept -Name $s.Name -DisplayName $s.DisplayName)) { return $true }
    }
    $liveOnes = @()
    foreach ($n in $ServiceNames) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($null -ne $s -and $s.Status -eq 'Running' -and "$($s.StartType)" -match '^Automatic') { $liveOnes += $s.Name }
    }
    if ($liveOnes.Count -eq 0) { return $false }
    Write-Step ($Label + " service(s) running + Automatic but not in keep_services.txt: " + ($liveOnes -join ', '))
    if ($script:AuditOnly -or $script:ApplySafe) {
        Write-WarnLine ($Label + " looks intended but is not declared critical, so nothing is changed automatically. Add it to keep_services.txt and re-run to harden it.")
        return $false
    }
    if (Ask-YesNo ("Is " + $Label + " meant to stay on this computer? (Yes = protect it and harden it)") $false) {
        foreach ($n in $liveOnes) { Add-KeptService $n }
        return $true
    }
    return $false
}

function Ensure-CriticalServicesRunning {
    Initialize-ServiceGraph
    Update-KeptDependencyClosure
    $seeds = @()
    foreach ($lower in @($script:ServiceCanonByLower.Keys)) {
        $canon = [string]$script:ServiceCanonByLower[$lower]
        $disp = [string]$script:ServiceDisplayByLower[$lower]
        if (Test-ServiceScenarioKept -Name $canon -DisplayName $disp) { $seeds += $canon }
    }
    $seeds = @($seeds | Sort-Object -Unique)
    if ($seeds.Count -eq 0) {
        Write-Step 'No scenario services declared yet (keep_services.txt empty and nothing kept by choice) - nothing to keep running.'
        return
    }
    $depNames = @()
    foreach ($k in @($script:KeptClosureLower.Keys)) {
        if (-not [string]::IsNullOrEmpty([string]$script:KeptClosureLower[$k]) -and $script:ServiceCanonByLower.ContainsKey($k)) {
            $depNames += [string]$script:ServiceCanonByLower[$k]
        }
    }
    $depNames = @($depNames | Sort-Object -Unique)
    Write-Step ("Scenario-critical services to keep running (" + $seeds.Count + "): " + ($seeds -join ', '))
    if ($depNames.Count -gt 0) {
        Write-Step ("Dependencies protected automatically (" + $depNames.Count + ", never removed): " + ($depNames -join ', '))
    }
    $manualNormal = @('SessionEnv','UmRdpService','ssh-agent','FDResPub','IISADMIN','WMSVC','SNMPTrap','SQLBrowser','fdPHost')
    foreach ($seed in $seeds) {
        foreach ($dep in @(Get-TransitiveDependencies -Name $seed)) {
            $ds = Get-Service -Name $dep -ErrorAction SilentlyContinue
            if ($null -eq $ds) { continue }
            if ($ds.StartType -eq 'Disabled') {
                if ($script:AuditOnly) {
                    Write-Host ("[AUDIT] Dependency " + $dep + " of " + $seed + " is Disabled - would set it to Manual so " + $seed + " can start.")
                } else {
                    try {
                        Set-Service -Name $dep -StartupType Manual -ErrorAction Stop
                        Write-Good ("Dependency repair: " + $dep + " was Disabled; set to Manual so critical service " + $seed + " can start. Dependencies are never removed.")
                    } catch { Write-WarnLine ("Could not repair dependency " + $dep + " for service " + $seed + ": " + $_.Exception.Message) }
                }
            }
        }
        $s = Get-Service -Name $seed -ErrorAction SilentlyContinue
        if ($null -eq $s) { continue }
        if ($s.StartType -eq 'Disabled') {
            $target = 'Automatic'
            if ($manualNormal -icontains $seed) { $target = 'Manual' }
            if ($script:AuditOnly) {
                Write-Host ("[AUDIT] Critical service " + $seed + " is Disabled - would set it to " + $target + " and start it.")
            } else {
                try {
                    Set-Service -Name $seed -StartupType $target -ErrorAction Stop
                    Write-Good ("Critical service " + $seed + " was Disabled; startup type set to " + $target + ".")
                } catch { Write-WarnLine ("Could not change startup type of critical service " + $seed + ": " + $_.Exception.Message) }
            }
        }
        $s = Get-Service -Name $seed -ErrorAction SilentlyContinue
        $onDemand = ($null -ne $s -and $s.StartType -eq 'Manual')
        if ($onDemand) {
            Write-Step ("Critical helper " + $seed + " is Manual/on-demand (" + $s.Status + ") - protected, and Windows starts it when needed; not force-started.")
        }
        if (-not $onDemand) {
        if ($null -ne $s -and $s.Status -ne 'Running') {
            if ($script:AuditOnly) {
                Write-Host ("[AUDIT] Critical service " + $seed + " is " + $s.Status + " - would start it (Windows starts its dependencies first).")
            } else {
                try {
                    Start-Service -Name $seed -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    $after = Get-Service -Name $seed -ErrorAction SilentlyContinue
                    if ($null -ne $after -and $after.Status -eq 'Running') {
                        Write-Good ("Critical service started and verified RUNNING: " + $seed)
                    } else {
                        Write-WarnLine ("Started " + $seed + " but it is not Running yet - check its event log before moving on.")
                    }
                } catch {
                    $depState = @()
                    foreach ($dep in @(Get-TransitiveDependencies -Name $seed)) {
                        $ds = Get-Service -Name $dep -ErrorAction SilentlyContinue
                        if ($null -ne $ds) { $depState += ($dep + '=' + $ds.Status + '/' + $ds.StartType) }
                    }
                    Write-WarnLine ("CRITICAL service " + $seed + " failed to start: " + $_.Exception.Message + "  Dependencies: " + ($depState -join ', ') + ". Fix this before continuing - a stopped critical service loses points every scoring cycle.")
                }
            }
        } elseif ($null -ne $s) {
            Write-Step ("Critical service running: " + $seed)
        }
        if (-not $script:AuditOnly) {
            try {
                if (Test-Path $script:BackupDir) {
                    $recFile = Join-Path $script:BackupDir 'service-recovery-before.txt'
                    ("===== " + $seed + " =====") | Out-File $recFile -Append
                    & sc.exe qfailure $seed 2>$null | Out-File $recFile -Append
                }
                & sc.exe failure $seed 'reset=' '86400' 'actions=' 'restart/60000/restart/60000/none/0' 2>$null | Out-Null
                Write-Step ("Recovery set for " + $seed + ": restart automatically on 1st and 2nd failure.")
            } catch { Write-WarnLine ("Could not set failure recovery for service " + $seed + ".") }
        } else {
            Write-Host ("[AUDIT] Would set restart-on-failure recovery for critical service " + $seed)
        }
        }
    }
    try {
        $seedInfo = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $seeds -icontains $_.Name } | Select-Object 'Name','State','StartMode','StartName','PathName')
        Add-Report 'hardened-services.txt' 'Critical services: account and binary path' $seedInfo
        foreach ($info in $seedInfo) {
            if ($info.StartName -ieq 'LocalSystem' -and $info.PathName -notmatch 'Windows' -and $info.PathName -notmatch 'svchost') {
                Write-WarnLine ("Critical service " + $info.Name + " runs " + $info.PathName + " as LocalSystem. Service accounts are NOT changed automatically (that breaks apps); confirm this binary is expected.")
            }
        }
    } catch {}
}

function Invoke-ServiceHardening {
    Write-Banner 'STEP 9C OF 12 - HARDEN SERVICES THAT MUST STAY (kept services get extra hardening; dependencies are never removed)'
    Write-Host 'Every service the scenario needs stays ON. This step makes each of them'
    Write-Host 'harder to abuse, makes sure they (and everything they depend on) are'
    Write-Host 'running, and reports the few settings that are unsafe to force.'
    if (-not (Ask-YesNo 'Harden the services that are meant to stay on this computer?' $true)) {
        Write-Step 'Skipped kept-service hardening at your choice.'
        return
    }
    Ensure-CriticalServicesRunning
    $iisBackedUp = $false

    # --- Remote Desktop: additional hardening beyond NLA/TLS ----------------
    try {
        if ($script:RdpCritical -or (Test-ServiceIntended -Label 'Remote Desktop' -ServiceNames @('TermService') -Tokens @('RDP','REMOTEDESKTOP','REMOTE DESKTOP','REMOTE'))) {
            $tsPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Write-Step 'Remote Desktop stays ON. NLA, TLS and High encryption were set in the previous step.'
            Write-Step 'RDP accounts will be restricted to rdpusers.txt in the user-audit step.'
            if (Ask-YesNo 'ALSO apply stricter CIS Level-2 Remote Desktop controls? (disables clipboard/drive/COM/LPT/PnP redirection, 15-minute idle disconnect, ends disconnected sessions after 1 minute, one session per user - choose No if users copy files over RDP or leave sessions idle)' $false) {
                Set-RegValue $tsPol 'fDisableClip' 1 'DWord' 'Disable RDP clipboard redirection'
                Set-RegValue $tsPol 'fDisableCdm' 1 'DWord' 'Disable RDP drive redirection'
                Set-RegValue $tsPol 'fDisableCcm' 1 'DWord' 'Disable RDP COM port redirection'
                Set-RegValue $tsPol 'fDisableLPT' 1 'DWord' 'Disable RDP LPT port redirection'
                Set-RegValue $tsPol 'fDisablePNPRedir' 1 'DWord' 'Disable RDP Plug-and-Play redirection'
                Set-RegValue $tsPol 'MaxIdleTime' 900000 'DWord' 'Disconnect idle RDP sessions after 15 minutes'
                Set-RegValue $tsPol 'MaxDisconnectionTime' 60000 'DWord' 'End disconnected RDP sessions after 1 minute'
                Set-RegValue $tsPol 'fSingleSessionPerUser' 1 'DWord' 'One Remote Desktop session per user'
            } else {
                Write-Step 'RDP redirection and session limits left unchanged (contained-user workflows stay intact).'
            }
        }
    } catch { Write-WarnLine ("Remote Desktop extra hardening stopped safely: " + $_.Exception.Message) }

    # --- IIS web server ------------------------------------------------------
    try {
        if (Test-ServiceIntended -Label 'IIS web server' -ServiceNames @('W3SVC','WAS') -Tokens @('IIS','WEB','WEBDAV')) {
            $hasWA = $false
            if (Test-CommandExists 'Get-Website') { $hasWA = $true }
            else { try { Import-Module WebAdministration -ErrorAction Stop; $hasWA = $true } catch {} }
            if (-not $hasWA) {
                Write-WarnLine 'IIS PowerShell module (WebAdministration) not available - harden IIS in IIS Manager: disable Directory Browsing, enable Logging, review app-pool identities.'
            } else {
                try {
                    $dbAttr = Get-WebConfigurationProperty -Filter 'system.webServer/directoryBrowse' -PSPath 'IIS:\' -Name 'enabled' -ErrorAction Stop
                    $dbOn = $false
                    if ($null -ne $dbAttr) { $dbOn = [bool]$dbAttr.Value }
                    if ($dbOn) {
                        if ($script:AuditOnly) { Write-Host '[AUDIT] Would disable IIS directory browsing server-wide.' }
                        else {
                            if (Test-CommandExists 'Backup-WebConfiguration') {
                                try { Backup-WebConfiguration -Name ('CP-' + $script:Stamp) -ErrorAction Stop | Out-Null; $iisBackedUp = $true } catch {}
                            }
                            Set-WebConfigurationProperty -Filter 'system.webServer/directoryBrowse' -PSPath 'IIS:\' -Name 'enabled' -Value:$false -ErrorAction Stop
                            Write-Good 'IIS: directory browsing disabled server-wide (file listings no longer leak).'
                        }
                    } else { Write-Step 'IIS: directory browsing already disabled.' }
                } catch { Write-WarnLine ("IIS directory browsing check failed: " + $_.Exception.Message) }
                try {
                    $logAttr = Get-WebConfigurationProperty -Filter 'system.applicationHost/sites/siteDefaults/logFile' -PSPath 'MACHINE/WEBROOT/APPHOST' -Name 'enabled' -ErrorAction Stop
                    $logOn = $null
                    if ($null -ne $logAttr) { $logOn = [bool]$logAttr.Value }
                    if ($logOn -eq $false) {
                        if ($script:AuditOnly) { Write-Host '[AUDIT] Would enable IIS site logging by default.' }
                        else {
                            Set-WebConfigurationProperty -Filter 'system.applicationHost/sites/siteDefaults/logFile' -PSPath 'MACHINE/WEBROOT/APPHOST' -Name 'enabled' -Value:$true -ErrorAction Stop
                            Write-Good 'IIS: HTTP logging enabled by default for sites.'
                        }
                    } else { Write-Step 'IIS: site logging default already enabled.' }
                } catch { Write-Step 'IIS: could not read site logging defaults here - confirm Logging is enabled in IIS Manager.' }
                try {
                    $sites = @(Get-Website -ErrorAction Stop | Select-Object 'Name','State','PhysicalPath')
                    Add-Report 'hardened-services.txt' 'IIS sites' $sites
                } catch {}
                try {
                    $pools = @(Get-ChildItem 'IIS:\AppPools' -ErrorAction Stop)
                    foreach ($pool in $pools) {
                        $identity = "$($pool.processModel.identityType)"
                        Add-Report 'hardened-services.txt' ("IIS app pool " + $pool.Name + " identity") $identity
                        if ($identity -ieq 'LocalSystem') {
                            Write-WarnLine ("IIS app pool '" + $pool.Name + "' runs as LocalSystem (full machine access).")
                            if (-not $script:AuditOnly) {
                                if (Ask-YesNo ("Switch app pool '" + $pool.Name + "' to ApplicationPoolIdentity (least privilege)? Choose No unless you can test the website right after - file/database permissions may need it.") $false) {
                                    try {
                                        Set-ItemProperty ('IIS:\AppPools\' + $pool.Name) -Name 'processModel.identityType' -Value 'ApplicationPoolIdentity' -ErrorAction Stop
                                        Write-Good ("App pool '" + $pool.Name + "' now uses ApplicationPoolIdentity. TEST THE WEBSITE NOW.")
                                    } catch { Write-WarnLine ("Could not change app pool identity: " + $_.Exception.Message) }
                                }
                            }
                        }
                    }
                } catch {}
                try {
                    $dav = Get-WindowsOptionalFeature -Online -FeatureName 'IIS-WebDAV' -ErrorAction Stop
                    if ("$($dav.State)" -eq 'Enabled' -and -not (Test-TokenKept @('WEBDAV'))) {
                        Write-WarnLine 'IIS WebDAV Publishing is installed but WEBDAV is not in keep_services.txt. WebDAV is a classic attack surface - remove the feature in Server Manager / Optional Features unless a site truly publishes with it. (Not removed automatically: sites may depend on it.)'
                    }
                } catch {}
                Write-Step 'IIS anonymous authentication for websites was NOT changed: public websites normally require it. Restrict authentication per-site in IIS Manager only when the README says a site is private.'
            }
        }
    } catch { Write-WarnLine ("IIS hardening stopped safely: " + $_.Exception.Message) }

    # --- Apache / nginx (third-party web servers) -----------------------------
    try {
        $apacheSvcs = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^Apache' })
        if ($apacheSvcs.Count -gt 0) {
            $apacheNames = @($apacheSvcs | Select-Object -ExpandProperty Name)
            if (Test-ServiceIntended -Label 'Apache web server' -ServiceNames $apacheNames -Tokens @('APACHE','WEB')) {
                $aSvc = $apacheSvcs[0]
                $aExe = $null
                try {
                    $wmiA = Get-CimInstance Win32_Service -Filter ("Name='" + $aSvc.Name + "'") -ErrorAction Stop
                    if ($wmiA.PathName -match '"([^"]+\.exe)"') { $aExe = $Matches[1] }
                    elseif ($wmiA.PathName -match '^(\S+\.exe)') { $aExe = $Matches[1] }
                } catch {}
                $candidates = @()
                if ($null -ne $aExe) { $candidates += (Join-Path (Split-Path (Split-Path $aExe)) 'conf\httpd.conf') }
                $candidates += 'C:\Apache24\conf\httpd.conf'
                $candidates += 'C:\Apache\conf\httpd.conf'
                $candidates += 'C:\xampp\apache\conf\httpd.conf'
                $aConf = $null
                foreach ($c in $candidates) { if (Test-Path $c) { $aConf = $c; break } }
                $directives = @(
                    @{ K='ServerTokens'; V='Prod' },
                    @{ K='ServerSignature'; V='Off' },
                    @{ K='TraceEnable'; V='Off' },
                    @{ K='FileETag'; V='None' }
                )
                if ($null -eq $aConf) {
                    Write-WarnLine 'Apache service found but httpd.conf was not in a standard location. Add these global directives manually, run httpd -t, then restart Apache: ServerTokens Prod, ServerSignature Off, TraceEnable Off, FileETag None.'
                } elseif ($script:AuditOnly) {
                    foreach ($d in $directives) { Write-Host ("[AUDIT] Apache: would ensure '" + $d.K + ' ' + $d.V + "' in " + $aConf) }
                } elseif (Ask-YesNo ("Apply safe global Apache directives (ServerTokens Prod, ServerSignature Off, TraceEnable Off, FileETag None) in " + $aConf + "? The file is backed up, syntax-tested, and auto-restored if the test fails.") $true) {
                    $bak = $aConf + '.cp-backup-' + $script:Stamp
                    try { Copy-Item $aConf $bak -Force -ErrorAction Stop } catch { $bak = $null }
                    if ($null -ne $bak -and (Test-Path $script:BackupDir)) { try { Copy-Item $aConf (Join-Path $script:BackupDir 'httpd.conf') -Force } catch {} }
                    if ($null -eq $bak) {
                        Write-WarnLine 'Could not back up httpd.conf - Apache config left untouched.'
                    } else {
                        $lines = @(Get-Content $aConf -ErrorAction SilentlyContinue)
                        foreach ($d in $directives) {
                            $pattern = '^\s*' + [regex]::Escape($d.K) + '\s+'
                            $found = -1
                            for ($li = 0; $li -lt $lines.Count; $li++) {
                                $trim = ([string]$lines[$li]).TrimStart()
                                if ($trim.StartsWith('#')) { continue }
                                if ($lines[$li] -match $pattern) { $found = $li; break }
                            }
                            if ($found -ge 0) { $lines[$found] = ($d.K + ' ' + $d.V + '   # hardened by CP script') }
                            else { $lines += ($d.K + ' ' + $d.V + '   # hardened by CP script') }
                        }
                        Set-Content -Path $aConf -Value $lines -Encoding ASCII
                        $valid = $false
                        if ($null -ne $aExe -and (Test-Path $aExe)) {
                            try { & $aExe -t 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { $valid = $true } } catch {}
                        }
                        if (-not $valid) {
                            Copy-Item $bak $aConf -Force
                            Write-WarnLine 'Apache rejected the edited config (or httpd.exe could not be tested) - original httpd.conf restored, nothing changed.'
                        } else {
                            Write-Good 'Apache: banner/trace directives hardened and syntax verified.'
                            if (Ask-YesNo ("Restart " + $aSvc.Name + " now to apply the Apache settings?") $true) {
                                try {
                                    Restart-Service -Name $aSvc.Name -ErrorAction Stop
                                    Start-Sleep -Seconds 2
                                    $aAfter = Get-Service -Name $aSvc.Name -ErrorAction SilentlyContinue
                                    if ($null -eq $aAfter -or $aAfter.Status -ne 'Running') {
                                        Copy-Item $bak $aConf -Force
                                        Start-Service -Name $aSvc.Name -ErrorAction SilentlyContinue
                                        Write-WarnLine 'Apache did not come back up with the new config - original httpd.conf restored and service restarted.'
                                    }
                                } catch {
                                    Copy-Item $bak $aConf -Force
                                    Start-Service -Name $aSvc.Name -ErrorAction SilentlyContinue
                                    Write-WarnLine 'Apache restart failed - original httpd.conf restored.'
                                }
                            }
                        }
                    }
                }
            }
        }
        $ngx = Get-Service -Name 'nginx' -ErrorAction SilentlyContinue
        if ($null -ne $ngx -and (Test-ServiceIntended -Label 'nginx web server' -ServiceNames @('nginx') -Tokens @('NGINX','WEB'))) {
            Write-WarnLine "nginx is protected and kept running. Its config is context-sensitive, so it is not auto-edited: add 'server_tokens off;' inside the http block of nginx.conf, then run nginx -t and reload."
        }
    } catch { Write-WarnLine ("Apache/nginx hardening stopped safely: " + $_.Exception.Message) }

    # --- FTP ------------------------------------------------------------------
    try {
        if (Test-ServiceIntended -Label 'FTP service' -ServiceNames @('FTPSVC','MSFTPSVC') -Tokens @('FTP','ANONYMOUSFTP','PUBLICFTP')) {
            $anonAllowed = Test-TokenKept @('ANONYMOUSFTP','PUBLICFTP')
            $hasWA = $false
            if (Test-CommandExists 'Get-Website') { $hasWA = $true }
            else { try { Import-Module WebAdministration -ErrorAction Stop; $hasWA = $true } catch {} }
            if (-not $hasWA) {
                Write-WarnLine 'FTP hardening needs the WebAdministration module - in IIS Manager, open FTP Authentication per site and disable Anonymous unless the README requires a public FTP site.'
            } else {
                $allSites = @()
                try { $allSites = @(Get-Website -ErrorAction Stop) } catch {}
                foreach ($site in $allSites) {
                    $psPath = 'IIS:\Sites\' + $site.Name
                    $anonAttr = $null
                    try { $anonAttr = Get-WebConfigurationProperty -Filter 'system.ftpServer/security/authentication/anonymousAuthentication' -PSPath $psPath -Name 'enabled' -ErrorAction Stop } catch {}
                    if ($null -eq $anonAttr -or $null -eq $anonAttr.Value) { continue }
                    $anonOn = [bool]$anonAttr.Value
                    $sslInfo = 'unknown'
                    try {
                        $ctl = Get-WebConfigurationProperty -Filter 'system.ftpServer/security/ssl' -PSPath $psPath -Name 'controlChannelPolicy' -ErrorAction Stop
                        $dat = Get-WebConfigurationProperty -Filter 'system.ftpServer/security/ssl' -PSPath $psPath -Name 'dataChannelPolicy' -ErrorAction Stop
                        $sslInfo = ("control=" + $ctl.Value + " data=" + $dat.Value + " (0=allow plain, 1=require if configured, 2=require)")
                    } catch {}
                    Add-Report 'hardened-services.txt' ("FTP-capable site '" + $site.Name + "'") ("Anonymous=" + $anonOn + "  SSL policy: " + $sslInfo)
                    if ($anonOn) {
                        if ($anonAllowed) {
                            Write-WarnLine ("FTP site '" + $site.Name + "' allows anonymous logons and ANONYMOUSFTP is in the keep list, so it stays ON. Make sure anonymous users can only read a dedicated folder (FTP Authorization Rules + NTFS).")
                        } elseif ($script:AuditOnly) {
                            Write-Host ("[AUDIT] Would disable anonymous FTP on site '" + $site.Name + "' and enable Basic (password) authentication.")
                        } elseif (Ask-YesNo ("FTP site '" + $site.Name + "' allows ANONYMOUS logons (no password). Disable anonymous and require a username/password? Choose No only if the README requires public/anonymous FTP.") $true) {
                            try {
                                if (-not $iisBackedUp -and (Test-CommandExists 'Backup-WebConfiguration')) {
                                    try { Backup-WebConfiguration -Name ('CP-' + $script:Stamp) -ErrorAction Stop | Out-Null; $iisBackedUp = $true } catch {}
                                }
                                Set-WebConfigurationProperty -Filter 'system.ftpServer/security/authentication/anonymousAuthentication' -PSPath $psPath -Name 'enabled' -Value:$false -ErrorAction Stop
                                Set-WebConfigurationProperty -Filter 'system.ftpServer/security/authentication/basicAuthentication' -PSPath $psPath -Name 'enabled' -Value:$true -ErrorAction Stop
                                Write-Good ("FTP site '" + $site.Name + "': anonymous logons disabled, Basic (password) authentication enabled.")
                            } catch { Write-WarnLine ("Could not change FTP authentication on site '" + $site.Name + "': " + $_.Exception.Message) }
                        }
                    } else {
                        Write-Step ("FTP site '" + $site.Name + "': anonymous logons already off.")
                    }
                }
            }
            Write-Step 'FTPS (TLS) was NOT forced: requiring SSL without a bound certificate breaks every FTP client. Bind a certificate in IIS Manager (FTP SSL Settings) first, then set the SSL policy to Require.'
        }
    } catch { Write-WarnLine ("FTP hardening stopped safely: " + $_.Exception.Message) }

    # --- DNS server -------------------------------------------------------------
    try {
        if (Test-ServiceIntended -Label 'DNS server' -ServiceNames @('DNS') -Tokens @('DNS','AD','DOMAIN')) {
            if (-not (Test-CommandExists 'Get-DnsServerZone')) {
                Write-WarnLine 'DnsServer PowerShell module not available - in DNS Manager, restrict every primary zone transfer to only the servers listed as NS records (Zone Transfers tab), and enable cache pollution protection.'
            } else {
                try {
                    $cache = Get-DnsServerCache -ErrorAction Stop
                    if ($cache.EnablePollutionProtection -ne $true) {
                        if ($script:AuditOnly) { Write-Host '[AUDIT] Would enable DNS cache pollution protection.' }
                        else {
                            Set-DnsServerCache -PollutionProtection:$true -ErrorAction Stop
                            Write-Good 'DNS: cache pollution protection enabled (out-of-zone answers are no longer cached blindly).'
                        }
                    } else { Write-Step 'DNS: cache pollution protection already on.' }
                } catch { Write-WarnLine ("DNS cache pollution protection check failed: " + $_.Exception.Message) }
                $zones = @()
                try { $zones = @(Get-DnsServerZone -ErrorAction Stop) } catch {}
                Add-Report 'hardened-services.txt' 'DNS zones' ($zones | Select-Object 'ZoneName','ZoneType','DynamicUpdate','SecureSecondaries','IsDsIntegrated')
                foreach ($zone in $zones) {
                    if ("$($zone.ZoneType)" -eq 'Primary' -and "$($zone.SecureSecondaries)" -eq 'TransferAnyServer') {
                        if ($script:AuditOnly) {
                            Write-Host ("[AUDIT] DNS zone '" + $zone.ZoneName + "' allows AXFR transfers to ANY server - would restrict transfers to servers listed as NS records.")
                        } elseif (Ask-YesNo ("DNS zone '" + $zone.ZoneName + "' lets ANY host download the whole zone (AXFR). Restrict zone transfers to servers listed as NS records? (Safe unless an unlisted secondary server pulls this zone.)") $true) {
                            try {
                                Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries 'TransferToZoneNameServer' -Confirm:$false -ErrorAction Stop
                                Write-Good ("DNS zone '" + $zone.ZoneName + "': zone transfers restricted to listed name servers.")
                            } catch { Write-WarnLine ("Could not restrict zone transfers on '" + $zone.ZoneName + "': " + $_.Exception.Message) }
                        }
                    }
                    if ("$($zone.DynamicUpdate)" -eq 'NonsecureAndSecure' -and $zone.IsDsIntegrated -eq $true) {
                        if ($script:AuditOnly -or $script:ApplySafe) {
                            Write-WarnLine ("DNS zone '" + $zone.ZoneName + "' accepts NON-secure dynamic updates. Not changed automatically: non-domain devices (printers, Linux boxes) may rely on it. Re-run in Interactive mode to switch it to secure-only updates.")
                        } elseif (Ask-YesNo ("DNS zone '" + $zone.ZoneName + "' accepts NON-secure dynamic updates (anyone can register names). Switch to secure-only updates? Only choose Yes if all clients are domain-joined Windows machines.") $false) {
                            try {
                                Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate 'Secure' -Confirm:$false -ErrorAction Stop
                                Write-Good ("DNS zone '" + $zone.ZoneName + "': dynamic updates now secure-only.")
                            } catch { Write-WarnLine ("Could not set secure dynamic updates on '" + $zone.ZoneName + "': " + $_.Exception.Message) }
                        }
                    }
                }
                try {
                    if (Test-CommandExists 'Get-DnsServerRecursion') {
                        Add-Report 'hardened-services.txt' 'DNS recursion settings (reported only - AD clients usually need recursion)' (Get-DnsServerRecursion -ErrorAction SilentlyContinue)
                    }
                } catch {}
                Write-Step 'DNS recursion was left as-is: domain clients usually need this server to resolve internet names.'
            }
        }
    } catch { Write-WarnLine ("DNS hardening stopped safely: " + $_.Exception.Message) }

    # --- DHCP server --------------------------------------------------------------
    try {
        $dhcpSvc = Get-Service -Name 'DHCPServer' -ErrorAction SilentlyContinue
        if ($null -ne $dhcpSvc -and (Test-ServiceIntended -Label 'DHCP server' -ServiceNames @('DHCPServer') -Tokens @('DHCP'))) {
            if (-not (Test-CommandExists 'Get-DhcpServerAuditLog')) {
                Write-WarnLine 'DhcpServer PowerShell module not available - in the DHCP console, enable audit logging (server Properties, General tab).'
            } else {
                $dhcpChanged = $false
                try {
                    $auditLog = Get-DhcpServerAuditLog -ErrorAction Stop
                    if ($auditLog.Enable -ne $true) {
                        if ($script:AuditOnly) { Write-Host '[AUDIT] Would enable DHCP audit logging.' }
                        else {
                            Set-DhcpServerAuditLog -Enable:$true -ErrorAction Stop
                            $dhcpChanged = $true
                            Write-Good 'DHCP: audit logging enabled (every lease event is now logged).'
                        }
                    } else { Write-Step 'DHCP: audit logging already enabled.' }
                } catch { Write-WarnLine ("DHCP audit log check failed: " + $_.Exception.Message) }
                try { Add-Report 'hardened-services.txt' 'DHCP scopes' (Get-DhcpServerv4Scope -ErrorAction Stop | Select-Object 'ScopeId','Name','State') } catch {}
                try {
                    $dhcpSettings = Get-DhcpServerSetting -ErrorAction Stop
                    Add-Report 'hardened-services.txt' 'DHCP server settings' $dhcpSettings
                    if ($dhcpSettings.ConflictDetectionAttempts -eq 0 -and -not $script:AuditOnly) {
                        if (Ask-YesNo 'Enable DHCP conflict detection (server pings an address once before leasing it)? Slightly slower leases, prevents duplicate IPs.' $false) {
                            Set-DhcpServerSetting -ConflictDetectionAttempts 1 -ErrorAction Stop
                            Write-Good 'DHCP: conflict detection set to 1 attempt.'
                        }
                    }
                } catch {}
                if ($dhcpChanged -and -not $script:AuditOnly) {
                    if (Ask-YesNo 'Restart the DHCP Server service now so audit logging takes effect? (Seconds-long pause; existing leases are kept.)' $false) {
                        try {
                            Restart-Service -Name 'DHCPServer' -ErrorAction Stop
                            Write-Good 'DHCP Server service restarted with audit logging active.'
                        } catch { Write-WarnLine ("DHCP restart failed: " + $_.Exception.Message + " - restart it manually soon; do not leave it stopped.") }
                    } else {
                        Write-Step 'DHCP audit logging will take full effect at the next DHCP service restart.'
                    }
                }
            }
        }
    } catch { Write-WarnLine ("DHCP hardening stopped safely: " + $_.Exception.Message) }

    # --- SMB file sharing ---------------------------------------------------------
    try {
        if ($script:FileSharingCritical -or (Test-ServiceIntended -Label 'SMB file sharing' -ServiceNames @('LanmanServer') -Tokens @('SMB','FILES','FILE','SHARES'))) {
            if (Test-CommandExists 'Get-SmbServerConfiguration') {
                $smbCfg = $null
                try { $smbCfg = Get-SmbServerConfiguration -ErrorAction Stop } catch {}
                if ($null -ne $smbCfg) {
                    if (-not $script:AuditOnly -and (Test-Path $script:BackupDir)) {
                        try { ($smbCfg | Format-List * | Out-String) | Out-File (Join-Path $script:BackupDir 'smb-server-config-before.txt') } catch {}
                    }
                    if ($smbCfg.EnableSMB2Protocol -ne $true) {
                        if ($script:AuditOnly) { Write-Host '[AUDIT] SMB2 is OFF - would re-enable SMB2/3 for the file server.' }
                        else {
                            try {
                                Set-SmbServerConfiguration -EnableSMB2Protocol:$true -Force -ErrorAction Stop
                                Write-Good 'SMB: SMB2/3 re-enabled (file sharing needs it; SMB1 stays disabled).'
                            } catch { Write-WarnLine ("Could not enable SMB2: " + $_.Exception.Message) }
                        }
                    }
                    if ($null -ne $smbCfg.PSObject.Properties['AuditSmb1Access'] -and $smbCfg.AuditSmb1Access -ne $true) {
                        if ($script:AuditOnly) { Write-Host '[AUDIT] Would enable auditing of SMB1 access attempts (logging only).' }
                        else {
                            try {
                                Set-SmbServerConfiguration -AuditSmb1Access:$true -Force -ErrorAction Stop
                                Write-Good 'SMB: SMB1 access attempts are now audited (detection only, nothing is blocked).'
                            } catch { Write-WarnLine ("Could not enable SMB1 access auditing: " + $_.Exception.Message) }
                        }
                    }
                    try {
                        $setSmb = Get-Command 'Set-SmbServerConfiguration' -ErrorAction Stop
                        if ($setSmb.Parameters.ContainsKey('AuditInsecureGuestLogon') -and $null -ne $smbCfg.PSObject.Properties['AuditInsecureGuestLogon'] -and $smbCfg.AuditInsecureGuestLogon -ne $true) {
                            if ($script:AuditOnly) { Write-Host '[AUDIT] Would enable auditing of insecure guest logons (logging only).' }
                            else {
                                Set-SmbServerConfiguration -AuditInsecureGuestLogon:$true -Force -ErrorAction Stop
                                Write-Good 'SMB: insecure guest logons are now audited (detection only).'
                            }
                        }
                    } catch {}
                    Add-Report 'hardened-services.txt' 'SMB server configuration' ($smbCfg | Select-Object 'EnableSMB1Protocol','EnableSMB2Protocol','EncryptData','RejectUnencryptedAccess','RequireSecuritySignature','EnableSecuritySignature')
                    if ($smbCfg.EncryptData -ne $true -and -not $script:AuditOnly) {
                        if (Ask-YesNo 'Enable SMB encryption server-wide in TRANSITION mode (encrypts when clients support it, but does NOT reject older unencrypted clients)?' $false) {
                            try {
                                Set-SmbServerConfiguration -RejectUnencryptedAccess:$false -EncryptData:$true -Force -ErrorAction Stop
                                Write-Good 'SMB encryption enabled in transition mode (no client is locked out). Once every client is SMB 3.x, set RejectUnencryptedAccess to true manually.'
                            } catch { Write-WarnLine ("Could not enable SMB encryption: " + $_.Exception.Message) }
                        }
                    }
                    if (Test-CommandExists 'Get-SmbShare') {
                        try { Add-Report 'hardened-services.txt' 'SMB shares and per-share encryption' (Get-SmbShare -ErrorAction Stop | Select-Object 'Name','Path','EncryptData') } catch {}
                    }
                }
            }
        }
    } catch { Write-WarnLine ("SMB hardening stopped safely: " + $_.Exception.Message) }

    # --- Print spooler ---------------------------------------------------------------
    try {
        if (Test-ServiceIntended -Label 'Print Spooler' -ServiceNames @('Spooler') -Tokens @('PRINT','PRINTING')) {
            $pointPrint = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
            Set-RegValue $pointPrint 'RestrictDriverInstallationToAdministrators' 1 'DWord' 'Only administrators can install print drivers (PrintNightmare fix)'
            Set-RegValue $pointPrint 'NoWarningNoElevationOnInstall' 0 'DWord' 'Show elevation prompt for new print connections'
            Set-RegValue $pointPrint 'UpdatePromptSettings' 0 'DWord' 'Show elevation prompt for updated print drivers'
            $sharedCount = 0
            if (Test-CommandExists 'Get-Printer') {
                try {
                    $printers = @(Get-Printer -ErrorAction Stop | Select-Object 'Name','Shared','ShareName','PortName')
                    Add-Report 'hardened-services.txt' 'Printers' $printers
                    $sharedCount = @($printers | Where-Object { $_.Shared }).Count
                } catch {}
            }
            if ($script:IsDC) {
                Write-WarnLine 'The Print Spooler is running on a DOMAIN CONTROLLER and marked critical, so it stays on with the driver restrictions above. Microsoft recommends no spooler on DCs - only keep it if the README truly requires printing here.'
            }
            if ($sharedCount -gt 0) {
                Write-Step ("Shared printers found (" + $sharedCount + "), so the spooler keeps accepting client connections. Restrict shared-printer permissions to the groups that need them.")
            } elseif (Ask-YesNo 'Is printing LOCAL ONLY on this machine (no other computer prints through it)? Yes blocks remote connections to the spooler (strong PrintNightmare mitigation) while local printing keeps working.' $false) {
                $printPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
                [void](Set-RegValue $printPol 'RegisterSpoolerRemoteRpcEndPoint' 2 'DWord' 'Print Spooler refuses remote client connections (local printing only)')
                if (-not $script:AuditOnly) {
                    if (Ask-YesNo 'Restart the Print Spooler now to activate the remote-connection block?' $true) {
                        try {
                            Restart-Service -Name 'Spooler' -ErrorAction Stop
                            Write-Good 'Print Spooler restarted: remote print connections are now refused.'
                        } catch { Write-WarnLine ("Spooler restart failed: " + $_.Exception.Message + " - the setting applies at the next spooler restart.") }
                    }
                }
            }
        }
    } catch { Write-WarnLine ("Print hardening stopped safely: " + $_.Exception.Message) }

    # --- OpenSSH server ---------------------------------------------------------------
    try {
        if (Test-ServiceIntended -Label 'OpenSSH server' -ServiceNames @('sshd') -Tokens @('SSH')) {
            $sshCfg = Join-Path $env:ProgramData 'ssh\sshd_config'
            if (-not (Test-Path $sshCfg)) {
                Write-WarnLine ("sshd is kept but " + $sshCfg + " does not exist yet (it is created when the service starts). Re-run this step after sshd has started once.")
            } else {
                $sshDirectives = @(
                    @{ K='PermitEmptyPasswords'; V='no' },
                    @{ K='MaxAuthTries'; V='4' },
                    @{ K='LoginGraceTime'; V='60' },
                    @{ K='X11Forwarding'; V='no' },
                    @{ K='HostbasedAuthentication'; V='no' },
                    @{ K='IgnoreRhosts'; V='yes' },
                    @{ K='StrictModes'; V='yes' },
                    @{ K='PubkeyAuthentication'; V='yes' },
                    @{ K='MaxSessions'; V='5' }
                )
                $lines = @(Get-Content $sshCfg -ErrorAction SilentlyContinue)
                $matchIdx = $lines.Count
                for ($li = 0; $li -lt $lines.Count; $li++) {
                    if ([string]$lines[$li] -match '^\s*Match\b') { $matchIdx = $li; break }
                }
                $toInsert = @()
                $sshChanged = $false
                foreach ($d in $sshDirectives) {
                    $pattern = '^\s*' + [regex]::Escape($d.K) + '(\s|=)'
                    $found = -1
                    $currentVal = '(not set)'
                    for ($li = 0; $li -lt $matchIdx; $li++) {
                        if ([string]$lines[$li] -match $pattern) {
                            $found = $li
                            $currentVal = (([string]$lines[$li] -replace $pattern, '')).Trim()
                            break
                        }
                    }
                    if ($script:AuditOnly) {
                        Write-Host ("[AUDIT] sshd: would ensure '" + $d.K + ' ' + $d.V + "' (now: " + $currentVal + ")")
                    } elseif ($found -ge 0) {
                        if ($currentVal -ine $d.V) {
                            $lines[$found] = ($d.K + ' ' + $d.V + '   # hardened by CP script')
                            $sshChanged = $true
                        }
                    } else {
                        $toInsert += ($d.K + ' ' + $d.V + '   # hardened by CP script')
                        $sshChanged = $true
                    }
                }
                if ($script:AuditOnly) {
                    Write-Host '[AUDIT] sshd: password authentication would be left as-is (disabling it without tested keys locks everyone out).'
                } elseif (-not $sshChanged) {
                    Write-Step 'OpenSSH: sshd_config already matches the hardened values.'
                } elseif (Ask-YesNo 'Apply the safe sshd_config values above? (backup + syntax test + automatic restore on failure; password authentication is NOT touched, so nobody is locked out)' $true) {
                    $sshBak = $sshCfg + '.cp-backup-' + $script:Stamp
                    try { Copy-Item $sshCfg $sshBak -Force -ErrorAction Stop } catch { $sshBak = $null }
                    if ($null -ne $sshBak -and (Test-Path $script:BackupDir)) { try { Copy-Item $sshCfg (Join-Path $script:BackupDir 'sshd_config') -Force } catch {} }
                    if ($null -eq $sshBak) {
                        Write-WarnLine 'Could not back up sshd_config - file left untouched.'
                    } else {
                        if ($toInsert.Count -gt 0) {
                            $newLines = @()
                            if ($matchIdx -gt 0) { $newLines += @($lines[0..($matchIdx - 1)]) }
                            $newLines += $toInsert
                            if ($matchIdx -lt $lines.Count) { $newLines += @($lines[$matchIdx..($lines.Count - 1)]) }
                            $lines = $newLines
                        }
                        Set-Content -Path $sshCfg -Value $lines -Encoding ASCII
                        $sshExe = $null
                        foreach ($cand in @((Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'), 'C:\Program Files\OpenSSH\sshd.exe')) {
                            if (Test-Path $cand) { $sshExe = $cand; break }
                        }
                        if ($null -eq $sshExe) {
                            try {
                                $wmiS = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
                                if ($wmiS.PathName -match '"([^"]+\.exe)"') { $sshExe = $Matches[1] }
                                elseif ($wmiS.PathName -match '^(\S+\.exe)') { $sshExe = $Matches[1] }
                            } catch {}
                        }
                        $valid = $false
                        if ($null -ne $sshExe -and (Test-Path $sshExe)) {
                            try { & $sshExe -t -f $sshCfg 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { $valid = $true } } catch {}
                        }
                        if (-not $valid) {
                            Copy-Item $sshBak $sshCfg -Force
                            Write-WarnLine 'sshd rejected the edited config (or sshd.exe could not be run to test it) - original sshd_config restored, nothing changed.'
                        } else {
                            Write-Good 'OpenSSH: sshd_config hardened and syntax verified with sshd -t.'
                            if (Ask-YesNo 'Restart the sshd service now to apply the SSH settings?' $true) {
                                try {
                                    Restart-Service -Name 'sshd' -ErrorAction Stop
                                    Start-Sleep -Seconds 2
                                    $sshAfter = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue
                                    if ($null -eq $sshAfter -or $sshAfter.Status -ne 'Running') {
                                        Copy-Item $sshBak $sshCfg -Force
                                        Start-Service -Name 'sshd' -ErrorAction SilentlyContinue
                                        Write-WarnLine 'sshd did not come back up with the new config - original sshd_config restored and service restarted.'
                                    }
                                } catch {
                                    Copy-Item $sshBak $sshCfg -Force
                                    Start-Service -Name 'sshd' -ErrorAction SilentlyContinue
                                    Write-WarnLine 'sshd restart failed - original sshd_config restored.'
                                }
                            }
                        }
                    }
                }
                Write-Step 'OpenSSH password authentication was intentionally NOT disabled. Switch to key-only logins manually (PasswordAuthentication no) only after proving key logins work for every required account.'
            }
        }
    } catch { Write-WarnLine ("SSH hardening stopped safely: " + $_.Exception.Message) }

    # --- WinRM ---------------------------------------------------------------------------
    try {
        if (Test-ServiceIntended -Label 'WinRM remote management' -ServiceNames @('WinRM') -Tokens @('WINRM','REMOTE')) {
            Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' 0 'DWord' 'WinRM service must not use Basic (clear-text password) authentication'
            try {
                $listeners = & cmd.exe /c 'winrm enumerate winrm/config/listener' 2>$null
                Add-Report 'hardened-services.txt' 'WinRM listeners' ($listeners -join "`r`n")
                $auth = & cmd.exe /c 'winrm get winrm/config/service/auth' 2>$null
                Add-Report 'hardened-services.txt' 'WinRM service authentication' ($auth -join "`r`n")
            } catch {}
            Write-Step 'WinRM listeners were NOT removed and HTTPS was NOT forced: remote management may depend on the HTTP listener and Kerberos/Negotiate already encrypts message payloads on domain networks. Add an HTTPS listener manually only with a proper certificate.'
        }
    } catch { Write-WarnLine ("WinRM hardening stopped safely: " + $_.Exception.Message) }

    # --- SNMP -------------------------------------------------------------------------------
    try {
        if (Test-ServiceIntended -Label 'SNMP' -ServiceNames @('SNMP') -Tokens @('SNMP')) {
            Write-Step 'SNMP stays ON. Community strings are never renamed automatically (the management station would lose access instantly); only write-capable rights are reduced, with your confirmation.'
            $commKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
            $snmpChanged = $false
            if (Test-Path $commKey) {
                $props = Get-ItemProperty $commKey -ErrorAction SilentlyContinue
                if ($null -ne $props) {
                    foreach ($prop in $props.PSObject.Properties) {
                        if ($prop.Name -like 'PS*') { continue }
                        $rights = 0
                        try { $rights = [int]$prop.Value } catch {}
                        $rightsText = ('custom (' + $rights.ToString() + ')')
                        if ($rights -eq 1) { $rightsText = 'None' }
                        elseif ($rights -eq 2) { $rightsText = 'Notify' }
                        elseif ($rights -eq 4) { $rightsText = 'ReadOnly' }
                        elseif ($rights -eq 8) { $rightsText = 'ReadWrite' }
                        elseif ($rights -eq 16) { $rightsText = 'ReadCreate' }
                        Add-Report 'hardened-services.txt' 'SNMP communities' ($prop.Name + " = " + $rightsText)
                        if ($prop.Name -ieq 'public' -or $prop.Name -ieq 'private') {
                            Write-WarnLine ("SNMP uses the well-known community '" + $prop.Name + "'. Rename it Together With the management station - never unilaterally.")
                        }
                        if ($rights -ge 8) {
                            if ($script:AuditOnly) {
                                Write-Host ("[AUDIT] SNMP community '" + $prop.Name + "' has write rights (" + $rightsText + ") - would reduce it to ReadOnly.")
                            } elseif (Ask-YesNo ("SNMP community '" + $prop.Name + "' can WRITE (" + $rightsText + "). Reduce it to ReadOnly? Choose No only if the management station truly sets values through SNMP.") $true) {
                                if (-not $snmpChanged -and (Test-Path $script:BackupDir)) {
                                    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters' (Join-Path $script:BackupDir 'reg-snmp-before.reg')
                                }
                                try {
                                    Set-ItemProperty -Path $commKey -Name $prop.Name -Value 4 -ErrorAction Stop
                                    $snmpChanged = $true
                                    Write-Good ("SNMP community '" + $prop.Name + "' reduced to ReadOnly (name unchanged, so existing managers keep working).")
                                } catch { Write-WarnLine ("Could not change SNMP community rights: " + $_.Exception.Message) }
                            }
                        }
                    }
                }
            } else {
                Write-Step 'No SNMP ValidCommunities key found (SNMP may be freshly installed with no communities yet).'
            }
            $mgrKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers'
            $mgrs = @()
            try {
                $mgrProps = Get-ItemProperty $mgrKey -ErrorAction Stop
                foreach ($prop in $mgrProps.PSObject.Properties) { if ($prop.Name -notlike 'PS*') { $mgrs += [string]$prop.Value } }
            } catch {}
            if ($mgrs.Count -eq 0) {
                Write-WarnLine 'SNMP accepts queries from ANY host (no PermittedManagers). Add only the management station IP under HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers once you know it - guessing it here could cut off monitoring.'
            } else {
                Add-Report 'hardened-services.txt' 'SNMP permitted managers' ($mgrs -join ', ')
            }
            if ($snmpChanged -and -not $script:AuditOnly) {
                if (Ask-YesNo 'Restart the SNMP service now to apply the community-rights change?' $true) {
                    try { Restart-Service -Name 'SNMP' -ErrorAction Stop; Write-Good 'SNMP service restarted with read-only community rights.' }
                    catch { Write-WarnLine ("SNMP restart failed: " + $_.Exception.Message) }
                }
            }
        }
    } catch { Write-WarnLine ("SNMP hardening stopped safely: " + $_.Exception.Message) }

    # --- Active Directory / LDAP on a domain controller ---------------------------------------
    try {
        if ($script:IsDC) {
            $ntdsParams = 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
            $cbt = Get-RegValue $ntdsParams 'LdapEnforceChannelBinding'
            if ($null -eq $cbt -or "$cbt" -eq '0') {
                Set-RegValue $ntdsParams 'LdapEnforceChannelBinding' 1 'DWord' 'LDAP channel binding in audit mode (logs weak clients, rejects nobody)'
            } else {
                Write-Step ("LDAP channel binding already set (LdapEnforceChannelBinding = " + $cbt + ").")
            }
            if (-not $script:AuditOnly -and -not $script:ApplySafe) {
                if (Ask-YesNo 'Require LDAP signing on this domain controller (LDAPServerIntegrity = 2)? Unsigned LDAP binds will be REJECTED - old apps/devices may break. Choose No unless you have checked the directory service log for unsigned binds.' $false) {
                    Set-RegValue $ntdsParams 'LDAPServerIntegrity' 2 'DWord' 'Require LDAP signing (operator opt-in)'
                }
            }
        }
    } catch { Write-WarnLine ("AD/LDAP hardening stopped safely: " + $_.Exception.Message) }

    # --- Databases -------------------------------------------------------------------------------
    try {
        $dbSvcs = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(MSSQL|SQLAgent|MySQL|MariaDB|postgres)' })
        if ($dbSvcs.Count -gt 0) {
            $dbNames = @($dbSvcs | Select-Object -ExpandProperty Name)
            if (Test-ServiceIntended -Label 'Database server' -ServiceNames $dbNames -Tokens @('SQL','DATABASE','MYSQL','POSTGRESQL')) {
                try {
                    $dbInfo = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.Name -match '^(MSSQL|SQLAgent|MySQL|MariaDB|postgres|SQLBrowser)' } | Select-Object 'Name','State','StartMode','StartName','PathName')
                    Add-Report 'hardened-services.txt' 'Database services (account and binary)' $dbInfo
                } catch {}
                Write-WarnLine 'Database engine internals are NOT auto-edited (one wrong setting can lock out every application). Inside the engine, check: no blank/default sa or root password, xp_cmdshell disabled (SQL Server), no anonymous users (MySQL), ForceEncryption only with a trusted certificate (SQL Server Configuration Manager), and application accounts are not sysadmin/root.'
                $browser = Get-Service -Name 'SQLBrowser' -ErrorAction SilentlyContinue
                if ($null -ne $browser -and $browser.Status -eq 'Running' -and -not $script:AuditOnly) {
                    if (Ask-YesNo 'SQL Server Browser is running (UDP 1434 helps attackers enumerate instances). Disable it? Choose Yes ONLY if clients connect by fixed IP/port; named-instance discovery by name will stop working.' $false) {
                        Disable-ServiceSafe -Name 'SQLBrowser' -Why 'Instance enumeration not needed (operator opt-in)'
                    }
                }
            }
        }
    } catch { Write-WarnLine ("Database checks stopped safely: " + $_.Exception.Message) }

    # --- Mail / VPN / Telnet: honest manual notes -------------------------------------------------
    try {
        $smtp = Get-Service -Name 'SMTPSVC' -ErrorAction SilentlyContinue
        if ($null -ne $smtp -and (Test-ServiceIntended -Label 'SMTP mail service' -ServiceNames @('SMTPSVC') -Tokens @('SMTP','EMAIL'))) {
            Write-WarnLine 'Legacy IIS SMTP is kept running. In Internet Information Services (IIS 6.0) Manager, open the SMTP Virtual Server properties, Access tab, Relay restrictions: ONLY the list below may relay, and that list must be nearly empty. An open relay is both a vulnerability and a scoring penalty.'
        }
        $rras = Get-Service -Name 'RemoteAccess' -ErrorAction SilentlyContinue
        if ($null -ne $rras -and (Test-ServiceIntended -Label 'VPN / Routing and Remote Access' -ServiceNames @('RemoteAccess') -Tokens @('VPN'))) {
            try { Add-Report 'hardened-services.txt' 'RRAS authentication types' (& netsh.exe ras show authtype 2>$null | Out-String) } catch {}
            Write-WarnLine 'RRAS/VPN is kept running with IKEEXT and PolicyAgent. Authentication protocols were NOT changed (PPTP/CHAP may be all a legacy client supports): in the RRAS console prefer EAP/MS-CHAPv2, disable PAP/CHAP/shiva and unauthenticated access, and confirm the VPN still connects after every change.'
        }
        $telnet = Get-Service -Name 'TlntSvr' -ErrorAction SilentlyContinue
        if ($null -ne $telnet -and (Test-ServiceIntended -Label 'Telnet server' -ServiceNames @('TlntSvr') -Tokens @('TELNET'))) {
            Write-WarnLine 'TELNET IS KEPT ONLY BECAUSE YOU/LIST SAY SO. Telnet cannot be encrypted: credentials cross the network in clear text. Set NTLM authentication with tlntadmn, restrict tcp/23 in the firewall to known hosts, and strongly consider migrating the workflow to SSH.'
        }
    } catch { Write-WarnLine ("Mail/VPN/Telnet checks stopped safely: " + $_.Exception.Message) }

    Write-Step 'Kept-service hardening finished. Confirm every critical service still shows RUNNING, then refresh the Scoring Report.'
}

# ----------------------------------------------------------------------------
# Network protocols: SMBv1, LLMNR, NetBIOS, TLS, hosts
# ----------------------------------------------------------------------------
function Invoke-NetworkProtocols {
    Write-Banner 'STEP 9D OF 12 - NETWORK PROTOCOLS (SMBv1, LLMNR, NetBIOS, TLS, hosts)'
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
    Write-Banner 'STEP 9E OF 12 - FILE SHARES + PERMISSIONS'
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
        Initialize-ServiceGraph
        Update-KeptDependencyClosure
        $keptDown = @()
        $keptUp = 0
        $keptTotal = 0
        foreach ($lower in @($script:ServiceCanonByLower.Keys)) {
            $canon = [string]$script:ServiceCanonByLower[$lower]
            $disp = [string]$script:ServiceDisplayByLower[$lower]
            if (-not (Test-ServiceScenarioKept -Name $canon -DisplayName $disp)) { continue }
            $fresh = Get-Service -Name $canon -ErrorAction SilentlyContinue
            if ($null -eq $fresh) { continue }
            if ($fresh.StartType -eq 'Manual') { continue }
            $keptTotal++
            if ($fresh.Status -eq 'Running') { $keptUp++ } else { $keptDown += $canon }
        }
        if ($keptTotal -gt 0) {
            Test-Row 'All scenario-critical services RUNNING' ($keptDown.Count -eq 0) ($keptUp.ToString() + '/' + $keptTotal.ToString() + ' running; down: ' + ($keptDown -join ', '))
            $depBroken = @()
            foreach ($lower in @($script:KeptClosureLower.Keys)) {
                if ([string]::IsNullOrEmpty([string]$script:KeptClosureLower[$lower])) { continue }
                if (-not $script:ServiceCanonByLower.ContainsKey($lower)) { continue }
                $canon = [string]$script:ServiceCanonByLower[$lower]
                $fresh = Get-Service -Name $canon -ErrorAction SilentlyContinue
                if ($null -ne $fresh -and $fresh.StartType -eq 'Disabled') { $depBroken += ($canon + ' (needed by ' + $script:KeptClosureLower[$lower] + ')') }
            }
            Test-Row 'No critical-service dependency is Disabled' ($depBroken.Count -eq 0) ($depBroken -join ', ')
        }
    } catch {}
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
            Invoke-ServiceHardening
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
        Invoke-ServiceHardening
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
