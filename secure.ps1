<#
.SYNOPSIS
    CyberPatriot Windows hardening for Windows images (Windows 10 / 11 and
    Windows Server 2019 / 2022 / 2025), audit-first and penalty-averse.

.DESCRIPTION
    Design rules of this script (in priority order):
      1. NEVER lose points: forensics gate first, README-driven allow-lists,
         the scoring service / VM tools / current user / service accounts /
         domain controllers are hard-protected, core backups precede changes,
         nothing is deleted silently, and the script never reboots. Rollback
         is partial; keep a VM snapshot and review the README recovery limits.
      2. Gain points: applies the controls CyberPatriot scores (users,
         password + lockout policy, security options, audit policy,
         firewall, Defender, insecure services, remote access, SMB,
         shares, prohibited software/files, updates) using values aligned
         with CIS Benchmarks and current Microsoft security baselines.
      3. Be transparent: -Mode Audit changes nothing, everything is logged,
         and docs/RESEARCH_AND_SAFETY.md explains every single fix.

.EXAMPLE
    .\secure.ps1 -Mode Audit        (read-only: reports + pass/fail table)
    .\secure.ps1                     (interactive, the normal way)
    .\secure.ps1 -Mode ApplySafe -ForensicsDone -ReadmeConfigured
    .\secure.ps1 -Mode Update       (auto-update necessary apps & dependencies)
    .\secure.ps1 -Rollback           (restore the newest backup)
#>
[CmdletBinding()]
param(
    [ValidateSet('Interactive','Audit','ApplySafe','Update')]
    [string]$Mode = 'Interactive',
    [switch]$ForensicsDone,
    [switch]$ReadmeConfigured,
    [switch]$AutoUpdate,
    [switch]$SkipWindowsUpdates,
    [switch]$ScanFiles,
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
$script:EntryScript = $PSCommandPath
$script:Root = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($script:Root)) { $script:Root = (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($script:EntryScript)) { $script:EntryScript = Join-Path $script:Root 'secure.ps1' }
$script:Stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:LogDir = Join-Path $script:Root 'Logs'
$script:ReportDir = Join-Path $script:Root ("Reports\" + $script:Stamp)
$script:BackupDir = Join-Path $script:Root ("Backups\" + $script:Stamp)
$script:Config = [PSCustomObject]@{
    Mode               = $Mode
    ForensicsDone      = [bool]$ForensicsDone
    ReadmeConfigured   = [bool]$ReadmeConfigured
    AutoUpdate         = [bool]$AutoUpdate
    SkipWindowsUpdates = [bool]$SkipWindowsUpdates
    ScanFiles          = [bool]$ScanFiles
    Rollback           = [bool]$Rollback
    RollbackPath       = $RollbackPath
    ShowAIPrompt       = [bool]$ShowAIPrompt
    NoElevate          = [bool]$NoElevate
    MinPasswordLength  = $MinPasswordLength
    PasswordHistorySize= $PasswordHistorySize
    MaxPasswordAgeDays = $MaxPasswordAgeDays
    MinPasswordAgeDays = $MinPasswordAgeDays
    LockoutThreshold   = $LockoutThreshold
    LockoutDurationMin = $LockoutDurationMin
    LockoutResetMin    = $LockoutResetMin
}
$script:AuditOnly = ($Mode -eq 'Audit')
$script:ApplySafe = ($Mode -eq 'ApplySafe')
$script:UpdateOnly = ($Mode -eq 'Update')
$script:AutoUpdateStep = $false
$script:ElevatedExitCode = 0
$script:WinGetSupportsNonInteractive = $true
$script:Changes = New-Object System.Collections.ArrayList
$script:Warnings = New-Object System.Collections.ArrayList
$script:PendingRebootReasons = New-Object System.Collections.ArrayList
$script:QuarantineEntries = New-Object System.Collections.ArrayList
$script:SuspiciousFilesSummary = $null
$script:CurrentUser = [Environment]::UserName
$script:IsServer = $false
$script:IsDC = $false
$script:DomainJoined = $false
$script:OSCaption = 'Unknown Windows'
$script:TeamPassword = $null
$script:KeepEntries = @()
$script:KeptByChoice = New-Object System.Collections.ArrayList
$script:AuthorizedUsers = @()
$script:AuthorizedAdmins = @()
$script:RdpUsers = @()
$script:NecessaryApps = @()
$script:ExcludedFromUpdates = @()
$script:ProhibitedSoftware = @()
$script:BuiltInUsers = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')
$script:FileSharingCritical = $false
$script:RdpCritical = $false

foreach ($dirPath in @($script:LogDir, $script:ReportDir)) {
    if (-not (Test-Path $dirPath)) { New-Item -ItemType Directory -Path $dirPath -Force | Out-Null }
}
try { Start-Transcript -Path (Join-Path $script:LogDir ("secure_" + $script:Stamp + ".log")) -Force | Out-Null } catch {}

$script:ModuleFiles = @(
    'Common.ps1',
    'ServiceShield.ps1',
    'BackupAndPreflight.ps1',
    'ReconAndPolicy.ps1',
    'ProcessTriage.ps1',
    'NetworkAndAccess.ps1',
    'ServiceHardening.ps1',
    'FileScanner.ps1',
    'Updates.ps1',
    'Verification.ps1'
)
foreach ($modFile in $script:ModuleFiles) {
    $modPath = Join-Path (Join-Path $script:Root 'modules') $modFile
    if (-not (Test-Path -LiteralPath $modPath)) {
        throw ("Missing required module file: " + $modPath + ". Keep the entire modules folder beside secure.ps1.")
    }
    . $modPath
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
function Invoke-Main {
    Write-Banner 'CyberPatriot Windows Hardening - 2026 edition (Windows 10/11, Server 2019/2022/2025)'
    Write-Host 'Audit-first, backup-always, never-auto-reboot.'
    Show-AIPrompt

    if ($script:Config.Rollback) {
        Invoke-Rollback -Path $script:Config.RollbackPath
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
            Invoke-ProcessTriage
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
        Write-Host 'Audit complete. No system settings were changed. Reports and logs were written locally.'
        return
    }

    if ($script:UpdateOnly) {
        try {
            Invoke-Updates
            if ($script:Config.ScanFiles) { Invoke-VulnerabilityFileScan }
        } catch {
            Write-WarnLine ("Auto-update stopped early: " + $_.Exception.Message)
        }
        Write-Banner 'AUTO-UPDATE SUMMARY'
        Write-Host ("Updates/repairs : " + $script:Changes.Count)
        Write-Host ("Warnings        : " + $script:Warnings.Count)
        Write-Host ("Reports         : " + $script:ReportDir)
        $summaryPath = Join-Path $script:ReportDir 'summary.txt'
        @(
            ('Date: ' + (Get-Date -Format s)),
            ('Computer: ' + $env:COMPUTERNAME + '  OS: ' + $script:OSCaption),
            'Mode: Update',
            '',
            '--- CHANGES ---'
        ) + @($script:Changes) + @('', '--- WARNINGS ---') + @($script:Warnings) |
            Out-File $summaryPath -Force
        return
    }

    if ($script:ApplySafe -and (-not $script:Config.ForensicsDone -or -not $script:Config.ReadmeConfigured)) {
        Write-WarnLine 'ApplySafe requires BOTH -ForensicsDone and -ReadmeConfigured (proof you did'
        Write-WarnLine 'the two manual gates). Refusing to run unattended without them.'
        return
    }

    try { Invoke-Backup } catch {
        Write-WarnLine ("Backup failed; stopping before hardening: " + $_.Exception.Message)
        return
    }
    try {
        Invoke-Recon
        Invoke-Passwords
        Invoke-AccountPolicy
        Invoke-SecurityOptions
        Invoke-AuditPolicy
        Invoke-Defender
        Invoke-ProcessTriage
        Invoke-PersistenceRemediation
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
if ($script:ElevatedExitCode -ne 0) { exit $script:ElevatedExitCode }
