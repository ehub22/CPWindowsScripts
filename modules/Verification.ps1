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
    if (-not (Confirm-YesNo 'Apply ONE role-appropriate legacy GPO set anyway (not recommended for Windows 11 / Server 2022+ images)?' $false)) {
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
    if (Confirm-YesNo 'Proceed with the role-appropriate LGPO import?' $false) {
        try {
            & $lgpo /g $stage
            Write-Good 'Legacy GPO import finished. Watch the Scoring Report closely.'
            Write-WarnLine 'If the score DROPS, run .\secure.ps1 -Rollback and re-check gpedit.msc by hand.'
        } catch { Write-WarnLine 'LGPO failed to run.' }
    }
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
    $mdns = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS'
    Test-Row 'mDNS disabled' ("$mdns" -eq '0') ("value=" + $mdns)
    $aieLm = Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $aieCu = Get-RegValue 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    Test-Row 'AlwaysInstallElevated disabled (HKLM & HKCU)' (("$aieLm" -ne '1') -and ("$aieCu" -ne '1')) ("HKLM=" + $aieLm + " HKCU=" + $aieCu)
    $wdigest = Get-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' 'UseLogonCredential'
    Test-Row 'WDigest plaintext credentials off' ("$wdigest" -eq '0') ("value=" + $wdigest)
    $noAutoUpd = Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate'
    Test-Row 'Automatic Updates on' ("$noAutoUpd" -eq '0') ("NoAutoUpdate=" + $noAutoUpd)
    try {
        $disabledUpdSvcs = @()
        foreach ($uSvcName in @('wuauserv','BITS','UsoSvc','CryptSvc','TrustedInstaller')) {
            $uSvc = Get-Service -Name $uSvcName -ErrorAction SilentlyContinue
            if ($null -ne $uSvc -and $uSvc.StartType -eq 'Disabled') { $disabledUpdSvcs += $uSvcName }
        }
        Test-Row 'Update dependency services not Disabled' ($disabledUpdSvcs.Count -eq 0) ('disabled=' + ($disabledUpdSvcs -join ', '))
    } catch {}
    $appUpdBlocked = @()
    if ("$(Get-RegValue 'HKLM\SOFTWARE\Policies\Google\Update' 'UpdateDefault')" -eq '0') { $appUpdBlocked += 'Chrome:UpdateDefault=0' }
    if ("$(Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate' 'UpdateDefault')" -eq '0') { $appUpdBlocked += 'Edge:UpdateDefault=0' }
    if ("$(Get-RegValue 'HKLM\SOFTWARE\Policies\Mozilla\Firefox' 'DisableAppUpdate')" -eq '1') { $appUpdBlocked += 'Firefox:DisableAppUpdate=1' }
    if ("$(Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' 'AutoDownload')" -eq '2') { $appUpdBlocked += 'Store:AutoDownload=2' }
    if ("$(Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' 'EnableAppInstaller')" -eq '0') { $appUpdBlocked += 'AppInstaller:EnableAppInstaller=0' }
    Test-Row 'App and Store auto-updates not policy-blocked' ($appUpdBlocked.Count -eq 0) ($appUpdBlocked -join ', ')
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
    if (-not $script:IsDC -and (Test-CommandExists 'Get-LocalUser')) {
        try {
            $uList = @(Get-LocalUser -ErrorAction Stop)
            $svcLogons = @(Get-ServiceLogonAccounts)
            $hygieneIssues = @(Get-UserAccountIssues -Users $uList -ServiceLogons $svcLogons -AuthorizedUsers $script:AuthorizedUsers)
            $pwIssues = @($hygieneIssues | Where-Object { $_.PasswordNeverExpires -or $_.CannotChangePassword -or $_.PasswordNotRequired })
            Test-Row 'No non-service local user has PasswordNeverExpires/NoPasswordRequired' ($pwIssues.Count -eq 0) (($pwIssues | Select-Object -ExpandProperty Name) -join ', ')
        } catch {}
    }
    try {
        $pAlerts = @(Get-PersistenceFindings)
        Test-Row 'No IFEO Debugger / abnormal Winlogon / WMI persistence' ($pAlerts.Count -eq 0) (($pAlerts | ForEach-Object { $_.Kind + ':' + $_.Target }) -join ', ')
    } catch {}
    $cfgTmp = Join-Path $env:TEMP ('cp-verify-' + [guid]::NewGuid().ToString('N') + '.cfg')
    try {
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
    finally { Remove-Item -LiteralPath $cfgTmp -Force -ErrorAction SilentlyContinue }
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
    if ($null -ne $script:SuspiciousFilesSummary) {
        $remHigh = [Math]::Max(0, ($script:SuspiciousFilesSummary.Critical + $script:SuspiciousFilesSummary.High - $script:SuspiciousFilesSummary.HighRiskQuarantined))
        $detail = ("Total=" + $script:SuspiciousFilesSummary.Total + " Critical=" + $script:SuspiciousFilesSummary.Critical + " High=" + $script:SuspiciousFilesSummary.High + " Quarantined=" + $script:SuspiciousFilesSummary.HighRiskQuarantined + " RemainingHigh=" + $remHigh)
        Test-Row 'No unreviewed CRITICAL/HIGH executable or archive risks' ($remHigh -eq 0) $detail
    }
    $table = $rows | Format-Table 'Check','State','Detail' -AutoSize | Out-String -Width 250
    Write-Host $table
    Add-Report 'verification.txt' 'Verification table' $table
    Write-Host 'Now compare with the live Scoring Report. Green increases = keep going.'
    Write-Host 'Any DROP right after a step = that step conflicted with the scenario: undo it'
    Write-Host 'first (.\secure.ps1 -Rollback, or re-enable that one service/user/share).'
    Write-Host 'Penalty points come back when the conflicting change is undone.'
}

