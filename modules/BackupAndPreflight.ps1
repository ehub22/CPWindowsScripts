# ----------------------------------------------------------------------------
# Self-elevation helper (shared by Preflight and Rollback)
# ----------------------------------------------------------------------------
function Invoke-SelfElevateIfNeeded {
    if (Test-Admin) { return $true }
    $noElev = ($null -ne $script:Config -and [bool]$script:Config.NoElevate)
    if (-not $noElev) {
        Write-WarnLine 'Not running as Administrator. Relaunching with elevation ...'
        try {
            $entry = $script:EntryScript
            if ([string]::IsNullOrWhiteSpace($entry)) { $entry = Join-Path $script:Root 'secure.ps1' }
            $cfg = $script:Config
            $modeVal = 'Interactive'
            if ($null -ne $cfg -and -not [string]::IsNullOrWhiteSpace($cfg.Mode)) { $modeVal = $cfg.Mode }
            $elevArgs = '-NoProfile -ExecutionPolicy Bypass -File "' + $entry + '" -Mode ' + $modeVal + ' -NoElevate'
            if ($null -ne $cfg) {
                if ($cfg.ForensicsDone) { $elevArgs += ' -ForensicsDone' }
                if ($cfg.ReadmeConfigured) { $elevArgs += ' -ReadmeConfigured' }
                if ($cfg.AutoUpdate) { $elevArgs += ' -AutoUpdate' }
                if ($cfg.SkipWindowsUpdates) { $elevArgs += ' -SkipWindowsUpdates' }
                if ($cfg.ScanFiles) { $elevArgs += ' -ScanFiles' }
                if ($cfg.ShowAIPrompt) { $elevArgs += ' -ShowAIPrompt' }
                if ($cfg.Rollback) { $elevArgs += ' -Rollback' }
                if (-not [string]::IsNullOrWhiteSpace($cfg.RollbackPath)) {
                    $safeRb = ($cfg.RollbackPath -replace '"', '\"')
                    $elevArgs += (' -RollbackPath "' + $safeRb + '"')
                }
                foreach ($name in @('MinPasswordLength','PasswordHistorySize','MaxPasswordAgeDays','MinPasswordAgeDays','LockoutThreshold','LockoutDurationMin','LockoutResetMin')) {
                    $elevArgs += ' -' + $name + ' ' + $cfg.$name
                }
            }
            $waitChild = ($script:ApplySafe -or $script:UpdateOnly -or ($null -ne $cfg -and $cfg.Rollback))
            if ($waitChild) {
                $proc = Start-Process powershell.exe -ArgumentList $elevArgs -WorkingDirectory $script:Root -Verb RunAs -PassThru -Wait
                if ($null -ne $proc) { $script:ElevatedExitCode = [int]$proc.ExitCode }
            } else {
                Start-Process powershell.exe -ArgumentList $elevArgs -WorkingDirectory $script:Root -Verb RunAs | Out-Null
            }
            return $false
        } catch { Write-WarnLine ("Elevation failed: " + $_.Exception.Message) }
    }
    Write-WarnLine 'Please right-click secure.bat and choose "Run as administrator".'
    return $false
}

# ----------------------------------------------------------------------------
# Rollback
# ----------------------------------------------------------------------------
function Invoke-Rollback {
    param([string]$Path)
    Write-Banner 'ROLLBACK - restore a previous backup'
    if (-not (Invoke-SelfElevateIfNeeded)) { return }
    $base = Join-Path $script:Root 'Backups'
    if ([string]::IsNullOrWhiteSpace($Path)) {
        $dirs = @(Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | Where-Object {
            -not (Test-Path (Join-Path $_.FullName 'backup-incomplete')) -and
            (Test-Path (Join-Path $_.FullName 'secedit-backup.cfg')) -and
            (Test-Path (Join-Path $_.FullName 'auditpol-backup.csv')) -and
            (Test-Path (Join-Path $_.FullName 'firewall-backup.wfw')) -and
            (Test-Path (Join-Path $_.FullName 'services-backup.csv'))
        } | Sort-Object Name -Descending)
        if ($dirs.Count -eq 0) { Write-WarnLine 'No backups found.'; return }
        $Path = $dirs[0].FullName
    }
    Write-Step ("Backup folder: " + $Path)
    if (-not (Confirm-YesNo 'Restore from this backup now?' $false)) { return }

    $cfg = Join-Path $Path 'secedit-backup.cfg'
    if (Test-Path $cfg) {
        if (Confirm-YesNo 'Restore account / security policy from backup (secedit)?' $true) {
            $db = Join-Path $env:TEMP ('cp-rollback-' + [guid]::NewGuid().ToString('N') + '.sdb')
            try {
                & secedit.exe /configure /db $db /cfg $cfg /areas SECURITYPOLICY /quiet | Out-Null
                if ($LASTEXITCODE -ne 0) { throw ('secedit exit code ' + $LASTEXITCODE) }
                Write-Good 'Restored security policy from backup.'
            } catch { Write-WarnLine ("secedit restore failed: " + $_.Exception.Message) }
            finally { Remove-Item -LiteralPath $db -Force -ErrorAction SilentlyContinue }
        }
    }
    $audit = Join-Path $Path 'auditpol-backup.csv'
    if (Test-Path $audit) {
        if (Confirm-YesNo 'Restore audit policy from backup (auditpol)?' $true) {
            try { & auditpol.exe /restore "/file:$audit" | Out-Null; if ($LASTEXITCODE -ne 0) { throw ('auditpol exit code ' + $LASTEXITCODE) }; Write-Good 'Restored audit policy from backup.' }
            catch { Write-WarnLine ("auditpol restore failed: " + $_.Exception.Message) }
        }
    }
    $fw = Join-Path $Path 'firewall-backup.wfw'
    if (Test-Path $fw) {
        if (Confirm-YesNo 'Restore Windows Firewall policy from backup?' $true) {
            try { & netsh.exe advfirewall import $fw | Out-Null; if ($LASTEXITCODE -ne 0) { throw ('netsh exit code ' + $LASTEXITCODE) }; Write-Good 'Restored firewall policy from backup.' }
            catch { Write-WarnLine ("Firewall restore failed: " + $_.Exception.Message) }
        }
    }
    $svcCsv = Join-Path $Path 'services-backup.csv'
    if (Test-Path $svcCsv) {
        if (Confirm-YesNo 'Restore original service start types from backup?' $true) {
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
        if (Confirm-YesNo ("Import registry backup " + $reg.Name + '?') $false) {
            try { & reg.exe import $reg.FullName | Out-Null; if ($LASTEXITCODE -ne 0) { throw ('reg exit code ' + $LASTEXITCODE) }; Write-Good ("Imported " + $reg.Name) }
            catch { Write-WarnLine ("Registry import failed for " + $reg.Name) }
        }
    }
    $hostsBak = Join-Path $Path 'hosts-backup'
    if (Test-Path $hostsBak) {
        if (Confirm-YesNo 'Restore the hosts file from backup?' $false) {
            try {
                Copy-Item $hostsBak (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') -Force
                Write-Good 'Restored hosts file.'
            } catch { Write-WarnLine 'Hosts restore failed.' }
        }
    }
    $defBak = Join-Path $Path 'defender-exclusions.json'
    if ((Test-Path $defBak) -and (Test-CommandExists 'Add-MpPreference')) {
        if (Confirm-YesNo 'Restore Defender exclusions recorded before hardening?' $false) {
            try {
                $defData = Get-Content -LiteralPath $defBak -Raw | ConvertFrom-Json
                foreach ($p in @($defData.ExclusionPath)) { if ($p) { Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue } }
                foreach ($p in @($defData.ExclusionProcess)) { if ($p) { Add-MpPreference -ExclusionProcess $p -ErrorAction SilentlyContinue } }
                foreach ($p in @($defData.ExclusionExtension)) { if ($p) { Add-MpPreference -ExclusionExtension $p -ErrorAction SilentlyContinue } }
                Write-Good 'Restored saved Defender exclusions.'
            } catch { Write-WarnLine 'Could not restore Defender exclusions.' }
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
    if (-not (Invoke-SelfElevateIfNeeded)) { return $false }
    Write-Good 'Running as Administrator.'

    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $script:OSCaption = $os.Caption
        $build = $os.BuildNumber
        $productType = $os.ProductType  # 1=workstation, 2=domain controller, 3=server
        if ($productType -notin @(1,2,3)) { throw 'Unknown Windows product type.' }
        $script:IsServer = ($productType -ne 1)
        if ($productType -eq 2) { $script:IsDC = $true }
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
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
    } catch { Write-WarnLine 'Could not detect the OS role safely; stopping before hardening.'; return $false }

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
    $updCfg = Get-UpdateConfig (Join-Path $script:Root 'necessary_apps.txt')
    $script:NecessaryApps = @($updCfg.Necessary)
    $script:ExcludedFromUpdates = @($updCfg.Excluded)
    $script:ProhibitedSoftware = @(Get-TextList (Join-Path $script:Root 'prohibited_software.txt') | Where-Object { $_ -ne 'EDIT_ME' })
    Set-ScenarioFeatureFlags

    if ($script:AuditOnly) {
        Write-Step 'Mode = Audit: every module runs as a read-only dry-run; nothing is changed.'
        return $true
    }
    if ($script:UpdateOnly) {
        Write-Step 'Mode = Update: auto-updating necessary apps and dependencies (no user, firewall, or policy hardening).'
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

    $forensicsDoneFlag = ($null -ne $script:Config -and [bool]$script:Config.ForensicsDone)
    if (-not $forensicsDoneFlag) {
        if (-not (Confirm-YesNo 'Have you finished ALL Forensic Questions (and seen the points)?' $false)) {
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
    if ($unedited.Count -gt 0) {
        Write-WarnLine ("Missing, unreadable, or unedited configuration: " + ($unedited -join ', '))
        Write-WarnLine 'Complete these files before applying changes; -ReadmeConfigured does not bypass the file checks.'
        return $false
    }

    $script:KeepEntries = @(Get-TextList $keepFile | Where-Object { $_ -ne 'EDIT_ME' })
    $script:AuthorizedUsers = @(Get-TextList $usersFile | Where-Object { $_ -ne 'EDIT_ME' })
    $script:AuthorizedAdmins = @(Get-TextList $adminsFile | Where-Object { $_ -ne 'EDIT_ME' })
    $script:RdpUsers = @(Get-TextList (Join-Path $script:Root 'rdpusers.txt') | Where-Object { $_ -ne 'EDIT_ME' })
    Set-ScenarioFeatureFlags
    foreach ($adm in $script:AuthorizedAdmins) {
        if ($adm -ine 'Administrator' -and -not ($script:AuthorizedUsers | Where-Object { $_ -ieq $adm })) {
            Write-WarnLine ("admins.txt lists '" + $adm + "', which is not in authorizedusers.txt - review both lists.")
        }
    }
    foreach ($ru in $script:RdpUsers) {
        if ($ru -ine 'Administrator' -and -not ($script:AuthorizedUsers | Where-Object { $_ -ieq $ru })) {
            Write-WarnLine ("rdpusers.txt lists '" + $ru + "', which is not in authorizedusers.txt - review both lists.")
        }
    }
    Write-Step ("Critical-service entries loaded: " + ($script:KeepEntries -join ', '))
    if ($script:FileSharingCritical) { Write-Step 'File sharing (SMB) is marked critical - server service and shares are protected.' }
    if ($script:RdpCritical) { Write-Step 'Remote Desktop is marked critical - it will be SECURED, not disabled.' }
    return $true
}


# ----------------------------------------------------------------------------
# Backup
# ----------------------------------------------------------------------------
function Invoke-Backup {
    if ($script:AuditOnly) { return }
    Write-Banner 'STEP 2 OF 12 - BACKUP (core system state)'
    New-Item -ItemType Directory -Path $script:BackupDir -Force -ErrorAction Stop | Out-Null
    Write-Step ("Backup folder: " + $script:BackupDir)
    $incomplete = Join-Path $script:BackupDir 'backup-incomplete'
    Set-Content -LiteralPath $incomplete -Value 'Backup in progress' -ErrorAction Stop
    # Native executables do not throw on nonzero exit codes in Windows PowerShell.
    # Never proceed with changes if any of the core exports failed.
    $cfgFile = Join-Path $script:BackupDir 'secedit-backup.cfg'
    & secedit.exe /export /cfg $cfgFile /quiet | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $cfgFile)) { throw 'Security policy backup failed.' }
    $auditFile = Join-Path $script:BackupDir 'auditpol-backup.csv'
    & auditpol.exe /backup "/file:$auditFile" | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $auditFile)) { throw 'Audit policy backup failed.' }
    $firewallFile = Join-Path $script:BackupDir 'firewall-backup.wfw'
    & netsh.exe advfirewall export $firewallFile | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $firewallFile)) { throw 'Firewall backup failed.' }
    $servicesFile = Join-Path $script:BackupDir 'services-backup.csv'
    $services = @(Get-Service -ErrorAction Stop | Select-Object 'Name','DisplayName','Status','StartType')
    if ($services.Count -eq 0) { throw 'Service inventory is empty; backup failed.' }
    $services | Export-Csv $servicesFile -NoTypeInformation -ErrorAction Stop
    Export-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows' (Join-Path $script:BackupDir 'reg-policies-windows.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' (Join-Path $script:BackupDir 'reg-lsa.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' (Join-Path $script:BackupDir 'reg-lanmanserver.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' (Join-Path $script:BackupDir 'reg-lanmanworkstation.reg')
    Export-RegKey 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' (Join-Path $script:BackupDir 'reg-policies-system.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' (Join-Path $script:BackupDir 'reg-schannel.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' (Join-Path $script:BackupDir 'reg-terminalserver.reg')
    Export-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' (Join-Path $script:BackupDir 'reg-policies-ts.reg')
    Export-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' (Join-Path $script:BackupDir 'reg-policies-dnsclient.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' (Join-Path $script:BackupDir 'reg-dnscache.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' (Join-Path $script:BackupDir 'reg-netbt-interfaces.reg')
    Export-RegKey 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' (Join-Path $script:BackupDir 'reg-winlogon.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' (Join-Path $script:BackupDir 'reg-sessionmanager.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Services\CDROM' (Join-Path $script:BackupDir 'reg-cdrom.reg')
    Export-RegKey 'HKLM\SYSTEM\CurrentControlSet\Control\Print' (Join-Path $script:BackupDir 'reg-print.reg')
    Export-RegKey 'HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' (Join-Path $script:BackupDir 'reg-dotnet64.reg')
    Export-RegKey 'HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' (Join-Path $script:BackupDir 'reg-dotnet32.reg')
    if (Test-CommandExists 'Get-MpPreference') {
        try {
            $mpPref = Get-MpPreference -ErrorAction Stop
            [PSCustomObject]@{
                ExclusionPath      = @($mpPref.ExclusionPath)
                ExclusionProcess   = @($mpPref.ExclusionProcess)
                ExclusionExtension = @($mpPref.ExclusionExtension)
            } | ConvertTo-Json -Depth 3 | Out-File (Join-Path $script:BackupDir 'defender-exclusions.json') -Encoding ascii -Force
        } catch {}
    }
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
    Remove-Item -LiteralPath $incomplete -ErrorAction Stop
    Write-Good 'Core backups complete. Rollback is partial; retain a VM snapshot and review the recovery guidance.'
}

