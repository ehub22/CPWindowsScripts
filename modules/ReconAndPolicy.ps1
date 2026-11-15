# ----------------------------------------------------------------------------
# Recon reports (always read-only)
# ----------------------------------------------------------------------------
function Get-InstalledPrograms {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $apps = @()
    $seen = @{}
    foreach ($k in $keys) {
        try {
            $entries = Get-ItemProperty $k -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object 'DisplayName','DisplayVersion','Publisher','UninstallString'
            foreach ($entry in @($entries)) {
                $dedupKey = (([string]$entry.DisplayName).Trim() + '|' + ([string]$entry.DisplayVersion).Trim() + '|' + ([string]$entry.UninstallString).Trim()).ToLower()
                if (-not $seen.ContainsKey($dedupKey)) {
                    $seen[$dedupKey] = $true
                    $apps += $entry
                }
            }
        } catch {}
    }
    return @($apps | Sort-Object DisplayName)
}

function Get-AppxProhibitedPackages {
    param(
        [string[]]$ProhibitedList = @(),
        [object[]]$Packages = $null
    )
    $proh = @($ProhibitedList | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and $_ -ne 'EDIT_ME' })
    if ($proh.Count -eq 0) { return @() }
    $pkgs = $Packages
    if ($null -eq $pkgs) {
        if (-not (Test-CommandExists 'Get-AppxPackage')) { return @() }
        try { $pkgs = @(Get-AppxPackage -AllUsers -ErrorAction Stop) }
        catch {
            try { $pkgs = @(Get-AppxPackage -ErrorAction Stop) } catch { return @() }
        }
    }
    $hits = @()
    foreach ($pkg in @($pkgs)) {
        if ($null -eq $pkg) { continue }
        try { if ([bool]$pkg.IsFramework) { continue } } catch {}
        $sig = ([string]$pkg.SignatureKind)
        if ($sig -eq 'System') { continue }
        $name = [string]$pkg.Name
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $nameLow = $name.ToLower()
        foreach ($bad in $proh) {
            $b = ([string]$bad).Trim()
            if ($b.Length -ge 3 -and $nameLow.Contains($b.ToLower())) {
                $hits += [PSCustomObject]@{
                    Name              = $name
                    Version           = [string]$pkg.Version
                    PackageFullName   = [string]$pkg.PackageFullName
                    Publisher         = [string]$pkg.Publisher
                    MatchedRule       = $b
                }
                break
            }
        }
    }
    return @($hits | Sort-Object Name -Unique)
}

function Get-PersistenceFindings {
    param(
        [object[]]$IfeoEntries = $null,
        [object]$WinlogonInfo = $null,
        [object[]]$WmiFilters = $null
    )
    $alerts = New-Object System.Collections.ArrayList
    $ifeoList = $IfeoEntries
    if ($null -eq $ifeoList) {
        $ifeoList = @()
        $ifeoBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        foreach ($sub in @(Get-ChildItem $ifeoBase -ErrorAction SilentlyContinue)) {
            $dbg = Get-ItemProperty $sub.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue
            if ($null -ne $dbg -and -not [string]::IsNullOrWhiteSpace([string]$dbg.Debugger)) {
                $ifeoList += [PSCustomObject]@{
                    Target   = [string]$sub.PSChildName
                    Debugger = [string]$dbg.Debugger
                    KeyPath  = [string]$sub.PSPath
                }
            }
        }
    }
    foreach ($e in @($ifeoList)) {
        $tgt = [string]$e.Target
        $isAccess = ($tgt -imatch '^(sethc|utilman|osk|narrator|magnify|displayswitch|atbroker)\.exe$')
        [void]$alerts.Add([PSCustomObject]@{
            Kind     = 'IFEODebugger'
            Severity = $(if ($isAccess) { 'CRITICAL' } else { 'HIGH' })
            Target   = $tgt
            Detail   = ('Debugger=' + [string]$e.Debugger)
            KeyPath  = [string]$e.KeyPath
        })
    }

    $wl = $WinlogonInfo
    if ($null -eq $wl) {
        $wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
    }
    if ($null -ne $wl) {
        $shellVal = ([string]$wl.Shell).Trim()
        if (-not [string]::IsNullOrWhiteSpace($shellVal) -and $shellVal -ine 'explorer.exe') {
            [void]$alerts.Add([PSCustomObject]@{
                Kind     = 'WinlogonShell'
                Severity = 'CRITICAL'
                Target   = 'Winlogon\Shell'
                Detail   = ('Shell=' + $shellVal + ' (expected explorer.exe)')
                KeyPath  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            })
        }
        $userinitVal = ([string]$wl.Userinit).Trim()
        if (-not [string]::IsNullOrWhiteSpace($userinitVal)) {
            $parts = @($userinitVal -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($parts.Count -gt 1 -or ($parts.Count -eq 1 -and $parts[0] -notmatch '(?i)(^|\\)userinit\.exe$')) {
                [void]$alerts.Add([PSCustomObject]@{
                    Kind     = 'WinlogonUserinit'
                    Severity = 'HIGH'
                    Target   = 'Winlogon\Userinit'
                    Detail   = ('Userinit=' + $userinitVal)
                    KeyPath  = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                })
            }
        }
    }

    $wmiList = $WmiFilters
    if ($null -eq $wmiList) {
        try {
            $wmiList = @(Get-CimInstance -Namespace 'root\subscription' -ClassName __EventFilter -ErrorAction Stop |
                Select-Object 'Name','Query')
        } catch { $wmiList = @() }
    }
    foreach ($wf in @($wmiList)) {
        if ($null -eq $wf) { continue }
        $wfName = [string]$wf.Name
        if ([string]::IsNullOrWhiteSpace($wfName)) { continue }
        [void]$alerts.Add([PSCustomObject]@{
            Kind     = 'WMIEventFilter'
            Severity = 'HIGH'
            Target   = $wfName
            Detail   = ('Query=' + [string]$wf.Query)
            KeyPath  = 'root\subscription'
        })
    }
    return @($alerts)
}

function Invoke-PersistenceRemediation {
    if ($script:AuditOnly -or $script:ApplySafe) { return }
    $findings = @(Get-PersistenceFindings)
    if ($findings.Count -eq 0) { return }
    Write-Banner 'PERSISTENCE CLEANUP (IFEO Debuggers / Winlogon / WMI)'
    foreach ($f in $findings) {
        Write-WarnLine ("[" + $f.Severity + " " + $f.Kind + "] " + $f.Target + " -> " + $f.Detail)
        if ($f.Kind -eq 'IFEODebugger' -and -not [string]::IsNullOrWhiteSpace($f.KeyPath)) {
            if (Confirm-YesNo ("Remove IFEO Debugger persistence value on '" + $f.Target + "'?") $true) {
                try {
                    Remove-ItemProperty -Path $f.KeyPath -Name 'Debugger' -ErrorAction Stop
                    Write-Good ("Removed IFEO Debugger on " + $f.Target)
                } catch { Write-WarnLine ("Could not remove IFEO Debugger on " + $f.Target + ": " + $_.Exception.Message) }
            }
        } elseif ($f.Kind -eq 'WinlogonShell') {
            if (Confirm-YesNo "Reset Winlogon\Shell back to 'explorer.exe'?" $true) {
                [void](Set-RegValue 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'Shell' 'explorer.exe' 'String' 'Restore default Windows Shell')
            }
        }
    }
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
        $appxProh = @(Get-AppxProhibitedPackages -ProhibitedList $script:ProhibitedSoftware)
        if ($appxProh.Count -gt 0) {
            Add-Report $report 'Prohibited Microsoft Store (Appx/MSIX) apps' ($appxProh | Format-Table 'Name','Version','MatchedRule' -AutoSize | Out-String)
            Write-WarnLine ("Prohibited Store/Appx apps matched: " + (($appxProh | Select-Object -ExpandProperty Name) -join ', '))
        }
    } catch {}
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

    try {
        $persistAlerts = @(Get-PersistenceFindings)
        if ($persistAlerts.Count -gt 0) {
            Add-Report $report 'HIGH-SIGNAL PERSISTENCE ALERTS' ($persistAlerts | Format-Table 'Severity','Kind','Target','Detail' -AutoSize | Out-String)
            foreach ($pa in $persistAlerts) {
                Write-WarnLine ("Persistence alert [" + $pa.Severity + " " + $pa.Kind + "]: " + $pa.Target + " (" + $pa.Detail + ")")
            }
        }
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
    if ($script:ApplySafe) { Write-Step 'Password changes require an interactive run; skipping in ApplySafe.'; return }
    if (-not (Confirm-YesNo 'Change passwords for authorized local users (NOT you, not built-ins, not service accounts)?' $true)) { return }
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
    $uid = [guid]::NewGuid().ToString('N')
    $infPath = Join-Path $env:TEMP ('cp-' + $Label + '-' + $uid + '.inf')
    $dbPath = Join-Path $env:TEMP ('cp-' + $Label + '-' + $uid + '.sdb')
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
    } finally {
        Remove-Item -LiteralPath $infPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $dbPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-AccountPolicy {
    Write-Banner 'STEP 5 OF 12 - PASSWORD + LOCKOUT POLICY (CIS / Microsoft baseline values)'
    $minPwLen = $(if ($null -ne $script:Config) { [int]$script:Config.MinPasswordLength } else { 14 })
    $pwHist = $(if ($null -ne $script:Config) { [int]$script:Config.PasswordHistorySize } else { 24 })
    $maxAge = $(if ($null -ne $script:Config) { [int]$script:Config.MaxPasswordAgeDays } else { 60 })
    $minAge = $(if ($null -ne $script:Config) { [int]$script:Config.MinPasswordAgeDays } else { 1 })
    $lockThresh = $(if ($null -ne $script:Config) { [int]$script:Config.LockoutThreshold } else { 5 })
    $lockDur = $(if ($null -ne $script:Config) { [int]$script:Config.LockoutDurationMin } else { 15 })
    $lockReset = $(if ($null -ne $script:Config) { [int]$script:Config.LockoutResetMin } else { 15 })
    if (-not (Confirm-YesNo ("Apply: min length " + $minPwLen + ", history " + $pwHist + ", max age " + $maxAge + " days, min age " + $minAge + ", lockout " + $lockThresh + "/" + $lockDur + "/" + $lockReset + " ?") $true)) { return }
    if ($script:IsDC) {
        Write-WarnLine 'On a Domain Controller this sets LOCAL policy; the effective domain'
        Write-WarnLine 'password policy lives in the Default Domain Policy GPO. If the score'
        Write-WarnLine 'does not move, set the same values in Group Policy Management.'
    }
    $lines = @(
        '[System Access]',
        ('MinimumPasswordLength = ' + $minPwLen),
        ('PasswordHistorySize = ' + $pwHist),
        ('MaximumPasswordAge = ' + $maxAge),
        ('MinimumPasswordAge = ' + $minAge),
        'PasswordComplexity = 1',
        'ClearTextPassword = 0',
        ('LockoutBadCount = ' + $lockThresh),
        ('LockoutDuration = ' + $lockDur),
        ('ResetLockoutCount = ' + $lockReset),
        'LSAAnonymousNameLookup = 0'
    )
    if ($script:AuditOnly) { Write-Host '[AUDIT] Would apply the account-policy template and the conservative user-rights template (see function Invoke-AccountPolicy / docs).'; return }
    [void](Invoke-SecurityTemplate -Lines $lines -Label 'accountpolicy')
    Write-Step 'Reminder: passwords were changed BEFORE this policy, so nobody is instantly expired.'

    # ---- conservative user-rights subset ----
    if (Confirm-YesNo 'Apply conservative User Rights (deny Guests, strip dangerous privileges, admin-only backup/debug/etc.)?' $true) {
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
    if (-not (Confirm-YesNo 'Apply security options (each value is logged, defaults follow CIS / Microsoft baselines)?' $true)) { return }

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

    $smbAsk = Confirm-YesNo 'Require SMB signing (client and server)? Choose NO only if this machine must talk to a very old non-Windows file device.' $true
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
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Print' 'RpcAuthnLevelPrivacyEnabled' 1 'DWord' 'PrintNightmare RPC privacy authentication required'
    Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 'DWord' 'Prevent MSI elevated installs by standard users (HKLM)'
    Set-RegValue 'HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 0 'DWord' 'Prevent MSI elevated installs by standard users (HKCU)'
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'ProtectionMode' 1 'DWord' ''
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'SafeDllSearchMode' 1 'DWord' ''
    Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' 'CWDIllegalInDllSearch' 1 'DWord' 'Block DLL loading from current working directory'
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
        if (Confirm-YesNo 'Set Data Execution Prevention (DEP) to OptOut (all programs, applies at reboot)?' $true) {
            try { & bcdedit.exe /set '{current}' nx OptOut | Out-Null; Write-Good 'DEP set to OptOut via bcdedit.' }
            catch { Write-WarnLine 'bcdedit DEP change failed.' }
        }
        if (Confirm-YesNo 'Set a logon banner? Only if the README asks for one (you will type the exact text).' $false) {
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
    if (-not (Confirm-YesNo 'Enable Success+Failure auditing for all categories and enlarge the event logs?' $true)) { return }
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
    if (-not (Confirm-YesNo 'Harden Defender (remove planted exclusions, enable cloud/PUA/script scanning, safe ASR)?' $true)) { return }

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
                if (-not $script:ApplySafe) { $confirmed = Confirm-YesNo ("Remove exclusion " + $ex.Kind + ' "' + $ex.Value + '"?') $true }
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
    if (Confirm-YesNo 'Run a Defender QUICK scan now? (Full scans are too slow for a 4-hour round.)' $true) {
        try { Start-MpScan -ScanType QuickScan; Write-Good 'Defender quick scan finished. Check Windows Security > Protection history.' }
        catch { Write-WarnLine 'Quick scan failed to start.' }
    }
}

