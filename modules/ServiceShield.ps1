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

function Set-ScenarioFeatureFlags {
    # A service name or display name is as valid as a scenario keyword.
    $script:FileSharingCritical = (Test-TokenKept @('SMB','FILES','FILE','SHARES')) -or
        (Test-ServiceScenarioKept -Name 'LanmanServer' -DisplayName 'Server')
    $script:RdpCritical = (Test-TokenKept @('RDP','REMOTEDESKTOP','REMOTE DESKTOP','REMOTE')) -or
        (Test-ServiceScenarioKept -Name 'TermService' -DisplayName 'Remote Desktop Services') -or
        (Test-ServiceScenarioKept -Name 'UmRdpService' -DisplayName 'Remote Desktop Services UserMode Port Redirector') -or
        (Test-ServiceScenarioKept -Name 'SessionEnv' -DisplayName 'Remote Desktop Configuration')
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
    if (Confirm-YesNo ("Is " + $Label + " meant to stay on this computer? (Yes = protect it and harden it)") $false) {
        foreach ($n in $liveOnes) { Add-KeptService $n }
        return $true
    }
    return $false
}

function Confirm-CriticalServicesRunning {
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

