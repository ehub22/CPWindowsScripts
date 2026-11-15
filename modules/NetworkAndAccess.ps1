# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
function Test-FirewallPortRisky {
    param(
        [object]$LocalPort,
        [int[]]$RiskyPorts = @(21,22,23,25,53,69,80,110,135,137,138,139,143,443,445,1433,1723,3306,3389,5800,5900,5985,5986,8080)
    )
    $matched = New-Object System.Collections.ArrayList
    $tokens = @()
    foreach ($entry in @($LocalPort)) {
        if ($null -eq $entry) { continue }
        foreach ($piece in (([string]$entry) -split '[,\s]+')) {
            $t = $piece.Trim()
            if ($t) { $tokens += $t }
        }
    }
    foreach ($tok in $tokens) {
        if ($tok -ieq 'Any') {
            if (-not $matched.Contains('Any')) { [void]$matched.Add('Any') }
            continue
        }
        if ($tok -match '^(\d+)-(\d+)$') {
            $lo = [int]$Matches[1]
            $hi = [int]$Matches[2]
            if ($lo -gt $hi) { $tmp = $lo; $lo = $hi; $hi = $tmp }
            foreach ($rp in $RiskyPorts) {
                if ($rp -ge $lo -and $rp -le $hi) {
                    $s = [string]$rp
                    if (-not $matched.Contains($s)) { [void]$matched.Add($s) }
                }
            }
            continue
        }
        $pNum = 0
        if ([int]::TryParse($tok, [ref]$pNum)) {
            if ($RiskyPorts -contains $pNum) {
                $s = [string]$pNum
                if (-not $matched.Contains($s)) { [void]$matched.Add($s) }
            }
        }
    }
    return [PSCustomObject]@{
        IsRisky      = ($matched.Count -gt 0)
        MatchedPorts = @($matched)
        DisplayPort  = ($tokens -join ',')
    }
}

function Get-RiskyInboundFirewallRules {
    param(
        [object[]]$Rules = $null
    )
    $allRules = $Rules
    if ($null -eq $allRules) {
        $allRules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue)
    }
    $hits = @()
    foreach ($rule in @($allRules)) {
        if ($null -eq $rule) { continue }
        try {
            $portSpec = $null
            $prog = ''
            $remote = ''
            if ($rule.PSObject.Properties.Name -contains 'LocalPort') {
                $portSpec = $rule.LocalPort
                $prog = [string]$rule.Program
                $remote = [string]$rule.RemoteAddress
            } else {
                $pf = $rule | Get-NetFirewallPortFilter -ErrorAction Stop
                $portSpec = $pf.LocalPort
                try {
                    $af = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
                    $prog = [string]$af.Program
                } catch {}
                try {
                    $adf = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
                    $remote = (@($adf.RemoteAddress) -join ',')
                } catch {}
            }
            $check = Test-FirewallPortRisky -LocalPort $portSpec
            if (-not $check.IsRisky) { continue }
            $dName = [string]$rule.DisplayName
            if ([string]::IsNullOrWhiteSpace($dName)) { $dName = [string]$rule.Name }
            $keepIt = $false
            foreach ($k in $script:KeepEntries) {
                if ($k.Length -ge 3 -and $dName.ToLower().Contains($k.ToLower())) { $keepIt = $true }
            }
            if ($script:RdpCritical -and ($check.MatchedPorts -contains '3389')) { $keepIt = $true }
            if ((Test-TokenKept @('IIS','WEB','APACHE')) -and (($check.MatchedPorts -contains '80') -or ($check.MatchedPorts -contains '443'))) { $keepIt = $true }
            if ((Test-TokenKept @('FTP')) -and ($check.MatchedPorts -contains '21')) { $keepIt = $true }
            if ((Test-TokenKept @('SSH')) -and ($check.MatchedPorts -contains '22')) { $keepIt = $true }
            if ((Test-TokenKept @('DNS')) -and ($check.MatchedPorts -contains '53')) { $keepIt = $true }
            if ($script:FileSharingCritical -and (($check.MatchedPorts -contains '445') -or ($check.MatchedPorts -contains '139') -or ($check.MatchedPorts -contains '137') -or ($check.MatchedPorts -contains '138'))) { $keepIt = $true }
            if ($dName -match $script:ProtectedPatterns) { $keepIt = $true }
            $hits += [PSCustomObject]@{
                RuleName      = [string]$rule.Name
                Name          = $dName
                Port          = $check.DisplayPort
                MatchedPorts  = ($check.MatchedPorts -join ',')
                Profile       = [string]$rule.Profile
                Program       = $(if ($prog) { $prog } else { 'Any' })
                RemoteAddress = $(if ($remote) { $remote } else { 'Any' })
                KeepCritical  = $keepIt
            }
        } catch {}
    }
    return @($hits)
}

function Invoke-Firewall {
    Write-Banner 'STEP 8 OF 12 - WINDOWS FIREWALL (on, block inbound, ALLOW outbound)'
    if (-not (Confirm-YesNo 'Turn on all firewall profiles with secure defaults and logging?' $true)) { return }
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
        $hits = @(Get-RiskyInboundFirewallRules)
        Add-Report 'firewall.txt' 'Enabled inbound allow rules for risky ports (or Any)' ($hits | Format-Table 'Name','Port','Profile','Program','RemoteAddress','KeepCritical' -AutoSize | Out-String)
        $reviewable = @()
        foreach ($hit in $hits) {
            if ($hit.KeepCritical) {
                Write-Step ("Keeping firewall rule (critical service): " + $hit.Name + ' port ' + $hit.Port)
                continue
            }
            Write-Host ("    Inbound allow: " + $hit.Name + "  port=" + $hit.Port + "  profile=" + $hit.Profile + "  prog=" + $hit.Program + "  remote=" + $hit.RemoteAddress)
            $reviewable += $hit
        }
        if ($reviewable.Count -gt 0 -and -not $script:AuditOnly) {
            if (-not $script:ApplySafe) {
                Write-Host 'Review non-critical risky inbound allow rules one by one (default: Keep unless README prohibits):'
                foreach ($rev in $reviewable) {
                    if ([string]::IsNullOrWhiteSpace($rev.RuleName)) { continue }
                    if (Confirm-YesNo ("  Disable inbound firewall rule '" + $rev.Name + "' (port " + $rev.Port + ', program ' + $rev.Program + ')?') $false) {
                        try {
                            Disable-NetFirewallRule -Name $rev.RuleName -ErrorAction Stop
                            Write-Good ("Disabled inbound firewall rule: " + $rev.Name + " (port " + $rev.Port + ")")
                        } catch { Write-WarnLine ("Could not disable firewall rule " + $rev.Name + ": " + $_.Exception.Message) }
                    }
                }
            }
            if (Confirm-YesNo 'Open Windows Firewall with Advanced Security (wf.msc) now for manual review?' $false) {
                try { Start-Process wf.msc } catch {}
            }
        }
    } catch { Write-WarnLine 'Could not enumerate firewall rules on this system.' }
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
    if (Confirm-YesNo $modeMsg $configReady) {
        foreach ($item in $autoList) {
            $svc = Get-Service -Name $item.Name -ErrorAction SilentlyContinue
            if ($null -eq $svc) { continue }
            if (Test-ServiceKept -Name $svc.Name -DisplayName $svc.DisplayName) {
                Write-Step ("PROTECTED (critical / keep list): " + $svc.Name + " (" + $svc.DisplayName + ")")
                continue
            }
            if (-not $configReady -and -not $script:AuditOnly) {
                if (-not (Confirm-YesNo ("Disable " + $svc.Name + " (" + $svc.DisplayName + ')? ' + $item.Why) $false)) {
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
        if (Confirm-YesNo ("Disable " + $svc.Name + " (" + $svc.DisplayName + ')? ' + $item.Why) $defaultDisable) {
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
                    if (Confirm-YesNo ("Disable Windows feature " + $feat + " (enabled now)? May need a reboot to finish.") $false) {
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
        $rdpRequired = Confirm-YesNo 'Does the README REQUIRE Remote Desktop (RDP) on this machine?' $false
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
                if (Confirm-YesNo 'Disable WinRM (Windows Remote Management) service? Keep it if the scenario manages servers remotely.' (-not $script:IsServer)) {
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
    Write-Banner 'STEP 9D OF 12 - NETWORK PROTOCOLS (SMBv1, LLMNR, NetBIOS, TLS, hosts)'
    if (Confirm-YesNo 'Disable SMBv1 (server + client driver)? It is the WannaCry-era protocol.' $true) {
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
            if (Test-CommandExists 'Get-WindowsOptionalFeature') {
                foreach ($smbFeat in @('SMB1Protocol','FS-SMB1')) {
                    try {
                        $fState = (Get-WindowsOptionalFeature -Online -FeatureName $smbFeat -ErrorAction Stop).State
                        if ("$fState" -eq 'Enabled') {
                            Disable-WindowsOptionalFeature -Online -FeatureName $smbFeat -NoRestart -ErrorAction Stop | Out-Null
                            Write-Good ("Disabled optional feature: " + $smbFeat)
                        }
                    } catch {}
                }
            }
        } else {
            Write-Host '[AUDIT] Would disable SMBv1.'
        }
    }
    if (Confirm-YesNo 'Disable LLMNR and mDNS (multicast name resolution, credential-theft favorites)?' $true) {
        Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 'DWord' 'LLMNR off'
        Set-RegValue 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS' 0 'DWord' 'mDNS off'
    }
    if (Confirm-YesNo 'Disable NetBIOS over TCP/IP on every adapter? Say NO if old-style file sharing / name resolution is critical.' $false) {
        $ifaceBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        foreach ($sub in @(Get-ChildItem $ifaceBase -ErrorAction SilentlyContinue)) {
            Set-RegValue ($sub.Name -replace '^HKEY_LOCAL_MACHINE', 'HKLM') 'NetbiosOptions' 2 'DWord' 'NetBIOS over TCP/IP disabled'
        }
    }
    if (Confirm-YesNo 'Disable SSL 2.0 / SSL 3.0 / TLS 1.0 / TLS 1.1 and require modern .NET crypto (TLS 1.2+ stays on)?' $true) {
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
        if (-not $script:AuditOnly -and (Confirm-YesNo 'Reset the hosts file to the Microsoft default (original is in the backup)?' $false)) {
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
        if ($script:AuditOnly -or $script:ApplySafe) { continue }
        if ($kept) {
            if ($everyoneOpen) {
                if (Confirm-YesNo ("  Share '" + $share.Name + "' is critical but Everyone/Full. Revoke Everyone from it (share itself stays)?") $false) {
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

function Get-UserAccountIssues {
    param(
        [object[]]$Users = @(),
        [string[]]$ServiceLogons = @(),
        [string[]]$AuthorizedUsers = @(),
        [string[]]$SkipBuiltIns = @('Guest','DefaultAccount','WDAGUtilityAccount')
    )
    $issues = New-Object System.Collections.ArrayList
    foreach ($u in @($Users)) {
        if ($null -eq $u -or [string]::IsNullOrWhiteSpace([string]$u.Name)) { continue }
        $uName = [string]$u.Name
        if (Test-NameInList $uName $SkipBuiltIns) { continue }
        if (Test-NameInList $uName $ServiceLogons) { continue }
        if ($AuthorizedUsers.Count -gt 0 -and -not (Test-NameInList $uName $AuthorizedUsers) -and ($uName -ine 'Administrator')) { continue }

        $hasNeverProp = ($u.PSObject.Properties.Name -contains 'PasswordNeverExpires')
        $neverExp = $(if ($hasNeverProp) { [bool]$u.PasswordNeverExpires } else { $null -eq $u.PasswordExpires })
        $hasMayChange = ($u.PSObject.Properties.Name -contains 'UserMayChangePassword')
        $cannotChange = $(if ($hasMayChange) { -not [bool]$u.UserMayChangePassword } else { $false })
        $hasPwReq = ($u.PSObject.Properties.Name -contains 'PasswordRequired')
        $noPwReq = $(if ($hasPwReq) { -not [bool]$u.PasswordRequired } else { $false })
        $isDisabledAuth = (-not [bool]$u.Enabled) -and ($uName -ine 'Administrator')

        if ($neverExp -or $cannotChange -or $noPwReq -or $isDisabledAuth) {
            [void]$issues.Add([PSCustomObject]@{
                Name                  = $uName
                PasswordNeverExpires  = $neverExp
                CannotChangePassword  = $cannotChange
                PasswordNotRequired   = $noPwReq
                DisabledAuthorized    = $isDisabledAuth
            })
        }
    }
    return @($issues)
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
    $acctIssues = @(Get-UserAccountIssues -Users $localUsers -ServiceLogons $serviceLogons -AuthorizedUsers $script:AuthorizedUsers)
    foreach ($ai in $acctIssues) {
        $flags = @()
        if ($ai.PasswordNeverExpires) { $flags += 'PasswordNeverExpires' }
        if ($ai.CannotChangePassword) { $flags += 'UserMayNotChangePassword' }
        if ($ai.PasswordNotRequired)  { $flags += 'PasswordNotRequired' }
        if ($ai.DisabledAuthorized)   { $flags += 'Disabled' }
        Write-WarnLine ("Account hygiene flag on '" + $ai.Name + "': " + ($flags -join ', '))
    }
    if ($script:AuditOnly -or $script:ApplySafe) {
        if ($script:ApplySafe) { Write-Step 'Account and group changes require interactive review; skipping in ApplySafe.' }
        return
    }

    foreach ($ai in $acctIssues) {
        if ($ai.PasswordNeverExpires -or $ai.CannotChangePassword) {
            if (Confirm-YesNo ("Fix password-expiration / user-change flags on authorized user '" + $ai.Name + "'?") $true) {
                try {
                    Set-LocalUser -Name $ai.Name -PasswordNeverExpires:$false -UserMayChangePassword:$true -ErrorAction Stop
                    Write-Good ("Cleared PasswordNeverExpires/UserMayNotChangePassword on " + $ai.Name)
                } catch { Write-WarnLine ("Could not update password flags on " + $ai.Name + ": " + $_.Exception.Message) }
            }
        }
        if ($ai.PasswordNotRequired) {
            if (Confirm-YesNo ("Require a password on authorized user '" + $ai.Name + "' (currently PasswordNotRequired)?") $true) {
                try {
                    & net.exe user $ai.Name /passwordreq:yes 2>$null | Out-Null
                    if ($LASTEXITCODE -eq 0) { Write-Good ("Set PasswordRequired on " + $ai.Name) }
                } catch { Write-WarnLine ("Could not set /passwordreq:yes on " + $ai.Name) }
            }
        }
        if ($ai.DisabledAuthorized) {
            if (Confirm-YesNo ("Enable disabled authorized user '" + $ai.Name + "'?") $false) {
                try { Enable-LocalUser -Name $ai.Name -ErrorAction Stop; Write-Good ("Enabled authorized user " + $ai.Name) }
                catch { Write-WarnLine ("Could not enable " + $ai.Name) }
            }
        }
    }

    foreach ($name in $missing) {
        if (Confirm-YesNo ("Create missing authorized user '" + $name + "'?") $true) {
            try {
                if ($null -ne $script:TeamPassword) {
                    New-LocalUser -Name $name -Password $script:TeamPassword -PasswordNeverExpires:$false -ErrorAction Stop | Out-Null
                } else {
                    Write-WarnLine ("Skipping creation of " + $name + ': no team password was provided.')
                    continue
                }
                Add-LocalGroupMember -Group 'Users' -Member $name -ErrorAction SilentlyContinue
                Write-Good ("Created user " + $name)
            } catch { Write-WarnLine ("Could not create " + $name + ': ' + $_.Exception.Message) }
        }
    }
    foreach ($name in $missingAdmins) {
        if (Confirm-YesNo ("Add '" + $name + "' to Administrators?") $true) {
            try { Add-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction Stop; Write-Good ("Added admin " + $name) }
            catch { Write-WarnLine ("Could not add admin " + $name + ' (does the account exist?)') }
        }
    }
    foreach ($entry in $unauthAdmins) {
        if (Confirm-YesNo ("Remove '" + $entry.Full + "' from Administrators (account itself stays)?") $true) {
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
            if (Confirm-YesNo 'Disable the Guest account?' $true) { Disable-LocalUser -Name 'Guest'; Write-Good 'Guest account disabled.' }
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
                    if (Confirm-YesNo ("Disable the built-in Administrator account (" + $adminAcct.Name + ")? Another admin exists (" + $otherAdmins[0].Full + "). Make sure you KNOW that admin's password first!") $false) {
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
                if (Confirm-YesNo ("Remove '" + $m.Full + "' from Remote Desktop Users?") $true) {
                    try { Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $m.Full; Write-Good ("Removed RDP access for " + $m.Full) } catch {}
                }
            }
        }
        foreach ($want in $script:RdpUsers) {
            $have = Test-NameInList $want @($rdpMembers | Select-Object -ExpandProperty Short)
            if (-not $have) {
                if (Confirm-YesNo ("Add '" + $want + "' to Remote Desktop Users?") $true) {
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
# Current-user password + auto-logon (last, deliberately)
# ----------------------------------------------------------------------------
function Invoke-FinalAccountSafety {
    Write-Banner 'FINAL ACCOUNT SAFETY - your own password + automatic logon'
    $wl = Get-RegValue 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon'
    $hasAutoLogon = ("$wl" -eq '1')
    if ($null -ne $script:TeamPassword) {
        if (Confirm-YesNo ("Set YOUR OWN account (" + $script:CurrentUser + ") to the new team password now? Only say YES if it is written down.") $false) {
            if (Set-UserPasswordSafe -User $script:CurrentUser -Password $script:TeamPassword) {
                Write-Good ("Your password (" + $script:CurrentUser + ") was changed. Lock (Win+L) and unlock NOW to prove it works, before any reboot.")
                Wait-Enter 'Press ENTER after you have tested lock/unlock ...'
                if ($hasAutoLogon) {
                    if (Confirm-YesNo 'Automatic logon is ON for this image (scored as insecure, but convenient). Disable it now that your password is known and tested?' $false) {
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

