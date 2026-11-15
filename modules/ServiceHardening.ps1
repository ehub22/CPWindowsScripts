function Invoke-ServiceHardening {
    Write-Banner 'STEP 9C OF 12 - HARDEN SERVICES THAT MUST STAY (kept services get extra hardening; dependencies are never removed)'
    Write-Host 'Every service the scenario needs stays ON. This step makes each of them'
    Write-Host 'harder to abuse, makes sure they (and everything they depend on) are'
    Write-Host 'running, and reports the few settings that are unsafe to force.'
    if (-not (Confirm-YesNo 'Harden the services that are meant to stay on this computer?' $true)) {
        Write-Step 'Skipped kept-service hardening at your choice.'
        return
    }
    Confirm-CriticalServicesRunning
    $iisBackedUp = $false

    # --- Remote Desktop: additional hardening beyond NLA/TLS ----------------
    try {
        if ($script:RdpCritical -or (Test-ServiceIntended -Label 'Remote Desktop' -ServiceNames @('TermService') -Tokens @('RDP','REMOTEDESKTOP','REMOTE DESKTOP','REMOTE'))) {
            $tsPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            Write-Step 'Remote Desktop stays ON. NLA, TLS and High encryption were set in the previous step.'
            Write-Step 'RDP accounts will be restricted to rdpusers.txt in the user-audit step.'
            if (Confirm-YesNo 'ALSO apply stricter CIS Level-2 Remote Desktop controls? (disables clipboard/drive/COM/LPT/PnP redirection, 15-minute idle disconnect, ends disconnected sessions after 1 minute, one session per user - choose No if users copy files over RDP or leave sessions idle)' $false) {
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
                                if (Confirm-YesNo ("Switch app pool '" + $pool.Name + "' to ApplicationPoolIdentity (least privilege)? Choose No unless you can test the website right after - file/database permissions may need it.") $false) {
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
                } elseif (Confirm-YesNo ("Apply safe global Apache directives (ServerTokens Prod, ServerSignature Off, TraceEnable Off, FileETag None) in " + $aConf + "? The file is backed up, syntax-tested, and auto-restored if the test fails.") $true) {
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
                            if (Confirm-YesNo ("Restart " + $aSvc.Name + " now to apply the Apache settings?") $true) {
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
                        } elseif (Confirm-YesNo ("FTP site '" + $site.Name + "' allows ANONYMOUS logons (no password). Disable anonymous and require a username/password? Choose No only if the README requires public/anonymous FTP.") $true) {
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
                        } elseif (Confirm-YesNo ("DNS zone '" + $zone.ZoneName + "' lets ANY host download the whole zone (AXFR). Restrict zone transfers to servers listed as NS records? (Safe unless an unlisted secondary server pulls this zone.)") $true) {
                            try {
                                Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries 'TransferToZoneNameServer' -Confirm:$false -ErrorAction Stop
                                Write-Good ("DNS zone '" + $zone.ZoneName + "': zone transfers restricted to listed name servers.")
                            } catch { Write-WarnLine ("Could not restrict zone transfers on '" + $zone.ZoneName + "': " + $_.Exception.Message) }
                        }
                    }
                    if ("$($zone.DynamicUpdate)" -eq 'NonsecureAndSecure' -and $zone.IsDsIntegrated -eq $true) {
                        if ($script:AuditOnly -or $script:ApplySafe) {
                            Write-WarnLine ("DNS zone '" + $zone.ZoneName + "' accepts NON-secure dynamic updates. Not changed automatically: non-domain devices (printers, Linux boxes) may rely on it. Re-run in Interactive mode to switch it to secure-only updates.")
                        } elseif (Confirm-YesNo ("DNS zone '" + $zone.ZoneName + "' accepts NON-secure dynamic updates (anyone can register names). Switch to secure-only updates? Only choose Yes if all clients are domain-joined Windows machines.") $false) {
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
                        if (Confirm-YesNo 'Enable DHCP conflict detection (server pings an address once before leasing it)? Slightly slower leases, prevents duplicate IPs.' $false) {
                            Set-DhcpServerSetting -ConflictDetectionAttempts 1 -ErrorAction Stop
                            Write-Good 'DHCP: conflict detection set to 1 attempt.'
                        }
                    }
                } catch {}
                if ($dhcpChanged -and -not $script:AuditOnly) {
                    if (Confirm-YesNo 'Restart the DHCP Server service now so audit logging takes effect? (Seconds-long pause; existing leases are kept.)' $false) {
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
                        if (Confirm-YesNo 'Enable SMB encryption server-wide in TRANSITION mode (encrypts when clients support it, but does NOT reject older unencrypted clients)?' $false) {
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
            } elseif (Confirm-YesNo 'Is printing LOCAL ONLY on this machine (no other computer prints through it)? Yes blocks remote connections to the spooler (strong PrintNightmare mitigation) while local printing keeps working.' $false) {
                $printPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
                [void](Set-RegValue $printPol 'RegisterSpoolerRemoteRpcEndPoint' 2 'DWord' 'Print Spooler refuses remote client connections (local printing only)')
                if (-not $script:AuditOnly) {
                    if (Confirm-YesNo 'Restart the Print Spooler now to activate the remote-connection block?' $true) {
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
                } elseif (Confirm-YesNo 'Apply the safe sshd_config values above? (backup + syntax test + automatic restore on failure; password authentication is NOT touched, so nobody is locked out)' $true) {
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
                            if (Confirm-YesNo 'Restart the sshd service now to apply the SSH settings?' $true) {
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
                            } elseif (Confirm-YesNo ("SNMP community '" + $prop.Name + "' can WRITE (" + $rightsText + "). Reduce it to ReadOnly? Choose No only if the management station truly sets values through SNMP.") $true) {
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
                if (Confirm-YesNo 'Restart the SNMP service now to apply the community-rights change?' $true) {
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
                if (Confirm-YesNo 'Require LDAP signing on this domain controller (LDAPServerIntegrity = 2)? Unsigned LDAP binds will be REJECTED - old apps/devices may break. Choose No unless you have checked the directory service log for unsigned binds.' $false) {
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
                    if (Confirm-YesNo 'SQL Server Browser is running (UDP 1434 helps attackers enumerate instances). Disable it? Choose Yes ONLY if clients connect by fixed IP/port; named-instance discovery by name will stop working.' $false) {
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

