# ----------------------------------------------------------------------------
# Running-process triage: possible backdoors / malware
# ----------------------------------------------------------------------------
function Invoke-ProcessTriage {
    Write-Banner 'STEP 7B OF 12 - RUNNING-PROCESS TRIAGE (possible backdoors / malware)'
    Write-Host 'This is evidence-based triage, not a magical malware oracle. It combines'
    Write-Host 'Defender detections, executable path, signature, command line, parent,'
    Write-Host 'network exposure, persistence and service hosting. It never kills a'
    Write-Host 'protected, core, scoring, antivirus, VM-tools, or service-hosted process'
    Write-Host 'directly. A lone suspicious service is handled through the existing'
    Write-Host 'dependency-checked service path instead of killing its host process.'
    if (-not (Confirm-YesNo 'Triage running processes for backdoors or malware?' $true)) {
        Write-Step 'Skipped running-process triage at your choice.'
        return
    }

    function Test-PublicAddress {
        param([string]$Address)
        if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
        $a = $Address.Trim().ToLower()
        if ($a -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$') {
            $one = [int]$Matches[1]
            $two = [int]$Matches[2]
            if ($one -eq 0 -or $one -eq 10 -or $one -eq 127 -or $one -ge 224) { return $false }
            if ($one -eq 169 -and $two -eq 254) { return $false }
            if ($one -eq 172 -and $two -ge 16 -and $two -le 31) { return $false }
            if ($one -eq 192 -and $two -eq 168) { return $false }
            if ($one -eq 100 -and $two -ge 64 -and $two -le 127) { return $false }
            return $true
        }
        if ($a -eq '::' -or $a -eq '::1') { return $false }
        if ($a.StartsWith('fc') -or $a.StartsWith('fd') -or $a.StartsWith('ff') -or $a.StartsWith('fe8') -or $a.StartsWith('fe9') -or $a.StartsWith('fea') -or $a.StartsWith('feb')) { return $false }
        return ($a.Contains(':'))
    }

    function Add-TriageReason {
        param([object]$Candidate, [int]$Points, [string]$Reason)
        $Candidate.Score = $Candidate.Score + $Points
        [void]$Candidate.Reasons.Add($Reason)
    }

    function Stop-TriageProcess {
        param([object]$Candidate)
        $target = $null
        try { $target = Get-CimInstance Win32_Process -Filter ("ProcessId=" + $Candidate.ProcessId) -ErrorAction Stop } catch {}
        if ($null -eq $target) {
            $Candidate.ActionTaken = 'Process had already exited before containment'
            return $true
        }
        $freshPath = [string]$target.ExecutablePath
        if (-not [string]::IsNullOrWhiteSpace($Candidate.Path) -and -not [string]::IsNullOrWhiteSpace($freshPath) -and $freshPath -ine $Candidate.Path) {
            Write-WarnLine ("Not stopping PID " + $Candidate.ProcessId + ": its executable path changed, so the PID may have been reused.")
            $Candidate.ActionTaken = 'Not stopped: PID/path changed during triage'
            return $false
        }
        $live = $null
        try { $live = Get-Process -Id $Candidate.ProcessId -ErrorAction Stop } catch {}
        if ($null -eq $live) {
            $Candidate.ActionTaken = 'Process had already exited before containment'
            return $true
        }
        try {
            if ($live.MainWindowHandle -ne 0) {
                [void]$live.CloseMainWindow()
                try { [void]$live.WaitForExit(3000) } catch {}
                $live.Refresh()
                if ($live.HasExited) {
                    $Candidate.ActionTaken = 'Closed normally through its main window'
                    return $true
                }
            }
        } catch {}
        try {
            Stop-Process -Id $Candidate.ProcessId -Force -Confirm:$false -ErrorAction Stop
            try { [void]$live.WaitForExit(3000) } catch {}
            $stillThere = Get-Process -Id $Candidate.ProcessId -ErrorAction SilentlyContinue
            if ($null -eq $stillThere) {
                $Candidate.ActionTaken = 'Stopped (exact PID only; children were not bulk-killed)'
                return $true
            }
            $Candidate.ActionTaken = 'Stop requested but the process was still present'
            return $false
        } catch {
            if ($null -eq (Get-Process -Id $Candidate.ProcessId -ErrorAction SilentlyContinue)) {
                $Candidate.ActionTaken = 'Process exited during containment'
                return $true
            }
            Write-WarnLine ("Could not stop PID " + $Candidate.ProcessId + " (" + $Candidate.Name + "): " + $_.Exception.Message)
            $Candidate.ActionTaken = 'Stop failed: ' + $_.Exception.Message
            return $false
        }
    }

    $allProcesses = @()
    try { $allProcesses = @(Get-CimInstance Win32_Process -ErrorAction Stop) }
    catch {
        Write-WarnLine 'Could not enumerate Win32_Process, so process triage cannot run safely.'
        return
    }

    Initialize-ServiceGraph
    Update-KeptDependencyClosure

    $procById = @{}
    $childCountByPid = @{}
    foreach ($p in $allProcesses) {
        try { $procById[[int]$p.ProcessId] = $p } catch {}
        try {
            $parentId = [int]$p.ParentProcessId
            if (-not $childCountByPid.ContainsKey($parentId)) { $childCountByPid[$parentId] = 0 }
            $childCountByPid[$parentId] = $childCountByPid[$parentId] + 1
        } catch {}
    }

    # Protect this script, every ancestor, and every descendant of it.
    $protectedPids = @{}
    $protectedPids[[int]$PID] = $true
    $cursor = $PID
    $guard = 0
    while ($procById.ContainsKey([int]$cursor) -and $guard -lt 32) {
        $guard++
        $parentId = 0
        try { $parentId = [int]$procById[[int]$cursor].ParentProcessId } catch {}
        if ($parentId -le 0 -or $protectedPids.ContainsKey($parentId)) { break }
        $protectedPids[$parentId] = $true
        $cursor = $parentId
    }
    $changed = $true
    while ($changed) {
        $changed = $false
        foreach ($p in $allProcesses) {
            try {
                if ($protectedPids.ContainsKey([int]$p.ParentProcessId) -and -not $protectedPids.ContainsKey([int]$p.ProcessId)) {
                    $protectedPids[[int]$p.ProcessId] = $true
                    $changed = $true
                }
            } catch {}
        }
    }

    # Map service-host processes. Kept/dependency closure membership means a
    # host can never be killed directly; a lone non-kept service can later be
    # stopped only through Disable-ServiceSafe.
    $servicesByPid = @{}
    $keptServicePids = @{}
    try {
        foreach ($svc in @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)) {
            $svcPid = 0
            try { $svcPid = [int]$svc.ProcessId } catch {}
            if ($svcPid -le 0) { continue }
            if (-not $servicesByPid.ContainsKey($svcPid)) { $servicesByPid[$svcPid] = New-Object System.Collections.ArrayList }
            [void]$servicesByPid[$svcPid].Add([string]$svc.Name)
            if ($script:KeptClosureLower.ContainsKey(([string]$svc.Name).ToLower())) { $keptServicePids[$svcPid] = $true }
            if ([string]$svc.Name -match $script:ProtectedPatterns -or [string]$svc.DisplayName -match $script:ProtectedPatterns) { $keptServicePids[$svcPid] = $true }
        }
    } catch {}

    $networkByPid = @{}
    try {
        $connections = @()
        try { $connections += @(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' }) } catch {}
        foreach ($conn in $connections) {
            $owner = 0
            try { $owner = [int]$conn.OwningProcess } catch {}
            if ($owner -le 0) { continue }
            if (-not $networkByPid.ContainsKey($owner)) {
                $networkByPid[$owner] = @{
                    Listen = New-Object System.Collections.ArrayList
                    Established = New-Object System.Collections.ArrayList
                    ListenExposed = $false
                    RemotePublic = $false
                }
            }
            $entry = $networkByPid[$owner]
            if ($conn.State -eq 'Listen') {
                $label = ('TCP ' + $conn.LocalAddress + ':' + $conn.LocalPort + ' LISTEN')
                if (-not $entry.Listen.Contains($label)) { [void]$entry.Listen.Add($label) }
                if ("$($conn.LocalAddress)" -notin @('127.0.0.1','::1')) { $entry.ListenExposed = $true }
            } else {
                $label = ('TCP ' + $conn.LocalAddress + ':' + $conn.LocalPort + ' -> ' + $conn.RemoteAddress + ':' + $conn.RemotePort)
                if (-not $entry.Established.Contains($label)) { [void]$entry.Established.Add($label) }
                if (Test-PublicAddress ([string]$conn.RemoteAddress)) { $entry.RemotePublic = $true }
            }
        }
        try {
            foreach ($udp in @(Get-NetUDPEndpoint -ErrorAction Stop)) {
                $owner = 0
                try { $owner = [int]$udp.OwningProcess } catch {}
                if ($owner -le 0) { continue }
                if (-not $networkByPid.ContainsKey($owner)) {
                    $networkByPid[$owner] = @{
                        Listen = New-Object System.Collections.ArrayList
                        Established = New-Object System.Collections.ArrayList
                        ListenExposed = $false
                        RemotePublic = $false
                    }
                }
                $entry = $networkByPid[$owner]
                $label = ('UDP ' + $udp.LocalAddress + ':' + $udp.LocalPort)
                if (-not $entry.Listen.Contains($label)) { [void]$entry.Listen.Add($label) }
                if ("$($udp.LocalAddress)" -notin @('127.0.0.1','::1')) { $entry.ListenExposed = $true }
            }
        } catch {}
    } catch {}

    # Exact-path persistence references from Run keys and scheduled tasks.
    # This is evidence only; persistence entries are never edited here.
    $persistLines = New-Object System.Collections.ArrayList
    foreach ($rk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce')) {
        try {
            $props = Get-ItemProperty $rk -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -notmatch '^PS') { [void]$persistLines.Add(([string]$prop.Value).ToLower()) }
            }
        } catch {}
    }
    if (Test-CommandExists 'Get-ScheduledTask') {
        try {
            foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
                foreach ($action in @($task.Actions)) {
                    $line = ''
                    try { $line = (([string]$action.Execute) + ' ' + ([string]$action.Arguments)).ToLower() } catch {}
                    if (-not [string]::IsNullOrWhiteSpace($line)) { [void]$persistLines.Add($line) }
                }
            }
        } catch {}
    }
    $persistenceBlob = ($persistLines -join "`r`n")

    # Active Defender verdicts are the strongest evidence. Historical
    # detections alone are deliberately not treated as current process proof.
    $activeThreats = @()
    $activeThreatIds = @{}
    if (Test-CommandExists 'Get-MpThreat') {
        try {
            foreach ($threat in @(Get-MpThreat -ErrorAction Stop)) {
                if ([bool]$threat.IsActive) {
                    $activeThreats += $threat
                    $activeThreatIds["$($threat.ThreatID)"] = $threat
                }
            }
        } catch {}
    }
    $detectionThreatByPath = @{}
    if ((Test-CommandExists 'Get-MpThreatDetection') -and $activeThreatIds.Count -gt 0) {
        try {
            foreach ($detection in @(Get-MpThreatDetection -ErrorAction Stop)) {
                $tid = "$($detection.ThreatID)"
                if (-not $activeThreatIds.ContainsKey($tid)) { continue }
                $procPath = ([string]$detection.ProcessName).Trim().ToLower()
                if (-not [string]::IsNullOrWhiteSpace($procPath) -and $procPath -ne 'unknown') {
                    $detectionThreatByPath[$procPath] = $activeThreatIds[$tid]
                }
                foreach ($resource in @($detection.Resources)) {
                    $resText = ([string]$resource).ToLower()
                    if ($resText.StartsWith('file:_')) { $detectionThreatByPath[$resText.Substring(6)] = $activeThreatIds[$tid] }
                    if ($resText.StartsWith('containerfile:_')) { $detectionThreatByPath[$resText.Substring(15)] = $activeThreatIds[$tid] }
                }
            }
        } catch {}
    }

    $pfLower = ([string]$env:ProgramFiles).TrimEnd('\').ToLower()
    $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $pf86Lower = ''
    if ($pf86) { $pf86Lower = ([string]$pf86).TrimEnd('\').ToLower() }
    $usersLower = 'c:\users\'
    $programDataLower = ([string]$env:ProgramData).TrimEnd('\').ToLower()
    $rootLower = ($script:Root.TrimEnd('\')).ToLower()
    $coreNames = @('system','system idle process','registry','secure system','memory compression')
    $expectedSystem = @{
        'svchost.exe' = @('\windows\system32\svchost.exe','\windows\syswow64\svchost.exe')
        'lsass.exe' = @('\windows\system32\lsass.exe')
        'csrss.exe' = @('\windows\system32\csrss.exe')
        'winlogon.exe' = @('\windows\system32\winlogon.exe')
        'services.exe' = @('\windows\system32\services.exe')
        'smss.exe' = @('\windows\system32\smss.exe')
        'wininit.exe' = @('\windows\system32\wininit.exe')
        'spoolsv.exe' = @('\windows\system32\spoolsv.exe')
        'conhost.exe' = @('\windows\system32\conhost.exe')
        'dllhost.exe' = @('\windows\system32\dllhost.exe','\windows\syswow64\dllhost.exe')
        'explorer.exe' = @('\windows\explorer.exe')
        'dwm.exe' = @('\windows\system32\dwm.exe')
        'runtimebroker.exe' = @('\windows\system32\runtimebroker.exe')
        'taskhostw.exe' = @('\windows\system32\taskhostw.exe')
        'ctfmon.exe' = @('\windows\system32\ctfmon.exe')
        'fontdrvhost.exe' = @('\windows\system32\fontdrvhost.exe')
        'wudfhost.exe' = @('\windows\system32\wudfhost.exe')
    }
    $lolBins = @('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe','curl.exe','wget.exe')
    $officeBrowserParents = @('winword.exe','excel.exe','powerpnt.exe','outlook.exe','msaccess.exe','visio.exe','acrobat.exe','acrord32.exe','chrome.exe','firefox.exe','msedge.exe','iexplore.exe')
    $signatureCache = @{}
    $candidates = @()

    foreach ($p in $allProcesses) {
        $processId = 0
        try { $processId = [int]$p.ProcessId } catch {}
        if ($processId -le 4) { continue }
        $name = [string]$p.Name
        $nameLower = $name.ToLower()
        if ($coreNames -icontains $nameLower) { continue }
        if ($protectedPids.ContainsKey($processId)) { continue }

        $path = [string]$p.ExecutablePath
        if ($path.StartsWith('\??\')) { $path = $path.Substring(4) }
        if ([string]::IsNullOrWhiteSpace($path) -or $path.StartsWith('\Device\')) {
            try {
                $gp = Get-Process -Id $processId -ErrorAction Stop
                $fallbackPath = [string]$gp.Path
                if (-not [string]::IsNullOrWhiteSpace($fallbackPath)) { $path = $fallbackPath }
            } catch {}
        }
        if (-not [string]::IsNullOrWhiteSpace($path)) { $path = [Environment]::ExpandEnvironmentVariables($path) }
        $pathLower = ''
        if ($path) { $pathLower = ($path -replace '/', '\').ToLower() }
        $commandLine = [string]$p.CommandLine
        $parentId = 0
        try { $parentId = [int]$p.ParentProcessId } catch {}
        $parent = $null
        if ($procById.ContainsKey($parentId)) { $parent = $procById[$parentId] }
        $parentName = ''
        if ($null -ne $parent) { $parentName = [string]$parent.Name }

        $serviceNames = @()
        if ($servicesByPid.ContainsKey($processId)) { $serviceNames = @($servicesByPid[$processId]) }
        $protectedReason = ''
        if ($keptServicePids.ContainsKey($processId)) { $protectedReason = 'Hosts a kept/protected service' }
        if ($pathLower -and $pathLower.StartsWith($rootLower)) { $protectedReason = 'Runs from this script folder' }
        if ($pathLower -match '\\cyberpatriot\\') { $protectedReason = 'CyberPatriot scoring path' }
        if ($name -match $script:ProtectedPatterns -or $path -match $script:ProtectedPatterns) { $protectedReason = 'Scoring/VM/protected process pattern' }
        if ($nameLower -in @('msmpeng.exe','nissrv.exe','mpdefendercoreservice.exe','securityhealthservice.exe','securityhealthsystray.exe','mssense.exe')) { $protectedReason = 'Microsoft Defender process' }

        $ancestorId = $parentId
        $ancestorGuard = 0
        while ($ancestorId -gt 0 -and $procById.ContainsKey($ancestorId) -and $ancestorGuard -lt 16) {
            $ancestorGuard++
            if ($keptServicePids.ContainsKey($ancestorId)) {
                $protectedReason = 'Descendant of a kept-service host process'
                break
            }
            try { $ancestorId = [int]$procById[$ancestorId].ParentProcessId } catch { $ancestorId = 0 }
        }

        $candidate = [PSCustomObject]@{
            ProcessId = $processId
            Name = $name
            ParentProcessId = $parentId
            ParentName = $parentName
            Path = $path
            CommandLine = $commandLine
            Created = "$($p.CreationDate)"
            Score = 0
            Level = 'Review'
            DefenderThreat = ''
            DefenderConfirmed = $false
            SignatureStatus = 'Not checked'
            Signer = ''
            Company = ''
            SHA256 = ''
            Services = ($serviceNames -join ', ')
            Network = ''
            ProtectedReason = $protectedReason
            ServiceManaged = ($serviceNames.Count -gt 0)
            ChildCount = 0
            HasMainWindow = $false
            Reasons = (New-Object System.Collections.ArrayList)
            Notes = (New-Object System.Collections.ArrayList)
            ActionTaken = 'Reported only'
        }
        if ($childCountByPid.ContainsKey($processId)) { $candidate.ChildCount = [int]$childCountByPid[$processId] }
        try {
            $gp2 = Get-Process -Id $processId -ErrorAction Stop
            if ($gp2.MainWindowHandle -ne 0) { $candidate.HasMainWindow = $true }
        } catch {}

        $matchedThreat = $null
        if ($pathLower -and $detectionThreatByPath.ContainsKey($pathLower)) { $matchedThreat = $detectionThreatByPath[$pathLower] }
        if ($null -eq $matchedThreat -and $pathLower) {
            foreach ($threat in $activeThreats) {
                foreach ($resource in @($threat.Resources)) {
                    $resLower = ([string]$resource).ToLower()
                    if ($resLower.Contains($pathLower)) { $matchedThreat = $threat; break }
                }
                if ($null -ne $matchedThreat) { break }
            }
        }
        if ($null -ne $matchedThreat) {
            $candidate.DefenderThreat = [string]$matchedThreat.ThreatName
            if ($candidate.DefenderThreat -like 'PUA:*') {
                Add-TriageReason $candidate 45 ("Defender has an ACTIVE PUA detection for this exact process path: " + $candidate.DefenderThreat)
            } else {
                $candidate.DefenderConfirmed = $true
                Add-TriageReason $candidate 100 ("Defender has an ACTIVE threat detection for this exact process path: " + $candidate.DefenderThreat)
            }
        }

        $systemImpersonation = $false
        if ($pathLower -and $expectedSystem.ContainsKey($nameLower)) {
            $pathExpected = $false
            foreach ($fragment in @($expectedSystem[$nameLower])) {
                if ($pathLower.EndsWith($fragment)) { $pathExpected = $true }
            }
            if (-not $pathExpected) {
                $systemImpersonation = $true
                Add-TriageReason $candidate 70 ("Uses a Windows system-process name but runs from an unexpected path: " + $path)
            }
        }

        if ($nameLower -match '^(nc|ncat|netcat|mimikatz|sekurlsa|psexec|psexecsvc|psexesvc|meterpreter|beacon|gsecdump|pwdump|sharphound|rubeus|procdump)(\d*)?\.exe$') {
            Add-TriageReason $candidate 35 'Executable name matches a remote-shell, credential-theft, or post-exploitation tool'
        }

        $highRiskPath = $false
        $userWritablePath = $false
        if ($pathLower) {
            if ($pathLower.StartsWith($usersLower)) { $userWritablePath = $true }
            if ($pathLower.StartsWith($programDataLower) -and $pathLower -notmatch '\\microsoft\\windows defender\\') { $userWritablePath = $true }
            if ($pathLower -match '\\appdata\\|\\temp\\|\\tmp\\|\\downloads\\|\\desktop\\|\\\$recycle\.bin\\') { $highRiskPath = $true }
            if ($pathLower -match '^[a-z]:\\[^\\]+\.exe$') { $highRiskPath = $true }
            if ($highRiskPath) {
                Add-TriageReason $candidate 30 'Executable runs from Temp/Downloads/Desktop/Recycle Bin or a drive root'
            } elseif ($userWritablePath) {
                Add-TriageReason $candidate 22 'Executable runs from a user-writable profile or ProgramData path'
            }
            if ($pathLower.StartsWith('\\')) {
                Add-TriageReason $candidate 20 'Executable runs from a network/UNC path'
            }
            if (-not (Test-Path -LiteralPath $path)) {
                Add-TriageReason $candidate 25 'Executable file is missing or inaccessible while the process is running'
            }
        } elseif ($networkByPid.ContainsKey($processId)) {
            Add-TriageReason $candidate 15 'Process has network activity but its executable path could not be read'
        }

        $strongCommand = $false
        $cmdLower = $commandLine.ToLower()
        if (($lolBins -icontains $nameLower) -and $cmdLower) {
            if ($cmdLower -match '(-enc(\s|:|$)|-encodedcommand|frombase64string|downloadstring|downloadfile|invoke-expression|javascript:|vbscript:|https?://|\\appdata\\|\\temp\\|\\downloads\\)') {
                $strongCommand = $true
                Add-TriageReason $candidate 38 'Built-in command/script host has an encoded, download, web, or user-writable-path command line'
            }
        }
        if (($officeBrowserParents -icontains $parentName.ToLower()) -and (($lolBins -icontains $nameLower) -or $userWritablePath)) {
            Add-TriageReason $candidate 18 ("Spawned by Office, a PDF reader, or a browser: " + $parentName)
        }

        if ($networkByPid.ContainsKey($processId)) {
            $net = $networkByPid[$processId]
            $netLabels = @()
            $netLabels += @($net.Listen | Select-Object -First 6)
            $netLabels += @($net.Established | Select-Object -First 6)
            $candidate.Network = ($netLabels -join '; ')
            if ($net.Listen.Count -gt 0 -and $net.ListenExposed) {
                Add-TriageReason $candidate 22 'Process listens on a non-loopback network endpoint'
            } elseif ($net.Listen.Count -gt 0) {
                Add-TriageReason $candidate 10 'Process listens on a local network endpoint'
            }
            if ($net.RemotePublic) {
                Add-TriageReason $candidate 12 'Process has an established connection to a public IP address'
            }
        }

        if ($candidate.Score -lt 10 -and -not $candidate.DefenderConfirmed) { continue }

        if ($path -and (Test-Path -LiteralPath $path)) {
            try {
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                $candidate.Company = [string]$versionInfo.CompanyName
            } catch {}
            $sig = $null
            if ($signatureCache.ContainsKey($pathLower)) {
                $sig = $signatureCache[$pathLower]
            } else {
                try { $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop } catch {}
                $signatureCache[$pathLower] = $sig
            }
            if ($null -ne $sig) {
                $candidate.SignatureStatus = [string]$sig.Status
                try { $candidate.Signer = [string]$sig.SignerCertificate.Subject } catch {}
                if ($candidate.SignatureStatus -eq 'Valid') {
                    if ($candidate.Signer -match 'Microsoft' -and -not $strongCommand) {
                        $candidate.Score = $candidate.Score - 30
                        [void]$candidate.Notes.Add('Valid Microsoft signature reduced the risk score.')
                    } elseif ($pathLower.StartsWith($pfLower) -or ($pf86Lower -and $pathLower.StartsWith($pf86Lower))) {
                        if (-not $strongCommand) {
                            $candidate.Score = $candidate.Score - 15
                            [void]$candidate.Notes.Add('Valid signature and Program Files location reduced the risk score.')
                        }
                    } elseif (-not $strongCommand) {
                        $candidate.Score = $candidate.Score - 10
                        [void]$candidate.Notes.Add('Valid third-party signature reduced the risk score.')
                    }
                } elseif ($candidate.SignatureStatus -eq 'HashMismatch') {
                    Add-TriageReason $candidate 35 'Authenticode hash mismatch (file differs from its signed content)'
                } elseif ($candidate.SignatureStatus -eq 'NotSigned') {
                    Add-TriageReason $candidate 18 'Executable is not digitally signed'
                } elseif ($candidate.SignatureStatus -ne 'Valid') {
                    Add-TriageReason $candidate 5 ("Authenticode status is " + $candidate.SignatureStatus)
                }
            }
        }

        if ($pathLower -and $persistenceBlob.Contains($pathLower) -and ($userWritablePath -or $candidate.SignatureStatus -ne 'Valid')) {
            Add-TriageReason $candidate 12 'Exact executable path is referenced by a Run key or scheduled task'
        }
        if ($candidate.ProtectedReason) {
            [void]$candidate.Notes.Add('Protected from direct process termination: ' + $candidate.ProtectedReason)
        }
        if ($candidate.Score -lt 35 -and -not $candidate.DefenderConfirmed) { continue }

        if ($path -and (Test-Path -LiteralPath $path)) {
            try {
                $fileItem = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($fileItem.Length -le 268435456) {
                    $candidate.SHA256 = [string](Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
                } else {
                    [void]$candidate.Notes.Add('SHA-256 skipped because the executable is larger than 256 MB.')
                }
            } catch {}
        }
        if ($candidate.DefenderConfirmed) { $candidate.Level = 'DEFENDER-CONFIRMED' }
        elseif ($candidate.Score -ge 70) { $candidate.Level = 'HIGH' }
        elseif ($candidate.Score -ge 50) { $candidate.Level = 'SUSPICIOUS' }
        else { $candidate.Level = 'REVIEW' }
        $candidates += $candidate
    }

    $candidates = @($candidates | Sort-Object -Property 'Score' -Descending)
    if ($candidates.Count -eq 0) {
        Write-Step 'No running process crossed the suspicious-process threshold. This does not prove the machine is malware-free.'
        Write-Step 'Fileless malware, injected threads, and malicious DLLs inside genuine svchost/services still require Defender and the recon/service/task review.'
        return
    }

    Write-WarnLine ("Suspicious running processes found: " + $candidates.Count + ". Evidence is shown per process; protected/service-hosted processes are not killed directly.")
    foreach ($candidate in $candidates) {
        Write-Host ''
        Write-Host ("[" + $candidate.Level + " score " + $candidate.Score + "] PID " + $candidate.ProcessId + "  " + $candidate.Name) -ForegroundColor Yellow
        Write-Host ("  Path       : " + $candidate.Path)
        Write-Host ("  Parent     : " + $candidate.ParentName + " (PID " + $candidate.ParentProcessId + ")")
        Write-Host ("  Signature  : " + $candidate.SignatureStatus + "  Signer: " + $candidate.Signer)
        if ($candidate.Network) { Write-Host ("  Network    : " + $candidate.Network) }
        if ($candidate.Services) { Write-Host ("  Services   : " + $candidate.Services) }
        Write-Host ("  Children   : " + $candidate.ChildCount + "  Main window: " + $candidate.HasMainWindow)
        Write-Host '  Evidence:'
        foreach ($reason in $candidate.Reasons) { Write-Host ("    - " + $reason) }
        foreach ($note in $candidate.Notes) { Write-Host ("    * " + $note) }
        if ($candidate.CommandLine) {
            $shownCmd = $candidate.CommandLine
            if ($shownCmd.Length -gt 500) { $shownCmd = $shownCmd.Substring(0, 500) + '...' }
            Write-Host ("  Command    : " + $shownCmd)
        }

        if ($script:AuditOnly) {
            $candidate.ActionTaken = 'Audit only: no process was stopped'
            Write-Host '[AUDIT] No process will be stopped in Audit mode.'
            continue
        }
        if ($candidate.ProtectedReason) {
            $candidate.ActionTaken = 'Not stopped: ' + $candidate.ProtectedReason
            Write-WarnLine ("Not stopping PID " + $candidate.ProcessId + ": " + $candidate.ProtectedReason + ". Investigate its service/application and Defender history instead.")
            continue
        }

        $defaultStop = $candidate.DefenderConfirmed
        if ($script:ApplySafe -and $candidate.Score -ge 90) { $defaultStop = $true }
        if (-not $script:ApplySafe -and $candidate.Score -ge 65) { $defaultStop = $true }

        if ($candidate.ServiceManaged) {
            $hostedServices = @($candidate.Services -split ',\s*' | Where-Object { $_ })
            if ($hostedServices.Count -ne 1) {
                $candidate.ActionTaken = 'Not stopped: shared service-host process'
                Write-WarnLine ("Not killing PID " + $candidate.ProcessId + " because it hosts multiple services. Identify the one bad service in services.msc / the report, then handle that service only.")
                continue
            }
            $onlyService = $hostedServices[0]
            if ($script:ApplySafe -and -not $candidate.DefenderConfirmed) {
                $candidate.ActionTaken = 'Not stopped in ApplySafe: heuristic-only service detections require manual review'
                Write-WarnLine ("Service " + $onlyService + " is suspicious, but Services are never disabled from heuristics alone in ApplySafe; it was left running for manual review.")
                continue
            }
            if (Confirm-YesNo ("This process is the ONLY host for service '" + $onlyService + "'. Safely stop + disable that service instead of killing the process (keep-list/dependency checks still apply)?") $defaultStop) {
                $candidate.ActionTaken = 'Requested dependency-checked service stop/disable: ' + $onlyService
                Disable-ServiceSafe -Name $onlyService -Why 'Running-process triage found a suspicious/backdoor-like service process'
                Start-Sleep -Seconds 2
                if (Get-Process -Id $candidate.ProcessId -ErrorAction SilentlyContinue) {
                    $candidate.ActionTaken = $candidate.ActionTaken + '; host process still present afterward'
                } else {
                    $candidate.ActionTaken = $candidate.ActionTaken + '; host process exited'
                }
            }
            continue
        }

        if ($script:ApplySafe -and $candidate.HasMainWindow -and -not $candidate.DefenderConfirmed) {
            $candidate.ActionTaken = 'Not stopped in ApplySafe: visible application window could contain unsaved work'
            Write-WarnLine ("Not auto-stopping PID " + $candidate.ProcessId + " in ApplySafe because it has a visible window and no Defender verdict.")
            continue
        }
        if ($script:ApplySafe -and $candidate.ChildCount -gt 0 -and -not $candidate.DefenderConfirmed) {
            $candidate.ActionTaken = 'Not stopped in ApplySafe: child processes require manual review'
            Write-WarnLine ("Not auto-stopping PID " + $candidate.ProcessId + " in ApplySafe because it has child processes and no Defender verdict.")
            continue
        }

        $stopQuestion = "Stop ONLY PID " + $candidate.ProcessId + " (" + $candidate.Name + ") now? The executable file will not be deleted, child processes will not be bulk-killed, and persistence may restart it."
        if (-not (Confirm-YesNo $stopQuestion $defaultStop)) {
            $candidate.ActionTaken = 'Left running by operator/ApplySafe decision rule'
            Write-Step ("Left running: PID " + $candidate.ProcessId + " " + $candidate.Name)
            continue
        }

        if (Stop-TriageProcess $candidate) {
            Write-Good ("Contained suspicious process PID " + $candidate.ProcessId + " (" + $candidate.Name + ").")
            Start-Sleep -Seconds 2
            if ($candidate.Path) {
                $restarted = @()
                try { $restarted = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { [string]$_.ExecutablePath -ieq $candidate.Path }) } catch {}
                if ($restarted.Count -gt 0) {
                    $candidate.ActionTaken = $candidate.ActionTaken + '; WARNING: same executable reappeared, likely persistence/watchdog'
                    Write-WarnLine 'The same executable is running again. Find and remove its service/task/Run entry; repeatedly killing the process will not remove the backdoor.'
                }
                if ((Test-Path -LiteralPath $candidate.Path) -and (Test-CommandExists 'Start-MpScan')) {
                    if (Confirm-YesNo 'Run a Defender custom scan on this exact executable now? Defender may quarantine it if it is malicious.' $true) {
                        try {
                            Start-MpScan -ScanType CustomScan -ScanPath $candidate.Path -ErrorAction Stop
                            $candidate.ActionTaken = $candidate.ActionTaken + '; Defender custom scan completed'
                            Write-Good ("Defender custom scan completed for " + $candidate.Path)
                        } catch {
                            $candidate.ActionTaken = $candidate.ActionTaken + '; Defender custom scan failed'
                            Write-WarnLine ("Defender custom scan failed for " + $candidate.Path + ": " + $_.Exception.Message)
                        }
                    }
                }
            }
        }
    }

    try {
        $rows = foreach ($candidate in $candidates) {
            [PSCustomObject]@{
                ProcessId = $candidate.ProcessId
                Name = $candidate.Name
                Level = $candidate.Level
                Score = $candidate.Score
                ParentProcessId = $candidate.ParentProcessId
                ParentName = $candidate.ParentName
                Path = $candidate.Path
                CommandLine = $candidate.CommandLine
                DefenderThreat = $candidate.DefenderThreat
                SignatureStatus = $candidate.SignatureStatus
                Signer = $candidate.Signer
                Company = $candidate.Company
                SHA256 = $candidate.SHA256
                Services = $candidate.Services
                Network = $candidate.Network
                Reasons = ($candidate.Reasons -join '; ')
                Notes = ($candidate.Notes -join '; ')
                ActionTaken = $candidate.ActionTaken
            }
        }
        $rows | Export-Csv (Join-Path $script:ReportDir 'suspicious-processes.csv') -NoTypeInformation
        Add-Report 'process-triage.txt' 'Suspicious running processes' ($rows | Format-List | Out-String)
        Write-Step ("Process-triage evidence saved to " + (Join-Path $script:ReportDir 'suspicious-processes.csv'))
    } catch { Write-WarnLine 'Could not write the suspicious-process evidence report.' }
    Write-Step 'Stopping a process is containment, not removal. Check the matching service, scheduled task, Run key, startup item and Defender Protection history so a real backdoor cannot restart.'
}

