# ----------------------------------------------------------------------------
# Automated vulnerability file search (.exe, scripts, .zip/archives, sensitive)
# ----------------------------------------------------------------------------
function Get-SuspiciousFileRules {
    return [PSCustomObject]@{
        ExecutableExtensions = @('.exe','.msi','.msix','.appx','.scr','.com','.pif','.cpl','.jar','.dll','.sys','.ocx')
        ScriptExtensions     = @('.ps1','.psm1','.bat','.cmd','.vbs','.vbe','.js','.jse','.wsf','.wsh','.hta','.reg')
        ArchiveExtensions    = @('.zip','.7z','.rar','.tar','.gz','.tgz','.bz2','.xz','.cab','.iso','.img','.vhd','.vhdx')
        WebShellExtensions   = @('.asp','.aspx','.ashx','.asmx','.php','.jsp','.jspx')
        SensitiveExtensions  = @('.kdbx','.pfx','.p12','.pem','.ppk','.key','.pcap','.pcapng','.cap','.dmp','.rdp')
        ShortcutExtensions   = @('.lnk')
        HackToolRegex        = '(?i)(^|[\\/_.\-\s])(mimikatz|sekurlsa|nc|ncat|netcat|nmap|zenmap|wireshark|tshark|ettercap|cain|ophcrack|john|hashcat|hydra|medusa|aircrack|kismet|burpsuite|metasploit|msfvenom|meterpreter|cobalt|beacon|psexec|procdump|lazagne|rubeus|sharphound|bloodhound|chisel|ligolo|responder|crackmapexec|impacket|winpeas|linpeas|gsecdump|pwdump|fgdump|wce|keylogger|backdoor|keygen|reverse[-_\s]?shell|netbus|darkcomet|sub7)([._\-\s\d]|$)'
        DoubleExtensionRegex = '(?i)\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|jpg|jpeg|png|gif|mp3|mp4|csv)\.(exe|scr|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|com|pif|msi)$'
        SensitiveNameRegex   = '(?i)(password|passwd|creds|credential|secret|unattend\.xml|sysprep\.xml|id_rsa|id_ed25519|\.htpasswd)'
    }
}

function Test-SuspiciousFileExcludedPath {
    param(
        [string]$Path,
        [string]$ToolkitRoot = ''
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    $norm = ($Path -replace '/', '\').TrimEnd('\')
    if (-not [string]::IsNullOrWhiteSpace($ToolkitRoot)) {
        $rootNorm = ($ToolkitRoot -replace '/', '\').TrimEnd('\')
        if ($norm.Equals($rootNorm, [StringComparison]::OrdinalIgnoreCase) -or
            $norm.StartsWith(($rootNorm + '\'), [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    if ($norm -imatch '\\CyberPatriot(\\|$)' -or
        $norm -imatch '\\CP-Quarantine(\\|$)' -or
        $norm -imatch '\\Forensic') {
        return $true
    }
    if ($norm -imatch '^[a-z]:\\windows\\(winsxs|system32|syswow64|servicing|assembly|microsoft\.net|installer|softwaredistribution)(\\|$)' -or
        $norm -imatch '^[a-z]:\\program files( \(x86\))?(\\|$)' -or
        $norm -imatch '^[a-z]:\\(recovery|system volume information|perflogs|\$recycle\.bin)(\\|$)') {
        return $true
    }
    if ($norm -imatch '\\appdata\\local\\(packages|microsoft|google|mozilla|programs|pip|npm-cache)(\\|$)' -or
        $norm -imatch '\\(node_modules|\.git|\.venv|__pycache__)(\\|$)') {
        return $true
    }
    return $false
}

function Get-ZipArchiveContents {
    param(
        [string]$ZipPath,
        [int]$MaxEntries = 200
    )
    $rules = Get-SuspiciousFileRules
    $execExts = @($rules.ExecutableExtensions) + @($rules.ScriptExtensions) + @($rules.WebShellExtensions)
    $archExts = @($rules.ArchiveExtensions)
    $execEntries = New-Object System.Collections.ArrayList
    $toolMatches = New-Object System.Collections.ArrayList
    $nestedArchives = New-Object System.Collections.ArrayList
    $entryCount = 0
    $unreadable = $false

    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop } catch {}
    $zip = $null
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        foreach ($entry in $zip.Entries) {
            if ([string]::IsNullOrWhiteSpace($entry.Name)) { continue }
            $entryCount++
            if ($entryCount -gt $MaxEntries) { continue }
            $fullEntry = [string]$entry.FullName
            $ext = ([System.IO.Path]::GetExtension($entry.Name)).ToLower()
            if ($execExts -contains $ext) {
                if ($execEntries.Count -lt 25) { [void]$execEntries.Add($fullEntry) }
            }
            if ($archExts -contains $ext) {
                if ($nestedArchives.Count -lt 10) { [void]$nestedArchives.Add($fullEntry) }
            }
            if ($fullEntry -match $rules.HackToolRegex -or $fullEntry -match $rules.DoubleExtensionRegex) {
                if ($toolMatches.Count -lt 15) { [void]$toolMatches.Add($fullEntry) }
            }
        }
    } catch {
        $unreadable = $true
    } finally {
        if ($null -ne $zip) { try { $zip.Dispose() } catch {} }
    }

    return [PSCustomObject]@{
        EntryCount            = $entryCount
        HasExecutables        = ($execEntries.Count -gt 0)
        HasNestedArchives     = ($nestedArchives.Count -gt 0)
        HasHackTools          = ($toolMatches.Count -gt 0)
        ExecutableEntries     = @($execEntries)
        NestedArchives        = @($nestedArchives)
        ToolMatches           = @($toolMatches)
        EncryptedOrUnreadable = $unreadable
    }
}

function Test-ShortcutTargetSuspicious {
    param([string]$ShortcutPath)
    $result = [PSCustomObject]@{ IsSuspicious = $false; Target = ''; Reason = '' }
    if ([string]::IsNullOrWhiteSpace($ShortcutPath) -or -not (Test-Path -LiteralPath $ShortcutPath)) { return $result }
    try {
        $shell = New-Object -ComObject WScript.Shell
        $sc = $shell.CreateShortcut($ShortcutPath)
        $tgt = [string]$sc.TargetPath
        $args = [string]$sc.Arguments
        $combined = ($tgt + ' ' + $args).Trim()
        $rules = Get-SuspiciousFileRules
        if ([string]::IsNullOrWhiteSpace($combined)) { return $result }
        $lolRx = '(?i)(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)(\.exe)?$'
        if ($tgt -match $lolRx -and $args -match '(?i)(-enc|-encodedcommand|frombase64string|downloadstring|http://|https://|\\temp\\|\\appdata\\|\\public\\|\\users\\)') {
            return [PSCustomObject]@{ IsSuspicious = $true; Target = $combined; Reason = 'Shortcut launches command/script host with suspicious arguments' }
        }
        if ($tgt -match $rules.HackToolRegex) {
            return [PSCustomObject]@{ IsSuspicious = $true; Target = $combined; Reason = 'Shortcut points to a known security/hacking tool' }
        }
        if ($tgt -imatch '\\(users\\[^\\]+\\(downloads|desktop|appdata|temp)|users\\public|temp)\\.*\.(exe|bat|cmd|ps1|vbs|hta|scr)$') {
            return [PSCustomObject]@{ IsSuspicious = $true; Target = $combined; Reason = 'Shortcut executes a binary/script in a user-writable or Temp folder' }
        }
    } catch {}
    return $result
}

function Test-TextFileSensitiveContent {
    param(
        [string]$FilePath = '',
        [string]$Text = ''
    )
    $content = $Text
    if ([string]::IsNullOrEmpty($content) -and -not [string]::IsNullOrWhiteSpace($FilePath)) {
        if (-not (Test-Path -LiteralPath $FilePath)) {
            return [PSCustomObject]@{ HasSensitiveContent = $false; Points = 0; Indicators = @() }
        }
        $sr = $null
        try {
            $fi = New-Object System.IO.FileInfo($FilePath)
            if ($fi.Length -le 0 -or $fi.Length -gt 2097152) {
                return [PSCustomObject]@{ HasSensitiveContent = $false; Points = 0; Indicators = @() }
            }
            $sr = New-Object System.IO.StreamReader($FilePath, [System.Text.Encoding]::UTF8, $true)
            $sb = New-Object System.Text.StringBuilder
            $buf = New-Object char[] 16384
            $total = 0
            while ($total -lt 524288) {
                $readCount = $sr.Read($buf, 0, $buf.Length)
                if ($readCount -le 0) { break }
                [void]$sb.Append($buf, 0, $readCount)
                $total += $readCount
            }
            $content = $sb.ToString()
        } catch {
            return [PSCustomObject]@{ HasSensitiveContent = $false; Points = 0; Indicators = @() }
        } finally {
            if ($null -ne $sr) { try { $sr.Dispose() } catch {} }
        }
    }
    if ([string]::IsNullOrWhiteSpace($content)) {
        return [PSCustomObject]@{ HasSensitiveContent = $false; Points = 0; Indicators = @() }
    }

    $indicators = New-Object System.Collections.ArrayList
    $points = 0
    if ($content -match '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----') {
        $points += 45
        [void]$indicators.Add('Private key header')
    }
    if ($content -match '(?:\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bxox[baprs]-[0-9A-Za-z-]{10,}\b|\bAIza[0-9A-Za-z\-_]{35}\b|(?i)bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+|(?i)(?:Server|Data Source|Host)=[^;\r\n]+;[^;\r\n]*(?:Password|Pwd)\s*=\s*[^;\s\r\n]{3,})') {
        $points += 40
        [void]$indicators.Add('Cloud, API, bearer, or connection-string secret')
    }
    if ($content -match '(?i)(?:\b(?:password|passwd|passphrase|passcode|pwd|secret_key|api_key|apikey|client_secret|access_token|auth_token|private_key)\b\s*[:=]\s*["'']?[^\s"'']{3,}|\b(?:administrator|admin|root|wi-fi|wpa|psk)\s+(?:password|pw|key)\s*[:=\-]\s*\S+|\b(?:username|user|login|account)\b\s*[:=]\s*\S+[^\r\n]*\b(?:pass|password|pwd)\b\s*[:=]\s*\S+)') {
        $points += 35
        [void]$indicators.Add('Plaintext password or credential assignment')
    }
    $hasLabeledSsnOrCard = ($content -match '(?i)(?:\b(?:ssn|social\s*security(?:\s*number)?)\b\s*[:=#-]?\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b|\b(?:credit\s*card|card\s*number|cvv|cvc)\b\s*[:=#-]?\s*\d{3,})')
    $hasPairedSsn = ($content -match '\b\d{3}-\d{2}-\d{4}\b') -and ($content -match '(?i)\b(?:ssn|social\s*security|dob|date\s*of\s*birth)\b')
    if ($hasLabeledSsnOrCard -or $hasPairedSsn) {
        $points += 35
        [void]$indicators.Add('Sensitive PII (SSN or payment card indicator)')
    }

    return [PSCustomObject]@{
        HasSensitiveContent = ($indicators.Count -gt 0)
        Points              = $points
        Indicators          = @($indicators)
    }
}

function Measure-SuspiciousFileRisk {
    param(
        [string]$FullName,
        [long]$Length = 0,
        [string]$Extension = '',
        [object]$ZipInfo = $null,
        [object]$TextInfo = $null,
        [string[]]$ProhibitedList = @(),
        [string[]]$NecessaryList = @(),
        [string]$SignatureStatus = 'NotChecked',
        [string]$Signer = '',
        [bool]$HasZoneIdentifier = $false,
        [bool]$IsActiveDefenderThreat = $false,
        [bool]$InWebRoot = $false,
        [bool]$ShortcutSuspicious = $false,
        [string]$ShortcutReason = ''
    )
    $rules = Get-SuspiciousFileRules
    $norm = ($FullName -replace '/', '\')
    $name = [System.IO.Path]::GetFileName($norm)
    $ext = $Extension.ToLower()
    if ([string]::IsNullOrWhiteSpace($ext)) { $ext = ([System.IO.Path]::GetExtension($name)).ToLower() }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($name)

    $category = 'SensitiveData'
    if ($rules.ExecutableExtensions -contains $ext) { $category = 'Executable' }
    elseif ($rules.ScriptExtensions -contains $ext) { $category = 'Script' }
    elseif ($rules.ArchiveExtensions -contains $ext) { $category = 'Archive' }
    elseif ($rules.WebShellExtensions -contains $ext) { $category = 'WebShell' }
    elseif ($rules.ShortcutExtensions -contains $ext) { $category = 'Script' }

    $score = 0
    $reasons = New-Object System.Collections.ArrayList
    $matchesProhibited = $false
    $matchesNecessary = $false
    $matchesHackTool = $false
    $doubleExt = $false

    foreach ($p in @($ProhibitedList)) {
        $pt = ([string]$p).Trim()
        if ($pt.Length -ge 3 -and $norm.ToLower().Contains($pt.ToLower())) {
            $matchesProhibited = $true
            break
        }
    }
    foreach ($n in @($NecessaryList)) {
        $nt = ([string]$n).Trim()
        if ($nt.Length -ge 3 -and ($name.ToLower().Contains($nt.ToLower()) -or $base.ToLower().Contains($nt.ToLower()))) {
            $matchesNecessary = $true
            break
        }
    }

    if ($IsActiveDefenderThreat) {
        $score += 100
        [void]$reasons.Add('Matches an active Microsoft Defender threat detection')
    }
    if ($matchesProhibited) {
        $score += 45
        [void]$reasons.Add('Matches prohibited_software.txt')
    }
    if ($name -match $rules.HackToolRegex) {
        $matchesHackTool = $true
        $score += 60
        [void]$reasons.Add('Filename matches known hacking, cracking, or remote-admin tool')
    }
    if ($name -match $rules.DoubleExtensionRegex) {
        $doubleExt = $true
        $score += 65
        [void]$reasons.Add('Suspicious double extension masquerading as a document/media file')
    }
    if ($ShortcutSuspicious) {
        $score += 55
        if ($ShortcutReason) { [void]$reasons.Add($ShortcutReason) }
        else { [void]$reasons.Add('Shortcut launches suspicious payload') }
    }

    $inHighRiskLoc = ($norm -imatch '^[a-z]:\\[^\\]+$') -or
                     ($norm -imatch '\\(downloads|desktop|temp|tmp|public)\\') -or
                     ($norm -imatch '\\start menu\\programs\\startup\\')
    $inUserLoc = ($norm -imatch '^[a-z]:\\users\\')

    if ($category -eq 'Executable') {
        if ($ext -in @('.dll','.sys','.ocx')) {
            if ($inHighRiskLoc) {
                $score += 35
                [void]$reasons.Add('Binary library/driver in high-risk user/Temp/root location')
            } else {
                $score += 15
            }
        } else {
            $score += 20
            if ($inHighRiskLoc) {
                $score += 25
                [void]$reasons.Add('Executable/installer in Downloads, Desktop, Temp, Startup, Public, or drive root')
            } elseif ($inUserLoc) {
                $score += 15
                [void]$reasons.Add('Executable/installer inside user profile directory')
            }
        }
    } elseif ($category -eq 'Script') {
        if ($ext -ne '.lnk') {
            $score += 20
            if ($inHighRiskLoc) {
                $score += 25
                [void]$reasons.Add('Script/registry file in high-risk user/Temp/Startup/root location')
            } elseif ($inUserLoc) {
                $score += 12
                [void]$reasons.Add('Script file inside user profile directory')
            }
        }
    } elseif ($category -eq 'WebShell') {
        if ($InWebRoot) {
            $score += 40
            [void]$reasons.Add('Dynamic server script inside webroot (review for web shells)')
        } else {
            $score += 15
        }
    } elseif ($category -eq 'Archive') {
        $score += 15
        if ($inHighRiskLoc) {
            $score += 25
            [void]$reasons.Add('Archive/disk image in Downloads, Desktop, Temp, Public, or drive root')
        } elseif ($inUserLoc) {
            $score += 10
            [void]$reasons.Add('Archive/disk image inside user profile directory')
        }
    } elseif ($category -eq 'SensitiveData') {
        $isSensitiveExt = ($rules.SensitiveExtensions -contains $ext)
        $isSensitiveName = ($name -match $rules.SensitiveNameRegex)
        $hasTextHit = ($null -ne $TextInfo -and [bool]$TextInfo.HasSensitiveContent)
        if ($isSensitiveExt -or $isSensitiveName -or $hasTextHit) {
            $score += 35
            [void]$reasons.Add('Potential credential, private key, PII, memory dump, or packet capture artifact')
        }
        if ($hasTextHit) {
            $score += [int]$TextInfo.Points
            [void]$reasons.Add('Text file content indicates: ' + (@($TextInfo.Indicators) -join ', '))
        }
    }

    if ($name -match $rules.SensitiveNameRegex -and $category -ne 'Executable') {
        $score += 30
        [void]$reasons.Add('Filename suggests credentials, passwords, keys, or unattended answer file')
    }

    $zipSummary = ''
    if ($null -ne $ZipInfo) {
        if ($ZipInfo.HasHackTools) {
            $score += 65
            [void]$reasons.Add('ZIP archive contains known hacking/cracking tool(s): ' + (@($ZipInfo.ToolMatches | Select-Object -First 5) -join ', '))
        }
        if ($ZipInfo.HasExecutables) {
            $score += 40
            [void]$reasons.Add('ZIP archive contains executable/script payload(s): ' + (@($ZipInfo.ExecutableEntries | Select-Object -First 5) -join ', '))
        }
        if ($ZipInfo.HasNestedArchives) {
            $score += 10
            [void]$reasons.Add('ZIP archive contains nested archive(s)')
        }
        if ($ZipInfo.EncryptedOrUnreadable) {
            $score += 15
            [void]$reasons.Add('ZIP archive could not be read cleanly (possibly encrypted or corrupt)')
        }
        $zipSummary = ('Entries=' + $ZipInfo.EntryCount + '; Execs=' + @($ZipInfo.ExecutableEntries).Count + '; ToolHits=' + @($ZipInfo.ToolMatches).Count)
    }

    if ($HasZoneIdentifier) {
        $score += 15
        [void]$reasons.Add('Marked as downloaded from the Internet (Zone.Identifier ADS)')
    }

    if ($SignatureStatus -eq 'HashMismatch') {
        $score += 40
        [void]$reasons.Add('Authenticode signature hash mismatch (tampered or corrupt)')
    } elseif ($SignatureStatus -eq 'NotSigned' -and $category -eq 'Executable') {
        $score += 20
        [void]$reasons.Add('Executable is not digitally signed')
    } elseif ($SignatureStatus -eq 'Valid' -and -not $matchesHackTool -and -not $matchesProhibited -and -not $doubleExt) {
        if ($Signer -match 'Microsoft') {
            $score -= 20
            [void]$reasons.Add('Valid Microsoft Authenticode signature reduced risk score')
        } else {
            $score -= 10
            [void]$reasons.Add('Valid Authenticode signature reduced risk score')
        }
    }

    if ($matchesNecessary -and $SignatureStatus -eq 'Valid' -and -not $matchesProhibited -and -not $matchesHackTool) {
        $score -= 15
        [void]$reasons.Add('Matches necessary_apps.txt with valid signature')
    }

    if ($score -lt 0) { $score = 0 }
    $risk = 'LOW'
    if ($score -ge 90) { $risk = 'CRITICAL' }
    elseif ($score -ge 65) { $risk = 'HIGH' }
    elseif ($score -ge 35) { $risk = 'MEDIUM' }

    $quarantineRecommended = ($score -ge 70) -and
                             ($category -in @('Executable','Script','Archive','WebShell')) -and
                             ((-not $matchesNecessary) -or $matchesProhibited -or $IsActiveDefenderThreat -or $doubleExt -or $matchesHackTool)

    return [PSCustomObject]@{
        FullName              = $norm
        Name                  = $name
        Extension             = $ext
        Length                = $Length
        Category              = $category
        Score                 = $score
        RiskLevel             = $risk
        Reasons               = ($reasons -join '; ')
        ZipSummary            = $zipSummary
        SignatureStatus       = $SignatureStatus
        Signer                = $Signer
        MatchesProhibited     = $matchesProhibited
        MatchesHackTool       = $matchesHackTool
        DoubleExtension       = $doubleExt
        QuarantineRecommended = $quarantineRecommended
    }
}

function Get-SuspiciousFileScanRoots {
    param([string]$ToolkitRoot = '')
    $roots = New-Object System.Collections.ArrayList
    $seen = @{}
    function Add-ScanRoot {
        param([string]$Path, [int]$Depth, [bool]$IsWebRoot)
        if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return }
        if (Test-SuspiciousFileExcludedPath -Path $Path -ToolkitRoot $ToolkitRoot) { return }
        $key = ($Path -replace '/', '\').TrimEnd('\').ToLower()
        if ($seen.ContainsKey($key)) { return }
        $seen[$key] = $true
        [void]$roots.Add([PSCustomObject]@{ Path = ($Path -replace '/', '\').TrimEnd('\'); MaxDepth = $Depth; IsWebRoot = $IsWebRoot })
    }

    if (Test-Path -LiteralPath 'C:\Users') { Add-ScanRoot -Path 'C:\Users' -Depth 8 -IsWebRoot:$false }
    if (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        Add-ScanRoot -Path (Join-Path $env:SystemRoot 'Temp') -Depth 3 -IsWebRoot:$false
    }
    if (Test-Path -LiteralPath 'C:\inetpub\wwwroot') {
        Add-ScanRoot -Path 'C:\inetpub\wwwroot' -Depth 5 -IsWebRoot:$true
    }

    try {
        foreach ($drv in @([System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady })) {
            $rootDir = $drv.RootDirectory.FullName.TrimEnd('\')
            # Scan immediate files in each fixed drive root
            Add-ScanRoot -Path ($rootDir + '\') -Depth 0 -IsWebRoot:$false
            try {
                foreach ($sub in @([System.IO.Directory]::GetDirectories(($rootDir + '\')))) {
                    $leaf = [System.IO.Path]::GetFileName($sub)
                    if ($leaf -imatch '^(Windows|Program Files|Program Files \(x86\)|ProgramData|Users|CyberPatriot|CP-Quarantine|Recovery|PerfLogs|\$Recycle\.Bin|System Volume Information)$') {
                        continue
                    }
                    try {
                        $attr = [System.IO.File]::GetAttributes($sub)
                        if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                    } catch { continue }
                    Add-ScanRoot -Path $sub -Depth 3 -IsWebRoot:$false
                }
            } catch {}
        }
    } catch {}

    # Non-default SMB shares outside system paths
    if (Test-CommandExists 'Get-SmbShare') {
        try {
            foreach ($sh in @(Get-SmbShare -ErrorAction SilentlyContinue)) {
                $sp = [string]$sh.Path
                if ([string]::IsNullOrWhiteSpace($sp) -or $sh.Name -match '^(ADMIN\$|IPC\$|[A-Z]\$|SYSVOL|NETLOGON)$') { continue }
                Add-ScanRoot -Path $sp -Depth 5 -IsWebRoot:$false
            }
        } catch {}
    }

    return @($roots)
}

function Get-ScopedFilesSafe {
    param(
        [object[]]$ScanRoots,
        [string[]]$TargetExtensions,
        [string]$SensitiveNameRegex = '',
        [string]$ToolkitRoot = '',
        [switch]$IncludeTextFiles,
        [switch]$ExcludeAppData
    )
    $results = New-Object System.Collections.ArrayList
    $seenFiles = @{}
    $stack = New-Object System.Collections.Stack

    foreach ($r in @($ScanRoots)) {
        if ($null -eq $r -or [string]::IsNullOrWhiteSpace($r.Path)) { continue }
        $stack.Push([PSCustomObject]@{ Dir = [string]$r.Path; Depth = 0; MaxDepth = [int]$r.MaxDepth; IsWebRoot = [bool]$r.IsWebRoot })
    }

    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $dirPath = [string]$cur.Dir
        if (Test-SuspiciousFileExcludedPath -Path $dirPath -ToolkitRoot $ToolkitRoot) { continue }
        if ($ExcludeAppData -and ([System.IO.Path]::GetFileName($dirPath.TrimEnd('\')) -ieq 'AppData')) { continue }
        $searchDir = $dirPath
        if ($searchDir -match '^[A-Za-z]:$') { $searchDir = $searchDir + '\' }

        try {
            foreach ($f in @([System.IO.Directory]::GetFiles($searchDir))) {
                if (Test-SuspiciousFileExcludedPath -Path $f -ToolkitRoot $ToolkitRoot) { continue }
                $fkey = $f.ToLower()
                if ($seenFiles.ContainsKey($fkey)) { continue }
                $ext = ([System.IO.Path]::GetExtension($f)).ToLower()
                $fname = [System.IO.Path]::GetFileName($f)
                $matchExt = ($TargetExtensions -contains $ext)
                $matchSensitive = (-not [string]::IsNullOrWhiteSpace($SensitiveNameRegex)) -and ($fname -match $SensitiveNameRegex)
                $isTextScanCandidate = ($IncludeTextFiles -and $ext -eq '.txt')
                if ($ext -eq '.txt' -and -not $matchSensitive -and -not $isTextScanCandidate) { $matchExt = $false }
                if (-not $matchExt -and -not $matchSensitive -and -not $isTextScanCandidate) { continue }
                $seenFiles[$fkey] = $true
                try {
                    $fi = New-Object System.IO.FileInfo($f)
                    if ($isTextScanCandidate -and -not $matchSensitive -and ($fi.Length -le 0 -or $fi.Length -gt 2097152)) { continue }
                    [void]$results.Add([PSCustomObject]@{
                        FullName  = $fi.FullName
                        Name      = $fi.Name
                        Extension = $ext
                        Length    = [long]$fi.Length
                        IsWebRoot = [bool]$cur.IsWebRoot
                    })
                } catch {}
            }
        } catch {}

        if ($cur.Depth -ge $cur.MaxDepth) { continue }
        try {
            foreach ($sub in @([System.IO.Directory]::GetDirectories($searchDir))) {
                if (Test-SuspiciousFileExcludedPath -Path $sub -ToolkitRoot $ToolkitRoot) { continue }
                if ($ExcludeAppData -and ([System.IO.Path]::GetFileName($sub.TrimEnd('\')) -ieq 'AppData')) { continue }
                try {
                    $attr = [System.IO.File]::GetAttributes($sub)
                    if (($attr -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                } catch { continue }
                $stack.Push([PSCustomObject]@{ Dir = $sub; Depth = ($cur.Depth + 1); MaxDepth = $cur.MaxDepth; IsWebRoot = [bool]$cur.IsWebRoot })
            }
        } catch {}
    }

    return @($results)
}

function Move-FileToQuarantine {
    param(
        [string]$SourcePath,
        [string]$QuarantineRoot
    )
    if ([string]::IsNullOrWhiteSpace($SourcePath) -or -not (Test-Path -LiteralPath $SourcePath)) { return $false }
    try {
        $rel = $SourcePath
        if ($SourcePath -match '^([A-Za-z]):\\(.*)$') {
            $drv = $Matches[1].ToUpper()
            $tail = $Matches[2]
            if ($drv -eq 'C') { $rel = $tail }
            else { $rel = ('Drive_' + $drv + '\' + $tail) }
        }
        $dest = Join-Path $QuarantineRoot $rel
        $destDir = Split-Path $dest -Parent
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        Move-Item -LiteralPath $SourcePath -Destination $dest -Force -ErrorAction Stop
        [void]$script:QuarantineEntries.Add([PSCustomObject]@{ From = $SourcePath; To = $dest })
        return $true
    } catch {
        Write-WarnLine ("Could not move " + $SourcePath + ": " + $_.Exception.Message)
        return $false
    }
}

function Invoke-VulnerabilityFileScan {
    Write-Step 'Automated executable, archive (.zip), script, and vulnerability-file search:'
    Write-Step 'scans C:\Users, drive roots, Temp, Startup, webroot, and non-system shares.'
    Write-Step 'CyberPatriot, Forensics, Windows system folders, and Program Files are excluded.'
    if (-not (Confirm-YesNo 'Automatically search for .exe, scripts, .zip archives, and vulnerable files now?' $true)) { return }

    $rules = Get-SuspiciousFileRules
    $allExts = @($rules.ExecutableExtensions) + @($rules.ScriptExtensions) + @($rules.ArchiveExtensions) + @($rules.SensitiveExtensions) + @($rules.WebShellExtensions) + @($rules.ShortcutExtensions)
    $prohibitedList = @()
    try { $prohibitedList = @(Get-TextList (Join-Path $script:Root 'prohibited_software.txt') | Where-Object { $_ -ne 'EDIT_ME' }) } catch {}
    $necCfg = Get-UpdateConfig (Join-Path $script:Root 'necessary_apps.txt')
    $necessaryList = @($necCfg.Necessary)

    # Active Defender threat paths for instant confirmation
    $defenderThreatPaths = @{}
    if (Test-CommandExists 'Get-MpThreat') {
        try {
            $activeIds = @{}
            foreach ($t in @(Get-MpThreat -ErrorAction Stop)) {
                if ([bool]$t.IsActive) {
                    $activeIds["$($t.ThreatID)"] = $true
                    foreach ($r in @($t.Resources)) {
                        $rl = ([string]$r).ToLower()
                        if ($rl.StartsWith('file:_')) { $defenderThreatPaths[$rl.Substring(6)] = $true }
                        if ($rl.StartsWith('containerfile:_')) { $defenderThreatPaths[$rl.Substring(15)] = $true }
                    }
                }
            }
            if ($activeIds.Count -gt 0 -and (Test-CommandExists 'Get-MpThreatDetection')) {
                foreach ($d in @(Get-MpThreatDetection -ErrorAction Stop)) {
                    if (-not $activeIds.ContainsKey("$($d.ThreatID)")) { continue }
                    foreach ($r in @($d.Resources)) {
                        $rl = ([string]$r).ToLower()
                        if ($rl.StartsWith('file:_')) { $defenderThreatPaths[$rl.Substring(6)] = $true }
                        if ($rl.StartsWith('containerfile:_')) { $defenderThreatPaths[$rl.Substring(15)] = $true }
                    }
                }
            }
        } catch {}
    }

    $scanRoots = @(Get-SuspiciousFileScanRoots -ToolkitRoot $script:Root)
    Write-Step 'Scanning targeted directories for executables, archives, scripts, and sensitive files/texts...'
    $rawFiles = @(Get-ScopedFilesSafe -ScanRoots $scanRoots -TargetExtensions $allExts -SensitiveNameRegex $rules.SensitiveNameRegex -ToolkitRoot $script:Root -IncludeTextFiles)
    Write-Step ("Candidate files inspected: " + $rawFiles.Count)

    $findings = New-Object System.Collections.ArrayList
    $sigCache = @{}
    foreach ($f in $rawFiles) {
        $ext = [string]$f.Extension
        $zipInfo = $null
        $textInfo = $null
        $scSuspicious = $false
        $scReason = ''

        if ($ext -eq '.lnk') {
            if ($f.FullName -notmatch '\\(desktop|downloads|temp|tmp|startup|public)\\' -and $f.FullName -notmatch '^[a-z]:\\[^\\]+$') { continue }
            $scInfo = Test-ShortcutTargetSuspicious -ShortcutPath $f.FullName
            if (-not $scInfo.IsSuspicious) { continue }
            $scSuspicious = $true
            $scReason = $scInfo.Reason
        }
        if ($ext -eq '.zip' -and $f.Length -le 134217728) {
            $zipInfo = Get-ZipArchiveContents -ZipPath $f.FullName
        }
        if ($ext -eq '.txt' -and $f.Length -gt 0 -and $f.Length -le 2097152) {
            $textInfo = Test-TextFileSensitiveContent -FilePath $f.FullName
        }

        $hasMotw = $false
        try {
            $zone = Get-Item -LiteralPath $f.FullName -Stream 'Zone.Identifier' -ErrorAction SilentlyContinue
            if ($null -ne $zone) { $hasMotw = $true }
        } catch {}

        $sigStatus = 'NotChecked'
        $signer = ''
        if (($ext -in @('.exe','.msi','.msix','.dll','.sys','.ocx','.ps1','.bat','.cmd','.vbs','.js')) -and $f.Length -le 134217728) {
            $key = $f.FullName.ToLower()
            $sig = $null
            if ($sigCache.ContainsKey($key)) { $sig = $sigCache[$key] }
            else {
                try { $sig = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction Stop } catch {}
                $sigCache[$key] = $sig
            }
            if ($null -ne $sig) {
                $sigStatus = [string]$sig.Status
                try { $signer = [string]$sig.SignerCertificate.Subject } catch {}
            }
        }

        $isDef = $defenderThreatPaths.ContainsKey($f.FullName.ToLower())
        $eval = Measure-SuspiciousFileRisk -FullName $f.FullName `
            -Length $f.Length `
            -Extension $ext `
            -ZipInfo $zipInfo `
            -TextInfo $textInfo `
            -ProhibitedList $prohibitedList `
            -NecessaryList $necessaryList `
            -SignatureStatus $sigStatus `
            -Signer $signer `
            -HasZoneIdentifier $hasMotw `
            -IsActiveDefenderThreat $isDef `
            -InWebRoot $f.IsWebRoot `
            -ShortcutSuspicious $scSuspicious `
            -ShortcutReason $scReason

        if ($eval.Score -ge 35) {
            $sha = ''
            if ($eval.Score -ge 65 -and $f.Length -le 134217728) {
                try { $sha = [string](Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
            }
            [void]$findings.Add([PSCustomObject]@{
                RiskLevel             = $eval.RiskLevel
                Score                 = $eval.Score
                Category              = $eval.Category
                Extension             = $eval.Extension
                Length                = $eval.Length
                FullName              = $eval.FullName
                SignatureStatus       = $eval.SignatureStatus
                ZipSummary            = $eval.ZipSummary
                SHA256                = $sha
                QuarantineRecommended = $eval.QuarantineRecommended
                Reasons               = $eval.Reasons
            })
        }
    }

    $sorted = @($findings | Sort-Object -Property 'Score' -Descending)
    $critCount = @($sorted | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
    $highCount = @($sorted | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
    $medCount  = @($sorted | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
    $script:SuspiciousFilesSummary = [PSCustomObject]@{
        Total               = $sorted.Count
        Critical            = $critCount
        High                = $highCount
        Medium              = $medCount
        HighRiskQuarantined = 0
    }

    if ($sorted.Count -eq 0) {
        Write-Step 'No suspicious executables, archives, scripts, or vulnerable files found in targeted paths.'
        return
    }

    $sorted | Export-Csv (Join-Path $script:ReportDir 'suspicious-files.csv') -NoTypeInformation
    $txtTable = $sorted | Format-Table 'RiskLevel','Score','Category','FullName','ZipSummary','Reasons' -AutoSize | Out-String -Width 300
    Add-Report 'suspicious-files.txt' 'Suspicious executables, archives (.zip), scripts, and vulnerable files' $txtTable
    Write-WarnLine ("Suspicious/vulnerable files found: " + $sorted.Count + " (CRITICAL=" + $critCount + ", HIGH=" + $highCount + ", MEDIUM=" + $medCount + "). See Reports\...\suspicious-files.csv")

    $displayLimit = 25
    foreach ($item in ($sorted | Select-Object -First $displayLimit)) {
        $line = ('  [' + $item.RiskLevel + ' ' + $item.Score + '] (' + $item.Category + ') ' + $item.FullName + '  [' + $item.Reasons + ']')
        if ($item.RiskLevel -eq 'CRITICAL' -or $item.RiskLevel -eq 'HIGH') { Write-Host $line -ForegroundColor Yellow }
        else { Write-Host $line }
    }
    if ($sorted.Count -gt $displayLimit) {
        Write-Step ("  ... and " + ($sorted.Count - $displayLimit) + " more item(s) listed in suspicious-files.csv.")
    }

    if ($script:AuditOnly) { return }

    $quarantineRoot = 'C:\CP-Quarantine\' + $script:Stamp
    $recommended = @($sorted | Where-Object { $_.QuarantineRecommended })
    if ($recommended.Count -gt 0) {
        if ($script:ApplySafe) {
            foreach ($rec in $recommended) {
                if ($rec.Score -ge 90) {
                    if (Move-FileToQuarantine -SourcePath $rec.FullName -QuarantineRoot $quarantineRoot) {
                        Write-Good ("Quarantined high-confidence risk file (reversible): " + $rec.FullName)
                        if ($rec.RiskLevel -in @('CRITICAL','HIGH')) { $script:SuspiciousFilesSummary.HighRiskQuarantined++ }
                    }
                }
            }
        } else {
            Write-Host ''
            Write-Host 'You can reversibly QUARANTINE flagged executables/archives into C:\CP-Quarantine'
            Write-Host '(nothing is permanently deleted). Review each item carefully against the README:'
            foreach ($rec in $recommended) {
                $defYes = ($rec.Score -ge 75)
                $msg = ("  QUARANTINE [" + $rec.RiskLevel + "] " + $rec.FullName + " (" + $rec.Reasons + ")?")
                if (Confirm-YesNo $msg $defYes) {
                    if (Move-FileToQuarantine -SourcePath $rec.FullName -QuarantineRoot $quarantineRoot) {
                        Write-Good ("Quarantined: " + $rec.FullName)
                        if ($rec.RiskLevel -in @('CRITICAL','HIGH')) { $script:SuspiciousFilesSummary.HighRiskQuarantined++ }
                    }
                }
            }
        }
    }

    if (-not $script:ApplySafe) {
        $otherArchivesOrScripts = @($sorted | Where-Object { (-not $_.QuarantineRecommended) -and ($_.Category -in @('Archive','Script','Executable')) })
        if ($otherArchivesOrScripts.Count -gt 0) {
            if (Confirm-YesNo ("Review/quarantine " + $otherArchivesOrScripts.Count + " remaining MEDIUM/archive/script finding(s) one by one?") $false) {
                foreach ($other in $otherArchivesOrScripts) {
                    if (Confirm-YesNo ("  QUARANTINE " + $other.FullName + " (" + $other.Reasons + ")?") $false) {
                        if (Move-FileToQuarantine -SourcePath $other.FullName -QuarantineRoot $quarantineRoot) {
                            Write-Good ("Quarantined: " + $other.FullName)
                            if ($other.RiskLevel -in @('CRITICAL','HIGH')) { $script:SuspiciousFilesSummary.HighRiskQuarantined++ }
                        }
                    }
                }
            }
        }
    }
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
        Write-Step 'No installed Win32 program matches prohibited_software.txt.'
    } else {
        Add-Report 'prohibited-software.txt' 'Programs matching prohibited_software.txt' ($flaggedApps | Format-Table 'DisplayName','DisplayVersion','Publisher' -AutoSize | Out-String)
        foreach ($app in $flaggedApps) {
            Write-Host ("  Found: " + $app.DisplayName + ' ' + $app.DisplayVersion + ' (' + $app.Publisher + ')')
            if ($script:AuditOnly) { continue }
            if ([string]::IsNullOrWhiteSpace("$($app.UninstallString)")) {
                Write-WarnLine '    No uninstall command recorded - remove it via Settings > Apps.'
                continue
            }
            if (Confirm-YesNo ("  Launch the uninstaller for " + $app.DisplayName + " now? (Follow its prompts; do NOT reboot if it asks - choose Later)") $false) {
                try {
                    $uninstall = "$($app.UninstallString)" -replace '/I\{', '/X{'
                    Start-Process cmd.exe -ArgumentList ('/c ' + $uninstall) -Wait
                    Write-Good ("Ran uninstaller for " + $app.DisplayName)
                } catch { Write-WarnLine '    Uninstaller failed to launch - use Settings > Apps.' }
            }
        }
    }

    if (Test-CommandExists 'Get-AppxProhibitedPackages') {
        $flaggedAppx = @(Get-AppxProhibitedPackages -ProhibitedList $badList)
        if ($flaggedAppx.Count -gt 0) {
            Add-Report 'prohibited-software.txt' 'Store / Appx apps matching prohibited_software.txt' ($flaggedAppx | Format-Table 'Name','Version','MatchedRule' -AutoSize | Out-String)
            foreach ($ap in $flaggedAppx) {
                Write-Host ("  Found Store app: " + $ap.Name + ' ' + $ap.Version + ' (rule: ' + $ap.MatchedRule + ')')
                if (-not $script:AuditOnly -and (Test-CommandExists 'Remove-AppxPackage')) {
                    if (Confirm-YesNo ("  Uninstall Store app '" + $ap.Name + "'?") $false) {
                        try {
                            Remove-AppxPackage -Package $ap.PackageFullName -ErrorAction Stop
                            Write-Good ("Removed Store app " + $ap.Name)
                        } catch { Write-WarnLine ("    Could not remove Store app " + $ap.Name + ": " + $_.Exception.Message) }
                    }
                }
            }
        }
    }

    Invoke-VulnerabilityFileScan

    Write-Step 'Media / prohibited-file scan (this changed the most from the 2019 script):'
    Write-Step 'scans REPORT first, then MOVES files into C:\CP-Quarantine (reversible).'
    Write-Step 'Deletion is a separate, second, typed decision. Program files under'
    Write-Step 'AppData are excluded by default, as are CyberPatriot and Forensics folders.'
    if (Confirm-YesNo 'Scan C:\Users for music/video files now?' $true) {
        $includeImages = Confirm-YesNo 'Also scan IMAGE files (jpg/png/gif)? Say YES only if the README prohibits images (a photography business must keep them).' $false
        $includeAppData = Confirm-YesNo 'Also scan inside AppData (slower; may list program assets)?' $false
        $extensions = @('.mp3','.flac','.m4a','.ogg','.wma','.aac','.mp4','.mov','.avi','.mkv','.wmv','.mpg','.mpeg','.flv','.m4v','.webm','.3gp')
        if ($includeImages) { $extensions += @('.jpg','.jpeg','.png','.gif','.bmp','.tif','.tiff') }
        $scanRoot = 'C:\Users'
        if (-not (Test-Path $scanRoot)) {
            Write-WarnLine 'C:\Users not found - skipping the media scan.'
        } else {
            Write-Step 'Scanning ... (reparse-point-safe directory walk)'
            $found = @()
            try {
                $mediaRoots = @([PSCustomObject]@{ Path = $scanRoot; MaxDepth = 12; IsWebRoot = $false })
                $found = @(Get-ScopedFilesSafe -ScanRoots $mediaRoots -TargetExtensions $extensions -SensitiveNameRegex '' -ToolkitRoot $script:Root -ExcludeAppData:(-not $includeAppData) |
                    Select-Object 'FullName','Length','Extension')
            } catch { Write-WarnLine 'The media scan hit an error; see the transcript.' }
            Write-Step ("Files found: " + $found.Count)
            $found | Export-Csv (Join-Path $script:ReportDir 'media-found.csv') -NoTypeInformation
            if ($found.Count -gt 0 -and -not $script:AuditOnly) {
                $byExt = $found | Group-Object Extension
                $quarantineRoot = 'C:\CP-Quarantine\' + $script:Stamp
                foreach ($grp in $byExt) {
                    Write-Host ("  " + $grp.Name + " : " + $grp.Count + " file(s)")
                    if (Confirm-YesNo ("  QUARANTINE (move, not delete) all " + $grp.Name + " files into C:\CP-Quarantine?") $false) {
                        foreach ($file in $grp.Group) {
                            [void](Move-FileToQuarantine -SourcePath $file.FullName -QuarantineRoot $quarantineRoot)
                        }
                        Write-Good ("Quarantined " + $grp.Name + " files.")
                    }
                }
            }
        }
    }

    if ($script:QuarantineEntries.Count -gt 0 -and -not $script:AuditOnly) {
        $quarantineRoot = 'C:\CP-Quarantine\' + $script:Stamp
        @($script:QuarantineEntries) | Export-Csv (Join-Path $script:ReportDir 'quarantine-log.csv') -NoTypeInformation
        Write-Host 'Check the Scoring Report. If removing a file cost points, move it back'
        Write-Host ('from ' + $quarantineRoot + ' to its original path (see quarantine-log.csv).')
        Write-Host 'Empty the quarantine only when you are sure: scoring usually checks that'
        Write-Host 'prohibited files are gone from user folders, and a quarantine OUTSIDE'
        Write-Host 'C:\Users keeps them recoverable until the round ends.'
    }
}

