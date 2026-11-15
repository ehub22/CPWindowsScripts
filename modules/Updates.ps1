# ----------------------------------------------------------------------------
# Updates: necessary apps + dependencies + update-infrastructure repair
# ----------------------------------------------------------------------------
function Get-KnownAppDependencyCatalog {
    return @(
        # Update-tooling & platform/runtime dependencies (updated FIRST)
        [PSCustomObject]@{ Id='Microsoft.AppInstaller'; Label='App Installer (WinGet)'; Category='Dependency'; Aliases=@('App Installer','WinGet','DesktopAppInstaller'); ProcessNames=@('winget'); ServiceNames=@(); DetectPaths=@("$env:LOCALAPPDATA\Microsoft\WindowsApps\winget.exe") },
        [PSCustomObject]@{ Id='Microsoft.VCRedist.2015+.x64'; Label='Visual C++ 2015-2022 Redistributable (x64)'; Category='Dependency'; Aliases=@('Visual C++','VC++','VCRedist','C++ Redistributable'); ProcessNames=@(); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.VCRedist.2015+.x86'; Label='Visual C++ 2015-2022 Redistributable (x86)'; Category='Dependency'; Aliases=@('Visual C++','VC++','VCRedist','C++ Redistributable'); ProcessNames=@(); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.VCRedist.2013.x64'; Label='Visual C++ 2013 Redistributable (x64)'; Category='Dependency'; Aliases=@('Visual C++ 2013','VCRedist 2013'); ProcessNames=@(); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.VCRedist.2013.x86'; Label='Visual C++ 2013 Redistributable (x86)'; Category='Dependency'; Aliases=@('Visual C++ 2013','VCRedist 2013'); ProcessNames=@(); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.EdgeWebView2Runtime'; Label='Microsoft Edge WebView2 Runtime'; Category='Dependency'; Aliases=@('WebView2','Edge WebView2','WebView2 Runtime'); ProcessNames=@('msedgewebview2'); ServiceNames=@(); DetectPaths=@("${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application\msedgewebview2.exe") },
        [PSCustomObject]@{ Id='Microsoft.DotNet.Runtime.8'; Label='.NET 8 Runtime'; Category='Dependency'; Aliases=@('.NET','.NET 8','DotNet'); ProcessNames=@('dotnet'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.DotNet.DesktopRuntime.8'; Label='.NET 8 Desktop Runtime'; Category='Dependency'; Aliases=@('.NET','.NET Desktop','.NET 8','DotNet'); ProcessNames=@('dotnet'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.DotNet.AspNetCore.8'; Label='ASP.NET Core 8 Runtime'; Category='Dependency'; Aliases=@('ASP.NET Core','.NET 8','DotNet'); ProcessNames=@('dotnet'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.DotNet.Runtime.10'; Label='.NET 10 Runtime'; Category='Dependency'; Aliases=@('.NET','.NET 10','DotNet'); ProcessNames=@('dotnet'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.DotNet.DesktopRuntime.10'; Label='.NET 10 Desktop Runtime'; Category='Dependency'; Aliases=@('.NET','.NET Desktop','.NET 10','DotNet'); ProcessNames=@('dotnet'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.DotNet.AspNetCore.10'; Label='ASP.NET Core 10 Runtime'; Category='Dependency'; Aliases=@('ASP.NET Core','.NET 10','DotNet'); ProcessNames=@('dotnet'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.PowerShell'; Label='PowerShell 7'; Category='Dependency'; Aliases=@('PowerShell 7','PowerShell Core','pwsh'); ProcessNames=@('pwsh'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\PowerShell\7\pwsh.exe") },
        [PSCustomObject]@{ Id='Git.Git'; Label='Git for Windows'; Category='Dependency'; Aliases=@('Git','Git for Windows'); ProcessNames=@('git','bash'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\Git\cmd\git.exe","${env:ProgramFiles(x86)}\Git\cmd\git.exe") },
        [PSCustomObject]@{ Id='Python.Launcher'; Label='Python Launcher'; Category='Dependency'; Aliases=@('Python','Python Launcher'); ProcessNames=@('py'); ServiceNames=@(); DetectPaths=@("$env:SystemRoot\py.exe") },
        [PSCustomObject]@{ Id='Python.Python.3.12'; Label='Python 3.12'; Category='Dependency'; Aliases=@('Python','Python 3','Python 3.12'); ProcessNames=@('python','pythonw'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Python.Python.3.13'; Label='Python 3.13'; Category='Dependency'; Aliases=@('Python','Python 3','Python 3.13'); ProcessNames=@('python','pythonw'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Python.Python.3.14'; Label='Python 3.14'; Category='Dependency'; Aliases=@('Python','Python 3','Python 3.14'); ProcessNames=@('python','pythonw'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='OpenJS.NodeJS.LTS'; Label='Node.js LTS'; Category='Dependency'; Aliases=@('Node.js','NodeJS','npm'); ProcessNames=@('node'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\nodejs\node.exe") },
        [PSCustomObject]@{ Id='OpenJS.NodeJS'; Label='Node.js'; Category='Dependency'; Aliases=@('Node.js','NodeJS','npm'); ProcessNames=@('node'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\nodejs\node.exe") },
        [PSCustomObject]@{ Id='EclipseAdoptium.Temurin.21.JRE'; Label='Eclipse Temurin JRE 21'; Category='Dependency'; Aliases=@('Java','JRE','Temurin','OpenJDK'); ProcessNames=@('java','javaw'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='EclipseAdoptium.Temurin.17.JRE'; Label='Eclipse Temurin JRE 17'; Category='Dependency'; Aliases=@('Java','JRE','Temurin','OpenJDK'); ProcessNames=@('java','javaw'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Oracle.JavaRuntimeEnvironment'; Label='Oracle Java Runtime'; Category='Dependency'; Aliases=@('Java','JRE','Oracle Java'); ProcessNames=@('java','javaw'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='ShiningLight.OpenSSL'; Label='OpenSSL'; Category='Dependency'; Aliases=@('OpenSSL'); ProcessNames=@('openssl'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\OpenSSL-Win64\bin\openssl.exe") },

        # Common essential & scenario-necessary user applications
        [PSCustomObject]@{ Id='Google.Chrome'; Label='Google Chrome'; Category='NecessaryApp'; Aliases=@('Chrome','Google Chrome'); ProcessNames=@('chrome'); ServiceNames=@('gupdate','gupdatem'); DetectPaths=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe") },
        [PSCustomObject]@{ Id='Mozilla.Firefox'; Label='Mozilla Firefox'; Category='NecessaryApp'; Aliases=@('Firefox','Mozilla Firefox'); ProcessNames=@('firefox'); ServiceNames=@('MozillaMaintenance'); DetectPaths=@("$env:ProgramFiles\Mozilla Firefox\firefox.exe","${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe") },
        [PSCustomObject]@{ Id='Microsoft.Edge'; Label='Microsoft Edge'; Category='NecessaryApp'; Aliases=@('Edge','Microsoft Edge'); ProcessNames=@('msedge'); ServiceNames=@('edgeupdate','edgeupdatem'); DetectPaths=@("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe","$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") },
        [PSCustomObject]@{ Id='Brave.Brave'; Label='Brave Browser'; Category='NecessaryApp'; Aliases=@('Brave','Brave Browser'); ProcessNames=@('brave'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe") },
        [PSCustomObject]@{ Id='Opera.Opera'; Label='Opera Browser'; Category='NecessaryApp'; Aliases=@('Opera'); ProcessNames=@('opera'); ServiceNames=@(); DetectPaths=@("$env:LOCALAPPDATA\Programs\Opera\opera.exe") },
        [PSCustomObject]@{ Id='Notepad++.Notepad++'; Label='Notepad++'; Category='NecessaryApp'; Aliases=@('Notepad++','NotepadPlusPlus'); ProcessNames=@('notepad++'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\Notepad++\notepad++.exe","${env:ProgramFiles(x86)}\Notepad++\notepad++.exe") },
        [PSCustomObject]@{ Id='Adobe.Acrobat.Reader.64-bit'; Label='Adobe Acrobat Reader'; Category='NecessaryApp'; Aliases=@('Adobe Acrobat Reader','Adobe Reader','Acrobat Reader'); ProcessNames=@('Acrobat','AcroRd32'); ServiceNames=@('AdobeARMservice'); DetectPaths=@("$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe") },
        [PSCustomObject]@{ Id='Adobe.Acrobat.Reader.32-bit'; Label='Adobe Acrobat Reader (32-bit)'; Category='NecessaryApp'; Aliases=@('Adobe Acrobat Reader','Adobe Reader','Acrobat Reader'); ProcessNames=@('AcroRd32','Acrobat'); ServiceNames=@('AdobeARMservice'); DetectPaths=@("${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe") },
        [PSCustomObject]@{ Id='VideoLAN.VLC'; Label='VLC media player'; Category='NecessaryApp'; Aliases=@('VLC','VLC media player'); ProcessNames=@('vlc'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\VideoLAN\VLC\vlc.exe","${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe") },
        [PSCustomObject]@{ Id='7zip.7zip'; Label='7-Zip'; Category='NecessaryApp'; Aliases=@('7-Zip','7zip'); ProcessNames=@('7zFM','7zG','7z'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\7-Zip\7zFM.exe","${env:ProgramFiles(x86)}\7-Zip\7zFM.exe") },
        [PSCustomObject]@{ Id='TheDocumentFoundation.LibreOffice'; Label='LibreOffice'; Category='NecessaryApp'; Aliases=@('LibreOffice'); ProcessNames=@('soffice.bin','soffice'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\LibreOffice\program\soffice.exe") },
        [PSCustomObject]@{ Id='Mozilla.Thunderbird'; Label='Mozilla Thunderbird'; Category='NecessaryApp'; Aliases=@('Thunderbird','Mozilla Thunderbird'); ProcessNames=@('thunderbird'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\Mozilla Thunderbird\thunderbird.exe","${env:ProgramFiles(x86)}\Mozilla Thunderbird\thunderbird.exe") },
        [PSCustomObject]@{ Id='Microsoft.VisualStudioCode'; Label='Visual Studio Code'; Category='NecessaryApp'; Aliases=@('Visual Studio Code','VS Code','VSCode'); ProcessNames=@('Code'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\Microsoft VS Code\Code.exe","$env:LOCALAPPDATA\Programs\Microsoft VS Code\Code.exe") },
        [PSCustomObject]@{ Id='PuTTY.PuTTY'; Label='PuTTY'; Category='NecessaryApp'; Aliases=@('PuTTY'); ProcessNames=@('putty'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\PuTTY\putty.exe","${env:ProgramFiles(x86)}\PuTTY\putty.exe") },
        [PSCustomObject]@{ Id='WinSCP.WinSCP'; Label='WinSCP'; Category='NecessaryApp'; Aliases=@('WinSCP'); ProcessNames=@('WinSCP'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\WinSCP\WinSCP.exe","${env:ProgramFiles(x86)}\WinSCP\WinSCP.exe") },
        [PSCustomObject]@{ Id='TimKosse.FileZilla.Client'; Label='FileZilla Client'; Category='NecessaryApp'; Aliases=@('FileZilla','FileZilla Client'); ProcessNames=@('filezilla'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\FileZilla FTP Client\filezilla.exe") },
        [PSCustomObject]@{ Id='GIMP.GIMP.2'; Label='GIMP'; Category='NecessaryApp'; Aliases=@('GIMP'); ProcessNames=@('gimp-2.10'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='GIMP.GIMP.3'; Label='GIMP'; Category='NecessaryApp'; Aliases=@('GIMP'); ProcessNames=@('gimp-3'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='DominikReichl.KeePass'; Label='KeePass'; Category='NecessaryApp'; Aliases=@('KeePass'); ProcessNames=@('KeePass'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\KeePass Password Safe 2\KeePass.exe","${env:ProgramFiles(x86)}\KeePass Password Safe 2\KeePass.exe") },
        [PSCustomObject]@{ Id='KeePassXCTeam.KeePassXC'; Label='KeePassXC'; Category='NecessaryApp'; Aliases=@('KeePassXC'); ProcessNames=@('KeePassXC'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\KeePassXC\KeePassXC.exe") },
        [PSCustomObject]@{ Id='SumatraPDF.SumatraPDF'; Label='SumatraPDF'; Category='NecessaryApp'; Aliases=@('SumatraPDF'); ProcessNames=@('SumatraPDF'); ServiceNames=@(); DetectPaths=@("$env:ProgramFiles\SumatraPDF\SumatraPDF.exe") },
        [PSCustomObject]@{ Id='Microsoft.WindowsTerminal'; Label='Windows Terminal'; Category='NecessaryApp'; Aliases=@('Windows Terminal','Terminal'); ProcessNames=@('WindowsTerminal'); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.Sysinternals.Suite'; Label='Sysinternals Suite'; Category='NecessaryApp'; Aliases=@('Sysinternals'); ProcessNames=@(); ServiceNames=@(); DetectPaths=@() },
        [PSCustomObject]@{ Id='WireGuard.WireGuard'; Label='WireGuard'; Category='NecessaryApp'; Aliases=@('WireGuard'); ProcessNames=@('wireguard'); ServiceNames=@('WireGuardManager'); DetectPaths=@("$env:ProgramFiles\WireGuard\wireguard.exe") },
        [PSCustomObject]@{ Id='OpenVPNTechnologies.OpenVPN'; Label='OpenVPN'; Category='NecessaryApp'; Aliases=@('OpenVPN'); ProcessNames=@('openvpn-gui','openvpn'); ServiceNames=@('OpenVPNService','OpenVPNServiceInteractive'); DetectPaths=@("$env:ProgramFiles\OpenVPN\bin\openvpn-gui.exe") },

        # Critical server daemons (require backup + post-update service-running verification)
        [PSCustomObject]@{ Id='ApacheLounge.httpd'; Label='Apache HTTP Server'; Category='ServerDaemon'; Aliases=@('Apache','httpd'); ProcessNames=@('httpd'); ServiceNames=@('Apache2.4','Apache'); DetectPaths=@('C:\Apache24\bin\httpd.exe') },
        [PSCustomObject]@{ Id='Nginx.nginx'; Label='nginx'; Category='ServerDaemon'; Aliases=@('nginx'); ProcessNames=@('nginx'); ServiceNames=@('nginx'); DetectPaths=@() },
        [PSCustomObject]@{ Id='Oracle.MySQL'; Label='MySQL Server'; Category='ServerDaemon'; Aliases=@('MySQL','MySQL Server'); ProcessNames=@('mysqld'); ServiceNames=@('MySQL','MySQL80'); DetectPaths=@() },
        [PSCustomObject]@{ Id='MariaDB.Server'; Label='MariaDB Server'; Category='ServerDaemon'; Aliases=@('MariaDB'); ProcessNames=@('mariadbd','mysqld'); ServiceNames=@('MariaDB'); DetectPaths=@() },
        [PSCustomObject]@{ Id='PostgreSQL.PostgreSQL'; Label='PostgreSQL'; Category='ServerDaemon'; Aliases=@('PostgreSQL','postgres'); ProcessNames=@('postgres'); ServiceNames=@('postgresql-x64-16','postgresql-x64-15','postgresql-x64-17'); DetectPaths=@() },
        [PSCustomObject]@{ Id='TimKosse.FileZilla.Server'; Label='FileZilla Server'; Category='ServerDaemon'; Aliases=@('FileZilla Server'); ProcessNames=@('filezilla-server'); ServiceNames=@('filezilla-server','FileZilla Server'); DetectPaths=@() },
        [PSCustomObject]@{ Id='Microsoft.OpenSSH.Beta'; Label='OpenSSH for Windows'; Category='ServerDaemon'; Aliases=@('OpenSSH','sshd'); ProcessNames=@('sshd'); ServiceNames=@('sshd','ssh-agent'); DetectPaths=@("$env:ProgramFiles\OpenSSH\sshd.exe") }
    )
}

function Get-NecessaryAppsFromServices {
    param(
        [string[]]$KeepEntries = @(),
        [string[]]$KeptChoices = @()
    )
    $clientPatterns = New-Object System.Collections.ArrayList
    $dependencyPatterns = New-Object System.Collections.ArrayList
    $serverPatterns = New-Object System.Collections.ArrayList
    $serviceNames = New-Object System.Collections.ArrayList
    $allTokens = @()
    foreach ($x in @($KeepEntries)) { if (-not [string]::IsNullOrWhiteSpace($x)) { $allTokens += $x.Trim() } }
    foreach ($x in @($KeptChoices)) { if (-not [string]::IsNullOrWhiteSpace($x)) { $allTokens += $x.Trim() } }

    $abstractTokens = @('RDP','REMOTEDESKTOP','REMOTE DESKTOP','REMOTE','SMB','FILES','FILE','SHARES','AD','DOMAIN','DNS','DHCP','PRINT','PRINTING','WINRM','SNMP','FAX','BLUETOOTH','SMARTCARD','TELNET','ANONYMOUSFTP','PUBLICFTP','WEBDAV','TERMSERVICE','UMRDPSERVICE','SESSIONENV','LANMANSERVER','SPOOLER','W3SVC','WAS','IISADMIN')
    foreach ($tok in $allTokens) {
        $u = $tok.ToUpper()
        if ($u -in @('IIS','WEB','W3SVC','WAS','IISADMIN','WEBDAV')) {
            foreach ($p in @('ASP.NET Core','.NET')) { if (-not $dependencyPatterns.Contains($p)) { [void]$dependencyPatterns.Add($p) } }
            foreach ($s in @('W3SVC','WAS')) { if (-not $serviceNames.Contains($s)) { [void]$serviceNames.Add($s) } }
        }
        if ($u -in @('APACHE','APACHE2.4','WEB')) {
            foreach ($p in @('Apache','httpd')) { if (-not $serverPatterns.Contains($p)) { [void]$serverPatterns.Add($p) } }
            foreach ($p in @('Visual C++','OpenSSL')) { if (-not $dependencyPatterns.Contains($p)) { [void]$dependencyPatterns.Add($p) } }
            if (-not $serviceNames.Contains('Apache2.4')) { [void]$serviceNames.Add('Apache2.4') }
        }
        if ($u -in @('NGINX','WEB')) {
            if (-not $serverPatterns.Contains('nginx')) { [void]$serverPatterns.Add('nginx') }
            if (-not $dependencyPatterns.Contains('OpenSSL')) { [void]$dependencyPatterns.Add('OpenSSL') }
            if (-not $serviceNames.Contains('nginx')) { [void]$serviceNames.Add('nginx') }
        }
        if ($u -in @('SQL','DATABASE','MYSQL','MARIADB','POSTGRESQL','MSSQLSERVER')) {
            foreach ($p in @('MySQL','MariaDB','PostgreSQL','SQL Server')) { if (-not $serverPatterns.Contains($p)) { [void]$serverPatterns.Add($p) } }
            foreach ($p in @('Visual C++','.NET')) { if (-not $dependencyPatterns.Contains($p)) { [void]$dependencyPatterns.Add($p) } }
        }
        if ($u -in @('SSH','SSHD')) {
            if (-not $serverPatterns.Contains('OpenSSH')) { [void]$serverPatterns.Add('OpenSSH') }
            foreach ($p in @('PuTTY','WinSCP')) { if (-not $clientPatterns.Contains($p)) { [void]$clientPatterns.Add($p) } }
            if (-not $serviceNames.Contains('sshd')) { [void]$serviceNames.Add('sshd') }
        }
        if ($u -in @('FTP','FTPSVC','MSFTPSVC')) {
            if (-not $serverPatterns.Contains('FileZilla Server')) { [void]$serverPatterns.Add('FileZilla Server') }
            if (-not $clientPatterns.Contains('FileZilla')) { [void]$clientPatterns.Add('FileZilla') }
        }
        if ($u -in @('VPN','REMOTEACCESS','OPENVPN','WIREGUARD')) {
            foreach ($p in @('OpenVPN','WireGuard')) { if (-not $clientPatterns.Contains($p)) { [void]$clientPatterns.Add($p) } }
        }
        if ($u -in @('EMAIL','SMTP','SMTPSVC')) {
            if (-not $clientPatterns.Contains('Thunderbird')) { [void]$clientPatterns.Add('Thunderbird') }
            if (-not $serverPatterns.Contains('hMailServer')) { [void]$serverPatterns.Add('hMailServer') }
        }
        if ($u -eq 'PYTHON') {
            if (-not $dependencyPatterns.Contains('Python')) { [void]$dependencyPatterns.Add('Python') }
        }
        if ($u -in @('NODE','NODEJS')) {
            if (-not $dependencyPatterns.Contains('Node.js')) { [void]$dependencyPatterns.Add('Node.js') }
        }
        if ($u -in @('JAVA','TOMCAT')) {
            foreach ($p in @('Java','Temurin','OpenJDK')) { if (-not $dependencyPatterns.Contains($p)) { [void]$dependencyPatterns.Add($p) } }
        }
        if ($tok.Length -ge 3 -and ($abstractTokens -inotcontains $u)) {
            if (-not $clientPatterns.Contains($tok)) { [void]$clientPatterns.Add($tok) }
        }
    }
    return [PSCustomObject]@{
        ClientPatterns     = @($clientPatterns)
        DependencyPatterns = @($dependencyPatterns)
        ServerPatterns     = @($serverPatterns)
        ServiceNames       = @($serviceNames)
    }
}

function Test-MatchAgainstPatterns {
    param(
        [string[]]$Targets,
        [string[]]$Patterns
    )
    foreach ($pat in @($Patterns)) {
        $p = ([string]$pat).Trim()
        if ($p.Length -lt 2) { continue }
        $pl = $p.ToLower()
        foreach ($tgt in @($Targets)) {
            $t = ([string]$tgt).Trim()
            if ($t.Length -eq 0) { continue }
            $tl = $t.ToLower()
            if ($tl -eq $pl) { return $true }
            if ($pl.Length -ge 3 -and $tl.Contains($pl)) { return $true }
        }
    }
    return $false
}

function Format-CommandArguments {
    param([string[]]$ArgumentList)
    $quoted = @()
    foreach ($arg in @($ArgumentList)) {
        $s = [string]$arg
        if ($s.Length -eq 0) {
            $quoted += '""'
        } elseif ($s -match '[\s"]') {
            $escaped = [regex]::Replace($s, '(\\*)"', '$1$1\"')
            $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
            $quoted += ('"' + $escaped + '"')
        } else {
            $quoted += $s
        }
    }
    return ($quoted -join ' ')
}

function Invoke-ProcessCapture {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutSeconds = 120
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = Format-CommandArguments $ArgumentList
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    $timedOut = $false
    try {
        if (-not $proc.Start()) { throw ('Could not start ' + $FilePath) }
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $errTask = $proc.StandardError.ReadToEndAsync()
        $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            $timedOut = $true
            try { $proc.Kill() } catch {}
            try { [void]$proc.WaitForExit(3000) } catch {}
        } else {
            $proc.WaitForExit()
        }
        $stdout = ''
        $stderr = ''
        $waitMs = 5000
        if ($timedOut) { $waitMs = 1500 }
        try { [void]$outTask.Wait($waitMs) } catch {}
        try { [void]$errTask.Wait($waitMs) } catch {}
        if ($outTask.IsCompleted) { $stdout = [string]$outTask.Result }
        if ($errTask.IsCompleted) { $stderr = [string]$errTask.Result }
        $exitCode = -1
        if (-not $timedOut) {
            try { $exitCode = [int]$proc.ExitCode } catch {}
        }
        return [PSCustomObject]@{
            ExitCode = $exitCode
            Stdout   = $stdout
            Stderr   = $stderr
            TimedOut = $timedOut
        }
    } finally {
        try { $proc.Dispose() } catch {}
    }
}

function Resolve-WinGetPath {
    $candidates = New-Object System.Collections.ArrayList
    try {
        $cmd = Get-Command 'winget' -ErrorAction SilentlyContinue
        if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
            [void]$candidates.Add($cmd.Source)
        }
    } catch {}
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        [void]$candidates.Add((Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'))
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        try {
            $pkgDirs = @(Get-ChildItem (Join-Path $env:ProgramFiles 'WindowsApps') -Directory -Filter 'Microsoft.DesktopAppInstaller_*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
            foreach ($dir in $pkgDirs) {
                [void]$candidates.Add((Join-Path $dir.FullName 'winget.exe'))
            }
        } catch {}
    }
    foreach ($cand in $candidates) {
        if ([string]::IsNullOrWhiteSpace($cand) -or -not (Test-Path -LiteralPath $cand)) { continue }
        try {
            $res = Invoke-ProcessCapture -FilePath $cand -ArgumentList @('--version') -TimeoutSeconds 15
            if (-not $res.TimedOut -and $res.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($res.Stdout)) {
                return $cand
            }
        } catch {}
    }
    return $null
}

function Resolve-PythonPaths {
    $seen = @{}
    $paths = New-Object System.Collections.ArrayList
    $candidates = New-Object System.Collections.ArrayList
    try {
        foreach ($cmd in @(Get-Command 'python.exe' -All -ErrorAction SilentlyContinue)) {
            if ($cmd.Source) { [void]$candidates.Add($cmd.Source) }
        }
    } catch {}
    $searchGlobs = @()
    if ($env:ProgramFiles) { $searchGlobs += (Join-Path $env:ProgramFiles 'Python*\python.exe') }
    $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    if ($pf86) { $searchGlobs += (Join-Path $pf86 'Python*\python.exe') }
    if ($env:LOCALAPPDATA) { $searchGlobs += (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\python.exe') }
    $searchGlobs += 'C:\Python*\python.exe'
    foreach ($glob in $searchGlobs) {
        try {
            foreach ($item in @(Get-Item $glob -ErrorAction SilentlyContinue)) {
                [void]$candidates.Add($item.FullName)
            }
        } catch {}
    }
    foreach ($cand in $candidates) {
        if ([string]::IsNullOrWhiteSpace($cand) -or -not (Test-Path -LiteralPath $cand)) { continue }
        if ($cand -match '\\Microsoft\\WindowsApps\\') { continue }
        $key = $cand.ToLower()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        [void]$paths.Add($cand)
    }
    return @($paths)
}

function ConvertFrom-WinGetListOutput {
    param(
        [string[]]$Lines,
        [string[]]$ExportedIds = @()
    )
    $ellipsis = [string]([char]0x2026)
    $cleanLines = New-Object System.Collections.ArrayList
    foreach ($rawLine in @($Lines)) {
        $text = [string]$rawLine
        if ($text.Contains("`r")) {
            $segs = @($text -split "`r" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            if ($segs.Count -gt 0) { $text = [string]$segs[$segs.Count - 1] }
            else { $text = '' }
        }
        [void]$cleanLines.Add($text.TrimEnd())
    }
    $sepIdx = -1
    for ($i = 0; $i -lt $cleanLines.Count; $i++) {
        if (([string]$cleanLines[$i]).Trim() -match '^-{15,}$') {
            $sepIdx = $i
            break
        }
    }
    if ($sepIdx -lt 1) { return @() }
    $headerIdx = -1
    for ($h = $sepIdx - 1; $h -ge 0 -and $h -ge ($sepIdx - 3); $h--) {
        if (-not [string]::IsNullOrWhiteSpace($cleanLines[$h])) {
            $headerIdx = $h
            break
        }
    }
    if ($headerIdx -lt 0) { return @() }
    $header = [regex]::Replace([string]$cleanLines[$headerIdx], '^[\s\\|/]+(?=\S)', '')
    $colMatches = [regex]::Matches($header, '\S+')
    if ($colMatches.Count -lt 4) { return @() }

    $c0 = $colMatches[0].Index
    $c1 = $colMatches[1].Index
    $c2 = $colMatches[2].Index
    $c3 = $colMatches[3].Index
    $c4 = -1
    if ($colMatches.Count -ge 5) { $c4 = $colMatches[4].Index }

    $items = New-Object System.Collections.ArrayList
    for ($i = $sepIdx + 1; $i -lt $cleanLines.Count; $i++) {
        $row = [string]$cleanLines[$i]
        $trimmed = $row.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed -match '^\d+\s+upgrade|cannot be determined|following packages|^\s*[-\\|/]\s*$') { continue }
        if ($row.Length -lt ($c3 + 1)) { continue }

        $name = ''
        $id = ''
        $ver = ''
        $avail = ''
        $src = ''
        $sliceOk = ($row.Length -gt $c3) -and
                   ($c1 -eq 0 -or $row[$c1 - 1] -eq ' ') -and
                   ($row[$c2 - 1] -eq ' ') -and
                   ($row[$c3 - 1] -eq ' ')
        if ($sliceOk) {
            $name = $row.Substring($c0, $c1 - $c0).Trim()
            $id = $row.Substring($c1, $c2 - $c1).Trim()
            $ver = $row.Substring($c2, $c3 - $c2).Trim()
            if ($c4 -gt 0 -and $row.Length -gt $c4) {
                $avail = $row.Substring($c3, $c4 - $c3).Trim()
                $src = $row.Substring($c4).Trim()
            } else {
                $avail = $row.Substring($c3).Trim()
            }
            if ([string]::IsNullOrWhiteSpace($id) -or $id -match '\s') { $sliceOk = $false }
        }
        if (-not $sliceOk) {
            if ($trimmed -match '^(.+?)\s+(\S+)\s+((?:<\s*)?\S+)\s+((?:<\s*)?\S+)(?:\s+(\S+))?\s*$') {
                $name = $Matches[1].Trim()
                $id = $Matches[2].Trim()
                $ver = $Matches[3].Trim()
                $avail = $Matches[4].Trim()
                if ($Matches.Count -ge 6 -and $Matches[5]) { $src = $Matches[5].Trim() }
            } else {
                continue
            }
        }
        if ([string]::IsNullOrWhiteSpace($id) -or [string]::IsNullOrWhiteSpace($avail) -or $avail -ieq 'Unknown') { continue }

        $idTruncated = $false
        if ($id.EndsWith($ellipsis) -or $id.EndsWith('...')) {
            $idTruncated = $true
            $prefix = $id.TrimEnd([char]0x2026, '.')
            if ($prefix.Length -ge 3 -and @($ExportedIds).Count -gt 0) {
                $matchesId = @($ExportedIds | Where-Object { ([string]$_).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -Unique)
                if ($matchesId.Count -eq 1) {
                    $id = [string]$matchesId[0]
                    $idTruncated = $false
                }
            }
        }
        [void]$items.Add([PSCustomObject]@{
            Name        = $name
            Id          = $id
            Version     = $ver
            Available   = $avail
            Source      = $src
            IdTruncated = $idTruncated
        })
    }
    return @($items)
}

function Select-UpdatablePackages {
    param(
        [object[]]$UpgradablePackages = @(),
        [string[]]$NecessaryList = @(),
        [string[]]$ExcludedList = @(),
        [string[]]$ProhibitedList = @(),
        [string[]]$KeepEntries = @(),
        [string[]]$KeptChoices = @(),
        [bool]$PaidAcrobatDetected = $false
    )
    $catalog = @(Get-KnownAppDependencyCatalog)
    $byId = @{}
    foreach ($entry in $catalog) { $byId[$entry.Id.ToLower()] = $entry }

    $svcDerived = Get-NecessaryAppsFromServices -KeepEntries $KeepEntries -KeptChoices $KeptChoices
    $depPattern = '^(Microsoft\.AppInstaller|Microsoft\.VCRedist\.|Microsoft\.DotNet\.|Microsoft\.EdgeWebView2Runtime|Microsoft\.DirectX|Microsoft\.PowerShell|EclipseAdoptium\.|Microsoft\.OpenJDK\.|Oracle\.(Java|JDK)|Amazon\.Corretto\.|Azul\.Zulu\.|Python\.(Python\.|Launcher)|OpenJS\.NodeJS|Git\.Git|(ShiningLight|FireDaemon)\.OpenSSL)'
    $essentialPattern = '^(Google\.Chrome|Mozilla\.Firefox|Microsoft\.Edge|Notepad\+\+\.Notepad\+\+|Adobe\.Acrobat\.Reader\.(64-bit|32-bit)|VideoLAN\.VLC|7zip\.7zip|TheDocumentFoundation\.LibreOffice|Mozilla\.Thunderbird|Microsoft\.VisualStudioCode|PuTTY\.PuTTY|WinSCP\.WinSCP|TimKosse\.FileZilla\.Client|GIMP\.GIMP|DominikReichl\.KeePass|KeePassXCTeam\.KeePassXC|Brave\.Brave|Opera\.Opera|Vivaldi\.Vivaldi|SumatraPDF\.SumatraPDF|Microsoft\.WindowsTerminal|Microsoft\.Sysinternals\.Suite|WireGuard\.WireGuard|OpenVPNTechnologies\.OpenVPN)$'
    $serverPattern = '^(ApacheLounge\.httpd|Apache\.|Nginx\.nginx|Oracle\.MySQL|MariaDB\.Server|PostgreSQL\.PostgreSQL|Microsoft\.SQLServer|TimKosse\.FileZilla\.Server|Microsoft\.OpenSSH|Win32OpenSSH\.OpenSSH)'

    $deps = New-Object System.Collections.ArrayList
    $necessary = New-Object System.Collections.ArrayList
    $servers = New-Object System.Collections.ArrayList
    $other = New-Object System.Collections.ArrayList
    $skippedProhibited = New-Object System.Collections.ArrayList
    $skippedPinned = New-Object System.Collections.ArrayList
    $skippedAcrobat = New-Object System.Collections.ArrayList

    $seenIds = @{}
    foreach ($pkg in @($UpgradablePackages)) {
        if ($null -eq $pkg) { continue }
        $id = [string]$pkg.Id
        if ([string]::IsNullOrWhiteSpace($id)) { continue }
        $idLower = $id.ToLower()
        if ($seenIds.ContainsKey($idLower)) { continue }
        $seenIds[$idLower] = $true

        $name = [string]$pkg.Name
        if ([string]::IsNullOrWhiteSpace($name)) { $name = $id }
        $catEntry = $null
        if ($byId.ContainsKey($idLower)) { $catEntry = $byId[$idLower] }

        $targets = @($name, $id)
        if ($null -ne $catEntry) { $targets += @($catEntry.Aliases) }
        $label = $name
        if ($null -ne $catEntry) { $label = $catEntry.Label }

        $explicitNecessary = Test-MatchAgainstPatterns -Targets $targets -Patterns $NecessaryList
        $isProhibited = Test-MatchAgainstPatterns -Targets $targets -Patterns $ProhibitedList
        if ($isProhibited) {
            [void]$skippedProhibited.Add([PSCustomObject]@{
                Id                  = $id
                Name                = $name
                Label               = $label
                Version             = [string]$pkg.Version
                Available           = [string]$pkg.Available
                ConflictWithNecessary = $explicitNecessary
            })
            continue
        }

        $isPinned = Test-MatchAgainstPatterns -Targets $targets -Patterns $ExcludedList
        if ($isPinned) {
            [void]$skippedPinned.Add([PSCustomObject]@{
                Id        = $id
                Name      = $name
                Label     = $label
                Version   = [string]$pkg.Version
                Available = [string]$pkg.Available
            })
            continue
        }

        if ($PaidAcrobatDetected -and $id -like 'Adobe.Acrobat.Reader*') {
            [void]$skippedAcrobat.Add([PSCustomObject]@{
                Id        = $id
                Name      = $name
                Label     = $label
                Version   = [string]$pkg.Version
                Available = [string]$pkg.Available
            })
            continue
        }

        $procNames = @()
        $svcNames = @()
        if ($null -ne $catEntry) {
            $procNames = @($catEntry.ProcessNames)
            $svcNames = @($catEntry.ServiceNames)
        }
        $pkgObj = [PSCustomObject]@{
            Id                = $id
            Name              = $name
            Label             = $label
            Version           = [string]$pkg.Version
            Available         = [string]$pkg.Available
            Source            = [string]$pkg.Source
            ExplicitNecessary = $explicitNecessary
            IdTruncated       = [bool]$pkg.IdTruncated
            ProcessNames      = $procNames
            ServiceNames      = $svcNames
        }

        $isServerDaemon = ($id -match $serverPattern) -or
                          ($null -ne $catEntry -and $catEntry.Category -eq 'ServerDaemon') -or
                          (Test-MatchAgainstPatterns -Targets $targets -Patterns $svcDerived.ServerPatterns)
        if ($isServerDaemon) {
            [void]$servers.Add($pkgObj)
            continue
        }

        $isDependency = ($id -match $depPattern) -or
                        ($null -ne $catEntry -and $catEntry.Category -eq 'Dependency') -or
                        (Test-MatchAgainstPatterns -Targets $targets -Patterns $svcDerived.DependencyPatterns)
        if ($isDependency) {
            [void]$deps.Add($pkgObj)
            continue
        }

        $isNecessaryApp = $explicitNecessary -or
                          ($id -match $essentialPattern) -or
                          ($null -ne $catEntry -and $catEntry.Category -eq 'NecessaryApp') -or
                          (Test-MatchAgainstPatterns -Targets $targets -Patterns $svcDerived.ClientPatterns)
        if ($isNecessaryApp) {
            [void]$necessary.Add($pkgObj)
            continue
        }

        [void]$other.Add($pkgObj)
    }

    return [PSCustomObject]@{
        Dependencies         = @($deps)
        NecessaryApps        = @($necessary)
        CriticalServerApps   = @($servers)
        OtherApps            = @($other)
        SkippedProhibited    = @($skippedProhibited)
        SkippedPinned        = @($skippedPinned)
        SkippedAcrobatMismatch = @($skippedAcrobat)
    }
}

function Get-UnmappedNecessaryApps {
    param(
        [string[]]$NecessaryList = @(),
        [string[]]$ExcludedList = @(),
        [string[]]$ProhibitedList = @(),
        [object[]]$InstalledPrograms = @(),
        [string[]]$TrackedWinGetIds = @(),
        [object[]]$TrackedWinGetPackages = @()
    )
    $catalog = @(Get-KnownAppDependencyCatalog)
    $unmapped = New-Object System.Collections.ArrayList
    $seenDisplay = @{}
    foreach ($entry in @($NecessaryList)) {
        $req = ([string]$entry).Trim()
        if ($req.Length -lt 2) { continue }
        $reqTargets = @($req)
        foreach ($cat in $catalog) {
            $catTargets = @($cat.Id, $cat.Label) + @($cat.Aliases)
            if (Test-MatchAgainstPatterns -Targets $catTargets -Patterns @($req)) {
                $reqTargets += $catTargets
            }
        }
        $reqTargets = @($reqTargets | Select-Object -Unique)
        if (Test-MatchAgainstPatterns -Targets $reqTargets -Patterns $ExcludedList) { continue }
        if (Test-MatchAgainstPatterns -Targets $reqTargets -Patterns $ProhibitedList) { continue }

        $matchedWinGet = $false
        foreach ($wgId in @($TrackedWinGetIds)) {
            if (Test-MatchAgainstPatterns -Targets @($wgId) -Patterns $reqTargets) { $matchedWinGet = $true; break }
        }
        if (-not $matchedWinGet) {
            foreach ($pkg in @($TrackedWinGetPackages)) {
                if (Test-MatchAgainstPatterns -Targets @([string]$pkg.Name, [string]$pkg.Id) -Patterns $reqTargets) { $matchedWinGet = $true; break }
            }
        }
        if ($matchedWinGet) { continue }

        foreach ($prog in @($InstalledPrograms)) {
            $disp = [string]$prog.DisplayName
            if ([string]::IsNullOrWhiteSpace($disp)) { continue }
            if (Test-MatchAgainstPatterns -Targets @($disp) -Patterns $ProhibitedList) { continue }
            if (Test-MatchAgainstPatterns -Targets @($disp) -Patterns $ExcludedList) { continue }
            if (Test-MatchAgainstPatterns -Targets @($disp) -Patterns $reqTargets) {
                $key = $disp.ToLower()
                if (-not $seenDisplay.ContainsKey($key)) {
                    $seenDisplay[$key] = $true
                    [void]$unmapped.Add([PSCustomObject]@{
                        RequestedEntry = $req
                        DisplayName    = $disp
                        DisplayVersion = [string]$prog.DisplayVersion
                        Publisher      = [string]$prog.Publisher
                    })
                }
            }
        }
    }
    return @($unmapped)
}

function Repair-UpdateInfrastructure {
    Write-Step 'Checking Windows Update, Store, Office, and vendor updater dependencies...'
    $serviceTargets = @(
        @{ Name='wuauserv'; Target='Manual'; Desc='Windows Update' },
        @{ Name='BITS'; Target='Manual'; Desc='Background Intelligent Transfer' },
        @{ Name='UsoSvc'; Target='Manual'; Desc='Update Orchestrator' },
        @{ Name='DoSvc'; Target='Manual'; Desc='Delivery Optimization' },
        @{ Name='CryptSvc'; Target='Automatic'; Desc='Cryptographic Services' },
        @{ Name='TrustedInstaller'; Target='Manual'; Desc='Windows Modules Installer' },
        @{ Name='msiserver'; Target='Manual'; Desc='Windows Installer' },
        @{ Name='InstallService'; Target='Manual'; Desc='Microsoft Store Install Service' },
        @{ Name='AppXSvc'; Target='Manual'; Desc='AppX Deployment Service' },
        @{ Name='WaaSMedicSvc'; Target='Manual'; Desc='Windows Update Medic Service' }
    )
    foreach ($item in $serviceTargets) {
        $svc = Get-Service -Name $item.Name -ErrorAction SilentlyContinue
        if ($null -eq $svc -or $svc.StartType -ne 'Disabled') { continue }
        if ($script:AuditOnly) {
            Write-Host ("[AUDIT] Update dependency service " + $item.Name + " (" + $item.Desc + ") is Disabled - would set to " + $item.Target + ".")
        } else {
            try {
                Set-Service -Name $item.Name -StartupType $item.Target -ErrorAction Stop
                Write-Good ("Re-enabled update dependency service (was Disabled): " + $item.Name + " -> " + $item.Target)
            } catch {
                if ($item.Name -ne 'WaaSMedicSvc') {
                    Write-WarnLine ("Could not repair update dependency service " + $item.Name + ": " + $_.Exception.Message)
                }
            }
        }
    }

    # Check update-blocking policies (WSUS hijack, Store off, AppInstaller off)
    $wuPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $useWU = Get-RegValue ($wuPol + '\AU') 'UseWUServer'
    $wuServer = Get-RegValue $wuPol 'WUServer'
    if ("$useWU" -eq '1') {
        Write-Step ("WSUS policy active (UseWUServer=1, WUServer=" + $wuServer + ").")
        if ("$wuServer" -match '127\.0\.0\.1|localhost|0\.0\.0\.0') {
            Write-WarnLine ("Suspicious WSUS server URL points to localhost (" + $wuServer + "). This can block all updates unless intentional.")
        }
    } else {
        $noInet = Get-RegValue $wuPol 'DoNotConnectToWindowsUpdateInternetLocations'
        if ("$noInet" -eq '1') {
            Set-RegValue $wuPol 'DoNotConnectToWindowsUpdateInternetLocations' 0 'DWord' 'Allow Windows Update internet locations'
        }
    }

    $storePol = 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore'
    $storeAuto = Get-RegValue $storePol 'AutoDownload'
    if ("$storeAuto" -eq '2') {
        Set-RegValue $storePol 'AutoDownload' 4 'DWord' 'Re-enable Microsoft Store automatic app updates'
    }

    $appInstPol = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
    $appInstEnabled = Get-RegValue $appInstPol 'EnableAppInstaller'
    if ("$appInstEnabled" -eq '0') {
        Set-RegValue $appInstPol 'EnableAppInstaller' 1 'DWord' 'Re-enable App Installer (WinGet)'
    }

    # Office Click-to-Run has its own supported update task. Repair/start
    # that task rather than calling OfficeC2RClient.exe switches, which
    # Microsoft does not support for automation. Starting the task checks
    # and stages updates; it does not force-close Office applications.
    try {
        $officeTask = $null
        try { $officeTask = Get-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction Stop } catch {}
        $officeSvc = Get-Service -Name 'ClickToRunSvc' -ErrorAction SilentlyContinue
        if ($null -ne $officeTask -or $null -ne $officeSvc) {
            $officePolicy = 'HKLM\SOFTWARE\Policies\Microsoft\Office\16.0\common\OfficeUpdate'
            $officeAuto = Get-RegValue $officePolicy 'EnableAutomaticUpdates'
            if ("$officeAuto" -eq '0') {
                Set-RegValue $officePolicy 'EnableAutomaticUpdates' 1 'DWord' 'Re-enable automatic Office updates'
            }
            if ($null -ne $officeSvc -and $officeSvc.StartType -eq 'Disabled') {
                if ($script:AuditOnly) { Write-Host '[AUDIT] Office ClickToRunSvc is Disabled - would set it to Manual so the Office update task can run.' }
                else {
                    try {
                        Set-Service -Name 'ClickToRunSvc' -StartupType Manual -ErrorAction Stop
                        Write-Good 'Office ClickToRunSvc was Disabled; set to Manual for Office updates.'
                    } catch { Write-WarnLine ("Could not repair ClickToRunSvc: " + $_.Exception.Message) }
                }
            }
            if ($null -ne $officeTask) {
                if ($officeTask.State -eq 'Disabled') {
                    if ($script:AuditOnly) { Write-Host '[AUDIT] Office Automatic Updates 2.0 task is Disabled - would enable it.' }
                    else {
                        try {
                            Enable-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction Stop | Out-Null
                            Write-Good 'Office Automatic Updates 2.0 scheduled task enabled.'
                            $officeTask = Get-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction SilentlyContinue
                        } catch { Write-WarnLine ("Could not enable the Office update task: " + $_.Exception.Message) }
                    }
                }
                if ($script:AuditOnly) {
                    Write-Host '[AUDIT] Would start the supported Office Automatic Updates 2.0 task.'
                } elseif ($null -ne $officeTask -and $officeTask.State -eq 'Running') {
                    Write-Step 'Office Automatic Updates 2.0 is already running.'
                } elseif (Confirm-YesNo 'Start the supported Office Automatic Updates 2.0 check now? It stages updates without force-closing Office.' $true) {
                    try {
                        Start-ScheduledTask -TaskPath '\Microsoft\Office\' -TaskName 'Office Automatic Updates 2.0' -ErrorAction Stop
                        Write-Good 'Office Automatic Updates 2.0 started; close and reopen Office apps when convenient to finish applying updates.'
                    } catch { Write-WarnLine ("Could not start the Office update task: " + $_.Exception.Message) }
                }
            }
        }
    } catch { Write-WarnLine 'Office update task check stopped safely; update Office from File > Account > Update Options.' }

    # Vendor updater services (including Chromium Omaha 4 services)
    foreach ($updater in @(
        @{ Name='gupdate'; Target='Automatic'; Product='Google Chrome' },
        @{ Name='gupdatem'; Target='Manual'; Product='Google Chrome' },
        @{ Name='edgeupdate'; Target='Automatic'; Product='Microsoft Edge' },
        @{ Name='edgeupdatem'; Target='Manual'; Product='Microsoft Edge' },
        @{ Name='MozillaMaintenance'; Target='Manual'; Product='Mozilla Firefox' },
        @{ Name='AdobeARMservice'; Target='Automatic'; Product='Adobe Acrobat/Reader' }
    )) {
        $updaterSvc = Get-Service -Name $updater.Name -ErrorAction SilentlyContinue
        if ($null -eq $updaterSvc -or $updaterSvc.StartType -ne 'Disabled') { continue }
        if ($script:AuditOnly) {
            Write-Host ("[AUDIT] " + $updater.Product + " updater service " + $updater.Name + " is Disabled - would set it to " + $updater.Target + ".")
        } else {
            try {
                Set-Service -Name $updater.Name -StartupType $updater.Target -ErrorAction Stop
                Write-Good ($updater.Product + " updater service repaired: " + $updater.Name + " set to " + $updater.Target + ".")
            } catch { Write-WarnLine ("Could not repair updater service " + $updater.Name + ": " + $_.Exception.Message) }
        }
    }
    try {
        foreach ($extraUpdater in @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^GoogleUpdater(Internal)?Service' -and $_.StartType -eq 'Disabled' })) {
            if ($script:AuditOnly) {
                Write-Host ("[AUDIT] Google Chrome updater service " + $extraUpdater.Name + " is Disabled - would set to Automatic.")
            } else {
                try {
                    Set-Service -Name $extraUpdater.Name -StartupType Automatic -ErrorAction Stop
                    Write-Good ("Google Chrome updater service repaired: " + $extraUpdater.Name + " set to Automatic.")
                } catch {}
            }
        }
    } catch {}

    # Vendor updater scheduled tasks (often disabled alongside services)
    if (Test-CommandExists 'Get-ScheduledTask') {
        try {
            $updaterTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
                $_.State -eq 'Disabled' -and (
                    $_.TaskName -like 'GoogleUpdateTaskMachine*' -or
                    $_.TaskName -like 'GoogleUpdaterTaskSystem*' -or
                    $_.TaskName -like 'MicrosoftEdgeUpdateTaskMachine*' -or
                    $_.TaskName -like 'Firefox Background Update*' -or
                    $_.TaskName -like 'Adobe Acrobat Update Task*'
                )
            })
            foreach ($ut in $updaterTasks) {
                if ($script:AuditOnly) {
                    Write-Host ("[AUDIT] Vendor updater task is Disabled - would enable: " + $ut.TaskPath + $ut.TaskName)
                } else {
                    try {
                        Enable-ScheduledTask -TaskPath $ut.TaskPath -TaskName $ut.TaskName -ErrorAction Stop | Out-Null
                        Write-Good ("Enabled vendor updater task: " + $ut.TaskPath + $ut.TaskName)
                    } catch { Write-WarnLine ("Could not enable updater task " + $ut.TaskName + ": " + $_.Exception.Message) }
                }
            }
        } catch {}
    }

    # Vendor updater blocking policies (only repaired when already explicitly blocking)
    $googlePol = 'HKLM\SOFTWARE\Policies\Google\Update'
    if ("$(Get-RegValue $googlePol 'UpdateDefault')" -eq '0') { Set-RegValue $googlePol 'UpdateDefault' 1 'DWord' 'Re-enable Google Chrome updates' }
    if ("$(Get-RegValue $googlePol 'DisableAutoUpdateChecksCheckboxValue')" -eq '1') { Set-RegValue $googlePol 'DisableAutoUpdateChecksCheckboxValue' 0 'DWord' 'Re-enable Google Chrome update checks' }
    if ("$(Get-RegValue $googlePol 'AutoUpdateCheckPeriodMinutes')" -eq '0') { Set-RegValue $googlePol 'AutoUpdateCheckPeriodMinutes' 295 'DWord' 'Restore Google Chrome update check interval' }

    $edgePol = 'HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate'
    if ("$(Get-RegValue $edgePol 'UpdateDefault')" -eq '0') { Set-RegValue $edgePol 'UpdateDefault' 1 'DWord' 'Re-enable Microsoft Edge updates' }
    if ("$(Get-RegValue $edgePol 'AutoUpdateCheckPeriodMinutes')" -eq '0') { Set-RegValue $edgePol 'AutoUpdateCheckPeriodMinutes' 295 'DWord' 'Restore Microsoft Edge update check interval' }

    $ffPol = 'HKLM\SOFTWARE\Policies\Mozilla\Firefox'
    if ("$(Get-RegValue $ffPol 'DisableAppUpdate')" -eq '1') { Set-RegValue $ffPol 'DisableAppUpdate' 0 'DWord' 'Re-enable Mozilla Firefox updates' }
    if ("$(Get-RegValue $ffPol 'AppAutoUpdate')" -eq '0') { Set-RegValue $ffPol 'AppAutoUpdate' 1 'DWord' 'Re-enable Mozilla Firefox auto-updates' }

    foreach ($adobePol in @('HKLM\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown','HKLM\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown')) {
        if ("$(Get-RegValue $adobePol 'bUpdater')" -eq '0') { Set-RegValue $adobePol 'bUpdater' 1 'DWord' 'Re-enable Adobe updater' }
    }
}

function Initialize-WinGetReady {
    $wg = Resolve-WinGetPath
    if ($null -eq $wg -and -not $script:AuditOnly) {
        if (Test-CommandExists 'Add-AppxPackage') {
            try {
                Add-AppxPackage -RegisterByFamilyName -MainPackage 'Microsoft.DesktopAppInstaller_8wekyb3d8bbwe' -ErrorAction Stop | Out-Null
                $wg = Resolve-WinGetPath
                if ($null -ne $wg) { Write-Good 'Registered built-in Microsoft App Installer (WinGet).' }
            } catch {}
        }
        if ($null -eq $wg -and (Test-CommandExists 'Repair-WinGetPackageManager')) {
            try {
                Repair-WinGetPackageManager -AllUsers -ErrorAction Stop | Out-Null
                $wg = Resolve-WinGetPath
                if ($null -ne $wg) { Write-Good 'Repaired WinGet via Microsoft.WinGet.Client.' }
            } catch {}
        }
        if ($null -eq $wg -and (Test-CommandExists 'Add-AppxPackage')) {
            if (Confirm-YesNo 'WinGet (Microsoft.DesktopAppInstaller) is missing. Download and install official Microsoft-signed WinGet + VCLibs/UI.Xaml dependencies now?' $true) {
                $tmpDir = Join-Path $env:TEMP ('cp-winget-' + $script:Stamp)
                try {
                    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
                    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                    $arch = 'x64'
                    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { $arch = 'arm64' }
                    $vclibsPath = Join-Path $tmpDir 'Microsoft.VCLibs.Desktop.appx'
                    $vclibsUrl = 'https://aka.ms/Microsoft.VCLibs.' + $arch + '.14.00.Desktop.appx'
                    Invoke-WebRequest -Uri $vclibsUrl -OutFile $vclibsPath -UseBasicParsing -ErrorAction Stop
                    $vcSig = Get-AuthenticodeSignature -FilePath $vclibsPath -ErrorAction Stop
                    if ($vcSig.Status -eq 'Valid' -and $vcSig.SignerCertificate.Subject -match 'Microsoft') {
                        Add-AppxPackage -Path $vclibsPath -ErrorAction SilentlyContinue
                    }
                    $msixPath = Join-Path $tmpDir 'Microsoft.DesktopAppInstaller.msixbundle'
                    Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile $msixPath -UseBasicParsing -ErrorAction Stop
                    $msixSig = Get-AuthenticodeSignature -FilePath $msixPath -ErrorAction Stop
                    if ($msixSig.Status -ne 'Valid' -or $msixSig.SignerCertificate.Subject -notmatch 'Microsoft') {
                        throw 'Downloaded AppInstaller package failed Microsoft Authenticode signature verification.'
                    }
                    Add-AppxPackage -Path $msixPath -ErrorAction Stop
                    $wg = Resolve-WinGetPath
                    if ($null -ne $wg) { Write-Good 'Installed official Microsoft-signed WinGet and its dependencies.' }
                } catch {
                    Write-WarnLine ("WinGet bootstrap did not succeed (offline or missing dependency): " + $_.Exception.Message)
                } finally {
                    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
    if ($null -ne $wg -and -not $script:AuditOnly) {
        $srcArgs = @('source','update','--name','winget')
        if ($script:WinGetSupportsNonInteractive) { $srcArgs += '--disable-interactivity' }
        try {
            $srcRes = Invoke-ProcessCapture -FilePath $wg -ArgumentList $srcArgs -TimeoutSeconds 90
            if ($srcRes.ExitCode -eq -1978335229 -or $srcRes.ExitCode -eq -1978335231) {
                $script:WinGetSupportsNonInteractive = $false
                $srcRes = Invoke-ProcessCapture -FilePath $wg -ArgumentList @('source','update','--name','winget') -TimeoutSeconds 90
            }
            if ($srcRes.ExitCode -eq 0) { Write-Step 'WinGet package index updated.' }
            else { Write-Step ('WinGet source update returned code ' + $srcRes.ExitCode + ' (continuing with available catalog).') }
        } catch { Write-WarnLine ("WinGet source update failed: " + $_.Exception.Message) }
    }
    return $wg
}

function Get-WinGetExportedIds {
    param([string]$WinGetExe)
    if ([string]::IsNullOrWhiteSpace($WinGetExe)) { return @() }
    $tmpJson = Join-Path $env:TEMP ('cp-winget-export-' + [guid]::NewGuid().ToString() + '.json')
    try {
        $expArgs = @('export','-o',$tmpJson,'--source','winget','--accept-source-agreements')
        if ($script:WinGetSupportsNonInteractive) { $expArgs += '--disable-interactivity' }
        $res = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList $expArgs -TimeoutSeconds 90
        if (($res.ExitCode -eq -1978335229 -or $res.ExitCode -eq -1978335231) -and $script:WinGetSupportsNonInteractive) {
            $script:WinGetSupportsNonInteractive = $false
            $res = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList @('export','-o',$tmpJson,'--source','winget','--accept-source-agreements') -TimeoutSeconds 90
        }
        if (-not (Test-Path -LiteralPath $tmpJson)) { return @() }
        $data = Get-Content -LiteralPath $tmpJson -Raw -ErrorAction Stop | ConvertFrom-Json
        $ids = New-Object System.Collections.ArrayList
        foreach ($src in @($data.Sources)) {
            foreach ($pkg in @($src.Packages)) {
                $pidStr = [string]$pkg.PackageIdentifier
                if (-not [string]::IsNullOrWhiteSpace($pidStr)) { [void]$ids.Add($pidStr) }
            }
        }
        return @($ids | Select-Object -Unique)
    } catch {
        return @()
    } finally {
        Remove-Item -LiteralPath $tmpJson -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-WinGetListUpgrades {
    param(
        [string]$WinGetExe,
        [string[]]$ExportedIds = @(),
        [object[]]$InstalledPrograms = @()
    )
    $found = New-Object System.Collections.ArrayList
    $seen = @{}

    # Fast structured path if Microsoft.WinGet.Client is available
    if (Test-CommandExists 'Get-WinGetPackage') {
        try {
            $wgPkgs = @(Get-WinGetPackage -Source 'winget' -ErrorAction Stop | Where-Object { $_.IsUpdateAvailable })
            foreach ($p in $wgPkgs) {
                $id = [string]$p.Id
                if ([string]::IsNullOrWhiteSpace($id)) { continue }
                $avail = ''
                if (@($p.AvailableVersions).Count -gt 0) { $avail = [string]$p.AvailableVersions[0] }
                $seen[$id.ToLower()] = $true
                [void]$found.Add([PSCustomObject]@{
                    Name        = [string]$p.Name
                    Id          = $id
                    Version     = [string]$p.InstalledVersion
                    Available   = $avail
                    Source      = 'winget'
                    IdTruncated = $false
                })
            }
            return @($found)
        } catch {}
    }

    $listArgs = @('list','--upgrade-available','--source','winget','--accept-source-agreements')
    if ($script:WinGetSupportsNonInteractive) { $listArgs += '--disable-interactivity' }
    $res = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList $listArgs -TimeoutSeconds 120
    if (($res.ExitCode -eq -1978335229 -or $res.ExitCode -eq -1978335231) -and $script:WinGetSupportsNonInteractive) {
        $script:WinGetSupportsNonInteractive = $false
        $res = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList @('list','--upgrade-available','--source','winget','--accept-source-agreements') -TimeoutSeconds 120
    }
    if ($res.TimedOut) {
        Write-WarnLine 'WinGet upgrade query timed out; continuing with any detected updates.'
        return @()
    }
    $rawLines = @($res.Stdout -split "\r?\n")
    $parsed = @(ConvertFrom-WinGetListOutput -Lines $rawLines -ExportedIds $ExportedIds)
    foreach ($item in $parsed) {
        $id = [string]$item.Id
        $stillTruncated = [bool]$item.IdTruncated
        if ($stillTruncated -and $id.Length -gt 3) {
            $prefix = $id.TrimEnd([char]0x2026, '.')
            $expMatches = @($ExportedIds | Where-Object { ([string]$_).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) } | Select-Object -Unique)
            if ($expMatches.Count -eq 1) {
                $id = [string]$expMatches[0]
                $stillTruncated = $false
            } elseif ($expMatches.Count -gt 1) {
                foreach ($candId in $expMatches) {
                    if ($seen.ContainsKey($candId.ToLower())) { continue }
                    $cArgs = @('list','--id',$candId,'--exact','--upgrade-available','--source','winget','--accept-source-agreements')
                    if ($script:WinGetSupportsNonInteractive) { $cArgs += '--disable-interactivity' }
                    try {
                        $cRes = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList $cArgs -TimeoutSeconds 30
                        if (-not $cRes.TimedOut -and $cRes.ExitCode -eq 0) {
                            $cParsed = @(ConvertFrom-WinGetListOutput -Lines ($cRes.Stdout -split "\r?\n") -ExportedIds @($candId))
                            foreach ($cp in $cParsed) {
                                if ($cp.Id -ieq $candId -and -not $seen.ContainsKey($candId.ToLower())) {
                                    $seen[$candId.ToLower()] = $true
                                    [void]$found.Add($cp)
                                    $stillTruncated = $false
                                }
                            }
                        }
                    } catch {}
                }
                if (-not $stillTruncated) { continue }
            }
            if ($stillTruncated) {
                $catMatches = @(Get-KnownAppDependencyCatalog | Where-Object { $_.Id.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
                if ($catMatches.Count -eq 1) {
                    $id = $catMatches[0].Id
                    $stillTruncated = $false
                }
            }
        }
        if ($seen.ContainsKey($id.ToLower())) { continue }
        $seen[$id.ToLower()] = $true
        [void]$found.Add([PSCustomObject]@{
            Name        = $item.Name
            Id          = $id
            Version     = $item.Version
            Available   = $item.Available
            Source      = $item.Source
            IdTruncated = $stillTruncated
        })
    }

    # Targeted fallback ONLY for installed catalog/necessary apps not already in WinGet's upgrade/export output
    $exportedLookup = @{}
    foreach ($eid in @($ExportedIds)) { $exportedLookup[([string]$eid).ToLower()] = $true }
    $installedNames = @($InstalledPrograms | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ })
    foreach ($cat in @(Get-KnownAppDependencyCatalog)) {
        if ($seen.ContainsKey($cat.Id.ToLower())) { continue }
        if ($exportedLookup.ContainsKey($cat.Id.ToLower())) { continue }
        $isInstalled = $false
        foreach ($dp in @($cat.DetectPaths)) {
            if (-not [string]::IsNullOrWhiteSpace($dp) -and (Test-Path -LiteralPath $dp)) { $isInstalled = $true; break }
        }
        if (-not $isInstalled -and $installedNames.Count -gt 0) {
            if (Test-MatchAgainstPatterns -Targets $installedNames -Patterns $cat.Aliases) { $isInstalled = $true }
        }
        if (-not $isInstalled) { continue }
        $tArgs = @('list','--id',$cat.Id,'--exact','--upgrade-available','--source','winget','--accept-source-agreements')
        if ($script:WinGetSupportsNonInteractive) { $tArgs += '--disable-interactivity' }
        try {
            $tRes = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList $tArgs -TimeoutSeconds 45
            if (-not $tRes.TimedOut -and $tRes.ExitCode -eq 0) {
                $tParsed = @(ConvertFrom-WinGetListOutput -Lines ($tRes.Stdout -split "\r?\n") -ExportedIds @($cat.Id))
                foreach ($tp in $tParsed) {
                    if ($tp.Id -ieq $cat.Id -and -not $seen.ContainsKey($cat.Id.ToLower())) {
                        $seen[$cat.Id.ToLower()] = $true
                        [void]$found.Add($tp)
                    }
                }
            }
        } catch {}
    }

    return @($found)
}

function Update-WinGetPackageSafe {
    param(
        [string]$WinGetExe,
        [object]$Package
    )
    $label = [string]$Package.Label
    $id = [string]$Package.Id
    if ($Package.IdTruncated -or $id.EndsWith([string]([char]0x2026)) -or $id.EndsWith('...')) {
        Write-WarnLine ("Skipping " + $label + ": WinGet package ID (" + $id + ") was truncated in output; update manually or list exact WinGet ID in necessary_apps.txt.")
        return $false
    }
    Write-Step ("Updating " + $label + " (" + $id + ": " + $Package.Version + " -> " + $Package.Available + ")...")

    $runningProcs = @()
    foreach ($pn in @($Package.ProcessNames)) {
        try {
            if (Get-Process -Name $pn -ErrorAction SilentlyContinue) { $runningProcs += $pn }
        } catch {}
    }
    if ($runningProcs.Count -gt 0) {
        Write-Step ("  Note: " + ($runningProcs -join ', ') + " is currently running (never force-closed); close/reopen normally afterward to load the new version.")
    }

    $upArgs = @('upgrade','--id',$id,'--exact','--source','winget','--silent','--accept-source-agreements','--accept-package-agreements')
    if ($script:WinGetSupportsNonInteractive) { $upArgs += '--disable-interactivity' }
    try {
        $res = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList $upArgs -TimeoutSeconds 600
        if (($res.ExitCode -eq -1978335229 -or $res.ExitCode -eq -1978335231) -and $script:WinGetSupportsNonInteractive) {
            $script:WinGetSupportsNonInteractive = $false
            $res = Invoke-ProcessCapture -FilePath $WinGetExe -ArgumentList @('upgrade','--id',$id,'--exact','--source','winget','--silent','--accept-source-agreements','--accept-package-agreements') -TimeoutSeconds 600
        }
        if ($res.TimedOut) {
            Write-WarnLine ("WinGet update timed out for " + $label + " (" + $id + "). Check installer state or update manually.")
            Add-Report 'app-updates.txt' ("Timed out: " + $label + " (" + $id + ")") ($res.Stdout + "`r`n" + $res.Stderr)
            return $false
        }
        $code = $res.ExitCode
        if ($code -eq 0) {
            Write-Good ("Updated with WinGet: " + $label + " (" + $Package.Version + " -> " + $Package.Available + ")")
            Add-Report 'app-updates.txt' ("Updated: " + $label + " (" + $id + ")") ($Package.Version + " -> " + $Package.Available)
            return $true
        } elseif ($code -eq 3010) {
            Write-Good ("Updated with WinGet: " + $label + " (reboot pending; reboot only when YOU choose)")
            [void]$script:PendingRebootReasons.Add($label + ' (' + $id + ')')
            Add-Report 'app-updates.txt' ("Updated (reboot pending): " + $label + " (" + $id + ")") ($Package.Version + " -> " + $Package.Available)
            return $true
        } elseif ($code -eq -1978335189 -or $code -eq 2316632107 -or $code -eq -1978335212 -or $code -eq 2316632084) {
            Write-Step ($label + " is already current according to WinGet.")
            return $false
        } elseif ($code -eq 1641) {
            Write-WarnLine ($label + " installer initiated a reboot; save work now.")
            [void]$script:PendingRebootReasons.Add($label + ' (installer 1641)')
            return $true
        } elseif ($code -eq -1978335157 -or $code -eq 2316632139 -or $code -eq 1618) {
            Write-WarnLine ($label + " could not update while in use or another install is running (exit " + $code + "). Close the app and retry.")
            return $false
        } elseif ($code -eq -1978335185 -or $code -eq 2316632111) {
            Write-WarnLine ($label + " installer prohibits elevated execution (per-user install). Update from the app's Help > About screen as the signed-in user.")
            return $false
        } else {
            Write-WarnLine ("WinGet update for " + $label + " returned exit code " + $code + ". Update via Help > About or vendor updater.")
            Add-Report 'app-updates.txt' ("Failed (" + $code + "): " + $label + " (" + $id + ")") ($res.Stdout + "`r`n" + $res.Stderr)
            return $false
        }
    } catch {
        Write-WarnLine ("WinGet update failed for " + $label + ": " + $_.Exception.Message)
        return $false
    }
}

function Update-EcosystemDependencies {
    param(
        [string[]]$ExcludedList = @(),
        [string[]]$ProhibitedList = @()
    )
    Write-Step 'Checking Store, PowerShell module, Python, Node.js, and .NET dependencies...'

    # 1. Microsoft Store / UWP app and framework update scan (non-disruptive)
    if (-not $script:IsServer) {
        if ($script:AuditOnly) {
            Write-Host '[AUDIT] Would trigger Microsoft Store app and framework update scan (MDM UpdateScanMethod).'
        } elseif (Confirm-YesNo 'Trigger a Microsoft Store app & framework dependency update scan in the background?' $true) {
            try {
                $appMgmt = Get-CimInstance -Namespace 'Root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' -ErrorAction Stop
                if ($null -ne $appMgmt) {
                    Invoke-CimMethod -InputObject $appMgmt -MethodName 'UpdateScanMethod' -ErrorAction Stop | Out-Null
                    Write-Good 'Triggered Microsoft Store app & framework update scan.'
                }
            } catch {
                Write-Step 'Microsoft Store background scan unavailable on this build/edition (continuing).'
            }
        }
    }

    # 2. PowerShellGet modules (only when NuGet provider >= 2.8.5.201 is already ready so it never blocks)
    if (Test-CommandExists 'Get-InstalledModule') {
        try {
            $nugetReady = $false
            if (Test-CommandExists 'Get-PackageProvider') {
                $nuget = Get-PackageProvider -ListAvailable -Name 'NuGet' -ErrorAction SilentlyContinue | Sort-Object Version -Descending | Select-Object -First 1
                if ($null -ne $nuget -and $nuget.Version -ge [version]'2.8.5.201') { $nugetReady = $true }
            }
            $psMods = @(Get-InstalledModule -ErrorAction SilentlyContinue)
            if ($psMods.Count -gt 0) {
                Add-Report 'dependency-updates.txt' 'Installed PowerShellGet modules' ($psMods | Format-Table 'Name','Version','Repository' -AutoSize | Out-String)
                if ($script:AuditOnly) {
                    Write-Host ("[AUDIT] Would check " + $psMods.Count + " PowerShellGet module(s) for updates.")
                } elseif (-not $nugetReady) {
                    Write-Step 'Skipping PowerShellGet module updates (NuGet provider not bootstrapped; avoiding network prompt).'
                } else {
                    $corePsMods = @($psMods | Where-Object { $_.Name -in @('PackageManagement','PowerShellGet','Microsoft.WinGet.Client','PSWindowsUpdate') })
                    $otherPsMods = @($psMods | Where-Object { $_.Name -notin @('PackageManagement','PowerShellGet','Microsoft.WinGet.Client','PSWindowsUpdate') })
                    if ($corePsMods.Count -gt 0 -and (Confirm-YesNo ("Update core PowerShell tooling module(s): " + (($corePsMods | Select-Object -ExpandProperty Name) -join ', ') + "?") $true)) {
                        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
                        foreach ($m in $corePsMods) {
                            try {
                                Update-Module -Name $m.Name -AcceptLicense -ErrorAction Stop
                                Write-Good ("Updated PowerShell module: " + $m.Name)
                            } catch { Write-Step ("PowerShell module check (" + $m.Name + "): " + $_.Exception.Message) }
                        }
                    }
                    if ($otherPsMods.Count -gt 0 -and (Confirm-YesNo ("Also update " + $otherPsMods.Count + " other PowerShellGet module(s)?") $false)) {
                        try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
                        foreach ($m in $otherPsMods) {
                            try {
                                Update-Module -Name $m.Name -ErrorAction Stop
                                Write-Good ("Updated PowerShell module: " + $m.Name)
                            } catch { Write-Step ("PowerShell module check (" + $m.Name + "): " + $_.Exception.Message) }
                        }
                    }
                }
            }
        } catch {}
    }

    # 3. Python pip dependencies (if Python is installed and not prohibited/pinned)
    $pyBlocked = (Test-MatchAgainstPatterns -Targets @('Python','pip') -Patterns $ProhibitedList) -or
                 (Test-MatchAgainstPatterns -Targets @('Python','pip') -Patterns $ExcludedList)
    $pyPaths = @(Resolve-PythonPaths)
    if ($pyPaths.Count -gt 0 -and -not $pyBlocked) {
        $corePipNames = @('pip','setuptools','wheel','certifi','urllib3','requests','cryptography','idna','charset-normalizer')
        foreach ($py in $pyPaths) {
            if ($script:AuditOnly) {
                Write-Host ("[AUDIT] Python found at " + $py + " - would check pip packaging/TLS dependencies.")
                continue
            }
            try {
                $pipOut = Invoke-ProcessCapture -FilePath $py -ArgumentList @('-m','pip','list','--outdated','--format=json','--disable-pip-version-check') -TimeoutSeconds 45
                if ($pipOut.TimedOut -or $pipOut.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($pipOut.Stdout)) { continue }
                $outdated = @($pipOut.Stdout | ConvertFrom-Json -ErrorAction Stop)
                if ($outdated.Count -eq 0) {
                    Write-Step ("Python pip dependencies up to date (" + $py + ").")
                    continue
                }
                Add-Report 'dependency-updates.txt' ("Outdated Python packages (" + $py + ")") ($outdated | Format-Table 'name','version','latest_version' -AutoSize | Out-String)
                $coreOutdated = @($outdated | Where-Object { ($corePipNames -icontains [string]$_.name) -and -not (Test-MatchAgainstPatterns -Targets @([string]$_.name) -Patterns $ExcludedList) })
                $otherOutdated = @($outdated | Where-Object { ($corePipNames -inotcontains [string]$_.name) -and -not (Test-MatchAgainstPatterns -Targets @([string]$_.name) -Patterns $ExcludedList) })
                if ($coreOutdated.Count -gt 0) {
                    $coreLabels = @($coreOutdated | ForEach-Object { [string]$_.name + ' (' + $_.version + '->' + $_.latest_version + ')' })
                    if (Confirm-YesNo ("Update Python core/TLS dependencies at " + $py + ": " + ($coreLabels -join ', ') + "?") $true) {
                        foreach ($pkg in $coreOutdated) {
                            $upRes = Invoke-ProcessCapture -FilePath $py -ArgumentList @('-m','pip','install','--upgrade',[string]$pkg.name,'--disable-pip-version-check') -TimeoutSeconds 120
                            if ($upRes.ExitCode -eq 0) { Write-Good ("Updated Python dependency: " + $pkg.name + " -> " + $pkg.latest_version) }
                            else { Write-WarnLine ("Failed to update Python dependency " + $pkg.name + " (exit " + $upRes.ExitCode + ").") }
                        }
                    }
                }
                if ($otherOutdated.Count -gt 0) {
                    if (Confirm-YesNo ("Also update " + $otherOutdated.Count + " other global Python pip package(s) at " + $py + "? (May change pinned app versions)") $false) {
                        foreach ($pkg in $otherOutdated) {
                            $upRes = Invoke-ProcessCapture -FilePath $py -ArgumentList @('-m','pip','install','--upgrade',[string]$pkg.name,'--disable-pip-version-check') -TimeoutSeconds 120
                            if ($upRes.ExitCode -eq 0) { Write-Good ("Updated Python package: " + $pkg.name + " -> " + $pkg.latest_version) }
                            else { Write-WarnLine ("Failed to update Python package " + $pkg.name + " (exit " + $upRes.ExitCode + ").") }
                        }
                    }
                }
            } catch { Write-Step ("Python pip check skipped for " + $py + ": " + $_.Exception.Message) }
        }
    }

    # 4. Node.js global npm dependencies (if npm is installed and not prohibited/pinned)
    $nodeBlocked = (Test-MatchAgainstPatterns -Targets @('Node.js','NodeJS','npm') -Patterns $ProhibitedList) -or
                   (Test-MatchAgainstPatterns -Targets @('Node.js','NodeJS','npm') -Patterns $ExcludedList)
    $npmCmd = $null
    try { $c = Get-Command 'npm.cmd' -ErrorAction SilentlyContinue; if ($null -ne $c) { $npmCmd = $c.Source } } catch {}
    if ($null -eq $npmCmd -and (Test-Path "$env:ProgramFiles\nodejs\npm.cmd")) { $npmCmd = "$env:ProgramFiles\nodejs\npm.cmd" }
    if ($null -ne $npmCmd -and -not $nodeBlocked) {
        if ($script:AuditOnly) {
            Write-Host ("[AUDIT] npm found at " + $npmCmd + " - would check global Node.js dependencies.")
        } else {
            try {
                $npmOut = Invoke-ProcessCapture -FilePath $npmCmd -ArgumentList @('outdated','-g','--json') -TimeoutSeconds 45
                if (-not $npmOut.TimedOut -and -not [string]::IsNullOrWhiteSpace($npmOut.Stdout)) {
                    $parsedNpm = $npmOut.Stdout | ConvertFrom-Json -ErrorAction Stop
                    $outdatedNpm = @()
                    foreach ($prop in $parsedNpm.PSObject.Properties) {
                        $outdatedNpm += [PSCustomObject]@{ Name = $prop.Name; Current = [string]$prop.Value.current; Latest = [string]$prop.Value.latest }
                    }
                    if ($outdatedNpm.Count -gt 0) {
                        Add-Report 'dependency-updates.txt' 'Outdated global npm packages' ($outdatedNpm | Format-Table 'Name','Current','Latest' -AutoSize | Out-String)
                        $coreNpm = @($outdatedNpm | Where-Object { ($_.Name -in @('npm','corepack')) -and -not (Test-MatchAgainstPatterns -Targets @($_.Name) -Patterns $ExcludedList) })
                        $otherNpm = @($outdatedNpm | Where-Object { ($_.Name -notin @('npm','corepack')) -and -not (Test-MatchAgainstPatterns -Targets @($_.Name) -Patterns $ExcludedList) })
                        if ($coreNpm.Count -gt 0 -and (Confirm-YesNo ("Update global Node.js tooling: " + (($coreNpm | Select-Object -ExpandProperty Name) -join ', ') + "?") $true)) {
                            foreach ($np in $coreNpm) {
                                $nRes = Invoke-ProcessCapture -FilePath $npmCmd -ArgumentList @('install','-g',($np.Name + '@latest')) -TimeoutSeconds 120
                                if ($nRes.ExitCode -eq 0) { Write-Good ("Updated npm dependency: " + $np.Name + " -> " + $np.Latest) }
                            }
                        }
                        if ($otherNpm.Count -gt 0 -and (Confirm-YesNo ("Also update " + $otherNpm.Count + " other global npm package(s)?") $false)) {
                            foreach ($np in $otherNpm) {
                                $nRes = Invoke-ProcessCapture -FilePath $npmCmd -ArgumentList @('install','-g',($np.Name + '@latest')) -TimeoutSeconds 120
                                if ($nRes.ExitCode -eq 0) { Write-Good ("Updated global npm package: " + $np.Name + " -> " + $np.Latest) }
                            }
                        }
                    } else {
                        Write-Step 'Global npm dependencies up to date.'
                    }
                }
            } catch {}
        }
    }

    # 5. .NET Runtimes & SDKs inventory + EOL check
    $dotnetExe = $null
    try { $dc = Get-Command 'dotnet.exe' -ErrorAction SilentlyContinue; if ($null -ne $dc) { $dotnetExe = $dc.Source } } catch {}
    if ($null -eq $dotnetExe -and (Test-Path "$env:ProgramFiles\dotnet\dotnet.exe")) { $dotnetExe = "$env:ProgramFiles\dotnet\dotnet.exe" }
    if ($null -ne $dotnetExe) {
        try {
            $dnRt = Invoke-ProcessCapture -FilePath $dotnetExe -ArgumentList @('--list-runtimes') -TimeoutSeconds 20
            if ($dnRt.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($dnRt.Stdout)) {
                Add-Report 'dependency-updates.txt' 'Installed .NET Runtimes' $dnRt.Stdout
                $eolHits = @()
                foreach ($line in @($dnRt.Stdout -split "\r?\n")) {
                    if ($line -match '\s([23567]\.\d+\.\d+)\s') { $eolHits += $line.Trim() }
                }
                if ($eolHits.Count -gt 0) {
                    Write-WarnLine 'End-of-life .NET runtime(s) detected (2.x/3.1/5/6/7) - verify whether a scenario app requires them or migrate to .NET 8/10 LTS:'
                    foreach ($eh in $eolHits) { Write-Host ('    ' + $eh) }
                }
            }
        } catch {}
    }
}

function Register-AutoUpdateTask {
    $taskName = 'CP-AutoUpdate-NecessaryApps'
    $scriptFile = Join-Path $script:Root 'secure.ps1'
    if ($script:AuditOnly) {
        Write-Host '[AUDIT] Optional recurring auto-update task is interactive opt-in only.'
        return
    }
    if ($script:UpdateOnly -or $script:ApplySafe -or $script:AutoUpdateStep) { return }
    if (-not (Test-CommandExists 'Register-ScheduledTask')) { return }
    $existing = $null
    try { $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue } catch {}
    $prompt = 'Register a daily Windows Scheduled Task to auto-update necessary apps and dependencies in the background? (Recommended for persistent systems; skip in timed competitions unless wanted.)'
    if ($null -ne $existing) {
        Write-Step ("Recurring auto-update task '" + $taskName + "' is already registered (State=" + $existing.State + ").")
        return
    }
    if (-not (Confirm-YesNo $prompt $false)) { return }
    try {
        $argStr = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $scriptFile + '" -Mode Update'
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argStr -WorkingDirectory $script:Root
        $trigger = New-ScheduledTaskTrigger -Daily -At '03:00AM'
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Automatically updates necessary apps and runtime dependencies via CPWindowsScripts.' -Force | Out-Null
        Write-Good ("Registered recurring scheduled task '" + $taskName + "' (daily at 03:00 as SYSTEM; never auto-reboots).")
    } catch {
        Write-WarnLine ("Could not register auto-update scheduled task: " + $_.Exception.Message)
    }
}

function Invoke-Updates {
    Write-Banner 'STEP 12A OF 12 - AUTO-UPDATING NECESSARY APPS AND DEPENDENCIES (never reboots)'
    $wasAutoStep = $script:AutoUpdateStep
    $autoUpdFlag = ($null -ne $script:Config -and [bool]$script:Config.AutoUpdate)
    $skipWuFlag = ($null -ne $script:Config -and [bool]$script:Config.SkipWindowsUpdates)
    if ($autoUpdFlag -or $script:UpdateOnly) { $script:AutoUpdateStep = $true }
    try {
        $au = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
        Set-RegValue $au 'NoAutoUpdate' 0 'DWord' 'Automatic Updates on'
        Set-RegValue $au 'AUOptions' 4 'DWord' 'Auto-download and schedule install'
        Set-RegValue $au 'AutoInstallMinorUpdates' 1 'DWord' ''
        Set-RegValue $au 'IncludeRecommendedUpdates' 1 'DWord' ''
        Set-RegValue $au 'NoAutoRebootWithLoggedOnUsers' 1 'DWord' 'Never auto-restart while someone is signed in (round safety)'
        Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'DisableWindowsUpdateAccess' 0 'DWord' ''
        Set-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' 'ElevateNonAdmins' 0 'DWord' 'Only administrators approve updates'
        Set-RegValue 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' 'AUOptions' 4 'DWord' ''

        # Receive security/quality updates for other Microsoft products too (for
        # example MSI-based Office). Skipped when WSUS manages this machine.
        try {
            $muId = '7971f918-a847-4430-9279-4a52d1efe18d'
            $useWUServer = Get-RegValue 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'UseWUServer'
            $muManager = New-Object -ComObject 'Microsoft.Update.ServiceManager'
            $muRegistered = $false
            foreach ($updateService in $muManager.Services) {
                try {
                    if ($updateService.ServiceID -ieq $muId -and [bool]$updateService.IsRegisteredWithAU) { $muRegistered = $true }
                } catch {}
            }
            if ("$useWUServer" -eq '1') {
                Write-Step 'Microsoft Update opt-in skipped: WSUS policy manages this machine.'
            } elseif ($muRegistered) {
                Write-Step 'Microsoft Update (updates for other Microsoft products) is already enabled.'
            } elseif ($script:AuditOnly) {
                Write-Host '[AUDIT] Would enable Microsoft Update for other Microsoft products (documented ServiceManager opt-in).'
            } elseif (Confirm-YesNo 'Enable Microsoft Update so Windows Update also patches other Microsoft products (for example MSI-based Office)? No reboot is triggered.' $true) {
                try {
                    $muManager.ClientApplicationID = 'CPWindowsScripts'
                    [void]$muManager.AddService2($muId, 7, '')
                    Write-Good 'Microsoft Update enabled for other Microsoft products.'
                } catch { Write-WarnLine ("Microsoft Update opt-in failed: " + $_.Exception.Message) }
            }
        } catch { Write-WarnLine 'Could not check Microsoft Update registration; Windows Update settings are unchanged.' }

        # Phase 1: Repair update & servicing infrastructure dependencies
        Repair-UpdateInfrastructure

        $updCfg = Get-UpdateConfig (Join-Path $script:Root 'necessary_apps.txt')
        $script:NecessaryApps = @($updCfg.Necessary)
        $script:ExcludedFromUpdates = @($updCfg.Excluded)
        $prohibitedForUpdates = @()
        try { $prohibitedForUpdates = @(Get-TextList (Join-Path $script:Root 'prohibited_software.txt') | Where-Object { $_ -ne 'EDIT_ME' }) } catch {}
        $script:ProhibitedSoftware = $prohibitedForUpdates

        $installedPrograms = @()
        try { $installedPrograms = @(Get-InstalledPrograms) } catch {}
        $paidAcrobatDetected = $false
        foreach ($installed in $installedPrograms) {
            if ("$($installed.DisplayName)" -match 'Adobe Acrobat' -and "$($installed.DisplayName)" -notmatch 'Reader') { $paidAcrobatDetected = $true }
        }

        # Phase 2: WinGet + dependency-first + necessary-app updating
        $wingetExe = Initialize-WinGetReady
        $serviceAffected = $false
        $depUpdated = $false
        $allTrackedIds = @()
        $allUpgradable = @()

        if ($script:AuditOnly) {
            if ($null -eq $wingetExe) {
                Write-Host '[AUDIT] WinGet (Microsoft.DesktopAppInstaller) not found - would offer to register/install WinGet and its dependencies.'
            } else {
                Write-Host ("[AUDIT] WinGet found at " + $wingetExe + " - would update sources and upgrade installed dependencies and necessary apps.")
            }
            $catalog = @(Get-KnownAppDependencyCatalog)
            foreach ($cat in $catalog) {
                $present = $false
                foreach ($dp in @($cat.DetectPaths)) {
                    if (-not [string]::IsNullOrWhiteSpace($dp) -and (Test-Path -LiteralPath $dp)) { $present = $true; break }
                }
                if (-not $present -and $installedPrograms.Count -gt 0) {
                    $dispNames = @($installedPrograms | ForEach-Object { [string]$_.DisplayName })
                    if (Test-MatchAgainstPatterns -Targets $dispNames -Patterns $cat.Aliases) { $present = $true }
                }
                if ($present) {
                    $allTrackedIds += $cat.Id
                    Write-Host ("[AUDIT] Would check WinGet for [" + $cat.Category + "] " + $cat.Label + " (" + $cat.Id + ").")
                }
            }
            $unmappedAudit = @(Get-UnmappedNecessaryApps -NecessaryList $script:NecessaryApps -ExcludedList $script:ExcludedFromUpdates -ProhibitedList $prohibitedForUpdates -InstalledPrograms $installedPrograms -TrackedWinGetIds $allTrackedIds -TrackedWinGetPackages @())
            foreach ($ua in $unmappedAudit) {
                Write-Host ("[AUDIT] Necessary app installed without known WinGet mapping: " + $ua.DisplayName + " " + $ua.DisplayVersion)
            }
        } elseif ($null -ne $wingetExe) {
            Write-Step 'Scanning all WinGet-tracked apps and runtime dependencies for updates (this can take a minute)...'
            $allTrackedIds = @(Get-WinGetExportedIds -WinGetExe $wingetExe)
            $allUpgradable = @(Invoke-WinGetListUpgrades -WinGetExe $wingetExe -ExportedIds $allTrackedIds -InstalledPrograms $installedPrograms)

            $classified = Select-UpdatablePackages -UpgradablePackages $allUpgradable `
                -NecessaryList $script:NecessaryApps `
                -ExcludedList $script:ExcludedFromUpdates `
                -ProhibitedList $prohibitedForUpdates `
                -KeepEntries $script:KeepEntries `
                -KeptChoices @($script:KeptByChoice) `
                -PaidAcrobatDetected $paidAcrobatDetected

            foreach ($skipProh in $classified.SkippedProhibited) {
                if ($skipProh.ConflictWithNecessary) {
                    Write-WarnLine ("CONFLICT: '" + $skipProh.Label + "' matches BOTH prohibited_software.txt and necessary_apps.txt. Skipping update until you remove it from one list.")
                } else {
                    Write-Step ("Not updating " + $skipProh.Label + ": matches prohibited_software.txt (removal/review takes priority).")
                }
            }
            foreach ($skipPin in $classified.SkippedPinned) {
                Write-Step ("Skipping pinned/excluded package (! rule in necessary_apps.txt): " + $skipPin.Label + " (" + $skipPin.Id + ")")
            }
            if ($classified.SkippedAcrobatMismatch.Count -gt 0) {
                Write-WarnLine 'Non-Reader Adobe Acrobat edition detected; skipping WinGet Reader package to avoid edition mismatch (repair/use Help > Check for Updates).'
            }

            # Tier 1: Platform & runtime dependencies FIRST
            if ($classified.Dependencies.Count -gt 0) {
                $depSummary = (($classified.Dependencies | ForEach-Object { $_.Label + ' (' + $_.Version + '->' + $_.Available + ')' }) -join ', ')
                Add-Report 'dependency-updates.txt' 'WinGet runtime/platform dependency upgrades available' ($classified.Dependencies | Format-Table 'Label','Id','Version','Available' -AutoSize | Out-String)
                if (Confirm-YesNo ("Update platform/runtime DEPENDENCIES first: " + $depSummary + "?") $true) {
                    foreach ($depPkg in $classified.Dependencies) {
                        if (Update-WinGetPackageSafe -WinGetExe $wingetExe -Package $depPkg) {
                            $depUpdated = $true
                            if ($depPkg.ServiceNames.Count -gt 0) { $serviceAffected = $true }
                        }
                    }
                }
            } else {
                Write-Step 'WinGet: all detected runtime/platform dependencies are up to date.'
            }

            # Tier 2: Necessary apps (necessary_apps.txt + curated essentials + keep_services client tools)
            if ($classified.NecessaryApps.Count -gt 0) {
                $appSummary = (($classified.NecessaryApps | ForEach-Object { $_.Label + ' (' + $_.Version + '->' + $_.Available + ')' }) -join ', ')
                Add-Report 'app-updates.txt' 'WinGet necessary-app upgrades available' ($classified.NecessaryApps | Format-Table 'Label','Id','Version','Available' -AutoSize | Out-String)
                if (Confirm-YesNo ("Update NECESSARY APPS now with WinGet: " + $appSummary + "? (Silent, no forced close, no auto-reboot)") $true) {
                    $browserOrGuiUpdated = $false
                    foreach ($appPkg in $classified.NecessaryApps) {
                        if (Update-WinGetPackageSafe -WinGetExe $wingetExe -Package $appPkg) {
                            if ($appPkg.ServiceNames.Count -gt 0) { $serviceAffected = $true }
                            if ($appPkg.ProcessNames.Count -gt 0) { $browserOrGuiUpdated = $true }
                        }
                    }
                    if ($browserOrGuiUpdated) {
                        Write-WarnLine 'Close and reopen updated browsers/GUI apps when convenient so the new versions take effect in memory.'
                    }
                }
            } else {
                Write-Step 'WinGet: all detected necessary apps are up to date.'
            }

            # Tier 2b: Critical server daemons (cautious, service-continuity checked)
            if ($classified.CriticalServerApps.Count -gt 0) {
                Add-Report 'app-updates.txt' 'WinGet critical server daemon upgrades available' ($classified.CriticalServerApps | Format-Table 'Label','Id','Version','Available' -AutoSize | Out-String)
                foreach ($srvPkg in $classified.CriticalServerApps) {
                    $srvDefault = $srvPkg.ExplicitNecessary
                    $srvMsg = "Update critical server package '" + $srvPkg.Label + "' (" + $srvPkg.Version + " -> " + $srvPkg.Available + ")? Verify configs and service status immediately afterward."
                    if (Confirm-YesNo $srvMsg $srvDefault) {
                        if (Update-WinGetPackageSafe -WinGetExe $wingetExe -Package $srvPkg) { $serviceAffected = $true }
                    }
                }
            }

            # Unmapped necessary apps from necessary_apps.txt
            $unmappedApps = @(Get-UnmappedNecessaryApps -NecessaryList $script:NecessaryApps -ExcludedList $script:ExcludedFromUpdates -ProhibitedList $prohibitedForUpdates -InstalledPrograms $installedPrograms -TrackedWinGetIds $allTrackedIds -TrackedWinGetPackages $allUpgradable)
            if ($unmappedApps.Count -gt 0) {
                Add-Report 'app-updates.txt' 'Installed necessary apps without WinGet mapping (update via Help > About or vendor updater)' ($unmappedApps | Format-Table 'DisplayName','DisplayVersion','Publisher','RequestedEntry' -AutoSize | Out-String)
                Write-WarnLine 'Installed necessary apps from necessary_apps.txt without an automatic WinGet upgrade (check Help > About or vendor updater):'
                foreach ($ua in $unmappedApps) { Write-Host ('    - ' + $ua.DisplayName + ' ' + $ua.DisplayVersion) }
            }

            # Tier 3: Other remaining upgradable apps (never includes prohibited or pinned apps)
            if ($classified.OtherApps.Count -gt 0) {
                Add-Report 'app-updates.txt' 'Other WinGet-upgradable installed apps' ($classified.OtherApps | Format-Table 'Label','Id','Version','Available' -AutoSize | Out-String)
                $otherSummary = (($classified.OtherApps | ForEach-Object { $_.Label + ' (' + $_.Version + '->' + $_.Available + ')' }) -join ', ')
                if (Confirm-YesNo ("ALSO update these other installed app(s) (prohibited and pinned apps excluded): " + $otherSummary + "?") $false) {
                    foreach ($otherPkg in $classified.OtherApps) {
                        if (Update-WinGetPackageSafe -WinGetExe $wingetExe -Package $otherPkg) {
                            if ($otherPkg.ServiceNames.Count -gt 0) { $serviceAffected = $true }
                        }
                    }
                    Write-WarnLine 'Other apps updated: re-test critical services/scenario applications and refresh the Scoring Report.'
                }
            }
        } else {
            Write-WarnLine 'WinGet is not available, so WinGet app/dependency updates were skipped. Update required browsers/apps from Help > About.'
        }

        # Phase 3: Store, PowerShell modules, Python pip, Node npm, .NET EOL audit
        Update-EcosystemDependencies -ExcludedList $script:ExcludedFromUpdates -ProhibitedList $prohibitedForUpdates

        # Ensure any kept/critical services remain running after app/runtime updates
        if (-not $script:AuditOnly -and ($serviceAffected -or (($depUpdated -or $script:UpdateOnly) -and $script:KeepEntries.Count -gt 0))) {
            Write-Step 'Verifying critical services remain running after software/dependency updates...'
            try { Confirm-CriticalServicesRunning } catch { Write-WarnLine ("Post-update service verification warning: " + $_.Exception.Message) }
        }

        # Phase 4: Windows Update scan and optional/auto install (last so fast app/dependency updates finish first)
        if (-not $script:AuditOnly) {
            try { & UsoClient.exe StartScan | Out-Null; Write-Step 'Triggered Windows Update scan (UsoClient StartScan).' } catch {}
            $installWuDefault = ($script:UpdateOnly -or $autoUpdFlag) -and (-not $skipWuFlag)
            $doWuApi = $false
            if ($skipWuFlag) {
                Write-Step 'Skipped Windows Update API installation (-SkipWindowsUpdates specified).'
            } elseif ($script:UpdateOnly -or $autoUpdFlag) {
                $doWuApi = $true
            } else {
                $doWuApi = Confirm-YesNo 'Search for Windows updates with the Update API and optionally install them? (Can take a long time; any reboot stays YOUR decision afterwards.)' $false
            }
            if ($doWuApi) {
                try {
                    $session = New-Object -ComObject Microsoft.Update.Session
                    $searcher = $session.CreateUpdateSearcher()
                    Write-Step 'Searching for Windows updates ...'
                    $result = $searcher.Search("IsInstalled=0 and Type='Software'")
                    Write-Step ("Windows updates found: " + $result.Updates.Count)
                    foreach ($u in $result.Updates) { Write-Host ('    - ' + $u.Title) }
                    $confirmInstall = $false
                    if ($result.Updates.Count -gt 0) {
                        if ($installWuDefault) { $confirmInstall = $true }
                        else { $confirmInstall = Confirm-YesNo 'Download and install all of these Windows updates now?' $false }
                    }
                    if ($confirmInstall) {
                        $toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
                        foreach ($u in $result.Updates) { if ($u.EulaAccepted -eq $false) { $u.AcceptEula() }; [void]$toDownload.Add($u) }
                        $downloader = $session.CreateUpdateDownloader()
                        $downloader.Updates = $toDownload
                        [void]$downloader.Download()
                        Write-Good 'Windows Update downloads complete. Installing ...'
                        $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                        foreach ($u in $result.Updates) { if ($u.IsDownloaded) { [void]$toInstall.Add($u) } }
                        $installer = $session.CreateUpdateInstaller()
                        $installer.Updates = $toInstall
                        $installResult = $installer.Install()
                        Write-Good ("Windows Update install finished. Result code: " + $installResult.ResultCode + "  Reboot required: " + $installResult.RebootRequired)
                        if ($installResult.RebootRequired) { [void]$script:PendingRebootReasons.Add('Windows Update') }
                    }
                } catch { Write-WarnLine ("Windows Update API failed (" + $_.Exception.Message + "). Use Settings > Windows Update instead.") }
            } elseif (-not $script:ApplySafe -and -not $script:UpdateOnly -and -not $script:AutoUpdateStep) {
                Write-Host 'FASTEST RELIABLE PATH: open Settings > Windows Update > Check for updates NOW'
                Write-Host 'and let it work while you continue. "Majority of updates installed" is scored.'
                if (Confirm-YesNo 'Open the Windows Update settings page now?' $true) {
                    try { Start-Process 'ms-settings:windowsupdate' } catch {}
                }
            }
        }

        # Phase 5: Optional recurring auto-update task (interactive opt-in only)
        Register-AutoUpdateTask

        # Pending reboot summary (without ever rebooting)
        $rebootPending = ($script:PendingRebootReasons.Count -gt 0) -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        if ($rebootPending) {
            Write-WarnLine 'A reboot is pending to finish applying updates. Reboot ONCE, manually, only when ready (after verifying passwords and lock/unlock).'
        }

        # Final app-version & runtime snapshot (after any updates above)
        $appVersionInfo = @()
        foreach ($candidate in @(
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
            "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
            "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Notepad++\notepad++.exe",
            "$env:ProgramFiles\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
            "$env:ProgramFiles\VideoLAN\VLC\vlc.exe",
            "$env:ProgramFiles\7-Zip\7zFM.exe",
            "$env:ProgramFiles\Git\cmd\git.exe",
            "$env:ProgramFiles\nodejs\node.exe",
            "$env:ProgramFiles\PowerShell\7\pwsh.exe"
        )) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) {
                try { $appVersionInfo += ($candidate + '  version ' + (Get-Item -LiteralPath $candidate).VersionInfo.FileVersion) } catch {}
            }
        }
        if ($null -ne $wingetExe) {
            try {
                $wgVer = Invoke-ProcessCapture -FilePath $wingetExe -ArgumentList @('--version') -TimeoutSeconds 15
                if (-not $wgVer.TimedOut -and $wgVer.ExitCode -eq 0) {
                    $appVersionInfo += ($wingetExe + '  version ' + $wgVer.Stdout.Trim())
                }
            } catch {}
        }
        foreach ($py in @(Resolve-PythonPaths)) {
            try {
                $pyVer = Invoke-ProcessCapture -FilePath $py -ArgumentList @('--version') -TimeoutSeconds 15
                if (-not $pyVer.TimedOut -and $pyVer.ExitCode -eq 0) {
                    $appVersionInfo += ($py + '  version ' + $pyVer.Stdout.Trim())
                }
            } catch {}
        }
        if ($appVersionInfo.Count -gt 0) {
            Add-Report 'app-versions.txt' 'App and runtime dependency versions after update step' ($appVersionInfo -join "`r`n")
            Write-Step 'App and dependency versions recorded in the Reports folder.'
        }
    } finally {
        $script:AutoUpdateStep = $wasAutoStep
    }
}

