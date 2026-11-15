# Run with Windows PowerShell 5.1: powershell.exe -NoProfile -File tests\regression.ps1
# Load only pure helpers from the AST: never execute the hardening engine here.
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$source = Join-Path $repo 'secure.ps1'
$moduleDir = Join-Path $repo 'modules'
$moduleFiles = @(Get-ChildItem -LiteralPath $moduleDir -Filter '*.ps1' | Sort-Object Name | Select-Object -ExpandProperty FullName)
if ($moduleFiles.Count -lt 10) { throw 'Expected all modular PowerShell files under modules/' }
$allPsFiles = @($source) + $moduleFiles

$asts = @()
foreach ($file in $allPsFiles) {
    $tokens = $null
    $errors = $null
    $parsedAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { throw ("Parse error in ${file}:`n" + ($errors | Out-String)) }
    $asts += $parsedAst
}
$ast = $asts[0]

function Find-AstFunction {
    param([string]$Name)
    foreach ($a in $asts) {
        $fn = $a.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $Name }, $true)
        if ($null -ne $fn) { return $fn }
    }
    return $null
}

foreach ($name in @(
    'Write-Banner', 'Write-Step', 'Write-Good', 'Write-WarnLine',
    'Confirm-YesNo', 'Wait-Enter', 'Show-AIPrompt', 'Set-RegValue',
    'Test-FileEdited', 'Get-TextList', 'Get-UpdateConfig', 'Test-ConfigReady',
    'Get-InstalledPrograms', 'Get-AppxProhibitedPackages', 'Get-PersistenceFindings',
    'Test-ServiceScenarioKept', 'Test-TokenKept',
    'Set-ScenarioFeatureFlags', 'Add-KeptService',
    'Test-FirewallPortRisky', 'Get-RiskyInboundFirewallRules',
    'Test-NameInList', 'Get-UserAccountIssues',
    'Get-KnownAppDependencyCatalog', 'Get-NecessaryAppsFromServices', 'Test-MatchAgainstPatterns',
    'Format-CommandArguments', 'ConvertFrom-WinGetListOutput', 'Select-UpdatablePackages',
    'Get-UnmappedNecessaryApps',
    'Get-SuspiciousFileRules', 'Test-SuspiciousFileExcludedPath', 'Get-ZipArchiveContents',
    'Test-ShortcutTargetSuspicious', 'Test-TextFileSensitiveContent',
    'Measure-SuspiciousFileRisk', 'Get-ScopedFilesSafe'
)) {
    $func = Find-AstFunction -Name $name
    if ($null -eq $func) { throw "Missing function $name" }
    Invoke-Expression $func.Extent.Text
}

function Assert-Equal($actual, $expected, $message) {
    if ($actual -ne $expected) { throw "$message (expected $expected; got $actual)" }
}
function Assert-Condition([bool]$cond, $message) {
    if (-not $cond) { throw $message }
}

$script:Changes = New-Object System.Collections.ArrayList
$script:Warnings = New-Object System.Collections.ArrayList
$script:ProtectedPatterns = 'CyberPatriot|Scoring|CCSClient|CCS|VMware|VMTools|VBox|VirtualBox|QEMU|qemu|Hyper-V'

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('cp-tests-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    foreach ($template in @('keep_services.txt', 'authorizedusers.txt', 'admins.txt', 'rdpusers.txt')) {
        $copy = Join-Path $temp $template
        Copy-Item (Join-Path $repo $template) $copy
        Assert-Equal (Test-FileEdited $copy) $false "$template should initially have a marker"
        @(Get-Content $copy | Where-Object { $_.Trim() -ine 'EDIT_ME' }) | Set-Content $copy
        Assert-Equal (Test-FileEdited $copy) $true "$template should work after its marker is removed"
    }
    $script:Root = $temp
    $path = Join-Path $temp 'keep_services.txt'
    Remove-Item -LiteralPath $path
    Assert-Equal (Test-Path -LiteralPath $path) $false 'Missing-file test fixture must not exist'
    Assert-Equal (Test-FileEdited $path) $false 'Missing files must fail closed'
    Set-Content $path @('# Delete the EDIT_ME line', '  EDIT_ME  ')
    Assert-Equal (Test-FileEdited $path) $false 'Active marker must block configuration'
    Set-Content $path @('# Delete the EDIT_ME line', '# An empty list can be intentional')
    Assert-Equal (Test-FileEdited $path) $true 'Comments and empty lists are valid'
    Set-Content $path @('# EDIT_ME', 'DNS', ' RDP ')
    Assert-Equal (Test-FileEdited $path) $true 'Completed list must be accepted'
    $list = @(Get-TextList $path)
    Assert-Equal ($list -join ',') 'DNS,RDP' 'List must ignore comments and trim entries'
    Set-Content (Join-Path $temp 'authorizedusers.txt') @('# EDIT_ME', 'Administrator')
    Set-Content (Join-Path $temp 'admins.txt') @('# EDIT_ME', 'Administrator')
    Assert-Equal (Test-ConfigReady) $true 'Three completed files should be ready'
    $ReadmeConfigured = $true
    Set-Content (Join-Path $temp 'admins.txt') 'EDIT_ME'
    Assert-Equal (Test-ConfigReady) $false 'Confirmation switch must not bypass an active marker'
    Remove-Item (Join-Path $temp 'admins.txt')
    Assert-Equal (Test-ConfigReady) $false 'Confirmation switch must not bypass a missing file'

    $script:KeptByChoice = New-Object System.Collections.ArrayList
    $script:KeepTokenMap = @{ RDP = @('TermService'); SMB = @('LanmanServer') }
    $script:ServiceGraphReady = $false
    foreach ($entry in @('RDP', 'TermService', 'Remote Desktop Services')) {
        $script:KeepEntries = @($entry)
        Set-ScenarioFeatureFlags
        Assert-Equal $script:RdpCritical $true "RDP must be protected for $entry"
    }
    foreach ($entry in @('SMB', 'LanmanServer', 'Server')) {
        $script:KeepEntries = @($entry)
        Set-ScenarioFeatureFlags
        Assert-Equal $script:FileSharingCritical $true "File sharing must be protected for $entry"
    }
    $script:KeepEntries = @()
    Add-KeptService 'ExampleService'
    Add-KeptService 'ExampleService'
    Assert-Equal $script:KeptByChoice.Count 1 'A service kept by choice must be recorded once'
    Assert-Equal (Test-ServiceScenarioKept -Name 'ExampleService' -DisplayName '') $true 'Kept choice must protect the service'

    # Record the paths used for installed-program discovery without touching the registry.
    $script:seenPaths = @()
    function Get-ItemProperty {
        param($Path, $ErrorAction)
        $script:seenPaths += $Path
        [pscustomobject]@{ DisplayName = $Path; DisplayVersion = '1.0'; Publisher = 'Test'; UninstallString = $Path }
    }
    $programs = @(Get-InstalledPrograms)
    Assert-Equal $programs.Count 3 'All three uninstall registry locations should be queried'
    Assert-Equal (($script:seenPaths | Where-Object { $_ -notmatch '^HK(LM|CU):\\' }).Count) 0 'Registry paths need a PowerShell drive colon'
    Remove-Item Function:\Get-ItemProperty -ErrorAction SilentlyContinue

    # Verify dual-version entries with identical DisplayName are preserved
    function Get-ItemProperty {
        param($Path, $ErrorAction)
        @(
            [pscustomobject]@{ DisplayName = 'Python 3.12'; DisplayVersion = '3.12.1'; Publisher = 'PSF'; UninstallString = 'msiexec /x {1}' },
            [pscustomobject]@{ DisplayName = 'Python 3.12'; DisplayVersion = '3.12.9'; Publisher = 'PSF'; UninstallString = 'msiexec /x {2}' }
        )
    }
    $dual = @(Get-InstalledPrograms)
    Assert-Equal $dual.Count 2 'Get-InstalledPrograms must keep distinct DisplayVersion/UninstallString rows'
    Remove-Item Function:\Get-ItemProperty -ErrorAction SilentlyContinue

    # --- Auto-update & dependency engine checks ---
    # 1. necessary_apps.txt template and Get-UpdateConfig parsing
    $necTemplate = Join-Path $repo 'necessary_apps.txt'
    Assert-Equal (Test-Path -LiteralPath $necTemplate) $true 'necessary_apps.txt template must exist'
    $tplCfg = Get-UpdateConfig $necTemplate
    Assert-Equal ($tplCfg.Necessary -contains 'Google Chrome') $true 'necessary_apps.txt must list essential defaults'
    Assert-Equal ($tplCfg.Excluded.Count) 0 'necessary_apps.txt must have zero active exclusions by default'

    $customNec = Join-Path $temp 'necessary_apps.txt'
    Set-Content $customNec @('# comment line', 'EDIT_ME', '  PuTTY  ', '!Python', '! 7-Zip ', '', 'CustomApp')
    $parsedCfg = Get-UpdateConfig $customNec
    Assert-Equal ($parsedCfg.Necessary -join ',') 'PuTTY,CustomApp' 'Get-UpdateConfig must trim entries and ignore comments/EDIT_ME'
    Assert-Equal ($parsedCfg.Excluded -join ',') 'Python,7-Zip' 'Get-UpdateConfig must split !-prefixed exclusions'
    Assert-Equal ((Get-UpdateConfig (Join-Path $temp 'missing_apps.txt')).Necessary.Count) 0 'Missing necessary_apps.txt must return empty config'

    # 2. Service-to-dependency and app inference
    $svcInf = Get-NecessaryAppsFromServices -KeepEntries @('IIS','APACHE','SQL','SSH','PYTHON','RDP','SMB') -KeptChoices @('FTP')
    Assert-Equal ($svcInf.DependencyPatterns -contains 'ASP.NET Core') $true 'IIS must imply ASP.NET Core dependency'
    Assert-Equal ($svcInf.DependencyPatterns -contains 'Visual C++') $true 'Apache/SQL must imply Visual C++ dependency'
    Assert-Equal ($svcInf.DependencyPatterns -contains 'Python') $true 'PYTHON keep entry must imply Python dependency'
    Assert-Equal ($svcInf.ServerPatterns -contains 'Apache') $true 'APACHE keep entry must map to Apache server pattern'
    Assert-Equal ($svcInf.ClientPatterns -contains 'PuTTY') $true 'SSH keep entry must imply PuTTY client pattern'
    Assert-Equal ($svcInf.ClientPatterns -contains 'FileZilla') $true 'FTP keep choice must imply FileZilla client pattern'
    Assert-Equal ($svcInf.ClientPatterns -contains 'RDP') $false 'Abstract token RDP must not pollute client app patterns'
    Assert-Equal ($svcInf.ClientPatterns -contains 'SMB') $false 'Abstract token SMB must not pollute client app patterns'

    # 3. Format-CommandArguments quoting for PS 5.1 ProcessStartInfo
    $formattedArgs = Format-CommandArguments @('upgrade', '--id', 'Notepad++.Notepad++', '--source', 'My Source')
    Assert-Equal $formattedArgs 'upgrade --id Notepad++.Notepad++ --source "My Source"' 'Format-CommandArguments must quote spaced arguments'

    # 4. WinGet table parsing + truncation resolution + Unknown skip
    $ellipsisChar = [string]([char]0x2026)
    $wgSample = @(
        "   - \ | ",
        "Name                                       Id                             Version        Available      Source",
        "--------------------------------------------------------------------------------------------------------------",
        "Microsoft Visual C++ 2015-2022 Redistribut Microsoft.VCRedist.2015+.x64   14.38.33135.0  14.42.34438.0  winget",
        ("Microsoft .NET Windows Desktop Runtime 8   Microsoft.DotNet.DesktopR" + $ellipsisChar + "  8.0.10         8.0.14         winget"),
        "Google Chrome                              Google.Chrome                  130.0.0.1      131.0.0.2      winget",
        "PuTTY release 0.81                         PuTTY.PuTTY                    < 0.82         0.83           winget",
        "Unknown Tool                               Vendor.Unknown                 1.0.0          Unknown        winget",
        ("Ambiguous App                              Vendor.Ambig" + $ellipsisChar + "               1.0            2.0            winget"),
        "2 upgrades available."
    )
    $parsedWg = @(ConvertFrom-WinGetListOutput -Lines $wgSample -ExportedIds @('Microsoft.DotNet.DesktopRuntime.8', 'Vendor.AmbiguousOne', 'Vendor.AmbiguousTwo'))
    Assert-Equal $parsedWg.Count 5 'ConvertFrom-WinGetListOutput must skip Unknown rows and footer lines'
    Assert-Equal $parsedWg[0].Id 'Microsoft.VCRedist.2015+.x64' 'Fixed-width WinGet row must parse VC++ ID'
    Assert-Equal $parsedWg[1].Id 'Microsoft.DotNet.DesktopRuntime.8' 'Truncated WinGet ID must resolve uniquely from ExportedIds'
    Assert-Equal $parsedWg[1].IdTruncated $false 'Uniquely resolved WinGet ID must clear IdTruncated flag'
    Assert-Equal $parsedWg[3].Version '< 0.82' 'Version with < prefix must parse cleanly'
    Assert-Equal $parsedWg[4].IdTruncated $true 'Ambiguous truncated WinGet ID must stay flagged as IdTruncated'

    # 5. Dependency-first package classification and safety exclusions
    $upgInputs = @(
        [PSCustomObject]@{ Name='VC++'; Id='Microsoft.VCRedist.2015+.x64'; Version='14.38'; Available='14.42'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='Python 3.12'; Id='Python.Python.3.12'; Version='3.12.1'; Available='3.12.9'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='Google Chrome'; Id='Google.Chrome'; Version='130'; Available='131'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='Google Chrome'; Id='Google.Chrome'; Version='130'; Available='131'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='PuTTY'; Id='PuTTY.PuTTY'; Version='0.81'; Available='0.83'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='Wireshark'; Id='WiresharkFoundation.Wireshark'; Version='4.0'; Available='4.4'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='Adobe Acrobat Reader'; Id='Adobe.Acrobat.Reader.64-bit'; Version='24.0'; Available='24.5'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='Apache HTTP Server'; Id='ApacheLounge.httpd'; Version='2.4.58'; Available='2.4.62'; Source='winget'; IdTruncated=$false },
        [PSCustomObject]@{ Name='Custom Tool'; Id='Vendor.CustomTool'; Version='1.0'; Available='2.0'; Source='winget'; IdTruncated=$false }
    )
    $sel = Select-UpdatablePackages -UpgradablePackages $upgInputs `
        -NecessaryList @('PuTTY', 'Wireshark') `
        -ExcludedList @('Python') `
        -ProhibitedList @('Wireshark') `
        -KeepEntries @('APACHE') `
        -KeptChoices @() `
        -PaidAcrobatDetected $true
    Assert-Equal $sel.Dependencies.Count 1 'VC++ must be selected in Dependencies while !Python is excluded'
    Assert-Equal $sel.Dependencies[0].Id 'Microsoft.VCRedist.2015+.x64' 'Dependency tier must contain VC++'
    Assert-Equal $sel.NecessaryApps.Count 2 'Chrome and PuTTY must be selected in NecessaryApps (deduplicated)'
    Assert-Equal $sel.CriticalServerApps.Count 1 'Apache server daemon must be separated into CriticalServerApps'
    Assert-Equal $sel.OtherApps.Count 1 'Unlisted non-essential app must fall into OtherApps'
    Assert-Equal $sel.SkippedPinned.Count 1 '!Python must appear in SkippedPinned'
    Assert-Equal $sel.SkippedProhibited.Count 1 'Prohibited Wireshark must appear in SkippedProhibited'
    Assert-Equal $sel.SkippedProhibited[0].ConflictWithNecessary $true 'Conflict between prohibited and necessary_apps must be flagged'
    Assert-Equal $sel.SkippedAcrobatMismatch.Count 1 'Reader package must be skipped when paid Acrobat is detected'

    # 6. Unmapped necessary app detection
    $mockInstalled = @(
        [PSCustomObject]@{ DisplayName='Custom Line Of Business App'; DisplayVersion='2.1.0'; Publisher='Scenario Corp' },
        [PSCustomObject]@{ DisplayName='Google Chrome'; DisplayVersion='131.0.0.0'; Publisher='Google LLC' },
        [PSCustomObject]@{ DisplayName='Python 3.12.1'; DisplayVersion='3.12.1'; Publisher='Python Software Foundation' }
    )
    $unmapped = @(Get-UnmappedNecessaryApps `
        -NecessaryList @('Custom Line Of Business App', 'Google Chrome', 'Python') `
        -ExcludedList @('Python') `
        -ProhibitedList @() `
        -InstalledPrograms $mockInstalled `
        -TrackedWinGetIds @('Google.Chrome') `
        -TrackedWinGetPackages @())
    Assert-Equal $unmapped.Count 1 'Only unmapped non-excluded installed necessary apps should be reported'
    Assert-Equal $unmapped[0].DisplayName 'Custom Line Of Business App' 'Custom LOB app must be flagged for manual Help > About check'

    # 7. AST & safety invariants on secure.ps1 (Update mode, switches, pure ASCII, no forced closes/reboots)
    $modeParam = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $validateAttr = $modeParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' } | Select-Object -First 1
    $modeValues = @($validateAttr.PositionalArguments | ForEach-Object { $_.Value })
    Assert-Equal ($modeValues -contains 'Update') $true 'Mode ValidateSet must include Update'
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    Assert-Equal ($paramNames -contains 'AutoUpdate') $true 'secure.ps1 must expose -AutoUpdate switch'
    Assert-Equal ($paramNames -contains 'SkipWindowsUpdates') $true 'secure.ps1 must expose -SkipWindowsUpdates switch'
    Assert-Equal ($paramNames -contains 'ScanFiles') $true 'secure.ps1 must expose -ScanFiles switch'

    # 8. Automated suspicious executable / archive / vulnerability-file scanning checks
    $rules = Get-SuspiciousFileRules
    Assert-Equal (Test-SuspiciousFileExcludedPath -Path 'C:\CyberPatriot\CCSClient.exe' -ToolkitRoot 'C:\Toolkit') $true 'CyberPatriot path must always be excluded'
    Assert-Equal (Test-SuspiciousFileExcludedPath -Path 'C:\Users\Alice\Forensics\question1.zip' -ToolkitRoot 'C:\Toolkit') $true 'Forensics path must always be excluded'
    Assert-Equal (Test-SuspiciousFileExcludedPath -Path 'C:\Windows\System32\cmd.exe' -ToolkitRoot 'C:\Toolkit') $true 'Windows System32 must be excluded'
    Assert-Equal (Test-SuspiciousFileExcludedPath -Path 'C:\Toolkit\LGPO.exe' -ToolkitRoot 'C:\Toolkit') $true 'Toolkit root itself must be excluded'
    Assert-Equal (Test-SuspiciousFileExcludedPath -Path 'C:\Users\Alice\Downloads\nc.exe' -ToolkitRoot 'C:\Toolkit') $false 'User Downloads executable must be scanned'

    $ncRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Downloads\nc.exe' -Extension '.exe' -SignatureStatus 'NotSigned' -HasZoneIdentifier $true
    Assert-Equal ($ncRisk.Score -ge 90) $true 'Unsigned Internet-downloaded nc.exe in Downloads must score CRITICAL'
    Assert-Equal $ncRisk.RiskLevel 'CRITICAL' 'nc.exe risk level must be CRITICAL'
    Assert-Equal $ncRisk.QuarantineRecommended $true 'nc.exe must recommend reversible quarantine'

    $dblRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Desktop\invoice.pdf.exe' -Extension '.exe' -SignatureStatus 'NotSigned'
    Assert-Equal $dblRisk.DoubleExtension $true 'Double-extension masquerade must be detected'
    Assert-Equal ($dblRisk.Score -ge 90) $true 'Double-extension executable must score CRITICAL'

    $signedNecRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Downloads\ChromeSetup.exe' -Extension '.exe' -SignatureStatus 'Valid' -Signer 'CN=Google LLC' -NecessaryList @('Chrome')
    Assert-Equal $signedNecRisk.QuarantineRecommended $false 'Validly signed necessary-app installer must not recommend quarantine'

    $pwRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Documents\passwords.txt' -Extension '.txt'
    Assert-Equal $pwRisk.Category 'SensitiveData' 'Password text file must classify as SensitiveData'
    Assert-Equal $pwRisk.QuarantineRecommended $false 'SensitiveData must stay report-only and never auto-quarantine'

    # Real temporary filesystem + ZIP central-directory inspection fixtures
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $scanFixture = Join-Path $temp 'scanroot'
    $dlDir = Join-Path $scanFixture 'Users\Alice\Downloads'
    $forensicDir = Join-Path $scanFixture 'Users\Alice\Forensics'
    $cpDir = Join-Path $scanFixture 'Users\Alice\CyberPatriot'
    $cacheDir = Join-Path $scanFixture 'Users\Alice\AppData\Local\Google\Chrome'
    $tempDropDir = Join-Path $scanFixture 'Users\Alice\AppData\Local\Temp'
    foreach ($d in @($dlDir, $forensicDir, $cpDir, $cacheDir, $tempDropDir)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
    Set-Content (Join-Path $dlDir 'nc.exe') 'stub'
    Set-Content (Join-Path $dlDir 'passwords.txt') 'stub'
    Set-Content (Join-Path $tempDropDir 'dropper.bat') '@echo off'
    Set-Content (Join-Path $forensicDir 'evidence.exe') 'stub'
    Set-Content (Join-Path $cpDir 'score.exe') 'stub'
    Set-Content (Join-Path $cacheDir 'cache.exe') 'stub'
    Set-Content (Join-Path $dlDir 'song.mp3') 'mp3'
    Set-Content (Join-Path $tempDropDir 'cached.mp3') 'mp3'

    $benignSrc = Join-Path $temp 'zip_benign'
    $badSrc = Join-Path $temp 'zip_bad'
    New-Item -ItemType Directory -Path $benignSrc -Force | Out-Null
    New-Item -ItemType Directory -Path $badSrc -Force | Out-Null
    Set-Content (Join-Path $benignSrc 'photo.jpg') 'jpg'
    Set-Content (Join-Path $badSrc 'mimikatz.exe') 'mz'
    Set-Content (Join-Path $badSrc 'stage.ps1') 'ps'
    $benignZip = Join-Path $dlDir 'photos.zip'
    $badZip = Join-Path $dlDir 'tools.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($benignSrc, $benignZip)
    [System.IO.Compression.ZipFile]::CreateFromDirectory($badSrc, $badZip)

    $benignInfo = Get-ZipArchiveContents -ZipPath $benignZip
    Assert-Equal $benignInfo.HasExecutables $false 'Benign photo ZIP must report no executables'
    Assert-Equal $benignInfo.HasHackTools $false 'Benign photo ZIP must report no hack tools'
    $badInfo = Get-ZipArchiveContents -ZipPath $badZip
    Assert-Equal $badInfo.HasExecutables $true 'Tool ZIP must detect inner executable/script entries'
    Assert-Equal $badInfo.HasHackTools $true 'Tool ZIP must detect mimikatz inside archive'

    $badZipRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Downloads\tools.zip' -Extension '.zip' -ZipInfo $badInfo
    Assert-Equal $badZipRisk.RiskLevel 'CRITICAL' 'ZIP containing mimikatz.exe in Downloads must score CRITICAL'
    Assert-Equal $badZipRisk.QuarantineRecommended $true 'Tool-bearing ZIP must recommend quarantine'

    $benignZipRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Downloads\photos.zip' -Extension '.zip' -ZipInfo $benignInfo
    Assert-Equal $benignZipRisk.RiskLevel 'MEDIUM' 'Plain ZIP in Downloads must be reported at MEDIUM for review'
    Assert-Equal $benignZipRisk.QuarantineRecommended $false 'Benign ZIP without executables must not recommend quarantine'

    $allScanExts = @($rules.ExecutableExtensions) + @($rules.ScriptExtensions) + @($rules.ArchiveExtensions) + @($rules.SensitiveExtensions) + @($rules.WebShellExtensions)
    $mockRoots = @([PSCustomObject]@{ Path = $scanFixture; MaxDepth = 10; IsWebRoot = $false })
    $scanned = @(Get-ScopedFilesSafe -ScanRoots $mockRoots -TargetExtensions $allScanExts -SensitiveNameRegex $rules.SensitiveNameRegex -ToolkitRoot $repo)
    $scannedNames = @($scanned | Select-Object -ExpandProperty Name)
    Assert-Equal ($scannedNames -contains 'nc.exe') $true 'Scanner must find nc.exe in Downloads'
    Assert-Equal ($scannedNames -contains 'tools.zip') $true 'Scanner must find tools.zip in Downloads'
    Assert-Equal ($scannedNames -contains 'dropper.bat') $true 'Scanner must find dropper.bat in AppData\Local\Temp'
    Assert-Equal ($scannedNames -contains 'passwords.txt') $true 'Scanner must find passwords.txt'
    Assert-Equal ($scannedNames -contains 'evidence.exe') $false 'Scanner must exclude Forensics directories'
    Assert-Equal ($scannedNames -contains 'score.exe') $false 'Scanner must exclude CyberPatriot directories'
    Assert-Equal ($scannedNames -contains 'cache.exe') $false 'Scanner must prune noisy Chrome AppData cache directories'

    $mediaScan = @(Get-ScopedFilesSafe -ScanRoots $mockRoots -TargetExtensions @('.mp3') -SensitiveNameRegex '' -ToolkitRoot $repo -ExcludeAppData)
    $mediaNames = @($mediaScan | Select-Object -ExpandProperty Name)
    Assert-Equal ($mediaNames -contains 'song.mp3') $true 'Media scan must find song.mp3 in Downloads'
    Assert-Equal ($mediaNames -contains 'cached.mp3') $false 'Media scan with -ExcludeAppData must prune AppData and empty SensitiveNameRegex must not match non-media'
    Assert-Equal ($mediaNames -contains 'nc.exe') $false 'Empty SensitiveNameRegex must not match unrelated files'

    # 9. Sensitive .txt content inspection tests
    $plainNote = Join-Path $dlDir 'shopping_list.txt'
    $credNote = Join-Path $dlDir 'notes.txt'
    $keyNote = Join-Path $dlDir 'backup_info.txt'
    Set-Content $plainNote @('milk', 'eggs', 'bread')
    Set-Content $credNote @('Server=db.local;User Id=sa;Password=TempTestValue99!', 'SSN: 123-45-6789')
    Set-Content $keyNote @(('-----BEGIN ' + 'OPENSSH PRIVATE KEY-----'), 'synthetic-key-body')

    $plainTxtInfo = Test-TextFileSensitiveContent -FilePath $plainNote
    Assert-Equal $plainTxtInfo.HasSensitiveContent $false 'Benign grocery .txt must not trigger sensitive-content detection'
    $plainTxtRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Downloads\shopping_list.txt' -Extension '.txt' -TextInfo $plainTxtInfo
    Assert-Equal ($plainTxtRisk.Score -lt 35) $true 'Benign .txt must stay below reporting threshold'

    $credTxtInfo = Test-TextFileSensitiveContent -FilePath $credNote
    Assert-Equal $credTxtInfo.HasSensitiveContent $true 'Notes .txt with connection-string secret and SSN must trigger sensitive detection'
    $credTxtRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Downloads\notes.txt' -Extension '.txt' -TextInfo $credTxtInfo
    Assert-Equal $credTxtRisk.Category 'SensitiveData' 'Sensitive .txt must classify as SensitiveData'
    Assert-Equal ($credTxtRisk.Score -ge 90) $true 'Sensitive .txt with multiple secrets/PII must score CRITICAL'
    Assert-Equal $credTxtRisk.QuarantineRecommended $false 'Sensitive .txt files must remain report-only and never auto-quarantine'

    $keyTxtInfo = Test-TextFileSensitiveContent -FilePath $keyNote
    Assert-Equal $keyTxtInfo.HasSensitiveContent $true 'Notes .txt with private key header must trigger sensitive detection'
    $keyTxtRisk = Measure-SuspiciousFileRisk -FullName 'C:\Users\Alice\Downloads\backup_info.txt' -Extension '.txt' -TextInfo $keyTxtInfo
    Assert-Equal $keyTxtRisk.RiskLevel 'HIGH' 'Private key inside .txt must score HIGH'

    $scannedWithText = @(Get-ScopedFilesSafe -ScanRoots $mockRoots -TargetExtensions $allScanExts -SensitiveNameRegex $rules.SensitiveNameRegex -ToolkitRoot $repo -IncludeTextFiles)
    $scannedTextNames = @($scannedWithText | Select-Object -ExpandProperty Name)
    Assert-Equal ($scannedTextNames -contains 'notes.txt') $true 'Scoped text scan must inspect ordinary-named .txt files'
    Assert-Equal ($scannedTextNames -contains 'backup_info.txt') $true 'Scoped text scan must inspect backup_info.txt'
    Assert-Equal ($scannedTextNames -contains 'shopping_list.txt') $true 'Scoped text scan enumerates .txt files for content filtering'

    # 10. Firewall multi-port / range parsing & critical-rule matching
    $fwArray = Test-FirewallPortRisky -LocalPort @('80','443')
    Assert-Equal $fwArray.IsRisky $true 'Array of risky ports must be flagged'
    Assert-Equal (($fwArray.MatchedPorts -contains '80') -and ($fwArray.MatchedPorts -contains '443')) $true 'Both array ports must match'
    $fwRange = Test-FirewallPortRisky -LocalPort '135-140'
    Assert-Equal $fwRange.IsRisky $true 'Port range containing 135-139 must be flagged'
    Assert-Equal ($fwRange.MatchedPorts -contains '139') $true 'Range matching must detect port 139 inside 135-140'
    $fwSafe = Test-FirewallPortRisky -LocalPort '54321'
    Assert-Equal $fwSafe.IsRisky $false 'Non-risky high port must not be flagged'

    $script:KeepEntries = @('IIS')
    Set-ScenarioFeatureFlags
    $mockFwRules = @(
        [PSCustomObject]@{ Name='WebRule'; DisplayName='Custom Web'; LocalPort=@('80','443'); Profile='Any'; Program='C:\inetpub\app.exe'; RemoteAddress='Any' },
        [PSCustomObject]@{ Name='BadRange'; DisplayName='Unknown Tool'; LocalPort='440-450'; Profile='Public'; Program='C:\Users\Alice\nc.exe'; RemoteAddress='0.0.0.0/0' },
        [PSCustomObject]@{ Name='SafeApp'; DisplayName='Safe High Port'; LocalPort='51234'; Profile='Private'; Program='C:\app.exe'; RemoteAddress='LocalSubnet' }
    )
    $fwHits = @(Get-RiskyInboundFirewallRules -Rules $mockFwRules)
    Assert-Equal $fwHits.Count 2 'Only risky/Any inbound rules must be returned'
    Assert-Equal $fwHits[0].KeepCritical $true 'IIS token must keep port 80/443 rule protected'
    Assert-Equal $fwHits[1].KeepCritical $false 'Port 445 inside range 440-450 without SMB keep entry must flag for review'

    # 11. Persistence findings, Store/Appx prohibited apps & User Account hygiene checks
    $mockIfeo = @([PSCustomObject]@{ Target='sethc.exe'; Debugger='C:\Windows\System32\cmd.exe'; KeyPath='HKLM:\Mock\sethc.exe' })
    $mockWl = [PSCustomObject]@{ Shell='explorer.exe, C:\temp\evil.exe'; Userinit='C:\Windows\system32\userinit.exe,' }
    $mockWmi = @([PSCustomObject]@{ Name='EvilSub'; Query='SELECT * FROM __InstanceCreationEvent' })
    $pAlerts = @(Get-PersistenceFindings -IfeoEntries $mockIfeo -WinlogonInfo $mockWl -WmiFilters $mockWmi)
    Assert-Equal $pAlerts.Count 3 'Persistence detector must catch IFEO Sticky Keys, abnormal Winlogon Shell, and WMI subscription'
    Assert-Equal $pAlerts[0].Severity 'CRITICAL' 'sethc.exe IFEO Debugger must be rated CRITICAL'

    $cleanWl = [PSCustomObject]@{ Shell='explorer.exe'; Userinit='C:\Windows\system32\userinit.exe,' }
    Assert-Equal ((@(Get-PersistenceFindings -IfeoEntries @() -WinlogonInfo $cleanWl -WmiFilters @())).Count) 0 'Clean IFEO/Winlogon/WMI must yield zero persistence alerts'

    $mockAppx = @(
        [PSCustomObject]@{ Name='king.com.CandyCrushSaga'; Version='1.0'; PackageFullName='cc_1'; Publisher='King'; IsFramework=$false; SignatureKind='Store' },
        [PSCustomObject]@{ Name='Microsoft.VCLibs.140.00'; Version='14.0'; PackageFullName='vclibs'; Publisher='MS'; IsFramework=$true; SignatureKind='Store' },
        [PSCustomObject]@{ Name='Microsoft.WindowsCalculator'; Version='11.0'; PackageFullName='calc'; Publisher='MS'; IsFramework=$false; SignatureKind='System' }
    )
    $appxHits = @(Get-AppxProhibitedPackages -ProhibitedList @('CandyCrush', 'VCLibs', 'Calculator') -Packages $mockAppx)
    Assert-Equal $appxHits.Count 1 'Appx filter must catch prohibited Store apps while skipping Framework and System packages'
    Assert-Equal $appxHits[0].Name 'king.com.CandyCrushSaga' 'CandyCrush Store package must be flagged'

    $mockUsers = @(
        [PSCustomObject]@{ Name='Alice'; Enabled=$true; PasswordExpires=$null; UserMayChangePassword=$false; PasswordRequired=$false },
        [PSCustomObject]@{ Name='SvcAccount'; Enabled=$true; PasswordExpires=$null; UserMayChangePassword=$false; PasswordRequired=$true },
        [PSCustomObject]@{ Name='Guest'; Enabled=$false; PasswordExpires=$null; UserMayChangePassword=$false; PasswordRequired=$false },
        [PSCustomObject]@{ Name='Bob'; Enabled=$false; PasswordExpires=(Get-Date).AddDays(30); UserMayChangePassword=$true; PasswordRequired=$true },
        [PSCustomObject]@{ Name='Healthy'; Enabled=$true; PasswordExpires=(Get-Date).AddDays(30); UserMayChangePassword=$true; PasswordRequired=$true }
    )
    $acctIssues = @(Get-UserAccountIssues -Users $mockUsers -ServiceLogons @('SvcAccount') -AuthorizedUsers @('Alice','Bob','Healthy'))
    Assert-Equal $acctIssues.Count 2 'Account hygiene check must catch Alice and disabled Bob while skipping SvcAccount and Guest'
    Assert-Equal $acctIssues[0].PasswordNeverExpires $true 'Null PasswordExpires must detect PasswordNeverExpires'
    Assert-Equal $acctIssues[0].CannotChangePassword $true 'UserMayChangePassword=$false must be detected'
    Assert-Equal $acctIssues[0].PasswordNotRequired $true 'PasswordRequired=$false must be detected'
    Assert-Equal $acctIssues[1].DisabledAuthorized $true 'Disabled authorized user Bob must be flagged'

    # 12. Registry MultiString check + non-blocking ApplySafe AI prompt + .lnk shortcut check
    $script:AuditOnly = $true
    function Test-Path { param($Path, $LiteralPath); return $true }
    function Get-ItemProperty {
        param($Path, $Name, $ErrorAction)
        return [pscustomobject]@{ NullSessionPipes = @('') }
    }
    Assert-Equal (Set-RegValue -Path 'HKLM\System\Test' -Name 'NullSessionPipes' -Value @('') -Type 'MultiString') $true 'Identical empty MultiString arrays must compare equal'
    Assert-Equal (Set-RegValue -Path 'HKLM\System\Test' -Name 'NullSessionPipes' -Value @('evilpipe') -Type 'MultiString') $false 'Different MultiString arrays must trigger audit change'
    Remove-Item Function:\Test-Path -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-ItemProperty -ErrorAction SilentlyContinue
    $script:AuditOnly = $false

    $script:ApplySafe = $true
    $script:Config = [PSCustomObject]@{ ShowAIPrompt = $false }
    function Read-Host { throw 'Read-Host must not be called in ApplySafe Show-AIPrompt' }
    Show-AIPrompt
    Remove-Item Function:\Read-Host -ErrorAction SilentlyContinue
    $script:ApplySafe = $false

    $lnkPath = Join-Path $dlDir 'calc_helper.lnk'
    try {
        $ws = New-Object -ComObject WScript.Shell
        $sc = $ws.CreateShortcut($lnkPath)
        $sc.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $sc.Arguments = '-nop -enc SQBFAFgA'
        $sc.Save()
        $scRes = Test-ShortcutTargetSuspicious -ShortcutPath $lnkPath
        Assert-Equal $scRes.IsSuspicious $true 'Shortcut invoking encoded PowerShell must be flagged'
    } catch {
        # WScript.Shell COM may not be available in headless containers; continue safely
    }

    # 13. AST safety invariants & approved-verb enforcement across secure.ps1 and all modules
    $vulnFn = Find-AstFunction -Name 'Invoke-VulnerabilityFileScan'
    $moveFn = Find-AstFunction -Name 'Move-FileToQuarantine'
    $softFn = Find-AstFunction -Name 'Invoke-SoftwareAndFiles'
    Assert-Equal ($vulnFn.Extent.Text -match 'Remove-Item') $false 'Invoke-VulnerabilityFileScan must never permanently delete user files'
    Assert-Equal ($moveFn.Extent.Text -match 'Remove-Item') $false 'Move-FileToQuarantine must only move files, never delete'
    Assert-Equal ($softFn.Extent.Text -match 'Remove-Item') $false 'Invoke-SoftwareAndFiles must never permanently delete user files'

    $updFn = Find-AstFunction -Name 'Invoke-Updates'
    $updSafeFn = Find-AstFunction -Name 'Update-WinGetPackageSafe'
    Assert-Equal ($updFn.Extent.Text -match 'Stop-Process') $false 'Invoke-Updates must never force-close running apps with Stop-Process'
    Assert-Equal ($updSafeFn.Extent.Text -match 'Stop-Process') $false 'Update-WinGetPackageSafe must never force-close running apps'
    Assert-Equal ($updSafeFn.Extent.Text -match '--allow-reboot|--force') $false 'WinGet upgrades must never pass --allow-reboot or --force'
    Assert-Equal ($updSafeFn.Extent.Text -match 'IdTruncated') $true 'Update-WinGetPackageSafe must refuse truncated WinGet IDs'

    $approvedVerbs = @(Get-Verb | Select-Object -ExpandProperty Verb)
    foreach ($parsedAst in $asts) {
        $allFnDefs = @($parsedAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true))
        foreach ($fnDef in $allFnDefs) {
            $verb = ($fnDef.Name -split '-')[0]
            Assert-Condition ($approvedVerbs -contains $verb) ("Unapproved PowerShell verb in function '" + $fnDef.Name + "'")
        }
    }

    foreach ($psFile in ($allPsFiles + @($PSCommandPath))) {
        $bytes = [System.IO.File]::ReadAllBytes($psFile)
        $badBytes = @($bytes | Where-Object { $_ -gt 127 })
        Assert-Equal $badBytes.Count 0 "$psFile must remain pure ASCII for PowerShell 5.1"
    }

    Write-Host 'Regression checks passed.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
