# Run with Windows PowerShell 5.1: powershell.exe -NoProfile -File tests\regression.ps1
# Load only pure helpers from the AST: never execute the hardening engine here.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'secure.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @(
    'Test-FileEdited', 'Get-TextList', 'Get-UpdateConfig', 'Test-ConfigReady',
    'Get-InstalledPrograms', 'Test-ServiceScenarioKept', 'Test-TokenKept',
    'Set-ScenarioFeatureFlags', 'Add-KeptService', 'Get-KnownAppDependencyCatalog',
    'Get-NecessaryAppsFromServices', 'Test-MatchAgainstPatterns', 'Format-CommandArguments',
    'ConvertFrom-WinGetListOutput', 'Select-UpdatablePackages', 'Get-UnmappedNecessaryApps',
    'Get-SuspiciousFileRules', 'Test-SuspiciousFileExcludedPath', 'Get-ZipArchiveContents',
    'Test-TextFileSensitiveContent', 'Measure-SuspiciousFileRisk', 'Get-ScopedFilesSafe'
)) {
    $func = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -eq $func) { throw "Missing function $name" }
    Invoke-Expression $func.Extent.Text
}
function Assert-Equal($actual, $expected, $message) {
    if ($actual -ne $expected) { throw "$message (expected $expected; got $actual)" }
}
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('cp-tests-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $repo = Split-Path $PSScriptRoot -Parent
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
        [pscustomobject]@{ DisplayName = $Path }
    }
    $programs = @(Get-InstalledPrograms)
    Assert-Equal $programs.Count 3 'All three uninstall registry locations should be queried'
    Assert-Equal (($script:seenPaths | Where-Object { $_ -notmatch '^HK(LM|CU):\\' }).Count) 0 'Registry paths need a PowerShell drive colon'

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

    $vulnFn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-VulnerabilityFileScan' }, $true)
    $moveFn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Move-FileToQuarantine' }, $true)
    Assert-Equal ($vulnFn.Extent.Text -match 'Remove-Item') $false 'Invoke-VulnerabilityFileScan must never permanently delete user files'
    Assert-Equal ($moveFn.Extent.Text -match 'Remove-Item') $false 'Move-FileToQuarantine must only move files, never delete'

    $updFn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-Updates' }, $true)
    $updSafeFn = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Update-WinGetPackageSafe' }, $true)
    Assert-Equal ($updFn.Extent.Text -match 'Stop-Process') $false 'Invoke-Updates must never force-close running apps with Stop-Process'
    Assert-Equal ($updSafeFn.Extent.Text -match 'Stop-Process') $false 'Update-WinGetPackageSafe must never force-close running apps'
    Assert-Equal ($updSafeFn.Extent.Text -match '--allow-reboot|--force') $false 'WinGet upgrades must never pass --allow-reboot or --force'
    Assert-Equal ($updSafeFn.Extent.Text -match 'IdTruncated') $true 'Update-WinGetPackageSafe must refuse truncated WinGet IDs'

    foreach ($psFile in @($source, $PSCommandPath)) {
        $bytes = [System.IO.File]::ReadAllBytes($psFile)
        $badBytes = @($bytes | Where-Object { $_ -gt 127 })
        Assert-Equal $badBytes.Count 0 "$psFile must remain pure ASCII for PowerShell 5.1"
    }

    Write-Host 'Regression checks passed.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
