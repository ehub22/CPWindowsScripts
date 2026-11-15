# Run with Windows PowerShell 5.1: powershell.exe -NoProfile -File tests\regression.ps1
# Load only pure helpers from the AST: never execute the hardening engine here.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'secure.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @('Test-FileEdited', 'Get-TextList', 'Test-ConfigReady', 'Get-InstalledPrograms', 'Test-ServiceScenarioKept', 'Test-TokenKept', 'Set-ScenarioFeatureFlags', 'Add-KeptService')) {
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
    Write-Host 'Regression checks passed.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
}
