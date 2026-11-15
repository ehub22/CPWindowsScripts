
# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
function Write-Banner {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host ("[*] " + $Text)
}

function Write-Good {
    param([string]$Text)
    Write-Host ("[+] " + $Text) -ForegroundColor Green
    [void]$script:Changes.Add($Text)
}

function Write-WarnLine {
    param([string]$Text)
    Write-Host ("[!] " + $Text) -ForegroundColor Yellow
    [void]$script:Warnings.Add($Text)
}

function Confirm-YesNo {
    param([string]$Question, [bool]$DefaultYes = $true)
    if ($script:ApplySafe -or $script:AuditOnly -or $script:UpdateOnly -or $script:AutoUpdateStep) { return $DefaultYes }
    $suffix = ' [Y/n]'
    if (-not $DefaultYes) { $suffix = ' [y/N]' }
    try {
        $answer = Read-Host ($Question + $suffix)
    } catch {
        return $DefaultYes
    }
    if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultYes }
    $answer = $answer.Trim().ToLower()
    if ($answer -eq 'c' -or $answer -eq 'q') { throw 'User cancelled.' }
    return ($answer -eq 'y' -or $answer -eq 'yes')
}

function Wait-Enter {
    param([string]$Text = 'Press ENTER to continue...')
    if ($script:ApplySafe -or $script:UpdateOnly) { return }
    try { Read-Host $Text | Out-Null } catch {}
}

function Test-Admin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-CommandExists {
    param([string]$Name)
    return ($null -ne (Get-Command $Name -ErrorAction SilentlyContinue))
}

function Get-TextList {
    param([string]$Path)
    $items = @()
    if (-not (Test-Path $Path)) { return $items }
    foreach ($line in (Get-Content $Path -ErrorAction SilentlyContinue)) {
        $t = $line.Trim()
        if ($t.Length -eq 0) { continue }
        if ($t.StartsWith('#')) { continue }
        $items += $t
    }
    return $items
}

function Get-UpdateConfig {
    param([string]$Path)
    $necessary = New-Object System.Collections.ArrayList
    $excluded = New-Object System.Collections.ArrayList
    if (-not [string]::IsNullOrWhiteSpace($Path) -and (Test-Path -LiteralPath $Path)) {
        foreach ($line in @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            $t = ([string]$line).Trim()
            if ($t.Length -eq 0 -or $t.StartsWith('#') -or $t -ieq 'EDIT_ME') { continue }
            if ($t.StartsWith('!')) {
                $item = $t.Substring(1).Trim()
                if ($item.Length -gt 0) { [void]$excluded.Add($item) }
            } else {
                [void]$necessary.Add($t)
            }
        }
    }
    return [PSCustomObject]@{
        Necessary = @($necessary)
        Excluded  = @($excluded)
    }
}

function Test-FileEdited {
    param([string]$Path)
    # Only an active marker counts. Instructions in comment lines deliberately
    # mention EDIT_ME and must not prevent a completed file from being used.
    try {
        $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
        foreach ($line in $lines) {
            $text = $line.Trim()
            if (-not $text -or $text.StartsWith('#')) { continue }
            if ($text -ieq 'EDIT_ME') { return $false }
        }
        return $true
    } catch { return $false }
}

function Add-Report {
    param([string]$File, [string]$Heading, [object]$Content)
    $path = Join-Path $script:ReportDir $File
    try {
        Add-Content $path ''
        Add-Content $path ('----- ' + $Heading + ' -----')
        if ($null -eq $Content) { Add-Content $path '(none found)' }
        else { ($Content | Out-String -Width 250) | Add-Content $path }
    } catch {}
}

function Set-RegValue {
    param(
        [string]$Path, [string]$Name, [object]$Value,
        [ValidateSet('DWord','String','MultiString','ExpandString')]
        [string]$Type = 'DWord',
        [string]$Why = ''
    )
    # Path uses HKLM\... form; convert to a PowerShell drive path.
    $psPath = $Path -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\'
    try {
        $before = $null
        $keyExists = Test-Path $psPath
        if ($keyExists) {
            $item = Get-ItemProperty $psPath -Name $Name -ErrorAction SilentlyContinue
            if ($null -ne $item) { $before = $item.$Name }
        }
        $alreadyEqual = $false
        if ($null -ne $before) {
            if ($Type -eq 'MultiString') {
                $beforeArr = @($before | ForEach-Object { [string]$_ })
                $valArr = @($Value | ForEach-Object { [string]$_ })
                if ($beforeArr.Count -eq $valArr.Count) {
                    $alreadyEqual = $true
                    for ($idx = 0; $idx -lt $valArr.Count; $idx++) {
                        if ($beforeArr[$idx] -cne $valArr[$idx]) { $alreadyEqual = $false; break }
                    }
                }
            } else {
                $alreadyEqual = ("$before" -eq "$Value")
            }
        }
        $beforeDisplay = $before
        if ($before -is [System.Array]) { $beforeDisplay = ('@(' + (($before | ForEach-Object { '"' + $_ + '"' }) -join ', ') + ')') }
        $valueDisplay = $Value
        if ($Value -is [System.Array]) { $valueDisplay = ('@(' + (($Value | ForEach-Object { '"' + $_ + '"' }) -join ', ') + ')') }
        if ($alreadyEqual) {
            Write-Step ("Already set : " + $Path + '\' + $Name + ' = ' + $valueDisplay)
            return $true
        }
        if ($script:AuditOnly) {
            Write-Host ("[AUDIT] Would set " + $Path + '\' + $Name + ' = ' + $valueDisplay + ' (now: ' + $beforeDisplay + ')')
            return $false
        }
        if (-not $keyExists) { New-Item -Path $psPath -Force | Out-Null }
        $writeVal = $Value
        if ($Type -eq 'MultiString') { $writeVal = [string[]]@($Value | ForEach-Object { [string]$_ }) }
        New-ItemProperty -Path $psPath -Name $Name -Value $writeVal -PropertyType $Type -Force | Out-Null
        Write-Good ("Set " + $Path + '\' + $Name + ' = ' + $valueDisplay + ' (was: ' + $beforeDisplay + ')  ' + $Why)
        return $true
    } catch {
        Write-WarnLine ("Could not set " + $Path + '\' + $Name + ' : ' + $_.Exception.Message)
        return $false
    }
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    $psPath = $Path -replace '^HKLM\\', 'HKLM:\' -replace '^HKCU\\', 'HKCU:\'
    try {
        $item = Get-ItemProperty $psPath -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch { return $null }
}

function Export-RegKey {
    param([string]$RegPath, [string]$OutFile)
    try { & reg.exe export $RegPath $OutFile /y 2>$null | Out-Null } catch {}
}


# ----------------------------------------------------------------------------
# AI paragraph (printed on first run)
# ----------------------------------------------------------------------------
function Show-AIPrompt {
    $forceShow = ($null -ne $script:Config -and [bool]$script:Config.ShowAIPrompt)
    if (($script:UpdateOnly -or $script:ApplySafe) -and -not $forceShow) { return }
    $marker = Join-Path $script:Root '.ai_prompt_acknowledged'
    if ((Test-Path $marker) -and -not $forceShow) { return }
    Write-Banner 'STEP 0 OF 12 - PROTECT CRITICAL SERVICES (READ THIS FIRST)'
    Write-Host 'Disabling a service the scenario needs, or deleting an authorized user,' -ForegroundColor Yellow
    Write-Host 'LOSES points. Before this script touches anything, identify the critical' -ForegroundColor Yellow
    Write-Host 'services from the README that sits on the image desktop.'
    Write-Host ''
    Write-Host 'The paragraph between the lines below is a prompt for an' -ForegroundColor Yellow
    Write-Host 'AI model. Copy it, then paste the image README immediately after it.' -ForegroundColor Yellow
    Write-Host 'It also lives in AI_PROMPT.txt next to this script. Paste the AI output' -ForegroundColor Yellow
    Write-Host 'into keep_services.txt / authorizedusers.txt / admins.txt / rdpusers.txt' -ForegroundColor Yellow
    Write-Host '/ necessary_apps.txt and VERIFY EVERY LINE against the original README.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '------------------------- COPY FROM HERE -------------------------' -ForegroundColor White
    $promptFile = Join-Path $script:Root 'AI_PROMPT.txt'
    if (Test-Path $promptFile) {
        Get-Content $promptFile | ForEach-Object { Write-Host $_ }
    } else {
        Write-Host 'List every critical / necessary service in the README pasted below that must NOT be disabled, with Windows service names, ports and dependencies, then give paste-ready lists for keep_services.txt, authorizedusers.txt, admins.txt and rdpusers.txt. The README is:'
    }
    Write-Host '------------------------- COPY TO HERE ---------------------------' -ForegroundColor White
    Write-Host ''
    Wait-Enter 'Copy the paragraph now if you need it, then press ENTER to continue ...'
    try { Set-Content $marker (Get-Date -Format s) -Force } catch {}
}


function Test-ConfigReady {
    # True when the README-driven files have actually been edited.
    $ok = (Test-FileEdited (Join-Path $script:Root 'keep_services.txt')) -and
          (Test-FileEdited (Join-Path $script:Root 'authorizedusers.txt')) -and
          (Test-FileEdited (Join-Path $script:Root 'admins.txt'))
    return $ok
}

