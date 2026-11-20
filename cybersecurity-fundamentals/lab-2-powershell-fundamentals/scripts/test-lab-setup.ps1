#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Checks that the folders and files from the lab exercises exist. Exits 0 if every check passes, 1 otherwise.

.EXAMPLE
    ./test-lab-setup.ps1              # checks under your home folder
    ./test-lab-setup.ps1 -BasePath /tmp/pwsh-practice
#>
[CmdletBinding()]
param(
    [string]$BasePath = $HOME
)

Write-Host "=== Lab validation (base: $BasePath) ===" -ForegroundColor Magenta

$script:passed = 0
$script:total = 0

function Test-Step {
    param(
        [string]$Description,
        [scriptblock]$Check
    )
    $script:total++
    $ok = $false
    try { $ok = [bool](& $Check) } catch { $ok = $false }
    if ($ok) {
        Write-Host "[PASS] $Description" -ForegroundColor Green
        $script:passed++
    } else {
        Write-Host "[FAIL] $Description" -ForegroundColor Red
    }
}

$lab      = Join-Path $BasePath 'PowerShellLab'
$practice = Join-Path $BasePath 'Practice'
$level1   = Join-Path $practice 'Level1'
$level2   = Join-Path $level1 'Level2'

Test-Step 'PowerShellLab folder exists'          { Test-Path $lab -PathType Container }
Test-Step 'PowerShellLab/SubDir1/SubDir2 exists'  { Test-Path (Join-Path $lab 'SubDir1/SubDir2') -PathType Container }
Test-Step 'original.txt exists in PowerShellLab'  { Test-Path (Join-Path $lab 'original.txt') -PathType Leaf }
Test-Step 'Practice/Level1/Level2 exists'          { Test-Path $level2 -PathType Container }
Test-Step 'A file exists at every Practice level' {
    (Test-Path (Join-Path $practice 'root_file.txt')) -and
    (Test-Path (Join-Path $level1 'level1_file.txt')) -and
    (Test-Path (Join-Path $level2 'level2_file.txt'))
}
Test-Step 'Level1 holds copies of the test_*.txt files' {
    @(Get-ChildItem -Path $level1 -Filter 'test_*.txt' -File).Count -gt 0
}
Test-Step 'Level2 holds only even-numbered test files' {
    $names = @(Get-ChildItem -Path $level2 -Filter 'test_*.txt' -File).Name
    $names.Count -gt 0 -and -not ($names | Where-Object { $_ -notmatch '^test_\d*[02468]\.txt$' })
}

Write-Host "`n=== Result: $script:passed/$script:total checks passed ===" -ForegroundColor Yellow
if ($script:passed -eq $script:total) {
    Write-Host 'Everything is in place.' -ForegroundColor Green
    exit 0
}
Write-Host 'Some checks failed. Re-run the matching exercise and try again.' -ForegroundColor Red
exit 1
