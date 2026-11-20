#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Prints a short report: PowerShell version, OS, a folder's contents and its largest files.

.EXAMPLE
    ./get-system-report.ps1
    ./get-system-report.ps1 -Path /var/log -Top 10
#>
[CmdletBinding()]
param(
    [string]$Path = (Get-Location).Path,
    [int]$Top = 5
)

if (-not (Test-Path -Path $Path -PathType Container)) {
    Write-Error "Folder not found: $Path"
    exit 1
}
$Path = (Resolve-Path -Path $Path).Path

Write-Host '=== System report ===' -ForegroundColor Magenta

Write-Host "`nPowerShell" -ForegroundColor Yellow
"  Version : $($PSVersionTable.PSVersion)"
"  Edition : $($PSVersionTable.PSEdition)"
"  OS      : $($PSVersionTable.OS)"
"  User    : $([Environment]::UserName) on $([Environment]::MachineName)"

# @() keeps .Count correct even when there are zero or one items
$files = @(Get-ChildItem -Path $Path -File -ErrorAction SilentlyContinue)
$dirs  = @(Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue)

Write-Host "`nContents of $Path" -ForegroundColor Yellow
"  Files       : $($files.Count)"
"  Directories : $($dirs.Count)"

Write-Host "`nLargest $Top files" -ForegroundColor Yellow
if ($files.Count -eq 0) {
    '  (no files)'
} else {
    $files |
        Sort-Object -Property Length -Descending |
        Select-Object -First $Top |
        ForEach-Object { '  {0,12:N0} bytes  {1}' -f $_.Length, $_.Name }
}

Write-Host "`nReport complete." -ForegroundColor Green
