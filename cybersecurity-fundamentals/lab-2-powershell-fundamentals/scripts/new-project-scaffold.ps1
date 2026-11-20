#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Creates a starter project layout (src, docs, tests, config) with placeholder files.

.EXAMPLE
    ./new-project-scaffold.ps1
    ./new-project-scaffold.ps1 -Name AuditTool -Destination ~/work
#>
[CmdletBinding()]
param(
    [string]$Name = 'MyProject',
    [string]$Destination = (Get-Location).Path
)

$root = Join-Path $Destination $Name
Write-Host "Scaffolding project at $root" -ForegroundColor Green

# Folders to create inside the project root
$folders = 'src', 'docs', 'tests', 'config'
foreach ($folder in $folders) {
    New-Item -ItemType Directory -Path (Join-Path $root $folder) -Force | Out-Null
    Write-Host "  dir   $folder" -ForegroundColor Yellow
}

# Placeholder files: relative path => starting content
$files = [ordered]@{
    'src/main.ps1'         = "# Entry point for $Name"
    'docs/README.md'       = "# $Name`n`nWhat this project does goes here."
    'tests/smoke.ps1'      = '# Quick checks go here'
    'config/settings.json' = '{ "version": "1.0" }'
}
foreach ($relative in $files.Keys) {
    $target = Join-Path $root $relative
    if (Test-Path $target) {
        Write-Host "  skip  $relative (already exists)" -ForegroundColor DarkGray
        continue
    }
    New-Item -ItemType File -Path $target -Value $files[$relative] | Out-Null
    Write-Host "  file  $relative" -ForegroundColor Cyan
}

Write-Host 'Done.' -ForegroundColor Green
Get-ChildItem -Path $root -Recurse | Select-Object -ExpandProperty FullName
