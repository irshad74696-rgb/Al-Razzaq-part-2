#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Sorts the files in a folder into subfolders named after their extension (txt_files, log_files, ...).

.DESCRIPTION
    Files with no extension are left where they are. A file whose name already exists in the
    target subfolder is skipped, never overwritten. Run with -WhatIf first to preview the moves.

.EXAMPLE
    ./organize-by-extension.ps1 -Path ~/Downloads -WhatIf
    ./organize-by-extension.ps1 -Path ~/Downloads
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Path = (Get-Location).Path
)

if (-not (Test-Path -Path $Path -PathType Container)) {
    Write-Error "Folder not found: $Path"
    exit 1
}
$Path = (Resolve-Path -Path $Path).Path

Write-Host "=== Organizing $Path ===" -ForegroundColor Blue

# Never move this script if it happens to live in the folder being organized
$files = @(Get-ChildItem -Path $Path -File |
    Where-Object { $_.Extension -ne '' -and $_.FullName -ne $PSCommandPath })

if ($files.Count -eq 0) {
    Write-Host 'No files with an extension found. Nothing to do.' -ForegroundColor Red
    exit 0
}

# Group-Object gives one group per extension, with its files attached
$groups = $files | Group-Object -Property { $_.Extension.ToLower() } | Sort-Object Name

Write-Host "`nExtensions found:" -ForegroundColor Yellow
$i = 1
foreach ($group in $groups) {
    '  {0}. {1} ({2} file(s))' -f $i, $group.Name, $group.Count
    $i++
}

$moved = 0
$skipped = 0
foreach ($group in $groups) {
    $folder = Join-Path $Path ($group.Name.TrimStart('.') + '_files')

    if (-not (Test-Path $folder) -and $PSCmdlet.ShouldProcess($folder, 'Create folder')) {
        New-Item -ItemType Directory -Path $folder | Out-Null
        Write-Host "Created $folder" -ForegroundColor Green
    }

    foreach ($file in $group.Group) {
        $target = Join-Path $folder $file.Name
        if (Test-Path $target) {
            Write-Warning "Skipped $($file.Name): already exists in $(Split-Path $folder -Leaf)"
            $skipped++
            continue
        }
        if ($PSCmdlet.ShouldProcess($file.FullName, "Move to $folder")) {
            Move-Item -Path $file.FullName -Destination $target
            Write-Host "Moved $($file.Name) -> $(Split-Path $folder -Leaf)/" -ForegroundColor Cyan
            $moved++
        }
    }
}

Write-Host "`nDone. Moved: $moved  Skipped: $skipped" -ForegroundColor Green
