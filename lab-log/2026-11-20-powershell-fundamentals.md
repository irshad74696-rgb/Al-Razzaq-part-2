# 2026-11-20 · PowerShell fundamentals on Linux

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Done (my own terminal output and screenshots still to add) |
| **Environment** | Ubuntu Linux, PowerShell 7 (`pwsh`) |
| **Lab folder** | [`Cyber-Security/powershell-fundamentals/`](../Cyber-Security/powershell-fundamentals/README.md) |

## What the lab covered

Running PowerShell 7 on Linux, the Verb-Noun naming of cmdlets, finding commands with `Get-Command` and `Get-Help`, managing files and folders with the `*-Item` cmdlets, and the basics of scripting: variables, arrays, `if`/`elseif`, `switch`, and `for`, `foreach` and `while` loops.

## Commands and configs used

```powershell
# discovery
$PSVersionTable; Get-Command -Noun Item; Get-Help Copy-Item -Examples
Get-ChildItem | Get-Member

# files and folders
New-Item -ItemType Directory -Path PowerShellLab/SubDir1/SubDir2 -Force
New-Item -ItemType File -Path original.txt -Value 'First version'
Copy-Item *.txt SubDir1/; Copy-Item SubDir1 SubDir1_Backup -Recurse
Move-Item temp2.txt SubDir1/renamed.txt
Move-Item test_*[02468].txt Level1/Level2/ -WhatIf   # preview first
Test-Path Practice/Level1/Level2 -PathType Container

# scripting
for ($i = 1; $i -le 10; $i++) { New-Item -ItemType File -Path "test_$i.txt" -Value "Test $i" | Out-Null }
Get-ChildItem -File | Sort-Object Length -Descending | Select-Object -First 5
```

Scripts: [`new-project-scaffold.ps1`](../Cyber-Security/powershell-fundamentals/scripts/new-project-scaffold.ps1), [`get-system-report.ps1`](../Cyber-Security/powershell-fundamentals/scripts/get-system-report.ps1), [`organize-by-extension.ps1`](../Cyber-Security/powershell-fundamentals/scripts/organize-by-extension.ps1), [`test-lab-setup.ps1`](../Cyber-Security/powershell-fundamentals/scripts/test-lab-setup.ps1).

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| `Cannot convert 'System.Object[]' to ... parameter 'Name'` | `New-Item -Name` takes one name only | Passed the list to `-Path` instead |
| `Set-ExecutionPolicy: Operation is not supported on this platform` | Execution policy only exists on Windows | Nothing needed on Linux; scripts already run |
| `Move-Item move*.txt SubDir2/` failed | `SubDir2` is inside `SubDir1` | Used `SubDir1/SubDir2/` |
| Organizer indexed a letter instead of an extension | One result came back as a string, not an array | Wrapped the result in `@( )` |

## Key takeaway

PowerShell passes objects, not text. Pipe anything into `Get-Member` to see what it holds, then sort and filter on those properties directly. And run `-WhatIf` before any bulk move or delete.

## Screenshots

Folder: [`screenshots/2026-11-20-powershell-fundamentals/`](screenshots/)

- `01-psversiontable.png`: `pwsh` started and `$PSVersionTable` output
- `02-validation.png`: `test-lab-setup.ps1` with every check passing
