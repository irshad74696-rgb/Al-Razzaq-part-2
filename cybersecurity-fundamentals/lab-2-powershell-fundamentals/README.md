# Lab 2: PowerShell Fundamentals on Linux

PowerShell is the main automation shell on Windows, and a lot of real-world security work (incident response on Windows hosts, Active Directory audits, reading attacker scripts) means reading or writing it. Since PowerShell 6 it is cross-platform and open source, so it can be learned on a Linux box. This lab covers the core of the language: how commands are named, how to look things up, how to work with files and folders, and the basic building blocks of a script.

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Environment** | Ubuntu Linux, PowerShell 7 (`pwsh`) |
| **Skills** | Cmdlet discovery, file and directory management, variables, arrays, conditions, loops, small automation scripts |
| **Artifacts** | [`scripts/`](scripts/): four working scripts written for this lab |

## Contents

1. [What PowerShell Core is](#1-what-powershell-core-is)
2. [How a cmdlet is named](#2-how-a-cmdlet-is-named)
3. [Finding commands and help](#3-finding-commands-and-help)
4. [Working with files and folders](#4-working-with-files-and-folders)
5. [Scripting basics](#5-scripting-basics)
6. [The scripts in this folder](#6-the-scripts-in-this-folder)
7. [Common mistakes and fixes](#7-common-mistakes-and-fixes)
8. [Cmdlet reference with Linux equivalents](#8-cmdlet-reference-with-linux-equivalents)
9. [Takeaway](#9-takeaway)

---

## 1. What PowerShell Core is

There are two PowerShells:

- **Windows PowerShell 5.1** ships with Windows, runs on the old .NET Framework, and is Windows only. It is no longer getting new features.
- **PowerShell 7** (often still called "PowerShell Core") runs on modern .NET, which is cross-platform. It installs on Linux and macOS, and its program name is `pwsh`.

The big difference from Bash is that **PowerShell passes objects, not text**. When `ls` in Bash prints a file list, the next command in the pipe receives lines of text and has to cut them apart. When `Get-ChildItem` runs, the next command receives file objects with real properties like `.Name`, `.Length` and `.LastWriteTime`. Sorting by size is `Sort-Object Length`, with no `awk` or column counting.

Start it and check the version:

```bash
pwsh
```

```powershell
$PSVersionTable          # version, edition (Core), OS
$PSVersionTable.PSVersion
exit                     # back to Bash
```

The prompt changes to `PS /home/<you>>` so you always know which shell you are in.

## 2. How a cmdlet is named

Built-in commands are called **cmdlets** and are always named **Verb-Noun**:

| Verb | Means | Examples |
| --- | --- | --- |
| `Get` | read something, change nothing | `Get-ChildItem`, `Get-Process`, `Get-Content` |
| `New` | create something | `New-Item` |
| `Set` | change something | `Set-Location`, `Set-Content` |
| `Copy`, `Move`, `Remove` | what they say | `Copy-Item`, `Move-Item`, `Remove-Item` |
| `Test` | answer true or false | `Test-Path` |

The verbs come from a fixed approved list (`Get-Verb` shows it), so once you know the pattern you can often guess a command's name. Parameters start with a dash: `-Path`, `-Recurse`, `-Force`. You can shorten a parameter as long as it stays unambiguous, and tab completion fills in both cmdlet and parameter names.

Many cmdlets have short **aliases**. On Linux, `ls`, `cd`, `pwd`, `cp` and `mv` exist as both a PowerShell alias and a real Linux program; inside `pwsh`, `cd` and `pwd` map to cmdlets, while `ls`, `cp` and `mv` run the Linux programs. Use full cmdlet names in scripts so they behave the same everywhere.

## 3. Finding commands and help

```powershell
Get-Command                      # every command available
Get-Command -Verb Get            # all Get-* commands
Get-Command -Noun Item           # everything that works on items: New-Item, Copy-Item, ...
Get-Command *process*            # wildcard search

Get-Help Get-ChildItem           # summary and syntax
Get-Help Get-ChildItem -Examples # just the examples, usually the most useful part
Get-Help Get-ChildItem -Online   # opens the full docs page
Update-Help                      # downloads the full local help (needs internet, run once)

Get-ChildItem | Get-Member       # list the properties and methods of what a command returns
```

`Get-Member` is the one beginners skip and should not. It shows you what an object actually contains, which tells you what you can sort, filter or print.

## 4. Working with files and folders

PowerShell calls files and folders **items**, which is why the same few cmdlets handle both.

### Where am I, what is here

```powershell
Get-Location                     # current folder
Set-Location ~                   # go home
Set-Location ..                  # up one level

Get-ChildItem                    # list the current folder
Get-ChildItem -Force             # include hidden items (names starting with a dot on Linux)
Get-ChildItem -Hidden            # only hidden items
Get-ChildItem -File              # files only
Get-ChildItem -Directory         # folders only
Get-ChildItem -Recurse           # walk into subfolders
Get-ChildItem *.txt              # wildcard filter
Get-ChildItem -Recurse -Filter *.log | Sort-Object Length -Descending | Select-Object -First 5
```

### Create

```powershell
New-Item -ItemType Directory -Path PowerShellLab
New-Item -ItemType Directory -Path TestDir1, TestDir2, TestDir3        # several at once: use -Path
New-Item -ItemType Directory -Path PowerShellLab/SubDir1/SubDir2 -Force # -Force builds the missing parents
New-Item -ItemType File -Path notes.txt                                 # empty file
New-Item -ItemType File -Path greeting.txt -Value 'Hello from pwsh'     # file with content
```

`-Force` on a folder means "create the parents too, and don't complain if it already exists", like `mkdir -p`. On a file, `-Force` overwrites an existing file, so use it with care.

### Copy, move, rename

```powershell
Set-Location PowerShellLab
New-Item -ItemType File -Path original.txt -Value 'First version'

Copy-Item original.txt copy1.txt                       # copy
Copy-Item original.txt SubDir1/original_backup.txt     # copy into another folder
Copy-Item *.txt SubDir1/                               # copy many with a wildcard
Copy-Item SubDir1 SubDir1_Backup -Recurse              # copy a folder and everything in it
Copy-Item original.txt copy2.txt -Confirm              # ask before doing it

Move-Item temp1.txt SubDir1/                           # move
Move-Item temp2.txt SubDir1/renamed.txt                # move and rename in one step
Rename-Item copy1.txt copy-one.txt                     # rename in place
```

Two safety switches work on almost every cmdlet that changes something:

- `-WhatIf` prints what *would* happen and does nothing. Use it before any bulk move or delete.
- `-Confirm` asks yes or no for each item.

### Check before you act

```powershell
Test-Path PowerShellLab                    # True or False
Test-Path PowerShellLab -PathType Container # True only if it is a folder
Test-Path notes.txt -PathType Leaf          # True only if it is a file
Resolve-Path ./SubDir1                      # turn a relative path into a full one
Join-Path $HOME 'Practice/Level1'           # build paths without worrying about slashes
```

## 5. Scripting basics

### Variables

Every variable starts with `$`. You don't declare a type; PowerShell works it out.

```powershell
$name = 'Analyst'
$attempts = 3
$isLocked = $false          # booleans are $true and $false

"User $name has $attempts failed logins"   # double quotes expand variables
'User $name'                               # single quotes print literally
"First file: $($files[0].Name)"            # $( ) is needed for anything beyond a plain variable
```

### Arrays and hashtables

```powershell
$ports = @(22, 80, 443)
$ports[0]           # 22, arrays start at 0
$ports[-1]          # 443, negative counts from the end
$ports.Count        # 3
$ports += 8080      # add an item

$owner = @{ 'web01' = 'ops'; 'db01' = 'data' }    # key = value pairs
$owner['web01']     # ops
$owner.Keys         # web01, db01
```

### Comparison operators

PowerShell does not use `>` and `==`, because `>` already means "redirect to a file". It uses words:

| Operator | Meaning | Operator | Meaning |
| --- | --- | --- | --- |
| `-eq` | equal | `-ne` | not equal |
| `-gt` | greater than | `-ge` | greater or equal |
| `-lt` | less than | `-le` | less or equal |
| `-like` | wildcard match (`'*.log'`) | `-match` | regex match |
| `-and`, `-or`, `-not` | combine conditions | `-contains` | array holds a value |

String comparisons ignore case by default (`'ADMIN' -eq 'admin'` is `$true`). Add a `c` for case-sensitive: `-ceq`, `-clike`.

### if / elseif / else

```powershell
$failed = 7

if ($failed -ge 10) {
    'Lock the account'
} elseif ($failed -ge 5) {
    'Raise an alert'
} else {
    'Normal'
}
```

### switch

Cleaner than a long `elseif` chain when you are matching one value against many options:

```powershell
$port = 443

switch ($port) {
    22      { 'SSH' }
    80      { 'HTTP' }
    443     { 'HTTPS' }
    default { 'Unknown service' }
}
```

`switch -Wildcard` and `switch -Regex` let each case be a pattern instead of an exact value.

### Loops

```powershell
# for: when you need a counter
for ($i = 1; $i -le 3; $i++) {
    New-Item -ItemType File -Path "report_$i.txt" -Value "Report number $i" | Out-Null
}

# foreach: once per item in a collection
foreach ($file in Get-ChildItem -File *.txt) {
    "$($file.Name) is $($file.Length) bytes"
}

# while: until a condition changes
$tries = 0
while ($tries -lt 3) {
    $tries++
    "Attempt $tries"
}
```

In a pipeline, `ForEach-Object` does the same job as `foreach`, with the current item in `$_`:

```powershell
Get-ChildItem -File | ForEach-Object { "$($_.Name): $($_.Length) bytes" }
```

### Running a script file

Save code in a `.ps1` file, then run it from inside `pwsh` with its path:

```powershell
./get-system-report.ps1
```

Or straight from Bash: `pwsh ./get-system-report.ps1`. The scripts here start with `#!/usr/bin/env pwsh` and are executable, so `./get-system-report.ps1` also works from Bash.

## 6. The scripts in this folder

All four take parameters instead of hard-coding paths, check that their target exists before touching anything, and use `Join-Path` so they work wherever they are run from. Every one of them supports `Get-Help ./<script>.ps1 -Examples`.

| Script | What it does | Try it |
| --- | --- | --- |
| [`new-project-scaffold.ps1`](scripts/new-project-scaffold.ps1) | Creates a project folder with `src`, `docs`, `tests` and `config`, plus a placeholder file in each. Skips files that already exist rather than overwriting them | `./new-project-scaffold.ps1 -Name AuditTool -Destination ~/work` |
| [`get-system-report.ps1`](scripts/get-system-report.ps1) | Prints PowerShell version, OS and user, then counts the files and folders in a directory and lists the largest files | `./get-system-report.ps1 -Path /var/log -Top 10` |
| [`organize-by-extension.ps1`](scripts/organize-by-extension.ps1) | Moves each file into a subfolder named after its extension (`txt_files`, `log_files`, ...). Supports `-WhatIf`, never overwrites, and won't move itself | `./organize-by-extension.ps1 -Path ~/Downloads -WhatIf` |
| [`test-lab-setup.ps1`](scripts/test-lab-setup.ps1) | Checks that the folders and files from the exercises exist, prints PASS or FAIL for each, and exits with 0 or 1 so other scripts can use the result | `./test-lab-setup.ps1` |

Compared with a first draft of the same ideas, a few deliberate fixes went in:

- The organizer wraps its file list in `@( )` and uses `Group-Object`. Without `@( )`, a folder with just one file type returns a single string instead of an array, and `$extensions[0]` then gives you the first *letter* of the extension.
- The scaffold script builds full paths with `Join-Path` instead of calling `Set-Location`, so it doesn't leave your shell sitting in a different folder when it finishes.
- The validation script checks real results of the exercises (nested folders, even-numbered files in `Level2`) and returns an exit code, rather than just "some file exists here".

## 7. Common mistakes and fixes

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `pwsh: command not found` | PowerShell is not installed. It is not in Ubuntu's default package list, so plain `apt install powershell` fails too | `sudo snap install powershell --classic`, or add Microsoft's package repository and then `sudo apt install powershell` |
| `Cannot convert 'System.Object[]' to the type 'System.String' required by parameter 'Name'` | Gave several names to `New-Item -Name`, which only takes one | Pass the list to `-Path` instead: `New-Item -ItemType File -Path a.txt, b.txt` |
| `Set-ExecutionPolicy: Operation is not supported on this platform` | Execution policy is a Windows feature. On Linux it is always `Unrestricted` and cannot be changed | Nothing to fix on Linux. On Windows, `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `The term 'myscript.ps1' is not recognized` | The current folder is not searched for commands | Run it with a path: `./myscript.ps1` |
| `Cannot find path '...' because it does not exist` | Wrong current folder, or a parent folder that was never created | `Get-Location` to see where you are, `Test-Path` to check, `-Force` on `New-Item` to create parents |
| `Move-Item move*.txt SubDir2/` fails | `SubDir2` lives inside `SubDir1`, not next to the files | Use the real path: `Move-Item move*.txt SubDir1/SubDir2/` |
| `Move-Item TestDir1 PowerShellLab/` fails | You already `Set-Location` into `PowerShellLab`, so the relative paths no longer match | `Set-Location ..` first, or use full paths |
| `New-Item: The file '...' already exists` | Re-running a script | Check first with `Test-Path`, or add `-Force` if overwriting is really what you want |
| `Access to the path '...' is denied` | Writing somewhere your user can't, such as `/etc` or another user's home | Work under `~`, or start `sudo pwsh` only for tasks that truly need root |
| `.Count` is wrong, or `[0]` returns a single character | A command returned one item, not an array | Wrap it: `@(Get-ChildItem -File).Count` |
| Comparison like `if ($a > 5)` creates a file called `5` | `>` is redirection in PowerShell | Use `-gt` |

## 8. Cmdlet reference with Linux equivalents

| PowerShell | Short alias | Linux shell | Notes |
| --- | --- | --- | --- |
| `Get-Location` | `gl`, `pwd` | `pwd` | |
| `Set-Location <path>` | `sl`, `cd` | `cd <path>` | `Set-Location -` goes back, like `cd -` |
| `Get-ChildItem` | `gci`, `dir` | `ls` | |
| `Get-ChildItem -Force` | | `ls -a` | |
| `Get-ChildItem -Recurse` | | `ls -R`, `find .` | |
| `Get-ChildItem -Recurse -Filter *.log` | | `find . -name '*.log'` | |
| `New-Item -ItemType Directory -Path a/b -Force` | | `mkdir -p a/b` | |
| `New-Item -ItemType File -Path f.txt` | `ni` | `touch f.txt` | `touch` also updates timestamps; `New-Item` does not |
| `Copy-Item src dst` | `copy`, `cpi` | `cp src dst` | |
| `Copy-Item dir dst -Recurse` | | `cp -r dir dst` | |
| `Move-Item src dst` | `move`, `mi` | `mv src dst` | |
| `Rename-Item old new` | `ren`, `rni` | `mv old new` | |
| `Remove-Item f.txt` | `del`, `ri` | `rm f.txt` | |
| `Remove-Item dir -Recurse` | | `rm -r dir` | |
| `Test-Path f.txt` | | `test -e f.txt` | `-PathType Leaf` is `test -f`, `Container` is `test -d` |
| `Resolve-Path rel/path` | `rvpa` | `realpath rel/path` | |
| `Get-Content f.txt` | `gc` | `cat f.txt` | `-Tail 20 -Wait` is `tail -f` |
| `Set-Content f.txt 'x'` / `Add-Content` | | `echo x > f.txt` / `>>` | |
| `Select-String 'error' f.log` | `sls` | `grep error f.log` | |
| `Sort-Object Length -Descending` | | `sort -rn` | Sorts on a property, no column cutting |
| `Select-Object -First 5` | `select` | `head -n 5` | |
| `Where-Object { $_.Length -gt 1MB }` | `where`, `?` | `awk` / `find -size` | Filters objects by any property |
| `Measure-Object` | `measure` | `wc -l` | |
| `Get-Process` | `gps` | `ps aux` | |
| `Get-Help <cmd>` | `help` | `man <cmd>` | |
| `Get-Command <name>` | `gcm` | `which`, `type` | |
| `Write-Host`, `Write-Output` | `echo` | `echo` | Prefer `Write-Output` (or a bare value) when the text should go down the pipeline |

Aliases that clash with a Linux program (`ls`, `cp`, `mv`, `rm`, `cat`, `ps`, `sort`) are left out on Linux, so those names run the real Linux tools. Aliases are fine at the prompt. In scripts, write the full cmdlet name so the script reads clearly and doesn't depend on which Linux tools are installed.

## 9. Takeaway

The idea to hold onto is that PowerShell passes **objects**. Once that clicks, `Get-Member` tells you what's inside them, `Where-Object` and `Sort-Object` work on any property, and the Verb-Noun naming means you can usually find the command you need with `Get-Command`. For security work, this matters both ways: defenders use it to collect evidence and audit systems at scale, and attackers use it for the same reasons, so being able to read a PowerShell script is a core skill. Make `-WhatIf` a habit before any bulk change.
