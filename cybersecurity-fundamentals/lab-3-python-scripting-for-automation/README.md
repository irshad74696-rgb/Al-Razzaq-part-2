# Lab 3: Python Scripting for Security Automation

Most security work is repetitive: read an inventory, write an event to a log, clear out junk files, check a value against a rule, do it again tomorrow. Python is the usual tool for turning those chores into scripts that run the same way every time. This lab builds five small command-line tools that practise the basics: reading and writing files safely, handling errors, automating a cleanup job, and combining loops, conditions and functions into something useful.

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Environment** | Ubuntu Linux, Python 3 (standard library only, nothing to `pip install`) |
| **Skills** | File I/O with context managers, CSV parsing, exception handling, `argparse`, safe file deletion, loops, conditions, functions |
| **Artifacts** | [`scripts/`](scripts/): five working scripts, [`data/`](data/): sample inventory CSV |

## Contents

1. [Quick start](#1-quick-start)
2. [Reading and writing files](#2-reading-and-writing-files)
3. [Why `with open()` matters](#3-why-with-open-matters)
4. [Handling errors](#4-handling-errors)
5. [Automating a folder cleanup](#5-automating-a-folder-cleanup)
6. [Loops, conditions and functions together](#6-loops-conditions-and-functions-together)
7. [What I changed from the handout versions](#7-what-i-changed-from-the-handout-versions)
8. [Common mistakes and fixes](#8-common-mistakes-and-fixes)
9. [Takeaway](#9-takeaway)

---

## 1. Quick start

```bash
cd cybersecurity-fundamentals/lab-3-python-scripting-for-automation

python3 scripts/file_reader.py                  # print the device inventory
python3 scripts/log_writer.py                   # append sample events to logs/security.log
python3 scripts/folder_cleanup.py --make-sample # build temp_files/ to practise on
python3 scripts/folder_cleanup.py               # dry run: shows what it would delete
python3 scripts/folder_cleanup.py --delete      # actually delete
python3 scripts/network_monitor.py              # 5 simulated scans, 2 s apart
python3 scripts/password_checker.py             # score the example passwords
python3 scripts/password_checker.py --interactive
```

Every script has `--help`. Paths are worked out from the script's own location, so they work from any directory. `logs/` and `temp_files/` are created on demand and are ignored by git.

| Script | What it does |
| --- | --- |
| `file_reader.py` | Reads `data/network_devices.csv` (or any CSV you pass) and prints a table plus an active/inactive count. Bad rows are reported with their line number. |
| `log_writer.py` | Appends `[timestamp] LEVEL: message` lines to a log. Writes sample events, or one of your own with `--event WARNING "text"`. |
| `folder_cleanup.py` | Finds files by extension (`tmp log cache bak` by default), removes them and any folders left empty. Dry run unless you pass `--delete`. |
| `network_monitor.py` | Generates fake traffic numbers, rates each scan LOW / MEDIUM / HIGH, logs anything above LOW, prints a summary. |
| `password_checker.py` | Scores passwords out of 11 on length, character variety, common-password and repetition rules, with suggestions. |

## 2. Reading and writing files

`open(path, mode)` returns a file object. The mode decides what you can do:

| Mode | Meaning | If the file exists | If it does not |
| --- | --- | --- | --- |
| `"r"` | read (default) | read from the start | `FileNotFoundError` |
| `"w"` | write | **emptied first** | created |
| `"a"` | append | new text goes on the end | created |
| `"x"` | create | `FileExistsError` | created |

Logs should always use `"a"`. Opening a log with `"w"` silently wipes its history, which is the last thing you want during an investigation.

Reading line by line is the normal pattern, because it never loads the whole file into memory:

```python
with open("data/network_devices.csv", newline="", encoding="utf-8") as f:
    for row in csv.reader(f):
        name, ip, status = row
```

For CSV, use the `csv` module instead of `line.split(",")`. It copes with quoted fields that contain commas, and `newline=""` is what the docs ask for so line endings are handled correctly.

Two more habits worth keeping:

- Say `encoding="utf-8"`. Without it Python uses the system default, which differs between machines.
- Create the output folder before writing: `log_path.parent.mkdir(parents=True, exist_ok=True)`. A missing `logs/` folder was one of the first errors I hit.

## 3. Why `with open()` matters

A `with` block is a **context manager**: when the block ends, the file is closed, even if an exception happened halfway through.

```python
# Without with: if write() raises, close() never runs
f = open("security.log", "a")
f.write(entry)
f.close()

# With with: closed no matter what
with open("security.log", "a") as f:
    f.write(entry)
```

Why that matters in practice:

- **Data actually reaches disk.** Writes are buffered. Until the file is flushed or closed, the last lines may only exist in memory, and a crash loses them.
- **No leaked file handles.** Each process has a limit on open files (`ulimit -n`). A monitoring loop that opens a log every few seconds and never closes it will eventually fail with `Too many open files`.
- **Other programs see a consistent file.** Log shippers and `tail -f` read what has been flushed.

## 4. Handling errors

File operations fail for ordinary reasons: wrong path, no permission, disk full. A script should say what went wrong in one line instead of dumping a traceback, and should exit with a non-zero status so a cron job or another script can tell it failed.

```python
try:
    devices, problems = read_devices(args.csv_file)
except FileNotFoundError:
    print(f"Error: '{args.csv_file}' not found.", file=sys.stderr)
    return 1
except PermissionError:
    print(f"Error: no permission to read '{args.csv_file}'.", file=sys.stderr)
    return 1
```

Guidelines I followed:

- **Catch the specific exception you expect.** `FileNotFoundError` and `PermissionError` are both subclasses of `OSError`, so `except OSError` covers "anything the OS refused".
- **Avoid a bare `except Exception` around everything.** It hides real bugs, such as a typo in a variable name, behind a friendly message.
- **Errors go to stderr** (`file=sys.stderr`), normal output to stdout, so `> report.txt` captures only the report.
- **Return an exit code** with `sys.exit(main())`. `0` means success. Check it with `echo $?`.

## 5. Automating a folder cleanup

The cleanup tool shows the most important rule of automation that deletes things: **it must be safe to run by accident.**

```bash
python3 scripts/folder_cleanup.py --make-sample       # practice files
python3 scripts/folder_cleanup.py                     # DRY RUN, removes nothing
python3 scripts/folder_cleanup.py --delete            # removes 11 files and 1 empty folder
python3 scripts/folder_cleanup.py /path --ext tmp --no-recursive
```

How it works:

1. **Find candidates.** `Path.rglob("*")` walks the folder recursively. A file matches if it is a regular file (not a symlink) and its suffix is in the extension list.
2. **Work out which folders become empty.** `os.walk(..., topdown=False)` visits the deepest folders first, so a parent can be marked empty after its children are.
3. **Act, or just report.** Without `--delete` every line says "Would remove". With it, files are unlinked and empty folders removed.

Safety features:

- **Dry run is the default.** You see the exact list before anything happens.
- **Refuses obvious disasters.** It will not clean `/`, your home folder, or top-level system folders like `/etc` or `/usr`.
- **Does not follow symlinks.** A symlink named `x.tmp` pointing at something important is left alone.
- **Prints a before and after tree**, which doubles as a record of what changed.

In real life the same idea cleans old rotated logs, stale downloads in `/tmp`, or temporary files a tool forgot to remove. Scheduled with cron or a systemd timer, it runs unattended, which is exactly why the safety defaults matter.

## 6. Loops, conditions and functions together

The last two scripts are small security tools built from the three basic pieces.

**Functions** give each job a name and one responsibility: `sample_metrics()` produces numbers, `assess()` judges them, `show()` prints, `log_scan()` writes. Each can be tested on its own, and `main()` reads like a summary of the program.

**Conditions** turn numbers into decisions. In the monitor, each check adds a finding with its own level, and the overall level is the worst one:

```python
if m["failed_logins"] > 10:
    findings.append(("HIGH", "High number of failed logins"))
elif m["failed_logins"] > 5:
    findings.append(("MEDIUM", "Elevated failed logins"))
...
level = max((lvl for lvl, _ in findings), key=LEVEL_RANK.get, default="LOW")
```

Ranking levels with a dictionary avoids the tangle of `if threat_level != "HIGH": threat_level = "MEDIUM"` that is easy to get wrong when you add a new rule.

**Loops** repeat the work. The monitor uses `for scan_no in range(1, args.scans + 1)` with a `time.sleep()` between scans, and catches `KeyboardInterrupt` so Ctrl+C prints the summary instead of a traceback. The password checker loops over a list, a file, or (with `--interactive`) keeps asking until you enter an empty line.

```bash
python3 scripts/network_monitor.py --scans 12 --interval 5
python3 scripts/network_monitor.py --seed 42 --interval 0   # same output every time
python3 scripts/password_checker.py --file candidates.txt
```

The monitor's data is random, not real traffic. The structure (collect, assess, alert, log, summarise) is the same one real monitoring tools use; only the data source would change.

The password score is a teaching heuristic. It rewards character variety, but in reality **length beats complexity**, and proper checkers compare against lists of breached passwords. `Password1` scoring "STRONG" here is a good example of why simple rules are not enough.

## 7. What I changed from the handout versions

The lab's example code had a few real bugs and risky defaults. My versions fix them:

| Problem in the handout | Effect | Fix here |
| --- | --- | --- |
| `import os` was inside `main()` in the network monitor, but `generate_summary_report()` used `os.path.exists` | `NameError: name 'os' is not defined` at the end of every run | All imports at the top of the file |
| Paths hardcoded as `../data/...` and `../logs/...` | Scripts only worked when run from inside `scripts/`; otherwise `FileNotFoundError` | Paths built from `Path(__file__).resolve().parent.parent`, and overridable with arguments |
| Log writer and monitor assumed `logs/` existed | `FileNotFoundError` on a fresh checkout | `mkdir(parents=True, exist_ok=True)` before writing |
| Cleanup deleted immediately with no preview | One wrong path and files are gone | Dry run by default, `--delete` to act, refuses `/` and home |
| Cleanup used `glob("*.ext")` on the top folder only | `.bak` files in `old_backups/` were never removed, so the "remove empty folders" step never had anything to do | Recursive search (switch off with `--no-recursive`) |
| Monitor summary counted "Threat Level: HIGH" in the whole log file | Numbers grew every run because the log is appended to | Summary counts this run only |
| Monitor ran for a fixed minute | Slow to test | `--scans`, `--interval` and `--seed` options |
| Password checker always ended in an `input()` loop and echoed passwords | Could not run unattended; password visible on screen | Report by default, `--interactive` uses `getpass` (hidden) |
| Special-character check used a hand-typed regex class | Symbols like `-`, `_` or `+` did not count | Uses `string.punctuation` |
| Repetition rule penalised every long passphrase | `CorrectHorseBatteryStaple9!` lost points | Ratio rule only under 16 characters, plus a check for 3 identical characters in a row |
| CSV split with `line.split(",")`, wrong rows silently skipped | Quoted commas break it; bad data goes unnoticed | `csv` module, bad rows reported with line numbers |

## 8. Common mistakes and fixes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `FileNotFoundError: ../data/network_devices.csv` | Relative path resolved from the current directory, not the script | Build paths from `__file__`, or `cd` to the right place and check with `pwd` |
| `FileNotFoundError` when writing a log | The `logs/` folder does not exist | `mkdir -p logs`, or `Path.mkdir(parents=True, exist_ok=True)` in the script |
| `IndentationError` / `TabError` | Tabs and spaces mixed | Set the editor to insert 4 spaces; check with `python3 -m py_compile script.py` |
| `NameError: name 'os' is not defined` | Module imported inside one function but used in another | Put imports at the top of the file |
| `ModuleNotFoundError: No module named 'datatime'` | Typo in the import | `import datetime` |
| `SyntaxError` on a function line | Wrote `define` or forgot the colon | `def name(args):` |
| `Permission denied` running `./script.py` | Not executable | `chmod +x script.py`, or run it with `python3 script.py` |
| `/usr/bin/env: 'python3\r': No such file` | File saved with Windows line endings | `sed -i 's/\r$//' script.py` |
| Old log lines disappeared | Opened with `"w"` instead of `"a"` | Use append mode for logs |
| Cleanup removed nothing in subfolders | Non-recursive glob | Use `rglob`, or `os.walk` |
| Script waits forever in cron | It calls `input()` | Make interactive parts optional behind a flag |

## 9. Takeaway

Small scripts become real tools when they are **safe** (dry run before delete), **portable** (paths that do not depend on where you are standing), **honest about failure** (clear errors and exit codes) and **runnable without a human** (interactive parts behind a flag). The Python itself is simple: `with open()`, `try/except`, a loop, a few `if` statements and well-named functions. The habits around it are what make it fit for unattended security work.
