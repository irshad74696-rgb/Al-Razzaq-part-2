# 2026-11-20 · Lab 3: Python scripting for security automation

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Done (my own terminal output and screenshots still to add) |
| **Environment** | Ubuntu Linux, Python 3, standard library only |
| **Lab folder** | [`cybersecurity-fundamentals/lab-3-python-scripting-for-automation/`](../cybersecurity-fundamentals/lab-3-python-scripting-for-automation/README.md) |

> Completes the work started on [2026-10-05](2026-10-05-python-scripting-automation.md), which covered only the file reader and log writer.

## What the lab covered

Reading a CSV inventory and writing timestamped security logs with `with open()`, handling file errors cleanly, an automated folder cleanup that removes temporary files by extension, and two small security tools (a simulated network monitor and a password strength checker) built from loops, conditions and functions.

## Commands and configs used

```bash
cd cybersecurity-fundamentals/lab-3-python-scripting-for-automation
python3 scripts/file_reader.py                       # table of devices from data/network_devices.csv
python3 scripts/log_writer.py --event WARNING "Port scan from 10.0.0.5"
python3 scripts/folder_cleanup.py --make-sample      # practice files in temp_files/
python3 scripts/folder_cleanup.py                    # dry run
python3 scripts/folder_cleanup.py --delete           # 11 files and 1 empty folder removed
python3 scripts/network_monitor.py --scans 5 --interval 2
python3 scripts/password_checker.py                  # report on example passwords
python3 scripts/password_checker.py --interactive    # hidden input
python3 -m py_compile scripts/*.py                   # syntax check
```

```python
# The pattern every script uses for output files
log_path.parent.mkdir(parents=True, exist_ok=True)
with open(log_path, "a", encoding="utf-8") as f:
    f.write(f"[{timestamp}] {level}: {message}\n")
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| `NameError: name 'os' is not defined` at the end of the monitor run | `import os` sat inside `main()` but the report function used it | Moved all imports to the top |
| `FileNotFoundError` when running a script from the lab folder | Paths were hardcoded as `../data` and `../logs` | Built paths from `Path(__file__)` |
| Backup files in the subfolder were not cleaned | Cleanup only globbed the top folder | Recursive search, plus empty-folder removal |
| Cleanup could delete straight away | No preview | Dry run by default, `--delete` to act |
| Password checker could not run without a keyboard | It always ended in an `input()` loop | Interactive mode behind `--interactive`, using `getpass` |

## Key takeaway

Anything that deletes files should do a dry run by default, and any script meant for automation should run without a human and report failures through its exit code.

## Screenshots

None captured yet.
