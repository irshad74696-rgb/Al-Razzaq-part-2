# 2026-10-05 · Python scripting for security automation

| | |
| --- | --- |
| **Track** | Cyber Security |
| **Status** | Done, finished on [2026-11-20](2026-11-20-python-automation.md) |
| **Environment** | Ubuntu 25.10, Python 3 |
| **Lab folder** | [`cybersecurity-fundamentals/lab-3-python-scripting-for-automation/`](../cybersecurity-fundamentals/lab-3-python-scripting-for-automation/README.md) |

> Backfilled entry, written from my notes after the fact.

## What the lab covered

Basic file handling in Python for security tasks: reading a CSV inventory of network devices and printing it as a table, and appending timestamped security events to a log file.

## Commands and configs used

```bash
mkdir -p data logs scripts
printf 'server1,192.168.1.10,active\nserver2,192.168.1.11,inactive\nfirewall1,192.168.1.1,active\n' > data/network_devices.csv
cd scripts
python3 file_reader.py     # reads ../data/network_devices.csv
python3 log_writer.py      # appends entries to ../logs/
```

```python
# Core pattern from the log writer
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
with open(log_file, "a") as f:
    f.write(f"[{timestamp}] {event_type}: {message}\n")
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| `No such file or directory` when creating the CSV | The `data/` folder did not exist yet | `mkdir -p data` first |
| `SyntaxError` on line 6 | Typed `define` instead of `def` | Changed to `def` |
| `IndentationError` | Tabs and spaces mixed, docstrings not indented under their `def` | Re-wrote the file with four-space indentation only |
| `ModuleNotFoundError: datatime` | Typo in the import | `import datetime` |
| Log entries not written | Arguments passed as one quoted string and a misspelled loop variable | Passed `log_file, event_type, message` as separate values |

## Key takeaway

Python is strict about indentation, so I set my editor to insert spaces. Scripts that write files should create their output folder first with `os.makedirs(..., exist_ok=True)`.

## Screenshots

None captured.
