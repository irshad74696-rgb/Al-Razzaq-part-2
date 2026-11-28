# 2026-11-28 · Lab 17: Windows forensics automation

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Scripts written and tested in a container (34 of 34 tests, PowerShell 7.4 included) on synthetic evidence; not yet run on the lab machine's own samples or my laptop |
| **Environment** | Lab: provided Ubuntu cloud machine with python-evtx, python-registry and PowerShell 7. Script testing: Ubuntu 24.04 container, Python 3.13 venv, PowerShell 7.4.6 |
| **Lab folder** | [`cybersecurity-fundamentals/lab-17-windows-forensics-automation/`](../cybersecurity-fundamentals/lab-17-windows-forensics-automation/README.md) |

## What the lab covered

Parsing Windows event logs (`.evtx`) and registry hives on Linux with Python, summarising both with a PowerShell 7 script, building a timeline and a Markdown report, then detecting abnormal activity (brute force, persistence, Defender tampering, log clearing, off-hours admin work) and writing an IOC report. Because real Windows evidence can't be published, I also wrote small writers for the real `.evtx` and `regf` formats and built a staged attack scenario, plus a clean one, to test against.

## Commands used

```bash
python3 -m venv ~/forensics-venv && ~/forensics-venv/bin/pip install -r requirements.txt
sudo snap install powershell --classic

cd samples/event-logs
~/forensics-venv/bin/python ../../scripts/extract_eventlogs.py Security.evtx security_events.json
cd ../registry-hives
~/forensics-venv/bin/python ../../scripts/extract_registry.py SYSTEM
~/forensics-venv/bin/python ../../scripts/extract_registry.py SOFTWARE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
cd ../..
pwsh -File scripts/forensic_automation.ps1
python3 scripts/analyze_activity.py

./scripts/run_lab.sh samples ./forensic_case      # all four stages, evidence folder untouched
```

Key lines from the real run:

```
[A001] Critical Brute force succeeded: it-admin logged on from 203.0.113.50
       Sat 2026-11-21 02:12:03 (UTC+05:00)
[A003] High     Account it-admin performed 5 sensitive actions in 11 minutes
[A006] High     New service 'Windows Update Helper' (confirmed by 2 sources)
[A007] High     Microsoft Defender Antivirus Service disabled (confirmed by 2 sources)
Decoded commands: Write-Output 'FORENSICS-LAB SAMPLE: harmless placeholder ...'
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| `pip3 install python-evtx` failed | Ubuntu blocks system-wide pip, and the system setuptools could not build `hexdump` | Virtual environment with pinned requirements |
| The night-time attack was not "off hours" | Event logs store UTC; 21:04 UTC looks like business hours | Read the UTC offset from the SYSTEM hive: it was 02:04 local on a Saturday |
| `Bias` read as 4294966996 | REG_DWORD is unsigned; -300 minutes wraps | Convert to signed before use |
| `HKLM\SYSTEM\CurrentControlSet\...` not found | Offline hives have `ControlSet001`, not `CurrentControlSet` | Translate using `Select\Current` |
| The keyword "key" flagged `TimeZoneKeyName`; "password" flagged `PasswordExpiryWarning` | Substring matching on value names | Name patterns for real secrets, string values only |
| The same service was reported twice | Seen as event 7045 and as a registry key | Merge into one finding "confirmed by 2 sources" |
| PowerShell results changed between two runs | Hashtable order differs per process in .NET | Sort every list explicitly; test runs under two time zones and compares |
| A service name with `|` and a newline broke the report table | Evidence text is attacker-controlled | Escape every table cell |
| "Successful logon as SYSTEM after 1 failure" | All local logons share the source address "-" | Only correlate real remote addresses |

## Key takeaway

Correlation beats volume: the findings worth acting on are the ones two sources agree on (a service in both the event log and the registry, Defender disabled in both, within the same minute), judged in the machine's own time zone.

## Still to do

- Run `run_lab.sh` on the lab machine's own samples at `/home/student/forensics-lab/samples/` and compare with the synthetic results.
- Set up the venv and PowerShell (snap) on my Ubuntu 25.10 laptop.
- Run PSScriptAnalyzer on the `.ps1` (it could not be installed in the test container).
