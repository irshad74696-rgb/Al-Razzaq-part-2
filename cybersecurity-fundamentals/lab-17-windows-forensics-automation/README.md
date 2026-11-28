# Lab 17: Windows Forensics Automation

Investigating a Windows machine without a Windows machine: parsing event logs (`.evtx`) and registry hives on Linux with Python, summarising them with PowerShell 7, and turning the result into a graded Indicators of Compromise (IOC) report and a timeline.

The workflow has four stages. Each one reads only what the previous one wrote, and none of them changes the evidence:

| Stage | Script | What it produces |
| --- | --- | --- |
| Extract event logs | [`extract_eventlogs.py`](scripts/extract_eventlogs.py) | One JSON per log: every record's time, event ID, provider, computer, named data fields and XML, plus the source file's SHA-256 |
| Extract registry | [`extract_registry.py`](scripts/extract_registry.py) | SYSTEM: computer name, time zone, last shutdown, services, network. SOFTWARE: Windows version, installed programs, autostart entries, Defender exclusions. Or any single key |
| Summarise (PowerShell) | [`forensic_automation.ps1`](scripts/forensic_automation.ps1) | `*_analysis.json` per log, `registry_analysis.json`, `forensic_timeline.json`, `forensic_report.md` |
| Detect and report | [`analyze_activity.py`](scripts/analyze_activity.py) | `ioc_report.json` and `ioc_summary.txt`: graded anomalies with MITRE ATT&CK mapping, indicators, recommendations |

[`run_lab.sh`](scripts/run_lab.sh) runs all four in one go.

**Sample output from a real run:** [Markdown report](samples/example-output/forensic_report.md), [IOC summary](samples/example-output/ioc_summary.txt), [IOC report (JSON)](samples/example-output/ioc_report.json), [timeline](samples/example-output/forensic_timeline.json), [terminal transcript](samples/example-output/session-transcript.txt).

## Contents

1. [Files in this folder](#1-files-in-this-folder)
2. [Setup](#2-setup)
3. [Quick start](#3-quick-start)
4. [The sample evidence](#4-the-sample-evidence)
5. [Task 1: event logs](#5-task-1-event-logs)
6. [Task 2: registry hives](#6-task-2-registry-hives)
7. [Task 3: PowerShell automation](#7-task-3-powershell-automation)
8. [Task 4: abnormal activity and the IOC report](#8-task-4-abnormal-activity-and-the-ioc-report)
9. [What I changed from the starting templates, and why](#9-what-i-changed-from-the-starting-templates-and-why)
10. [Normal versus suspicious](#10-normal-versus-suspicious)
11. [How I tested it](#11-how-i-tested-it)
12. [Running it on the lab machine's own samples](#12-running-it-on-the-lab-machines-own-samples)
13. [Troubleshooting](#13-troubleshooting)
14. [Takeaway](#14-takeaway)

## 1. Files in this folder

| File | What it does | Changes anything? |
| --- | --- | --- |
| [`scripts/extract_eventlogs.py`](scripts/extract_eventlogs.py) | `.evtx` to JSON with python-evtx, plus a statistics summary | No, writes one JSON file |
| [`scripts/extract_registry.py`](scripts/extract_registry.py) | Offline hive to JSON with python-registry; secrets masked | No, writes one JSON file |
| [`scripts/winevents.py`](scripts/winevents.py) | Shared event ID names, watched IDs, timestamp parsing, private JSON writer | No (imported) |
| [`scripts/forensic_automation.ps1`](scripts/forensic_automation.ps1) | Per-log statistics, logons per source address, registry flags, timeline, Markdown report | No, writes to the output folder |
| [`scripts/analyze_activity.py`](scripts/analyze_activity.py) | Anomaly detection, severity, MITRE mapping, IOC report | No, writes to the output folder |
| [`scripts/run_lab.sh`](scripts/run_lab.sh) | All four stages; extracted JSON goes to the case folder, not next to the evidence | No |
| [`tools/evtx_writer.py`](tools/evtx_writer.py) | Writes real-format `.evtx` files (checksummed chunks, Binary XML templates) | Only creates sample files |
| [`tools/regf_writer.py`](tools/regf_writer.py) | Writes real-format registry hives (`regf` base block, hive bin, nk/vk/lf cells) | Only creates sample files |
| [`tools/make_samples.py`](tools/make_samples.py) | Builds the "attack" and "clean" scenarios below | Only creates sample files |
| [`tests/test_lab.py`](tests/test_lab.py) | 34 tests: file formats, both extractors, the whole pipeline, a clean baseline, hostile input | No |
| [`samples/`](samples/) | `event-logs/` and `registry-hives/` (synthetic evidence), `example-output/` from one run | |
| [`requirements.txt`](requirements.txt) | python-evtx and python-registry, pinned | |
| [`social/`](social/) | Post text and graphic for sharing the lab | |

## 2. Setup

```bash
# Python libraries. On Ubuntu 23.04 and later, "pip3 install" system-wide is
# refused (PEP 668), so use a virtual environment:
sudo apt install -y python3-venv
python3 -m venv ~/forensics-venv
~/forensics-venv/bin/pip install -r requirements.txt

# PowerShell 7. The handout's packages-microsoft-prod.deb for Ubuntu 20.04 does not
# fit newer releases; the snap or the official tarball work everywhere:
sudo snap install powershell --classic
pwsh --version
```

On the provided lab machine both libraries and PowerShell are already installed, so `python3` and `pwsh` work directly.

## 3. Quick start

```bash
cd lab-17-windows-forensics-automation
PYTHON=~/forensics-venv/bin/python ./scripts/run_lab.sh samples ./forensic_case
cat forensic_case/forensic_output/forensic_report.md
cat forensic_case/forensic_output/ioc_summary.txt

# Or step by step, exactly as the lab does it:
cd samples/event-logs
~/forensics-venv/bin/python ../../scripts/extract_eventlogs.py System.evtx system_events.json
~/forensics-venv/bin/python ../../scripts/extract_eventlogs.py Security.evtx security_events.json
cd ../registry-hives
~/forensics-venv/bin/python ../../scripts/extract_registry.py SYSTEM
~/forensics-venv/bin/python ../../scripts/extract_registry.py SOFTWARE
cd ../..
pwsh -File scripts/forensic_automation.ps1          # -> ./forensic_output/
python3 scripts/analyze_activity.py                 # exit 1 when something is High or Critical

~/forensics-venv/bin/python -m unittest discover -s tests -v   # the test suite
```

## 4. The sample evidence

The lab machine ships sample `.evtx` files and hives, but those can't go into a public repository, and real ones from a real PC would be full of account names, SIDs and addresses. A parser that is never fed a file is also a parser that was never tested. So I wrote two small writers that produce the **real on-disk formats**, then built a scenario with them:

- **`evtx_writer.py`**: a 4 KiB file header and 64 KiB chunks, each with its CRC32 checksums, string table and template table. Each record is Binary XML: the XML skeleton of an event type is stored once per chunk as a template with numbered holes, and every later record of that type only carries the values. That is how Windows writes them, and how python-evtx expects to read them.
- **`regf_writer.py`**: the `regf` base block with its XOR checksum, one hive bin, and cells for keys (`nk`, with their last-write times), values (`vk` plus data cells, small values stored inline), subkey lists (`lf`, sorted) and value lists.

Both are checked by tools I did not write: the samples verify with python-evtx's own checksum checks, and they parse identically in the Rust-based `evtx` parser and in `regipy`.

**The scenario** ([`make_samples.py`](tools/make_samples.py)), all invented, all in Pakistan time (UTC+5):

- **WS-LAB-07**, a LabCorp workstation, three normal working days (18-20 November 2026): boots at 08:40, alice logs on and unlocks after lunch, bob opens her shared folder from 10.20.30.15, it-admin does maintenance over RDP from 10.20.30.5, one mistyped password.
- **That Friday night, 02:04-02:25 Saturday**: 1,200 failed network logons from **203.0.113.50** against administrator, admin, it-admin, guest and others, until it-admin's password is guessed. Within 13 minutes the intruder uses explicit credentials, runs a hidden encoded PowerShell command, creates `support_tmp` and adds it to Administrators, installs a service "Windows Update Helper" from `C:\Users\Public\Libraries\winupdate.exe`, disables Microsoft Defender and excludes that folder from scanning, adds a Run key with an encoded command, installs AnyDesk, and clears the Security log.
- The SOFTWARE hive also holds a forgotten auto-logon password in Winlogon (a misconfiguration, not the attacker).
- A **clean** scenario (`--scenario clean`) has the same three days and nothing else. The test suite requires zero findings on it.

Safe by construction: SIDs follow an obviously fake pattern (`S-1-5-21-1111111111-2222222222-3333333333-*`), the attacker is in 203.0.113.0/24 (reserved for documentation), the "password" is `SAMPLE-ONLY-not-a-real-password`, and the encoded PowerShell decodes to a harmless `Write-Output`. Nothing here is ever executed.

One honest simplification: when a real Security log is cleared, the older records are gone and event 1102 is the first record of the new log. The sample keeps both so every detection has something to find. On a real case, the earlier events would come from a log forwarder, a shadow copy or a backup.

## 5. Task 1: event logs

`extract_eventlogs.py <input.evtx> <output.json>` fills in the template's TODOs: it opens the file with `Evtx.Evtx`, walks every record and keeps the timestamp, event ID, computer name and XML. On top of that:

- **The named fields**, parsed from `EventData` (`<Data Name="IpAddress">`) and `UserData` (event 1102 keeps its fields there, not in `EventData`). Without them every later step would have to re-parse XML.
- **Chain of custody:** the JSON starts with the source file's name, size and SHA-256, and the time of extraction.
- **One bad record doesn't stop the run.** It goes into `parse_errors` with its record number. The test suite breaks a record on purpose to check this.
- **A clear error for wrong input** (exit 2): a file that doesn't start with `ElfFile` is rejected with a message instead of a stack trace.
- **One timestamp format everywhere** (`2026-11-20T21:04:10.250000Z`, always UTC). python-evtx renders times as `2026-11-20 21:04:10+00:00` and Windows as `...10.2500000Z` with seven digits; mixing styles breaks sorting.
- `--no-xml` leaves the raw XML out when the files get large.

`analyze_events` prints the total, the top 10 event IDs with their meaning (and an arrow on the ones the lab watches), the time range and the computers seen.

## 6. Task 2: registry hives

`extract_registry.py` keeps the three functions from the template and adds what an offline hive needs:

- **SYSTEM:** the current control set from `Select\Current` (offline there is no `CurrentControlSet`, only `ControlSet001`, `002`...), the computer name, the **time zone** (`Bias` is stored as an unsigned number; -300 minutes reads as 4294966996 until it is converted), the last clean shutdown (a FILETIME in `Control\Windows\ShutdownTime`), every service with its start type, image path, account and last-write time, and each network interface's DHCP or static address, gateway and DNS.
- **SOFTWARE:** Windows edition, version, build and install date; installed programs from both `Uninstall` keys (64- and 32-bit); autostart entries from the Run/RunOnce keys and Winlogon `Shell`/`Userinit`; Defender path, extension and process exclusions.
- **Key mode** (`extract_registry.py <hive> <key path>`) works on any hive, including `NTUSER.DAT`. It accepts what people actually type: `HKLM\SYSTEM\CurrentControlSet\Services\X` becomes `ControlSet001\Services\X`.
- **The hive type comes from the hive's own header**, not from the file name. The template's `"SYSTEM" in reg_file.upper()` would treat `/cases/SYSTEMS-TEAM/SOFTWARE` as a SYSTEM hive.
- **Secrets are masked.** A value whose name looks like a password or token is written as `SA************ (31 characters, masked)`. `--show-secrets` keeps the real value for when it is genuinely needed. The test suite checks the plaintext never reaches any output file.

## 7. Task 3: PowerShell automation

`forensic_automation.ps1 [-DataPath ./samples] [-OutputPath ./forensic_output]` implements the four functions from the template:

- **Analyze-EventLogs**, per extracted log: total events, counts per ID and the top 10, counts of the watched IDs (4624, 4625, 4648, 4672, 7045 and the extra key indicators 1102, 4688, 4720, 4732, 7040), the date range, events per UTC hour and per computer, and **logons per source address**: failures, successes, accounts tried, first and last failure, and the first successful logon from that address after the failures began. That last field is what turns "a brute force" into "a brute force that worked". Notable events get a readable one-line description, and an encoded PowerShell command line is decoded for display (never run).
- **Analyze-RegistryData**: secrets found anywhere in the registry JSON, autostart entries flagged for encoded or hidden PowerShell, downloads, user-writable folders, living-off-the-land binaries or a changed Winlogon Shell/Userinit; services flagged when they auto-start from a folder any user can write to or imitate a Windows name; disabled security services; Defender exclusions; remote access tools.
- **Generate-Timeline** merges notable events, the start and end of each brute force, and the last-write times of every flagged registry key into one sorted list. Registry timestamps matter here: the Run key's last write (02:20) sits exactly between the service install and the log clear.
- **Create-ForensicReport** writes [`forensic_report.md`](samples/example-output/forensic_report.md): files processed with their evidence hashes, key facts about the machine, every indicator, the timeline from just before the first suspicious entry, and recommendations for what was found.

Two PowerShell details that cost me time:

- `ConvertFrom-Json` silently converts anything that looks like a date into a `[datetime]`. Written back out, that could shift by the machine's own time zone. Every timestamp goes through one helper that pins it to UTC, and a test runs the script under `TZ=Asia/Karachi` and `TZ=America/New_York` and requires identical output.
- Hashtable order changes between runs in .NET, so any list built from one is sorted explicitly. The same test caught this.

Evidence text is attacker-controlled: a service name can contain `|`, a newline and `## Fake heading`. Table cells are escaped, so that kind of name can't break the Markdown report or inject markup (tested).

## 8. Task 4: abnormal activity and the IOC report

`analyze_activity.py` keeps the `ForensicAnalyzer` class and its methods from the template, and adds three detectors for the "key indicators" the lab lists. Each anomaly carries a severity, the evidence, the UTC and local time, its source files and a MITRE ATT&CK technique.

| Detector | Rule | Severity |
| --- | --- | --- |
| `detect_high_frequency_events` (lab) | An event ID seen more than 1,000 times / more than 5,000 times | Medium / High |
| `detect_off_hours_activity` (lab) | Security-relevant events outside 06:00-22:00 **in the machine's time zone**, grouped into windows | Medium |
| `detect_suspicious_registry_values` (lab) | A value name that suggests a stored secret | High |
| `analyze_user_behavior` (lab) | More than 50 suspicious events on one computer; one account doing several sensitive things in a short burst | Medium / High |
| `detect_brute_force` | 10 or more failed logons from one address | High |
| | ...and a successful logon from that address after the failures began | **Critical** |
| `detect_security_events` | 1102/104 log cleared; 7045 new service (High from a user-writable folder); 7040 security service disabled; 4720 account created; 4732 added to Administrators; 4688 hidden/encoded PowerShell; 4648 explicit credentials | Low to High |
| `detect_registry_persistence` | Flagged Run keys and services, disabled Defender, Defender exclusions, remote access tools | Medium / High |

On the sample: **17 anomalies: 1 Critical, 12 High, 3 Medium, 1 Low.** The [summary](samples/example-output/ioc_summary.txt) also lists the indicators (attacker IP, accounts, file paths, services, registry values, the decoded command) and one recommendation per kind of finding.

Choices that make the report trustworthy rather than long:

- **Off hours in local time.** Event logs store UTC. The attack started at 21:04 UTC, which is inside 06:00-22:00 if you read it as local time, and the handout's rule would miss it. The analyser reads the UTC offset from the SYSTEM hive (`TimeZoneInformation\Bias`) and finds 02:04 on a Saturday. `--utc-offset` overrides it. (The registry bias ignores daylight saving, which Pakistan does not use; elsewhere, check.)
- **One finding, several sources.** The new service appears as event 7045 in the System log and as a key in the SYSTEM hive; Defender's disabling as event 7040 and as `Start = 4`. Those are merged into one anomaly marked "confirmed by 2 sources" instead of being counted twice.
- **Bursts, not totals.** it-admin's legitimate RDP maintenance on Thursday and the intrusion on Friday night are different stories. The behaviour check splits an account's actions into bursts and reports "5 sensitive actions in 11 minutes", not "7 actions in 36 hours".
- **4672 is not suspicious on its own.** Windows logs it at every administrator and service logon, so it is counted but not graded.
- **A clean machine must be quiet.** The clean scenario produces zero anomalies; that is a test, not a hope.

The script exits 1 when anything is High or Critical, so it can gate a pipeline or a cron job.

## 9. What I changed from the starting templates, and why

| Starting point | Problem | What I did |
| --- | --- | --- |
| `pip3 install python-evtx python-registry` | Refused on Ubuntu 23.04+ (externally managed environment); the system setuptools also failed to build `hexdump` | Virtual environment + pinned `requirements.txt` |
| PowerShell from the Ubuntu 20.04 Microsoft `.deb` | Wrong package for current releases | Snap or the official tarball |
| Outputs written into `samples/event-logs/` and `samples/registry-hives/` | The evidence folder gets modified | `run_lab.sh` writes everything into a separate case folder; the step-by-step commands still work |
| Extracted JSON with timestamp, ID, computer and XML only | Every later step has to re-parse XML | Named data fields as a dictionary, plus the source hash |
| Hive type from `"SYSTEM" in path.upper()` | Wrong for folders with those words in the name | Read the type from the hive header, fall back to name and contents |
| Key paths like `HKLM\SYSTEM\CurrentControlSet\...` | Don't exist in an offline hive | Translated automatically |
| Keywords `password, key, token` matched anywhere | "key" matches `TimeZoneKeyName`, `KeyboardDelay`; "password" matches `PasswordExpiryWarning` (a number of days) | Name-based patterns, string values only; tested both ways |
| Sensitive values copied into every report | The IOC report spreads the credential further | Masked by default |
| `DateRange` used for off-hours | Only two timestamps per log, in UTC | Every timeline entry, in the machine's time zone, grouped into windows (DateRange kept as the fallback) |
| 4624 and 4672 listed as suspicious | Every normal logon would be an anomaly | Counted and shown, graded only in context (after a brute force, from a public address) |
| Failed logons counted per log | Can't tell a typo from an attack, or whether it worked | Per source address, with "success after failure" |
| Report sections as TODOs | | Generated from the data; evidence text escaped |

## 10. Normal versus suspicious

| Normal | Suspicious |
| --- | --- |
| A failed logon or two after a typo, followed by success from the same place | Hundreds of failures from one outside address within minutes, across many account names |
| 4624 logon type 2/7 (at the keyboard), type 3 from colleagues' machines, type 5 for services | Type 3 or 10 from a public address, especially right after failures |
| 4672 for administrators and SYSTEM at logon | 4720 and 4732 to Administrators by an account that just logged on remotely |
| 7036 services starting and stopping | 7045 for a service whose program sits in `Users\Public`, `AppData` or `Temp`; 7040 disabling Defender |
| Run key `SecurityHealth` pointing at `System32` | Run key with `-WindowStyle Hidden -EncodedCommand` |
| Defender exclusions set by IT for a known application | An exclusion for the folder the new service runs from |
| Activity during working hours in the machine's time zone | Administrative changes at 02:00 on a Saturday |
| | 1102: the audit log cleared |

## 11. How I tested it

Everything ran in a disposable Ubuntu 24.04 cloud container with Python 3.13, python-evtx 0.8.1, python-registry 1.3.1 and **PowerShell 7.4.6**:

- `tests/test_lab.py`: **34 of 34 tests pass** ([output](samples/test-run.txt)), including:
  - the committed samples regenerate byte for byte; EVTX header and chunk checksums verify; hive checksums verify; both cross-checked with independent parsers (Rust `evtx`, `regipy`);
  - both extractors' fields, hashes, owner-only file permissions, bad input, a deliberately damaged record, key-path translation, secret masking (and `--show-secrets`), the secret-name rules in both directions;
  - the full pipeline: every expected output file, brute force then success graded Critical, every key indicator found, merged findings with both sources, the encoded command decoded, the handout's thresholds, off hours in local time and the `--utc-offset` override, a sorted timeline, all report sections, the plaintext secret absent from every output;
  - the same PowerShell run under two different local time zones giving identical results;
  - the clean scenario giving zero anomalies;
  - hostile event text (`|`, newline, `## heading`, `<img>`) not breaking the report;
  - the `.ps1` parsing without errors, and a clear exit 2 for a wrong `-DataPath`.
- Python passes `pyflakes`; `run_lab.sh` passes `shellcheck`.

What the container could not show, still to do:

- **The lab machine's own sample files** at `/home/student/forensics-lab/samples/`, which come from real Windows systems (see the next section). Real logs have event types and field layouts my samples don't, and real hives have far more keys.
- **My own Ubuntu 25.10 laptop**: the venv install and PowerShell from snap.
- PSScriptAnalyzer was not run (it could not be installed in the container); the script parses cleanly, and the functions keep the lab's names (`Analyze-...`, `Generate-...`, `Create-...`), which PSScriptAnalyzer would flag as unapproved verbs.

## 12. Running it on the lab machine's own samples

```bash
cd /home/student/forensics-lab
git clone https://github.com/irshad74696-rgb/Al-Razzaq-part-2.git
L=Al-Razzaq-part-2/cybersecurity-fundamentals/lab-17-windows-forensics-automation

PYTHON=python3 $L/scripts/run_lab.sh /home/student/forensics-lab/samples ./case-01
cat case-01/forensic_output/forensic_report.md
cat case-01/forensic_output/ioc_summary.txt
```

`run_lab.sh` expects the same layout as the lab (`samples/event-logs/*.evtx`, `samples/registry-hives/SYSTEM` and `SOFTWARE`) and leaves that folder untouched. If the samples come from a machine in another time zone and the SYSTEM hive is missing, pass the offset by hand: `python3 $L/scripts/analyze_activity.py --data-dir case-01/forensic_output --utc-offset +00:00`.

## 13. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError: No module named 'Evtx'` | python-evtx not installed for this interpreter | Use the venv's Python (`~/forensics-venv/bin/python`) or `PYTHON=... ./run_lab.sh` |
| `error: externally-managed-environment` | Ubuntu blocks system-wide pip | Virtual environment (section 2) |
| `Failed building wheel for hexdump` | The system setuptools on recent Debian/Ubuntu | Same: inside a venv it builds |
| `key not found` | Path starts with the hive name, or uses a key that only exists on a live system | Paths are relative to the hive root (`ControlSet001\Services`); `HKLM\SYSTEM\` and `CurrentControlSet` are translated for you |
| `could not tell what kind of hive` | Not SYSTEM or SOFTWARE | Give a key path (key mode), or `--type` |
| `pwsh: command not found` | PowerShell not installed | `sudo snap install powershell --classic` |
| `No extracted JSON found` in the PowerShell output | Extraction not run, or written somewhere else | Run the extractors first; `-DataPath` must contain `event-logs/` and `registry-hives/` |
| `Skipping x.json: not valid JSON` | Extraction interrupted | `jq . x.json` to see where; extract again |
| Off-hours findings look shifted by hours | Wrong time zone | Check "Local time: ..." at the top of the summary; set `--utc-offset` |
| `analyze_activity.py` exits 1 | Not an error: High or Critical findings exist | Read `ioc_summary.txt` |

## 14. Takeaway

Windows evidence doesn't need Windows. What it needs is care with the parts that quietly go wrong: times stored in UTC but judged in local time, keys that only exist on a live system, secrets copied into reports, and attacker-written text landing in your tables. The strongest findings are the ones two sources agree on: a service in the event log and in the registry, Defender disabled in both, at the same minute.
