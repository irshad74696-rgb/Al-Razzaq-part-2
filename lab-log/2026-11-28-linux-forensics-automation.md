# 2026-11-28 · Lab 16: Linux forensics automation

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Scripts written and tested in a container (57 of 57 end-to-end checks, 16 of 16 unit tests); not yet run on my own laptop |
| **Environment** | Lab: provided Ubuntu cloud machine. Script testing: Ubuntu 24.04 container, run as root, OpenBSD netcat, iproute2 `ss` |
| **Lab folder** | [`cybersecurity-fundamentals/lab-16-linux-forensics-automation/`](../cybersecurity-fundamentals/lab-16-linux-forensics-automation/README.md) |

## What the lab covered

Collecting forensic evidence from a live Linux host (logs, processes, sockets, accounts, system details), first by hand and then with a Bash collector; analysing the collection with Python for brute force, suspicious processes and backdoor ports; staging a harmless simulated attack to detect; a live detection script; and generated text and HTML reports.

## Commands used

```bash
sudo ./create_test_activities.sh --apply                    # staged, labelled test activity
sudo ./forensic_collector.sh --extra-log /tmp/forensics_lab_sim/test_auth.log
sudo python3 forensic_analyzer.py                           # graded findings, JSON + text + timeline
sudo ./detect_unauthorized.sh --auth-log /tmp/forensics_lab_sim/test_auth.log
sudo ./generate_report.sh --analyst "Irshad Ali"
sudo python3 html_report_generator.py --analyst "Irshad Ali"
sudo ./create_test_activities.sh --cleanup --apply
cd /home/forensics/automated_collection_* && sha256sum -c MANIFEST.sha256
```

Key lines from the real run:

```
[CRITICAL] brute force from 203.0.113.50 (19 failures) followed by a successful login
[HIGH] nc running as root (PID 5569) in listen or exec mode
[HIGH] listener on backdoor port 4444 (loopback only)
[MEDIUM] log injection attempt: username contains a fake source address
MANIFEST.sha256: all 41 file hashes verified OK
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| Brute force blamed the wrong address | A username like `test from 10.9.9.9 port 22` plants a fake address before the real one | Take the address from the end of the line; report the injection |
| `ps aux \| grep nc` flagged `grep nc` and `timeout ... nc` | Text match instead of program name | Compare the program name exactly |
| No `/var/log/auth.log` | Recent Ubuntu logs auth to the journal unless rsyslog is installed | Read the file if it exists, `journalctl` otherwise |
| Handout's test log lines were never parsed | `$(date)` output is not a syslog timestamp | Generate real RFC 3339 syslog lines |
| shellcheck warned the manifest could hash itself half-written | `sha256sum > MANIFEST.sha256` inside the folder being hashed | Write it outside first, then move it in |
| The same finding appeared twice in the report | Live detection and analysis both found it, in different words | Same wording in both tools; the report merges and lists both sources |
| A login before the attack counted as "brute force succeeded" | Any success from that address matched | Only a success after the first failure counts |

## Key takeaway

Evidence is only useful if someone else can check it: record what failed as well as what worked, hash every file before analysis, and never trust a field the attacker can write into.

## Still to do

- Run the full workflow on my own Ubuntu 25.10 laptop, where the journal holds real sudo and login events.
- See how noisy the INFO network findings are on a desktop with a browser open, and tune if needed.
- Check `systemctl list-timers` and UFW status are collected there (the container has neither).
