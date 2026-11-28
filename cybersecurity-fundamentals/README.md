# Cybersecurity Fundamentals

Core hands-on skills for security work: driving a shell on Linux and Windows-style tooling, automating routine jobs with Python and Bash, hardening and monitoring a Linux host, detecting changes to the files that matter, protecting files with hashing and encryption, responding to an incident from detection to report, and automating forensic collection and analysis. Each folder holds its own README with what I did, the commands, what broke and how I fixed it, plus the scripts I wrote.

| Folder | What it covers | Scripts |
| --- | --- | --- |
| [`lab-1-linux-command-line-basics/`](lab-1-linux-command-line-basics/README.md) | Navigating the filesystem, managing files, `chmod`/`chown` and how directory permissions behave | 3 Bash scripts |
| [`lab-2-powershell-fundamentals/`](lab-2-powershell-fundamentals/README.md) | PowerShell 7 on Linux: finding cmdlets, `*-Item` file management, variables, conditions and loops, with a cmdlet-to-Linux comparison | 4 PowerShell scripts |
| [`lab-3-python-scripting-for-automation/`](lab-3-python-scripting-for-automation/README.md) | File handling, error handling, log writing, a dry-run-first folder cleanup, a simulated network monitor and a password checker | 5 Python scripts + sample CSV |
| [`lab-4-bash-scripting-essentials/`](lab-4-bash-scripting-essentials/README.md) | Variables, functions, loops and `case`; verified backups with logging and retention; cron scheduling and why jobs fail under cron | 7 Bash scripts + sample crontab |
| [`lab-5-linux-security-hardening/`](lab-5-linux-security-hardening/README.md) | UFW firewall, SSH hardening checked with `sshd -T`, journalctl log analysis, automated brute-force and resource alerts on cron | 9 Bash scripts + sshd drop-in + sample log |
| [`lab-13-file-integrity-monitoring/`](lab-13-file-integrity-monitoring/README.md) | auditd watch rules and `ausearch`/`aureport`, SHA-256 baselines with permission and owner checks, live `inotifywait` alerts, critical-folder monitoring on a systemd timer | 7 Bash scripts + audit rules + systemd units |
| [`lab-14-cryptography-with-python/`](lab-14-cryptography-with-python/README.md) | SHA-256 hashing and integrity checks, Fernet and password-based AES-256 with PBKDF2 and HMAC, an encrypted vault, a folder security audit | 6 Python tools + shared module + 19 tests |
| [`lab-15-incident-response-simulation/`](lab-15-incident-response-simulation/README.md) | A staged Linux compromise worked as an incident: IoC triage, containment with snapshot-first and surgical iptables rules, hashed evidence with chain of custody, a generated incident report | 7 Bash scripts + shared library + 38-check test |
| [`lab-16-linux-forensics-automation/`](lab-16-linux-forensics-automation/README.md) | Evidence collection with a hashed manifest, Python analysis of auth logs, processes and sockets, live detection of unauthorised activity, generated text and HTML forensic reports | 4 Bash scripts + 2 Python tools + shared library + 73 tests |

Write-ups for each day are in the [Lab Log](../LAB-LOG.md).
