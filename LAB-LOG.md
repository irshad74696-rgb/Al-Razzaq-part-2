# Lab Log

A running journal of the hands-on labs I work through in Linux administration, containers, cybersecurity, and (coming next) cloud and AI. Each row links to a short write-up: what the lab covered, the commands I used, what broke and how I fixed it, and the one thing I took away.

Newest entries are at the top. The "what broke" sections are deliberate: debugging is most of the real work.

| Date | Track | Lab | Outcome |
| --- | --- | --- | --- |
| 2026-11-28 | Cyber Security | [Lab 17: Windows forensics automation](lab-log/2026-11-28-windows-forensics-automation.md) | Parsed EVTX logs and registry hives on Linux, PowerShell 7 summary, timeline and report, graded IOC report: a brute force that succeeded, a fake Windows service, Defender disabled and a cleared log, each confirmed by two sources; [lab folder](cybersecurity-fundamentals/lab-17-windows-forensics-automation/README.md) with four scripts, synthetic evidence and 34 passing tests |
| 2026-11-28 | Cyber Security | [Lab 16: Linux forensics automation](lab-log/2026-11-28-linux-forensics-automation.md) | Hashed evidence collection (logs, processes, sockets, accounts), Python analysis and live detection of a staged brute force, netcat backdoor and log injection, generated text and HTML reports; [lab folder](cybersecurity-fundamentals/lab-16-linux-forensics-automation/README.md) with six scripts, 57 end-to-end checks and 16 unit tests |
| 2026-11-27 | Cyber Security | [Lab 15: Incident response simulation](lab-log/2026-11-27-incident-response-simulation.md) | Staged compromise worked end to end: IoC triage, process snapshot before the kill, surgical iptables block proven by packet counters, account locked and expired, hashed evidence with chain of custody, generated incident report; [lab folder](cybersecurity-fundamentals/lab-15-incident-response-simulation/README.md) with seven scripts and 38 passing checks |
| 2026-11-23 | Cyber Security | [Lab 14: Cryptography with Python](lab-log/2026-11-23-cryptography-with-python.md) | SHA-256 hashing and an integrity checker; Fernet and password-based AES-256 with an HMAC check; encrypted vault with hash verification; folder security audit; [lab folder](cybersecurity-fundamentals/lab-14-cryptography-with-python/README.md) with six tools and 19 passing tests |
| 2026-11-23 | Cyber Security | [Lab 13: File integrity monitoring](lab-log/2026-11-23-file-integrity-monitoring.md) | auditd watches on accounts, sudoers, cron and system binaries; SHA-256 baseline with permission and owner checks; live inotify alerts; systemd timer; [lab folder](cybersecurity-fundamentals/lab-13-file-integrity-monitoring/README.md) with seven scripts and an audit rules file |
| 2026-11-21 | Cyber Security | [Lab 5: Linux security hardening](lab-log/2026-11-21-linux-security-hardening.md) | UFW default-deny firewall live on my machine, SSH audit against effective `sshd -T` settings, journal-based brute-force and sudo alerts on cron; [lab folder](cybersecurity-fundamentals/lab-5-linux-security-hardening/README.md) with nine scripts and an sshd drop-in |
| 2026-11-20 | Cyber Security | [Lab 4: Bash scripting essentials](lab-log/2026-11-20-bash-scripting-essentials.md) | Variables, functions, loops and `case`; verified backups with logging and safe retention; cron scheduling and a health monitor; [lab folder](cybersecurity-fundamentals/lab-4-bash-scripting-essentials/README.md) with seven scripts and a sample crontab |
| 2026-11-20 | Cyber Security | [Lab 3: Python scripting for security automation](lab-log/2026-11-20-python-automation.md) | File I/O with `with open()`, error handling, a dry-run-first folder cleanup, simulated network monitor and password checker; [lab folder](cybersecurity-fundamentals/lab-3-python-scripting-for-automation/README.md) with five scripts |
| 2026-11-20 | Cyber Security | [Lab 2: PowerShell fundamentals on Linux](lab-log/2026-11-20-powershell-fundamentals.md) | Cmdlet discovery, `*-Item` file management, variables, conditions and loops; [lab folder](cybersecurity-fundamentals/lab-2-powershell-fundamentals/README.md) with four scripts |
| 2026-11-20 | Cyber Security | [Lab 1: Linux command-line basics](lab-log/2026-11-20-linux-command-line-basics.md) | Navigation, file management, `chmod`/`chown` and directory permissions; [lab folder](cybersecurity-fundamentals/lab-1-linux-command-line-basics/README.md) with practice scripts |
| 2026-11-20 | Cyber Security | [Packet analysis with Wireshark and tshark](lab-log/2026-11-20-wireshark-packet-analysis.md) | Captured live traffic, filtered HTTP/TCP/DNS, and exported reports with `tshark -z` |
| 2026-10-19 | Linux | [Scheduling jobs with systemd timers](lab-log/2026-10-19-systemd-timers.md) | In progress: service and timer units written; results still to record |
| 2026-10-11 | Linux / Cyber Security | [Hardening the SSH server](lab-log/2026-10-11-ssh-hardening.md) | sshd on port 2222, root and password logins off, key-only login for one user |
| 2026-10-05 | Cyber Security | [Python scripting for security automation](lab-log/2026-10-05-python-scripting-automation.md) | CSV inventory reader and timestamped security log writer working; finished on [2026-11-20](lab-log/2026-11-20-python-automation.md) |
| 2026-10-04 | Containers | [Podman: Containerfile instructions, ports and storage](lab-log/2026-10-04-podman-containerfile-labs.md) | Four labs: ADD vs COPY, ENTRYPOINT/CMD, EXPOSE and `-p`, volumes and bind mounts |

## Adding a new day

```bash
cp lab-log/TEMPLATE.md lab-log/$(date +%F)-short-topic.md
# fill it in, add screenshots under lab-log/screenshots/<same-name>/
# then add a row at the top of the table above
git add LAB-LOG.md lab-log/
git commit -m "Lab log: $(date +%F) short topic"
git push
```

Never commit passwords, tokens, private keys or raw packet captures (`*.pcap` is ignored).
