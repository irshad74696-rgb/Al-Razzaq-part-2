# Cybersecurity Fundamentals

Core hands-on skills for security work: driving a shell on Linux and Windows-style tooling, automating routine jobs with Python and Bash, and hardening and monitoring a Linux host. Each folder holds its own README with what I did, the commands, what broke and how I fixed it, plus the scripts I wrote.

| Folder | What it covers | Scripts |
| --- | --- | --- |
| [`lab-1-linux-command-line-basics/`](lab-1-linux-command-line-basics/README.md) | Navigating the filesystem, managing files, `chmod`/`chown` and how directory permissions behave | 3 Bash scripts |
| [`lab-2-powershell-fundamentals/`](lab-2-powershell-fundamentals/README.md) | PowerShell 7 on Linux: finding cmdlets, `*-Item` file management, variables, conditions and loops, with a cmdlet-to-Linux comparison | 4 PowerShell scripts |
| [`lab-3-python-scripting-for-automation/`](lab-3-python-scripting-for-automation/README.md) | File handling, error handling, log writing, a dry-run-first folder cleanup, a simulated network monitor and a password checker | 5 Python scripts + sample CSV |
| [`lab-4-bash-scripting-essentials/`](lab-4-bash-scripting-essentials/README.md) | Variables, functions, loops and `case`; verified backups with logging and retention; cron scheduling and why jobs fail under cron | 7 Bash scripts + sample crontab |
| [`lab-5-linux-security-hardening/`](lab-5-linux-security-hardening/README.md) | UFW firewall, SSH hardening checked with `sshd -T`, journalctl log analysis, automated brute-force and resource alerts on cron | 9 Bash scripts + sshd drop-in + sample log |

Write-ups for each day are in the [Lab Log](../LAB-LOG.md).
