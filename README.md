# Hands-on Labs: Linux, Containers and Cybersecurity

Practical lab work by **Irshad Ali**, done on my own Ubuntu machine. I'm building skills toward a role in security operations and cloud infrastructure, and I record each lab as I go.

**Start here: [Lab Log](LAB-LOG.md)**, a dated list of every lab with what I did, what broke, and how I fixed it.

## Tracks

| Track | What it covers | Where |
| --- | --- | --- |
| Linux system administration | Shell, files and permissions, users, processes, systemd services and timers, SSH, networking, storage, SELinux | [`redhat-3/`](redhat-3/README.md), [Lab Log](LAB-LOG.md) |
| Containers | Podman, Containerfiles, ports, volumes and bind mounts | [Lab Log](LAB-LOG.md) (lab folders coming soon) |
| Cyber Security | Linux command-line basics and permissions, PowerShell fundamentals, Python automation for security tasks, Bash scripting and cron, Linux hardening (UFW, SSH, log monitoring), file integrity monitoring (auditd, hashes, inotify), cryptography with Python (SHA-256, AES, PBKDF2), incident response (IoC triage, containment, evidence hashing), forensics automation (collection, log and process analysis, reports), packet analysis with Wireshark | [`cybersecurity-fundamentals/`](cybersecurity-fundamentals/README.md): [`lab-1-linux-command-line-basics/`](cybersecurity-fundamentals/lab-1-linux-command-line-basics/README.md), [`lab-2-powershell-fundamentals/`](cybersecurity-fundamentals/lab-2-powershell-fundamentals/README.md), [`lab-3-python-scripting-for-automation/`](cybersecurity-fundamentals/lab-3-python-scripting-for-automation/README.md), [`lab-4-bash-scripting-essentials/`](cybersecurity-fundamentals/lab-4-bash-scripting-essentials/README.md), [`lab-5-linux-security-hardening/`](cybersecurity-fundamentals/lab-5-linux-security-hardening/README.md), [`lab-13-file-integrity-monitoring/`](cybersecurity-fundamentals/lab-13-file-integrity-monitoring/README.md), [`lab-14-cryptography-with-python/`](cybersecurity-fundamentals/lab-14-cryptography-with-python/README.md), [`lab-15-incident-response-simulation/`](cybersecurity-fundamentals/lab-15-incident-response-simulation/README.md), [`lab-16-linux-forensics-automation/`](cybersecurity-fundamentals/lab-16-linux-forensics-automation/README.md), [Lab Log](LAB-LOG.md) |
| Cloud computing | Planned | |
| Artificial intelligence | Planned | |

## Tools used

Ubuntu 25.10, Bash, cron, UFW, PowerShell 7, Podman, systemd, OpenSSH, Python 3, Wireshark and tshark, Git.

## Repository layout

```
LAB-LOG.md                    index of daily lab entries, newest first
lab-log/                      one write-up per day, plus TEMPLATE.md
redhat-3/                     Linux administration labs, one folder per lab
cybersecurity-fundamentals/   security fundamentals labs, one folder per lab
  lab-1-linux-command-line-basics/         navigation, files, permissions
  lab-2-powershell-fundamentals/           cmdlets, file management, scripting
  lab-3-python-scripting-for-automation/   Python security tools + sample data
  lab-4-bash-scripting-essentials/         backups, loops, cron scheduling
  lab-5-linux-security-hardening/          UFW, SSH audit, log alerts
  lab-13-file-integrity-monitoring/        auditd rules, hash baselines, inotify
  lab-14-cryptography-with-python/         SHA-256, AES encryption, vault, audit
  lab-15-incident-response-simulation/     IoC triage, containment, evidence, report
  lab-16-linux-forensics-automation/       evidence collection, analysis, detection, reports
```
