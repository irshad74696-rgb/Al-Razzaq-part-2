# Hi, I'm Irshad Ali 👋

**Aspiring SOC Analyst | Blue Team | Linux Security | Digital Forensics | Python & Bash Automation**

I'm based in Pakistan and building toward an entry-level security operations role. I learn by doing: every lab I finish goes into a public repo with the scripts I wrote, what broke, how I fixed it, and how I tested it.

- 🔍 **Working on now:** forensics and incident response automation on Linux and Windows evidence
- 🛡️ **Focus areas:** incident response, log analysis, Linux hardening, file integrity monitoring, digital forensics
- 🐧 **Daily driver:** Ubuntu, run as my own lab machine
- 📫 **Find me:** [X @AlFatih80661889](https://x.com/AlFatih80661889)

## Featured lab work

All of it lives in **[my hands-on labs repo](https://github.com/irshad74696-rgb/Al-Razzaq-part-2)**. The strongest pieces:

| Lab | What I built |
| --- | --- |
| [Linux forensics automation](https://github.com/irshad74696-rgb/Al-Razzaq-part-2/tree/main/cybersecurity-fundamentals/lab-16-linux-forensics-automation) | Evidence collector (order of volatility, SHA-256 manifest, read-only archive), Python analyser for auth logs, processes and sockets, live detection, generated text and HTML reports. 73 tests. |
| [Windows forensics automation](https://github.com/irshad74696-rgb/Al-Razzaq-part-2/tree/main/cybersecurity-fundamentals/lab-17-windows-forensics-automation) | EVTX event logs and registry hives parsed on Linux with Python, PowerShell 7 timeline and report, IOC report mapped to MITRE ATT&CK. 34 tests. |
| [Incident response simulation](https://github.com/irshad74696-rgb/Al-Razzaq-part-2/tree/main/cybersecurity-fundamentals/lab-15-incident-response-simulation) | A staged Linux compromise worked end to end: IoC triage, snapshot-first containment with surgical firewall rules, hashed evidence with chain of custody, generated incident report. |
| [File integrity monitoring](https://github.com/irshad74696-rgb/Al-Razzaq-part-2/tree/main/cybersecurity-fundamentals/lab-13-file-integrity-monitoring) | auditd watch rules, SHA-256 baselines with owner and permission checks, live inotify alerts, critical-folder monitoring on a systemd timer. |
| [Linux security hardening](https://github.com/irshad74696-rgb/Al-Razzaq-part-2/tree/main/cybersecurity-fundamentals/lab-5-linux-security-hardening) | UFW firewall, SSH hardening verified with `sshd -T`, journalctl log analysis, automated brute-force and resource alerts. |
| [Cryptography with Python](https://github.com/irshad74696-rgb/Al-Razzaq-part-2/tree/main/cybersecurity-fundamentals/lab-14-cryptography-with-python) | SHA-256 integrity checks, AES-256 with PBKDF2 and HMAC, an encrypted vault, a folder security audit. 19 tests. |

Every lab is also written up day by day in the [Lab Log](https://github.com/irshad74696-rgb/Al-Razzaq-part-2/blob/main/LAB-LOG.md).

## Tools I use

![Linux](https://img.shields.io/badge/Linux-Ubuntu-E95420?logo=ubuntu&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-scripting-4EAA25?logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3-3776AB?logo=python&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-7-5391FE?logo=powershell&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-tshark-1679A7?logo=wireshark&logoColor=white)
![Podman](https://img.shields.io/badge/Podman-containers-892CA0?logo=podman&logoColor=white)
![Git](https://img.shields.io/badge/Git-GitHub-F05032?logo=git&logoColor=white)

auditd · inotify · UFW · iptables · OpenSSH · systemd · journalctl · cron · ss / lsof · MITRE ATT&CK

## What I care about in my work

- **Evidence you can verify.** Hash it before anyone looks at it, and check the hashes in the report.
- **Never trust attacker-controlled fields.** Usernames and log lines can be forged; my parsers are tested against that.
- **Safe by default.** Scripts that change a system do a dry run unless told `--apply`.
- **Tested, and honest about it.** Each lab says what was tested, where, and what still needs a real machine.

---

🔎 Open to entry-level SOC analyst, security operations and junior incident response roles.
