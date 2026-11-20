# Lab Log

A running journal of the hands-on labs I work through in Linux administration, containers, cybersecurity, and (coming next) cloud and AI. Each row links to a short write-up: what the lab covered, the commands I used, what broke and how I fixed it, and the one thing I took away.

Newest entries are at the top. The "what broke" sections are deliberate: debugging is most of the real work.

| Date | Track | Lab | Outcome |
| --- | --- | --- | --- |
| 2026-11-20 | Cyber Security | [PowerShell fundamentals on Linux](lab-log/2026-11-20-powershell-fundamentals.md) | Cmdlet discovery, `*-Item` file management, variables, conditions and loops; [lab folder](Cyber-Security/powershell-fundamentals/README.md) with four scripts |
| 2026-11-20 | Cyber Security | [Linux command-line basics](lab-log/2026-11-20-linux-command-line-basics.md) | Navigation, file management, `chmod`/`chown` and directory permissions; [lab folder](Cyber-Security/linux-command-line-basics/README.md) with practice scripts |
| 2026-11-20 | Cyber Security | [Packet analysis with Wireshark and tshark](lab-log/2026-11-20-wireshark-packet-analysis.md) | Captured live traffic, filtered HTTP/TCP/DNS, and exported reports with `tshark -z` |
| 2026-10-19 | Linux | [Scheduling jobs with systemd timers](lab-log/2026-10-19-systemd-timers.md) | In progress: service and timer units written; results still to record |
| 2026-10-11 | Linux / Cyber Security | [Hardening the SSH server](lab-log/2026-10-11-ssh-hardening.md) | sshd on port 2222, root and password logins off, key-only login for one user |
| 2026-10-05 | Cyber Security | [Python scripting for security automation](lab-log/2026-10-05-python-scripting-automation.md) | CSV inventory reader and timestamped security log writer working |
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
