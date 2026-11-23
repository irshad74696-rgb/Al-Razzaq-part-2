# 2026-11-23 · Lab 13: File integrity monitoring

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Done on the lab's cloud machine; scripts tested in a container with real auditd; not yet run on my own laptop |
| **Environment** | Lab: provided Ubuntu cloud machine. Script testing: Linux container, auditd 3.1.2, inotify-tools, run as root |
| **Lab folder** | [`cybersecurity-fundamentals/lab-13-file-integrity-monitoring/`](../cybersecurity-fundamentals/lab-13-file-integrity-monitoring/README.md) |

## What the lab covered

How to notice when important files change. auditd kernel watches record who touched a file and with which program, a SHA-256 baseline shows exactly what is different from a known-good state, and `inotifywait` raises an alert the moment it happens. Then I pointed all of it at the folders an attacker goes for (`/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`) and scheduled the check.

## Commands and configs used

```bash
sudo apt install auditd audispd-plugins inotify-tools
sudo auditctl -w ~/secure_files -p rwa -k secure_files   # watch a folder
sudo auditctl -w /etc/shadow -p wa -k identity
sudo auditctl -l                                         # loaded rules
sudo ausearch -k identity --format text                  # "who did what with which program"
sudo aureport -f -i --summary
./scripts/file_integrity_checker.sh -c && ./scripts/file_integrity_checker.sh -s
./scripts/realtime_monitor.sh
sudo ./scripts/setup_auditd.sh --persist                 # rules survive a reboot
sudo ./scripts/critical_dirs_monitor.sh baseline
sudo ./scripts/critical_dirs_monitor.sh report
```

```ini
# config/50-fim.rules (excerpt)
-w /etc/sudoers.d   -p wa -k privilege
-w /etc/cron.d      -p wa -k persistence
-w /usr/local/bin   -p wa -k binaries
```

Result of the critical-folder test after four planted changes:

```
MODIFIED  /etc/hosts
NEW       /etc/sudoers.d/zz-test
PERMS     /usr/bin/id  (mode 755 -> 4755)
NEW       /usr/local/bin/sshd-helper
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| Integrity check said "No changes detected" under a list of new files | The flag was set inside a `find \| while` pipeline, which runs in a subshell | Collect findings in an array in the main shell |
| A new file was never reported | `grep -q "$file"` is a substring match, and the new path was part of an existing one | Exact lookup by path |
| Only 6 of 19 audit rules loaded, no error at the end | `auditctl -R` stops at the first watch whose folder is missing (`/etc/ssh` on a machine without an SSH server) | Skip and name those lines before loading |
| Killing the real-time monitor left `inotifywait` running | It sat in a pipeline the `kill` never reached | Own file descriptor plus an exit trap |
| `fim_service.sh stop` left `sleep 300` behind | Only the loop's PID was killed | `setsid` and kill the whole process group |

## Key takeaway

A hash says *what* changed, auditd says *who and how*, inotify says *now*. You need at least the first two to tell a story an incident responder can use, and every check must be able to fail loudly.

## Still to do

- Run `setup_auditd.sh --persist` and the critical-folder baseline on my own Ubuntu machine, and paste real output here.
- Install the systemd timer and confirm `journalctl -u fim-check.service` shows a run.
