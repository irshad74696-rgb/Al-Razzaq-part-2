# Lab 13: File Integrity Monitoring

Detecting when important files change: who changed them, when, with which program, and what exactly is different. I used three tools that answer different parts of that question and built them into scripts that can run on a schedule.

| Tool | Answers | Blind spot |
| --- | --- | --- |
| **auditd** (kernel audit watches) | *Who* touched the file, as which user, with which program, and whether it worked | Says a write happened, not what the content is now |
| **SHA-256 baseline** (hash and compare) | *What* is different from a known-good state: content, permissions, owner, new and deleted files | Only knows at scan time; says nothing about who |
| **inotify** (`inotifywait`) | *Right now*: an event the moment it happens | No user or program, and nothing survives a reboot or a missed event |

**Why this matters for security work:** file integrity monitoring (FIM) is a required control in PCI DSS (requirement 11.5.2 in version 4.0) and appears in CIS benchmarks and most SOC playbooks. When an attacker gets in, the files they touch are predictable: `/etc/passwd` and `/etc/shadow` to add an account, `/etc/sudoers.d/` to give it root, cron and systemd units to survive a reboot, and `/usr/bin` or `/usr/local/bin` to plant a tool. Every one of those is covered here, and the sample report below shows each of them being caught.

## Contents

1. [Files in this folder](#1-files-in-this-folder)
2. [auditd: watch rules and searching the log](#2-auditd-watch-rules-and-searching-the-log)
3. [Hash baseline checker](#3-hash-baseline-checker)
4. [Real-time monitoring with inotify](#4-real-time-monitoring-with-inotify)
5. [Critical folders and scheduled checks](#5-critical-folders-and-scheduled-checks)
6. [Bugs I fixed compared with the starting code](#6-bugs-i-fixed-compared-with-the-starting-code)
7. [Troubleshooting](#7-troubleshooting)
8. [How I tested it](#8-how-i-tested-it)
9. [Takeaway](#9-takeaway)

## 1. Files in this folder

| File | What it does | Changes the system? |
| --- | --- | --- |
| [`config/50-fim.rules`](config/50-fim.rules) | auditd watches for accounts, sudoers, SSH config, persistence locations, system programs and the audit system itself | Only when installed |
| [`scripts/lib.sh`](scripts/lib.sh) | Shared helpers: run as root with or without `sudo`, private state folder, coloured output | No (sourced) |
| [`scripts/setup_auditd.sh`](scripts/setup_auditd.sh) | Checks auditd is installed, running and enabled; loads the rules now (`--load`) or permanently (`--persist`) | Only with a flag |
| [`scripts/audit_report.sh`](scripts/audit_report.sh) | Event count per key, the latest events in plain English, rule changes, failed access, logins | No |
| [`scripts/file_integrity_checker.sh`](scripts/file_integrity_checker.sh) | SHA-256 baseline (`-c`) and compare (`-s`): MODIFIED, PERMS, OWNER, DELETED, NEW. Exit 1 when anything changed | Writes baseline and reports |
| [`scripts/realtime_monitor.sh`](scripts/realtime_monitor.sh) | Live `inotifywait` watch with ALERT / CRITICAL levels and a TSV log | Writes a log |
| [`scripts/critical_dirs_monitor.sh`](scripts/critical_dirs_monitor.sh) | Baseline and check for `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin` and the demo folder; combined report with auditd events | Writes baseline and reports |
| [`scripts/fim_service.sh`](scripts/fim_service.sh) | Background loop with start / stop / status that cleanly stops everything it started | Starts a background process |
| [`config/fim-check.service`](config/fim-check.service), [`config/fim-check.timer`](config/fim-check.timer) | The proper way to schedule it: a systemd timer every 15 minutes | Only when installed |
| [`samples/sample-report.txt`](samples/sample-report.txt) | Real output of `critical_dirs_monitor.sh report` from my test run | No |

Baselines and reports go to `/var/lib/fim/` when run as root, or `~/.local/state/fim/` otherwise, always mode 700/600. They are never written inside a monitored folder, because then every report would itself be a "change".

## 2. auditd: watch rules and searching the log

```bash
sudo apt install auditd audispd-plugins
sudo systemctl enable --now auditd
sudo auditctl -s                         # "enabled 1" means the kernel is auditing
```

A watch rule has three parts: the path (`-w`), what to trigger on (`-p` with `r` read, `w` write, `x` execute, `a` attribute change), and a key (`-k`) so the events can be found later. A watch on a folder covers everything below it.

```bash
mkdir -p ~/secure_files
echo "This is a sensitive document" > ~/secure_files/important.txt

sudo auditctl -w ~/secure_files -p rwa -k secure_files   # demo folder, reads included
sudo auditctl -w /etc/passwd    -p wa  -k identity
sudo auditctl -w /etc/shadow    -p wa  -k identity
sudo auditctl -l                                         # list loaded rules

cat ~/secure_files/important.txt          # read
echo "changed" >> ~/secure_files/important.txt
chmod 755 ~/secure_files/important.txt    # attribute change

sudo ausearch -k secure_files -i                 # raw records, numbers turned into names
sudo ausearch -k secure_files --format text      # one readable sentence per event
sudo ausearch -ts recent                         # last 10 minutes, any key
sudo aureport -f -i --summary                    # files by number of events
sudo aureport -au -i                             # logins and authentication
```

`--format text` is the most useful view for triage. A line reads like *"At 09:14 irshadali, acting as root, successfully opened-file /etc/shadow using nano"*: the login user, the effective user, the action, the file and the program. The login user (`auid`) stays the same after `sudo` or `su`, so a change made through `sudo` still names the real person.

Rules added with `auditctl` are lost at reboot. To keep them:

```bash
sudo ./scripts/setup_auditd.sh            # status, and what it would load (changes nothing)
sudo ./scripts/setup_auditd.sh --persist  # writes /etc/audit/rules.d/50-fim.rules, runs augenrules --load
sudo ./scripts/audit_report.sh            # today's events per key
sudo ./scripts/audit_report.sh -t recent identity privilege
```

What [`config/50-fim.rules`](config/50-fim.rules) watches, and why:

| Key | Paths | An attacker would change it to... |
| --- | --- | --- |
| `identity` | `/etc/passwd`, `shadow`, `group`, `gshadow` | add a user or reset a password |
| `privilege` | `/etc/sudoers`, `/etc/sudoers.d/` | give that user root |
| `sshd_config` | `/etc/ssh/sshd_config` and `.d/` | turn password or root login back on |
| `persistence` | crontab, `cron.d`, user crontabs, `/etc/systemd/system`, `/etc/ld.so.preload` | come back after a reboot |
| `binaries` | `/usr/bin`, `/usr/sbin`, `/usr/local/bin` | plant or replace a program |
| `audit_config`, `audit_tools` | `/etc/audit/`, running `auditctl` / `auditd` | switch the monitoring off |

Busy paths use `-p wa`, not `rwxa`: every program start reads `/etc` and `/usr/bin`, so watching reads there floods the log and can make the kernel drop events (`lost` in `auditctl -s`).

## 3. Hash baseline checker

The idea: record a fingerprint of every file while the system is known to be good, and later compare.

```bash
./scripts/file_integrity_checker.sh -c              # baseline of ~/secure_files
./scripts/file_integrity_checker.sh -c /srv/www /opt/app   # or any folders
./scripts/file_integrity_checker.sh -s              # compare; exit 0 clean, 1 changed
./scripts/file_integrity_checker.sh -l              # what the baseline covers
```

For each regular file and symlink the baseline stores the SHA-256 hash (or the link target), the permission bits and the owner. That matters because some of the most dangerous changes do not touch the content at all: `chmod 4755` on a program adds a setuid bit, and only a permission check sees it. A scan after a few test changes:

```
6 change(s):
  MODIFIED  /home/labuser/secure_files/important.txt  (sha256 db5c633a9f04... -> 8aff8919b106...)
  PERMS     /home/labuser/secure_files/config.conf  (mode 644 -> 4755)
  MODIFIED  /home/labuser/secure_files/link  (sha256 link:importa... -> link:config....)
  DELETED   /home/labuser/secure_files/my notes.txt
  NEW       /home/labuser/secure_files/sub/a  (mode 644, root:root)
```

When a change is expected (you edited a config on purpose), review it and run `-c` again to accept it. After creating a baseline the script prints the baseline file's own SHA-256. Write that down somewhere off the machine: an attacker with root could otherwise edit the baseline to hide their change. Real FIM tools solve this by keeping the database read-only or on another host.

## 4. Real-time monitoring with inotify

```bash
sudo apt install inotify-tools
./scripts/realtime_monitor.sh &          # watches ~/secure_files
echo "new" > ~/secure_files/test_new.txt
chmod 600 ~/secure_files/test_new.txt
rm ~/secure_files/test_new.txt
kill %1                                  # also stops the inotifywait child
```

Output from my test run:

```
ALERT    2026-11-23 03:15:53  CREATE                 .../secure_files/test_new.txt
ALERT    2026-11-23 03:15:53  CLOSE_WRITE,CLOSE      .../secure_files/test_new.txt
ALERT    2026-11-23 03:15:53  CLOSE_WRITE,CLOSE      .../secure_files/config.conf
ALERT    2026-11-23 03:15:53  ATTRIB                 .../secure_files/test_new.txt
CRITICAL 2026-11-23 03:15:53  MOVED_FROM             .../secure_files/test_new.txt
ALERT    2026-11-23 03:15:53  MOVED_TO               .../secure_files/moved.txt
CRITICAL 2026-11-23 03:15:53  DELETE                 .../secure_files/moved.txt
```

I watch `close_write` instead of `modify`: `modify` fires on every `write()` call, so saving one large file can produce hundreds of lines, while `close_write` gives one line per save. Editor swap files can be ignored with `FIM_RT_EXCLUDE='\.swp$|~$'`. For a big tree, raise `fs.inotify.max_user_watches`, since every subfolder costs one watch.

## 5. Critical folders and scheduled checks

```bash
sudo ./scripts/critical_dirs_monitor.sh setup      # load the auditd rules
sudo ./scripts/critical_dirs_monitor.sh baseline   # /etc /usr/bin /usr/sbin /usr/local/bin ~/secure_files
sudo ./scripts/critical_dirs_monitor.sh check
sudo ./scripts/critical_dirs_monitor.sh report     # hash check + auditd events in one private file
```

In my test the baseline covered 2,638 files and took about 18 seconds. Then I made four "attacker" changes and ran `report`:

```
4 change(s):
  MODIFIED  /etc/hosts  (sha256 d343af6b2baf... -> 1542098795de...)
  NEW       /etc/sudoers.d/zz-test  (mode 644, root:root)
  PERMS     /usr/bin/id  (mode 755 -> 4755)
  NEW       /usr/local/bin/sshd-helper  (mode 755, root:root)
```

and the auditd half of the same report named the program behind each one:

```
At 03:19:46 ... successfully opened-file /etc/sudoers.d/zz-test using bash
At 03:19:46 ... successfully changed-file-permissions-of /usr/bin/id to suid,0755 using /usr/bin/chmod
At 03:19:46 ... successfully opened-file /usr/local/bin/sshd-helper using /usr/bin/cp
```

That pairing is the point of the lab: the hash check says *what* is different, auditd says *who and how*. The full output is in [`samples/sample-report.txt`](samples/sample-report.txt).

Under `sudo`, Ubuntu sets `HOME=/root`, so the demo folder becomes `/root/secure_files`. To include your own one, pass it explicitly: `sudo FIM_DEMO_DIR=/home/irshadali/secure_files ./scripts/critical_dirs_monitor.sh baseline`.

**Scheduling.** For a quick test, `fim_service.sh` runs the check on a loop:

```bash
./scripts/fim_service.sh start 300     # every 5 minutes
./scripts/fim_service.sh status        # PID and the last log lines, including what changed
./scripts/fim_service.sh stop          # stops the loop, its sleep, and any scan in progress
```

On a real machine a systemd timer is better: it survives logouts and reboots, systemd keeps the output, and a run that finds changes exits 1, so it shows in `systemctl --failed`.

```bash
sudo cp -r . /opt/fim
sudo cp config/fim-check.service config/fim-check.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo /opt/fim/scripts/critical_dirs_monitor.sh baseline
sudo systemctl enable --now fim-check.timer
systemctl list-timers fim-check.timer
journalctl -u fim-check.service -n 30
```

## 6. Bugs I fixed compared with the starting code

The handout scripts ran, but several of them gave wrong answers or left things behind:

| Problem in the starting code | Effect | What I did |
| --- | --- | --- |
| New files found with `grep -q "$file" baseline.txt` | Regex substring match: a new file `sub/a` is "found" because `sub/ab` is in the baseline, so it is never reported. A `.` in a name matches any character | Exact lookup in a Bash associative array keyed by path |
| `CHANGES_FOUND=1` set inside `find ... \| while read` | The loop runs in a subshell, so the flag is lost and the report says "No changes detected" right under a list of new files | Collect findings in an array in the main shell |
| Scan always exits 0 | Cron or systemd cannot tell a clean run from an alarm | Exit 0 clean, 1 changes, 2 error |
| MD5 checksums | MD5 collisions can be produced on purpose, so a crafted file can keep the same hash | SHA-256 |
| Only content hashes | `chmod 4755` (setuid) or `chown` changes go unnoticed | Mode and owner stored and compared |
| `md5sum` output parsed with `cut -d' ' -f3-` | `md5sum` escapes names containing a backslash or newline, so those paths come back wrong | Hash from stdin, `find -print0` for names with spaces |
| Paths built from `/home/$USER` | Under `sudo` or cron `$USER` is `root` or empty, and root's home is `/root`, so everything points at a folder that does not exist | Use `$HOME`, or `FIM_DEMO_DIR` |
| Baseline and reports in the home folder, default permissions | Readable by other users, and they pile up forever | Private state folder, `umask 077`, newest 30 reports kept |
| `auditctl -w dir -p rwxa` plus `-w dir -p a` | The second rule is already covered by the first | One rule per path |
| `rwxa` on `/etc`, `/usr/bin`, `/usr/sbin` and `/var/log` | Every program start and every log line is an event: the audit log floods and the kernel starts dropping events | `-p wa` on busy paths; `/var/log` not watched at all |
| Hash baseline of `/var/log` | Logs change every second, so every check is a wall of false alarms | Left out; logs are protected by shipping them elsewhere |
| `find ... 2>/dev/null` while baselining `/etc` | Run without root, `/etc/shadow` and `/etc/sudoers` are silently skipped, so the baseline misses exactly the files that matter | Warn when not root, mark unreadable files `UNREADABLE`, show `find` errors |
| Rules only via `auditctl` | Gone after a reboot | `setup_auditd.sh --persist` writes `/etc/audit/rules.d/` and runs `augenrules --load` |
| `auditctl -R` on a rules file with a path whose folder does not exist | `auditctl` stops at that line and silently drops every rule after it. I hit this in testing: no `/etc/ssh` meant only 6 of the 19 watches loaded | `setup_auditd.sh` skips such lines and names them |
| `inotifywait \| while read` and `kill $MONITOR_PID` | Kills the script, but the `inotifywait` in the pipeline keeps running in the background | `inotifywait` on its own file descriptor, stopped by an exit trap |
| `-e modify` | One line per `write()` call; a big save gives hundreds | `close_write` |
| `fim_service.sh` calls `./file_integrity_checker.sh` | Only works when started from the scripts folder | Scripts find each other by their own location |
| `kill $(cat pidfile)` | Kills the loop's subshell but not the running `sleep 300` or scan | Loop started with `setsid`, the whole process group is stopped |
| `ausearch ... 2>/dev/null \| head` | "No matches" and "permission denied" look the same: an empty section | Counts per key first, so 0 is shown as 0 |

All scripts use `set -euo pipefail` and pass `shellcheck` with no warnings.

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `auditd` fails to start, "start request repeated too quickly" | Bad line in a rules file or `auditd.conf` | `sudo augenrules --check`, fix the file, then `sudo systemctl reset-failed auditd && sudo systemctl start auditd` |
| `ausearch` shows `<no matches>` | Rule not loaded, wrong key, or the event happened before the rule existed | `sudo auditctl -l`, then repeat the action and search with `-ts recent` |
| Fewer rules loaded than in the file | A watched path's folder does not exist on this machine | `setup_auditd.sh` lists what it skipped |
| `lost` is above 0 in `auditctl -s` | Too many events for the kernel buffer | Watch fewer paths for `r`, or raise `-b 8192` in `rules.d` |
| `Error sending add rule data request (Rule exists)` | That exact rule is already loaded | Harmless. `sudo auditctl -D` clears all rules |
| `inotifywait: Failed to watch ...; upper limit on inotify watches reached` | Too many folders | `echo fs.inotify.max_user_watches=524288 \| sudo tee /etc/sysctl.d/90-inotify.conf && sudo sysctl --system` |
| Baseline shows `UNREADABLE` files | Not run as root | Run with `sudo` |
| Every check reports the same changes | Changes were expected but the baseline was never refreshed | Review, then run `baseline` (or `-c`) again |
| The demo folder's audit count keeps growing during scans | The `secure_files` rule includes reads, and the hash scan reads every file | Expected for the demo. Production rules use `-p wa` |

## 8. How I tested it

The lab itself ran on a provided Ubuntu cloud machine. I then tested every script in a clean Linux container with auditd 3.1.2 and inotify-tools, running as root, with the kernel audit system active, so the auditd results above are real output, not copied from the handout. Paths in the samples are shortened to `/home/labuser`.

- `shellcheck -x scripts/*.sh`: no findings. `bash -n` on every script.
- `file_integrity_checker.sh` on a folder with a space in a name, a backslash in a name, a symlink, and a new file whose path is a prefix of an existing one (the case the original `grep -q` misses). It reported all six changes, exit code 1; a clean run gives exit code 0.
- `realtime_monitor.sh`: create, append, chmod, move and delete each produced the expected line, and after `kill` no `inotifywait` was left running.
- `setup_auditd.sh --load` and `--persist` with real `auditctl` and `augenrules`. 18 keyed rules loaded; the two `/etc/ssh` rules were skipped because the container has no SSH server.
- `audit_report.sh` after adding and deleting a user, creating a cron file, and dropping a file in `/usr/local/bin`: each one appeared under the right key with the program that did it.
- `critical_dirs_monitor.sh baseline` and `report` over 2,638 files, with the four test changes shown in section 5.
- `fim_service.sh` start, a second start (refused, already running), status, and stop: no loop or `sleep` left behind.

**Not verified:** the systemd timer was not run (the container has no systemd), and none of this has been run on my own Ubuntu machine yet. On my laptop the `sshd_config` rules will load as well, since it runs an SSH server.

## 9. Takeaway

No single tool answers the whole question. A hash baseline proves *that* something changed, auditd tells you *who and with what*, and inotify tells you *now*. Together they turn "I think someone was on this box" into a timeline. And as with every monitor: a check that cannot fail (always exit 0, a flag lost in a subshell, rules that vanished at reboot) is worse than no check, because it gives you confidence you have not earned.
