# Lab 5: Linux Security Hardening

Locking down an Ubuntu machine in three layers. A host firewall decides what may connect at all. SSH is hardened so that the one service I do expose only takes key logins from one account. Then the system journal is watched by scripts that flag brute-force attempts, root login tries, sudo misuse and resource spikes, on a cron schedule.

**Why this matters for security work:** this covers the first hours of a typical server hardening ticket and the first questions in a SOC triage ("what is exposed, who tried to get in, and did anyone succeed?"). The firewall and SSH settings follow the same ideas as CIS benchmark controls. The log scripts are a small version of what a SIEM rule does.

## Contents

1. [Files in this folder](#1-files-in-this-folder)
2. [Firewall with UFW](#2-firewall-with-ufw)
3. [SSH hardening](#3-ssh-hardening)
4. [Reading security logs with journalctl](#4-reading-security-logs-with-journalctl)
5. [Automated alerts and scheduling](#5-automated-alerts-and-scheduling)
6. [Bugs I fixed compared with the starting code](#6-bugs-i-fixed-compared-with-the-starting-code)
7. [Troubleshooting](#7-troubleshooting)
8. [How I tested it](#8-how-i-tested-it)
9. [Takeaway](#9-takeaway)

## 1. Files in this folder

| File | What it does | Changes the system? |
| --- | --- | --- |
| [`scripts/lib.sh`](scripts/lib.sh) | Shared helpers: run as root with or without `sudo`, journal readers, IP extraction, coloured OK/WARN/FAIL output | No (sourced by the others) |
| [`scripts/firewall_check.sh`](scripts/firewall_check.sh) | UFW status and policies, flags sensitive ports open to Anywhere, listening sockets, outbound test, recent blocks | No |
| [`scripts/ufw_scope_ports.sh`](scripts/ufw_scope_ports.sh) | Replaces "allow from Anywhere" rules with "allow from a trusted network" for chosen ports | Only with `--apply` |
| [`scripts/ssh_audit.sh`](scripts/ssh_audit.sh) | Checks the *effective* sshd settings (`sshd -T`) against a baseline, detects `ssh.socket`, checks key file permissions | No |
| [`scripts/log_analysis.sh`](scripts/log_analysis.sh) | One-screen report: SSH failures and successes with top IPs and usernames, sudo use, PAM failures, UFW blocks by source and port | No |
| [`scripts/ssh_monitor.sh`](scripts/ssh_monitor.sh) | Alerts on failure bursts, per-IP brute force, root attempts, and a success from an IP that was failing | Writes an alert log |
| [`scripts/system_monitor.sh`](scripts/system_monitor.sh) | Alerts on CPU, memory, any disk over threshold, and heavy sudo use | Writes an alert log |
| [`scripts/security_monitor_master.sh`](scripts/security_monitor_master.sh) | Runs every check and saves a private, dated report with an honest summary | Writes reports |
| [`scripts/setup_monitoring_cron.sh`](scripts/setup_monitoring_cron.sh) | Shows, installs or removes the cron entries; safe to run twice | Only with `--install` / `--remove` |
| [`scripts/security_verification.sh`](scripts/security_verification.sh) | Final pass/fail checklist for every control in this lab | No |
| [`config/99-hardening.conf`](config/99-hardening.conf) | sshd drop-in with every hardening setting, commented | Only once copied in |
| [`samples/auth-sample.log`](samples/auth-sample.log) | Made-up journal lines (documentation IP ranges) for practising the log scripts | n/a |

Quick start:

```bash
cd scripts
./firewall_check.sh
./ssh_audit.sh
./log_analysis.sh
SAMPLE_LOG=../samples/auth-sample.log ./ssh_monitor.sh   # see what an attack looks like
./security_monitor_master.sh
./setup_monitoring_cron.sh            # preview, then --install
./security_verification.sh
```

The scripts work as root or as a normal user with `sudo`. As root, alert logs and reports go to `/var/log/`. As a normal user they go to `~/.local/state/security-monitor/`. Every threshold is a variable, for example `THRESHOLD=10 WINDOW="15 minutes ago" ./ssh_monitor.sh`. The monitors exit with 0 when everything is quiet, 2 when they raised alerts and 1 when the script itself could not run, so cron and the master script can tell those apart.

## 2. Firewall with UFW

UFW is a front end for the kernel's netfilter firewall. You describe rules in plain words and it writes the nftables/iptables rules for you.

### The baseline

```bash
ufw default deny incoming     # nothing gets in unless a rule says so
ufw default allow outgoing    # this machine can still reach the internet
ufw allow 2222/tcp            # the SSH port, added BEFORE enabling over SSH
ufw logging low               # log blocked packets
ufw enable                    # active now and at every boot
ufw status verbose
```

On a remote machine, allow the SSH port before `ufw enable`. Otherwise the firewall cuts off your own session.

### Reading my real status output

This is what my machine showed after `ufw enable`:

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)

To                         Action      From
22                         ALLOW IN    Anywhere
80                         ALLOW IN    Anywhere
443                        ALLOW IN    Anywhere
9392/tcp                   ALLOW IN    Anywhere
9000/tcp                   ALLOW IN    Anywhere
9200/tcp                   ALLOW IN    Anywhere
(each repeated as "(v6)" for IPv6)
```

| Line | Meaning |
| --- | --- |
| `Status: active` | Rules are loaded, and `ufw enable` also set the firewall to start at boot |
| `Logging: on (low)` | Blocked packets are logged with a `[UFW BLOCK]` prefix to the kernel log |
| `deny (incoming)` | Anything not matched by an ALLOW rule is dropped |
| `allow (outgoing)` | Connections this machine starts are not filtered |
| `deny (routed)` | The machine will not forward traffic between interfaces, so it is not acting as a router |
| `ALLOW IN ... Anywhere` | That port accepts connections from every address on the internet |
| `(v6)` | The same rule for IPv6. UFW adds both unless IPv6 is turned off in `/etc/default/ufw` |

### Hardening notes on my own rules

- **9392 (Greenbone/OpenVAS web UI), 9000 and 9200 are open to Anywhere.** These are admin and data interfaces. 9200 is the usual Elasticsearch/OpenSearch API, and an exposed one is a classic data-leak finding. 9000 is commonly Portainer, MinIO or PHP-FPM. None of them should be reachable from the whole internet. Scope them to this machine or the home LAN:

  ```bash
  ./scripts/ufw_scope_ports.sh                                   # dry run, prints the plan
  TRUSTED=192.168.1.0/24 ./scripts/ufw_scope_ports.sh --apply    # LAN only
  # or by hand:
  ufw allow from 192.168.1.0/24 to any port 9392 proto tcp
  ufw delete allow 9392/tcp                                      # removes the v4 and v6 copies
  ```

  The script adds the new rule before it deletes the old one, so there is never a gap. Note that a service bound to `127.0.0.1` is already unreachable from outside whatever UFW says. `ss -tlnp` shows which address each service listens on.
- **22 is still open, but my sshd listens on 2222** since the SSH lab. A rule for a port nothing listens on is harmless but untidy, and it hides mistakes. Once 2222 is allowed and tested, remove it with `ufw delete allow 22`.
- **80 and 443** only need to stay if this machine serves a website.
- **Docker caveat:** containers published with `docker run -p` add their own iptables rules that UFW does not see, so a "denied" port can still be reachable. Rootless Podman does not do this.

### Other rule shapes worth knowing

```bash
ufw allow from 192.168.1.100 to any port 2222 proto tcp   # one admin host only
ufw allow 8000:8010/tcp                                   # a range needs the protocol
ufw deny 23                                               # explicit deny (telnet)
ufw allow in on wlo1 to any port 3306                     # only on one interface
ufw limit 2222/tcp                                        # rate-limit: blocks an IP after 6 hits in 30 s
ufw status numbered && ufw delete 3                       # delete by number
```

`ufw limit` is a cheap brute-force brake for SSH and pairs well with `ssh_monitor.sh`.

## 3. SSH hardening

I hardened sshd in an earlier lab: [`redhat-3/lab-10`](../../redhat-3/lab-10/) and its [write-up](../../lab-log/2026-10-11-ssh-hardening.md). On my machine sshd already runs on port 2222 with root and password logins off, key-only authentication, and `AllowUsers irshadali`. A key login as `irshadali` works. This lab adds the remaining settings and an audit script instead of repeating that work.

### The full baseline

[`config/99-hardening.conf`](config/99-hardening.conf) is a drop-in for `/etc/ssh/sshd_config.d/`. A drop-in is easier to review and remove than edits scattered through the main file, and package upgrades leave it alone.

| Setting | Why |
| --- | --- |
| `PermitRootLogin no` | Attackers always try `root`. Log in as a user, then `sudo` |
| `PasswordAuthentication no` + `KbdInteractiveAuthentication no` | Both are password paths, so turn off both. `ChallengeResponseAuthentication` is the old, deprecated name for the second |
| `PubkeyAuthentication yes` | Keys cannot be guessed the way passwords can |
| `PermitEmptyPasswords no` | Never allow an account with a blank password to log in |
| `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxStartups 10:30:60` | Fewer guesses per connection, and half-open logins get dropped quickly |
| `ClientAliveInterval 300`, `ClientAliveCountMax 2` | An idle or dead session is closed after about 10 minutes |
| `X11Forwarding no`, `AllowAgentForwarding no`, `AllowTcpForwarding no` | Features a server rarely needs, each one a pivot path |
| `KerberosAuthentication no`, `GSSAPIAuthentication no` | Not used on a standalone machine |
| `AllowUsers irshadali` | Every other account is refused, even with a valid key |
| `LogLevel VERBOSE` | Logs the key fingerprint used for each login, which helps with forensics |

**Order matters.** sshd takes the *first* value it reads for each keyword. Ubuntu's `sshd_config` includes `sshd_config.d/*.conf` at the top, in name order, so a `50-cloud-init.conf` that says `PasswordAuthentication yes` beats a `99-` file. Always confirm with `sshd -T`, which prints the settings that are really in force. `ssh_audit.sh` does exactly that.

### Applying it without locking yourself out

```bash
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
cp config/99-hardening.conf /etc/ssh/sshd_config.d/
sshd -t                                   # silent means valid; otherwise it names the bad line
systemctl restart ssh                     # the unit is "ssh" on Ubuntu, "sshd" on RHEL
ufw allow 2222/tcp
ssh -p 2222 irshadali@127.0.0.1           # test from a SECOND terminal before closing the first
./scripts/ssh_audit.sh
```

### The socket activation trap (Ubuntu 22.10 and later)

On Ubuntu, `ssh.socket` listens on the port and starts sshd on demand. The socket unit holds the port, so changing `Port` in `sshd_config` alone does nothing, and sshd keeps answering on 22. Either turn socket activation off:

```bash
systemctl disable --now ssh.socket
systemctl enable --now ssh.service
```

or keep it and move the socket with `systemctl edit ssh.socket`:

```ini
[Socket]
ListenStream=
ListenStream=2222
```

`ssh_audit.sh` warns when `ssh.socket` is active and prints the port it really holds.

### Keys

```bash
ssh-keygen -t ed25519 -C "irshadali@laptop"   # shorter, faster and more modern than RSA-4096
ssh-copy-id -p 2222 irshadali@server          # or append the .pub to ~/.ssh/authorized_keys by hand
chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
```

Protect the private key with a passphrase and use `ssh-agent` so you only type it once. sshd ignores `authorized_keys` if the file or `~/.ssh` is writable by others (`StrictModes`), and that is the most common reason a "correct" key is refused.

## 4. Reading security logs with journalctl

```bash
journalctl -b                                   # this boot;  -b -1 for the previous one
journalctl -f                                   # follow live, like tail -f
journalctl -u ssh --since "1 hour ago"          # one unit, time-boxed ("ssh", not "sshd", on Ubuntu)
journalctl --since "2026-11-20 09:00" --until "2026-11-20 12:00"
journalctl -p warning -b                        # priority warning and worse
journalctl _COMM=sudo                           # every sudo event, matched by process name
journalctl -k | grep 'UFW BLOCK'                # firewall drops (kernel log)
journalctl -u ssh -o json-pretty -n 1           # every field of the last entry
```

What to look for:

| Pattern | Meaning |
| --- | --- |
| `Failed password for root from` | Someone guessing the root password. With `PermitRootLogin no` it fails anyway, but it shows you are being scanned |
| `Invalid user admin from` | A username that does not exist, typical of wordlist bots |
| `Failed publickey for` | A key was offered and refused. Often a misconfigured client of your own |
| `Accepted publickey for` | A successful login. Check the IP and the key fingerprint |
| `sudo: ... COMMAND=` | A command run as root, with who ran it and from where |
| `incorrect password attempt` / `NOT in sudoers` | Someone failing at sudo |
| `[UFW BLOCK] SRC=... DPT=...` | A dropped packet: the source address and the port it tried |

On Ubuntu 25.10 (OpenSSH 10) the per-connection process is called `sshd-session`, not `sshd`. Filtering by unit (`-u ssh`) catches both, but `grep sshd:` misses the session lines.

`log_analysis.sh` collects all of this into one report and ranks the top source IPs, usernames and blocked ports. To see what an attack looks like without waiting for one, run it on the sample:

```bash
SAMPLE_LOG=../samples/auth-sample.log ./scripts/log_analysis.sh
```

## 5. Automated alerts and scheduling

`ssh_monitor.sh` raises an alert when:

- total failed logins in the window go over `THRESHOLD` (default 5 per hour)
- one IP fails more than `PER_IP_THRESHOLD` times (default 3), which looks like brute force
- anyone tries `root`
- an IP that was failing then **succeeds**. This is the most important rule: a burst of failures followed by a success is what a guessed credential looks like

Against the sample log it produces:

```
SSH monitor: window since '1 hour ago', 7 failed attempts
ALERT ssh: 7 failed SSH attempts since 1 hour ago (threshold 5)
ALERT ssh: 203.0.113.45 made 5 failed attempts (possible brute force)
ALERT ssh: 2 root login attempt(s); PermitRootLogin should be refusing them
ALERT ssh: successful login from 198.51.100.7, which also failed in this window; check it was you
```

`system_monitor.sh` does the same for CPU, memory, every mounted disk and the number of sudo commands. `security_monitor_master.sh` runs all of the checks and writes a report with a summary table like this one:

```
  SSH activity       ALERTS
  System resources   ok
  Log analysis       ok
  Firewall           ok
  SSH config audit   ok
```

Scheduling:

```bash
./scripts/setup_monitoring_cron.sh             # preview
./scripts/setup_monitoring_cron.sh --install   # hourly full report, SSH check every 15 min
./scripts/setup_monitoring_cron.sh --remove
```

Each managed line is tagged `# security-monitor`, so installing twice does not add duplicate jobs and removing leaves my other cron jobs alone. Output goes to a log file because cron otherwise tries to email it. To receive alerts somewhere other than a log file, the `alert()` function in each monitor has a commented `logger` line. It can be pointed at `mail`, a webhook or `ntfy`.

For a busy server, the next step is `fail2ban`, which reads the same log lines and bans the offending IP in the firewall automatically.

## 6. Bugs I fixed compared with the starting code

The handout scripts ran, but several of them gave wrong answers on a current Ubuntu. These are the fixes:

| Problem in the starting code | Effect | What I did |
| --- | --- | --- |
| `systemctl restart sshd`, `journalctl -u sshd` | On Debian/Ubuntu the unit is `ssh`, so the restart fails and the log queries return nothing, which makes "0 failed logins" look like good news | Query both `ssh.service` and `sshd.service`. `ssh_unit()` picks the right one |
| `netstat -tlnp` | `netstat` (net-tools) is deprecated and not installed by default on Ubuntu 25.10 | `ss -tlnp` |
| `grep "^PasswordAuthentication" sshd_config` | Misses drop-ins in `sshd_config.d/`, misses defaults, and reports a commented-out line as unset | Read effective values with `sshd -T` |
| `ChallengeResponseAuthentication no` | Deprecated alias since OpenSSH 8.7 | `KbdInteractiveAuthentication no` |
| `ssh-keygen -t rsa -b 4096` | Works, but slower and larger than needed | `ssh-keygen -t ed25519` |
| CPU from `top -bn1 \| grep "Cpu(s)" \| awk '{print $2}'` | Column layout changes with locale and top version. `$2` is user CPU only, not total, and the first `top` sample is an average since boot | Two samples of `/proc/stat` one second apart |
| Memory as `used / total` from `free` | Overstates pressure on a machine with a large page cache | Uses `MemAvailable` from `/proc/meminfo` |
| Disk check on `/` only | A full `/var` or `/home` goes unnoticed | Checks every real filesystem |
| `awk '{print $11}'` to get the attacker IP | The column shifts for `invalid user` lines, so it prints `from` or a username instead of the IP | Regex `from <ip> port <n>` |
| `if [ $FAILED -gt $THRESHOLD ]` unquoted | An empty value causes `[: -gt: unary operator expected`, and the alert silently never fires | Quote everything, validate numbers, use `(( ))` |
| `grep ... \| wc -l` and `grep -c` under `set -e` | `grep` exits 1 on zero matches and kills the script | `count_matches()` always prints a number |
| `sudo` hard-coded on every line | Pointless as root, and fails where sudo is not installed | `as_root()` runs directly as root, or through sudo otherwise |
| Report in `/tmp/security_report_*.txt` | World-readable by default, never cleaned up, and contains usernames, IPs and open ports | Private folder with `umask 077`, keeps the newest 24 |
| Summary always says "All security checks completed successfully" | Misleading even when checks found problems | Each check's exit code goes in a summary table, and the master's own exit code reflects them |
| Cron setup appends with `(crontab -l; echo ...) \| crontab -` | Every run adds duplicates, and cron's output is mailed or lost | Tagged lines, idempotent install, `--remove`, output to a log |
| Firewall test pings `google.com` | ICMP is often blocked even when the web works, so it reports a false failure | Tries HTTPS first, then ping as a fallback |

All scripts use `set -euo pipefail` (the master uses `set -uo pipefail` so that one failing check does not stop the rest) and pass `shellcheck` with no warnings.

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Changed `Port`, sshd still on 22 | `ssh.socket` owns the port | Disable the socket or set `ListenStream=` (see section 3) |
| `ssh.service: Start request repeated too quickly` | A bad config made sshd crash several times in a row | Fix the file (`sshd -t` names the line), then `systemctl reset-failed ssh && systemctl restart ssh` |
| Locked out after the change | Port not allowed in UFW, or key not accepted | From the console: `cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config`, remove the drop-in, `systemctl restart ssh` |
| Key refused although it is in `authorized_keys` | Permissions too open, or the user is not in `AllowUsers` | `chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys`, then check `journalctl -u ssh -n 20` |
| `ufw status` says inactive after reboot | UFW service disabled | `systemctl enable --now ufw`, then `ufw enable` |
| Log scripts report 0 for everything | Wrong unit name, or not running as root (the journal hides other users' entries) | Run as root or with sudo; `journalctl -u ssh -n 5` should show lines |

## 8. How I tested it

In a clean Linux container (no UFW, no running sshd, no systemd), I tested the following:

- `shellcheck -x scripts/*.sh`: no findings. Also ran `bash -n` on every script.
- `log_analysis.sh` and `ssh_monitor.sh` against [`samples/auth-sample.log`](samples/auth-sample.log). They produced the counts and alerts shown above, and `ssh_monitor.sh` returned exit code 2.
- `firewall_check.sh`, `ssh_audit.sh` and `security_verification.sh` with stand-in `ufw`, `sshd` and `systemctl` programs that print my real UFW status and a deliberately weak sshd config. They flagged 9392/9000/9200, the four weak sshd settings and the active `ssh.socket`.
- `setup_monitoring_cron.sh` with a stand-in `crontab`. Installing twice left one copy of each job, and `--remove` kept an unrelated existing job.
- `ufw_scope_ports.sh` in dry-run mode only.
- `system_monitor.sh` live, including a real disk alert from a volume at 93%.

**Still to do on my own machine:** run the scripts against the real journal and the real UFW, install the cron jobs and confirm a report appears an hour later, scope ports 9392/9000/9200 with `ufw_scope_ports.sh --apply`, and apply `config/99-hardening.conf`, then see `ssh_audit.sh` pass.

## 9. Takeaway

Hardening is not a list of settings. It is settings plus proof. Every change here comes with a way to check it: `sshd -t` before the restart, `sshd -T` for the settings really in force, `ss` for what really listens, and `ufw status` for what is really allowed. And a monitor that quietly reports "0 failures" because it read the wrong log is worse than no monitor at all.
