# 2026-11-21 · Lab 5: Linux security hardening

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | In progress: firewall enabled on my machine; scripts written and tested on sample data, real-log run and cron still to do |
| **Environment** | Ubuntu 25.10 (irshadali-OMEN), UFW, OpenSSH 10, systemd journal, cron, run as root |
| **Lab folder** | [`cybersecurity-fundamentals/lab-5-linux-security-hardening/`](../cybersecurity-fundamentals/lab-5-linux-security-hardening/README.md) |

## What the lab covered

Three layers of host hardening. I set up a default-deny UFW firewall, finished the SSH hardening I started in the [2026-10-11 SSH lab](2026-10-11-ssh-hardening.md), and read the systemd journal for signs of attack. Then I turned the log checks into scripts that raise alerts and run from cron.

## Commands and configs used

```bash
ufw default deny incoming && ufw default allow outgoing
ufw enable && ufw status verbose        # active, logging low, deny routed
ss -tlnp                                # what is really listening
sshd -T | grep -E 'permitroot|passwordauth|kbdinteractive|maxauthtries'
journalctl -u ssh --since "24 hours ago" | grep -E 'Failed|Accepted'
journalctl -k | grep 'UFW BLOCK'
./scripts/ssh_audit.sh
./scripts/security_monitor_master.sh
./scripts/setup_monitoring_cron.sh --install
```

My firewall after `ufw enable`:

```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
22, 80, 443, 9392/tcp, 9000/tcp, 9200/tcp   ALLOW IN   Anywhere   (+ v6 copies)
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| 9392 (OpenVAS UI), 9000 and 9200 open to the whole internet | Rules added with a plain `ufw allow <port>` | Scope to localhost or LAN: `TRUSTED=192.168.1.0/24 ./scripts/ufw_scope_ports.sh --apply` (to do) |
| Rule for 22 still present | sshd moved to 2222 in the earlier lab | `ufw delete allow 22` once 2222 is allowed (to do) |
| Handout's `journalctl -u sshd` returns nothing | The unit is `ssh` on Ubuntu | Query both `ssh` and `sshd` units |
| `netstat: command not found` | net-tools not installed on 25.10 | `ss -tlnp` |
| Grepping `sshd_config` misreports settings | Drop-ins in `sshd_config.d/` and defaults are invisible to grep | `sshd -T` shows the effective values |
| `Port` change ignored | Socket-activated ssh: `ssh.socket` holds the port | `systemctl disable --now ssh.socket` then `systemctl restart ssh` |

The full list of script bugs I fixed compared with the starting code is in the [lab README](../cybersecurity-fundamentals/lab-5-linux-security-hardening/README.md#6-bugs-i-fixed-compared-with-the-starting-code).

## Key takeaway

A firewall rule that says "Anywhere" deserves a second look every time. And a monitoring script has to be tested against an attack it should catch (here, a sample log), because one that reads the wrong log happily reports zero.

## Screenshots

Folder: [`screenshots/2026-11-21-linux-security-hardening/`](screenshots/)

- `01-ufw-status-verbose.png`: firewall active with default deny (to add)
- `02-ssh-audit.png`: `ssh_audit.sh` result (to add)
