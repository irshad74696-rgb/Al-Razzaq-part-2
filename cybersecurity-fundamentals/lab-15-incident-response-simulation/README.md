# Lab 15: Incident Response Simulation

A full incident response cycle on a Linux host, from alert to signed-off report: **detect** the indicators of compromise, **contain** them without breaking anything else, **collect** evidence that can be proven untouched, and **document** every step with real times, PIDs and hashes.

The scenario: monitoring flagged unusual outbound traffic from a server. I staged a harmless compromise (a disguised shell loop that beacons to an outside address, an unauthorised account and a hidden file), then worked it as an incident. Every step is a script, so the whole cycle can be re-run and checked, and the report is generated from what the scripts recorded instead of being typed in by hand.

| Phase (NIST SP 800-61) | Script | What it produces |
| --- | --- | --- |
| Preparation | [`simulate_compromise.sh`](scripts/simulate_compromise.sh) | The staged indicators, and a private case folder |
| Detection and analysis | [`detect_iocs.sh`](scripts/detect_iocs.sh) | Findings graded HIGH / MEDIUM / LOW, exit 1 on HIGH |
| Containment | [`contain.sh`](scripts/contain.sh) | Process snapshot, firewall block, locked account, verification output |
| Evidence | [`collect_evidence.sh`](scripts/collect_evidence.sh) | Hashed archive, per-file manifest, chain of custody |
| Post-incident | [`build_report.sh`](scripts/build_report.sh) | `incident_report.md` with timeline, IoCs, actions and hashes |
| Recovery (lab only) | [`cleanup_lab.sh`](scripts/cleanup_lab.sh) | Removes exactly what the lab added; evidence is kept |

**Sample output:** [`samples/incident_report.md`](samples/incident_report.md) is a report generated from a real run, and [`samples/session-transcript.txt`](samples/session-transcript.txt) is the terminal output of that run.

## Contents

1. [Files in this folder](#1-files-in-this-folder)
2. [Quick start](#2-quick-start)
3. [The staged compromise](#3-the-staged-compromise)
4. [Detection: what the triage looks for](#4-detection-what-the-triage-looks-for)
5. [Containment, and why the order matters](#5-containment-and-why-the-order-matters)
6. [Evidence collection and integrity](#6-evidence-collection-and-integrity)
7. [The incident report](#7-the-incident-report)
8. [What I changed from the starting steps, and why](#8-what-i-changed-from-the-starting-steps-and-why)
9. [Safety rules built into the scripts](#9-safety-rules-built-into-the-scripts)
10. [How I tested it](#10-how-i-tested-it)
11. [Troubleshooting](#11-troubleshooting)
12. [Takeaway](#12-takeaway)

## 1. Files in this folder

| File | What it does | Changes the system? |
| --- | --- | --- |
| [`scripts/lib.sh`](scripts/lib.sh) | Shared helpers: case folder, timeline logging, dry-run wrapper, IP and account safety checks, exact firewall rule specs | No (sourced) |
| [`scripts/simulate_compromise.sh`](scripts/simulate_compromise.sh) | Starts the disguised beacon loop, creates the `hacker` account | Only with `--apply` |
| [`scripts/detect_iocs.sh`](scripts/detect_iocs.sh) | Read-only triage of processes, network, accounts, auth logs, temp files, SUID programs and persistence | No |
| [`scripts/contain.sh`](scripts/contain.sh) | Snapshot, block, kill, lock, verify | Only with `--apply` |
| [`scripts/collect_evidence.sh`](scripts/collect_evidence.sh) | Evidence archive with SHA-256 manifest; `--verify` re-checks an archive | Writes to the case folder |
| [`scripts/build_report.sh`](scripts/build_report.sh) | Generates the incident report from the case folder | Writes a report |
| [`scripts/cleanup_lab.sh`](scripts/cleanup_lab.sh) | Undoes the simulation, rule by rule | Only with `--apply` |
| [`tests/test_lab.sh`](tests/test_lab.sh) | 38 end-to-end checks of the whole cycle, including the safety refusals | Yes, on a throwaway machine |
| [`samples/`](samples/) | Report, transcript, timeline, chain of custody, hash list, evidence manifest and collection log from one real run, plus the test output | No |
| [`social/`](social/) | Post text and graphic for sharing the lab | No |

Everything a case produces goes into one folder: `/var/lib/ir-lab/` (mode 700) when run as root, or `$IR_STATE_DIR` if set. The handout used `/tmp`, which every local user can list and read: the wrong place for evidence about a local attacker.

## 2. Quick start

```bash
sudo apt update
sudo apt install -y net-tools tcpdump aide chkrootkit iproute2 iptables
cd lab-15-incident-response-simulation/scripts

sudo ./simulate_compromise.sh              # dry run: shows what it would plant
sudo ./simulate_compromise.sh --apply      # plant the indicators
sudo ./detect_iocs.sh -k irshadali         # triage; -k lists accounts I know are mine
sudo ./contain.sh                          # dry run: shows the containment plan
sudo ./contain.sh --apply                  # snapshot, block, kill, lock, verify
sudo ./collect_evidence.sh                 # hashed evidence archive
sudo ./collect_evidence.sh --verify /var/lib/ir-lab/evidence/ir_collection_*.tar.gz
sudo ./build_report.sh --analyst "Irshad Ali"
sudo ./cleanup_lab.sh --apply              # remove the lab's account, rules and files
```

Every script that changes the system prints its plan and changes nothing unless `--apply` is given.

## 3. The staged compromise

`simulate_compromise.sh --apply` plants four indicators, all harmless:

| Indicator | How it is staged | Why it looks suspicious |
| --- | --- | --- |
| Process | `bash -c 'while true; ...'` started with `setsid nohup`, so its parent is PID 1 | Detached from any terminal, output going to a hidden file in `/tmp` |
| Network | The loop keeps opening TCP connections to `203.0.113.66:4444` | 203.0.113.0/24 is TEST-NET-3, reserved for documentation, so nothing real answers. Port 4444 is a classic reverse-shell port |
| Account | `hacker`, login shell, no home folder, a usable password | Not created by any administrator I know of |
| File | `/tmp/.hidden_log` | Dot-file in a world-writable folder |

Two deliberate changes from the handout. The handout's loop never touches the network, so the "suspicious IP" could only be written down, not found; mine actually beacons, so `ss` shows it and the firewall rule's packet counter proves the block works. And the handout gives the account the fixed password `CompromisedPass123!`, which on any machine with SSH open is a real backdoor for as long as the lab runs; mine uses a random password nobody ever sees. The account also carries a marker in its comment field, so cleanup can never delete a real account that happens to be called `hacker`.

## 4. Detection: what the triage looks for

`detect_iocs.sh` only reads. Each finding is graded and saved to `findings.tsv`.

| Area | Check | Grade |
| --- | --- | --- |
| Processes | Program deleted from disk, or running from `/tmp`, `/var/tmp`, `/dev/shm` | HIGH |
| | Output (`/proc/PID/fd/1`, `2`) going to a hidden file in a temp folder | HIGH |
| | Watchlist IP hard-coded in the command line | HIGH |
| | Working folder in a temp folder | MEDIUM |
| Network | Any connection to the watchlist IP (`ss -tanp`) | HIGH |
| | Outbound connection attempt (SYN-SENT) to any public IP | MEDIUM |
| Accounts | A second UID 0 account | HIGH |
| | Unknown login account with a usable password; SSH keys in its `authorized_keys` | HIGH |
| | Unknown login account, password locked | MEDIUM |
| Auth logs | `useradd` events; 20+ failed passwords (top source IPs listed); root sessions; recent sudo commands | HIGH / MEDIUM / info |
| Files | Hidden or executable files in temp folders | MEDIUM |
| | SUID program that no installed package owns (`dpkg -S`) | HIGH |
| | `.sh` files changed inside the window in `/tmp`, `/etc`, `/opt`, `/usr/local` | LOW |
| Persistence | Cron files and systemd units changed inside the window | MEDIUM |

Two details that make it usable on a real machine:

- **Child processes are grouped.** The loop's `sleep` inherits the same hidden output file, so a naive check reports every child. The triage only reports the top of the tree.
- **SUID programs are checked against the package database.** A normal Ubuntu install has a dozen or more SUID programs (`passwd`, `sudo`, `mount`...). Listing them all, as the handout does, hides the one that matters; a SUID file no package installed is the one to look at.

Auth logs come from `/var/log/auth.log` when it exists and from the journal otherwise, because recent Ubuntu releases do not always ship rsyslog.

## 5. Containment, and why the order matters

The handout kills the process first and collects evidence later, while its own key takeaways say "collect forensic data before making system changes". `contain.sh` follows the takeaway:

1. **Snapshot the process before it dies.** Command line, environment, open files, sockets, working folder, child tree, and the SHA-256 of the running program read through `/proc/PID/exe`, which works even if the file was deleted from disk. After `kill -9`, all of that is gone.
2. **Block the IP in both directions.** Rules go in with `iptables -I ... 1` at the top of the chain. The handout's `-A` appends to the end, and if any earlier rule already accepts the traffic (an "allow established" rule, a UFW chain) the DROP never matches. Each rule is checked with `-C` first, so re-running adds no duplicates, and tagged with the comment `ir-lab`. Then a test connection is made and the rule's packet counter must go up: the block is proven, not assumed.
3. **Freeze, then kill, the whole tree.** `SIGSTOP` first so it cannot react or spawn anything, then `SIGKILL` for the process and every descendant. Killing only direct children is not enough: in my first test the `bash` started by `timeout` kept beaconing after its parent and grandparent were gone.
4. **Disable the account properly.** `usermod -L` and `passwd -l` both only lock the password (they do the same thing; the handout runs both). A locked password does not stop an SSH key login, so the account is also expired with `chage -E 0`, its shell set to `nologin`, and its processes killed.

Verification output for all three, plus `chage -l` and `who`, is saved to `containment_verification.txt` and copied into the report.

## 6. Evidence collection and integrity

`collect_evidence.sh` gathers evidence in order of volatility, the most short-lived first: clock and system details, processes, network sockets, routes and neighbours, firewall rules, sessions and logins, accounts, logs, persistence locations, and finally files on disk (hidden temp files, recent changes, SUID list, suspicious shell history lines).

Integrity is handled at two levels:

| Level | How | Proves |
| --- | --- | --- |
| Each file | `MANIFEST.sha256` inside the archive (`sha256sum -c` checks it) | No single file was changed |
| The archive | SHA-256 appended to `evidence_hashes.txt` and `chain_of_custody.txt` | The archive is the one that was collected |

```bash
sudo ./collect_evidence.sh --verify /var/lib/ir-lab/evidence/ir_collection_<host>_<time>.tar.gz
#   [ OK ] archive hash matches the recorded value: da9e5060...
```

The test suite appends one byte to an archive and checks that `--verify` reports a mismatch.

Other choices: the archive is made with `tar -C`, so it holds relative paths; the archive is set read-only (mode 400); one failing command (no `netstat`, no `wtmp`) is logged with its exit code in `collection_log.tsv` instead of silently leaving an empty file; and account status is collected with `passwd -S -a` rather than copying `/etc/shadow`, because the evidence archive should not become a second copy of every password hash.

## 7. The incident report

Each script appends to `timeline.tsv` as it works (time with timezone, phase, analyst, event). `build_report.sh` turns that, the findings, the verification output and the hash records into a Markdown report: summary table, executive summary, IoC table, every finding, containment steps with their verification, evidence and chain of custody, a full timeline, recommendations and next steps. It warns if any `[PLACEHOLDER]` is left.

Because nothing is typed in by hand, the PID, hash and times in the report always match the terminal output. See [`samples/incident_report.md`](samples/incident_report.md).

## 8. What I changed from the starting steps, and why

| Starting step | Problem | What I did |
| --- | --- | --- |
| Kill the process, then collect evidence | Destroys the volatile evidence the lab says to keep | Snapshot first, then kill |
| `iptables -A INPUT/OUTPUT ... -j DROP` | Appended rule never matches if an earlier rule accepts the traffic | `-I` at position 1, `-C` before adding, tagged for removal |
| Check the rule with `iptables -L -n \| grep` | Shows the rule exists, not that it works | Test connection plus packet counter check |
| `usermod -L` and `passwd -l` | Both only lock the password; SSH keys still log in | Also `chage -E 0`, `nologin`, kill the account's processes |
| `kill -9 PID` | Children and grandchildren keep running | Stop, then kill the whole tree |
| Fixed password `CompromisedPass123!` | A real weak login on any reachable machine | Random password, never shown |
| `useradd ... hacker`, `userdel -r hacker` in cleanup | Would delete a real account with that name | Marker in the comment field; cleanup only deletes marked accounts |
| Evidence in `/tmp/ir_collection_*` | World-listable, world-readable by default | Mode 700 case folder, archive mode 400 |
| `sha256sum /tmp/ir_collection_*.tar.gz` | Hashes every old archive too, so it is no longer "one line" | Hash the exact archive, append to a history file |
| `tar -czf /tmp/x.tar.gz /tmp/x` | Absolute paths, "Removing leading /" warning | `tar -C` with relative paths |
| `cp /var/log/auth.log` | Fails silently where there is no rsyslog | Copy logs that exist, also export from the journal |
| `cat ~/.bash_history` under sudo | Reads root's history only | All users' histories, matching lines only |
| Simulated IP only written down | Nothing to detect on the network | The loop really beacons to the test address |
| Report filled in by hand | Copy errors in PIDs, hashes and times | Generated from the case timeline |
| `mv /tmp/.x /tmp/.hidden_log` after starting the loop | Works only because the open file follows the rename; easy to misread | Write to `/tmp/.hidden_log` directly |

## 9. Safety rules built into the scripts

- Dry run is the default for every script that changes the system; `--apply` is required.
- Firewall changes are surgical: exact rules are added and the same exact rules removed. No chain is ever flushed. Cleanup also removes the untagged rules if they were typed by hand from the handout.
- `contain.sh` refuses, unless given `--force`, to: block loopback, the default gateway or the IP of my own SSH session; lock `root`, my own account or any member of `sudo`/`admin`/`wheel`; kill PID 1 or any process that is the script's own parent.
- Evidence is never deleted by cleanup unless `--remove-evidence` is given. In a real incident it would go to access-controlled storage instead.

## 10. How I tested it

All tests ran in a disposable Ubuntu 24.04 cloud container with real `iptables` (nf_tables), `useradd`/`chage` and `ss`, as root:

- `tests/test_lab.sh`: **38 of 38 checks pass**, three runs in a row ([output](samples/test-run.txt)). It covers every phase, the dry runs changing nothing, the refusals (lock root, block loopback, overwrite a real account), no duplicate rules on re-run, the tamper check, no password hashes in evidence, and an unrelated DROP rule surviving cleanup.
- One full manual run, from which the [report](samples/incident_report.md), [transcript](samples/session-transcript.txt), [timeline](samples/case_timeline.tsv), [chain of custody](samples/chain_of_custody.txt), [hash list](samples/evidence_hashes.txt), [manifest](samples/evidence_manifest.sha256) and [collection log](samples/collection_log.tsv) come. I redacted only the sandbox's own management processes and ports from the transcript.
- All scripts pass `shellcheck`.

What the container could not show, and what is still to run on my own Ubuntu machine:

- **auth.log and journal checks.** The container has neither, so the triage printed "no authentication log found". On a normal machine it will also report the `useradd` event for `hacker`.
- **SYN-SENT detection.** The sandbox refuses outbound connections at once, so no attempt was in flight when `ss` ran; the process was caught by its hidden output file and the IP in its command line instead. On a normal network each attempt hangs for up to two minutes and `ss` sees it.
- **Zombie process.** The container's init does not collect dead children, so the killed loop showed as `<defunct>`. The scripts treat a zombie as dead. With systemd as PID 1 this does not happen.
- **UFW interplay.** My laptop runs UFW. The rules go in above UFW's chains, which is the point of `-I`, but I have not run it there yet.

## 11. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `netstat: command not found` | `net-tools` is not installed by default | `sudo apt install -y net-tools`; the scripts use `ss` and only add `netstat` output when present |
| `passwd -S hacker` shows `P` after containment | Lock ran against the wrong name or without root | `getent passwd \| grep hacker`, then `sudo ./contain.sh --apply --skip-pid --skip-ip` |
| Rule present but traffic still flows | Rule appended below an ACCEPT | Use `-I`, as `contain.sh` does; check order with `iptables -L -n -v --line-numbers` |
| `ps -p PID` still shows the process after the kill, as `<defunct>` | A zombie: dead, waiting for its parent to collect its exit status | Nothing to kill; it disappears when the parent (or init) collects it |
| `contain.sh` says "refusing to lock" | The account is root, mine, or an admin | Check it really is compromised, then `--force` |
| `--verify` reports a mismatch | The archive changed after collection | Treat the archive as untrustworthy; collect again and note it in the chain of custody |
| No auth log findings | No rsyslog and the journal is not persistent | `sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald` |

## 12. Takeaway

Incident response is less about clever commands than about order and proof. Capture what will disappear before you change anything, contain with changes you can undo exactly, prove each step worked with its own output, and hash the evidence before anyone else touches it. Writing every action to a timeline as it happens is what turns a terminal session into a report someone else can trust.
