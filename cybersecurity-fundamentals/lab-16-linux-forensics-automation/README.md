# Lab 16: Linux Forensics Automation

Collecting evidence from a live Linux host, analysing it for signs of an intruder, and writing the result up as a report, with every step scripted so it runs the same way every time.

The workflow has four stages. Each one is a script, and each one reads only what the previous one wrote:

| Stage | Script | What it produces |
| --- | --- | --- |
| Stage test activity | [`create_test_activities.sh`](scripts/create_test_activities.sh) | A harmless, labelled "attack" to find: brute-force log, netcat listener, backdoor-named file |
| Collect | [`forensic_collector.sh`](scripts/forensic_collector.sh) | `automated_collection_<time>/` with system, user, process, network, log, persistence and temp-file evidence; per-file SHA-256 manifest; hashed read-only archive |
| Analyse | [`forensic_analyzer.py`](scripts/forensic_analyzer.py) | Graded findings from the collected data, plus a JSON report, a text report and an event timeline |
| Detect live | [`detect_unauthorized.sh`](scripts/detect_unauthorized.sh) | The same questions asked of the running host directly, with recommendations |
| Report | [`generate_report.sh`](scripts/generate_report.sh), [`html_report_generator.py`](scripts/html_report_generator.py) | One text report (and an HTML version) merging both, with timeline and hash verification |

**Sample output from a real run:** [text report](samples/forensic_report.txt), [HTML report](samples/forensic_report.html), [terminal transcript](samples/session-transcript.txt).

## Contents

1. [Files in this folder](#1-files-in-this-folder)
2. [Quick start](#2-quick-start)
3. [Manual collection first](#3-manual-collection-first)
4. [The collector](#4-the-collector)
5. [The analyser](#5-the-analyser)
6. [The simulated attack](#6-the-simulated-attack)
7. [Live detection](#7-live-detection)
8. [The reports](#8-the-reports)
9. [What I changed from the starting steps, and why](#9-what-i-changed-from-the-starting-steps-and-why)
10. [Normal versus suspicious](#10-normal-versus-suspicious)
11. [How I tested it](#11-how-i-tested-it)
12. [Troubleshooting](#12-troubleshooting)
13. [Takeaway](#13-takeaway)

## 1. Files in this folder

| File | What it does | Changes the system? |
| --- | --- | --- |
| [`scripts/lib.sh`](scripts/lib.sh) | Shared helpers: watchlists, private folders, auth log reader (file or journal), finding format, recommendations | No (sourced) |
| [`scripts/forensic_collector.sh`](scripts/forensic_collector.sh) | Evidence collection, manifest, archive | No, only writes evidence |
| [`scripts/forensic_analyzer.py`](scripts/forensic_analyzer.py) | Analysis of a collection: auth, processes, network, temp files | No |
| [`scripts/create_test_activities.sh`](scripts/create_test_activities.sh) | Stages and removes the simulated activity | Only with `--apply` |
| [`scripts/detect_unauthorized.sh`](scripts/detect_unauthorized.sh) | Read-only live checks of the host | No |
| [`scripts/generate_report.sh`](scripts/generate_report.sh) | Text report from the newest collection, detection and analysis | No, writes a report |
| [`scripts/html_report_generator.py`](scripts/html_report_generator.py) | Self-contained HTML report with severity chart | No, writes a report |
| [`tests/test_lab.sh`](tests/test_lab.sh) | 57 end-to-end checks of the whole workflow, including cleanup and tamper detection | Yes, on a throwaway machine |
| [`tests/test_analyzer.py`](tests/test_analyzer.py) | 16 unit tests of the analyser and HTML generator on fixed sample data | No |
| [`samples/`](samples/) | Reports, transcript, collection log and summary, test output from one real run | No |
| [`social/`](social/) | Post text and graphic for sharing the lab | No |

## 2. Quick start

```bash
sudo apt install -y net-tools lsof psmisc netcat-openbsd tree   # psmisc gives pstree
cd lab-16-linux-forensics-automation/scripts

sudo ./create_test_activities.sh                 # dry run: shows the plan
sudo ./create_test_activities.sh --apply         # stage the simulated activity
sudo ./forensic_collector.sh --extra-log /tmp/forensics_lab_sim/test_auth.log
sudo python3 forensic_analyzer.py                # exit 1 when anything is HIGH or CRITICAL
sudo ./detect_unauthorized.sh --auth-log /tmp/forensics_lab_sim/test_auth.log
sudo ./generate_report.sh --analyst "Irshad Ali"
sudo python3 html_report_generator.py --analyst "Irshad Ali"
sudo ./create_test_activities.sh --cleanup --apply

sudo ./tests/test_lab.sh                         # optional: the full self-test
python3 ../tests/test_analyzer.py
```

Everything is written under `/home/forensics/` (mode 700). Set `FORENSICS_BASE=/some/folder` to use another place. Without the simulated activity, drop the `--extra-log` / `--auth-log` options and the same scripts examine the real host.

## 3. Manual collection first

The lab starts by doing the collection by hand: create a folder layout (`logs/{system,auth,application}`, `processes/`, `network/`, `system_info/`), copy `syslog`, `kern.log` and `auth.log`, grep out failed logins, accepted logins and sudo use, then save `ps aux`, `pstree`, `ss`/`netstat`, routes, ARP, interfaces, firewall rules, `who`, `last`, `lscpu`, `free` and `df`.

Doing it once by hand is worth it, because it shows what each piece of evidence looks like and where it lives. It also shows the problems the script has to solve: on my Ubuntu 25.10 laptop there is no `/var/log/auth.log` unless rsyslog is installed (logins go only to the journal), `netstat`/`ifconfig`/`arp` are missing until `net-tools` is installed, and a folder created with the default umask lets every local user read the copied auth log.

## 4. The collector

`forensic_collector.sh` fills in all the TODOs from the handout and adds what makes a collection usable as evidence:

- **Order of volatility.** Processes and sockets first (they change by the second), then system details, accounts, logs, persistence and files.
- **Every command is logged.** `collection_log.tsv` records time, exit code, output file and command. A missing tool shows as `missing`, a missing log as `absent`, a failure with its exit code, instead of an empty file that looks like "nothing happened".
- **Both log sources.** `auth_events.txt` comes from `auth.log` (and `auth.log.1`) when they exist, from the journal otherwise; failed, accepted and sudo lines are then extracted from it.
- **Extra signals the handout did not collect:** programs that were deleted from disk while still running (`/proc/*/exe`), accounts with UID 0, accounts with a login shell, admin group members, cron and systemd timers, a listing of `/tmp`, `/var/tmp` and `/dev/shm`.
- **No password hashes.** Account status comes from `passwd -S -a`; `/etc/shadow` is never copied. The test suite checks that no hash appears anywhere in the evidence.
- **Integrity.** `MANIFEST.sha256` holds the hash of every collected file, and the `.tar.gz` gets its own `.sha256`. The archive is mode 400 and holds relative paths.
- **Read-only.** The firewall is listed (`iptables -L`, `nft list ruleset`, `ufw status`), never changed.

## 5. The analyser

`forensic_analyzer.py` keeps the class from the handout (`analyze_auth_logs`, `analyze_processes`, `analyze_network_connections`, `generate_report`) and adds `analyze_temp_files`. Every finding is graded CRITICAL, HIGH, MEDIUM, LOW or INFO.

| Area | Check | Grade |
| --- | --- | --- |
| Auth | More than 10 failed logins from one address | HIGH |
| | ...and a successful login from that address **after** the failures began | CRITICAL |
| | `sudo` refused ("NOT in sudoers") | HIGH |
| | `sudo` used by an account outside `sudo`/`admin`/`wheel` | HIGH |
| | `sudo` that reads `/etc/shadow`, makes a temp file executable, changes accounts or disables the firewall | MEDIUM |
| | Username crafted to plant a fake source address (see below) | MEDIUM |
| Processes | `nc`/`ncat`/`netcat`/`socat` in listen or exec mode | HIGH |
| | Program running from `/tmp`, `/var/tmp`, `/dev/shm`, or deleted from disk | HIGH |
| | CPU above 80% or memory above 50% | MEDIUM |
| | `wget`/`curl` running | LOW |
| Network | Listener on 4444, 5555, 6666, 1234 or 31337 (says whether it is loopback only) | HIGH |
| | Outbound connection to one of those ports (possible reverse shell) | HIGH |
| | Connections to public addresses, grouped by program | INFO |
| Files | Name contains backdoor / malicious / exploit in a temp folder | HIGH |
| | Executable file in a temp folder | MEDIUM |

Details that matter on real data:

- **Log injection.** sshd writes the username before the address: `Failed password for invalid user <name> from <ip> port <n>`. An attacker can choose the name `test from 10.9.9.9 port 22`, and a parser that takes the first `from <ip>` then blames 10.9.9.9. The analyser anchors the address to the end of the line, so it always gets the real one, and reports the attempt itself.
- **Matching by program name, not text.** Looking for "nc" anywhere in `ps aux` also matches `grep nc`, `timeout 60m nc ...` and any command containing "sync". The analyser compares the program name exactly.
- **Both timestamp styles.** Classic `Nov 28 10:01:00` and the RFC 3339 format Ubuntu now uses (`2026-11-28T10:01:00+05:00`), so timelines from mixed sources sort correctly.
- **`ss` and `netstat`.** Both output formats are parsed, including `[::]:22`, `*:68` and `127.0.0.53%lo:53`.

## 6. The simulated attack

`create_test_activities.sh --apply` stages a small, believable story inside `/tmp/forensics_lab_sim/` (mode 700):

| Staged | What it shows |
| --- | --- |
| `test_auth.log`: 18 failed logins from 203.0.113.50, then an accepted password for `webadmin`, then `webadmin` refused `sudo cat /etc/shadow` and allowed `sudo chmod +x .../backdoor.sh` | Brute force that worked, followed by privilege abuse |
| One failed login whose username contains a fake `from 10.9.9.9` | The log injection case |
| `backdoor.sh`, a file that only prints a message | Suspicious file name |
| `nc -l 127.0.0.1 4444`, stopped automatically after 60 minutes | Netcat listener on a backdoor port |

Choices I made on purpose:

- **203.0.113.50, not 192.168.1.100.** 203.0.113.0/24 is reserved for documentation. 192.168.1.100 is very likely a real device on a home network, and a report blaming it would be confusing.
- **The simulated log is a separate file**, passed to the tools with `--extra-log` / `--auth-log`. Writing fake lines into the real auth log would pollute the evidence the lab is about.
- **The listener binds to 127.0.0.1**, not every interface, and stops by itself.
- **Everything carries a marker** (`FORENSICS-LAB SIMULATED`). `--cleanup --apply` only stops a process whose command line is our listener and only deletes a folder holding the marker file. It also removes the handout's `/tmp/test_auth.log` and `/tmp/suspicious_test` if, and only if, their contents are exactly what the handout created.

## 7. Live detection

`detect_unauthorized.sh` asks the same questions of the running host instead of a saved collection: brute force (with the same end-of-line address rule), netcat-style processes, programs from temp folders or deleted from disk, backdoor ports listening or connected, suspicious files, sudo by non-admins, and extra UID 0 accounts. Findings go to `findings.txt`, `findings.tsv` and `summary.txt`, with one recommendation per category found. It exits 1 if anything is HIGH or CRITICAL, so it can run from cron or CI.

Running both a live check and an analysis of a saved collection is deliberate: the collection is the evidence you can hand over and re-check later; the live check is quick triage.

## 8. The reports

`generate_report.sh` combines the newest collection, detection run and analysis:

1. **Header:** report ID, date, host, OS and kernel, analyst, the folders used.
2. **Executive summary:** counts by severity, the HIGH and CRITICAL items, and a one-line assessment.
3. **Detailed findings:** type, description, evidence and source for each. The two tools use the same wording for shared checks, so a finding seen by both appears once, marked "live detection + log and data analysis", with both pieces of evidence.
4. **Timeline:** brute-force start and end, logins and sudo use from the logs, plus collection and detection times, sorted.
5. **Recommendations** for each category found.
6. **Appendix:** where the raw data is, whether every hash in `MANIFEST.sha256` still matches, the archive hash and whether it verifies, and every command that was missing or failed.

`html_report_generator.py` produces the same content as one self-contained page with colour-coded severities and a severity bar. Log text is attacker-controlled (a username can be `<script>...`), so every value is HTML-escaped and the page carries a Content-Security-Policy that blocks all scripts. A unit test feeds it exactly that username.

## 9. What I changed from the starting steps, and why

| Starting step | Problem | What I did |
| --- | --- | --- |
| `mkdir -p /home/forensics/...` with default permissions | Copied auth logs readable by every local user | Folders mode 700, files 600, archive 400 |
| Count failed logins by IP (a TODO), the obvious way: take the address after the first `from` | Fooled by a crafted username; a fixed field number also breaks on "invalid user" lines | Address taken from the end of the line; the injection itself is reported |
| `ps aux \| grep nc` | Matches `grep nc`, `sync`, `timeout ... nc` | Exact program-name match |
| `cp /var/log/auth.log` | No such file on recent Ubuntu without rsyslog | File if present, journal otherwise |
| Output of failed commands discarded with `2>/dev/null` | An empty file looks like "nothing found" | `collection_log.tsv` with exit codes |
| Archive hashed once, folder not at all | One changed file inside cannot be pinpointed | Per-file manifest plus archive hash, both verified in the report |
| 15 fake lines appended to `/tmp/test_auth.log` with `$(date)` | Not a real syslog format, so a real parser skips them | Real RFC 3339 syslog lines, separate file, marker header |
| `nc -l 4444 &` | Listens on every interface, runs forever | Loopback only, stops after 60 minutes |
| Attacker 192.168.1.100 | Probably a real device on a home LAN | 203.0.113.50 (documentation range) |
| Brute force "more than 20 failures" in total | Misses a single attacker below 20, flags many unrelated typos | Per-address threshold; the total is only used for spread-out attempts |
| Report sections left as TODO | | Generated from the data, nothing typed by hand |

## 10. Normal versus suspicious

The handout asks to document what normal looks like. From running this on a clean container and on the staged one:

| Normal | Suspicious |
| --- | --- |
| A few failed logins from your own address after a typo | Dozens of failures from one outside address within minutes, especially for `admin`, `root`, `test` |
| Accepted logins with `publickey` from known addresses | `Accepted password` from an address that was just failing |
| `sudo` by members of the `sudo` group | `sudo` by anyone else, or "NOT in sudoers" |
| Listeners on 22 (or your SSH port), 53 on 127.0.0.53, desktop services on loopback | Anything on 4444, 31337 and friends, especially on 0.0.0.0 |
| Executables under `/usr`, `/opt`, your home folder | Executables in `/tmp`, `/dev/shm`, or deleted from disk |

One honest note from the container run: the analyser flagged a container management process running from a deleted `memfd:` file as HIGH. That one is benign (the container's own telemetry), but the detection is right to raise it: running from memory with no file on disk is exactly how fileless malware hides. On a real host each such finding needs a look at what started it.

## 11. How I tested it

Everything ran in a disposable Ubuntu 24.04 cloud container, as root, with real `ss`, `lsof`, `pstree`, `iptables` and OpenBSD netcat:

- `tests/test_lab.sh`: **57 of 57 checks pass** ([output](samples/test-run.txt)). It covers dry runs changing nothing, the loopback-only listener, private permissions, no password hashes in the evidence, manifest and archive verification, every detection in both tools, the report sections, findings merged across tools, timeline order, no scripts in the HTML, a one-byte tamper being caught (and flagged in the report), cleanup leaving an unmarked folder alone, and the firewall rules being identical before and after.
- `tests/test_analyzer.py`: **16 of 16 pass** ([output](samples/unit-tests.txt)), on fixed log, `ps`, `ss`, `netstat` and file-listing samples: threshold edge, success before failures not counted as a compromise, the injection case, classic and ISO timestamps, `grep nc` not matched, HTML escaping.
- All Bash scripts pass `shellcheck`; the Python passes `pyflakes`.
- The [samples](samples/) come from one full run. I replaced the container's own management processes and service addresses with `<sandbox ...>` placeholders; nothing else was edited.

What the container could not show, still to run on my own Ubuntu machine:

- **Real authentication events.** The container has no sshd, no auth.log and an empty journal, so all auth findings came from the simulated log. On my laptop the journal fallback should pick up real `sudo` and login lines.
- **systemd timers.** `systemctl list-timers` fails without systemd as PID 1 (it is logged as exit 1 in the [collection log](samples/collection_log.tsv)).
- **UFW status** (not installed in the container) and `lsmod`.
- **Normal desktop noise.** A laptop has many more processes and connections; I want to see how many INFO lines that produces and whether the thresholds need tuning.

## 12. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `no authentication events on this host` | No rsyslog, and the journal is empty or not persistent | `sudo mkdir -p /var/log/journal && sudo systemctl restart systemd-journald`, or install rsyslog |
| `no collection found under /home/forensics` | The analyser runs before the collector, or a different `FORENSICS_BASE` | Run `forensic_collector.sh` first; use the same base for every script |
| Permission denied on logs | Not root | `sudo`; the collector warns and still collects what it can |
| `netstat: command not found` | `net-tools` not installed | `sudo apt install net-tools`; the scripts use `ss` anyway |
| The listener did not come up | Port 4444 already in use, or a netcat with different syntax | The script refuses to share the port: check `ss -tlnp 'sport = :4444'` first, that might be real |
| `VERIFICATION FAILED` in the report | A collected file changed after collection | Treat that collection as untrustworthy and collect again |

## 13. Takeaway

The scripts matter less than the habits they enforce: collect the most volatile evidence first, record what failed as well as what worked, hash everything before anyone looks at it, and never trust a field an attacker can write into. A report generated from the data, with the hashes checked inside it, is one someone else can verify instead of just believe.
