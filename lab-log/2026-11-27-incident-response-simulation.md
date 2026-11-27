# 2026-11-27 · Lab 15: Incident response simulation

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Done on the lab's cloud machine; scripts tested in a container (38 of 38 end-to-end checks pass); not yet run on my own laptop |
| **Environment** | Lab: provided Ubuntu cloud machine. Script testing: Ubuntu 24.04 container, iptables 1.8.10 (nf_tables), run as root |
| **Lab folder** | [`cybersecurity-fundamentals/lab-15-incident-response-simulation/`](../cybersecurity-fundamentals/lab-15-incident-response-simulation/README.md) |

## What the lab covered

A complete detect, contain, collect and document cycle on a staged Linux compromise: a disguised shell loop beaconing to an outside address, an unauthorised account and a hidden file in `/tmp`. I turned each phase into a script, so the report is generated from what actually happened, with the real PID, hash and times.

## Commands used

```bash
sudo ./simulate_compromise.sh --apply          # stage the indicators
sudo ./detect_iocs.sh -k irshadali             # read-only triage, exit 1 on HIGH
sudo ./contain.sh --apply                      # snapshot, block, kill, lock, verify
sudo ./collect_evidence.sh                     # hashed archive + chain of custody
sudo ./collect_evidence.sh --verify <archive>  # recompute and compare the hash
sudo ./build_report.sh --analyst "Irshad Ali"  # incident_report.md
sudo ./cleanup_lab.sh --apply                  # remove only what the lab added
sudo ./tests/test_lab.sh                       # 38 end-to-end checks
```

Key lines from the real run:

```
[FAIL] [process] PID 8999 (root, parent 1) writes its output to hidden file /tmp/.hidden_log
[FAIL] [account] unknown login account with a usable password: hacker
[ OK ] test connection to 203.0.113.66:4444 was dropped (OUTPUT rule packets 0 -> 3)
[ OK ] passwd -S hacker shows L (locked)
[ OK ] archive hash matches the recorded value: da9e5060e536...5341
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| The beacon kept trying after the loop was killed | Killing a process and its children leaves grandchildren: the `bash` started by `timeout` survived | Stop the parent, then kill every descendant |
| The killed PID still showed in `ps` | A zombie: the container's init never collects exit codes | Treat state `Z` as dead in every check |
| The handout's DROP rule could be ignored | `-A` appends below any rule that already accepts the traffic | `-I` at the top, `-C` before adding, then a test connection and packet counter check |
| Evidence order was backwards | The handout kills the process before collecting anything | Snapshot `/proc/PID` (cmdline, fds, sockets, program hash) before the kill |
| A locked account could still log in with an SSH key | `usermod -L` / `passwd -l` only lock the password | Also `chage -E 0` and `nologin` |
| `SSH_CONNECTION: unbound variable` | `set -u` and no SSH session in the test | Default to empty |
| The triage reported the loop three times | Its `sleep` children inherit the same hidden output file | Report only the top of the process tree |
| "Suspicious IP" could not be detected | The handout's loop never touches the network | The staged loop really connects to the TEST-NET address |

## Key takeaway

Order and proof: capture what will vanish before changing anything, contain with changes that can be undone exactly, verify each step with its own output, and hash the evidence before anyone touches it.

## Still to do

- Run the full cycle on my own Ubuntu machine, where auth.log or the journal will show the `useradd` event and `ss` will catch the beacon in SYN-SENT.
- Check the `-I` rules sit above UFW's chains on my laptop.
- Try AIDE and chkrootkit, installed in this lab but not used yet.
