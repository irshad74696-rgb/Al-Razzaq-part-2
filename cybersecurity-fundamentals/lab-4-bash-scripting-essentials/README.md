# Lab 4: Bash Scripting Essentials

Turning one-off shell commands into scripts that run on their own: a backup that checks its own work, a version that logs and cleans up after itself, a file sorter built from loops and `case`, and a schedule that runs it all through cron while nobody is watching.

**Why this matters for security work:** backups are the last line of defence against ransomware and mistakes, scheduled scripts are how log rotation, integrity checks and evidence collection actually happen, and a script that fails quietly at 2 AM is worse than no script. Most of this lab is about making failures loud.

## Contents

1. [Scripts in this folder](#1-scripts-in-this-folder)
2. [Script building blocks](#2-script-building-blocks)
3. [Loops](#3-loops)
4. [Conditionals and case](#4-conditionals-and-case)
5. [The backup scripts](#5-the-backup-scripts)
6. [Scheduling with cron](#6-scheduling-with-cron)
7. [Why a job works by hand but fails in cron](#7-why-a-job-works-by-hand-but-fails-in-cron)
8. [Bugs I fixed compared with the starting code](#8-bugs-i-fixed-compared-with-the-starting-code)
9. [How I tested it](#9-how-i-tested-it)
10. [Takeaway](#10-takeaway)

## 1. Scripts in this folder

| Script | What it does |
| --- | --- |
| [`make_test_data.sh`](scripts/make_test_data.sh) | Builds `~/test_data` with a few sample files, including one with spaces in its name |
| [`backup_script.sh`](scripts/backup_script.sh) | Copies one folder to `~/backups/backup_<timestamp>` and verifies the copy |
| [`advanced_backup.sh`](scripts/advanced_backup.sh) | Several folders, a disk-space check, a log file, and keeps only the newest N backups per folder |
| [`file_manager.sh`](scripts/file_manager.sh) | Creates, analyzes, sorts and reports on a test folder; run one action by name or use the menu |
| [`scheduled_backup.sh`](scripts/scheduled_backup.sh) | The cron version: own PATH, lock against overlapping runs, logs only, honest exit code |
| [`test_cron.sh`](scripts/test_cron.sh) | Proves cron fired and records the environment cron gave the job |
| [`cron_monitor.sh`](scripts/cron_monitor.sh) | Read-only health screen: crontab, cron service, logs, backups on disk, free space |
| [`crontab.example`](scripts/crontab.example) | Sample schedule for the scripts above, with the five time fields explained |

Quick start:

```bash
mkdir -p ~/scripts && cp scripts/*.sh ~/scripts/ && cd ~/scripts
./make_test_data.sh
./backup_script.sh
./advanced_backup.sh && cat ~/backup_log.txt
./file_manager.sh all
./scheduled_backup.sh; echo "exit code: $?"; cat ~/cron_backup.log
./cron_monitor.sh
```

Every script takes its folders from variables with sensible defaults, so you can point it elsewhere for a dry test, for example `BACKUP_DIR=/tmp/try ./backup_script.sh`.

## 2. Script building blocks

**The first line.** `#!/usr/bin/env bash` tells the kernel which interpreter runs the file. Without `chmod +x`, `./script.sh` gives "Permission denied"; `bash script.sh` still works because bash only needs to read it.

**Variables.** No spaces around `=`: `name="value"`. Read them with `"$name"`, and keep the double quotes. An unquoted `$file` holding `my notes.txt` becomes two words, `my` and `notes.txt`, and a command like `rm` then acts on the wrong things.

```bash
SOURCE_DIR="${SOURCE_DIR:-$HOME/test_data}"   # use the caller's value, or this default
STAMP="$(date +%Y%m%d_%H%M%S)"                # command substitution: capture output
```

**Arrays** hold a list where each item may contain spaces:

```bash
SOURCES=("$HOME/test_data" "$HOME/scripts")
for src in "${SOURCES[@]}"; do ...; done       # "${arr[@]}" keeps each item whole
echo "${#SOURCES[@]} folders"                  # number of items
```

**Functions** group steps and return a status (0 = success, anything else = failure) that `if` can test:

```bash
log() { printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$2" | tee -a "$LOG_FILE"; }
backup_one() { local src="$1"; ...; }          # local keeps variables inside the function
```

**Exit codes** are how scripts talk to whatever ran them, cron and monitoring included. `exit 0` means it worked; anything else means it did not. A backup script that prints "failed" but exits 0 looks healthy to every tool watching it.

**Safety options** at the top of the scripts: `set -u` stops on a misspelled variable instead of silently using an empty string, and `set -o pipefail` makes a pipeline fail if any part of it fails. I avoided `set -e` in the loop-heavy scripts and handled each failure explicitly instead, because `set -e` has surprising exceptions (see the `((count++))` note in section 8).

## 3. Loops

**`for` over a list or a range:**

```bash
for i in {1..10}; do echo "sample text $i" > "testfile$i.txt"; done
for file in "$TEST_DIR"/*; do [[ -f "$file" ]] || continue; ...; done
```

A glob like `"$TEST_DIR"/*` is the safe way to loop over files. Looping over `$(ls)` breaks on spaces.

**`while read` over command output.** The right shape is:

```bash
while IFS= read -r -d '' file; do
    ...
done < <(find "$TEST_DIR" -type f -print0)
```

`-print0` and `-d ''` separate names with a null byte, which can't appear in a filename, so spaces and even newlines in names are safe. `< <(...)` (process substitution) keeps the loop in the current shell. Writing `find ... | while read` instead runs the loop in a subshell, and any counter you update inside it is gone when the loop ends.

**`continue` and `break`** skip to the next item or leave the loop. The menu in `file_manager.sh` uses `break` on "quit", and also leaves when `read` hits end of input, so it can't spin forever with no keyboard attached.

**C-style loop** for counting: `for (( i = 0; i < extra; i++ )); do ...; done`.

## 4. Conditionals and case

`[[ ... ]]` is bash's test command. The ones used here:

| Test | True when |
| --- | --- |
| `[[ -d "$p" ]]` | `$p` is a folder |
| `[[ -f "$p" ]]` | `$p` is a regular file |
| `[[ -e "$p" ]]` | anything exists at `$p` |
| `[[ -s "$p" ]]` | file exists and is not empty |
| `[[ "$a" == *.txt ]]` | `$a` matches the pattern |
| `(( n > 5 ))` | arithmetic comparison |

`if` can test a command directly, which is cleaner than checking `$?` afterwards:

```bash
if cp -a -- "$src" "$dest"; then echo ok; else echo failed; fi
```

`case` picks a branch by pattern, which reads better than a long `if/elif` chain:

```bash
case "$name" in
    *.txt)  kind=text ;;
    *.log)  kind=log ;;
    *)      kind=other ;;
esac
```

`file_manager.sh` uses `case` twice: to classify files, and to choose the action from its first argument (`create`, `analyze`, `organize`, `report`, `clean`, `all`, `menu`).

## 5. The backup scripts

**`backup_script.sh`**: check the source exists, make the backup folder, `cp -a` (keeps permissions and timestamps, unlike plain `cp -r`), then `diff -rq` the copy against the source. Only a matching copy counts as success.

**`advanced_backup.sh`** adds:

- A free-space check before starting (`df -Pm`, default minimum 100 MB).
- A timestamped log line for every step in `~/backup_log.txt`.
- Copy to `<name>_<stamp>.partial`, verify, then rename. A half-finished copy never looks like a real backup, and a failed one is removed.
- Retention: keeps the newest `KEEP` (default 5) backups **of each folder**. It only considers folders whose name matches `<name>_YYYYMMDD_HHMMSS` exactly, so other files you keep in `~/backups` are never touched. The timestamp format sorts correctly as plain text, so the oldest come first in a glob without parsing `ls`.
- Refuses to write to a name that already exists (two runs in the same second).

**`scheduled_backup.sh`** is the same idea, built for cron (section 6), with `umask 077` so backups are readable only by their owner.

**In real life** you'd reach for `tar` or `rsync` rather than `cp`:

```bash
tar -czf "backup_$(date +%F).tar.gz" -C "$HOME" test_data   # one compressed file, easy to move offsite
tar -tzf backup_2026-11-20.tar.gz                           # list it to check it is readable
rsync -a --delete ~/test_data/ /mnt/backup/test_data/       # only copies what changed
rsync -a --link-dest=../previous ~/data/ ./today/            # snapshot-style: unchanged files are hard links
```

And a backup on the same disk as the data doesn't survive that disk failing or being encrypted. Keep at least one copy somewhere else.

## 6. Scheduling with cron

Cron runs commands on a schedule for each user. `crontab -e` edits your list, `crontab -l` shows it, and `crontab -r` deletes all of it (no undo, so keep a copy).

Each line has five time fields, then the command:

```
┌──────── minute        0-59
│ ┌────── hour          0-23
│ │ ┌──── day of month  1-31
│ │ │ ┌── month         1-12
│ │ │ │ ┌ day of week   0-7  (0 and 7 are both Sunday)
│ │ │ │ │
* * * * *  command
```

| Symbol | Meaning | Example |
| --- | --- | --- |
| `*` | every value | `* * * * *` every minute |
| `,` | a list | `0 8,20 * * *` at 08:00 and 20:00 |
| `-` | a range | `0 9-17 * * 1-5` on the hour, 9 to 5, weekdays |
| `/` | every n-th | `*/15 * * * *` every 15 minutes |

The schedule I'd use is in [`crontab.example`](scripts/crontab.example): a nightly backup at 02:00, every 30 minutes during working hours on weekdays, a weekly simple backup, and a monthly cleanup of this lab's own logs.

To try it:

```bash
systemctl status cron          # Ubuntu/Debian; the service is called crond on RHEL/Fedora
crontab -l > ~/crontab.backup  # save what you have first
crontab -e                     # paste the lines you want, with your real home path
# for a quick test, add:  * * * * * /home/YOURUSER/scripts/test_cron.sh
# wait two minutes, then:
cat ~/cron_test.log
crontab -e                     # remove the test line again
./cron_monitor.sh
```

## 7. Why a job works by hand but fails in cron

This is the classic cron problem. Cron does not start your job the way your terminal does:

| Your terminal | Under cron | What breaks |
| --- | --- | --- |
| Full `PATH` from your profile | Usually just `/usr/bin:/bin` | Commands in `/usr/local/bin` or `/usr/sbin` come back "command not found" |
| `bash` | `/bin/sh` unless `SHELL=` is set | Bash-only syntax in a cron line fails |
| You `cd` to the script's folder | Starts in your home folder | Relative paths like `./data` or `../logs` point nowhere |
| `$USER` is set | Cron sets `HOME` and `LOGNAME`, but often not `USER` | `/home/$USER/scripts/x.sh` turns into `/home//scripts/x.sh` and is not found; write the full path |
| Output on screen | Output is mailed or thrown away | Errors vanish unless you redirect: `>> /path/job.log 2>&1` |
| A `%` is just a `%` | `%` means newline in a crontab line | `date +%F` must be written `date +\%F` in the crontab |
| No overlap | A slow run can still be going when the next one starts | Two runs fight over the same files |

`scheduled_backup.sh` answers each one: it sets its own `PATH`, uses only absolute paths built from `$HOME` (which cron does set), logs to a file, and takes a `flock` lock so overlapping runs skip instead of colliding. `test_cron.sh` writes the `PATH`, shell and working folder it was given into its log, so you can see the difference for yourself. Also check: the cron service is running, the script is executable, and the line ends with a newline (a crontab's last line is ignored without one).

## 8. Bugs I fixed compared with the starting code

The lab's starting scripts worked on the happy path but had real problems. What I changed:

| Problem | Why it matters | Fix |
| --- | --- | --- |
| Checking `$?` on a line after the command | `$?` belongs to whatever ran last; move one line and it tests the wrong thing | `if cp ...; then` tests the command directly |
| `find \| while read` with counters inside | The loop runs in a subshell, so text/log counts were always 0 and never shown | `while ... done < <(find ... -print0)`, totals printed at the end |
| Counting and choosing backups with `ls \| wc -l` and `ls -t \| tail` | Breaks on names with spaces or newlines | Globs and `find -print0` |
| Retention counted everything in the backup folder | Any unrelated file or folder there could be deleted | Only names matching `<name>_YYYYMMDD_HHMMSS` are ever removed |
| `/home/$USER/...` in crontab lines | `USER` is often unset under cron, so the path becomes `/home//...` and the jobs never start | Full absolute paths in `crontab.example` |
| Monthly cleanup ran `find /home/$USER -name "*.log" -delete` | Deletes every old `.log` anywhere in the home folder | Limited to this lab's two log files, top level only |
| Interactive menu loop with no exit on end of input | Hangs forever when there's no keyboard (cron, a pipe, CI) | Actions run by name (`./file_manager.sh report`); menu leaves on end of input |
| `cp -r` with no check | A partial or failed copy still reported "success" | `cp -a`, then `diff -rq`, copy under `.partial` and rename on success |
| Two runs in the same second | The second `cp` nested inside the first backup | Refuse if the target name already exists |
| `((count++))` | Returns failure when `count` is 0, which kills a `set -e` script | `count=$((count + 1))` |
| Every-minute test job copied the whole scripts folder each time | Fills the disk with copies if you forget to remove it | `test_cron.sh` only appends a few lines to a log |
| `rm -rf "$TEST_DIR"` with no guard | A wrong `TEST_DIR` (empty, `/`, home) would be catastrophic | `clean` refuses those values |
| Cron service checked only as `cron` | It's `crond` on RHEL, Fedora and CentOS | `cron_monitor.sh` checks both, and reads `journalctl` when there is no syslog file |

## 9. How I tested it

All runs used a temporary folder as `HOME`, so nothing touched a real home folder or crontab.

- `bash -n` on every script: no syntax errors.
- `backup_script.sh`: a normal run made and verified a backup (exit 0). A missing source exited 1. A second run in the same second refused instead of nesting.
- `advanced_backup.sh`: eight runs with `KEEP=3` left exactly three backups per folder. A decoy file `my notes.txt` and a folder `test_data_keepme` in the same place both survived. A missing source folder exited 1 with a warning.
- `scheduled_backup.sh`: five runs with `MAX_BACKUPS=2` left two per folder. With a source missing, it exited non-zero until the folder existed. Holding the lock made the next run log "another run is still going" and skip. It ran fine under `env -i HOME=... /bin/sh`, which is close to what cron gives a job.
- `file_manager.sh all`: 15 files created, totals `10 text, 2 log, 1 config, 1 backup, 1 other`, files sorted, report correct. `menu </dev/null` exited at once instead of hanging. `clean` refused `/` and `$HOME`.
- `test_cron.sh` under `env -i`: logged `PATH=/usr/bin:/bin`, `PWD=/`, no terminal.
- `cron_monitor.sh` ran through every section on a machine with no cron service and no crontab, and reported that cleanly.

Not tested here: a real cron daemon firing the jobs. Do that on the lab machine with the steps in section 6.

## 10. Takeaway

A script for unattended use is judged by what it does when things go wrong: missing folders, odd filenames, a full disk, two copies running at once, an environment that isn't your terminal. Quote every variable, test commands directly, verify the result, log it, and exit with a code that tells the truth.
