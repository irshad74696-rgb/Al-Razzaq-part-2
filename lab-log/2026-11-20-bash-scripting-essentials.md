# 2026-11-20 · Lab 4: Bash scripting essentials

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Done (scripts tested; a real cron run on my machine and screenshots still to add) |
| **Environment** | Ubuntu Linux, Bash, cron |
| **Lab folder** | [`cybersecurity-fundamentals/lab-4-bash-scripting-essentials/`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/README.md) |

## What the lab covered

Writing Bash scripts with variables, arrays, functions and exit codes. I used `for` and `while` loops, `if` and `case`, and built up from a one-folder backup to a logged, self-pruning backup. Then I scheduled it with cron and wrote a script to check that the scheduled jobs are healthy.

## Commands and configs used

```bash
chmod +x *.sh
./make_test_data.sh && ./backup_script.sh
KEEP=3 ./advanced_backup.sh && tail ~/backup_log.txt
./file_manager.sh all            # create, analyze, organize, report
./scheduled_backup.sh; echo $?   # cron version: own PATH, flock, log file
./cron_monitor.sh

systemctl status cron
crontab -l > ~/crontab.backup
crontab -e                       # 0 2 * * * /home/YOURUSER/scripts/scheduled_backup.sh
```

Scripts: [`backup_script.sh`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/scripts/backup_script.sh), [`advanced_backup.sh`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/scripts/advanced_backup.sh), [`file_manager.sh`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/scripts/file_manager.sh), [`scheduled_backup.sh`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/scripts/scheduled_backup.sh), [`test_cron.sh`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/scripts/test_cron.sh), [`cron_monitor.sh`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/scripts/cron_monitor.sh), [`crontab.example`](../cybersecurity-fundamentals/lab-4-bash-scripting-essentials/scripts/crontab.example).

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| File type counters always 0 | `find \| while read` runs the loop in a subshell | Fed the loop with `< <(find ... -print0)` |
| Cleanup could delete files that weren't backups | Counted everything in the folder with `ls \| wc -l` | Only names matching `<name>_YYYYMMDD_HHMMSS` are pruned |
| Cron jobs would never start | `/home/$USER/...` in crontab, and `USER` is often unset under cron | Full absolute paths |
| Second backup in the same second ended up inside the first | `cp` into an existing folder nests the copy | Refuse when the target name exists; copy to `.partial`, verify, then rename |
| Menu script hung with no keyboard | `while true; read` never sees a quit option | Actions can be run by name, and the menu leaves on end of input |

## Key takeaway

A script for unattended use has to cope with things going wrong. Quote variables, test commands directly, verify the copy, write a log, and exit non-zero when something failed, because under cron nobody is watching the screen.
