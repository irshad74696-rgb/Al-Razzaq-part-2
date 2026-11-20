# 2026-10-19 · Scheduling jobs with systemd timers

| | |
| --- | --- |
| **Track** | Linux |
| **Status** | In progress (results not recorded yet) |
| **Environment** | Ubuntu 25.10, systemd |

> Backfilled entry. I started this lab but did not save the output, so the results below still need filling in.

## What the lab covered

Using systemd timers as a replacement for cron: a `oneshot` service that does the work, a `.timer` unit that schedules it, calendar expressions, `Persistent=true` for runs missed while the machine was off, and `RandomizedDelaySec` to spread load.

## Commands and configs used

```ini
# /etc/systemd/system/maintenance.service
[Unit]
Description=Example maintenance job

[Service]
Type=oneshot
# systemd does not run ExecStart through a shell, so redirection needs bash -c
ExecStart=/bin/bash -c 'echo "maintenance ran at $(date)" >> /var/log/maintenance.log'
```

```ini
# /etc/systemd/system/maintenance.timer
[Unit]
Description=Run the maintenance job daily

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now maintenance.timer
systemctl list-timers                        # next and last run
systemctl start maintenance.service          # run once now instead of waiting a day
journalctl -u maintenance.service
systemd-analyze calendar "Mon *-*-* 02:00:00" --iterations=3
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| A plain `ExecStart=/usr/bin/echo ... >> file` writes nothing to the log | systemd passes `>>` and `$(date)` to echo as literal text | Wrap the command in `/bin/bash -c '...'` |

_To do: add my own output from `systemctl list-timers` and the log file._

## Key takeaway

Timers give every run a journal entry and catch up on missed runs, which makes them easier to audit than cron.

## Screenshots

None captured yet.
