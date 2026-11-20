#!/usr/bin/env bash
# cron_monitor.sh: one screen showing whether scheduled backups are healthy.
# Read-only: it lists and reports, it never changes the crontab or deletes anything.
set -uo pipefail

BACKUP_BASE="${BACKUP_BASE:-$HOME/scheduled_backups}"
LOG_FILE="${LOG_FILE:-$HOME/cron_backup.log}"

section() { printf '\n%s\n%s\n' "$1" "${1//?/-}"; }

echo "Cron and backup status for $(id -un) on $(hostname) at $(date '+%F %T')"

section "Scheduled jobs"
if jobs=$(crontab -l 2>/dev/null); then
    grep -Ev '^[[:space:]]*(#|$)' <<<"$jobs" || echo "crontab exists but has no active lines"
else
    echo "no crontab for $(id -un)"
fi

section "Cron service"
# Debian and Ubuntu call the unit cron; RHEL, Fedora and CentOS call it crond.
found=""
for unit in cron crond; do
    if systemctl list-unit-files "$unit.service" 2>/dev/null | grep -q "^$unit\.service"; then
        found=$unit
        if systemctl is-active --quiet "$unit"; then echo "OK   $unit is running"
        else echo "FAIL $unit is installed but not running"; fi
    fi
done
[[ -n "$found" ]] || echo "no cron service found (or systemd not available here)"

section "Recent cron activity"
if [[ -n "$found" ]] && command -v journalctl >/dev/null && journalctl -u "$found" -n 1 >/dev/null 2>&1; then
    journalctl -u "$found" -n 10 --no-pager 2>/dev/null
elif [[ -r /var/log/cron ]]; then
    tail -n 10 /var/log/cron
elif [[ -r /var/log/syslog ]]; then
    grep -i cron /var/log/syslog | tail -n 10
else
    echo "no readable cron log (try: sudo journalctl -u cron)"
fi

section "Backup log"
if [[ -s "$LOG_FILE" ]]; then
    tail -n 5 "$LOG_FILE"
    if tail -n 20 "$LOG_FILE" | grep -q FAILED; then echo "WARNING: failures in recent runs"; fi
else
    echo "no backup log yet at $LOG_FILE"
fi

section "Backups on disk"
if [[ -d "$BACKUP_BASE" ]]; then
    count=$(find "$BACKUP_BASE" -mindepth 1 -maxdepth 1 -type d | wc -l)
    echo "$count backup folder(s) in $BACKUP_BASE, $(du -sh -- "$BACKUP_BASE" | cut -f1) in total"
    # Sort on the timestamp at the end of each name (cp -a keeps the source's
    # modification time, so the folder's own mtime says nothing about the backup).
    find "$BACKUP_BASE" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' |
        sed -nE 's/^(.*_([0-9]{8}_[0-9]{6}))$/\2 \1/p' | sort | tail -n 5 |
        cut -d' ' -f2- | sed 's/^/  recent: /'
else
    echo "no backup folder yet at $BACKUP_BASE"
fi

section "Disk space"
df -h -- "$HOME" | awk 'NR==2 {print $4 " free of " $2 " (" $5 " used) on " $6}'
