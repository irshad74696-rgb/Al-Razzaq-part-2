#!/usr/bin/env bash
# scheduled_backup.sh: a backup built to run unattended from cron.
#
# What makes it cron-safe:
#   - sets its own PATH, because cron starts jobs with a very short one
#   - uses only absolute paths and never depends on the current folder
#   - writes everything to a log file, because nobody sees cron's output
#   - takes a lock, so a slow run is never overlapped by the next one
#   - exits non-zero on failure, so monitoring can notice
#
#   ./scheduled_backup.sh                  -> run it by hand first, then check the log
#   MAX_BACKUPS=3 ./scheduled_backup.sh    -> keep 3 per folder (default 7)
set -uo pipefail
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077                                      # backups readable by the owner only

SOURCES=("$HOME/test_data" "$HOME/scripts" "$HOME/Documents")
BACKUP_BASE="${BACKUP_BASE:-$HOME/scheduled_backups}"
LOG_FILE="${LOG_FILE:-$HOME/cron_backup.log}"
STATUS_FILE="${STATUS_FILE:-$HOME/last_backup_status.txt}"
MAX_BACKUPS="${MAX_BACKUPS:-7}"
STAMP="$(date +%Y%m%d_%H%M%S)"

log() { printf '%s [scheduled-backup] %s\n' "$(date '+%F %T')" "$*" >> "$LOG_FILE"; }

mkdir -p "$BACKUP_BASE" || exit 1

# One run at a time. flock gives up at once if another run holds the lock.
exec 9> "$BACKUP_BASE/.lock"
if ! flock -n 9; then
    log "another run is still going, skipping this one"
    exit 0
fi

log "run started"
ok=0
present=0

for src in "${SOURCES[@]}"; do
    if [[ ! -d "$src" ]]; then
        log "skip: $src does not exist"
        continue
    fi
    present=$((present + 1))
    name="$(basename -- "$src")"
    dest="$BACKUP_BASE/${name}_${STAMP}"

    if [[ -e "$dest" ]]; then
        log "FAILED: $dest already exists, not overwriting it"
        continue
    fi
    # Copy under a temporary name, verify, then rename into place.
    if cp -a -- "$src" "$dest.partial" 2>>"$LOG_FILE" &&
       diff -rq -- "$src" "$dest.partial" >/dev/null 2>&1 &&
       mv -T -- "$dest.partial" "$dest"; then
        log "ok: $src -> $(basename -- "$dest") ($(du -sh -- "$dest" | cut -f1))"
        ok=$((ok + 1))
    else
        log "FAILED: $src"
        rm -rf -- "$dest.partial"
        continue
    fi

    # Retention: only folders named exactly <name>_YYYYMMDD_HHMMSS are candidates.
    shopt -s nullglob
    old=("$BACKUP_BASE/${name}"_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9])
    shopt -u nullglob
    extra=$(( ${#old[@]} - MAX_BACKUPS ))
    for (( i = 0; i < extra; i++ )); do
        [[ -d "${old[i]}" ]] && rm -rf -- "${old[i]}" && log "pruned: $(basename -- "${old[i]}")"
    done
done

summary="$ok of $present folder(s) backed up at $(date '+%F %T')"
log "run finished: $summary"
echo "$summary" > "$STATUS_FILE"

# Success only if every folder that exists was backed up.
(( present > 0 && ok == present ))
