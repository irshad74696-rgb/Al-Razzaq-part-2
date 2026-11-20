#!/usr/bin/env bash
# advanced_backup.sh: back up several folders, log every step, keep the newest N.
#
#   ./advanced_backup.sh                      -> folders listed in SOURCES below
#   ./advanced_backup.sh ~/notes ~/projects   -> back up these instead
#   KEEP=3 ./advanced_backup.sh               -> keep 3 backups per folder (default 5)
#
# Each backup is named <folder>_YYYYMMDD_HHMMSS. Retention only ever touches
# folders that match that exact pattern, so nothing else in BACKUP_DIR is at risk.
set -uo pipefail

BACKUP_DIR="${BACKUP_DIR:-$HOME/backups}"
LOG_FILE="${LOG_FILE:-$HOME/backup_log.txt}"
KEEP="${KEEP:-5}"
MIN_FREE_MB="${MIN_FREE_MB:-100}"
STAMP="$(date +%Y%m%d_%H%M%S)"

if (( $# > 0 )); then
    SOURCES=("$@")
else
    SOURCES=("$HOME/test_data" "$HOME/scripts")
fi

log() {
    printf '%s [%s] %s\n' "$(date '+%F %T')" "$1" "$2" | tee -a "$LOG_FILE"
}

free_space_ok() {
    local free_mb
    free_mb=$(df -Pm -- "$BACKUP_DIR" | awk 'NR==2 {print $4}')
    if (( free_mb < MIN_FREE_MB )); then
        log ERROR "only ${free_mb} MB free in $BACKUP_DIR, need ${MIN_FREE_MB} MB"
        return 1
    fi
    log INFO "disk check passed: ${free_mb} MB free"
}

backup_one() {
    local src="$1" name dest files
    name="$(basename -- "$src")"
    dest="$BACKUP_DIR/${name}_${STAMP}"

    if [[ ! -d "$src" ]]; then
        log WARN "skipping $src: not a folder"
        return 1
    fi

    # Two runs in the same second would aim at the same name. cp -a into an
    # existing folder nests the copy inside it, so refuse instead of overwriting.
    if [[ -e "$dest" ]]; then
        log ERROR "$dest already exists, not overwriting it"
        return 1
    fi

    files=$(find "$src" -type f | wc -l)
    log INFO "backing up $files file(s) from $src"

    # Copy to a .partial name first and rename only once it verifies, so a
    # half-finished copy never looks like a real backup.
    if cp -a -- "$src" "$dest.partial" && diff -rq -- "$src" "$dest.partial" >/dev/null &&
       mv -T -- "$dest.partial" "$dest"; then
        log OK "$src -> $dest ($(du -sh -- "$dest" | cut -f1))"
    else
        log ERROR "backup of $src failed or did not verify"
        rm -rf -- "$dest.partial"
        return 1
    fi
}

# Delete all but the newest $KEEP backups of one folder.
# The timestamp in the name sorts correctly as text, so no `ls -t` parsing is needed,
# and a glob handles names with spaces safely.
prune() {
    local name="$1" old
    local -a backups=()
    shopt -s nullglob
    backups=("$BACKUP_DIR/${name}"_[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]_[0-9][0-9][0-9][0-9][0-9][0-9])
    shopt -u nullglob

    local count=${#backups[@]}
    if (( count <= KEEP )); then
        log INFO "$name: $count backup(s), within the limit of $KEEP"
        return
    fi
    # Glob results come back sorted, oldest first.
    for old in "${backups[@]:0:count-KEEP}"; do
        [[ -d "$old" ]] || continue
        rm -rf -- "$old" && log INFO "removed old backup $(basename -- "$old")"
    done
}

mkdir -p "$BACKUP_DIR" || { echo "cannot create $BACKUP_DIR" >&2; exit 1; }
log INFO "backup run started ($STAMP)"
free_space_ok || exit 1

ok=0
failed=0
for src in "${SOURCES[@]}"; do
    # ((ok++)) returns status 1 when ok is 0, which would kill a script running
    # under `set -e`. Plain arithmetic assignment avoids that trap.
    if backup_one "$src"; then
        ok=$((ok + 1))
        prune "$(basename -- "$src")"
    else
        failed=$((failed + 1))
    fi
done

log INFO "finished: $ok succeeded, $failed failed"
(( failed == 0 ))
