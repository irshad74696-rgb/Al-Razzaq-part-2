#!/usr/bin/env bash
# backup_script.sh: copy one folder into a timestamped backup folder.
#
#   ./backup_script.sh                         -> backs up ~/test_data into ~/backups
#   SOURCE_DIR=~/notes ./backup_script.sh      -> back up a different folder
#   BACKUP_DIR=/mnt/usb ./backup_script.sh     -> store backups somewhere else
#
# Exit codes: 0 = backup made and verified, 1 = something failed.
set -uo pipefail

SOURCE_DIR="${SOURCE_DIR:-$HOME/test_data}"
BACKUP_DIR="${BACKUP_DIR:-$HOME/backups}"
STAMP="$(date +%Y%m%d_%H%M%S)"
DEST="$BACKUP_DIR/backup_$STAMP"

if [[ ! -d "$SOURCE_DIR" ]]; then
    echo "Error: source folder '$SOURCE_DIR' does not exist" >&2
    exit 1
fi

if [[ -e "$DEST" ]]; then
    echo "Error: '$DEST' already exists, wait a second and run again" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR" || { echo "Error: cannot create '$BACKUP_DIR'" >&2; exit 1; }

echo "Backing up $SOURCE_DIR"
echo "        to $DEST"

# Test the command itself instead of looking at $? afterwards: $? only ever
# holds the status of the very last command, so it is easy to check the wrong one.
if ! cp -a -- "$SOURCE_DIR" "$DEST"; then
    echo "Backup failed while copying" >&2
    exit 1
fi

# A copy that "succeeded" is not proof. Compare the two trees.
if ! diff -rq -- "$SOURCE_DIR" "$DEST" >/dev/null; then
    echo "Backup copied but does not match the source" >&2
    exit 1
fi

echo "Backup complete and verified: $(du -sh -- "$DEST" | cut -f1), $(find "$DEST" -type f | wc -l) files"
