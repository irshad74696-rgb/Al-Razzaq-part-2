#!/usr/bin/env bash
# audit_report.sh: readable summary of what the auditd watches caught.
#
#   audit_report.sh [-t START] [-n LINES] [KEY...]
#
#   -t START   time window for ausearch/aureport: today (default), recent
#              (last 10 minutes), boot, this-week, or "11/23/2026 09:00:00"
#   -n LINES   events to show per key (default 10)
#   KEY        keys to report on (default: every key in config/50-fim.rules,
#              plus secure_files)
#
# For each key it prints the event count and the latest events in plain
# English ("At 09:14 irshadali, acting as root, successfully opened-file
# /etc/shadow using nano"): who, as whom, what file, and which program. That
# "who and which program" is what inotify and hash checks cannot tell you.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

START=today
LINES=10
while getopts ':t:n:' opt; do
    case "$opt" in
        t) START="$OPTARG" ;;
        n) LINES="$OPTARG" ;;
        *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
    esac
done
shift $((OPTIND - 1))
[[ "$LINES" =~ ^[0-9]+$ ]] || die "-n needs a number"
have ausearch || die "ausearch not found: sudo apt install auditd"

KEYS=("$@")
if (( ${#KEYS[@]} == 0 )); then
    mapfile -t KEYS < <(grep -E '^-w' "$FIM_LAB_DIR/config/50-fim.rules" | grep -oE -- '-k [A-Za-z0-9_]+' | awk '{print $2}' | sort -u)
    KEYS+=(secure_files)
fi

# ausearch accepts "-ts today" but a date and a time are two arguments.
read -r -a TS <<< "$START"

# ausearch exits 1 and prints "<no matches>" when nothing matched; that is a
# normal answer here, not an error.
search() { as_root ausearch -ts "${TS[@]}" "$@" 2>/dev/null || true; }

echo "File integrity audit report - $(hostname) - $(date -Is)"
echo "Window: $START"

section "Events per key"
printf '  %-14s %s\n' KEY EVENTS
total=0
declare -A counts=()
for k in "${KEYS[@]}"; do
    # One SYSCALL record per event in raw output.
    n="$(search -k "$k" --raw | grep -c '^type=SYSCALL' || true)"
    counts["$k"]=$n
    total=$((total + n))
    printf '  %-14s %s\n' "$k" "$n"
done
printf '  %-14s %s\n' TOTAL "$total"

for k in "${KEYS[@]}"; do
    (( counts[$k] > 0 )) || continue
    section "Latest $LINES for key: $k"
    # --format text needs audit 2.6 or newer (Ubuntu 20.04 and later have it).
    # Rule loads and removals carry the key too; they are listed separately below.
    search -k "$k" --format text | grep -vE ' (add|remove)_rule ' | tail -n "$LINES" | sed 's/^/  /' || true
done

section "Audit rule changes (rules added or removed)"
search -m CONFIG_CHANGE --format text | grep -E ' (add|remove)_rule ' | awk '{
    who = $4; sub(/,$/, "", who); act = $9; key = $10
    n[act " " key " by " who]++
} END { for (x in n) printf "  %4d x %s\n", n[x], x }' | sort -k3 || true

section "Failed file access (permission denied)"
if have aureport; then
    as_root aureport -f --failed -i -ts "${TS[@]}" 2>/dev/null | tail -n +6 | tail -n "$LINES" | sed 's/^/  /' || true
fi

section "Authentication summary"
if have aureport; then
    as_root aureport -au -i -ts "${TS[@]}" --summary 2>/dev/null | sed 's/^/  /' || true
fi

section "Audit health"
as_root auditctl -s 2>/dev/null | grep -E '^(enabled|lost|backlog) ' | sed 's/^/  /' || true
