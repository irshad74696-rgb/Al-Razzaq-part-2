#!/usr/bin/env bash
# realtime_monitor.sh: watch folders live with inotify and log every change.
#
#   realtime_monitor.sh [--max-events N] [DIR...]     (default DIR: ~/secure_files)
#
# Each event is written to the log as: time <TAB> level <TAB> events <TAB> path
# Level is CRITICAL for deletes, moves out, and the watched folder itself being
# removed or moved; ALERT for everything else.
#
# inotify is instant but only says *what* changed. It cannot say which user or
# program did it. For that, pair it with the auditd rules (see setup_auditd.sh).
#
# Stop with Ctrl+C or kill; the inotifywait child is stopped too.
#
# Environment:
#   FIM_RT_LOG=path      log file (default: <state dir>/realtime_monitor.log)
#   FIM_RT_EXCLUDE=regex paths to ignore, e.g. '\.swp$|~$' for editor temp files
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

have inotifywait || die "inotifywait not found: sudo apt install inotify-tools"

MAX_EVENTS=0
if [[ "${1:-}" == "--max-events" ]]; then
    is_num='^[0-9]+$'
    [[ "${2:-}" =~ $is_num ]] || die "--max-events needs a number"
    MAX_EVENTS="$2"; shift 2
fi
DIRS=("$@")
(( ${#DIRS[@]} )) || DIRS=("$(demo_dir)")
for d in "${DIRS[@]}"; do [[ -d "$d" ]] || die "not a directory: $d"; done

STATE_DIR="$(private_dir "$(fim_state_dir)")"
LOG="${FIM_RT_LOG:-$STATE_DIR/realtime_monitor.log}"
EXCLUDE="${FIM_RT_EXCLUDE:-}"

# close_write fires once when a writer closes the file, instead of "modify"
# firing for every write() call, so a single save gives a single line.
EVENTS="close_write,create,delete,move,attrib,delete_self,move_self"
args=(-m -r -q -e "$EVENTS" --timefmt '%F %T' --format $'%T\t%e\t%w%f')
[[ -n "$EXCLUDE" ]] && args+=(--exclude "$EXCLUDE")

# Run inotifywait on its own file descriptor so we know its PID and can stop it.
# In the starting code it sat in a pipeline, so killing the script left an
# orphaned inotifywait running in the background.
exec {ifd}< <(exec inotifywait "${args[@]}" -- "${DIRS[@]}")
ipid=$!
cleanup() { kill "$ipid" 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

printf '%s\tINFO\tSTART\t%s\n' "$(date '+%F %T')" "${DIRS[*]}" >> "$LOG"
echo "Watching: ${DIRS[*]}"
echo "Log:      $LOG"
echo "Stop with Ctrl+C"

count=0
while IFS=$'\t' read -r -u "$ifd" ts ev path; do
    level=ALERT
    case ",$ev," in
        *,DELETE,*|*,DELETE_SELF,*|*,MOVED_FROM,*|*,MOVE_SELF,*) level=CRITICAL ;;
    esac
    printf '%s\t%s\t%s\t%s\n' "$ts" "$level" "$ev" "$path" >> "$LOG"
    printf '%-8s %s  %-22s %s\n' "$level" "$ts" "$ev" "$path"
    count=$((count + 1))
    if (( MAX_EVENTS > 0 && count >= MAX_EVENTS )); then
        break
    fi
done
