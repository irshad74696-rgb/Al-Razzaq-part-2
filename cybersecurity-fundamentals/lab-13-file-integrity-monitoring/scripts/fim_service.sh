#!/usr/bin/env bash
# fim_service.sh: run the integrity check on a loop in the background.
#
#   fim_service.sh start [SECONDS]   start; check every SECONDS (default 300)
#   fim_service.sh stop              stop the loop and anything it started
#   fim_service.sh status            running or not, plus the last log lines
#   fim_service.sh once              one check now, in the foreground
#
# Each round runs file_integrity_checker.sh --scan and, if anything changed,
# writes an ALERT line to the service log and to syslog (logger -t fim).
#
# This is the lab's "service" made safe to start and stop. For a real machine
# prefer the systemd timer in config/ (see README): it survives reboots and
# logouts, and systemd keeps the logs.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

STATE_DIR="$(private_dir "$(fim_state_dir)")"
LOG="$STATE_DIR/fim_service.log"
PID_FILE="$STATE_DIR/fim_service.pid"
CHECKER="$FIM_SCRIPT_DIR/file_integrity_checker.sh"

log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >> "$LOG"; }

running_pid() {
    local pid
    [[ -f "$PID_FILE" ]] || return 1
    pid="$(cat -- "$PID_FILE")"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        echo "$pid"
    else
        rm -f -- "$PID_FILE"     # stale: the process died without cleaning up
        return 1
    fi
}

one_round() {
    local out rc=0
    out="$("$CHECKER" --scan 2>&1)" || rc=$?
    case "$rc" in
        0) log "OK no changes" ;;
        1) log "ALERT changes detected"
           grep -E '^  (MODIFIED|PERMS|OWNER|DELETED|NEW) ' <<< "$out" >> "$LOG" || true
           if have logger; then
               logger -t fim -p auth.warning "file integrity changes detected, see $LOG" || true
           fi ;;
        *) log "ERROR checker exit $rc: $(head -1 <<< "$out")" ;;
    esac
    return 0
}

start() {
    local interval="${1:-300}" pid
    [[ "$interval" =~ ^[0-9]+$ && "$interval" -ge 10 ]] || die "interval must be a number of seconds, 10 or more"
    if pid="$(running_pid)"; then
        echo "already running (PID $pid)"; return 0
    fi
    log "START interval=${interval}s"
    # setsid puts the loop in its own process group, so stop can end the loop
    # *and* its current sleep or scan. The starting code killed only the
    # subshell PID, leaving the running sleep (and scan) behind.
    # shellcheck disable=SC2016  # $0 and $1 belong to the inner bash
    setsid bash -c '
        trap "exit 0" TERM
        while true; do
            "$0" once
            sleep "$1" & wait $!
        done
    ' "$0" "$interval" </dev/null >/dev/null 2>&1 &
    echo $! > "$PID_FILE"
    echo "started (PID $(cat -- "$PID_FILE")), checking every ${interval}s"
    echo "log: $LOG"
}

stop() {
    local pid
    if ! pid="$(running_pid)"; then
        echo "not running"; return 0
    fi
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    rm -f -- "$PID_FILE"
    log "STOP"
    echo "stopped (PID $pid)"
}

status() {
    local pid
    if pid="$(running_pid)"; then
        echo "running (PID $pid)"
    else
        echo "not running"
    fi
    echo "log: $LOG"
    [[ -f "$LOG" ]] && tail -n 8 -- "$LOG"
    return 0
}

case "${1:-}" in
    start)  start "${2:-300}" ;;
    stop)   stop ;;
    status) status ;;
    once)   one_round ;;
    restart) stop; start "${2:-300}" ;;
    *) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
