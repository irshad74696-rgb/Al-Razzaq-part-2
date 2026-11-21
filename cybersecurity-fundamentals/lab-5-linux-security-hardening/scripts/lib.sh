#!/usr/bin/env bash
# lib.sh: helpers shared by the hardening scripts. Sourced, never run directly.
#
# Environment overrides (all optional):
#   SAMPLE_LOG=path   read log lines from this file instead of the systemd journal
#                     (lets every log script be tested without real logs or root)
#   NO_COLOR=1        plain output, no ANSI colours

# Run a command as root: directly if we already are root, through sudo if not.
as_root() {
    if (( EUID == 0 )); then
        "$@"
    elif command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        echo "error: '$1' needs root and sudo is not installed" >&2
        return 1
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_BAD=$'\e[31m'; C_HEAD=$'\e[1m'; C_OFF=$'\e[0m'
else
    C_OK=''; C_WARN=''; C_BAD=''; C_HEAD=''; C_OFF=''
fi

section() { printf '\n%s== %s ==%s\n' "$C_HEAD" "$*" "$C_OFF"; }
ok()      { printf '  %s[ OK ]%s %s\n' "$C_OK" "$C_OFF" "$*"; }
warn()    { printf '  %s[WARN]%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
bad()     { printf '  %s[FAIL]%s %s\n' "$C_BAD" "$C_OFF" "$*"; }
info()    { printf '         %s\n' "$*"; }

# The SSH unit is "ssh" on Debian/Ubuntu and "sshd" on Fedora/RHEL.
ssh_unit() {
    local u
    for u in ssh.service sshd.service; do
        if systemctl list-unit-files "$u" --no-legend 2>/dev/null | grep -q "^$u"; then
            echo "$u"; return 0
        fi
    done
    echo ssh.service
}

# Journal readers. Each takes a --since value such as "1 hour ago".
# Both unit names are passed: journalctl ORs repeated -u options and ignores
# a unit that does not exist, so this works on Ubuntu and on RHEL.
ssh_log() {
    if [[ -n "${SAMPLE_LOG:-}" ]]; then grep -E 'sshd(-session)?\[' -- "$SAMPLE_LOG" || true; return; fi
    as_root journalctl -u ssh.service -u sshd.service --since "$1" --no-pager -q -o short 2>/dev/null || true
}
sudo_log() {
    if [[ -n "${SAMPLE_LOG:-}" ]]; then grep -E ' sudo(\[[0-9]+\])?:' -- "$SAMPLE_LOG" || true; return; fi
    as_root journalctl _COMM=sudo --since "$1" --no-pager -q -o short 2>/dev/null || true
}
kernel_log() {
    if [[ -n "${SAMPLE_LOG:-}" ]]; then grep -E ' kernel: ' -- "$SAMPLE_LOG" || true; return; fi
    as_root journalctl -k --since "$1" --no-pager -q -o short 2>/dev/null || true
}
all_log() {
    if [[ -n "${SAMPLE_LOG:-}" ]]; then cat -- "$SAMPLE_LOG"; return; fi
    as_root journalctl --since "$1" --no-pager -q -o short 2>/dev/null || true
}

# Count lines on stdin that match an extended regex. Always prints a number,
# and never fails, unlike "grep -c" which exits 1 when the count is zero.
count_matches() { grep -cE -- "$1" || true; }

# Pull the source address out of sshd "Failed password ... from IP port N" lines.
# Works for both "for root from" and "for invalid user bob from" forms, which a
# fixed awk column ($11) does not.
extract_ips() { grep -oE 'from [0-9A-Fa-f:.]+ port [0-9]+' | awk '{print $2}'; }

# Is the value a non-negative integer?
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

# Where alert logs go: /var/log when root, otherwise the user's own state dir.
default_log_dir() {
    if (( EUID == 0 )); then echo /var/log; else echo "${XDG_STATE_HOME:-$HOME/.local/state}/security-monitor"; fi
}
