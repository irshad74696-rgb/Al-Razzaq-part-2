#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables here are used by the scripts that source this file
# lib.sh: helpers shared by the incident response scripts.
# Sourced, never run directly.
#
# Environment overrides (all optional):
#   IR_STATE_DIR=path   case folder: findings, timeline, evidence, reports
#   IR_IP=addr          suspicious IP (default 203.0.113.66, a documentation address)
#   IR_USER=name        unauthorised account (default hacker)
#   IR_BEACON_SECONDS=n seconds between simulated beacon attempts (default 30)
#   NO_COLOR=1          plain output

IR_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IR_IP="${IR_IP:-203.0.113.66}"
IR_USER="${IR_USER:-hacker}"
IR_PORT="${IR_PORT:-4444}"
# Written into the GECOS field of the simulated account. Cleanup only deletes
# an account that carries it, so it can never remove a real user by mistake.
IR_MARKER="IR-LAB simulated account"
# iptables comment on every rule these scripts add, so removal is exact.
IR_RULE_TAG="ir-lab"
IR_LEGACY_PIDFILE=/tmp/simulated_pid.txt
IR_HIDDEN_LOG=/tmp/.hidden_log

have() { command -v "$1" >/dev/null 2>&1; }

as_root() {
    if (( EUID == 0 )); then
        "$@"
    elif have sudo; then
        sudo "$@"
    else
        echo "error: '$1' needs root and sudo is not installed" >&2
        return 1
    fi
}

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
die()     { echo "error: $*" >&2; exit 2; }

need_root() {
    (( EUID == 0 )) || die "run this as root: sudo $0"
}

now_iso() { date '+%Y-%m-%d %H:%M:%S %z'; }

# The person running the script, even under sudo.
analyst_login() { echo "${SUDO_USER:-$(id -un)}"; }

# Case folder. Root uses /var/lib/ir-lab (mode 700), not /tmp: evidence in a
# world-readable folder can be read or swapped by any local user.
ir_state_dir() {
    if [[ -n "${IR_STATE_DIR:-}" ]]; then
        echo "$IR_STATE_DIR"
    elif (( EUID == 0 )); then
        echo /var/lib/ir-lab
    else
        echo "${XDG_STATE_HOME:-$HOME/.local/state}/ir-lab"
    fi
}

private_dir() {
    local d="$1"
    (umask 077; mkdir -p -- "$d") || die "cannot create $d"
    chmod 700 -- "$d" 2>/dev/null || true
    echo "$d"
}

ir_init() {
    IR_STATE="$(private_dir "$(ir_state_dir)")"
    IR_TIMELINE="$IR_STATE/timeline.tsv"
    IR_PIDFILE="$IR_STATE/simulated.pid"
    if [[ ! -e "$IR_TIMELINE" ]]; then
        (umask 077; printf 'time\tphase\tanalyst\tevent\n' > "$IR_TIMELINE")
    fi
}

# Every action goes into the case timeline: the report is built from it.
log_event() {
    local phase="$1"; shift
    printf '%s\t%s\t%s\t%s\n' "$(now_iso)" "$phase" "$(analyst_login)" "$*" >> "$IR_TIMELINE"
}

# Run a command, or only show it in dry-run mode (DRY_RUN=1).
run() {
    if [[ "${DRY_RUN:-1}" == 1 ]]; then
        printf '  would run: %s\n' "$*"
    else
        printf '  + %s\n' "$*"
        "$@"
    fi
}

# Running and not a zombie. A killed process whose parent has not collected
# its exit status yet still answers kill -0, but it is already dead.
is_alive() {
    local st
    st="$(ps -o stat= -p "$1" 2>/dev/null)" || return 1
    [[ -n "$st" && "$st" != Z* ]]
}

# All descendants of a PID (children, grandchildren, ...), parents first.
# Killing only direct children leaves grandchildren running: here, the bash
# that `timeout` starts would keep beaconing after the loop was killed.
descendants() {
    local c
    for c in $(pgrep -P "$1"); do
        echo "$c"
        descendants "$c"
    done
}

is_ipv4() {
    local ip="$1" o
    [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}

is_private_ipv4() {
    [[ "$1" =~ ^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.) ]]
}

# The exact rule specs. Adding, checking and removing all use the same list,
# so cleanup deletes only these rules and never flushes a chain.
fw_specs() {
    local ip="$1"
    printf '%s\n' \
        "OUTPUT -d $ip/32 -m comment --comment $IR_RULE_TAG -j DROP" \
        "INPUT -s $ip/32 -m comment --comment $IR_RULE_TAG -j DROP"
}
# The untagged rules the lab handout adds by hand, so cleanup finds them too.
fw_specs_manual() {
    local ip="$1"
    printf '%s\n' "OUTPUT -d $ip/32 -j DROP" "INPUT -s $ip/32 -j DROP"
}

# Accounts that must never be locked or deleted without --force.
is_protected_user() {
    local u="$1" g
    [[ "$u" == root ]] && return 0
    [[ "$u" == "$(analyst_login)" ]] && return 0
    [[ -n "${SUDO_USER:-}" && "$u" == "$SUDO_USER" ]] && return 0
    for g in sudo admin wheel; do
        id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$g" && return 0
    done
    return 1
}

user_has_marker() {
    getent passwd "$1" | cut -d: -f5 | grep -qF "$IR_MARKER"
}

# Read authentication logs from the file when there is one, from the journal
# otherwise (recent Ubuntu releases may have no rsyslog and no auth.log).
auth_log() {
    local since="${1:-7 days ago}"
    if [[ -r /var/log/auth.log ]]; then
        cat /var/log/auth.log
    elif have journalctl; then
        journalctl -q --no-pager -o short-iso --since "$since" \
            SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 2>/dev/null
    fi
}
