#!/usr/bin/env bash
# lib.sh: helpers shared by the file integrity monitoring scripts.
# Sourced, never run directly.
#
# Environment overrides (all optional):
#   FIM_STATE_DIR=path   where baselines, reports and logs are kept
#   NO_COLOR=1           plain output, no ANSI colours

# Folder that holds these scripts, so they can call each other from anywhere
# (the starting code used ./other_script.sh, which only works from one folder).
FIM_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC2034  # used by the scripts that source this file
FIM_LAB_DIR="$(dirname -- "$FIM_SCRIPT_DIR")"

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
die()     { echo "error: $*" >&2; exit 2; }

# Where baselines and reports live. Root uses /var/lib/fim; a normal user gets
# a private folder under ~/.local/state. Never inside a monitored folder, or
# writing the report would itself show up as a change.
fim_state_dir() {
    if [[ -n "${FIM_STATE_DIR:-}" ]]; then
        echo "$FIM_STATE_DIR"
    elif (( EUID == 0 )); then
        echo /var/lib/fim
    else
        echo "${XDG_STATE_HOME:-$HOME/.local/state}/fim"
    fi
}

# Create a private folder (mode 700) and print its path.
private_dir() {
    local d="$1"
    (umask 077; mkdir -p -- "$d") || die "cannot create $d"
    chmod 700 -- "$d" 2>/dev/null || true
    echo "$d"
}

# The demo folder from the lab. $HOME, not /home/$USER: under sudo or cron
# $USER can be root or empty, and root's home is /root, not /home/root.
demo_dir() { echo "${FIM_DEMO_DIR:-$HOME/secure_files}"; }
