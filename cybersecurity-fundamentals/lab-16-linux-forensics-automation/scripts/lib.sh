#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables here are used by the scripts that source this file
# lib.sh: helpers shared by the forensics scripts. Sourced, never run directly.
#
# Environment overrides (all optional):
#   FORENSICS_BASE=path   where collections, analyses and reports go (default /home/forensics)
#   FX_SIM_DIR=path       where the simulated test activities live (default /tmp/forensics_lab_sim)
#   NO_COLOR=1            plain output

FX_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FORENSICS_BASE="${FORENSICS_BASE:-/home/forensics}"
FX_SIM_DIR="${FX_SIM_DIR:-/tmp/forensics_lab_sim}"
# Every simulated file and log line carries this marker, so cleanup can prove
# it only removes what the lab created.
FX_MARKER="FORENSICS-LAB SIMULATED"

# Watchlists used by both the live detector and the Python analyzer.
FX_SUSPICIOUS_PROCS=(nc netcat ncat socat)
FX_DOWNLOAD_PROCS=(wget curl)
FX_SUSPICIOUS_PORTS=(4444 5555 6666 1234 31337)
FX_FILE_PATTERNS=('*backdoor*' '*malicious*' '*exploit*')
FX_TEMP_DIRS=(/tmp /var/tmp /dev/shm)
FX_ADMIN_GROUPS=(sudo admin wheel)

have() { command -v "$1" >/dev/null 2>&1; }

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_BAD=$'\e[31m'; C_HEAD=$'\e[1m'; C_OFF=$'\e[0m'
else
    C_OK=''; C_WARN=''; C_BAD=''; C_HEAD=''; C_OFF=''
fi

print_status() { printf '%s[INFO]%s %s\n' "$C_OK" "$C_OFF" "$*"; }
print_warn()   { printf '%s[WARN]%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
print_error()  { printf '%s[ERROR]%s %s\n' "$C_BAD" "$C_OFF" "$*" >&2; }
section()      { printf '\n%s== %s ==%s\n' "$C_HEAD" "$*" "$C_OFF"; }
die()          { print_error "$*"; exit 2; }

now_iso() { date '+%Y-%m-%dT%H:%M:%S%z'; }
analyst_login() { echo "${SUDO_USER:-$(id -un)}"; }

# Evidence folders are private: the handout's /home/forensics is created with
# the default umask, so any local user could read the copied auth logs.
private_dir() {
    (umask 077; mkdir -p -- "$1") || die "cannot create $1"
    chmod 700 -- "$1" 2>/dev/null || true
}

# Newest folder under FORENSICS_BASE whose name starts with $1, or nothing.
latest_dir() {
    local prefix="$1" d newest=""
    for d in "$FORENSICS_BASE/$prefix"*/; do
        [[ -d "$d" ]] || continue
        d="${d%/}"
        [[ -z "$newest" || "$d" > "$newest" ]] && newest="$d"
    done
    [[ -n "$newest" ]] && echo "$newest"
}

# Authentication log lines: the file when there is one, the journal otherwise.
# Ubuntu 25.10 keeps auth.log only while rsyslog is installed.
auth_log() {
    local since="${1:-7 days ago}" f
    if [[ -r /var/log/auth.log ]]; then
        for f in /var/log/auth.log.1 /var/log/auth.log; do
            [[ -r "$f" ]] && cat -- "$f"
        done
    elif have journalctl; then
        journalctl -q --no-pager -o short-iso --since "$since" \
            SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 2>/dev/null
    fi
}

in_list() {  # in_list needle item...
    local n="$1" x; shift
    for x in "$@"; do [[ "$x" == "$n" ]] && return 0; done
    return 1
}

# Members of the admin groups, one per line (group members only; primary
# group membership is covered by `id`).
admin_users() {
    local g
    for g in "${FX_ADMIN_GROUPS[@]}"; do
        getent group "$g" | cut -d: -f4 | tr ',' '\n'
    done | sed '/^$/d' | sort -u
    echo root
}

# Findings: one TSV line each. severity <TAB> category <TAB> summary <TAB> evidence
# Tabs and newlines inside fields are flattened: log text is attacker-controlled.
fx_clean() { printf '%s' "$*" | tr '\t\n\r' '   '; }
add_finding() {  # add_finding FILE SEVERITY CATEGORY SUMMARY [EVIDENCE]
    printf '%s\t%s\t%s\t%s\n' "$2" "$3" "$(fx_clean "$4")" "$(fx_clean "${5:-}")" >> "$1"
}

# One remediation line per finding category, used by the detector and the report.
fx_recommendation() {
    case "$1" in
        authentication) echo "  - Block the brute-forcing addresses (ufw deny from <ip>), turn off SSH passwords, add fail2ban, and reset the password of any account that logged in after a brute force." ;;
        process) echo "  - Snapshot each flagged process (/proc/PID/cmdline, fd, exe hash) BEFORE killing it, then stop it and find what started it." ;;
        network) echo "  - Identify the program behind each backdoor-port socket (ss -tlnp), stop it, and check that no firewall rule allows the port." ;;
        file) echo "  - Hash and copy flagged files into the evidence folder, then remove them; check cron and systemd for anything that recreates them." ;;
        privilege) echo "  - Review what the non-admin account ran with sudo and why it was allowed (sudo -l -U <user>, /etc/sudoers.d)." ;;
        account) echo "  - Treat a second UID 0 account as a full compromise: disable it and audit the whole host." ;;
    esac
}
