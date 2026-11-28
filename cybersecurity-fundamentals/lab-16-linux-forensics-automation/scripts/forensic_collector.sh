#!/usr/bin/env bash
# forensic_collector.sh: collect system, user, process, network and log
# evidence from a live Linux host into one timestamped, hashed folder and archive.
#
# Read-only for the system: it only writes inside FORENSICS_BASE.
#
#   sudo ./forensic_collector.sh                       # collect, hash, archive
#   sudo ./forensic_collector.sh --since "2 days ago"  # wider journal window
#   sudo ./forensic_collector.sh --extra-log /tmp/forensics_lab_sim/test_auth.log
#   ./forensic_collector.sh --base ~/forensics         # without root: partial collection
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'TXT'
Options:
  --base DIR        where to write (default /home/forensics or $FORENSICS_BASE)
  --since TEXT      journal window, as journalctl understands it (default "24 hours ago")
  --extra-log FILE  also copy this auth-style log into logs/auth/extra/ (repeatable)
  --no-archive      leave the folder only, no .tar.gz
  -h, --help        this help
TXT
}

SINCE="24 hours ago"; ARCHIVE=1; EXTRA_LOGS=()
while (( $# )); do
    case "$1" in
        --base) FORENSICS_BASE="${2:?--base needs a folder}"; shift 2 ;;
        --since) SINCE="${2:?--since needs a value}"; shift 2 ;;
        --extra-log) EXTRA_LOGS+=("${2:?--extra-log needs a file}"); shift 2 ;;
        --no-archive) ARCHIVE=0; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done

(( EUID == 0 )) || print_warn "not root: auth logs, other users' open files and firewall rules will be missing"

# Create timestamp and directory
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
COLL_NAME="automated_collection_$TIMESTAMP"
private_dir "$FORENSICS_BASE"
FORENSIC_DIR="$FORENSICS_BASE/$COLL_NAME"
[[ -e "$FORENSIC_DIR" ]] && die "$FORENSIC_DIR already exists"
umask 077
mkdir -p "$FORENSIC_DIR"/{system_info,users,processes,network,logs/system,logs/auth,persistence,files}
LOG="$FORENSIC_DIR/collection_log.tsv"
printf 'time\texit\toutput\tcommand\n' > "$LOG"
START="$(now_iso)"
FAILED=0

print_status "Starting forensic collection - $TIMESTAMP"
print_status "Output: $FORENSIC_DIR"

# capture OUTFILE CMD [ARGS...]: run one command, save stdout, log the exit code.
# A missing tool or a failure is recorded instead of leaving a silent empty file.
capture() {
    local out="$1"; shift
    local rc err
    if ! have "$1"; then
        printf '%s\t%s\t%s\t%s\n' "$(now_iso)" "missing" "$out" "$*" >> "$LOG"
        return 0
    fi
    err="${FORENSIC_DIR:?}/${out:?}.err"
    timeout 120 "$@" > "$FORENSIC_DIR/$out" 2>> "$err"
    rc=$?
    [[ -s "$err" ]] || rm -f -- "$err"
    printf '%s\t%s\t%s\t%s\n' "$(now_iso)" "$rc" "$out" "$*" >> "$LOG"
    (( rc == 0 )) || FAILED=$((FAILED + 1))
    return 0
}

# Copy a file with its timestamps; note it in the log either way.
grab() {  # grab SOURCE DEST_RELATIVE
    if [[ -r "$1" ]]; then
        cp --preserve=timestamps -- "$1" "$FORENSIC_DIR/$2"
        printf '%s\t0\t%s\tcp %s\n' "$(now_iso)" "$2" "$1" >> "$LOG"
    else
        printf '%s\tabsent\t%s\tcp %s\n' "$(now_iso)" "$2" "$1" >> "$LOG"
    fi
}

# --- Most volatile first: processes and network change by the second --------
section "Processes"
capture processes/ps_aux.txt ps aux
capture processes/ps_detailed.txt ps -eo pid,ppid,user,group,lstart,etime,stat,comm,args
capture processes/process_tree.txt pstree -apl
capture processes/processes_by_cpu.txt ps aux --sort=-%cpu
capture processes/processes_by_memory.txt ps aux --sort=-%mem
# Programs deleted from disk while still running are a classic sign of malware.
{
    for exe in /proc/[0-9]*/exe; do
        t="$(readlink -- "$exe" 2>/dev/null)" || continue
        [[ "$t" == *" (deleted)" ]] && printf '%s\t%s\n' "${exe//[!0-9]/}" "$t"
    done
} > "$FORENSIC_DIR/processes/deleted_executables.txt"
capture processes/open_files.txt lsof -nP
print_status "Process information collected"

section "Network"
capture network/connections.txt ss -tunap
capture network/listening_tcp.txt ss -tlnp
capture network/listening_udp.txt ss -ulnp
have netstat && capture network/netstat_an.txt netstat -tunap
capture network/interfaces.txt ip addr show
capture network/routes.txt ip route show
capture network/neighbours.txt ip neigh show
# Firewall state is only listed, never changed.
if (( EUID == 0 )); then
    capture network/iptables.txt iptables -L -n -v --line-numbers
    capture network/nft_ruleset.txt nft list ruleset
    capture network/ufw_status.txt ufw status verbose
fi
print_status "Network information collected"

section "System"
{
    echo "=== SYSTEM INFORMATION ==="
    echo "Hostname:   $(hostname)"
    echo "Kernel:     $(uname -a)"
    echo "OS:         $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
    echo "Uptime:     $(uptime)"
    echo "Booted:     $(uptime -s 2>/dev/null)"
    echo "Date:       $(date '+%Y-%m-%d %H:%M:%S %Z (%z)')"
    echo "Collector:  $(analyst_login) (running as $(id -un))"
} > "$FORENSIC_DIR/system_info/system_overview.txt"
{
    echo "=== HARDWARE INFO ==="
    echo "CPU:"; lscpu 2>/dev/null | head -15
    echo; echo "Memory:"; free -h
    echo; echo "Disk:"; df -h
} > "$FORENSIC_DIR/system_info/hardware_info.txt" 2>&1
capture system_info/mounts.txt findmnt -l
capture system_info/kernel_modules.txt lsmod
print_status "System information collected"

section "Users"
{
    echo "=== LOGGED IN NOW (who) ==="; who
    echo; echo "=== ACTIVITY (w) ==="; w
    echo; echo "=== LAST 50 LOGINS (last) ==="; last -F -n 50 2>/dev/null || echo "wtmp not available"
    echo; echo "=== FAILED LOGINS (lastb) ==="; lastb -F -n 50 2>/dev/null || echo "btmp not readable"
} > "$FORENSIC_DIR/users/user_info.txt" 2>&1
grab /etc/passwd users/passwd.txt
grab /etc/group users/group.txt
# Account status (locked/usable password) without copying /etc/shadow:
# the evidence should not become a second copy of every password hash.
(( EUID == 0 )) && capture users/account_status.txt passwd -S -a
awk -F: '$3 == 0 {print $1}' /etc/passwd > "$FORENSIC_DIR/users/uid0_accounts.txt"
awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1"\t"$3"\t"$6"\t"$7}' /etc/passwd \
    > "$FORENSIC_DIR/users/login_accounts.txt"
admin_users > "$FORENSIC_DIR/users/admins.txt"
print_status "User information collected"

section "Logs"
echo "=== LOG EXTRACTION: $(date) ===" > "$FORENSIC_DIR/logs/extraction_log.txt"
grab /var/log/syslog logs/system/syslog_backup.log
grab /var/log/kern.log logs/system/kernel_backup.log
[[ -r /var/log/syslog ]] && tail -n 1000 /var/log/syslog > "$FORENSIC_DIR/logs/system/recent_syslog.txt"
capture logs/system/journal_since.txt journalctl -q --no-pager -o short-iso --since "$SINCE"
grab /var/log/auth.log logs/auth/auth_backup.log
grab /var/log/auth.log.1 logs/auth/auth_backup.1.log
# One combined authentication stream, from auth.log or from the journal.
A="$FORENSIC_DIR/logs/auth/auth_events.txt"
auth_log "7 days ago" > "$A"
grep -a "Failed password" "$A" > "$FORENSIC_DIR/logs/auth/failed_logins.txt"
grep -aE "Accepted (password|publickey)" "$A" > "$FORENSIC_DIR/logs/auth/successful_logins.txt"
grep -a "sudo:" "$A" > "$FORENSIC_DIR/logs/auth/sudo_usage.txt"
if (( ${#EXTRA_LOGS[@]} )); then
    mkdir -p "$FORENSIC_DIR/logs/auth/extra"
    for f in "${EXTRA_LOGS[@]}"; do
        [[ -r "$f" ]] || { print_warn "extra log not readable: $f"; continue; }
        grab "$f" "logs/auth/extra/$(basename -- "$f")"
        print_status "Included extra log: $f"
    done
fi
{
    echo "Auth source: $([[ -r /var/log/auth.log ]] && echo /var/log/auth.log || echo 'systemd journal')"
    printf 'Lines: %s auth events, %s failed, %s accepted, %s sudo\n' \
        "$(wc -l < "$A")" "$(wc -l < "$FORENSIC_DIR/logs/auth/failed_logins.txt")" \
        "$(wc -l < "$FORENSIC_DIR/logs/auth/successful_logins.txt")" \
        "$(wc -l < "$FORENSIC_DIR/logs/auth/sudo_usage.txt")"
} >> "$FORENSIC_DIR/logs/extraction_log.txt"
[[ -s "$A" ]] || print_warn "no authentication events on this host (no auth.log and an empty journal?)"
print_status "Logs collected"

section "Persistence and files"
{
    for p in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
             /etc/cron.monthly /var/spool/cron/crontabs; do
        [[ -e "$p" ]] && ls -la --time-style=full-iso -- "$p"
    done
} > "$FORENSIC_DIR/persistence/cron_listing.txt" 2>&1
capture persistence/timers.txt systemctl list-timers --all --no-pager
capture persistence/enabled_units.txt systemctl list-unit-files --state=enabled --no-pager
find "${FX_TEMP_DIRS[@]}" -xdev -maxdepth 3 \( -type f -o -type d \) \
    -printf '%y\t%TY-%Tm-%Td %TH:%TM\t%m\t%u\t%s\t%p\n' 2>/dev/null \
    | sort -t$'\t' -k6 > "$FORENSIC_DIR/files/temp_files.txt"
print_status "Persistence and file listings collected"

# --- Summary, hashes, archive -------------------------------------------------
section "Summary"
END="$(now_iso)"
FILES="$(find "$FORENSIC_DIR" -type f | wc -l)"
SIZE="$(du -sh "$FORENSIC_DIR" | cut -f1)"
{
    echo "=== FORENSIC COLLECTION SUMMARY ==="
    echo "Collection:   $COLL_NAME"
    echo "Host:         $(hostname)"
    echo "Collected by: $(analyst_login)"
    echo "Started:      $START"
    echo "Finished:     $END"
    echo "Files:        $FILES"
    echo "Total size:   $SIZE"
    echo "Commands that failed: $FAILED (see collection_log.tsv)"
    echo "Extra logs:   ${EXTRA_LOGS[*]:-none}"
} > "$FORENSIC_DIR/summary.txt"
cat "$FORENSIC_DIR/summary.txt"

# Per-file hashes, so any later change to one file can be detected.
# Written outside the folder first, so the manifest never lists itself.
(cd "$FORENSIC_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum) \
    > "$FORENSIC_DIR.manifest.tmp" && mv -- "$FORENSIC_DIR.manifest.tmp" "$FORENSIC_DIR/MANIFEST.sha256"
print_status "Per-file hashes: $FORENSIC_DIR/MANIFEST.sha256"

if (( ARCHIVE )); then
    ARCH="$FORENSICS_BASE/forensic_collection_$TIMESTAMP.tar.gz"
    tar -C "$FORENSICS_BASE" -czf "$ARCH" "$COLL_NAME"
    (cd "$FORENSICS_BASE" && sha256sum "$(basename -- "$ARCH")" > "$ARCH.sha256")
    chmod 400 "$ARCH" "$ARCH.sha256"
    print_status "Archive: $ARCH"
    print_status "SHA-256: $(cut -d' ' -f1 "$ARCH.sha256")"
fi

print_status "Collection completed: $FORENSIC_DIR"
