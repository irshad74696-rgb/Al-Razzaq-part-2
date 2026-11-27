#!/usr/bin/env bash
# shellcheck disable=SC2016  # the bash -c '...' snippets are expanded by the inner shell on purpose
# collect_evidence.sh: forensic collection with SHA-256 integrity and a
# chain-of-custody record.
#
#   sudo ./collect_evidence.sh [--pid PID] [-d DAYS] [-o FOLDER]
#   sudo ./collect_evidence.sh --verify ARCHIVE.tar.gz
#
# Collects in order of volatility (most short-lived first): clock, processes,
# network, firewall, sessions, accounts, logs, then files on disk. Each file
# gets a SHA-256 in MANIFEST.sha256 inside the archive; the archive itself is
# hashed into evidence_hashes.txt and chain_of_custody.txt in the case folder.
#
# Differences from the handout's script, and why:
#   - evidence goes to a mode-700 case folder, not world-readable /tmp
#   - one failing command (no netstat, no auth.log, no wtmp) is logged and the
#     collection carries on, instead of silently leaving an empty file
#   - tar uses -C, so the archive holds relative paths only
#   - the archive is hashed by its exact name; `sha256sum /tmp/ir_collection_*`
#     hashes every old archive too and the "one line" stops being one line
#   - account status is collected with passwd -S; /etc/shadow hashes are not
#     copied, because evidence should not become a second copy of secrets
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

PID=""; DAYS=1; OUT=""; VERIFY=""
while (( $# )); do
    case "$1" in
        --pid) PID="${2:?}"; shift ;;
        -d) DAYS="${2:?}"; shift ;;
        -o) OUT="${2:?}"; shift ;;
        --verify) VERIFY="${2:?}"; shift ;;
        -h|--help) sed -n '2,23p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done
[[ "$DAYS" =~ ^[0-9]+$ ]] || die "-d needs a whole number of days"
ir_init

# ---------------------------------------------------------------- verify mode
if [[ -n "$VERIFY" ]]; then
    [[ -f "$VERIFY" ]] || die "no such archive: $VERIFY"
    want="$(grep -F "  $(basename -- "$VERIFY")" "$IR_STATE/evidence_hashes.txt" 2>/dev/null | tail -1 | awk '{print $1}')"
    [[ -n "$want" ]] || die "$(basename -- "$VERIFY") is not recorded in $IR_STATE/evidence_hashes.txt"
    got="$(sha256sum -- "$VERIFY" | awk '{print $1}')"
    if [[ "$got" == "$want" ]]; then
        ok "archive hash matches the recorded value: $got"
        log_event evidence "Verified $(basename -- "$VERIFY"): hash matches"
        exit 0
    fi
    bad "HASH MISMATCH: recorded $want, now $got"
    log_event evidence "Verified $(basename -- "$VERIFY"): HASH MISMATCH"
    exit 1
fi

need_root
[[ -z "$PID" && -s "$IR_PIDFILE" ]] && PID="$(cat "$IR_PIDFILE")"
BASE="$(private_dir "${OUT:-$IR_STATE/evidence}")"
TS="$(date +%Y%m%d_%H%M%S)"
NAME="ir_collection_$(hostname -s)_${TS}"
DIR="$(private_dir "$BASE/$NAME")"
LOG="$DIR/collection_log.tsv"
printf 'time\texit\tfile\tcommand\n' > "$LOG"
umask 077

# capture FILE COMMAND...   run one command into one file, never abort
capture() {
    local file="$1"; shift
    "$@" > "$DIR/$file" 2>> "$DIR/errors.txt"
    local rc=$?
    printf '%s\t%s\t%s\t%s\n' "$(date '+%H:%M:%S')" "$rc" "$file" "$*" >> "$LOG"
    (( rc == 0 )) || printf '  [%s] exit %s: %s\n' "$file" "$rc" "$*"
}
capture_if() { have "$2" && capture "$@" || printf '%s\t-\t%s\tskipped: %s not installed\n' "$(date '+%H:%M:%S')" "$1" "$2" >> "$LOG"; }

echo "Starting forensic data collection..."
log_event evidence "Collection $NAME started"

# 1. clock and system: so every other timestamp can be related to real time
capture system_info.txt bash -c 'date; date -u; echo; uname -a; hostname -f 2>/dev/null || hostname; uptime; echo; cat /etc/os-release'
capture_if timedatectl.txt timedatectl

# 2. processes
capture processes_tree.txt ps auxf
capture processes_detail.txt ps -eo pid,ppid,user,lstart,etime,%cpu,%mem,stat,cmd --sort=pid
if [[ -n "$PID" ]] && is_alive "$PID"; then
    capture "pid_${PID}.txt" bash -c "ps -o pid,ppid,user,lstart,cmd -p $PID; echo; echo exe: \$(readlink /proc/$PID/exe); echo cwd: \$(readlink /proc/$PID/cwd); echo; ls -l /proc/$PID/fd; echo; echo exe sha256: \$(sha256sum < /proc/$PID/exe)"
fi

# 3. network
capture_if network_ss_all.txt ss -tanp
capture_if listening_ports.txt ss -tulpn
capture_if network_connections.txt netstat -antp
capture_if ip_addr.txt ip addr
capture_if ip_route.txt ip route
capture_if ip_neigh.txt ip neigh
capture_if iptables_rules.txt iptables-save

# 4. sessions and logins
capture logged_in_users.txt bash -c 'who; echo; w'
capture_if recent_logins.txt last -20 -F
capture_if failed_logins.txt lastb -20 -F
capture_if lastlog.txt lastlog

# 5. accounts (no password hashes)
capture passwd.txt cat /etc/passwd
capture group.txt cat /etc/group
capture account_status.txt passwd -S -a
capture sudoers.txt bash -c 'cat /etc/sudoers; for f in /etc/sudoers.d/*; do echo "== $f"; cat "$f"; done'

# 6. logs
mkdir -p "$DIR/logs"
for f in /var/log/auth.log /var/log/auth.log.1 /var/log/syslog /var/log/kern.log; do
    [[ -r "$f" ]] && cp -p -- "$f" "$DIR/logs/" 2>> "$DIR/errors.txt"
done
if have journalctl; then
    capture logs/journal_auth.txt journalctl -q --no-pager -o short-iso --since "$DAYS days ago" SYSLOG_FACILITY=4 SYSLOG_FACILITY=10
    capture logs/journal_errors.txt journalctl -q --no-pager -o short-iso --since "$DAYS days ago" -p err
fi
capture logs/dmesg.txt dmesg -T
capture shell_history_suspicious.txt bash -c 'for h in /root/.bash_history /home/*/.bash_history; do [ -r "$h" ] && grep -HnE "\b(wget|curl|nc|ncat|nmap|base64|chmod \+x|/dev/tcp)\b" "$h"; done; true'

# 7. persistence
capture cron.txt bash -c 'cat /etc/crontab; ls -la /etc/cron.*; for f in /var/spool/cron/crontabs/*; do [ -f "$f" ] && { echo "== $f"; cat "$f"; }; done; true'
capture_if systemd_units.txt systemctl list-units --type=service --all --no-pager
capture systemd_local_units.txt find /etc/systemd/system -xdev -type f -printf '%TY-%Tm-%Td %TH:%TM %u %m %p\n'

# 8. files on disk (slowest, least volatile)
capture hidden_temp_files.txt find /tmp /var/tmp /dev/shm -xdev -name '.*' -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS %u %s %p\n'
capture recent_home_changes.txt find /home /root -xdev -type f -mtime "-$DAYS" -ls
capture recent_etc_changes.txt find /etc -xdev -type f -mtime "-$DAYS" -ls
capture recent_scripts.txt find / -xdev -name '*.sh' -type f -mtime "-$DAYS" -not -path '/proc/*'
capture suid_files.txt find / -xdev -perm -4000 -type f -ls

# 9. the case timeline so far
cp -- "$IR_TIMELINE" "$DIR/case_timeline.tsv"

# hash every file, then archive and hash the archive
(cd "$DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum > "$BASE/.$NAME.manifest")
mv -- "$BASE/.$NAME.manifest" "$DIR/MANIFEST.sha256"
ARCHIVE="$BASE/$NAME.tar.gz"
tar -czf "$ARCHIVE" -C "$BASE" "$NAME" || die "tar failed"
chmod 400 "$ARCHIVE"
HASH="$(sha256sum -- "$ARCHIVE" | awk '{print $1}')"
printf '%s  %s\n' "$HASH" "$(basename -- "$ARCHIVE")" >> "$IR_STATE/evidence_hashes.txt"
COC="$IR_STATE/chain_of_custody.txt"
[[ -s "$COC" ]] || printf 'time | action | item | sha256 | by | host\n' > "$COC"
{
    printf '%s | collected | %s | %s | %s | %s\n' "$(now_iso)" "$(basename -- "$ARCHIVE")" "$HASH" "$(analyst_login)" "$(hostname)"
} >> "$COC"
chmod 600 "$IR_STATE/evidence_hashes.txt" "$IR_STATE/chain_of_custody.txt"

files="$(($(wc -l < "$DIR/MANIFEST.sha256")))"
failed="$(awk -F'\t' 'NR>1 && $2!=0 && $2!="-"' "$LOG" | wc -l)"
log_event evidence "Collected $files files into $(basename -- "$ARCHIVE"), SHA-256 $HASH"
echo "Collection complete: $ARCHIVE"
echo "  files: $files   commands that failed: $failed (see errors.txt inside)"
echo "  sha256: $HASH"
echo "  recorded in $IR_STATE/evidence_hashes.txt and chain_of_custody.txt"
