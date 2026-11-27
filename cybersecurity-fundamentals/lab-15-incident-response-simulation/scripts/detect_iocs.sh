#!/usr/bin/env bash
# detect_iocs.sh: read-only triage for indicators of compromise.
#
#   sudo ./detect_iocs.sh [-d DAYS] [-k user1,user2] [-w IP] [-x REGEX]
#
#   -d DAYS   look-back window for new files, cron and systemd changes (default 1)
#   -k LIST   accounts you know are legitimate (default: you and root)
#   -w IP     watchlist IP from the alert (default $IR_IP)
#   -x REGEX  ignore processes whose command line matches (known-good agents)
#
# Checks: processes running from or writing to temp folders, connections to
# public or watchlisted IPs, extra UID 0 accounts, unknown login accounts,
# authentication log events, hidden and executable files in temp folders,
# SUID programs no package owns, recent cron and systemd changes.
#
# Changes nothing on the system. Findings go to <case folder>/findings.tsv.
# Exit status: 0 nothing HIGH, 1 at least one HIGH finding, 2 usage error.
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

DAYS=1
KNOWN=""
WATCH_IP="$IR_IP"
IGNORE=""
while getopts ":d:k:w:x:h" opt; do
    case "$opt" in
        d) DAYS="$OPTARG" ;;
        k) KNOWN="$OPTARG" ;;
        w) WATCH_IP="$OPTARG" ;;
        x) IGNORE="$OPTARG" ;;
        h) sed -n '2,18p' "$0"; exit 0 ;;
        *) die "usage: $0 [-d DAYS] [-k user1,user2] [-w IP] [-x REGEX]" ;;
    esac
done
[[ "$DAYS" =~ ^[0-9]+$ ]] || die "-d needs a whole number of days"
is_ipv4 "$WATCH_IP" || die "not an IPv4 address: $WATCH_IP"
(( EUID == 0 )) || warn "not root: other users' processes, sockets and logs will be missing"
ir_init

FINDINGS="$IR_STATE/findings.tsv"
TMP_FINDINGS="$(mktemp)"
trap 'rm -f "$TMP_FINDINGS"' EXIT
HIGH=0; MED=0; LOW=0

# finding SEVERITY CATEGORY TEXT
finding() {
    local sev="$1" cat="$2"; shift 2
    printf '%s\t%s\t%s\n' "$sev" "$cat" "$*" >> "$TMP_FINDINGS"
    case "$sev" in
        HIGH) HIGH=$((HIGH+1)); bad  "[$cat] $*" ;;
        MEDIUM) MED=$((MED+1)); warn "[$cat] $*" ;;
        *) LOW=$((LOW+1)); info "[$cat] $*" ;;
    esac
}

in_temp() { [[ "$1" =~ ^/(tmp|var/tmp|dev/shm)(/|$) ]]; }

log_event detect "Triage started (window ${DAYS}d, watchlist $WATCH_IP)"

# ---------------------------------------------------------------- processes
section "Processes"
self=$$
for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    [[ "$pid" == "$self" || "$pid" == "$BASHPID" ]] && continue
    exe="$(readlink "$p/exe" 2>/dev/null)" || continue
    cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"
    [[ -z "$cmd" ]] && continue
    [[ -n "$IGNORE" && "$cmd" =~ $IGNORE ]] && continue
    user="$(stat -c %U "$p" 2>/dev/null)"
    ppid="$(awk '/^PPid:/{print $2}' "$p/status" 2>/dev/null)"
    short="${cmd:0:90}"
    if [[ "$exe" == *" (deleted)" ]]; then
        finding HIGH process "PID $pid ($user) runs a deleted program $exe: $short"
    elif in_temp "$exe"; then
        finding HIGH process "PID $pid ($user) runs from a temp folder $exe: $short"
    fi
    for fd in 1 2; do
        tgt="$(readlink "$p/fd/$fd" 2>/dev/null)" || continue
        if in_temp "$tgt" && [[ "$(basename -- "$tgt")" == .* ]]; then
            # A child that inherited the same output (the loop's sleep) is the
            # same finding; report only the top of the tree.
            [[ "$(readlink "/proc/$ppid/fd/$fd" 2>/dev/null)" == "$tgt" ]] && break
            finding HIGH process "PID $pid ($user, parent $ppid) writes its output to hidden file $tgt: $short"
            break
        fi
    done
    # A hard-coded address in a command line is an IoC on its own, even
    # between connection attempts when ss shows nothing.
    if [[ "$cmd" == *"$WATCH_IP"* && "$(tr '\0' ' ' < "/proc/$ppid/cmdline" 2>/dev/null)" != *"$WATCH_IP"* ]]; then
        finding HIGH process "PID $pid ($user) has the watchlist IP $WATCH_IP in its command line"
    fi
    cwd="$(readlink "$p/cwd" 2>/dev/null)"
    if in_temp "$cwd" && [[ "$(readlink "/proc/$ppid/cwd" 2>/dev/null)" != "$cwd" ]]; then
        finding MEDIUM process "PID $pid ($user) working directory is $cwd: $short"
    fi
done
if [[ -s "$IR_PIDFILE" ]]; then
    spid="$(cat "$IR_PIDFILE")"
    if is_alive "$spid"; then
        info "simulated PID $spid: $(ps -o pid=,ppid=,etime=,cmd= -p "$spid")"
    else
        info "simulated PID $spid is not running"
    fi
fi
echo "  Top CPU:"
ps -eo pid,user,%cpu,%mem,etime,cmd --sort=-%cpu | head -6 | sed 's/^/    /'

# ---------------------------------------------------------------- network
section "Network"
if have ss; then
    conns="$(ss -Htanp 2>/dev/null)"
    while read -r state _ _ local peer procinfo; do
        [[ -z "$state" ]] && continue
        [[ "$state" == LISTEN ]] && continue
        ip="${peer%:*}"; ip="${ip#[}"; ip="${ip%]}"; ip="${ip#::ffff:}"
        is_ipv4 "$ip" || continue
        if [[ "$ip" == "$WATCH_IP" ]]; then
            finding HIGH network "$state $local -> $peer matches the watchlist IP ${procinfo:-}"
        elif [[ "$state" == SYN-SENT ]] && ! is_private_ipv4 "$ip"; then
            finding MEDIUM network "$state $local -> $peer (outbound attempt to public IP) ${procinfo:-}"
        fi
    done <<< "$conns"
    echo "  Listening TCP/UDP ports:"
    ss -Htulpn 2>/dev/null | awk '{print "    "$1" "$5" "$7}' | sort -u | head -20
else
    warn "ss not found (package iproute2)"
fi

# ---------------------------------------------------------------- accounts
section "Accounts"
while IFS=: read -r name _ uid _ _ _ _; do
    [[ "$uid" == 0 && "$name" != root ]] && finding HIGH account "$name has UID 0 (a second root account)"
done < /etc/passwd

known=",root,$(analyst_login),${KNOWN},"
while IFS=: read -r name _ uid _ gecos home shell; do
    (( uid >= 1000 && uid < 60000 )) || continue
    [[ "$shell" =~ (nologin|false)$ ]] && continue
    [[ "$known" == *",$name,"* ]] && continue
    status="$(passwd -S "$name" 2>/dev/null | awk '{print $2}')"
    detail="$name (UID $uid, shell $shell, password status ${status:-?})"
    [[ -d "$home" ]] || detail+=", no home folder"
    if [[ "$status" == P ]]; then
        finding HIGH account "unknown login account with a usable password: $detail"
    else
        finding MEDIUM account "unknown login account: $detail"
    fi
    if [[ -s "$home/.ssh/authorized_keys" ]]; then
        finding HIGH account "$name has SSH keys in $home/.ssh/authorized_keys (a password lock does not stop these)"
    fi
    [[ "$gecos" == *"$IR_MARKER"* ]] && info "$name carries the lab's simulation marker"
done < /etc/passwd

# ---------------------------------------------------------------- auth logs
section "Authentication logs"
authlog="$(auth_log "$DAYS days ago")"
if [[ -z "$authlog" ]]; then
    warn "no authentication log found (no /var/log/auth.log, nothing in the journal)"
else
    fails="$(grep -c 'Failed password' <<< "$authlog")"
    info "failed password attempts: $fails"
    if (( fails > 0 )); then
        grep -oE 'Failed password for (invalid user )?[^ ]+ from [0-9.]+' <<< "$authlog" \
            | awk '{print $NF}' | sort | uniq -c | sort -rn | head -5 | sed 's/^/           /'
        (( fails >= 20 )) && finding MEDIUM auth "$fails failed password attempts in the log"
    fi
    info "root sessions opened: $(grep -c 'session opened for user root' <<< "$authlog")"
    while read -r line; do
        [[ -n "$line" ]] && finding HIGH auth "account created: ${line:0:160}"
    done < <(grep -E 'useradd.*new user' <<< "$authlog" | tail -5)
    grep -F 'sudo:' <<< "$authlog" | grep -F 'COMMAND=' | tail -5 | sed 's/^/           /'
fi

# ---------------------------------------------------------------- files
section "Files"
while read -r f; do
    [[ -n "$f" ]] && finding MEDIUM file "hidden file in a temp folder: $f ($(stat -c '%U %s bytes, modified %y' "$f" | cut -d. -f1))"
done < <(find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 -type f -name '.*' 2>/dev/null)
while read -r f; do
    [[ -n "$f" ]] && finding MEDIUM file "executable file in a temp folder: $f"
done < <(find /tmp /var/tmp /dev/shm -xdev -maxdepth 3 -type f -perm -u+x 2>/dev/null)
while read -r f; do
    [[ -n "$f" ]] && finding LOW file "script changed in the last ${DAYS}d: $f"
done < <(find /tmp /var/tmp /dev/shm /etc /opt /usr/local -xdev -type f -name '*.sh' -mtime "-$DAYS" 2>/dev/null | head -20)

suid=0
while read -r f; do
    [[ -z "$f" ]] && continue
    suid=$((suid+1))
    if have dpkg && ! dpkg -S "$f" >/dev/null 2>&1; then
        finding HIGH file "SUID program not installed by any package: $f"
    fi
done < <(find / -xdev -perm -4000 -type f 2>/dev/null)
info "SUID programs on the root filesystem: $suid (package-owned ones are not listed)"

# ---------------------------------------------------------------- persistence
section "Persistence"
while read -r f; do
    [[ -n "$f" ]] && finding MEDIUM persistence "changed in the last ${DAYS}d: $f"
done < <(find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/crontab /var/spool/cron \
              /etc/systemd/system /etc/rc.local -xdev -type f -mtime "-$DAYS" 2>/dev/null)

# ---------------------------------------------------------------- summary
{
    printf '# triage run %s by %s\n' "$(now_iso)" "$(analyst_login)"
    cat "$TMP_FINDINGS"
} > "$FINDINGS"
chmod 600 "$FINDINGS"
section "Summary"
echo "  HIGH: $HIGH   MEDIUM: $MED   LOW: $LOW"
echo "  Findings saved to $FINDINGS"
log_event detect "Triage finished: $HIGH high, $MED medium, $LOW low findings"
(( HIGH > 0 )) && exit 1
exit 0
