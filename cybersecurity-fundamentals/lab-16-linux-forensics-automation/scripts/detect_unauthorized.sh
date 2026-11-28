#!/usr/bin/env bash
# detect_unauthorized.sh: live, read-only check of this host for signs of
# unauthorised activity. Findings are graded CRITICAL / HIGH / MEDIUM / LOW.
#
#   sudo ./detect_unauthorized.sh
#   sudo ./detect_unauthorized.sh --auth-log /tmp/forensics_lab_sim/test_auth.log
#   sudo ./detect_unauthorized.sh --per-ip 5 --total 50
#
# Writes findings.txt (readable), findings.tsv (one finding per line) and
# summary.txt into FORENSICS_BASE/unauthorized_analysis_<time>/.
# Exit code: 1 if anything is HIGH or CRITICAL, 0 otherwise, 2 on usage errors.
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

PER_IP=10        # failed logins from one address before it counts as brute force
TOTAL=20         # failed logins in total (many addresses) before it is reported
EXTRA_LOGS=()
while (( $# )); do
    case "$1" in
        --auth-log) EXTRA_LOGS+=("${2:?--auth-log needs a file}"); shift 2 ;;
        --per-ip) PER_IP="${2:?}"; shift 2 ;;
        --total) TOTAL="${2:?}"; shift 2 ;;
        --base) FORENSICS_BASE="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done
[[ "$PER_IP" =~ ^[0-9]+$ && "$TOTAL" =~ ^[0-9]+$ ]] || die "--per-ip and --total take whole numbers"
(( EUID == 0 )) || print_warn "not root: the auth log and other users' process details may be hidden"

private_dir "$FORENSICS_BASE"
ANALYSIS_DIR="$FORENSICS_BASE/unauthorized_analysis_$(date +%Y%m%d_%H%M%S)"
private_dir "$ANALYSIS_DIR"
umask 077
OUT="$ANALYSIS_DIR/findings.txt"
TSV="$ANALYSIS_DIR/findings.tsv"
: > "$TSV"

report() { printf '%s\n' "$*" | tee -a "$OUT"; }
finding() {  # finding SEVERITY CATEGORY SUMMARY [EVIDENCE]
    add_finding "$TSV" "$@"
    report "  [$1] $3"
    [[ -n "${4:-}" ]] && report "           evidence: $(fx_clean "$4" | cut -c1-200)"
    return 0
}

: > "$OUT"
report "=== UNAUTHORIZED ACTIVITY DETECTION ==="
report "Host: $(hostname)   Time: $(now_iso)   Analyst: $(analyst_login)"
report "Thresholds: brute force at more than $PER_IP failures from one address, or $TOTAL in total"

# One stream of auth lines: the real log (or journal) plus any extra files.
AUTH="$ANALYSIS_DIR/auth_lines.txt"
{
    auth_log "7 days ago"
    for f in "${EXTRA_LOGS[@]}"; do
        if [[ -r "$f" ]]; then grep -av '^#' -- "$f"; else print_warn "cannot read $f" >&2; fi
    done
} > "$AUTH"
report "Auth lines examined: $(wc -l < "$AUTH") (sources: $([[ -r /var/log/auth.log ]] && echo auth.log || echo journal)${EXTRA_LOGS[*]:+ + ${EXTRA_LOGS[*]}})"

# The address is taken from the END of the line: sshd writes the username
# first, and an attacker can pick a username like "x from 10.9.9.9 port 22".
ip_of() { sed -nE 's/.* from ([0-9A-Fa-f:.]+) port [0-9]+( ssh2)?(:.*)?$/\1/p'; }

# --- 1. Brute force ----------------------------------------------------------
section "Brute force logins" | tee -a "$OUT"
FAILS="$(grep -a 'Failed password' "$AUTH")"
nfail=0; [[ -n "$FAILS" ]] && nfail="$(wc -l <<< "$FAILS")"
report "  failed password lines: $nfail"
flagged_ips=0
if (( nfail )); then
    while read -r count ip; do
        [[ -n "$ip" ]] || continue
        if (( count > PER_IP )); then
            flagged_ips=$((flagged_ips + 1))
            win="$(grep -a "Accepted [a-z/-]* for .* from $ip port" "$AUTH" | head -1)"
            if [[ -n "$win" ]]; then
                finding CRITICAL authentication "brute force from $ip ($count failures) followed by a successful login" "$win"
            else
                finding HIGH authentication "brute force from $ip: $count failed logins" \
                    "$(grep -a "from $ip port" <<< "$FAILS" | tail -1)"
            fi
        fi
    done < <(ip_of <<< "$FAILS" | sort | uniq -c | sort -rn)
    if (( nfail > TOTAL && flagged_ips == 0 )); then
        finding MEDIUM authentication "$nfail failed logins spread over many addresses (possible distributed brute force)"
    fi
    while read -r line; do
        finding MEDIUM authentication "log injection attempt: username contains a fake source address" "$line"
    done < <(grep -aE ' from [0-9A-Fa-f:.]+ port [0-9]+ .*from [0-9A-Fa-f:.]+ port [0-9]+' <<< "$FAILS")
fi
if (( flagged_ips == 0 && nfail <= TOTAL )); then report "  no brute force pattern"; fi

# --- 2. Suspicious processes -------------------------------------------------
section "Suspicious processes" | tee -a "$OUT"
found=0
while read -r pid user comm args; do
    in_list "$comm" "${FX_SUSPICIOUS_PROCS[@]}" || continue
    found=1
    if [[ " $args " =~ \ -[a-zA-Z]*[le][a-zA-Z]*\  ]]; then
        finding HIGH process "$comm running as $user (PID $pid) in listen or exec mode" "$args"
    else
        finding MEDIUM process "$comm running as $user (PID $pid)" "$args"
    fi
done < <(ps -eo pid=,user=,comm=,args=)
for exe in /proc/[0-9]*/exe; do
    t="$(readlink -- "$exe" 2>/dev/null)" || continue
    pid="${exe//[!0-9]/}"
    case "$t" in
        /tmp/*|/var/tmp/*|/dev/shm/*)
            found=1; finding HIGH process "PID $pid runs a program from a temp folder" "$t" ;;
        *" (deleted)")
            found=1; finding HIGH process "PID $pid runs a program that was deleted from disk" "$t" ;;
    esac
done
(( found )) || report "  none"

# --- 3. Suspicious ports -----------------------------------------------------
section "Suspicious listening ports and connections" | tee -a "$OUT"
found=0
if have ss; then
    while read -r line; do
        local_addr="$(awk '{print $4}' <<< "$line")"
        port="${local_addr##*:}"
        in_list "$port" "${FX_SUSPICIOUS_PORTS[@]}" || continue
        found=1
        scope="reachable from the network"
        [[ "$local_addr" == 127.* || "$local_addr" == "[::1]"* ]] && scope="loopback only"
        finding HIGH network "listener on backdoor port $port ($scope)" "$line"
    done < <(ss -Htlnp; ss -Hulnp)
    while read -r line; do
        peer="$(awk '{print $5}' <<< "$line")"
        port="${peer##*:}"
        in_list "$port" "${FX_SUSPICIOUS_PORTS[@]}" || continue
        found=1
        finding HIGH network "outbound connection to backdoor port $port (possible reverse shell)" "$line"
    done < <(ss -Htnp state established; ss -Htnp state syn-sent)
else
    print_warn "ss not installed (apt install iproute2)"
fi
(( found )) || report "  none"

# --- 4. Suspicious files -----------------------------------------------------
section "Suspicious files in temp folders" | tee -a "$OUT"
found=0
name_args=()
for p in "${FX_FILE_PATTERNS[@]}"; do name_args+=(-iname "$p" -o); done
unset 'name_args[-1]'
while IFS= read -r -d '' f; do
    found=1
    finding HIGH file "suspicious file name: $f" "$(stat -c '%A %U %y' -- "$f")"
done < <(find "${FX_TEMP_DIRS[@]}" -xdev -type f \( "${name_args[@]}" \) -print0 2>/dev/null)
while IFS= read -r -d '' f; do
    found=1
    finding MEDIUM file "executable file in a temp folder: $f" "$(stat -c '%A %U %y' -- "$f")"
done < <(find "${FX_TEMP_DIRS[@]}" -xdev -type f -perm /111 ! \( "${name_args[@]}" \) -print0 2>/dev/null)
(( found )) || report "  none"

# --- 5. Unauthorised sudo ----------------------------------------------------
section "Sudo use by non-admin accounts" | tee -a "$OUT"
mapfile -t ADMINS < <(admin_users)
report "  admin accounts: ${ADMINS[*]}"
found=0
while read -r line; do
    user="$(sed -nE 's/.*sudo(\[[0-9]+\])?: +([^ ]+) : .*/\2/p' <<< "$line")"
    [[ -n "$user" ]] || continue
    if [[ "$line" == *"NOT in sudoers"* || "$line" == *"incorrect password attempt"* ]]; then
        found=1; finding HIGH privilege "sudo refused for $user" "$line"
    elif ! in_list "$user" "${ADMINS[@]}"; then
        found=1; finding HIGH privilege "sudo used by $user, who is not in an admin group" "$line"
    fi
done < <(grep -a 'sudo' "$AUTH" | grep -a ' : ' | grep -av pam_unix)
(( found )) || report "  none"

# --- 6. Extra UID 0 accounts -------------------------------------------------
section "Accounts with UID 0" | tee -a "$OUT"
extra_root="$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)"
if [[ -n "$extra_root" ]]; then
    for u in $extra_root; do finding CRITICAL account "second UID 0 account: $u" "$(getent passwd "$u")"; done
else
    report "  only root"
fi

# --- Summary -----------------------------------------------------------------
section "Summary" | tee -a "$OUT"
declare -A N=([CRITICAL]=0 [HIGH]=0 [MEDIUM]=0 [LOW]=0)
while IFS=$'\t' read -r sev _; do N[$sev]=$(( ${N[$sev]:-0} + 1 )); done < "$TSV"
TOTAL_FINDINGS="$(wc -l < "$TSV")"
{
    echo "Total findings: $TOTAL_FINDINGS"
    echo "  CRITICAL: ${N[CRITICAL]}  HIGH: ${N[HIGH]}  MEDIUM: ${N[MEDIUM]}  LOW: ${N[LOW]}"
    echo
    echo "Recommendations:"
    cut -f2 "$TSV" | sort -u | while read -r cat; do fx_recommendation "$cat"; done
    (( TOTAL_FINDINGS )) || echo "  - Nothing found. Keep this run as a baseline of normal for this host."
} | tee "$ANALYSIS_DIR/summary.txt" | tee -a "$OUT"

echo
print_status "Analysis completed: $ANALYSIS_DIR"
(( N[CRITICAL] + N[HIGH] )) && exit 1
exit 0
