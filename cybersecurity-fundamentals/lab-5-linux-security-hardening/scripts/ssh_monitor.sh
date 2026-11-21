#!/usr/bin/env bash
# ssh_monitor.sh: raise an alert when SSH activity looks like an attack.
#
#   ./ssh_monitor.sh                         -> check the last hour
#   WINDOW="15 minutes ago" THRESHOLD=10 ./ssh_monitor.sh
#   SAMPLE_LOG=../samples/auth-sample.log ./ssh_monitor.sh
#
# Alerts (written to ALERT_LOG and printed) when:
#   - total failed attempts in WINDOW exceed THRESHOLD
#   - any single IP exceeds PER_IP_THRESHOLD (likely brute force)
#   - anyone tries to log in as root
#   - a login succeeds from an IP that also failed in the same window
# Exit code: 0 no alerts, 2 alerts raised, 1 script error. Cron and the
# master script use this to tell a quiet run from a noisy one.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

WINDOW="${WINDOW:-1 hour ago}"
THRESHOLD="${THRESHOLD:-5}"
PER_IP_THRESHOLD="${PER_IP_THRESHOLD:-3}"
ALERT_LOG="${ALERT_LOG:-$(default_log_dir)/ssh_alerts.log}"

for v in THRESHOLD PER_IP_THRESHOLD; do
    is_int "${!v}" || { echo "error: $v must be a whole number, got '${!v}'" >&2; exit 1; }
done
mkdir -p -- "$(dirname -- "$ALERT_LOG")"

alerts=0
alert() {
    alerts=$((alerts + 1))
    printf '%s ALERT ssh: %s\n' "$(date '+%F %T')" "$1" | tee -a "$ALERT_LOG"
    # Hook for real notifications: uncomment and point at your own channel.
    # logger -t ssh_monitor -p auth.warning "$1"
}

lines="$(ssh_log "$WINDOW")"
failed="$(grep -E 'Failed (password|publickey)' <<<"$lines" || true)"
nfailed="$(count_matches 'Failed (password|publickey)' <<<"$lines")"

echo "SSH monitor: window since '$WINDOW', $nfailed failed attempts"

if (( nfailed > THRESHOLD )); then
    alert "$nfailed failed SSH attempts since $WINDOW (threshold $THRESHOLD)"
fi

if [[ -n "$failed" ]]; then
    while read -r n ip; do
        [[ -n "$ip" ]] || continue
        if (( n > PER_IP_THRESHOLD )); then alert "$ip made $n failed attempts (possible brute force)"; fi
    done < <(extract_ips <<<"$failed" | sort | uniq -c | sort -rn)
fi

nroot="$(count_matches 'Failed [a-z]+ for root from|ROOT LOGIN REFUSED|User root from .* not allowed' <<<"$lines")"
if (( nroot > 0 )); then alert "$nroot root login attempt(s); PermitRootLogin should be refusing them"; fi

if [[ -n "$failed" ]]; then
    bad_ips="$(extract_ips <<<"$failed" | sort -u)"
    while read -r ip; do
        if [[ -n "$ip" ]] && grep -qxF -- "$ip" <<<"$bad_ips"; then
            alert "successful login from $ip, which also failed in this window; check it was you"
        fi
    done < <(grep 'Accepted ' <<<"$lines" | extract_ips | sort -u)
fi

if (( alerts == 0 )); then
    echo "no alerts"
    exit 0
fi
echo "$alerts alert(s) written to $ALERT_LOG"
exit 2
