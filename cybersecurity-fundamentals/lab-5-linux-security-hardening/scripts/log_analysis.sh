#!/usr/bin/env bash
# log_analysis.sh: one-screen security report from the systemd journal.
#
#   ./log_analysis.sh                     -> last 24 hours
#   SINCE="7 days ago" ./log_analysis.sh  -> any journalctl --since value
#   SAMPLE_LOG=../samples/auth-sample.log ./log_analysis.sh   -> practice data
#
# Read-only. Covers SSH failures and successes (with top source IPs), sudo
# use, other authentication failures, UFW blocks, disk, memory and who is on.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

SINCE="${SINCE:-24 hours ago}"
TOP="${TOP:-5}"

echo "Security log report for $(hostname), since: $SINCE"
echo "Generated: $(date '+%F %T %Z')"

ssh_lines="$(ssh_log "$SINCE")"
failed="$(grep -E 'Failed (password|publickey)' <<<"$ssh_lines" || true)"

section "SSH"
info "failed attempts:        $(count_matches 'Failed (password|publickey)' <<<"$ssh_lines")"
info "invalid usernames:      $(count_matches 'Invalid user' <<<"$ssh_lines")"
info "successful logins:      $(count_matches 'Accepted ' <<<"$ssh_lines")"
info "root login attempts:    $(count_matches 'for root from|user root from|ROOT LOGIN REFUSED' <<<"$ssh_lines")"
if [[ -n "$failed" ]]; then
    info ""; info "top source IPs of failures:"
    extract_ips <<<"$failed" | sort | uniq -c | sort -rn | head -n "$TOP" | sed 's/^/           /'
    info ""; info "most tried usernames:"
    grep -oE 'for (invalid user )?[^ ]+ from' <<<"$failed" | awk '{print $(NF-1)}' \
        | sort | uniq -c | sort -rn | head -n "$TOP" | sed 's/^/           /'
fi
accepted="$(grep 'Accepted ' <<<"$ssh_lines" || true)"
if [[ -n "$accepted" ]]; then
    info ""; info "last successful logins:"
    tail -n "$TOP" <<<"$accepted" | sed 's/^/           /'
fi

section "sudo"
sudo_lines="$(sudo_log "$SINCE")"
info "commands run:           $(count_matches 'COMMAND=' <<<"$sudo_lines")"
info "wrong password / denied: $(count_matches 'incorrect password|NOT in sudoers|authentication failure' <<<"$sudo_lines")"
cmds="$(grep 'COMMAND=' <<<"$sudo_lines" || true)"
if [[ -n "$cmds" ]]; then tail -n "$TOP" <<<"$cmds" | sed 's/^/           /'; fi

section "Other authentication failures"
info "pam 'authentication failure' lines: $(all_log "$SINCE" | count_matches 'authentication failure')"

section "Firewall"
blocks="$(kernel_log "$SINCE" | grep 'UFW BLOCK' || true)"
info "UFW blocks:             $(count_matches . <<<"$blocks")"
if [[ -n "$blocks" ]]; then
    info "top blocked sources (SRC=):"
    grep -oE 'SRC=[^ ]+' <<<"$blocks" | cut -d= -f2 | sort | uniq -c | sort -rn | head -n "$TOP" | sed 's/^/           /'
    info "top targeted ports (DPT=):"
    grep -oE 'DPT=[0-9]+' <<<"$blocks" | cut -d= -f2 | sort | uniq -c | sort -rn | head -n "$TOP" | sed 's/^/           /'
fi

section "System"
df -hP -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | sed 's/^/    /' || df -hP | sed 's/^/    /'
echo
free -h | sed 's/^/    /'
echo
info "logged in now:"
who | sed 's/^/           /' || true
