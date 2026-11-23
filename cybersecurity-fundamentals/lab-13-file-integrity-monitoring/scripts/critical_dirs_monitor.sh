#!/usr/bin/env bash
# critical_dirs_monitor.sh: integrity monitoring for system-critical folders.
#
#   critical_dirs_monitor.sh setup      load the auditd watches (setup_auditd.sh --load)
#   critical_dirs_monitor.sh baseline   hash every file in the critical folders
#   critical_dirs_monitor.sh check      compare them with the baseline
#   critical_dirs_monitor.sh report     check + auditd events, saved as one private report
#
# Default folders: /etc /usr/bin /usr/sbin /usr/local/bin ~/secure_files.
# /var/log is left out on purpose: log files change every second, so a hash
# baseline of them is all noise. Logs are protected by shipping them off the
# machine, not by hashing them.
#
# Run as root (or with sudo): /etc/shadow, /etc/sudoers and others are not
# readable by normal users, and a baseline that silently skips them is useless.
#
# Exit codes follow file_integrity_checker.sh: 0 clean, 1 changes, 2 error.
#
# Environment:
#   FIM_CRITICAL_DIRS="/etc:/opt/app"   colon-separated list to use instead
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

STATE_DIR="$(fim_state_dir)"
export FIM_BASELINE="$STATE_DIR/critical-baseline.tsv"
CHECKER="$FIM_SCRIPT_DIR/file_integrity_checker.sh"

if [[ -n "${FIM_CRITICAL_DIRS:-}" ]]; then
    IFS=: read -r -a DIRS <<< "$FIM_CRITICAL_DIRS"
else
    DIRS=(/etc /usr/bin /usr/sbin /usr/local/bin "$(demo_dir)")
fi

existing_dirs() {
    local d
    for d in "${DIRS[@]}"; do
        if [[ -d "$d" ]]; then echo "$d"; else echo "warning: $d does not exist, skipped" >&2; fi
    done
}

need_root_warning() {
    if (( EUID != 0 )); then
        warn "not running as root: files such as /etc/shadow will be UNREADABLE in the baseline"
        info "run with sudo for a complete result"
    fi
}

case "${1:-}" in
    setup)
        exec "$FIM_SCRIPT_DIR/setup_auditd.sh" --load
        ;;
    baseline)
        need_root_warning
        mapfile -t dirs < <(existing_dirs)
        (( ${#dirs[@]} )) || die "none of the folders exist"
        "$CHECKER" --create "${dirs[@]}"
        ;;
    check)
        "$CHECKER" --scan
        ;;
    report)
        need_root_warning
        dir="$(private_dir "$STATE_DIR/reports")"
        report="$dir/security_report_$(date +%Y%m%d_%H%M%S).txt"
        status=0
        (
            umask 077
            {
                echo "########## Hash comparison ##########"
                "$CHECKER" --scan || exit "$?"
            } > "$report.part" 2>&1
        ) || status=$?
        {
            cat "$report.part"
            echo
            echo "########## auditd events (today) ##########"
            NO_COLOR=1 "$FIM_SCRIPT_DIR/audit_report.sh" -t today -n 5 2>&1 || true
        } > "$report"
        rm -f -- "$report.part"
        chmod 600 "$report"
        cat "$report"
        echo
        echo "Combined report: $report"
        case "$status" in
            0) ok "no file changes since the baseline" ;;
            1) warn "file changes found: review them, then re-run 'baseline' to accept" ;;
            *) bad "the hash check failed (exit $status)" ;;
        esac
        exit "$status"
        ;;
    *)
        sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
