#!/usr/bin/env bash
# security_monitor_master.sh: run every check and save one dated report.
#
#   ./security_monitor_master.sh
#   REPORT_DIR=~/reports KEEP_REPORTS=48 ./security_monitor_master.sh
#
# Reports go to a private folder (mode 700), not /tmp, because they contain
# usernames, IP addresses and listening services. Only the newest
# KEEP_REPORTS are kept. The summary tells the truth: it lists which checks
# raised alerts or failed, instead of always saying "all good".
# Exit code: 0 all quiet, 2 at least one alert, 1 a check itself failed.
set -uo pipefail   # no -e: one failing check must not stop the others
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${REPORT_DIR:-$(default_log_dir)/security-reports}"
KEEP_REPORTS="${KEEP_REPORTS:-24}"

umask 077
mkdir -p -- "$REPORT_DIR"
REPORT="$REPORT_DIR/security_report_$(date +%Y%m%d_%H%M%S).txt"

declare -A result
run_check() {   # run_check <label> <script>
    local rc
    printf '\n######## %s ########\n' "$1"
    NO_COLOR=1 "$SCRIPT_DIR/$2"; rc=$?
    case $rc in
        0) result[$1]="ok" ;;
        2) result[$1]="ALERTS" ;;
        *) result[$1]="FAILED (exit $rc)" ;;
    esac
}

{
    echo "Automated security report: $(hostname), $(date '+%F %T %Z')"
    run_check "SSH activity"     ssh_monitor.sh
    run_check "System resources" system_monitor.sh
    run_check "Log analysis"     log_analysis.sh
    run_check "Firewall"         firewall_check.sh
    run_check "SSH config audit" ssh_audit.sh

    printf '\n######## Summary ########\n'
    for k in "SSH activity" "System resources" "Log analysis" "Firewall" "SSH config audit"; do
        printf '  %-18s %s\n' "$k" "${result[$k]}"
    done
} 2>&1 | tee -- "$REPORT"

# Keep only the newest reports.
find "$REPORT_DIR" -maxdepth 1 -name 'security_report_*.txt' -printf '%T@ %p\n' \
    | sort -rn | tail -n +"$((KEEP_REPORTS + 1))" | cut -d' ' -f2- | xargs -r rm -f --

echo
echo "Report saved to $REPORT"

# Exit status from the saved summary (the block above ran in a subshell).
if grep -q 'FAILED (exit' "$REPORT"; then exit 1; fi
if grep -qE '^  .{18} ALERTS$' "$REPORT"; then exit 2; fi
exit 0
