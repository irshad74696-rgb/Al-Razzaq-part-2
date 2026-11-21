#!/usr/bin/env bash
# setup_monitoring_cron.sh: schedule the monitors with cron, safely.
#
#   ./setup_monitoring_cron.sh            -> show the entries it would add
#   ./setup_monitoring_cron.sh --install  -> add them (running it twice adds nothing twice)
#   ./setup_monitoring_cron.sh --remove   -> take them out again
#
# Every line it manages ends with the tag "# security-monitor", so install and
# remove only touch those lines and leave the rest of your crontab alone.
# Output goes to a log file, because cron otherwise tries to mail it.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$(default_log_dir)"
TAG="# security-monitor"

ENTRIES="0 * * * * $SCRIPT_DIR/security_monitor_master.sh >> $LOG_DIR/security-monitor-cron.log 2>&1 $TAG
*/15 * * * * $SCRIPT_DIR/ssh_monitor.sh >> $LOG_DIR/security-monitor-cron.log 2>&1 $TAG"

current="$(crontab -l 2>/dev/null || true)"
without_ours="$(grep -vF -- "$TAG" <<<"$current" || true)"

case "${1:-}" in
    --install)
        have crontab || { echo "error: crontab not found (apt install cron)" >&2; exit 1; }
        mkdir -p -- "$LOG_DIR"
        printf '%s\n%s\n' "$without_ours" "$ENTRIES" | sed '/^$/d' | crontab -
        echo "Installed. Current crontab:"; crontab -l
        systemctl is-active --quiet cron 2>/dev/null || echo "warning: the cron service is not running (systemctl enable --now cron)"
        ;;
    --remove)
        printf '%s\n' "$without_ours" | sed '/^$/d' | crontab -
        echo "Removed the security-monitor entries. Current crontab:"; crontab -l 2>/dev/null || echo "(empty)"
        ;;
    "")
        echo "Would add these entries (run with --install):"
        echo "$ENTRIES"
        echo
        echo "  hourly        full report from security_monitor_master.sh"
        echo "  every 15 min  ssh_monitor.sh for brute-force bursts"
        ;;
    *) echo "usage: $0 [--install|--remove]" >&2; exit 1 ;;
esac
