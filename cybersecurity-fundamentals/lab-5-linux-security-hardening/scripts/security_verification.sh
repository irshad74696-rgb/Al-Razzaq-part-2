#!/usr/bin/env bash
# security_verification.sh: final pass/fail checklist for the whole lab.
#
#   ./security_verification.sh
#
# One line per control. Exit code is the number of failed checks (0 = done).
set -uo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
fails=0
check() {   # check <description> <command...>
    local d="$1"; shift
    if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fails=$((fails + 1)); fi
}

ufw_status="$(as_root ufw status verbose 2>/dev/null || true)"
eff="$(as_root "$(command -v sshd || echo /usr/sbin/sshd)" -T 2>/dev/null || true)"
# shellcheck disable=SC2329  # called through check()
sshd_is() { grep -qx "$1 $2" <<<"$eff"; }

section "Firewall"
check "UFW active"                       grep -q '^Status: active' <<<"$ufw_status"
check "default deny incoming"            grep -q 'deny (incoming)' <<<"$ufw_status"
check "UFW logging on"                   grep -q 'Logging: on' <<<"$ufw_status"
check "UFW enabled at boot"              systemctl is-enabled ufw

section "SSH"
check "sshd config valid (sshd -t)"      as_root "$(command -v sshd || echo /usr/sbin/sshd)" -t
check "root login disabled"              sshd_is permitrootlogin no
check "password login disabled"          sshd_is passwordauthentication no
check "keyboard-interactive disabled"    sshd_is kbdinteractiveauthentication no
check "max 3 auth tries"                 grep -qxE 'maxauthtries [1-3]' <<<"$eff"
check "AllowUsers set"                   grep -q '^allowusers ' <<<"$eff"

section "Monitoring"
check "monitor scripts executable"       test -x "$SCRIPT_DIR/ssh_monitor.sh" -a -x "$SCRIPT_DIR/system_monitor.sh"
check "cron entries installed"           bash -c 'crontab -l | grep -qF "# security-monitor"'
check "cron service running"             systemctl is-active cron

section "Last 24 hours"
ssh_lines="$(ssh_log "24 hours ago")"
info "failed SSH attempts:  $(count_matches 'Failed (password|publickey)' <<<"$ssh_lines")"
info "successful SSH logins: $(count_matches 'Accepted ' <<<"$ssh_lines")"
info "UFW blocks:           $(kernel_log "24 hours ago" | count_matches 'UFW BLOCK')"
alert_logs=("$(default_log_dir)"/*alerts.log)
if [[ -e "${alert_logs[0]}" ]]; then info "alert logs: ${alert_logs[*]}"; else info "no alert logs yet"; fi

section "Result"
if (( fails == 0 )); then ok "every control in place"; else bad "$fails control(s) missing"; fi
exit "$fails"
