#!/usr/bin/env bash
# ssh_audit.sh: check the SSH server against a hardening baseline. Read-only.
#
#   ./ssh_audit.sh   -> exit 0 every check passed, 2 some checks failed, 1 could not run
#
# It reads the *effective* settings with "sshd -T", not by grepping
# sshd_config. Grepping misses files in /etc/ssh/sshd_config.d/ (Ubuntu ships
# 50-cloud-init.conf there, which can turn PasswordAuthentication back on) and
# cannot tell a default from an explicit value.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

failures=0
SSHD="$(command -v sshd || echo /usr/sbin/sshd)"
UNIT="$(ssh_unit)"

section "Config syntax"
if [[ ! -x "$SSHD" ]]; then
    bad "sshd not found; is openssh-server installed?"; exit 1
fi
if err="$(as_root "$SSHD" -t 2>&1)"; then
    ok "sshd -t: configuration is valid"
else
    bad "sshd -t reports errors:"; info "$err"; exit 1
fi

# sshd -T prints every effective option as "keyword value", lower case.
eff="$(as_root "$SSHD" -T 2>/dev/null)"
get() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' <<<"$eff"; }

expect() {   # expect <keyword> <wanted value> <why>
    local have; have="$(get "$1")"
    if [[ "$have" == "$2" ]]; then ok "$1 $have"
    else bad "$1 is '${have:-unset}', want '$2' ($3)"; failures=$((failures + 1)); fi
}
at_most() {  # at_most <keyword> <max> <why>
    local have; have="$(get "$1")"
    if is_int "$have" && (( have <= $2 )); then ok "$1 $have"
    else bad "$1 is '${have:-unset}', want <= $2 ($3)"; failures=$((failures + 1)); fi
}

section "Effective sshd settings"
expect permitrootlogin no "log in as a normal user, then sudo"
expect passwordauthentication no "keys only; stops password guessing"
expect kbdinteractiveauthentication no "closes the other password path (replaces ChallengeResponseAuthentication)"
expect pubkeyauthentication yes "needed for key login"
expect permitemptypasswords no "never allow blank passwords"
expect x11forwarding no "not needed on a server"
expect gssapiauthentication no "unused on a single machine"
at_most maxauthtries 3 "fewer guesses per connection"
at_most logingracetime 60 "drop half-open logins quickly"
interval="$(get clientaliveinterval)"
if is_int "$interval" && (( interval > 0 && interval <= 600 )); then
    ok "clientaliveinterval $interval (count $(get clientalivecountmax))"
else
    warn "clientaliveinterval is '${interval:-0}'; idle sessions are never dropped"
fi
users="$(get allowusers)"
if [[ -n "$users" ]]; then ok "allowusers $users"; else warn "no AllowUsers/AllowGroups list; any account with a key may log in"; fi

section "Port and socket activation"
ports="$(awk '$1 == "port" {print $2}' <<<"$eff" | paste -sd' ' -)"
info "sshd_config port(s): $ports"
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    listen="$(systemctl show ssh.socket -p Listen --value 2>/dev/null)"
    warn "ssh.socket is active; it owns the listening port ($listen), so 'Port' in sshd_config is ignored"
    info "fix: systemctl disable --now ssh.socket && systemctl restart ssh"
    info "or set ListenStream= in a drop-in: systemctl edit ssh.socket"
else
    ok "ssh.socket not active; sshd listens on its configured port"
fi
if have ss; then
    listening="$(as_root ss -tlnpH 2>/dev/null | grep -E '"(sshd|systemd)"' | awk '{print $4}' | paste -sd' ' - || true)"
    info "actually listening: ${listening:-nothing found}"
fi

section "Service"
if systemctl is-active --quiet "$UNIT"; then ok "$UNIT is running"; else warn "$UNIT is not running"; fi

section "Keys"
for f in "$HOME"/.ssh/id_ed25519.pub "$HOME"/.ssh/id_ecdsa.pub "$HOME"/.ssh/id_rsa.pub; do
    [[ -f "$f" ]] && info "$(ssh-keygen -lf "$f")"
done
if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
    perms="$(stat -c '%a' "$HOME/.ssh/authorized_keys")"
    if [[ "$perms" == 600 || "$perms" == 644 || "$perms" == 400 ]]; then ok "authorized_keys mode $perms"
    else bad "authorized_keys mode $perms; run chmod 600 ~/.ssh/authorized_keys"; failures=$((failures + 1)); fi
fi

section "Result"
if (( failures == 0 )); then ok "all hard checks passed"; else bad "$failures check(s) failed"; fi
if (( failures > 0 )); then exit 2; fi
