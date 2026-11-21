#!/usr/bin/env bash
# firewall_check.sh: read-only look at the UFW firewall.
#
#   ./firewall_check.sh
#
# Shows UFW status and default policies, flags ALLOW rules open to "Anywhere"
# on ports that are usually admin or database interfaces, lists what is really
# listening (ss), tests outbound connectivity, and shows recent UFW blocks.
# Changes nothing.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

# Ports that should almost never be reachable from the whole internet.
RISKY_PORTS="${RISKY_PORTS:-21 23 25 110 139 445 1433 3306 3389 5432 5900 6379 9000 9200 9300 9392 11211 27017}"

section "UFW status"
if ! have ufw; then
    bad "ufw is not installed (apt install ufw)"
    exit 1
fi
status="$(as_root ufw status verbose)"
printf '    %s\n' "${status//$'\n'/$'\n'    }"
if grep -q '^Status: active' <<<"$status"; then ok "UFW is active"; else bad "UFW is inactive (ufw enable)"; fi
if grep -q 'deny (incoming)' <<<"$status"; then ok "default incoming policy is deny"
else warn "default incoming policy is not deny (ufw default deny incoming)"; fi
if grep -q 'Logging: on' <<<"$status"; then ok "logging is on"
else warn "logging is off (ufw logging low)"; fi

section "Rules open to Anywhere on sensitive ports"
found=0
while read -r line; do
    port="${line%%[ /]*}"
    for p in $RISKY_PORTS; do
        if [[ "$port" == "$p" ]]; then
            warn "$line"
            found=1
        fi
    done
done < <(grep -E 'ALLOW( IN)? +Anywhere' <<<"$status" | sed 's/  */ /g')
if (( found )); then
    info "Scope these to localhost or your LAN, for example:"
    info "  ufw allow from 192.168.1.0/24 to any port 9392 proto tcp"
    info "then remove the old rule with: ufw status numbered; ufw delete <n>"
else
    ok "no sensitive ports open to Anywhere"
fi

section "Listening TCP sockets"
if have ss; then
    as_root ss -tlnpH | awk '{printf "    %-28s %s\n", $4, $6}'
else
    warn "ss not found (package iproute2)"
fi

section "Outbound connectivity"
if have curl && curl -fsS -o /dev/null --max-time 5 https://example.com; then
    ok "HTTPS to example.com works (outgoing allowed)"
elif ping -c 2 -W 2 1.1.1.1 >/dev/null 2>&1; then
    ok "ping to 1.1.1.1 works (outgoing allowed)"
else
    warn "no outbound connectivity; check 'ufw default allow outgoing' and your network"
fi

section "Recent UFW blocks (last 24 h)"
blocks="$(kernel_log "24 hours ago" | grep 'UFW BLOCK' || true)"
if [[ -z "$blocks" ]]; then
    info "none logged"
else
    info "$(wc -l <<<"$blocks") blocked packets; last 5:"
    tail -n 5 <<<"$blocks" | sed 's/^/    /'
fi
