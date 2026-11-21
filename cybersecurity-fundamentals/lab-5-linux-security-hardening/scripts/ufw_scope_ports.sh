#!/usr/bin/env bash
# ufw_scope_ports.sh: replace "ALLOW from Anywhere" rules for chosen ports with
# rules that only allow a trusted network. Dry run unless --apply is given.
#
#   ./ufw_scope_ports.sh                                  -> show the plan for 9392 9000 9200
#   ./ufw_scope_ports.sh --apply                          -> do it
#   PORTS="9392" TRUSTED=10.0.0.0/24 ./ufw_scope_ports.sh --apply
#
# TRUSTED defaults to 127.0.0.1, so the services stay reachable from this
# machine only. Use your LAN range (for example 192.168.1.0/24) to reach them
# from other devices at home. The allow rule is added before the old one is
# deleted, so there is never a moment with no access.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

PORTS="${PORTS:-9392 9000 9200}"
TRUSTED="${TRUSTED:-127.0.0.1}"
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

run() {
    if (( APPLY )); then
        echo "+ ufw $*"; as_root ufw "$@"
    else
        echo "would run: ufw $*"
    fi
}

for port in $PORTS; do
    is_int "$port" || { echo "skipping invalid port '$port'" >&2; continue; }
    run allow from "$TRUSTED" to any port "$port" proto tcp
    # "ufw delete allow 9392/tcp" removes both the IPv4 and IPv6 copies.
    run delete allow "$port/tcp"
done

(( APPLY )) || echo "Dry run only. Re-run with --apply to make these changes."
