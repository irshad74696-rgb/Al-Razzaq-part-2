#!/usr/bin/env bash
# simulate_compromise.sh: plant the lab's harmless indicators of compromise.
#
#   sudo ./simulate_compromise.sh            show what would be created (default)
#   sudo ./simulate_compromise.sh --apply    create them
#
# What it plants (all harmless, all removed by cleanup_lab.sh):
#   1. A detached "bash -c 'while true ...'" loop with its output going to the
#      hidden file /tmp/.hidden_log. It keeps trying a TCP connection to
#      $IR_IP:$IR_PORT (each attempt hangs in SYN-SENT for up to 2 minutes,
#      then it waits 30 seconds), so the network IoC is visible in `ss`
#      instead of only being written down. 203.0.113.0/24 is TEST-NET-3,
#      reserved for documentation: nothing on the internet answers there.
#   2. An account "hacker" with a login shell and a password, so it shows as
#      "P" (usable) in `passwd -S`. The password is random and printed nowhere:
#      the handout's fixed "CompromisedPass123!" would be a real weak login on
#      any machine with SSH open. The GECOS field carries a marker so cleanup
#      can tell it apart from a real account.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=1
case "${1:-}" in
    --apply) DRY_RUN=0 ;;
    ""|--dry-run) ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown option: $1 (use --apply)" ;;
esac
need_root
ir_init

section "Simulated compromise ($([[ $DRY_RUN == 1 ]] && echo dry run || echo applying))"

# 1. Suspicious process
if [[ -s "$IR_PIDFILE" ]] && is_alive "$(cat "$IR_PIDFILE")"; then
    ok "suspicious process already running as PID $(cat "$IR_PIDFILE")"
else
    loop="while true; do timeout 120 bash -c 'exec 3<>/dev/tcp/$IR_IP/$IR_PORT' 2>/dev/null; sleep ${IR_BEACON_SECONDS:-30}; done"
    if [[ $DRY_RUN == 1 ]]; then
        printf '  would run: nohup bash -c "%s" > %s &\n' "$loop" "$IR_HIDDEN_LOG"
    else
        # setsid detaches it from this terminal, like a dropped implant would be.
        setsid nohup bash -c "$loop" > "$IR_HIDDEN_LOG" 2>&1 < /dev/null &
        pid=$!
        sleep 0.5
        is_alive "$pid" || die "simulated process did not start"
        echo "$pid" > "$IR_PIDFILE"
        echo "$pid" > "$IR_LEGACY_PIDFILE"     # where the handout expects it
        ok "suspicious process started: PID $pid, output to $IR_HIDDEN_LOG"
        log_event simulate "Started simulated suspicious process PID $pid (bash loop, output to $IR_HIDDEN_LOG, beacons to $IR_IP:$IR_PORT)"
    fi
fi

# 2. Unauthorised account
if getent passwd "$IR_USER" >/dev/null; then
    if user_has_marker "$IR_USER"; then
        ok "account $IR_USER already exists (simulated)"
    else
        die "a real account named $IR_USER already exists; set IR_USER to another name"
    fi
else
    run useradd -M -s /bin/bash -c "$IR_MARKER" "$IR_USER"
    if [[ $DRY_RUN == 0 ]]; then
        pw="$(head -c 18 /dev/urandom | base64)"
        printf '%s:%s\n' "$IR_USER" "$pw" | chpasswd
        unset pw
        ok "account $IR_USER created with a random password (status: $(passwd -S "$IR_USER" | awk '{print $2}'))"
        log_event simulate "Created simulated unauthorised account $IR_USER (UID $(id -u "$IR_USER"))"
    fi
fi

# 3. Suspicious IP: nothing to create, the process above already talks to it.
info "suspicious IP for this case: $IR_IP (port $IR_PORT)"
if [[ $DRY_RUN == 1 ]]; then
    echo
    echo "Dry run: nothing was changed. Re-run with --apply to plant the indicators."
else
    log_event simulate "Simulated suspicious destination $IR_IP:$IR_PORT"
    echo
    echo "Case folder: $IR_STATE"
    echo "Next: sudo ./detect_iocs.sh"
fi
