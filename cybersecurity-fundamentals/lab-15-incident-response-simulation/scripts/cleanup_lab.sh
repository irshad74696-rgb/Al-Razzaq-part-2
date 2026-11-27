#!/usr/bin/env bash
# cleanup_lab.sh: undo the simulation, dry run by default.
#
#   sudo ./cleanup_lab.sh                      show what would be removed
#   sudo ./cleanup_lab.sh --apply              remove it
#   sudo ./cleanup_lab.sh --apply --remove-evidence   also delete the case folder
#
# Removes only what the lab created:
#   - the account, and only if it carries the simulation marker (a real
#     account with the same name is left alone)
#   - the two iptables rules, deleted one by one with -D while -C still finds
#     them (tagged and hand-typed handout versions). Chains are never flushed.
#   - the simulated process, if it is still running and still looks like it
#   - /tmp/.hidden_log, /tmp/.x and /tmp/simulated_pid.txt
# The case folder (evidence, reports) is kept unless --remove-evidence is
# given: in a real incident evidence is preserved, not deleted.
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=1; RM_EVIDENCE=0
for a in "$@"; do
    case "$a" in
        --apply) DRY_RUN=0 ;;
        --remove-evidence) RM_EVIDENCE=1 ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) die "unknown option: $a" ;;
    esac
done
need_root
ir_init
section "Cleanup ($([[ $DRY_RUN == 1 ]] && echo dry run || echo applying))"

# process
for pidf in "$IR_PIDFILE" "$IR_LEGACY_PIDFILE"; do
    [[ -s "$pidf" ]] || continue
    p="$(cat "$pidf")"
    if is_alive "$p" && tr '\0' ' ' < "/proc/$p/cmdline" | grep -q 'while true'; then
        kids="$(descendants "$p" | tr '\n' ' ')"
        # shellcheck disable=SC2086  # word splitting of the PID list is intended
        run kill -KILL "$p" $kids     # children too, or the loop's sleep lingers
    fi
done

# account
if getent passwd "$IR_USER" >/dev/null; then
    if user_has_marker "$IR_USER"; then
        pgrep -u "$IR_USER" >/dev/null 2>&1 && run pkill -KILL -u "$IR_USER"
        home="$(getent passwd "$IR_USER" | cut -d: -f6)"
        if [[ -d "$home" && "$home" != / ]]; then run userdel -r "$IR_USER"; else run userdel "$IR_USER"; fi
    else
        warn "$IR_USER exists but has no simulation marker: not deleting it"
    fi
else
    ok "account $IR_USER is already gone"
fi

# firewall rules, exact matches only
removed=0
while read -r spec; do
    read -ra r <<< "$spec"
    while iptables -C "${r[@]}" 2>/dev/null; do
        run iptables -D "${r[@]}"
        removed=$((removed+1))
        [[ $DRY_RUN == 1 ]] && break
    done
done < <(fw_specs "$IR_IP"; fw_specs_manual "$IR_IP")
(( removed )) || ok "no lab rules for $IR_IP in iptables"

# files
for f in "$IR_HIDDEN_LOG" /tmp/.x "$IR_LEGACY_PIDFILE" /tmp/firewall_rules_backup.txt; do
    [[ -e "$f" ]] && run rm -f -- "$f"
done
[[ -e "$IR_PIDFILE" ]] && run rm -f -- "$IR_PIDFILE"

if (( RM_EVIDENCE )); then
    run rm -rf -- "$IR_STATE"
else
    info "case folder kept: $IR_STATE (use --remove-evidence only after the report is approved)"
fi

if [[ $DRY_RUN == 0 ]]; then
    section "Verification"
    if getent passwd "$IR_USER" >/dev/null; then bad "$IR_USER still exists"; else ok "account $IR_USER removed"; fi
    if iptables -S | grep -qF "$IR_IP"; then bad "rules for $IR_IP still present"; else ok "no rules for $IR_IP (other rules untouched)"; fi
    (( RM_EVIDENCE )) || log_event cleanup "Lab cleanup done: account, firewall rules and simulation files removed; evidence kept"
else
    echo; echo "Dry run: nothing was changed. Re-run with --apply."
fi
