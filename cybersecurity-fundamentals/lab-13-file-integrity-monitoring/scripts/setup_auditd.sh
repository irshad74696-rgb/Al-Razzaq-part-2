#!/usr/bin/env bash
# setup_auditd.sh: check auditd and load the file integrity watch rules.
#
#   setup_auditd.sh              show status and what would be done (changes nothing)
#   setup_auditd.sh --load       load config/50-fim.rules now (lost at reboot)
#   setup_auditd.sh --persist    install into /etc/audit/rules.d/ and load (survives reboot)
#   setup_auditd.sh --remove     remove the persistent file and reload
#
# --load and --persist also add a watch on the demo folder (~/secure_files)
# with key secure_files, covering reads too (-p rwa), as in the lab.
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

RULES_SRC="$FIM_LAB_DIR/config/50-fim.rules"
RULES_DST=/etc/audit/rules.d/50-fim.rules
DEMO_RULES_DST=/etc/audit/rules.d/51-fim-demo.rules
MODE="${1:-status}"

# Print the rules that can be loaded on this machine. A watch fails when the
# parent folder of the path does not exist (no /etc/ssh without openssh-server),
# and auditctl -R stops at the first failing line, silently dropping every rule
# after it. So those lines are skipped here and named on stderr instead.
usable_rules() {
    local line path
    while IFS= read -r line; do
        if [[ "$line" =~ ^-w[[:space:]]+([^[:space:]]+) ]]; then
            path="${BASH_REMATCH[1]}"
            if [[ ! -e "$path" && ! -d "$(dirname -- "$path")" ]]; then
                echo "skipped (parent folder missing): $line" >&2
                continue
            fi
        fi
        printf '%s\n' "$line"
    done < "$RULES_SRC"
}

demo_rule() { printf -- '-w %s -p rwa -k secure_files\n' "$(demo_dir)"; }

status() {
    section "auditd package and service"
    if have auditctl; then
        ok "auditctl found: $(auditctl -v 2>&1 | head -1)"
    else
        bad "auditd not installed: sudo apt install auditd audispd-plugins"
        return 1
    fi
    if have systemctl && systemctl is-active --quiet auditd 2>/dev/null; then
        ok "auditd service is active"
    elif pgrep -x auditd >/dev/null 2>&1; then
        ok "auditd is running (not managed by systemd here)"
    else
        bad "auditd is not running: sudo systemctl enable --now auditd"
    fi
    if have systemctl && systemctl is-enabled --quiet auditd 2>/dev/null; then
        ok "auditd starts at boot"
    fi

    section "Kernel audit status"
    local st enabled lost
    st="$(as_root auditctl -s 2>/dev/null || true)"
    enabled="$(awk '$1=="enabled"{print $2}' <<< "$st")"
    lost="$(awk '$1=="lost"{print $2}' <<< "$st")"
    case "$enabled" in
        1) ok "auditing enabled" ;;
        2) ok "auditing enabled and rules locked (immutable until reboot)" ;;
        *) bad "auditing disabled (enabled=${enabled:-?}): sudo auditctl -e 1" ;;
    esac
    if [[ -n "$lost" && "$lost" != 0 ]]; then
        warn "$lost events lost: raise the backlog with -b in rules.d, or watch fewer paths"
    fi

    section "Loaded rules"
    local n
    n="$(as_root auditctl -l 2>/dev/null | grep -c -- '-k ' || true)"
    info "$n rule(s) with a key are loaded"
    as_root auditctl -l 2>/dev/null | sed 's/^/         /' | head -40
    if [[ -f "$RULES_DST" ]]; then
        ok "persistent rules installed: $RULES_DST"
    else
        info "persistent rules not installed (use --persist)"
    fi

    section "Would load"
    info "from $RULES_SRC: $(usable_rules 2>/dev/null | grep -c '^-w' || true) of $(grep -c '^-w' "$RULES_SRC") watches usable here"
    info "demo folder: $(demo_rule)"
}

load_now() {
    [[ -d "$(demo_dir)" ]] || warn "$(demo_dir) does not exist yet; create it first (see README step 1)"
    section "Loading rules into the kernel"
    local tmp
    tmp="$(mktemp)"
    usable_rules > "$tmp" 2> >(sed 's/^/         /' >&2)
    as_root auditctl -R "$tmp" 2>&1 | sed 's/^/         /' || true
    rm -f -- "$tmp"
    as_root auditctl -w "$(demo_dir)" -p rwa -k secure_files 2>&1 | sed 's/^/         /' || true
    ok "$(as_root auditctl -l | grep -c -- '-k ' || true) keyed rules now loaded"
}

persist() {
    section "Installing persistent rules"
    as_root mkdir -p "$(dirname -- "$RULES_DST")"
    usable_rules | as_root tee "$RULES_DST" >/dev/null
    as_root chmod 640 "$RULES_DST"
    demo_rule | as_root tee "$DEMO_RULES_DST" >/dev/null
    as_root chmod 640 "$DEMO_RULES_DST"
    ok "wrote $RULES_DST and $DEMO_RULES_DST"
    if have augenrules; then
        # augenrules merges rules.d/*.rules into audit.rules and loads it.
        as_root augenrules --load >/dev/null 2>&1 || warn "augenrules --load failed; check: sudo augenrules --check"
    else
        load_now
    fi
    ok "$(as_root auditctl -l | grep -c -- '-k ' || true) keyed rules now loaded"
}

remove() {
    section "Removing persistent rules"
    as_root rm -f -- "$RULES_DST" "$DEMO_RULES_DST"
    if have augenrules; then as_root augenrules --load >/dev/null 2>&1 || warn "augenrules --load failed; check: sudo augenrules --check"; fi
    ok "removed; $(as_root auditctl -l | grep -c -- '-k ' || true) keyed rules still loaded"
}

case "$MODE" in
    status)    status ;;
    --load)    load_now ;;
    --persist) persist ;;
    --remove)  remove ;;
    *)         sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
