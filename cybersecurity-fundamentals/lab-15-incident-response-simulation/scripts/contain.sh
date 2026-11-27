#!/usr/bin/env bash
# contain.sh: containment for the three lab indicators, dry run by default.
#
#   sudo ./contain.sh                      show the plan, change nothing
#   sudo ./contain.sh --apply              carry it out
#   options: --pid PID  --ip IP  --user NAME  --force  --skip-pid|--skip-ip|--skip-user
#
# Order matters, and differs from the handout on purpose:
#   1. Snapshot the process (command line, program hash, open files, sockets)
#      BEFORE killing it. Once it is gone, that evidence is gone with it.
#   2. Block the IP, so nothing more leaves while the rest happens.
#   3. Freeze the process (SIGSTOP), then kill it (SIGKILL), then verify.
#   4. Lock the account, expire it (a password lock alone does not stop SSH
#      keys), kill its sessions, verify.
#
# Safety: rules are inserted with -I at the top of the chain (an appended -A
# rule never matches if an earlier rule already accepts the traffic), checked
# with -C first so a re-run adds no duplicates, and tagged "ir-lab" so cleanup
# removes exactly these rules. Nothing is ever flushed. Without --force it
# refuses to block loopback, your SSH client or the default gateway, to lock
# root, you or a sudo-group member, or to kill PID 1 or its own ancestors.
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

DRY_RUN=1; FORCE=0; PID=""; IP="$IR_IP"; USERNAME="$IR_USER"
DO_PID=1; DO_IP=1; DO_USER=1
while (( $# )); do
    case "$1" in
        --apply) DRY_RUN=0 ;;
        --dry-run) DRY_RUN=1 ;;
        --force) FORCE=1 ;;
        --pid) PID="${2:?--pid needs a value}"; shift ;;
        --ip) IP="${2:?--ip needs a value}"; shift ;;
        --user) USERNAME="${2:?--user needs a value}"; shift ;;
        --skip-pid) DO_PID=0 ;;
        --skip-ip) DO_IP=0 ;;
        --skip-user) DO_USER=0 ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done
need_root
ir_init
VERIFY="$IR_STATE/containment_verification.txt"
MODE="$([[ $DRY_RUN == 1 ]] && echo "dry run" || echo applying)"
FAILED=0

if [[ -z "$PID" && -s "$IR_PIDFILE" ]]; then PID="$(cat "$IR_PIDFILE")"; fi

# ---------------------------------------------------------------- checks
if (( DO_IP )); then
    is_ipv4 "$IP" || die "not an IPv4 address: $IP"
    if (( ! FORCE )); then
        [[ "$IP" =~ ^(127\.|0\.) ]] && die "refusing to block $IP (loopback); use --force if you really mean it"
        ssh_client="${SSH_CONNECTION:-}"; ssh_client="${ssh_client%% *}"
        [[ -n "$ssh_client" && "$IP" == "$ssh_client" ]] && die "refusing to block $IP: it is your own SSH session"
        gw="$(ip route show default 2>/dev/null | awk '{print $3; exit}')"
        [[ -n "$gw" && "$IP" == "$gw" ]] && die "refusing to block $IP: it is the default gateway"
    fi
fi
if (( DO_USER )); then
    getent passwd "$USERNAME" >/dev/null || { warn "account $USERNAME does not exist; skipping it"; DO_USER=0; }
fi
if (( DO_USER && ! FORCE )) && is_protected_user "$USERNAME"; then
    die "refusing to lock $USERNAME: root, your own account or an admin; use --force if it is compromised"
fi
if (( DO_PID )); then
    if [[ -z "$PID" ]]; then
        warn "no PID given and no simulated PID on file; skipping the process"; DO_PID=0
    elif ! [[ "$PID" =~ ^[0-9]+$ ]]; then
        die "not a PID: $PID"
    elif ! is_alive "$PID"; then
        warn "PID $PID is not running; skipping the process"; DO_PID=0
    elif (( PID == 1 )); then
        die "refusing to kill PID 1"
    else
        a=$$
        while (( a > 1 )); do
            (( a == PID )) && die "refusing to kill PID $PID: it is this script's own parent shell"
            a="$(awk '/^PPid:/{print $2}' "/proc/$a/status" 2>/dev/null || echo 1)"
        done
    fi
fi

section "Containment ($MODE)"
[[ $DRY_RUN == 0 ]] && log_event contain "Containment started (pid=${PID:-none} ip=$IP user=$USERNAME)"

# ---------------------------------------------------------------- 1. snapshot
if (( DO_PID )); then
    echo "Step 1: snapshot PID $PID before it is killed"
    snap="$IR_STATE/process_${PID}_$(date +%Y%m%d_%H%M%S)"
    if [[ $DRY_RUN == 1 ]]; then
        info "would save cmdline, status, environ, open files, sockets and the program's SHA-256 to $snap/"
    else
        private_dir "$snap" >/dev/null
        ps -o pid,ppid,user,lstart,etime,cmd -p "$PID" > "$snap/ps.txt" 2>&1
        tr '\0' ' ' < "/proc/$PID/cmdline" > "$snap/cmdline.txt" 2>/dev/null
        cp "/proc/$PID/status" "$snap/status.txt" 2>/dev/null
        tr '\0' '\n' < "/proc/$PID/environ" > "$snap/environ.txt" 2>/dev/null
        ls -l "/proc/$PID/fd" > "$snap/open_files.txt" 2>&1
        readlink "/proc/$PID/exe" > "$snap/exe_path.txt" 2>&1
        readlink "/proc/$PID/cwd" > "$snap/cwd.txt" 2>&1
        # /proc/PID/exe can be read even if the file was deleted from disk.
        sha256sum < "/proc/$PID/exe" | awk '{print $1}' > "$snap/exe_sha256.txt" 2>/dev/null
        ss -tanp 2>/dev/null | grep -F "pid=$PID," > "$snap/sockets.txt"
        pstree -p "$PID" > "$snap/children.txt" 2>/dev/null || ps --ppid "$PID" -o pid,cmd > "$snap/children.txt"
        (cd "$snap" && sha256sum -- *.txt > SHA256SUMS)
        ok "saved to $snap"
        log_event contain "Saved volatile snapshot of PID $PID to $snap (program SHA-256 $(cat "$snap/exe_sha256.txt"))"
    fi
fi

# ---------------------------------------------------------------- 2. block IP
if (( DO_IP )); then
    echo "Step 2: block $IP in both directions"
    [[ $DRY_RUN == 0 ]] && iptables-save > "$IR_STATE/iptables_before_$(date +%Y%m%d_%H%M%S).rules"
    while read -r spec; do
        read -ra r <<< "$spec"
        if iptables -C "${r[@]}" 2>/dev/null; then
            ok "already in place: iptables -I $spec"
        else
            chain="${r[0]}"
            run iptables -I "$chain" 1 "${r[@]:1}" || FAILED=1
        fi
    done < <(fw_specs "$IP")
    if [[ $DRY_RUN == 0 ]]; then
        iptables-save > "$IR_STATE/iptables_after_$(date +%Y%m%d_%H%M%S).rules"
        log_event contain "Blocked $IP with iptables DROP rules at the top of INPUT and OUTPUT (tag $IR_RULE_TAG)"
        # Prove the block works instead of assuming it: one test connection
        # must fail, and the OUTPUT rule's packet counter must go up.
        count_drops() { iptables -L OUTPUT -n -v -x | awk -v ip="$IP" '$3=="DROP" && $9==ip && /ir-lab/ {print $1; exit}'; }
        before="$(count_drops)"
        if timeout 3 bash -c "exec 3<>/dev/tcp/$IP/$IR_PORT" 2>/dev/null; then
            bad "a test connection to $IP:$IR_PORT still succeeded"; FAILED=1
        else
            after="$(count_drops)"
            if (( ${after:-0} > ${before:-0} )); then
                ok "test connection to $IP:$IR_PORT was dropped (OUTPUT rule packets $before -> $after)"
                log_event contain "Verified block: test connection to $IP:$IR_PORT was dropped by the OUTPUT rule"
            else
                warn "test connection failed, but not at the new rule (counter $before -> $after)"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------- 3. process
if (( DO_PID )); then
    echo "Step 3: stop and kill PID $PID and every process below it"
    kids="$(descendants "$PID" | tr '\n' ' ')"
    run kill -STOP "$PID"
    # shellcheck disable=SC2086  # word splitting of the PID list is intended
    run kill -KILL "$PID" $kids
    if [[ $DRY_RUN == 0 ]]; then
        sleep 0.5
        if is_alive "$PID"; then
            bad "PID $PID is still running"; FAILED=1
        else
            ok "PID $PID is no longer running"
            log_event contain "Killed PID $PID${kids:+ and the processes below it: ${kids% }}"
        fi
    fi
fi

# ---------------------------------------------------------------- 4. account
if (( DO_USER )); then
    echo "Step 4: disable account $USERNAME"
    run usermod -L "$USERNAME"           # puts ! in front of the password hash
    run passwd -l "$USERNAME"            # same lock through passwd; kept as in the handout
    run chage -E 0 "$USERNAME"           # expire the account: blocks SSH key logins too
    run usermod -s /usr/sbin/nologin "$USERNAME"
    if pgrep -u "$USERNAME" >/dev/null 2>&1; then
        run pkill -KILL -u "$USERNAME"
    else
        info "no processes owned by $USERNAME"
    fi
    if [[ $DRY_RUN == 0 ]]; then
        st="$(passwd -S "$USERNAME" | awk '{print $2}')"
        if [[ "$st" == L ]]; then
            ok "passwd -S $USERNAME shows L (locked)"
            log_event contain "Locked and expired account $USERNAME, shell set to nologin"
        else
            bad "passwd -S $USERNAME shows $st, not L"; FAILED=1
        fi
    fi
fi

# ---------------------------------------------------------------- verification
if [[ $DRY_RUN == 0 ]]; then
    {
        echo "# Containment verification, $(now_iso), host $(hostname)"
        if [[ -n "$PID" ]]; then
            echo; echo "\$ ps -p $PID -o pid,cmd"
            if is_alive "$PID"; then ps -p "$PID" -o pid,stat,cmd; else ps -p "$PID" -o pid,stat,cmd >/dev/null 2>&1 && echo "PID $PID is a zombie: dead, waiting for its parent to collect it"; echo "Process $PID is no longer running"; fi
        fi
        echo; echo "\$ iptables -L -n -v | grep $IP"
        iptables -L -n -v | grep -F "$IP" || echo "(no rules)"
        if getent passwd "$USERNAME" >/dev/null; then
            echo; echo "\$ passwd -S $USERNAME"; passwd -S "$USERNAME"
            echo; echo "\$ chage -l $USERNAME | grep 'Account expires'"
            chage -l "$USERNAME" | grep 'Account expires'
        fi
        echo; echo "\$ who"; who || true
    } > "$VERIFY" 2>&1
    chmod 600 "$VERIFY"
    section "Verification"
    sed 's/^/  /' "$VERIFY"
    log_event contain "Containment verified (result saved to $(basename "$VERIFY"))$([[ $FAILED == 1 ]] && echo ' WITH FAILURES')"
else
    echo
    echo "Dry run: nothing was changed. Re-run with --apply to contain."
fi
exit "$FAILED"
