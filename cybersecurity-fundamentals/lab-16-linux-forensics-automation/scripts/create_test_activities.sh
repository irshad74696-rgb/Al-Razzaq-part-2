#!/usr/bin/env bash
# create_test_activities.sh: stage harmless, clearly labelled "suspicious"
# activity for the detectors to find, and remove it again.
#
#   ./create_test_activities.sh                    # dry run: show the plan
#   sudo ./create_test_activities.sh --apply       # stage it
#   sudo ./create_test_activities.sh --status      # what is staged right now
#   sudo ./create_test_activities.sh --cleanup --apply
#
# What gets staged, all inside FX_SIM_DIR (default /tmp/forensics_lab_sim, mode 700):
#   test_auth.log  simulated sshd/sudo log: a brute force from 203.0.113.50 that
#                  ends in a successful login, sudo by a non-admin, and one
#                  log-injection attempt. Never written to the real auth log.
#   backdoor.sh    a file named like a backdoor that only prints a message
#   a netcat listener on 127.0.0.1:4444 (loopback only), stopped automatically
#                  after FX_SIM_MINUTES minutes (default 60)
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

SIM_IP=203.0.113.50       # TEST-NET-3: reserved for documentation, never a real host
SIM_PORT=4444
SIM_MINUTES="${FX_SIM_MINUTES:-60}"
STATE="$FX_SIM_DIR/state"
TAGFILE="$FX_SIM_DIR/.forensics-lab"

APPLY=0; MODE=create
while (( $# )); do
    case "$1" in
        --apply) APPLY=1 ;;
        --cleanup) MODE=cleanup ;;
        --status) MODE=status ;;
        -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done

say_or_do() {  # describe in dry-run mode, run with --apply
    if (( APPLY )); then printf '  + %s\n' "$1"; else printf '  would: %s\n' "$1"; fi
    (( APPLY ))
}

mode_label() { if (( APPLY )); then echo applying; else echo "dry run"; fi; }

listener_pid() {
    [[ -r "$STATE" ]] || return 1
    local pid
    pid="$(sed -n 's/^pid=//p' "$STATE")"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    # Only a process that is still our listener counts: PIDs get reused.
    tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q -- "-l 127.0.0.1 $SIM_PORT" || return 1
    echo "$pid"
}

port_in_use() { ss -Htln "sport = :$1" 2>/dev/null | grep -q .; }

write_auth_log() {
    local f="$FX_SIM_DIR/test_auth.log" now i t host
    now="$(date +%s)"; host="$(hostname)"
    ts() { date -d "@$1" '+%Y-%m-%dT%H:%M:%S%:z'; }
    {
        echo "# $FX_MARKER log - not real events. Created $(now_iso) by create_test_activities.sh"
        for i in $(seq 1 12); do
            t=$(( now - 600 + i * 7 ))
            echo "$(ts "$t") $host sshd[$((41000 + i))]: Failed password for invalid user admin from $SIM_IP port $((50000 + i)) ssh2"
        done
        for i in $(seq 1 6); do
            t=$(( now - 500 + i * 6 ))
            echo "$(ts "$t") $host sshd[$((41100 + i))]: Failed password for webadmin from $SIM_IP port $((51000 + i)) ssh2"
        done
        # A username chosen to plant a fake source address in the log line.
        # A parser that takes the first "from <ip>" blames 10.9.9.9 instead.
        echo "$(ts $(( now - 440 ))) $host sshd[41150]: Failed password for invalid user test from 10.9.9.9 port 22 from $SIM_IP port 51200 ssh2"
        echo "$(ts $(( now - 430 ))) $host sshd[41160]: Accepted password for webadmin from $SIM_IP port 51210 ssh2"
        echo "$(ts $(( now - 420 ))) $host sshd[41160]: pam_unix(sshd:session): session opened for user webadmin(uid=1050) by webadmin(uid=0)"
        echo "$(ts $(( now - 400 ))) $host sudo:  webadmin : user NOT in sudoers ; TTY=pts/3 ; PWD=/home/webadmin ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        echo "$(ts $(( now - 380 ))) $host sudo: webadmin : TTY=pts/3 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/chmod +x $FX_SIM_DIR/backdoor.sh"
        echo "$(ts $(( now - 360 ))) $host sudo: $(analyst_login) : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update"
        echo "$(ts $(( now - 300 ))) $host sshd[41300]: Accepted publickey for $(analyst_login) from 127.0.0.1 port 52000 ssh2: ED25519 SHA256:simulated"
    } > "$f"
}

create() {
    section "Staging simulated activity ($(mode_label))"
    if [[ -e "$FX_SIM_DIR" && ! -e "$TAGFILE" ]]; then
        die "$FX_SIM_DIR exists and was not made by this script; set FX_SIM_DIR to another path"
    fi
    if say_or_do "create $FX_SIM_DIR (mode 700) with a marker file"; then
        private_dir "$FX_SIM_DIR"
        echo "$FX_MARKER - safe to delete with: $0 --cleanup --apply" > "$TAGFILE"
    fi
    if say_or_do "write $FX_SIM_DIR/test_auth.log (simulated sshd and sudo lines, attacker $SIM_IP)"; then
        write_auth_log
    fi
    if say_or_do "create $FX_SIM_DIR/backdoor.sh (harmless: only prints a message)"; then
        printf '#!/bin/sh\n# %s file. Harmless: it only prints this message.\necho "simulated backdoor, nothing to see"\n' \
            "$FX_MARKER" > "$FX_SIM_DIR/backdoor.sh"
        chmod 700 "$FX_SIM_DIR/backdoor.sh"
    fi

    local nc_bin=""
    for b in nc ncat netcat; do have "$b" && { nc_bin="$b"; break; }; done
    if [[ -z "$nc_bin" ]]; then
        print_warn "no nc/ncat/netcat installed: skipping the listener (sudo apt install -y netcat-openbsd)"
    elif pid="$(listener_pid)"; then
        print_status "listener already running (PID $pid)"
    elif port_in_use "$SIM_PORT"; then
        print_warn "something else already listens on port $SIM_PORT: not starting a listener. Investigate that one!"
    elif say_or_do "start '$nc_bin -l 127.0.0.1 $SIM_PORT' (loopback only, stops by itself after ${SIM_MINUTES} min)"; then
        # Loopback only: the handout's `nc -l 4444` listens on every interface.
        # -k (keep listening) is OpenBSD/ncat only; without it nc exits after one client.
        local k=()
        "$nc_bin" -h 2>&1 | grep -q -- ' -k' && k=(-k)
        setsid timeout "${SIM_MINUTES}m" "$nc_bin" "${k[@]}" -l 127.0.0.1 "$SIM_PORT" \
            </dev/null >/dev/null 2>&1 &
        local npid=$!
        printf 'pid=%s\nport=%s\nstarted=%s\n' "$npid" "$SIM_PORT" "$(now_iso)" > "$STATE"
        sleep 1
        if port_in_use "$SIM_PORT"; then
            print_status "listener up on 127.0.0.1:$SIM_PORT (PID $npid)"
        else
            print_warn "listener did not come up; check '$nc_bin' syntax on this system"
        fi
    fi

    if (( APPLY )); then
        echo
        print_status "Test activities created. Collect with:"
        echo "  sudo ./forensic_collector.sh --extra-log $FX_SIM_DIR/test_auth.log"
        echo "  sudo ./detect_unauthorized.sh --auth-log $FX_SIM_DIR/test_auth.log"
        print_status "Cleanup: sudo $0 --cleanup --apply"
    else
        echo; print_status "Dry run: nothing changed. Add --apply to stage it."
    fi
}

status() {
    section "Simulated activity status"
    if [[ -e "$TAGFILE" ]]; then
        print_status "$FX_SIM_DIR exists:"; ls -la "$FX_SIM_DIR"
    else
        print_status "no staged folder at $FX_SIM_DIR"
    fi
    if pid="$(listener_pid)"; then print_status "listener running, PID $pid"
    else print_status "no listener running"; fi
}

cleanup() {
    section "Cleanup ($(mode_label))"
    local pid
    if pid="$(listener_pid)"; then
        if say_or_do "stop listener PID $pid and its child"; then
            pkill -TERM -P "$pid" 2>/dev/null
            kill -TERM "$pid" 2>/dev/null
        fi
    else
        print_status "no listener of ours is running"
    fi
    if [[ -e "$TAGFILE" ]]; then
        say_or_do "remove $FX_SIM_DIR" && rm -rf -- "${FX_SIM_DIR:?}"
    elif [[ -e "$FX_SIM_DIR" ]]; then
        print_warn "$FX_SIM_DIR has no marker file: leaving it alone"
    fi
    # Leftovers from the handout's version, removed only if they are exactly that.
    if [[ -f /tmp/test_auth.log ]] && ! grep -qv 'Failed password for invalid user admin from 192.168.1.100' /tmp/test_auth.log; then
        say_or_do "remove /tmp/test_auth.log (handout version)" && rm -f /tmp/test_auth.log
    fi
    if [[ -f /tmp/suspicious_test/backdoor.sh ]] && [[ "$(cat /tmp/suspicious_test/backdoor.sh)" == "test backdoor" ]]; then
        say_or_do "remove /tmp/suspicious_test (handout version)" \
            && rm -f /tmp/suspicious_test/backdoor.sh && rmdir /tmp/suspicious_test 2>/dev/null
    fi
    (( APPLY )) || { echo; print_status "Dry run: nothing removed. Add --apply."; }
}

case "$MODE" in
    create) create ;;
    status) status ;;
    cleanup) cleanup ;;
esac
