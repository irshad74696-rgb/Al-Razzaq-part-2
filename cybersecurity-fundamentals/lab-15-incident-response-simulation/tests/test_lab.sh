#!/usr/bin/env bash
# test_lab.sh: end-to-end test of the whole incident response cycle.
# Needs root, iptables and a throwaway machine or container: it really creates
# the simulated account and firewall rules (and removes them at the end).
#
#   sudo ./tests/test_lab.sh
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../scripts"
(( EUID == 0 )) || { echo "run as root on a test machine"; exit 2; }
export IR_STATE_DIR; IR_STATE_DIR="$(mktemp -d)/case"
export IR_BEACON_SECONDS=5 NO_COLOR=1
IP=203.0.113.66
PASS=0; FAIL=0
check() {  # check "description" command...
    if "${@:2}" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "ok   - $1"
    else FAIL=$((FAIL+1)); echo "FAIL - $1"; fi
}
not() { ! "$@"; }
rules() { iptables -S | grep -v -- '-P '; }

# A rule that is not ours must survive everything below.
iptables -A OUTPUT -d 198.51.100.7/32 -j DROP
before_rules="$(rules)"

"$S/simulate_compromise.sh" >/dev/null
check "simulate dry run creates no account" not getent passwd hacker
"$S/simulate_compromise.sh" --apply >/dev/null
PID="$(cat "$IR_STATE_DIR/simulated.pid")"
check "simulated process is running" kill -0 "$PID"
check "hidden log exists" test -e /tmp/.hidden_log
check "account exists with a usable password" bash -c "passwd -S hacker | grep -q ' P '"
check "a second simulate run is refused for a real (unmarked) account" \
    bash -c "IR_USER=root '$S/simulate_compromise.sh' --apply; [ \$? -eq 2 ]"

"$S/detect_iocs.sh" -k ubuntu > "$IR_STATE_DIR/../detect.out" 2>&1
check "triage exits 1 on HIGH findings" test $? -eq 1
check "triage flags the hidden-output process" grep -q "PID $PID .*hidden file /tmp/.hidden_log" "$IR_STATE_DIR/findings.tsv"
check "triage flags the watchlist IP" grep -q "watchlist IP $IP" "$IR_STATE_DIR/findings.tsv"
check "triage flags the account" grep -q "usable password: hacker" "$IR_STATE_DIR/findings.tsv"
check "triage flags the hidden file" grep -q "hidden file in a temp folder: /tmp/.hidden_log" "$IR_STATE_DIR/findings.tsv"

"$S/contain.sh" >/dev/null
check "contain dry run leaves the firewall alone" test "$(rules)" == "$before_rules"
check "contain dry run leaves the process running" kill -0 "$PID"
check "contain refuses to lock root" bash -c "'$S/contain.sh' --apply --user root --skip-pid --skip-ip; [ \$? -eq 2 ]"
check "contain refuses to block loopback" bash -c "'$S/contain.sh' --apply --ip 127.0.0.1 --skip-pid --skip-user; [ \$? -eq 2 ]"

check "contain --apply succeeds" "$S/contain.sh" --apply
check "process is gone" bash -c "source '$S/lib.sh'; ! is_alive $PID"
check "no beacon left after containment (grandchildren too)" not pgrep -f 'exec 3<>/dev/tcp/203.0.113.66'
check "OUTPUT DROP rule present" iptables -C OUTPUT -d $IP/32 -m comment --comment ir-lab -j DROP
check "INPUT DROP rule present" iptables -C INPUT -s $IP/32 -m comment --comment ir-lab -j DROP
check "account locked (L)" bash -c "passwd -S hacker | grep -q ' L '"
check "account expired" bash -c "chage -l hacker | grep -q 'Account expires.*1970'"
check "process snapshot has the program hash" bash -c "ls '$IR_STATE_DIR'/process_${PID}_*/exe_sha256.txt"
"$S/contain.sh" --apply --skip-pid >/dev/null 2>&1
check "second contain run adds no duplicate rules" test "$(iptables -S OUTPUT | grep -c "$IP")" -eq 1

"$S/collect_evidence.sh" > "$IR_STATE_DIR/../collect.out" 2>&1
A="$(find "$IR_STATE_DIR/evidence" -maxdepth 1 -name 'ir_collection_*.tar.gz' | sort | tail -1)"
check "archive created" test -s "$A"
check "archive hash recorded once" test "$(grep -c "$(basename "$A")" "$IR_STATE_DIR/evidence_hashes.txt")" -eq 1
check "archive paths are relative" bash -c "! tar -tzf '$A' | grep -q '^/'"
check "manifest inside the archive verifies" bash -c "d=\$(mktemp -d); tar -xzf '$A' -C \$d; cd \$d/*/ && sha256sum -c --quiet MANIFEST.sha256"
check "no password hashes in evidence" bash -c "! tar -xzOf '$A' | grep -qE '\\\$(6|y|5)\\\$'"
check "--verify passes on the untouched archive" "$S/collect_evidence.sh" --verify "$A"
cp -p "$A" "$A.bak"; chmod 600 "$A"; printf 'x' >> "$A"
check "--verify catches a tampered archive" not "$S/collect_evidence.sh" --verify "$A"
mv -f "$A.bak" "$A"

"$S/build_report.sh" --analyst "Test" -o "$IR_STATE_DIR/report.md" >/dev/null
check "report written" test -s "$IR_STATE_DIR/report.md"
check "report names the PID" grep -q "PID $PID" "$IR_STATE_DIR/report.md"
check "report has the archive hash" grep -q "$(sha256sum "$A" | cut -c1-64)" "$IR_STATE_DIR/report.md"
check "report has no [PLACEHOLDERS]" not grep -qE '\[[A-Z ]{3,}\]' "$IR_STATE_DIR/report.md"

"$S/cleanup_lab.sh" >/dev/null
check "cleanup dry run keeps the account" getent passwd hacker
"$S/cleanup_lab.sh" --apply >/dev/null
check "cleanup removed the account" not getent passwd hacker
check "cleanup removed only the lab rules" test "$(rules)" == "$before_rules"
check "cleanup kept the evidence" test -s "$A"

iptables -D OUTPUT -d 198.51.100.7/32 -j DROP
rm -rf "$(dirname "$IR_STATE_DIR")"
echo; echo "passed: $PASS  failed: $FAIL"
(( FAIL == 0 ))
