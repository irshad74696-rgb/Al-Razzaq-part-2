#!/usr/bin/env bash
# shellcheck disable=SC2012  # ls is fine here: every name is a generated timestamp
# test_lab.sh: end-to-end test of the whole forensics workflow.
# Needs root and a throwaway machine or container: it really starts the
# loopback netcat listener and writes into a temporary forensics folder.
#
#   sudo ./tests/test_lab.sh
set -uo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
S="$HERE/../scripts"
(( EUID == 0 )) || { echo "run as root on a test machine"; exit 2; }
TMP="$(mktemp -d)"
export FORENSICS_BASE="$TMP/forensics" FX_SIM_DIR="$TMP/sim" FX_SIM_MINUTES=5 NO_COLOR=1
PASS=0; FAIL=0
check() {  # check "description" command...
    if "${@:2}" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "ok   - $1"
    else FAIL=$((FAIL+1)); echo "FAIL - $1"; fi
}
not() { ! "$@"; }
listening() { ss -Htln "sport = :4444" | grep -q .; }
fw() { iptables -S 2>/dev/null; }
fw_before="$(fw)"

check "port 4444 is free before the test" not listening

# --- staging -------------------------------------------------------------------
"$S/create_test_activities.sh" >/dev/null
check "dry run creates no folder" not test -e "$FX_SIM_DIR"
check "dry run starts no listener" not listening
"$S/create_test_activities.sh" --apply >/dev/null
check "listener is up on 127.0.0.1:4444" bash -c "ss -Htln 'sport = :4444' | grep -q '127.0.0.1:4444'"
check "listener is not on all interfaces" not bash -c "ss -Htln 'sport = :4444' | grep -qE '0.0.0.0:4444|\*:4444'"
check "simulated folder is private (700)" test "$(stat -c %a "$FX_SIM_DIR")" = 700
check "backdoor file carries the marker" grep -q "FORENSICS-LAB SIMULATED" "$FX_SIM_DIR/backdoor.sh"
check "simulated auth log exists" test -s "$FX_SIM_DIR/test_auth.log"
"$S/create_test_activities.sh" --apply >/dev/null
check "second run does not start a second listener" test "$(pgrep -fc -- '-l 127.0.0.1 4444')" -le 2

# --- collection ----------------------------------------------------------------
"$S/forensic_collector.sh" --extra-log "$FX_SIM_DIR/test_auth.log" > "$TMP/collect.out" 2>&1
check "collector exits 0" test $? -eq 0
C="$(ls -d "$FORENSICS_BASE"/automated_collection_* | tail -1)"
ARCH="$(ls "$FORENSICS_BASE"/forensic_collection_*.tar.gz | tail -1)"
check "collection folder is private (700)" test "$(stat -c %a "$C")" = 700
check "ps, ss, passwd and summary were collected" test -s "$C/processes/ps_aux.txt" -a -s "$C/network/connections.txt" -a -s "$C/users/passwd.txt" -a -s "$C/summary.txt"
check "the listener is in the collected sockets" grep -q '127.0.0.1:4444' "$C/network/connections.txt"
check "extra log was copied" test -s "$C/logs/auth/extra/test_auth.log"
# shellcheck disable=SC2016  # the $ signs are literal regex
check "no password hashes in the evidence" not grep -rqE '\$(1|5|6|y|2b)\$' "$C"
check "every command is in the collection log" test "$(wc -l < "$C/collection_log.tsv")" -gt 20
check "per-file manifest verifies" bash -c "cd '$C' && sha256sum -c --quiet MANIFEST.sha256"
check "manifest does not list itself" not grep -q 'MANIFEST.sha256' "$C/MANIFEST.sha256"
check "archive hash verifies" bash -c "cd '$FORENSICS_BASE' && sha256sum -c --quiet '$ARCH.sha256'"
check "archive is read-only (400)" test "$(stat -c %a "$ARCH")" = 400
check "archive holds relative paths" bash -c "tar -tzf '$ARCH' | head -1 | grep -q '^automated_collection_'"

# --- analysis ------------------------------------------------------------------
python3 "$S/forensic_analyzer.py" > "$TMP/analyze.out" 2>&1
check "analyzer exits 1 on HIGH/CRITICAL" test $? -eq 1
A="$(ls -d "$FORENSICS_BASE"/python_analysis_* | tail -1)"
check "analyzer: brute force then success is CRITICAL" grep -q $'^CRITICAL\tauthentication\tbrute force from 203.0.113.50' "$A/findings.tsv"
check "analyzer: injected address is not blamed" not grep -q '"10.9.9.9"' "$A/analysis.json"
check "analyzer: netcat listener found" grep -q 'nc running as root .* in listen or exec mode' "$A/findings.tsv"
check "analyzer: backdoor port found" grep -q 'listener on backdoor port 4444 (loopback only)' "$A/findings.tsv"
check "analyzer: backdoor file found" grep -q "suspicious file name: $FX_SIM_DIR/backdoor.sh" "$A/findings.tsv"
check "analyzer: non-admin sudo found" grep -q 'sudo used by webadmin' "$A/findings.tsv"

"$S/detect_unauthorized.sh" --auth-log "$FX_SIM_DIR/test_auth.log" > "$TMP/detect.out" 2>&1
check "detector exits 1 on HIGH/CRITICAL" test $? -eq 1
D="$(ls -d "$FORENSICS_BASE"/unauthorized_analysis_* | tail -1)"
for pat in 'brute force from 203.0.113.50 (19 failures) followed by a successful login' \
           'nc running as root' 'listener on backdoor port 4444' "suspicious file name: $FX_SIM_DIR/backdoor.sh" \
           'sudo refused for webadmin' 'sudo used by webadmin' 'log injection attempt'; do
    check "detector: $pat" grep -qF "$pat" "$D/findings.tsv"
done
check "detector wrote a summary with recommendations" grep -q 'Recommendations' "$D/summary.txt"

"$S/generate_report.sh" --analyst "Test Analyst" > /dev/null 2>&1
R="$(ls "$FORENSICS_BASE"/reports/forensic_report_*.txt | tail -1)"
for sec in "EXECUTIVE SUMMARY" "DETAILED FINDINGS" "TIMELINE OF EVENTS" "RECOMMENDATIONS" "APPENDIX"; do
    check "report has $sec" grep -q "$sec" "$R"
done
check "report names the analyst" grep -q 'Analyst: *Test Analyst' "$R"
check "report merges findings seen by both tools" grep -q 'live detection + log and data analysis' "$R"
check "report verified the manifest and archive" bash -c "grep -q 'file hashes verified OK' '$R' && grep -q 'archive hash verified OK' '$R'"
check "timeline is in time order" bash -c "sed -n '/TIMELINE OF EVENTS/,/RECOMMENDATIONS/p' '$R' | grep -oE '^  [0-9-]+ [0-9:]+' | sort -c"
python3 "$S/html_report_generator.py" --analyst "Test Analyst" > /dev/null 2>&1
H="$(ls "$FORENSICS_BASE"/reports/forensic_report_*.html | tail -1)"
check "HTML report written, no script tags" bash -c "test -s '$H' && ! grep -qi '<script' '$H'"

# --- tamper check --------------------------------------------------------------
echo "x" >> "$C/processes/ps_aux.txt"
check "manifest catches a changed file" not bash -c "cd '$C' && sha256sum -c --quiet MANIFEST.sha256"
"$S/generate_report.sh" > /dev/null 2>&1
check "report flags the failed verification" grep -q 'VERIFICATION FAILED' "$(ls "$FORENSICS_BASE"/reports/forensic_report_*.txt | tail -1)"

# --- cleanup -------------------------------------------------------------------
"$S/create_test_activities.sh" --cleanup >/dev/null
check "cleanup dry run keeps the listener" listening
"$S/create_test_activities.sh" --cleanup --apply >/dev/null
sleep 1
check "cleanup stops the listener" not listening
check "cleanup removes the simulated folder" not test -e "$FX_SIM_DIR"
check "evidence is kept after cleanup" test -s "$ARCH"
mkdir -p "$FX_SIM_DIR"; echo keep > "$FX_SIM_DIR/real.txt"
"$S/create_test_activities.sh" --cleanup --apply >/dev/null 2>&1
check "cleanup leaves an unmarked folder alone" test -s "$FX_SIM_DIR/real.txt"
"$S/create_test_activities.sh" --apply >/dev/null 2>&1
check "staging refuses to reuse an unmarked folder" not listening
rm -f -- "${FX_SIM_DIR:?}/real.txt"; rmdir -- "$FX_SIM_DIR"

"$S/detect_unauthorized.sh" > "$TMP/detect2.out" 2>&1
D2="$(ls -d "$FORENSICS_BASE"/unauthorized_analysis_* | tail -1)"
check "after cleanup: no backdoor port or netcat findings" not grep -qE 'backdoor port 4444|nc running' "$D2/findings.tsv"
check "the firewall was never touched" test "$(fw)" == "$fw_before"

echo
echo "$PASS passed, $FAIL failed"
rm -rf -- "${TMP:?}"
(( FAIL == 0 ))
