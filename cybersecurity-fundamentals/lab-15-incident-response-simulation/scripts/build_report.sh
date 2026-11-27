#!/usr/bin/env bash
# build_report.sh: write incident_report.md from what the other scripts
# recorded, so every PID, hash and time in it comes from the case folder
# rather than being typed by hand.
#
#   sudo ./build_report.sh [--analyst "Name"] [--id IR-YYYYMMDD-001] [--severity HIGH] [-o FILE]
#
# Reads: timeline.tsv, findings.tsv, containment_verification.txt,
# process_*/ snapshots, evidence_hashes.txt and chain_of_custody.txt.
# Severity is HIGH when the triage found any HIGH finding, unless overridden.
# Writes <case folder>/reports/incident_report_<time>.md (or -o FILE).
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ANALYST="$(analyst_login)"; ID=""; SEV=""; OUTFILE=""
while (( $# )); do
    case "$1" in
        --analyst) ANALYST="${2:?}"; shift ;;
        --id) ID="${2:?}"; shift ;;
        --severity) SEV="${2:?}"; shift ;;
        -o) OUTFILE="${2:?}"; shift ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
    shift
done
ir_init
T="$IR_TIMELINE"; F="$IR_STATE/findings.tsv"; V="$IR_STATE/containment_verification.txt"
[[ -s "$F" ]] || die "no findings yet: run detect_iocs.sh first"

first_time() { awk -F'\t' -v p="$1" -v m="$2" 'NR>1 && $2==p && index($4,m){print $1; exit}' "$T"; }
last_time()  { awk -F'\t' -v p="$1" -v m="$2" 'NR>1 && $2==p && index($4,m){t=$1} END{print t}' "$T"; }

DETECTED="$(first_time detect 'Triage started')"
[[ -n "$DETECTED" ]] || DETECTED="$(now_iso)"
[[ -n "$ID" ]] || ID="IR-$(date -d "${DETECTED% *}" +%Y%m%d 2>/dev/null || date +%Y%m%d)-001"
n_high="$(awk -F'\t' '$1=="HIGH"' "$F" | wc -l)"
n_med="$(awk -F'\t' '$1=="MEDIUM"' "$F" | wc -l)"
n_low="$(awk -F'\t' '$1=="LOW"' "$F" | wc -l)"
if [[ -z "$SEV" ]]; then
    if (( n_high > 0 )); then SEV=HIGH; elif (( n_med > 0 )); then SEV=MEDIUM; else SEV=LOW; fi
fi

PID="$(awk -F'\t' 'index($4,"Killed PID "){split($4,a," "); print a[3]}' "$T" | tail -1)"
[[ -n "$PID" ]] || PID="$(cat "$IR_PIDFILE" 2>/dev/null)"
shopt -s nullglob
snaps=("$IR_STATE"/process_"${PID}"_*/)
shopt -u nullglob
SNAP=""
(( ${#snaps[@]} )) && SNAP="${snaps[-1]%/}"
CMD="$( [[ -n "$SNAP" ]] && sed 's/ *$//' "$SNAP/cmdline.txt")"
EXEHASH="$( [[ -n "$SNAP" ]] && cat "$SNAP/exe_sha256.txt")"
EVLINE="$(tail -1 "$IR_STATE/evidence_hashes.txt" 2>/dev/null)"
EVHASH="${EVLINE%%  *}"; EVFILE="${EVLINE#*  }"
BLOCKED="$(grep -c 'DROP' "$V" 2>/dev/null)"

EXEPATH="$( [[ -n "$SNAP" ]] && cat "$SNAP/exe_path.txt")"
if awk -F'\t' '$2=="network"' "$F" | grep -q .; then
    NETHOW="\`ss -tanp\` showed the process's connection attempts"
else
    NETHOW="The address is hard-coded in the process's command line; no attempt was in flight when \`ss\` ran"
fi
mkdir -p "$IR_STATE/reports"
OUTFILE="${OUTFILE:-$IR_STATE/reports/incident_report_$(date +%Y%m%d_%H%M%S).md}"

findings_of() {  # findings_of CATEGORY -> markdown bullets
    awk -F'\t' -v c="$1" '$2==c {printf "- **%s** %s\n", $1, $3}' "$F" | sed 's/`/'"'"'/g'
}

{
cat <<HDR
# Incident Response Report

| | |
| --- | --- |
| **Incident ID** | $ID |
| **Date/time detected** | $DETECTED |
| **Analyst** | $ANALYST |
| **Host** | $(hostname) ($(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-Linux}"), kernel $(uname -r)) |
| **Severity** | $SEV ($n_high high, $n_med medium, $n_low low findings) |
| **Status** | Contained; evidence preserved |

## Executive summary

A monitoring alert reported unusual outbound traffic from this host. Triage found a detached shell loop writing to a hidden file in \`/tmp\` and repeatedly trying to connect to $IR_IP on port $IR_PORT, and an unrecognised login account \`$IR_USER\` with a usable password. The process was snapshotted and killed, the IP was blocked in both directions, and the account was locked and expired. Evidence was collected and hashed before the report was written. No data loss has been confirmed; the root cause (how the process and account were created) still needs to be established.

## Indicators of compromise

| Type | Indicator | How it was found |
| --- | --- | --- |
| Process | PID ${PID:-unknown}: \`${CMD:-see processes_tree.txt}\` | Output redirected to a hidden file in /tmp (\`/proc/PID/fd\`), parent PID 1 |
| Network | Outbound TCP to $IR_IP:$IR_PORT | $NETHOW |
| Account | \`$IR_USER\` (no home folder, login shell, password status P) | Not on the list of known accounts; \`getent passwd $IR_USER\` |
| File | \`$IR_HIDDEN_LOG\` | Hidden file search in /tmp, /var/tmp, /dev/shm |
HDR
[[ -n "$EXEHASH" ]] && echo "| Program hash | \`$EXEHASH\` (SHA-256 of \`${EXEPATH:-?}\`, read through /proc/$PID/exe) | Saved before the kill. If it matches the packaged program, the attacker used a tool already on the system (living off the land) |"

echo
echo "### All triage findings"
echo
for c in process network account auth file persistence; do
    out="$(findings_of "$c")"
    [[ -n "$out" ]] && { echo "**$c**"; echo; echo "$out"; echo; }
done

cat <<CONT
## Containment actions taken

1. Saved a snapshot of PID ${PID:-?} (command line, environment, open files, sockets, program hash) to \`$( [[ -n "$SNAP" ]] && basename "$SNAP")\`, then stopped (SIGSTOP) and killed (SIGKILL) it and its children.
2. Blocked $IR_IP with iptables DROP rules inserted at the top of INPUT and OUTPUT, tagged \`$IR_RULE_TAG\` for exact removal. Rules were saved before and after.
3. Locked (\`usermod -L\`, \`passwd -l\`) and expired (\`chage -E 0\`) the account \`$IR_USER\`, set its shell to nologin and killed its processes. Expiry matters because a password lock alone does not stop an SSH key login.

### Verification

\`\`\`text
$(cat "$V" 2>/dev/null || echo "containment_verification.txt not found: run contain.sh --apply")
\`\`\`

$( (( BLOCKED >= 2 )) && echo "Both DROP rules are present." ) $(awk -F'\t' 'index($4,"Verified block")' "$T" | tail -1 | cut -f4 | sed 's/^Verified block: /After the rules went in, a /; s/$/./')

## Evidence collected

| Item | Value |
| --- | --- |
| Archive | \`${EVFILE:-not collected}\` |
| SHA-256 | \`${EVHASH:-not collected}\` |
| Location | \`$IR_STATE/evidence/\` (mode 700, archive mode 400) |
| Integrity check | \`collect_evidence.sh --verify <archive>\` recomputes the hash and compares it with evidence_hashes.txt |

Chain of custody:

\`\`\`text
$(cat "$IR_STATE/chain_of_custody.txt" 2>/dev/null)
\`\`\`

## Timeline of events

All times are local time on the host, from the case timeline written by each script as it ran. Rows marked *simulate* are the staged attacker activity for this exercise.

| Time | Phase | Event |
| --- | --- | --- |
CONT
awk -F'\t' 'NR>1 {gsub(/\|/,"/",$4); printf "| %s | %s | %s |\n", $1, $2, $4}' "$T"

cat <<REC

## Recommendations

1. Find the entry point: review how \`$IR_USER\` was created (\`useradd\` entries in the auth log, the shell history of every administrator) and what started the loop (its parent was PID 1, so it was detached from a shell or service).
2. Rotate credentials for every account that logged in to this host during the window, and review \`authorized_keys\` for all users.
3. Keep egress filtering: allow outbound traffic only to the destinations the host needs, so a beacon like this one fails by default.
4. Make \`/tmp\` and \`/dev/shm\` \`noexec,nosuid,nodev\` and alert on hidden files there.
5. Ship auth logs and audit events to a central log server so an attacker on the host cannot erase them.
6. Add the program hash and $IR_IP to the blocklist and watchlist used by monitoring.

## Next steps

- [ ] Analyse the process snapshot and any recovered program (malware analysis)
- [ ] Review all firewall rules, not only the two added here
- [ ] Check other hosts for the same indicators ($IR_IP, account \`$IR_USER\`, hidden files in /tmp)
- [ ] Move the evidence archive to access-controlled storage and record the transfer in the chain of custody
- [ ] Update the incident response and account-creation policies with what was learned
REC
} > "$OUTFILE"
chmod 600 "$OUTFILE"
log_event report "Incident report written: $(basename -- "$OUTFILE")"
echo "Report written: $OUTFILE"
if grep -qE '\[[A-Z ]{3,}\]' "$OUTFILE"; then
    warn "the report still contains a [PLACEHOLDER]"
fi
