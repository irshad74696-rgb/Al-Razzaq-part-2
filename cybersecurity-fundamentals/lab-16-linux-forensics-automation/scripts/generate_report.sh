#!/usr/bin/env bash
# generate_report.sh: build one forensic report from the newest collection,
# the newest live detection run and the newest Python analysis.
#
#   sudo ./generate_report.sh --analyst "Irshad Ali"
#   ./generate_report.sh --collection DIR --detection DIR --analysis DIR
#
# Sections: header, executive summary, detailed findings, timeline,
# recommendations, appendix (raw data paths and hash verification).
# Writes FORENSICS_BASE/reports/forensic_report_<time>.txt. Only reads the inputs.
set -uo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

ANALYST="$(analyst_login)"
COLL=""; DET=""; ANA=""
while (( $# )); do
    case "$1" in
        --analyst) ANALYST="${2:?}"; shift 2 ;;
        --base) FORENSICS_BASE="${2:?}"; shift 2 ;;
        --collection) COLL="${2:?}"; shift 2 ;;
        --detection) DET="${2:?}"; shift 2 ;;
        --analysis) ANA="${2:?}"; shift 2 ;;
        -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
done
COLL="${COLL:-$(latest_dir automated_collection_)}"
DET="${DET:-$(latest_dir unauthorized_analysis_)}"
ANA="${ANA:-$(latest_dir python_analysis_)}"
[[ -n "$COLL$DET$ANA" ]] || die "nothing to report under $FORENSICS_BASE: run the collector, detector or analyzer first"

REPORT_DIR="$FORENSICS_BASE/reports"
private_dir "$REPORT_DIR"
umask 077
STAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="$REPORT_DIR/forensic_report_$STAMP.txt"
WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK:?}"' EXIT

# --- Gather findings: severity, category, summary, evidence, source ----------
: > "$WORK/findings.tsv"
[[ -n "$DET" && -s "$DET/findings.tsv" ]] && sed 's/$/\tlive detection/' "$DET/findings.tsv" >> "$WORK/findings.tsv"
[[ -n "$ANA" && -s "$ANA/findings.tsv" ]] && sed 's/$/\tlog and data analysis/' "$ANA/findings.tsv" >> "$WORK/findings.tsv"
rank() { awk -F'\t' 'BEGIN{r["CRITICAL"]=1;r["HIGH"]=2;r["MEDIUM"]=3;r["LOW"]=4;r["INFO"]=5}
                     {print (r[$1]?r[$1]:9) "\t" $0}' | sort -t$'\t' -k1,1n -s | cut -f2-; }
# The two tools word a shared check the same way, so an event found by both
# becomes one finding with both sources and both pieces of evidence.
merge() {
    awk -F'\t' -v OFS='\t' '
        { k = $1 FS $2 FS $3
          if (!(k in src)) { order[++n] = k; src[k] = $5; ev[k] = $4 }
          else if (index(src[k], $5) == 0) { src[k] = src[k] " + " $5; if ($4 != "" && $4 != ev[k]) ev[k] = ev[k] " | " $4 } }
        END { for (i = 1; i <= n; i++) print order[i], ev[order[i]], src[order[i]] }'
}
merge < "$WORK/findings.tsv" | rank > "$WORK/sorted.tsv"
count() { awk -F'\t' -v s="$1" '$1==s' "$WORK/sorted.tsv" | wc -l; }

line() { printf '%*s\n' 72 '' | tr ' ' "$1"; }

# --- Timeline: every timestamped event from every source, oldest first -------
: > "$WORK/timeline.tsv"
add_event() {  # add_event TIME SOURCE TEXT
    local e; e="$(date -d "$1" +%s 2>/dev/null)" || return 0
    printf '%s\t%s\t%s\n' "$e" "$2" "$3" >> "$WORK/timeline.tsv"
}
if [[ -n "$COLL" && -f "$COLL/summary.txt" ]]; then
    add_event "$(sed -n 's/^Started: *//p' "$COLL/summary.txt")" collection "evidence collection started ($(basename -- "$COLL"))"
    add_event "$(sed -n 's/^Finished: *//p' "$COLL/summary.txt")" collection "evidence collection finished"
fi
if [[ -n "$ANA" && -s "$ANA/timeline.tsv" ]]; then
    while IFS=$'\t' read -r t src ev; do add_event "$t" "$src" "$ev"; done < "$ANA/timeline.tsv"
fi
if [[ -n "$DET" && -f "$DET/findings.txt" ]]; then
    t="$(sed -nE 's/.*Time: ([^ ]+) .*/\1/p' "$DET/findings.txt" | head -1)"
    [[ -n "$t" ]] && add_event "$t" detection "live detection run ($(wc -l < "$DET/findings.tsv") findings)"
fi

{
    line "="
    echo "LINUX FORENSIC INVESTIGATION REPORT"
    line "="
    printf '%-16s %s\n' "Report ID:" "FR-$(hostname)-$STAMP" \
        "Report date:" "$(date '+%Y-%m-%d %H:%M:%S %Z')" \
        "System:" "$(hostname) ($(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}"), kernel $(uname -r))" \
        "Analyst:" "$ANALYST" \
        "Collection:" "${COLL:-none}" \
        "Detection run:" "${DET:-none}" \
        "Analysis run:" "${ANA:-none}"
    echo

    echo "1. EXECUTIVE SUMMARY"; line -
    total="$(wc -l < "$WORK/sorted.tsv")"
    printf 'Findings: %s in total. CRITICAL %s, HIGH %s, MEDIUM %s, LOW %s, INFO %s.\n' \
        "$total" "$(count CRITICAL)" "$(count HIGH)" "$(count MEDIUM)" "$(count LOW)" "$(count INFO)"
    echo "Sources: live detection on the running host, and analysis of the collected"
    echo "data. A finding seen by both is listed once with both sources."
    echo
    if (( $(count CRITICAL) + $(count HIGH) )); then
        echo "Most serious:"
        awk -F'\t' '$1=="CRITICAL"||$1=="HIGH" {print "  - [" $1 "] " $3}' "$WORK/sorted.tsv" | sort -u
        echo
        if (( $(count CRITICAL) )); then
            echo "Assessment: evidence of a successful compromise. Treat the host as"
            echo "untrusted until the accounts and processes above are explained."
        else
            echo "Assessment: suspicious activity that needs investigation; no proof yet"
            echo "that an attacker got in."
        fi
    else
        echo "Assessment: no HIGH or CRITICAL findings. Keep this report as a baseline."
    fi
    echo

    echo "2. DETAILED FINDINGS"; line -
    n=0
    while IFS=$'\t' read -r sev cat summ evid src; do
        n=$((n + 1))
        printf '%3d. [%s] %s\n' "$n" "$sev" "$summ"
        printf '     Type:     %s\n' "$cat"
        [[ -n "$evid" ]] && printf '     Evidence: %s\n' "$(cut -c1-300 <<< "$evid")"
        printf '     Source:   %s\n' "$src"
    done < "$WORK/sorted.tsv"
    (( n )) || echo "  none"
    echo

    echo "3. TIMELINE OF EVENTS"; line -
    if [[ -s "$WORK/timeline.tsv" ]]; then
        sort -t$'\t' -k1,1n "$WORK/timeline.tsv" | while IFS=$'\t' read -r e src ev; do
            printf '  %s  %-16s %s\n' "$(date -d "@$e" '+%Y-%m-%d %H:%M:%S')" "[$src]" "$ev"
        done
        echo "  (times in $(date +%Z))"
    else
        echo "  no timestamped events"
    fi
    echo

    echo "4. RECOMMENDATIONS"; line -
    if [[ -s "$WORK/sorted.tsv" ]]; then
        cut -f2 "$WORK/sorted.tsv" | sort -u | while read -r c; do fx_recommendation "$c"; done
    fi
    echo "  - Keep the evidence archive read-only and record its SHA-256 with this report."
    echo "  - Re-run the collector after remediation and compare against this report."
    echo

    echo "5. APPENDIX: RAW DATA AND INTEGRITY"; line -
    if [[ -n "$COLL" ]]; then
        echo "Collection folder: $COLL"
        echo "  files: $(find "$COLL" -type f | wc -l), size: $(du -sh "$COLL" | cut -f1)"
        if [[ -f "$COLL/MANIFEST.sha256" ]]; then
            if (cd "$COLL" && sha256sum -c --quiet MANIFEST.sha256 >/dev/null 2>&1); then
                echo "  MANIFEST.sha256: all $(wc -l < "$COLL/MANIFEST.sha256") file hashes verified OK"
            else
                echo "  MANIFEST.sha256: VERIFICATION FAILED - a collected file changed after collection"
            fi
        fi
        ts="${COLL##*automated_collection_}"
        arch="$FORENSICS_BASE/forensic_collection_$ts.tar.gz"
        if [[ -f "$arch.sha256" ]]; then
            echo "  archive: $arch"
            echo "  archive SHA-256: $(cut -d' ' -f1 "$arch.sha256")"
            if (cd "$FORENSICS_BASE" && sha256sum -c --quiet "$arch.sha256" >/dev/null 2>&1); then
                echo "  archive hash verified OK"
            else
                echo "  archive hash MISMATCH or archive missing"
            fi
        fi
        if [[ -f "$COLL/collection_log.tsv" ]]; then
            bad="$(awk -F'\t' 'NR>1 && $2!="0" {print "    " $2 ": " $4}' "$COLL/collection_log.tsv")"
            [[ -n "$bad" ]] && { echo "  commands that were missing, absent or failed:"; echo "$bad"; }
        fi
        echo "  key files: logs/auth/auth_events.txt, processes/ps_aux.txt, network/connections.txt,"
        echo "             users/login_accounts.txt, files/temp_files.txt, summary.txt"
    fi
    [[ -n "$DET" ]] && echo "Live detection: $DET/findings.txt"
    [[ -n "$ANA" ]] && echo "Analysis: $ANA/analysis.txt, $ANA/analysis.json"
    echo
    line "="
    echo "End of report. Generated by generate_report.sh; nothing in it was typed by hand."
} > "$REPORT_FILE"

chmod 600 "$REPORT_FILE"
print_status "Report generated: $REPORT_FILE"
