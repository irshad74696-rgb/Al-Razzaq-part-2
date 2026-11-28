#!/usr/bin/env bash
# Run the whole workflow in one go, without writing anything into the
# evidence folder:
#
#   ./run_lab.sh                                   # the lab's own samples
#   ./run_lab.sh /home/student/forensics-lab/samples ./case-01
#
# 1. extract every .evtx under <samples>/event-logs   -> <out>/extracted/event-logs/
# 2. extract every hive under <samples>/registry-hives -> <out>/extracted/registry-hives/
# 3. forensic_automation.ps1                          -> <out>/forensic_output/
# 4. analyze_activity.py                              -> <out>/forensic_output/ioc_report.json
#
# PYTHON can point at the interpreter that has python-evtx and
# python-registry (default: ~/forensics-venv/bin/python if it exists).
# Exit status is analyze_activity.py's: 0 clean, 1 high/critical findings.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
samples="${1:-$here/../samples}"
out="${2:-./forensic_case}"

if [[ -z "${PYTHON:-}" ]]; then
    if [[ -x "$HOME/forensics-venv/bin/python" ]]; then
        PYTHON="$HOME/forensics-venv/bin/python"
    else
        PYTHON="python3"
    fi
fi
if ! "$PYTHON" -c 'import Evtx, Registry' 2>/dev/null; then
    echo "error: $PYTHON cannot import python-evtx and python-registry; see the README (virtual environment)" >&2
    exit 2
fi
if ! command -v pwsh >/dev/null 2>&1; then
    echo "error: pwsh (PowerShell 7) is not installed; see the README" >&2
    exit 2
fi
if [[ ! -d "$samples/event-logs" && ! -d "$samples/registry-hives" ]]; then
    echo "error: $samples has neither event-logs/ nor registry-hives/" >&2
    exit 2
fi

umask 077
mkdir -p "$out/extracted/event-logs" "$out/extracted/registry-hives"
out="$(cd "$out" && pwd)"

echo "== 1. Event logs"
shopt -s nullglob
for log in "$samples"/event-logs/*.evtx "$samples"/event-logs/*.EVTX; do
    stem="$(basename "${log%.*}" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9\n' '_')"
    msg="$("$PYTHON" "$here/extract_eventlogs.py" "$log" "$out/extracted/event-logs/${stem}_events.json")"
    echo "   ${msg%%$'\n'*}"
done

echo "== 2. Registry hives"
for hive in "$samples"/registry-hives/*; do
    [[ -f "$hive" ]] || continue
    [[ "$(head -c 4 "$hive")" == "regf" ]] || continue
    name="$(basename "$hive")"
    case "${name^^}" in
        SYSTEM) target="system_hive.json" ;;
        SOFTWARE) target="software_hive.json" ;;
        *) echo "   skipping $name (only SYSTEM and SOFTWARE are summarised; use key mode for others)"; continue ;;
    esac
    msg="$("$PYTHON" "$here/extract_registry.py" "$hive" -o "$out/extracted/registry-hives/$target")"
    echo "   ${msg%%$'\n'*}"
done

echo "== 3. PowerShell analysis"
pwsh -NoProfile -File "$here/forensic_automation.ps1" -DataPath "$out/extracted" -OutputPath "$out/forensic_output"

echo "== 4. Anomaly detection and IOC report"
status=0
"$PYTHON" "$here/analyze_activity.py" --data-dir "$out/forensic_output" || status=$?
echo
echo "Results: $out/forensic_output/ (forensic_report.md, ioc_report.json, ioc_summary.txt)"
exit "$status"
