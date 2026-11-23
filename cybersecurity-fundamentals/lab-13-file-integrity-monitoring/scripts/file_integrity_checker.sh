#!/usr/bin/env bash
# file_integrity_checker.sh: hash-based file integrity check (baseline, then compare).
#
#   file_integrity_checker.sh -c|--create [DIR...]   record a baseline
#   file_integrity_checker.sh -s|--scan               compare against the baseline
#   file_integrity_checker.sh -l|--list               show what the baseline covers
#
# With no DIR, --create uses ~/secure_files. --scan re-reads the folders that
# are stored in the baseline, so it needs no arguments.
#
# For every regular file and symlink the baseline stores the SHA-256 hash (or
# the link target), the permission bits and the owner. A scan reports:
#   MODIFIED  content hash changed
#   PERMS     mode changed (e.g. 644 -> 4755, a setuid bit appearing)
#   OWNER     owner or group changed
#   DELETED   in the baseline, gone now
#   NEW       not in the baseline
#
# Exit codes: 0 no changes, 1 changes found, 2 error. That makes it usable from
# cron or a systemd timer, which can alert on a non-zero exit.
#
# Environment:
#   FIM_BASELINE=path   baseline file (default: <state dir>/baseline.tsv)
#   FIM_STATE_DIR=path  where baselines and reports go (see lib.sh)
#   FIM_KEEP_REPORTS=N  reports to keep (default 30)
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

STATE_DIR="$(fim_state_dir)"
BASELINE="${FIM_BASELINE:-$STATE_DIR/baseline.tsv}"
REPORT_DIR="$STATE_DIR/reports"
KEEP_REPORTS="${FIM_KEEP_REPORTS:-30}"

usage() {
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

# Print one TSV line per file: path, hash, mode, owner:group. Sorted by path.
# find -print0 and read -d '' keep names with spaces intact. Names containing a
# tab or newline cannot be stored in TSV, so they are reported, not hidden.
snapshot() {
    local dir p h meta
    for dir in "$@"; do
        find "$dir" -xdev \( -type f -o -type l \) -print0 2> >(sed 's/^/warning: /' >&2) || true
    done | while IFS= read -r -d '' p; do
        if [[ "$p" == *$'\t'* || "$p" == *$'\n'* ]]; then
            echo "warning: skipping name with tab or newline: ${p@Q}" >&2
            continue
        fi
        if [[ -L "$p" ]]; then
            h="link:$(readlink -- "$p")"
        elif [[ -r "$p" ]]; then
            # Hash from stdin: sha256sum escapes odd file names in its output
            # (a leading backslash), which breaks "cut -d' ' -f1" parsing.
            h="$(sha256sum < "$p" | cut -d' ' -f1)"
        else
            h="UNREADABLE"
            echo "warning: cannot read $p (run as root to cover it)" >&2
        fi
        meta="$(stat -c '%a %U:%G' -- "$p" 2>/dev/null || echo '? ?')"
        printf '%s\t%s\t%s\t%s\n' "$p" "$h" "${meta% *}" "${meta#* }"
    done | LC_ALL=C sort
}

create_baseline() {
    local dirs=("$@") d tmp
    (( ${#dirs[@]} )) || dirs=("$(demo_dir)")
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] || die "not a directory: $d"
    done
    private_dir "$(dirname -- "$BASELINE")" >/dev/null
    tmp="$(mktemp "$BASELINE.XXXXXX")"
    {
        printf '# fim-baseline v1\tcreated %s\tby %s on %s\n' "$(date -Is)" "$(id -un)" "$(hostname)"
        for d in "${dirs[@]}"; do printf '# dir\t%s\n' "$(realpath -- "$d")"; done
        local real=()
        for d in "${dirs[@]}"; do real+=("$(realpath -- "$d")"); done
        snapshot "${real[@]}"
    } > "$tmp"
    chmod 600 "$tmp"
    mv -f -- "$tmp" "$BASELINE"

    section "Baseline created"
    info "File:      $BASELINE"
    info "Folders:   ${dirs[*]}"
    info "Entries:   $(grep -vc '^#' "$BASELINE" || true)"
    info "SHA-256 of the baseline itself (write it down somewhere else):"
    info "  $(sha256sum < "$BASELINE" | cut -d' ' -f1)"
}

list_baseline() {
    [[ -f "$BASELINE" ]] || die "no baseline at $BASELINE; run with --create first"
    grep '^#' "$BASELINE" | sed 's/^# //'
    echo "entries: $(grep -vc '^#' "$BASELINE" || true)"
}

check_integrity() {
    [[ -f "$BASELINE" ]] || die "no baseline at $BASELINE; run with --create first"

    local -a dirs=()
    local line
    while IFS= read -r line; do
        [[ "$line" == $'# dir\t'* ]] && dirs+=("${line#*$'\t'}")
    done < "$BASELINE"
    (( ${#dirs[@]} )) || die "baseline lists no folders: $BASELINE"

    # path -> "hash<TAB>mode<TAB>owner" for the baseline and for now.
    local -A old=() cur=()
    local p rest
    while IFS=$'\t' read -r p rest; do
        [[ "$p" == '#'* ]] && continue
        old["$p"]="$rest"
    done < "$BASELINE"
    while IFS=$'\t' read -r p rest; do
        cur["$p"]="$rest"
    done < <(snapshot "${dirs[@]}")

    local -a findings=()
    local oh om oo ch cm co
    for p in "${!old[@]}"; do
        if [[ -z "${cur[$p]+set}" ]]; then
            findings+=("DELETED"$'\t'"$p")
            continue
        fi
        IFS=$'\t' read -r oh om oo <<< "${old[$p]}"
        IFS=$'\t' read -r ch cm co <<< "${cur[$p]}"
        [[ "$oh" != "$ch" ]] && findings+=("MODIFIED"$'\t'"$p"$'\t'"sha256 ${oh:0:12}... -> ${ch:0:12}...")
        [[ "$om" != "$cm" ]] && findings+=("PERMS"$'\t'"$p"$'\t'"mode $om -> $cm")
        [[ "$oo" != "$co" ]] && findings+=("OWNER"$'\t'"$p"$'\t'"$oo -> $co")
    done
    for p in "${!cur[@]}"; do
        # Exact key lookup. The starting code used grep -q "$file", a regex
        # substring match, so a new file whose path is part of an existing one
        # (or matches via ".") was never reported.
        if [[ -z "${old[$p]+set}" ]]; then
            IFS=$'\t' read -r ch cm co <<< "${cur[$p]}"
            findings+=("NEW"$'\t'"$p"$'\t'"mode $cm, $co")
        fi
    done

    private_dir "$REPORT_DIR" >/dev/null
    local report status
    report="$REPORT_DIR/integrity_$(date +%Y%m%d_%H%M%S)_$$.txt"
    {
        echo "File integrity report - $(date -Is) - $(hostname)"
        echo "Baseline: $BASELINE"
        echo "Folders:  ${dirs[*]}"
        echo "Files in baseline: ${#old[@]}   files now: ${#cur[@]}"
        echo
        if (( ${#findings[@]} == 0 )); then
            echo "No changes detected."
        else
            echo "${#findings[@]} change(s):"
            printf '%s\n' "${findings[@]}" | LC_ALL=C sort -t$'\t' -k2,2 -k1,1 \
                | awk -F'\t' '{ printf "  %-9s %s", $1, $2; if ($3 != "") printf "  (%s)", $3; print "" }'
        fi
    } > "$report"
    chmod 600 "$report"
    cat "$report"
    echo
    echo "Report saved: $report"

    # Keep the newest N reports.
    find "$REPORT_DIR" -maxdepth 1 -name 'integrity_*.txt' -printf '%T@ %p\n' \
        | sort -rn | tail -n +"$((KEEP_REPORTS + 1))" | cut -d' ' -f2- \
        | xargs -r rm -f --

    status=0
    (( ${#findings[@]} )) && status=1
    return "$status"
}

case "${1:-}" in
    -c|--create) shift; create_baseline "$@" ;;
    -s|--scan)   check_integrity ;;
    -l|--list)   list_baseline ;;
    *)           usage ;;
esac
