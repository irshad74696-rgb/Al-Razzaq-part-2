#!/usr/bin/env bash
# file_manager.sh: practise for loops, while loops, if/elif and case on a test folder.
#
# Run one action and exit (works in scripts and cron):
#   ./file_manager.sh create      make sample files
#   ./file_manager.sh analyze     list files and count them by type
#   ./file_manager.sh organize    move files into per-type subfolders
#   ./file_manager.sh report      show what is in each subfolder
#   ./file_manager.sh clean       delete the test folder
#   ./file_manager.sh all         create, analyze, organize, report
# Or use the interactive menu:
#   ./file_manager.sh menu
#
# TEST_DIR=/tmp/ft ./file_manager.sh all   -> work somewhere other than ~/file_test
set -uo pipefail

TEST_DIR="${TEST_DIR:-$HOME/file_test}"
SUBDIRS=(txt_files log_files config_files backup_files)

create_files() {
    mkdir -p "$TEST_DIR"
    local i
    for i in {1..10}; do                       # brace expansion: 1 2 3 ... 10
        echo "sample text $i" > "$TEST_DIR/testfile$i.txt"
    done
    echo "service started" > "$TEST_DIR/app.log"
    echo "kernel message"  > "$TEST_DIR/system.log"
    echo "port=8080"       > "$TEST_DIR/config.conf"
    echo "old copy"        > "$TEST_DIR/backup.bak"
    echo "no extension"    > "$TEST_DIR/README"
    echo "Created $(find "$TEST_DIR" -maxdepth 1 -type f | wc -l) files in $TEST_DIR"
}

analyze_files() {
    [[ -d "$TEST_DIR" ]] || { echo "Nothing to analyze: run 'create' first"; return 1; }
    local txt=0 log=0 conf=0 bak=0 other=0 bytes=0 file name size

    # Feed the loop with process substitution, not a pipe. With `find | while`,
    # the loop runs in a subshell and every counter is lost when it ends.
    # -print0 with read -d '' also copes with spaces and newlines in names.
    while IFS= read -r -d '' file; do
        name="$(basename -- "$file")"
        size=$(stat -c %s -- "$file")
        bytes=$((bytes + size))
        case "$name" in
            *.txt)  txt=$((txt + 1));   kind="text" ;;
            *.log)  log=$((log + 1));   kind="log" ;;
            *.conf) conf=$((conf + 1)); kind="config" ;;
            *.bak)  bak=$((bak + 1));   kind="backup" ;;
            *)      other=$((other + 1)); kind="other" ;;
        esac
        printf '  %-16s %5d bytes  %s\n' "$name" "$size" "$kind"
    done < <(find "$TEST_DIR" -type f -print0 | sort -z)

    echo "Totals: $txt text, $log log, $conf config, $bak backup, $other other, $bytes bytes"
}

organize_files() {
    [[ -d "$TEST_DIR" ]] || { echo "Nothing to organize: run 'create' first"; return 1; }
    local d file name ext
    for d in "${SUBDIRS[@]}"; do mkdir -p "$TEST_DIR/$d"; done

    for file in "$TEST_DIR"/*; do
        [[ -f "$file" ]] || continue            # skip the subfolders themselves
        name="$(basename -- "$file")"
        # A name with no dot has no extension; ${name##*.} would return the whole name.
        if [[ "$name" == *.* ]]; then ext="${name##*.}"; else ext=""; fi

        if   [[ "$ext" == txt ]];  then d=txt_files
        elif [[ "$ext" == log ]];  then d=log_files
        elif [[ "$ext" == conf ]]; then d=config_files
        elif [[ "$ext" == bak ]];  then d=backup_files
        else
            echo "  left in place: $name"
            continue
        fi
        mv -n -- "$file" "$TEST_DIR/$d/" && echo "  $name -> $d/"
    done
}

report() {
    local d n f
    local -a files
    for d in "${SUBDIRS[@]}"; do
        [[ -d "$TEST_DIR/$d" ]] || continue
        shopt -s nullglob
        files=("$TEST_DIR/$d"/*)                # count with a glob, not `ls | wc -l`
        shopt -u nullglob
        n=${#files[@]}
        echo "$d: $n file(s)"
        for f in "${files[@]}"; do echo "    - $(basename -- "$f")"; done
    done
}

clean() {
    # Refuse anything that could be a disaster if TEST_DIR were set wrongly.
    case "$TEST_DIR" in
        ""|"/"|"$HOME"|"$HOME/") echo "Refusing to delete '$TEST_DIR'"; return 1 ;;
    esac
    rm -rf -- "$TEST_DIR" && echo "Removed $TEST_DIR"
}

menu() {
    local choice
    while true; do
        printf '\n1) create  2) analyze  3) organize  4) report  5) clean  6) quit\nChoice: '
        # read fails at end of input (Ctrl+D or no terminal): leave instead of looping forever.
        read -r choice || { echo; break; }
        case "$choice" in
            1) create_files ;;
            2) analyze_files ;;
            3) organize_files ;;
            4) report ;;
            5) clean ;;
            6|q) break ;;
            *) echo "Pick a number from 1 to 6" ;;
        esac
    done
}

case "${1:-}" in
    create)   create_files ;;
    analyze)  analyze_files ;;
    organize) organize_files ;;
    report)   report ;;
    clean)    clean ;;
    all)      create_files && analyze_files && organize_files && report ;;
    menu)     menu ;;
    *)        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
