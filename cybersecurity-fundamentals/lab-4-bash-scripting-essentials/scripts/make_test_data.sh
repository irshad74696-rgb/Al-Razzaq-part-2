#!/usr/bin/env bash
# make_test_data.sh: build a small folder of sample files to back up.
#
#   ./make_test_data.sh               -> creates ~/test_data
#   ./make_test_data.sh /tmp/demo     -> creates it somewhere else
set -euo pipefail

target="${1:-$HOME/test_data}"
mkdir -p "$target/subdirectory"

printf 'quarterly figures\n'    > "$target/document1.txt"
printf 'meeting notes\n'        > "$target/document2.txt"
printf 'do not lose this\n'     > "$target/important.txt"
printf 'one level down\n'       > "$target/subdirectory/nested.txt"
printf 'name with spaces\n'     > "$target/file with spaces.txt"   # catches unquoted variables

echo "Sample data ready in $target ($(find "$target" -type f | wc -l) files)"
