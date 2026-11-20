#!/usr/bin/env bash
# build-practice-area.sh: recreate the sandbox folder used in this lab, so the
# file-management exercises can be repeated from a clean start.
#
# Usage:  ./build-practice-area.sh [target-dir]     (default: ~/cli-practice)
# Nothing outside the target directory is touched.

set -euo pipefail

target="${1:-$HOME/cli-practice}"

if [[ -e "$target" ]]; then
    echo "Refusing to overwrite: $target already exists. Remove it or pick another path." >&2
    exit 1
fi

mkdir -p "$target"/{notes,archive}
cd "$target"

# Empty files, created in one go
touch alpha.txt beta.txt gamma.txt

# A file written with > (overwrite) and then >> (append)
echo "first line"  >  journal.txt
echo "second line" >> journal.txt

# A multi-line file written with a here-document
cat > notes/why-cli.txt <<'TEXT'
Servers usually have no desktop, only a shell.
Logs, configs and most security tools live in plain text files.
Knowing where you are and what you can touch is step one.
TEXT

# A small project tree built with brace expansion
mkdir -p project/{src,docs,tests}
touch project/README.md project/src/main.py project/docs/manual.txt project/tests/test_main.py

echo "Practice area ready at: $target"
find "$target" | sort
