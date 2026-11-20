#!/usr/bin/env bash
# permissions-demo.sh: show, step by step, how chmod changes what can be done
# with a file and with a directory. Works in a throwaway temp folder.
#
# Run it as a NORMAL user. Root ignores read/write permission checks, so the
# "this should fail" steps will succeed when run as root.

set -uo pipefail

work="$(mktemp -d)"
trap 'chmod -R u+rwx "$work" 2>/dev/null; rm -rf "$work"' EXIT
cd "$work"

show() { printf '\n$ %s\n' "$*"; "$@" 2>&1; }

if [[ $EUID -eq 0 ]]; then
    echo "NOTE: running as root, so denied-access steps below will NOT be denied."
fi

echo "== Files =="
printf '#!/usr/bin/env bash\necho "script ran"\n' > tool.sh
show ls -l tool.sh
show ./tool.sh                 # fails: no execute bit yet
show chmod u+x tool.sh
show ./tool.sh                 # works
show chmod 750 tool.sh         # owner rwx, group r-x, others none
show ls -l tool.sh

echo "secret" > key.txt
show chmod 600 key.txt         # typical for private keys and credentials
show ls -l key.txt
show chmod 444 key.txt         # read-only for everyone, including the owner
show sh -c 'echo overwrite > key.txt'   # fails for a normal user

echo
echo "== Directories =="
mkdir vault && echo "inside" > vault/file.txt
show chmod 700 vault
show ls -ld vault
show ls vault                  # works: owner has r and x

show chmod 600 vault           # r without x: names visible, contents unreachable
show ls vault
show cat vault/file.txt

show chmod 100 vault           # x without r: cannot list, but can open a known name
show ls vault
show cat vault/file.txt

show chmod 000 vault           # nothing at all
show ls vault

show chmod 755 vault           # restore
show ls vault

echo
echo "Done. Temp folder $work is removed on exit."
