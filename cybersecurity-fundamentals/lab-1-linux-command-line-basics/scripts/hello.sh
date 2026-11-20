#!/usr/bin/env bash
# hello.sh: the smallest possible script, used to practise execute permissions.
#
# Try it:
#   ./hello.sh            -> "Permission denied" until the execute bit is set
#   chmod u+x hello.sh    -> give the owner permission to run it
#   ./hello.sh            -> now it runs
#   bash hello.sh         -> also runs without +x, because bash only needs to READ the file

echo "Hello from $(whoami) on $(hostname), running in $(pwd)"
