#!/usr/bin/env bash
# test_cron.sh: prove a cron job runs, and record the environment cron gives it.
#
# Schedule it every minute for a few minutes, read ~/cron_test.log, then remove it.
# Comparing its log with `./test_cron.sh` run by hand shows why scripts that work
# in a terminal can fail in cron: PATH, SHELL and the working folder all differ.
LOG="${LOG:-$HOME/cron_test.log}"

{
    echo "=== $(date '+%F %T') run by $(id -un) ==="
    echo "PATH=$PATH"
    echo "SHELL=${SHELL:-unset}  PWD=$PWD  HOME=$HOME"
    if [[ -t 1 ]]; then echo "attached to a terminal"; else echo "no terminal (as under cron)"; fi
} >> "$LOG"
