#!/usr/bin/env bash
# system_monitor.sh: alert on high CPU, memory or disk use and noisy sudo.
#
#   ./system_monitor.sh
#   CPU_THRESHOLD=90 DISK_THRESHOLD=85 ./system_monitor.sh
#
# Exit code: 0 no alerts, 2 alerts raised, 1 script error.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"

CPU_THRESHOLD="${CPU_THRESHOLD:-80}"
MEMORY_THRESHOLD="${MEMORY_THRESHOLD:-80}"
DISK_THRESHOLD="${DISK_THRESHOLD:-90}"
SUDO_THRESHOLD="${SUDO_THRESHOLD:-10}"
WINDOW="${WINDOW:-1 hour ago}"
ALERT_LOG="${ALERT_LOG:-$(default_log_dir)/system_alerts.log}"

for v in CPU_THRESHOLD MEMORY_THRESHOLD DISK_THRESHOLD SUDO_THRESHOLD; do
    is_int "${!v}" || { echo "error: $v must be a whole number, got '${!v}'" >&2; exit 1; }
done
mkdir -p -- "$(dirname -- "$ALERT_LOG")"

alerts=0
alert() {
    alerts=$((alerts + 1))
    printf '%s ALERT system: %s\n' "$(date '+%F %T')" "$1" | tee -a "$ALERT_LOG"
}

# CPU: sample /proc/stat twice, one second apart. Parsing "top" output breaks
# whenever the locale or top version changes the column layout.
cpu_percent() {
    local a b idle1 idle2 total1 total2
    read -ra a < /proc/stat; sleep 1; read -ra b < /proc/stat
    idle1=$(( a[4] + a[5] )); idle2=$(( b[4] + b[5] ))
    total1=0; total2=0
    for i in 1 2 3 4 5 6 7 8; do total1=$(( total1 + a[i] )); total2=$(( total2 + b[i] )); done
    local dt=$(( total2 - total1 ))
    (( dt > 0 )) || { echo 0; return; }
    echo $(( (100 * (dt - (idle2 - idle1))) / dt ))
}

# Memory: use MemAvailable, which counts reclaimable cache as free. "used/total"
# from free(1) overstates pressure on a machine with a big page cache.
mem_percent() {
    awk '/^MemTotal:/ {t=$2} /^MemAvailable:/ {a=$2} END { if (t) printf "%d\n", (t-a)*100/t; else print 0 }' /proc/meminfo
}

cpu="$(cpu_percent)"
mem="$(mem_percent)"
echo "CPU ${cpu}%   memory ${mem}%"
if (( cpu > CPU_THRESHOLD )); then alert "CPU at ${cpu}% (threshold ${CPU_THRESHOLD}%)"; fi
if (( mem > MEMORY_THRESHOLD )); then alert "memory at ${mem}% (threshold ${MEMORY_THRESHOLD}%)"; fi

# Disk: every real filesystem, not only /.
while read -r use mount; do
    use="${use%\%}"
    is_int "$use" || continue
    echo "disk ${mount} ${use}%"
    if (( use > DISK_THRESHOLD )); then alert "disk ${mount} at ${use}% (threshold ${DISK_THRESHOLD}%)"; fi
done < <(df -P -x tmpfs -x devtmpfs -x squashfs -x overlay 2>/dev/null | awk 'NR > 1 {print $5, $6}')

nsudo="$(sudo_log "$WINDOW" | count_matches 'COMMAND=')"
echo "sudo commands since '$WINDOW': $nsudo"
if (( nsudo > SUDO_THRESHOLD )); then alert "$nsudo sudo commands since $WINDOW (threshold $SUDO_THRESHOLD)"; fi

section "Top CPU processes"
ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 6 | sed 's/^/    /'

section "Listening TCP ports"
if have ss; then as_root ss -tlnpH | awk '{printf "    %-28s %s\n", $4, $6}'; fi

if (( alerts == 0 )); then echo; echo "no alerts"; exit 0; fi
echo; echo "$alerts alert(s) written to $ALERT_LOG"
exit 2
