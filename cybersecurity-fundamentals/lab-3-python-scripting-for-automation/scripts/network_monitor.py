#!/usr/bin/env python3
"""Simulated network security monitor.

Generates fake traffic metrics, rates each scan LOW / MEDIUM / HIGH, prints
a short dashboard and appends any non-LOW scan to a log file. Nothing here
touches the real network: the numbers come from random.

Usage:
    python3 network_monitor.py                         # 5 scans, 2 s apart
    python3 network_monitor.py --scans 12 --interval 5
    python3 network_monitor.py --seed 42 --interval 0  # repeatable, no waiting
"""

import argparse
import random
import sys
import time
from datetime import datetime
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LOG = LAB_DIR / "logs" / "network_monitor.log"
LEVEL_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def sample_metrics(rng):
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "connections": rng.randint(50, 200),
        "failed_logins": rng.randint(0, 15),
        "bandwidth_pct": rng.randint(10, 95),
        "suspicious_ips": rng.randint(0, 5),
    }


def assess(m):
    """Return (level, findings). The overall level is the worst single finding."""
    findings = []  # (level, text)
    if m["failed_logins"] > 10:
        findings.append(("HIGH", "High number of failed logins"))
    elif m["failed_logins"] > 5:
        findings.append(("MEDIUM", "Elevated failed logins"))
    if m["suspicious_ips"] > 3:
        findings.append(("HIGH", "Several suspicious IP addresses"))
    elif m["suspicious_ips"] > 0:
        findings.append(("MEDIUM", "Suspicious IP address seen"))
    if m["bandwidth_pct"] > 85:
        findings.append(("MEDIUM", "Unusually high bandwidth (possible flood)"))
    level = max((lvl for lvl, _ in findings), key=LEVEL_RANK.get, default="LOW")
    return level, findings


def show(scan_no, m, level, findings):
    print(f"\n--- Scan {scan_no} at {m['timestamp']}  [{level}] ---")
    print(f"connections={m['connections']}  failed_logins={m['failed_logins']}  "
          f"bandwidth={m['bandwidth_pct']}%  suspicious_ips={m['suspicious_ips']}")
    for lvl, text in findings:
        print(f"  ! {lvl:<6} {text}")
    if not findings:
        print("  no issues")


def log_scan(log_path, m, level, findings):
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{m['timestamp']}] level={level} connections={m['connections']} "
                f"failed_logins={m['failed_logins']} bandwidth={m['bandwidth_pct']}% "
                f"suspicious_ips={m['suspicious_ips']}\n")
        for lvl, text in findings:
            f.write(f"    {lvl}: {text}\n")


def main():
    parser = argparse.ArgumentParser(description="Run a simulated network security monitor.")
    parser.add_argument("--scans", type=int, default=5, help="number of scans (default 5)")
    parser.add_argument("--interval", type=float, default=2, help="seconds between scans (default 2)")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG, help=f"log file (default: {DEFAULT_LOG})")
    parser.add_argument("--seed", type=int, help="random seed, for repeatable output")
    args = parser.parse_args()
    if args.scans < 1 or args.interval < 0:
        parser.error("--scans must be at least 1 and --interval cannot be negative")

    rng = random.Random(args.seed)
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    print(f"Simulated monitor: {args.scans} scans, {args.interval} s apart. Ctrl+C to stop early.")

    try:
        for scan_no in range(1, args.scans + 1):
            m = sample_metrics(rng)
            level, findings = assess(m)
            counts[level] += 1
            show(scan_no, m, level, findings)
            if level != "LOW":
                log_scan(args.log, m, level, findings)
            if scan_no < args.scans:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped by user.")

    total = sum(counts.values())
    print("\n=== Summary for this run ===")
    print(f"Scans: {total}   HIGH: {counts['HIGH']}   MEDIUM: {counts['MEDIUM']}   LOW: {counts['LOW']}")
    if counts["HIGH"] or counts["MEDIUM"]:
        print(f"Details appended to {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
