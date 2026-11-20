#!/usr/bin/env python3
"""Append timestamped security events to a log file.

With no options it writes a set of sample events. Use --event to log one
event of your own.

Usage:
    python3 log_writer.py                         # sample events -> ../logs/security.log
    python3 log_writer.py --event WARNING "Port scan from 10.0.0.5"
    python3 log_writer.py --log /tmp/test.log
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LOG = LAB_DIR / "logs" / "security.log"
LEVELS = ("INFO", "WARNING", "ERROR", "CRITICAL")

SAMPLE_EVENTS = [
    ("INFO", "User admin logged in successfully"),
    ("WARNING", "Failed login attempt from 192.168.1.100"),
    ("ERROR", "Unauthorized access attempt detected"),
    ("INFO", "Firewall rule updated"),
    ("CRITICAL", "Multiple failed login attempts, account locked"),
]


def write_event(log_path, level, message):
    """Append one line like: [2026-11-20 08:15:02] WARNING: message"""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {level}: {message}\n")


def main():
    parser = argparse.ArgumentParser(description="Append security events to a log file.")
    parser.add_argument("--log", type=Path, default=DEFAULT_LOG,
                        help=f"log file to append to (default: {DEFAULT_LOG})")
    parser.add_argument("--event", nargs=2, metavar=("LEVEL", "MESSAGE"),
                        help=f"log a single event; LEVEL is one of {', '.join(LEVELS)}")
    args = parser.parse_args()

    if args.event:
        level = args.event[0].upper()
        if level not in LEVELS:
            parser.error(f"LEVEL must be one of {', '.join(LEVELS)}")
        events = [(level, args.event[1])]
    else:
        events = SAMPLE_EVENTS

    try:
        for level, message in events:
            write_event(args.log, level, message)
            print(f"logged {level:<8} {message}")
    except OSError as e:
        print(f"Error writing to {args.log}: {e}", file=sys.stderr)
        return 1

    print(f"{len(events)} event(s) appended to {args.log}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
