#!/usr/bin/env python3
"""Print a network device inventory from a CSV file as a table.

The CSV has three columns: name, ip_address, status. A header row is
optional. Rows with the wrong number of columns are reported, not skipped
silently.

Usage:
    python3 file_reader.py                      # uses ../data/network_devices.csv
    python3 file_reader.py path/to/devices.csv
"""

import argparse
import csv
import sys
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CSV = LAB_DIR / "data" / "network_devices.csv"
HEADER = ["name", "ip_address", "status"]


def read_devices(csv_path):
    """Return (devices, problems): a list of dicts and a list of warning strings."""
    devices, problems = [], []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for line_no, row in enumerate(csv.reader(f), start=1):
            row = [cell.strip() for cell in row]
            if not row or row == [""]:
                continue  # blank line
            if line_no == 1 and [c.lower() for c in row] == HEADER:
                continue  # header row
            if len(row) != 3:
                problems.append(f"line {line_no}: expected 3 columns, got {len(row)}: {row}")
                continue
            devices.append(dict(zip(HEADER, row)))
    return devices, problems


def print_table(devices):
    print(f"{'Device':<12} | {'IP address':<15} | Status")
    print("-" * 42)
    for d in devices:
        print(f"{d['name']:<12} | {d['ip_address']:<15} | {d['status']}")
    active = sum(1 for d in devices if d["status"].lower() == "active")
    print("-" * 42)
    print(f"{len(devices)} devices, {active} active, {len(devices) - active} not active")


def main():
    parser = argparse.ArgumentParser(description="Show a network device inventory from CSV.")
    parser.add_argument("csv_file", nargs="?", default=DEFAULT_CSV, type=Path,
                        help=f"CSV file to read (default: {DEFAULT_CSV})")
    args = parser.parse_args()

    try:
        devices, problems = read_devices(args.csv_file)
    except FileNotFoundError:
        print(f"Error: '{args.csv_file}' not found.", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: no permission to read '{args.csv_file}'.", file=sys.stderr)
        return 1

    print_table(devices)
    for p in problems:
        print(f"Warning: {p}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
