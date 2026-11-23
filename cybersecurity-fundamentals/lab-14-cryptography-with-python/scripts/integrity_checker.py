#!/usr/bin/env python3
"""Track files by SHA-256 and report when they change.

    python3 integrity_checker.py add testfile.txt [more files...]
    python3 integrity_checker.py verify testfile.txt
    python3 integrity_checker.py verify            # every tracked file
    python3 integrity_checker.py list
    python3 integrity_checker.py update testfile.txt   # accept a change
    python3 integrity_checker.py remove testfile.txt

Paths are stored as absolute paths, so `verify` works from any folder.
Exit status: 0 all unchanged, 1 something changed or is missing, 2 usage error.
Use --db to keep the database somewhere other than ./integrity.json; in real
use it belongs on separate, read-only storage, because an attacker who can
edit a file can usually edit a hash database next to it as well.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

from crypto_common import file_hash, write_private


class IntegrityChecker:
    def __init__(self, db_file="integrity.json"):
        self.db_file = db_file
        self.database = {}
        self.load_database()

    def load_database(self):
        try:
            with open(self.db_file, encoding="utf-8") as f:
                self.database = json.load(f)
        except FileNotFoundError:
            self.database = {}
        except json.JSONDecodeError as exc:
            # Refuse to continue: silently starting over would wipe the
            # baseline, which is exactly what someone hiding a change wants.
            sys.exit(f"Error: {self.db_file} is not valid JSON ({exc}). "
                     "Restore it from a backup, or delete it to start over.")

    def save_database(self):
        data = json.dumps(self.database, indent=2, sort_keys=True) + "\n"
        write_private(self.db_file, data.encode(), overwrite=True)

    def calculate_hash(self, filepath):
        return file_hash(filepath, "sha256")

    @staticmethod
    def _key(filepath):
        return os.path.abspath(filepath)

    def _record(self, path):
        st = os.stat(path)
        return {
            "sha256": self.calculate_hash(path),
            "size": st.st_size,
            "mode": oct(st.st_mode & 0o7777),
            "added": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def add_file(self, filepath, update=False):
        path = self._key(filepath)
        if not os.path.isfile(path):
            print(f"Error: {filepath} is not a readable file")
            return False
        if path in self.database and not update:
            print(f"Already tracked: {filepath} (use 'update' to accept changes)")
            return False
        try:
            self.database[path] = self._record(path)
        except PermissionError:
            print(f"Error: permission denied: {filepath}")
            return False
        self.save_database()
        verb = "Updated" if update else "Added"
        print(f"{verb}: {filepath}  {self.database[path]['sha256'][:16]}...")
        return True

    def verify_file(self, filepath):
        path = self._key(filepath)
        entry = self.database.get(path)
        if entry is None:
            print(f"NOT TRACKED  {filepath}")
            return False
        if not os.path.exists(path):
            print(f"MISSING      {path}")
            return False
        try:
            current = self.calculate_hash(path)
        except PermissionError:
            print(f"UNREADABLE   {path}")
            return False
        mode = oct(os.stat(path).st_mode & 0o7777)

        ok = True
        if current != entry["sha256"]:
            ok = False
            print(f"MODIFIED     {path}")
            print(f"  expected {entry['sha256']}")
            print(f"  found    {current}")
        if mode != entry.get("mode", mode):
            ok = False
            print(f"PERMS        {path}  ({entry['mode']} -> {mode})")
        if ok:
            print(f"OK           {path}")
        return ok

    def verify_all(self):
        if not self.database:
            print("No files tracked yet. Add some with: add <file>")
            return True
        results = [self.verify_file(p) for p in sorted(self.database)]
        bad = results.count(False)
        print(f"\n{len(results)} checked, {bad} changed or missing")
        return bad == 0

    def remove_file(self, filepath):
        path = self._key(filepath)
        if self.database.pop(path, None) is None:
            print(f"Not tracked: {filepath}")
            return False
        self.save_database()
        print(f"Removed from database: {filepath}")
        return True

    def list_files(self):
        if not self.database:
            print("No files tracked.")
            return
        print(f"{'SHA-256 (first 16)':<18}  {'Size':>8}  {'Mode':<6}  {'Added (UTC)':<25}  Path")
        for path, e in sorted(self.database.items()):
            print(f"{e['sha256'][:16]:<18}  {e['size']:>8}  {e.get('mode', '?'):<6}  "
                  f"{e['added']:<25}  {path}")


def main():
    parser = argparse.ArgumentParser(description="SHA-256 file integrity checker")
    parser.add_argument("--db", default="integrity.json", help="database file")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("add", "update", "remove"):
        sub.add_parser(name).add_argument("files", nargs="+")
    sub.add_parser("verify").add_argument("files", nargs="*",
                                          help="default: every tracked file")
    sub.add_parser("list")
    args = parser.parse_args()

    checker = IntegrityChecker(args.db)
    if args.command == "list":
        checker.list_files()
        return 0
    if args.command == "verify":
        if not args.files:
            return 0 if checker.verify_all() else 1
        results = [checker.verify_file(f) for f in args.files]
        return 0 if all(results) else 1

    action = {"add": checker.add_file,
              "update": lambda f: checker.add_file(f, update=True),
              "remove": checker.remove_file}[args.command]
    results = [action(f) for f in args.files]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
