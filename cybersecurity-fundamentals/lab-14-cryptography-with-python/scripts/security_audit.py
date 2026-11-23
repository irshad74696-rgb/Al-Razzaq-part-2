#!/usr/bin/env python3
"""Scan a folder: hash every file and flag common security problems.

    python3 security_audit.py ~/crypto_lab
    python3 security_audit.py /srv/app -o audit.json --exclude .git node_modules
    python3 security_audit.py ~/crypto_lab --baseline old_audit.json

Warnings, by severity:
  HIGH    world-writable files or folders (without the sticky bit), setuid or
          setgid files, private keys or secret.key files other users can read
  MEDIUM  likely secrets left lying around (private keys, .env, secret.key,
          password= / AWS key patterns in small text files), unencrypted
          copies sitting next to an encrypted .enc version
  LOW     duplicate files (same SHA-256), hidden executables
With --baseline, files that are new, changed or gone since an earlier report
are listed too.

Symlinks are recorded but never followed, so a link to / cannot send the scan
across the whole disk. The report is written with mode 600 because it lists
where the secrets are. Exit status: 0 no HIGH warnings, 1 at least one HIGH.
"""

import argparse
import json
import os
import re
import stat
import sys
from collections import defaultdict
from datetime import datetime, timezone

from crypto_common import file_hash, write_private

SECRET_NAMES = {"secret.key", ".env", "id_rsa", "id_ed25519", "id_ecdsa",
                "credentials", ".pgpass", ".netrc"}
SECRET_SUFFIXES = (".key", ".pem", ".p12", ".pfx")
CONTENT_PATTERNS = [
    ("private key block", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key ID", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    # KEY=value or key: "value" lines, as in .env and config files. A value
    # with "(" in it is code (password = getpass(...)), not a literal.
    ("hard-coded password or token", re.compile(
        rb"(?im)^\s*(export\s+)?[\"']?[\w.-]*(password|passwd|pwd|secret|token)[\w.-]*[\"']?\s*[:=]\s*"
        rb"(['\"][^'\"\s]{3,}['\"]|[^\s'\"(]{3,})\s*,?\s*$")),
]
CONTENT_SCAN_LIMIT = 1024 * 1024  # only grep files up to 1 MiB
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


class SecurityAuditor:
    def __init__(self, scan_dir=".", excludes=(), skip_paths=()):
        self.scan_dir = os.path.abspath(scan_dir)
        self.excludes = set(excludes)
        self.skip_paths = {os.path.abspath(p) for p in skip_paths}
        self.report = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "directory": self.scan_dir,
            "files_scanned": 0,
            "file_hashes": {},
            "warnings": [],
            "errors": [],
        }

    def warn(self, severity, check, path, detail):
        self.report["warnings"].append(
            {"severity": severity, "check": check, "path": path, "detail": detail})

    def calculate_hash(self, filepath):
        return file_hash(filepath, "sha256")

    def _check_content(self, path, size):
        if size > CONTENT_SCAN_LIMIT:
            return
        with open(path, "rb") as f:
            data = f.read()
        if b"\0" in data[:8192]:  # binary file
            return
        for label, pattern in CONTENT_PATTERNS:
            if pattern.search(data):
                self.warn("MEDIUM", "secret-in-file", path, f"contains a {label}")

    def _check_name(self, path, name, st):
        lower = name.lower()
        if lower in SECRET_NAMES or lower.endswith(SECRET_SUFFIXES):
            if st.st_mode & 0o044:
                self.warn("HIGH", "readable-secret", path,
                          f"key or secret file is readable by group/others "
                          f"({stat.filemode(st.st_mode)}); chmod 600")
            else:
                self.warn("MEDIUM", "secret-file", path,
                          "key or secret file stored here; keep it out of "
                          "backups and version control")
        if name.startswith(".") and st.st_mode & 0o111:
            self.warn("LOW", "hidden-executable", path,
                      "hidden file with the execute bit set")

    def scan_directory(self):
        for root, dirs, files in os.walk(self.scan_dir, onerror=self._walk_error):
            dirs[:] = sorted(d for d in dirs if d not in self.excludes)
            self._check_dir(root)
            for name in sorted(files):
                path = os.path.join(root, name)
                if path in self.skip_paths:
                    continue
                self._scan_file(path, name)
            for d in dirs:  # os.walk does not descend into symlinked dirs
                p = os.path.join(root, d)
                if os.path.islink(p):
                    self.report["file_hashes"][p] = {"symlink": os.readlink(p)}
        return self.report

    def _walk_error(self, exc):
        self.report["errors"].append(f"{exc.filename}: {exc.strerror}")

    def _check_dir(self, path):
        try:
            mode = os.lstat(path).st_mode
        except OSError:
            return
        if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
            self.warn("HIGH", "world-writable-dir", path,
                      f"anyone can add or delete files here ({stat.filemode(mode)})")

    def _scan_file(self, path, name):
        try:
            st = os.lstat(path)
        except OSError as exc:
            self.report["errors"].append(f"{path}: {exc.strerror}")
            return
        if stat.S_ISLNK(st.st_mode):
            self.report["file_hashes"][path] = {"symlink": os.readlink(path)}
            return
        if not stat.S_ISREG(st.st_mode):
            return  # sockets, FIFOs, devices
        try:
            digest = self.calculate_hash(path)
            self._check_content(path, st.st_size)
        except OSError as exc:
            self.report["errors"].append(f"{path}: {exc.strerror}")
            digest = None
        self.report["file_hashes"][path] = {
            "sha256": digest,
            "size": st.st_size,
            "permissions": stat.filemode(st.st_mode),
            "mode": oct(st.st_mode & 0o7777),
            "uid": st.st_uid,
            "modified": datetime.fromtimestamp(st.st_mtime, timezone.utc)
                                .isoformat(timespec="seconds"),
        }
        self.report["files_scanned"] += 1
        self._check_name(path, name, st)
        self._check_plaintext_twin(path)

    def _check_plaintext_twin(self, path):
        if path.endswith(".enc"):
            base = path[:-4]
            for candidate in (base, base + ".txt"):
                if os.path.isfile(candidate):
                    self.warn("MEDIUM", "plaintext-next-to-encrypted", candidate,
                              f"unencrypted copy next to {os.path.basename(path)}")

    def check_duplicates(self):
        groups = defaultdict(list)
        for path, info in self.report["file_hashes"].items():
            if info.get("sha256") and info["size"] > 0:
                groups[info["sha256"]].append(path)
        dupes = {h: sorted(p) for h, p in groups.items() if len(p) > 1}
        for digest, paths in dupes.items():
            self.warn("LOW", "duplicate", paths[0],
                      f"{len(paths)} identical copies: " + ", ".join(
                          os.path.relpath(p, self.scan_dir) for p in paths))
        self.report["duplicates"] = dupes
        return dupes

    def check_permissions(self):
        for path, info in self.report["file_hashes"].items():
            if "mode" not in info:
                continue
            mode = int(info["mode"], 8)
            if mode & stat.S_IWOTH:
                self.warn("HIGH", "world-writable", path,
                          f"any user can change this file ({info['permissions']})")
            if mode & stat.S_ISUID:
                self.warn("HIGH", "setuid", path,
                          "runs as its owner, whoever starts it")
            if mode & stat.S_ISGID:
                self.warn("HIGH", "setgid", path,
                          "runs with its group, whoever starts it")

    def compare_baseline(self, baseline_file):
        with open(baseline_file, encoding="utf-8") as f:
            old = json.load(f)["file_hashes"]
        new = self.report["file_hashes"]
        changes = {
            "new": sorted(set(new) - set(old)),
            "deleted": sorted(set(old) - set(new)),
            "modified": sorted(p for p in set(new) & set(old)
                               if new[p].get("sha256") != old[p].get("sha256")
                               or new[p].get("mode") != old[p].get("mode")),
        }
        self.report["changes_since_baseline"] = changes
        return changes

    def generate_report(self, output_file):
        self.report["warnings"].sort(
            key=lambda w: (SEVERITY_ORDER[w["severity"]], w["check"], w["path"]))
        counts = defaultdict(int)
        for w in self.report["warnings"]:
            counts[w["severity"]] += 1
        self.report["summary"] = {s: counts[s] for s in SEVERITY_ORDER}
        data = json.dumps(self.report, indent=2) + "\n"
        write_private(output_file, data.encode(), overwrite=True)

        print(f"Security audit of {self.scan_dir}")
        print(f"Files scanned: {self.report['files_scanned']}   "
              f"HIGH {counts['HIGH']}  MEDIUM {counts['MEDIUM']}  LOW {counts['LOW']}")
        for w in self.report["warnings"]:
            rel = os.path.relpath(w["path"], self.scan_dir)
            print(f"  [{w['severity']:<6}] {w['check']:<28} {rel}: {w['detail']}")
        changes = self.report.get("changes_since_baseline")
        if changes:
            for kind in ("new", "modified", "deleted"):
                for p in changes[kind]:
                    print(f"  [{kind.upper():<8}] {os.path.relpath(p, self.scan_dir)}")
        for err in self.report["errors"]:
            print(f"  [ERROR ] {err}")
        print(f"Report saved to {output_file} (mode 600)")
        return counts["HIGH"]


def main():
    parser = argparse.ArgumentParser(description="Hash a folder and flag risky files")
    parser.add_argument("directory", nargs="?", default=".")
    parser.add_argument("-o", "--output",
                        help="report file (default audit_report_<time>.json in "
                             "the current folder)")
    parser.add_argument("--exclude", nargs="*", default=[".git", "__pycache__"],
                        help="folder names to skip")
    parser.add_argument("--baseline", help="earlier report to compare against")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        parser.error(f"{args.directory} is not a directory")
    output = args.output or datetime.now().strftime("audit_report_%Y%m%d_%H%M%S.json")

    auditor = SecurityAuditor(args.directory, args.exclude, skip_paths=[output])
    auditor.scan_directory()
    auditor.check_duplicates()
    auditor.check_permissions()
    if args.baseline:
        auditor.compare_baseline(args.baseline)
    high = auditor.generate_report(output)
    return 1 if high else 0


if __name__ == "__main__":
    sys.exit(main())
