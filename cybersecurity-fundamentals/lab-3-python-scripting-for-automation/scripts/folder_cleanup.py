#!/usr/bin/env python3
"""Find and remove temporary files by extension, then remove empty folders.

SAFE BY DEFAULT: without --delete it only shows what it would remove.

Usage:
    python3 folder_cleanup.py --make-sample            # build ../temp_files to practise on
    python3 folder_cleanup.py                          # dry run on ../temp_files
    python3 folder_cleanup.py ../temp_files --delete   # actually delete
    python3 folder_cleanup.py /var/tmp/myapp --ext tmp cache --no-recursive
"""

import argparse
import os
import sys
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = LAB_DIR / "temp_files"
DEFAULT_EXTENSIONS = ["tmp", "log", "cache", "bak"]

SAMPLE_FILES = [
    "old_log_1.log", "old_log_2.log",
    "temp_file_1.tmp", "temp_file_2.tmp", "temp_file_3.tmp",
    "backup_1.bak", "backup_2.bak",
    "document.txt", "important.pdf",
    "cache_file_1.cache", "cache_file_2.cache",
    "old_backups/backup_2023_01.bak", "old_backups/backup_2023_02.bak",
]


def make_sample(target):
    for rel in SAMPLE_FILES:
        path = target / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    print(f"Created {len(SAMPLE_FILES)} sample files under {target}")


def refuse_dangerous_target(target):
    """Stop before touching /, the home folder, or anything outside it that is a top-level system dir."""
    resolved = target.resolve()
    protected = {Path("/"), Path.home().resolve()}
    protected.update(Path("/" + d) for d in ("bin", "boot", "dev", "etc", "home", "lib",
                                               "opt", "proc", "root", "sbin", "sys", "usr", "var"))
    if resolved in protected:
        sys.exit(f"Refusing to clean {resolved}: point this at a specific folder of temporary files.")


def show_tree(target):
    for root, dirs, files in os.walk(target):
        dirs.sort()
        depth = len(Path(root).relative_to(target).parts)
        print("  " * depth + Path(root).name + "/")
        for name in sorted(files):
            print("  " * (depth + 1) + name)


def find_matches(target, extensions, recursive):
    """Regular files (not symlinks) whose extension is in the list."""
    wanted = {e.lower().lstrip(".") for e in extensions}
    candidates = target.rglob("*") if recursive else target.glob("*")
    return sorted(p for p in candidates
                  if p.is_file() and not p.is_symlink() and p.suffix.lower().lstrip(".") in wanted)


def empty_dirs_after(target, removed):
    """Folders that would be empty once `removed` files are gone, deepest first."""
    removed = set(removed)
    gone_dirs = set()
    for root, dirs, files in os.walk(target, topdown=False):
        root = Path(root)
        if root == target:
            continue
        left = [f for f in files if root / f not in removed]
        left += [d for d in dirs if root / d not in gone_dirs]
        if not left:
            gone_dirs.add(root)
    return sorted(gone_dirs, key=lambda p: len(p.parts), reverse=True)


def main():
    parser = argparse.ArgumentParser(description="Clean temporary files from a folder (dry run by default).")
    parser.add_argument("target", nargs="?", type=Path, default=DEFAULT_TARGET,
                        help=f"folder to clean (default: {DEFAULT_TARGET})")
    parser.add_argument("--ext", nargs="+", default=DEFAULT_EXTENSIONS,
                        help=f"extensions to remove (default: {' '.join(DEFAULT_EXTENSIONS)})")
    parser.add_argument("--no-recursive", dest="recursive", action="store_false",
                        help="only look at the top level of the folder")
    parser.add_argument("--delete", action="store_true",
                        help="really delete; without this flag nothing is removed")
    parser.add_argument("--make-sample", action="store_true",
                        help="create a set of practice files in the target folder and exit")
    args = parser.parse_args()
    target = args.target

    if args.make_sample:
        make_sample(target)
        return 0

    if not target.is_dir():
        print(f"Error: {target} is not a folder.", file=sys.stderr)
        return 1
    refuse_dangerous_target(target)
    target = target.resolve()

    mode = "DELETE" if args.delete else "DRY RUN (nothing will be removed; add --delete to remove)"
    print(f"Target:     {target}\nExtensions: {', '.join(args.ext)}\nMode:       {mode}\n")
    print("Before:")
    show_tree(target)
    print()

    files = find_matches(target, args.ext, args.recursive)
    dirs = empty_dirs_after(target, files) if args.recursive else []
    verb = "Removed" if args.delete else "Would remove"
    errors = 0

    for path in files:
        try:
            if args.delete:
                path.unlink()
            print(f"{verb} file:   {path.relative_to(target)}")
        except OSError as e:
            errors += 1
            print(f"Error removing {path}: {e}", file=sys.stderr)
    for path in dirs:
        try:
            if args.delete:
                path.rmdir()
            print(f"{verb} folder: {path.relative_to(target)}/")
        except OSError as e:
            errors += 1
            print(f"Error removing {path}: {e}", file=sys.stderr)

    print(f"\n{verb}: {len(files)} file(s), {len(dirs)} empty folder(s). Errors: {errors}")
    if args.delete:
        print("\nAfter:")
        show_tree(target)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
