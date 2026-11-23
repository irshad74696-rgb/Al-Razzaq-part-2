#!/usr/bin/env python3
"""Print the SHA-256 (or another) hash of one or more files.

    python3 hash_calculator.py testfile.txt
    python3 hash_calculator.py -a sha512 *.txt
    python3 hash_calculator.py --compare 3a7bd3e2... downloaded.iso

The output format matches `sha256sum`, so the result can be checked with
`sha256sum -c` as well. Exit status: 0 ok, 1 hash mismatch, 2 file error.
"""

import argparse
import hmac
import sys

from crypto_common import file_hash

ALGORITHMS = ["sha256", "sha512", "sha3_256", "blake2b", "sha1", "md5"]
WEAK = {"md5", "sha1"}


def calculate_sha256(filename):
    """Return the SHA-256 hex digest of a file, or None if it cannot be read."""
    try:
        return file_hash(filename, "sha256")
    except FileNotFoundError:
        print(f"Error: file not found: {filename}", file=sys.stderr)
    except IsADirectoryError:
        print(f"Error: {filename} is a directory", file=sys.stderr)
    except PermissionError:
        print(f"Error: permission denied: {filename}", file=sys.stderr)
    return None


def main():
    parser = argparse.ArgumentParser(description="Hash files for integrity checks.")
    parser.add_argument("files", nargs="+", help="file(s) to hash")
    parser.add_argument("-a", "--algorithm", default="sha256", choices=ALGORITHMS)
    parser.add_argument("-c", "--compare", metavar="HASH",
                        help="expected hash; exit 1 if the file does not match")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also print the digest length")
    args = parser.parse_args()

    if args.algorithm in WEAK:
        print(f"Note: {args.algorithm} is broken for security use (collisions "
              "can be crafted). Shown for comparison only.", file=sys.stderr)
    if args.compare and len(args.files) != 1:
        parser.error("--compare works with exactly one file")

    status = 0
    for name in args.files:
        if args.algorithm == "sha256":
            digest = calculate_sha256(name)
        else:
            try:
                digest = file_hash(name, args.algorithm)
            except OSError as exc:
                print(f"Error: {name}: {exc.strerror}", file=sys.stderr)
                digest = None
        if digest is None:
            status = 2
            continue

        print(f"{digest}  {name}")
        if args.verbose:
            print(f"  {args.algorithm}: {len(digest)} hex characters = "
                  f"{len(digest) * 4} bits")
        if args.compare:
            if hmac.compare_digest(digest, args.compare.strip().lower()):
                print("MATCH: file is identical to the expected hash")
            else:
                print("MISMATCH: file differs from the expected hash")
                status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
