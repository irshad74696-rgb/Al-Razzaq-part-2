#!/usr/bin/env python3
"""Encrypt and decrypt files with a password (AES-256-CBC, PBKDF2, HMAC).

    python3 file_encryptor.py encrypt secret.txt secret.enc
    python3 file_encryptor.py decrypt secret.enc recovered.txt
    python3 file_encryptor.py encrypt --password-stdin a.txt a.enc < pwfile

The password is asked twice when encrypting and is never echoed. Output files
are written with mode 600 and never overwrite an existing file unless --force
is given. Decryption checks the HMAC first, so a wrong password or a tampered
file is always reported and no partial plaintext is written.
See crypto_common.py for the byte layout of the .enc file.
"""

import argparse
import os
import sys

from crypto_common import (DEFAULT_ITERATIONS, DecryptionError, ask_password,
                           decrypt_bytes, derive_keys, encrypt_bytes,
                           write_private)


class FileEncryptor:
    def __init__(self, iterations=DEFAULT_ITERATIONS):
        self.iterations = iterations

    def derive_key(self, password, salt):
        """Return the 32-byte AES key (the MAC key is the next 32 bytes)."""
        return derive_keys(password, salt, self.iterations)[0]

    def encrypt_file(self, input_file, output_file, password, overwrite=False):
        if os.path.abspath(input_file) == os.path.abspath(output_file):
            print("Error: input and output must be different files", file=sys.stderr)
            return False
        try:
            with open(input_file, "rb") as f:
                data = f.read()
            write_private(output_file, encrypt_bytes(data, password, self.iterations),
                          overwrite=overwrite)
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return False
        print(f"Encrypted {input_file} ({len(data)} bytes) -> {output_file}")
        print("The original is still there. Delete it yourself once you have "
              "checked the encrypted copy decrypts.")
        return True

    def decrypt_file(self, input_file, output_file, password, overwrite=False):
        try:
            with open(input_file, "rb") as f:
                blob = f.read()
            data = decrypt_bytes(blob, password)
            write_private(output_file, data, overwrite=overwrite)
        except DecryptionError as exc:
            print(f"Decryption failed: {exc}", file=sys.stderr)
            return False
        except OSError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return False
        print(f"Decrypted {input_file} -> {output_file} ({len(data)} bytes)")
        return True


def main():
    parser = argparse.ArgumentParser(description="Password-based file encryption")
    parser.add_argument("action", choices=["encrypt", "decrypt"])
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--force", action="store_true", help="overwrite output")
    parser.add_argument("--password-stdin", action="store_true",
                        help="read the password from the first line of stdin")
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS,
                        help=f"PBKDF2 rounds when encrypting (default {DEFAULT_ITERATIONS:,})")
    args = parser.parse_args()
    if args.iterations < 100_000:
        parser.error("--iterations must be at least 100,000")

    try:
        password = ask_password(confirm=args.action == "encrypt",
                                from_stdin=args.password_stdin)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        return 130

    fe = FileEncryptor(args.iterations)
    func = fe.encrypt_file if args.action == "encrypt" else fe.decrypt_file
    return 0 if func(args.input, args.output, password, args.force) else 1


if __name__ == "__main__":
    sys.exit(main())
