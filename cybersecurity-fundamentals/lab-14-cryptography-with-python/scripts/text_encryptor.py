#!/usr/bin/env python3
"""Encrypt and decrypt short text with Fernet (AES-128-CBC + HMAC-SHA256).

    python3 text_encryptor.py demo                 # the lab's interactive demo
    python3 text_encryptor.py keygen               # writes secret.key (mode 600)
    python3 text_encryptor.py encrypt "meet at 6"  # prints a token
    echo "meet at 6" | python3 text_encryptor.py encrypt -
    python3 text_encryptor.py decrypt gAAAAAB...

A Fernet token already contains the IV, a timestamp and an HMAC, so it cannot
be altered without decryption failing. Whoever has secret.key can read every
message, so keep it out of git (it is in .gitignore) and never overwrite it:
an overwritten key means every old token is lost for good.
"""

import argparse
import os
import sys

from cryptography.fernet import Fernet, InvalidToken

from crypto_common import write_private


class TextEncryptor:
    def __init__(self):
        self.key = None

    def generate_key(self):
        self.key = Fernet.generate_key()
        return self.key

    def save_key(self, filename="secret.key", overwrite=False):
        write_private(filename, self.key, overwrite=overwrite)
        print(f"Key saved to {filename} (mode 600). Back it up; without it "
              "nothing encrypted with it can be recovered.", file=sys.stderr)

    def load_key(self, filename="secret.key"):
        try:
            with open(filename, "rb") as f:
                self.key = f.read().strip()
            Fernet(self.key)  # validates length and encoding
        except FileNotFoundError:
            print(f"Error: key file {filename} not found. Run 'keygen' first.",
                  file=sys.stderr)
            self.key = None
        except ValueError:
            print(f"Error: {filename} does not contain a valid Fernet key.",
                  file=sys.stderr)
            self.key = None
        else:
            if os.stat(filename).st_mode & 0o077:
                print(f"Warning: {filename} is readable by other users; "
                      f"run: chmod 600 {filename}", file=sys.stderr)
        return self.key is not None

    def encrypt_text(self, plaintext):
        if self.key is None:
            print("Error: no key loaded", file=sys.stderr)
            return None
        return Fernet(self.key).encrypt(plaintext.encode("utf-8"))

    def decrypt_text(self, encrypted_text, ttl=None):
        if self.key is None:
            print("Error: no key loaded", file=sys.stderr)
            return None
        if isinstance(encrypted_text, str):
            encrypted_text = encrypted_text.encode()
        try:
            return Fernet(self.key).decrypt(encrypted_text, ttl=ttl).decode("utf-8")
        except InvalidToken:
            print("Error: decryption failed (wrong key, token altered, or "
                  "older than --ttl).", file=sys.stderr)
            return None


def demo(enc, key_file):
    if os.path.exists(key_file):
        enc.load_key(key_file)
        print(f"Using existing key in {key_file}")
    else:
        enc.generate_key()
        enc.save_key(key_file)
    plaintext = input("Text to encrypt: ")
    token = enc.encrypt_text(plaintext)
    print(f"\nEncrypted token:\n{token.decode()}\n")
    recovered = enc.decrypt_text(token)
    print(f"Decrypted: {recovered}")
    print("Round trip OK" if recovered == plaintext else "Round trip FAILED")
    return 0 if recovered == plaintext else 1


def main():
    parser = argparse.ArgumentParser(description="Fernet text encryption")
    parser.add_argument("-k", "--key-file", default="secret.key")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("demo", help="interactive round trip (default)")
    kg = sub.add_parser("keygen")
    kg.add_argument("--force", action="store_true",
                    help="replace an existing key (old tokens become unreadable)")
    sub.add_parser("encrypt").add_argument("text", help="text, or - for stdin")
    de = sub.add_parser("decrypt")
    de.add_argument("token", help="token, or - for stdin")
    de.add_argument("--ttl", type=int, help="reject tokens older than N seconds")
    args = parser.parse_args()

    enc = TextEncryptor()
    if args.command in (None, "demo"):
        return demo(enc, args.key_file)
    if args.command == "keygen":
        enc.generate_key()
        try:
            enc.save_key(args.key_file, overwrite=args.force)
        except FileExistsError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        return 0

    if not enc.load_key(args.key_file):
        return 1
    if args.command == "encrypt":
        text = sys.stdin.read().rstrip("\n") if args.text == "-" else args.text
        print(enc.encrypt_text(text).decode())
        return 0
    token = sys.stdin.read().strip() if args.token == "-" else args.token
    result = enc.decrypt_text(token, ttl=args.ttl)
    if result is None:
        return 1
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
