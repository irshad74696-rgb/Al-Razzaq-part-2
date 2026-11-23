#!/usr/bin/env python3
"""A small encrypted vault: store files encrypted, get them back verified.

    python3 vault_manager.py store report1.txt
    python3 vault_manager.py list
    python3 vault_manager.py retrieve report1.txt recovered_report.txt
    python3 vault_manager.py verify               # check every blob decrypts
    python3 vault_manager.py remove report1.txt

Each file is encrypted with its own salt and IV (see crypto_common.py) and
saved under a random ID, not its real name, so the vault folder does not show
what is inside it, and a name like "../../etc/passwd" can never turn into a
path. On retrieve, the HMAC is checked first, then the SHA-256 of the result
is compared with the hash recorded at store time.

The vault folder is mode 700 and every file in it mode 600.
Use --vault DIR to pick the folder (default ./secure_vault).
"""

import argparse
import hashlib
import json
import os
import secrets
import sys
from datetime import datetime, timezone

from crypto_common import (DEFAULT_ITERATIONS, DecryptionError, ask_password,
                           decrypt_bytes, derive_keys, encrypt_bytes,
                           file_hash, write_private)


class VaultManager:
    def __init__(self, vault_dir="secure_vault"):
        self.vault_dir = vault_dir
        self.metadata_file = os.path.join(vault_dir, "vault_metadata.json")
        os.makedirs(vault_dir, mode=0o700, exist_ok=True)
        os.chmod(vault_dir, 0o700)
        self.metadata = self._load_metadata()

    def _load_metadata(self):
        try:
            with open(self.metadata_file, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError as exc:
            sys.exit(f"Error: {self.metadata_file} is damaged ({exc}). "
                     "The encrypted blobs are untouched; restore the metadata "
                     "from a backup before storing anything new.")

    def _save_metadata(self):
        data = json.dumps(self.metadata, indent=2, sort_keys=True) + "\n"
        write_private(self.metadata_file, data.encode(), overwrite=True)

    def _blob_path(self, entry):
        return os.path.join(self.vault_dir, entry["id"] + ".enc")

    def calculate_hash(self, filepath):
        return file_hash(filepath, "sha256")

    def derive_key(self, password, salt):
        return derive_keys(password, salt, DEFAULT_ITERATIONS)[0]

    def store_file(self, input_file, password, overwrite=False):
        name = os.path.basename(input_file)
        if name in self.metadata and not overwrite:
            print(f"Error: {name} is already in the vault (use --force to replace)")
            return False
        try:
            with open(input_file, "rb") as f:
                data = f.read()
        except OSError as exc:
            print(f"Error: {exc}")
            return False

        old = self.metadata.get(name)
        entry = {
            "id": secrets.token_hex(16),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "stored": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        write_private(self._blob_path(entry), encrypt_bytes(data, password))
        self.metadata[name] = entry
        self._save_metadata()
        if old:
            os.unlink(self._blob_path(old))
        print(f"Stored {name} ({entry['size']} bytes) as {entry['id']}.enc")
        print(f"  SHA-256 {entry['sha256']}")
        return True

    def _decrypt_entry(self, name, password):
        entry = self.metadata[name]
        with open(self._blob_path(entry), "rb") as f:
            data = decrypt_bytes(f.read(), password)
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise DecryptionError("decrypted, but SHA-256 does not match the "
                                  "hash recorded at store time")
        return data

    def retrieve_file(self, filename, output_path, password, overwrite=False):
        if filename not in self.metadata:
            print(f"Error: {filename} is not in the vault (see 'list')")
            return False
        try:
            data = self._decrypt_entry(filename, password)
            write_private(output_path, data, overwrite=overwrite)
        except DecryptionError as exc:
            print(f"Retrieve failed: {exc}")
            return False
        except OSError as exc:
            print(f"Error: {exc}")
            return False
        print(f"Retrieved {filename} -> {output_path}")
        print("Integrity verified: SHA-256 matches the stored hash")
        return True

    def verify_vault(self, password):
        bad = 0
        for name in sorted(self.metadata):
            try:
                self._decrypt_entry(name, password)
                print(f"OK       {name}")
            except (DecryptionError, OSError) as exc:
                bad += 1
                print(f"FAILED   {name}: {exc}")
        print(f"\n{len(self.metadata)} checked, {bad} failed")
        return bad == 0

    def list_vault(self):
        if not self.metadata:
            print("Vault is empty.")
            return
        print(f"{'File':<28} {'Size':>9}  {'Stored (UTC)':<25}  SHA-256")
        for name, e in sorted(self.metadata.items()):
            print(f"{name:<28} {e['size']:>9}  {e['stored']:<25}  {e['sha256'][:16]}...")
        print(f"\n{len(self.metadata)} file(s) in {os.path.abspath(self.vault_dir)}")

    def remove_file(self, filename):
        entry = self.metadata.pop(filename, None)
        if entry is None:
            print(f"Error: {filename} is not in the vault")
            return False
        try:
            os.unlink(self._blob_path(entry))
        except FileNotFoundError:
            pass
        self._save_metadata()
        print(f"Removed {filename} from the vault")
        return True


def main():
    parser = argparse.ArgumentParser(description="Encrypted file vault")
    parser.add_argument("--vault", default="secure_vault", help="vault folder")
    parser.add_argument("--password-stdin", action="store_true",
                        help="read the password from the first line of stdin")
    sub = parser.add_subparsers(dest="command", required=True)
    st = sub.add_parser("store")
    st.add_argument("files", nargs="+")
    st.add_argument("--force", action="store_true", help="replace same-named entry")
    rt = sub.add_parser("retrieve")
    rt.add_argument("name")
    rt.add_argument("output")
    rt.add_argument("--force", action="store_true", help="overwrite output")
    sub.add_parser("list")
    sub.add_parser("verify")
    sub.add_parser("remove").add_argument("names", nargs="+")
    args = parser.parse_args()

    vault = VaultManager(args.vault)
    if args.command == "list":
        vault.list_vault()
        return 0
    if args.command == "remove":
        return 0 if all([vault.remove_file(n) for n in args.names]) else 1

    try:
        password = ask_password(confirm=args.command == "store",
                                from_stdin=args.password_stdin)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        return 130

    if args.command == "store":
        ok = [vault.store_file(f, password, args.force) for f in args.files]
        return 0 if all(ok) else 1
    if args.command == "retrieve":
        return 0 if vault.retrieve_file(args.name, args.output, password, args.force) else 1
    return 0 if vault.verify_vault(password) else 1


if __name__ == "__main__":
    sys.exit(main())
