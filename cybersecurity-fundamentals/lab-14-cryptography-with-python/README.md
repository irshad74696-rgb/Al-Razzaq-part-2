# Lab 14: Cryptography with Python

Using Python's `hashlib` and the `cryptography` library to protect files: SHA-256 to prove a file has not changed, AES to keep it secret, and both together in a small encrypted vault and a folder audit tool.

| Primitive | Gives you | Does **not** give you |
| --- | --- | --- |
| **SHA-256 hash** | Integrity: any change to a file, even one bit, gives a completely different 64-character fingerprint | Secrecy. Anyone can compute a hash, so an attacker who changes a file can also recompute its hash |
| **AES encryption** | Confidentiality: without the key the data is unreadable | Integrity on its own. In CBC mode, a wrong password or an altered file can decrypt to garbage *without any error* (measured below) |
| **HMAC / authenticated encryption** (Fernet, or AES-CBC + HMAC-SHA256 here) | Both: the data is secret, and any change or wrong key is detected before plaintext is used | Key management. Lose the key or password and the data is gone; leak it and the data is readable |

**Why this matters for security work:** hashes are how you check a download, build a file integrity baseline, match malware samples (VirusTotal looks files up by SHA-256), and preserve evidence in an investigation. Encryption at rest is a requirement in PCI DSS, HIPAA and most data protection laws. And the most common real-world crypto bugs are not broken algorithms but mistakes in how they are used: no integrity check, a key file anyone can read, a key that gets overwritten. Section 6 lists the ones I fixed.

## Contents

1. [Files in this folder](#1-files-in-this-folder)
2. [SHA-256 hashing and the integrity checker](#2-sha-256-hashing-and-the-integrity-checker)
3. [Text encryption with Fernet](#3-text-encryption-with-fernet)
4. [Password-based file encryption](#4-password-based-file-encryption)
5. [Vault manager and security audit](#5-vault-manager-and-security-audit)
6. [Problems I fixed compared with the starting code](#6-problems-i-fixed-compared-with-the-starting-code)
7. [Troubleshooting](#7-troubleshooting)
8. [How I tested it](#8-how-i-tested-it)
9. [Takeaway](#9-takeaway)

## 1. Files in this folder

| File | What it does |
| --- | --- |
| [`scripts/crypto_common.py`](scripts/crypto_common.py) | Shared code: chunked hashing, PBKDF2 key derivation, AES-256-CBC + HMAC-SHA256 encrypt and decrypt, private atomic file writes, password prompt |
| [`scripts/hash_calculator.py`](scripts/hash_calculator.py) | SHA-256 (or SHA-512, SHA3, BLAKE2, and MD5/SHA-1 for comparison) of one or more files, `sha256sum`-compatible output, `--compare` against an expected hash |
| [`scripts/integrity_checker.py`](scripts/integrity_checker.py) | `add`, `verify`, `update`, `remove`, `list`: a JSON database of hashes, sizes and permissions; exit 1 when something changed |
| [`scripts/text_encryptor.py`](scripts/text_encryptor.py) | Fernet text encryption: `demo` (the lab's round trip), `keygen`, `encrypt`, `decrypt`, optional `--ttl` |
| [`scripts/file_encryptor.py`](scripts/file_encryptor.py) | Encrypt or decrypt a file with a password |
| [`scripts/vault_manager.py`](scripts/vault_manager.py) | `store`, `retrieve`, `list`, `verify`, `remove`: encrypted files under random IDs, SHA-256 checked on the way out |
| [`scripts/security_audit.py`](scripts/security_audit.py) | Hashes every file in a folder and flags world-writable files, setuid/setgid, readable key files, secrets in config files, plaintext next to `.enc` copies, duplicates; `--baseline` shows what changed since an earlier report |
| [`tests/test_lab.py`](tests/test_lab.py) | 19 end-to-end tests that run the real scripts in a temporary folder |
| [`tests/cbc_without_mac_demo.py`](tests/cbc_without_mac_demo.py) | Shows why the lab's original file format needed an integrity check |
| [`samples/sample-session.txt`](samples/sample-session.txt) | Output of the lab's test steps, run with these scripts |
| [`samples/sample-audit-report.json`](samples/sample-audit-report.json) | A full `security_audit.py` report of the lab folder |
| [`requirements.txt`](requirements.txt) | `cryptography>=42` |

Setup:

```bash
mkdir ~/crypto_lab && cd ~/crypto_lab
cp /path/to/this/folder/scripts/*.py .
python3 -m venv .venv && . .venv/bin/activate     # Ubuntu 23.04+ blocks system-wide pip
pip install -r /path/to/this/folder/requirements.txt
python3 -c "import cryptography; print(cryptography.__version__)"
```

On Ubuntu you can also use `sudo apt install python3-cryptography` instead of a virtual environment. `pip3 install cryptography` on its own fails there with `externally-managed-environment`.

## 2. SHA-256 hashing and the integrity checker

```bash
echo "Original content for testing" > testfile.txt
python3 hash_calculator.py -v testfile.txt
# f6224e122c8201d490de63dd4fa8679a8120047bf78b42272cb5618b2b53c133  testfile.txt
#   sha256: 64 hex characters = 256 bits
sha256sum testfile.txt          # same value: a good check that the script is right
```

The file is read in 4096-byte chunks, so a 4 GB ISO is hashed with a few KB of memory. Output is in `sha256sum` format, so `python3 hash_calculator.py *.txt > SHA256SUMS` can later be checked with `sha256sum -c SHA256SUMS`. `--compare <hash>` checks a download against the hash published by the vendor and exits 1 on a mismatch; the comparison uses `hmac.compare_digest`, which takes the same time wherever the difference is.

The integrity checker keeps a baseline:

```bash
python3 integrity_checker.py add testfile.txt
python3 integrity_checker.py verify testfile.txt     # OK, exit 0
echo "Modified" >> testfile.txt
python3 integrity_checker.py verify testfile.txt     # MODIFIED, exit 1
```

```
MODIFIED     /home/student/crypto_lab/testfile.txt
  expected f6224e122c8201d490de63dd4fa8679a8120047bf78b42272cb5618b2b53c133
  found    be464f88eb11b596fa089dad03d2e9552fc25ec3e4e8d8638ee2f076592ebce9
```

Adding one word changed every character of the hash: that is the avalanche effect. `verify` with no file name checks everything in the database, and permission changes (`chmod 4755`) are reported as `PERMS` even when the content is the same. After reviewing a change you accept it with `update`.

Where the database lives matters. `integrity.json` next to the files it protects is fine for the lab, but someone who can change a file can usually change the hash next to it too. In real use the baseline goes on read-only media or another machine, or is signed (see [File integrity monitoring](../lab-13-file-integrity-monitoring/README.md) for the auditd side of this).

## 3. Text encryption with Fernet

```bash
python3 text_encryptor.py              # the lab's demo: makes secret.key, asks for text, encrypts, decrypts
python3 text_encryptor.py encrypt "meet at 6"
# gAAAAABrBM_-4RKBHSb12LAZ26ZeUuYtyqcgco6l...
python3 text_encryptor.py decrypt gAAAAABrBM_-4RKBHSb12LAZ26ZeUuYtyqcgco6l...
# meet at 6
```

Fernet is a recipe, not a single algorithm: AES-128 in CBC mode, a random IV, a timestamp, and an HMAC-SHA256 over all of it. The token starts with `gAAAAA` because the first byte is the version (0x80) and the next eight are the time it was made. Changing one character of the token, or using another key, gives `InvalidToken` rather than wrong text. `--ttl 3600` refuses tokens older than an hour, which is useful for things like password-reset links.

`secret.key` is written with mode 600, and `keygen` refuses to replace an existing key: a new key means every old token can never be decrypted again.

## 4. Password-based file encryption

```bash
echo "Confidential data" > secret.txt
python3 file_encryptor.py encrypt secret.txt secret.enc     # asks for the password twice
python3 file_encryptor.py decrypt secret.enc recovered.txt
cat recovered.txt
# Confidential data
```

A password is not a key: it is short and guessable. **PBKDF2-HMAC-SHA256** turns it into a key by hashing it hundreds of thousands of times with a random salt, so every guess costs an attacker the same work, and the same password gives a different key in every file. The lab asked for 100,000 rounds; I used 600,000, the current OWASP recommendation, which costs about 0.3 seconds per encrypt on my test machine. The count is stored in the file, so it can be raised later without breaking old files.

The file format:

```
"PYC1" | iterations (4 bytes) | salt (16) | IV (16) | AES-256-CBC ciphertext | HMAC-SHA256 (32)
```

The lab's own format was `salt | IV | ciphertext`. That works, but CBC alone cannot tell you whether the result is right. I measured it with [`tests/cbc_without_mac_demo.py`](tests/cbc_without_mac_demo.py). One run printed:

```
wrong passwords accepted: 65 of 20000 (~1 in 307)
tampered file decrypts to: b'Pay Ali 900 USD'
```

About 1 wrong password in 256 happens to produce valid padding, so the script writes a file of garbage and reports success. Worse, flipping one byte of the IV changes the same byte of the plaintext: the file said "Pay Ali 100 USD" and, with no key at all, I turned it into "900". This is the classic CBC bit-flipping attack, and the same missing check is what makes padding-oracle attacks possible.

The fix is encrypt-then-MAC: PBKDF2 makes 64 bytes, 32 for AES and 32 for an HMAC over everything before it. On decrypt the HMAC is checked first, with a constant-time compare, and nothing is decrypted or written unless it matches. In the tests 20 wrong passwords and 7 tampered positions (header, salt, IV, ciphertext and tag) were all rejected, and no output file was left behind. In new code I would use AES-GCM, which builds this check in; I kept CBC + HMAC here because the lab is about CBC and padding.

The password is read with `getpass` (not echoed) and never taken from the command line, where it would show in `ps` and shell history. For scripts, `--password-stdin` reads it from a pipe instead. Outputs are mode 600, never overwrite an existing file without `--force`, and are written to a temp file then renamed, so a crash never leaves half a file.

## 5. Vault manager and security audit

```bash
echo "Report 1" > report1.txt
python3 vault_manager.py store report1.txt
python3 vault_manager.py list
python3 vault_manager.py retrieve report1.txt recovered_report.txt
```

```
Stored report1.txt (9 bytes) as a79584bd8643598c58bb5f15bef08cba.enc
  SHA-256 88e66961b3d822f15d7c3556afd66afa27532521d4581b3f8ae8f94b90ee093a
...
Retrieved report1.txt -> recovered_report.txt
Integrity verified: SHA-256 matches the stored hash
```

The vault combines both halves of the lab. Each file is encrypted with the format from section 4 and saved under a random ID, so the folder listing does not reveal names like `salaries-2026.xlsx`, and a name such as `../../etc/passwd` can never become a path. On `retrieve` the HMAC is checked, then the SHA-256 of the decrypted data is compared with the hash taken at `store`. `verify` checks every file in one go, which I used to find a blob I had damaged on purpose. The vault folder is mode 700, every file in it 600.

One honest limitation: `vault_metadata.json` keeps the names and SHA-256 of the *plaintext*, as the lab asked. Someone who can read it cannot read the files, but can confirm whether the vault holds a file they already have. Encrypting the metadata too would close that.

The audit tool scans a folder:

```bash
python3 security_audit.py ~/crypto_lab -o audit_report.json
```

```
Files scanned: 17   HIGH 1  MEDIUM 2  LOW 2
  [HIGH  ] world-writable               testfile.txt: any user can change this file (-rw-rw-rw-)
  [MEDIUM] plaintext-next-to-encrypted  secret.txt: unencrypted copy next to secret.enc
  [MEDIUM] secret-file                  secret.key: key or secret file stored here; keep it out of backups and version control
  [LOW   ] duplicate                    recovered.txt: 2 identical copies: recovered.txt, secret.txt
  [LOW   ] duplicate                    recovered_report.txt: 2 identical copies: recovered_report.txt, report1.txt
```

| Severity | Checks |
| --- | --- |
| HIGH | World-writable files, world-writable folders without the sticky bit, setuid and setgid files, key files (`*.key`, `*.pem`, `id_rsa`, `.env`...) readable by group or others |
| MEDIUM | Key and secret files present at all, `password=`/`token:` lines, private key blocks and AWS access key IDs in small text files, an unencrypted file next to its `.enc` copy |
| LOW | Duplicate files by SHA-256, hidden files with the execute bit |

The report (all hashes, sizes, permissions, owners and times) is saved as JSON with mode 600, because it is a map of where the secrets are. Run it again with `--baseline audit_report.json` to list NEW, MODIFIED and DELETED files since then. Exit code 1 means at least one HIGH finding, so it can gate a cron job or CI step. Symlinks are recorded but not followed, and the report never scans itself. The secret-pattern check is tuned so that code like `password = getpass.getpass()` is not flagged, while `DB_PASSWORD=hunter2` is: run against this lab's own scripts it reports nothing.

## 6. Problems I fixed compared with the starting code

The starting files were outlines with TODOs. Following them literally gives working scripts with these problems:

| In the starting outline | Effect | What I did |
| --- | --- | --- |
| File format salt + IV + ciphertext, no MAC | A wrong password "succeeds" about 1 time in 256 with garbage output, and an attacker can change the plaintext by flipping IV bits (shown in section 4) | HMAC-SHA256 over the whole file, checked before decrypting |
| Detect a wrong password by catching the padding error | Not reliable, see above, and the error is a padding oracle | Detection by HMAC only |
| PBKDF2 with 100,000 rounds | Below the current OWASP guidance for SHA-256 (600,000) | 600,000, stored in the header |
| `main()` in the text encryptor generates and saves a key every run | Each run overwrites `secret.key`, so every earlier message is lost for good | Reuse an existing key; `keygen` refuses to overwrite without `--force` |
| Key and output files written with `open(..., "wb")` | Mode 644 under the usual umask: other users on the machine can read the key and the decrypted data | Created as 600 from the start, written atomically |
| Decrypted output written straight to the target | A failed run can leave a partial or garbage file, or overwrite an existing one | Write only after checks pass; refuse to overwrite without `--force` |
| Vault saves the encrypted file under its original name in `vault_dir` | Folder listing shows what is stored, and `os.path.join(vault_dir, "../x")` escapes the vault | Random ID per file, names only in metadata |
| Corrupt `integrity.json`: "delete it and start over" | Deleting the baseline is exactly what someone hiding a change would want | Script stops with a clear error and leaves the file alone |
| Integrity database keyed by the path as typed | `verify testfile.txt` from another folder checks a different file, or nothing | Absolute paths |
| Only the hash is compared | `chmod 666` or `chmod 4755` is not reported | Mode stored and compared |
| `default_backend()` | Deprecated and ignored since cryptography 3.1 | Removed |
| Audit walks the folder and its own report is in it | Every run "finds" a changed report; symlinks could send the walk elsewhere | Report skipped, symlinks recorded and not followed |
| Scripts always exit 0 | Cron or CI cannot tell a clean run from an alarm | Exit codes: 0 clean, 1 finding or failure, 2 usage error |

## 7. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `error: externally-managed-environment` on `pip3 install` | Ubuntu 23.04+ protects the system Python | `python3 -m venv .venv && . .venv/bin/activate`, or `sudo apt install python3-cryptography` |
| `ModuleNotFoundError: No module named 'crypto_common'` | A script was copied without `crypto_common.py` | Keep all the `.py` files in the same folder |
| `Decryption failed: wrong password, or the file was modified` | Exactly that; these scripts cannot tell the two apart, by design | Check the password, then compare the `.enc` file's hash with a copy |
| `not a file made by these scripts (bad header)` | The file is in the lab's original format or is not encrypted | Decrypt it with the script that made it |
| `InvalidToken` / "decryption failed" in the text encryptor | Different `secret.key`, token cut off when copying, or `--ttl` expired | Copy the whole token including the `==` |
| `Error: ... already exists (use --force to replace it)` | Output or key file is already there | Choose another name, or `--force` if you mean it (never for a key) |
| `is not valid JSON` from the integrity checker | Database damaged or edited by hand | Restore from a backup; delete it only if you accept losing the baseline |
| Hash differs from a colleague's for "the same" text | Line endings (`\r\n` on Windows), a trailing newline, or encoding | Hash the exact bytes; `cat -A file` shows hidden characters |

## 8. How I tested it

The lab ran on the provided Ubuntu cloud machine. I then tested every script in a clean Linux container with Python 3.13 and `cryptography` 50.0.1, so the output in this README and in [`samples/`](samples/) is real output, not copied from the handout. Paths are shortened to `/home/student`.

- `python3 -m unittest discover -s tests -v`: 19 tests, all pass, about 12 seconds. They cover each script's normal path plus:
  - hash output identical to `hashlib` and `sha256sum` on a file larger than one chunk
  - integrity checker catching content changes, permission changes and deleted files, and refusing to replace a corrupt database
  - Fernet round trip, `keygen` not overwriting a key, wrong key and edited token rejected
  - file encryption round trips at 0, 1, 15, 16, 17 and 100,003 bytes (padding edge cases), a fresh salt and IV each time, 20 wrong passwords and 7 tampered byte positions all rejected with no output file
  - vault: real names not on disk, folder mode 700, wrong password, `../../etc/passwd` as a name, SHA-256 mismatch after editing the metadata, `verify` finding one damaged blob among two
  - audit: world-writable, setuid, readable `secret.key`, a password in `.env`, duplicates, plaintext next to `.enc`, a symlink to `/` not followed, report mode 600, and no false positives on the lab's own scripts
- The interactive `getpass` prompts (password asked twice, mismatch refused) were driven through a real pseudo-terminal, since `--password-stdin` skips them.
- A 5 MB random file encrypted and decrypted byte for byte.
- `pyflakes` on every script: no warnings.

**Not verified:** I have not run these on my own Ubuntu laptop yet, and the timing figure (0.3 s for 600,000 PBKDF2 rounds) is from the test container, so it will differ there.

## 9. Takeaway

Hashing proves a file did not change, encryption keeps it secret, and neither one does the other's job. The interesting part of this lab was not calling AES, which is one line, but everything around it: a check that the decrypted data is genuine, a key file only its owner can read, a key that is never silently replaced, and output that is never written until it has been verified. That is where real-world crypto goes wrong, and none of it is in the algorithm.
