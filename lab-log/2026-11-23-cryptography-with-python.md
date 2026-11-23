# 2026-11-23 · Lab 14: Cryptography with Python

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Done on the lab's cloud machine; scripts tested in a container (19 automated tests pass); not yet run on my own laptop |
| **Environment** | Lab: provided Ubuntu cloud machine. Script testing: Linux container, Python 3.13, cryptography 50.0.1 |
| **Lab folder** | [`cybersecurity-fundamentals/lab-14-cryptography-with-python/`](../cybersecurity-fundamentals/lab-14-cryptography-with-python/README.md) |

## What the lab covered

SHA-256 hashing for file integrity, AES for confidentiality, and both together. I built a hash calculator, a JSON-based integrity checker, a Fernet text encryptor, a password-based file encryptor (PBKDF2 + AES-256-CBC), an encrypted vault that verifies each file's hash on the way out, and a folder audit that flags risky permissions and leftover secrets.

## Commands used

```bash
python3 hash_calculator.py -v testfile.txt          # same value as sha256sum
python3 integrity_checker.py add testfile.txt
python3 integrity_checker.py verify                 # MODIFIED / PERMS / MISSING, exit 1
python3 text_encryptor.py                           # Fernet round trip
python3 file_encryptor.py encrypt secret.txt secret.enc
python3 file_encryptor.py decrypt secret.enc recovered.txt
python3 vault_manager.py store report1.txt
python3 vault_manager.py retrieve report1.txt recovered_report.txt
python3 security_audit.py ~/crypto_lab -o audit_report.json
python3 -m unittest discover -s tests -v
```

The experiment that changed my design, using the lab's original salt + IV + ciphertext format:

```
wrong passwords accepted: 65 of 20000 (~1 in 307)
tampered file decrypts to: b'Pay Ali 900 USD'      # was "Pay Ali 100 USD"
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| A wrong password sometimes "decrypted" to garbage with no error | AES-CBC has no integrity check; a random key gives valid padding about 1 time in 256 | HMAC-SHA256 over the whole file (encrypt-then-MAC), checked first |
| One flipped IV byte changed "100" to "900" in the plaintext | Same missing check: CBC bit-flipping | Same HMAC; every tampered byte is now rejected |
| Running the text encryptor twice made old messages unreadable | The outline generates and saves a new key every run | Reuse the existing key; `keygen` refuses to overwrite |
| `secret.key` readable by every user | Default umask gives 644 | Key and outputs created as 600 |
| Vault names like `../../x` could escape the vault folder | Encrypted file saved under its original name | Random ID per file |
| `pip3 install cryptography` refused | Ubuntu's externally-managed Python | venv, or `apt install python3-cryptography` |
| Audit flagged my own scripts as "hard-coded password" | Pattern matched `password = getpass(...)` | Only match literal values, as in `.env` lines |

## Key takeaway

Hashing proves integrity, encryption gives secrecy, and you need both, plus careful handling of keys and outputs, for either to mean anything. The algorithm is one line; the mistakes are in everything around it.

## Still to do

- Copy the scripts to `~/crypto_lab` on my own Ubuntu machine, run the test suite there and paste the output here.
- Try AES-GCM and RSA as the lab's follow-up suggests.
