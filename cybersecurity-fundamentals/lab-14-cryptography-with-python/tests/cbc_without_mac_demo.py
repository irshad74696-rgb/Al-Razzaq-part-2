#!/usr/bin/env python3
"""Why the lab's original file format needed a MAC.

Encrypts with salt + IV + AES-CBC ciphertext and nothing else, then shows
(1) how often a WRONG password still "decrypts" without an error, and
(2) that flipping one IV byte silently changes the plaintext.

    python3 tests/cbc_without_mac_demo.py
"""
# The lab's original format: salt(16) + IV(16) + AES-CBC ciphertext, no MAC.
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
IT = 1000  # low only to make the experiment fast; does not change the padding statistics
def key(pw, salt): return PBKDF2HMAC(hashes.SHA256(), 32, salt, IT).derive(pw.encode())
def enc(data, pw):
    salt, iv = os.urandom(16), os.urandom(16)
    p = padding.PKCS7(128).padder(); d = p.update(data) + p.finalize()
    e = Cipher(algorithms.AES(key(pw, salt)), modes.CBC(iv)).encryptor()
    return salt + iv + e.update(d) + e.finalize()
def dec(blob, pw):
    salt, iv, ct = blob[:16], blob[16:32], blob[32:]
    d = Cipher(algorithms.AES(key(pw, salt)), modes.CBC(iv)).decryptor()
    padded = d.update(ct) + d.finalize()
    u = padding.PKCS7(128).unpadder(); return u.update(padded) + u.finalize()
blob = enc(b"Pay Ali 100 USD", "right-password")
N = 20000; accepted = 0
for i in range(N):
    try: dec(blob, f"wrong{i}"); accepted += 1
    except ValueError: pass
print(f"wrong passwords accepted: {accepted} of {N} (~1 in {N//max(accepted,1)})")
b = bytearray(blob); b[16 + 8] ^= ord("1") ^ ord("9")   # flip one IV byte
print("tampered file decrypts to:", dec(bytes(b), "right-password"))
