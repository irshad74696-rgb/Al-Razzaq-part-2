"""Shared helpers for the cryptography lab scripts.

Everything that touches keys, passwords or hashes lives here so that
file_encryptor.py and vault_manager.py use exactly the same file format and
the same checks.

Encrypted file format (all integers big-endian):

    offset  size  field
    0       4     magic  b"PYC1"
    4       4     PBKDF2 iteration count
    8       16    salt   (random per file)
    24      16    IV     (random per file)
    40      n     AES-256-CBC ciphertext, PKCS7 padded
    40+n    32    HMAC-SHA256 tag over bytes 0 .. 40+n

The lab's starting format was salt + IV + ciphertext. CBC on its own has no
integrity protection: a wrong password or a tampered file is only noticed if
the padding happens to come out invalid, which a random key still passes about
1 time in 256. The HMAC (encrypt-then-MAC, separate key) makes both cases fail
every time, before any plaintext is written to disk.
"""

import getpass
import hashlib
import hmac
import os
import stat
import struct
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

CHUNK_SIZE = 4096
MAGIC = b"PYC1"
SALT_LEN = 16
IV_LEN = 16
TAG_LEN = 32
HEADER = struct.Struct(">4sI16s16s")  # magic, iterations, salt, iv
# The lab asks for 100,000; OWASP's 2023 guidance for PBKDF2-HMAC-SHA256 is
# 600,000. The count is stored in each file, so old files still decrypt.
DEFAULT_ITERATIONS = 600_000
MIN_PASSWORD_LEN = 8


class DecryptionError(Exception):
    """Wrong password, a damaged file, or not one of our files."""


def file_hash(path, algorithm="sha256"):
    """Hash a file in CHUNK_SIZE pieces so large files never sit in memory."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def derive_keys(password, salt, iterations=DEFAULT_ITERATIONS):
    """PBKDF2-HMAC-SHA256 -> 64 bytes: 32 for AES-256, 32 for the HMAC."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=64,
                     salt=salt, iterations=iterations)
    material = kdf.derive(password.encode("utf-8"))
    return material[:32], material[32:]


def encrypt_bytes(data, password, iterations=DEFAULT_ITERATIONS):
    salt = os.urandom(SALT_LEN)
    iv = os.urandom(IV_LEN)
    enc_key, mac_key = derive_keys(password, salt, iterations)

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    body = HEADER.pack(MAGIC, iterations, salt, iv) + ciphertext
    tag = hmac.new(mac_key, body, hashlib.sha256).digest()
    return body + tag


def decrypt_bytes(blob, password):
    if len(blob) < HEADER.size + 16 + TAG_LEN:
        raise DecryptionError("file is too short to be an encrypted file")
    magic, iterations, salt, iv = HEADER.unpack_from(blob)
    if magic != MAGIC:
        raise DecryptionError("not a file made by these scripts (bad header)")
    if not 1_000 <= iterations <= 10_000_000:
        raise DecryptionError("implausible iteration count in header")

    body, tag = blob[:-TAG_LEN], blob[-TAG_LEN:]
    enc_key, mac_key = derive_keys(password, salt, iterations)
    expected = hmac.new(mac_key, body, hashlib.sha256).digest()
    # compare_digest takes the same time wherever the first difference is
    if not hmac.compare_digest(tag, expected):
        raise DecryptionError("wrong password, or the file was modified")

    ciphertext = body[HEADER.size:]
    if len(ciphertext) % 16:
        raise DecryptionError("ciphertext length is not a multiple of 16")
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:  # cannot happen once the HMAC matched
        raise DecryptionError("bad padding") from exc


def write_private(path, data, overwrite=False):
    """Write bytes atomically with mode 600.

    The temp file is created with mode 600 from the start, so there is no
    moment where the data is readable by others, and a crash never leaves a
    half-written file under the real name.
    """
    path = os.path.abspath(path)
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(f"{path} already exists (use --force to replace it)")
    folder = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def ask_password(confirm=False, from_stdin=False):
    """Read a password without echoing it.

    --password-stdin reads the first line of stdin instead, for scripts and
    tests. Never put a password on the command line: it shows up in `ps` and
    in shell history.
    """
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        if confirm and getpass.getpass("Repeat password: ") != password:
            raise ValueError("passwords do not match")
    if confirm and len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"use at least {MIN_PASSWORD_LEN} characters")
    if not password:
        raise ValueError("empty password")
    return password


def mode_string(mode):
    return stat.filemode(mode)
