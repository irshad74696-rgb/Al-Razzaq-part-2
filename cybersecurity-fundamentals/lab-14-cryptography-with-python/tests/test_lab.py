#!/usr/bin/env python3
"""End-to-end tests for the lab scripts. Each test runs the real scripts in a
fresh temporary folder, the same way they are used from the command line.

    python3 -m unittest discover -s tests -v
"""

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
PW = "CorrectHorse9\n"


def run(script, *args, stdin=None, cwd):
    return subprocess.run([sys.executable, os.path.join(SCRIPTS, script), *args],
                          input=stdin, capture_output=True, text=True, cwd=cwd)


class LabTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.d = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, name, data):
        path = os.path.join(self.d, name)
        with open(path, "wb" if isinstance(data, bytes) else "w") as f:
            f.write(data)
        return path

    def read(self, name):
        with open(os.path.join(self.d, name), "rb") as f:
            return f.read()

    def flip(self, name, offset):
        b = bytearray(self.read(name))
        b[offset] ^= 0x01
        self.write(name, bytes(b))


class HashCalculator(LabTestCase):
    def test_matches_hashlib_and_sha256sum_format(self):
        data = os.urandom(10_000)  # more than one 4096-byte chunk
        self.write("f.bin", data)
        r = run("hash_calculator.py", "f.bin", cwd=self.d)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stdout.strip(), f"{hashlib.sha256(data).hexdigest()}  f.bin")

    def test_missing_file_and_compare(self):
        self.assertEqual(run("hash_calculator.py", "nope", cwd=self.d).returncode, 2)
        self.write("t.txt", "abc")
        good = hashlib.sha256(b"abc").hexdigest()
        self.assertEqual(run("hash_calculator.py", "-c", good, "t.txt", cwd=self.d).returncode, 0)
        self.assertEqual(run("hash_calculator.py", "-c", "0" * 64, "t.txt", cwd=self.d).returncode, 1)


class IntegrityChecker(LabTestCase):
    def test_add_verify_modify(self):
        self.write("testfile.txt", "Original content for testing\n")
        self.assertEqual(run("integrity_checker.py", "add", "testfile.txt", cwd=self.d).returncode, 0)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.d, "integrity.json")).st_mode), 0o600)
        self.assertEqual(run("integrity_checker.py", "verify", "testfile.txt", cwd=self.d).returncode, 0)
        with open(os.path.join(self.d, "testfile.txt"), "a") as f:
            f.write("Modified\n")
        r = run("integrity_checker.py", "verify", cwd=self.d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("MODIFIED", r.stdout)
        self.assertEqual(run("integrity_checker.py", "update", "testfile.txt", cwd=self.d).returncode, 0)
        self.assertEqual(run("integrity_checker.py", "verify", cwd=self.d).returncode, 0)

    def test_permission_change_and_missing(self):
        p = self.write("a.txt", "x")
        os.chmod(p, 0o644)
        run("integrity_checker.py", "add", "a.txt", cwd=self.d)
        os.chmod(p, 0o4755)
        self.assertIn("PERMS", run("integrity_checker.py", "verify", cwd=self.d).stdout)
        os.unlink(p)
        self.assertIn("MISSING", run("integrity_checker.py", "verify", cwd=self.d).stdout)

    def test_corrupt_database_is_not_silently_replaced(self):
        self.write("integrity.json", "{broken")
        r = run("integrity_checker.py", "list", cwd=self.d)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(self.read("integrity.json"), b"{broken")


class TextEncryptor(LabTestCase):
    def test_demo_round_trip(self):
        r = run("text_encryptor.py", "demo", stdin="hello lab\n", cwd=self.d)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Round trip OK", r.stdout)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.d, "secret.key")).st_mode), 0o600)

    def test_keygen_refuses_to_overwrite(self):
        run("text_encryptor.py", "keygen", cwd=self.d)
        key = self.read("secret.key")
        self.assertEqual(run("text_encryptor.py", "keygen", cwd=self.d).returncode, 1)
        self.assertEqual(self.read("secret.key"), key)

    def test_wrong_key_and_tamper(self):
        run("text_encryptor.py", "keygen", cwd=self.d)
        token = run("text_encryptor.py", "encrypt", "meet at 6", cwd=self.d).stdout.strip()
        self.assertEqual(run("text_encryptor.py", "decrypt", token, cwd=self.d).stdout.strip(), "meet at 6")
        bad = token[:20] + ("A" if token[20] != "A" else "B") + token[21:]
        self.assertEqual(run("text_encryptor.py", "decrypt", bad, cwd=self.d).returncode, 1)
        run("text_encryptor.py", "-k", "other.key", "keygen", cwd=self.d)
        self.assertEqual(run("text_encryptor.py", "-k", "other.key", "decrypt", token, cwd=self.d).returncode, 1)


class FileEncryptor(LabTestCase):
    def enc(self, *args, pw=PW):
        return run("file_encryptor.py", "encrypt", "--password-stdin", *args, stdin=pw, cwd=self.d)

    def dec(self, *args, pw=PW):
        return run("file_encryptor.py", "decrypt", "--password-stdin", *args, stdin=pw, cwd=self.d)

    def test_round_trip_sizes(self):
        for size in (0, 1, 15, 16, 17, 100_003):
            data = os.urandom(size)
            self.write("in.bin", data)
            self.assertEqual(self.enc("in.bin", "out.enc", "--force").returncode, 0)
            self.assertEqual(self.dec("out.enc", "back.bin", "--force").returncode, 0)
            self.assertEqual(self.read("back.bin"), data, f"size {size}")

    def test_layout_and_randomness(self):
        self.write("s.txt", "Confidential data\n")
        self.enc("s.txt", "a.enc")
        self.enc("s.txt", "b.enc")
        a, b = self.read("a.enc"), self.read("b.enc")
        self.assertEqual(a[:4], b"PYC1")
        self.assertNotEqual(a, b)  # fresh salt and IV every time
        self.assertNotIn(b"Confidential", a)
        self.assertEqual((len(a) - 40 - 32) % 16, 0)

    def test_wrong_password_writes_nothing(self):
        self.write("s.txt", "Confidential data\n")
        self.enc("s.txt", "s.enc")
        # Without the HMAC, roughly 1 wrong password in 256 would "succeed"
        # with garbage output. Try many to show it never happens now.
        for i in range(20):
            r = self.dec("s.enc", "out.txt", pw=f"wrongpass{i}\n")
            self.assertEqual(r.returncode, 1)
        self.assertFalse(os.path.exists(os.path.join(self.d, "out.txt")))

    def test_every_tampered_byte_is_detected(self):
        self.write("s.txt", "Confidential data\n")
        self.enc("s.txt", "s.enc", "--iterations", "100000")
        size = len(self.read("s.enc"))
        original = self.read("s.enc")
        for offset in (0, 5, 10, 30, 41, size - 33, size - 1):
            self.write("t.enc", original)
            self.flip("t.enc", offset)
            self.assertEqual(self.dec("t.enc", "o.txt", "--force").returncode, 1, offset)

    def test_short_password_rejected(self):
        self.write("s.txt", "x")
        self.assertEqual(self.enc("s.txt", "s.enc", pw="short\n").returncode, 2)


class Vault(LabTestCase):
    def v(self, *args, pw=PW):
        return run("vault_manager.py", "--password-stdin", *args, stdin=pw, cwd=self.d)

    def test_store_list_retrieve_remove(self):
        self.write("report1.txt", "Report 1\n")
        self.assertEqual(self.v("store", "report1.txt").returncode, 0)
        vault = os.path.join(self.d, "secure_vault")
        self.assertEqual(stat.S_IMODE(os.stat(vault).st_mode), 0o700)
        blobs = [f for f in os.listdir(vault) if f.endswith(".enc")]
        self.assertEqual(len(blobs), 1)
        self.assertNotIn("report1", blobs[0])  # real names are not exposed
        self.assertIn("report1.txt", run("vault_manager.py", "list", cwd=self.d).stdout)
        r = self.v("retrieve", "report1.txt", "recovered_report.txt")
        self.assertEqual(r.returncode, 0)
        self.assertIn("Integrity verified", r.stdout)
        self.assertEqual(self.read("recovered_report.txt"), b"Report 1\n")
        self.assertEqual(run("vault_manager.py", "remove", "report1.txt", cwd=self.d).returncode, 0)
        self.assertEqual(os.listdir(vault), ["vault_metadata.json"])

    def test_wrong_password_and_traversal(self):
        self.write("r.txt", "secret")
        self.v("store", "r.txt")
        self.assertEqual(self.v("retrieve", "r.txt", "o.txt", pw="wrongpass1\n").returncode, 1)
        self.assertEqual(self.v("retrieve", "../../etc/passwd", "o.txt").returncode, 1)
        self.assertFalse(os.path.exists(os.path.join(self.d, "o.txt")))

    def test_hash_mismatch_is_caught(self):
        self.write("r.txt", "secret")
        self.v("store", "r.txt")
        meta_path = os.path.join(self.d, "secure_vault", "vault_metadata.json")
        with open(meta_path) as f:
            meta = json.load(f)
        meta["r.txt"]["sha256"] = "0" * 64
        with open(meta_path, "w") as f:
            json.dump(meta, f)
        r = self.v("retrieve", "r.txt", "o.txt")
        self.assertEqual(r.returncode, 1)
        self.assertIn("SHA-256 does not match", r.stdout)

    def test_verify_finds_damaged_blob(self):
        self.write("a.txt", "A")
        self.write("b.txt", "B")
        self.v("store", "a.txt", "b.txt")
        meta = json.loads(self.read("secure_vault/vault_metadata.json"))
        self.flip(f"secure_vault/{meta['b.txt']['id']}.enc", 50)
        r = self.v("verify")
        self.assertEqual(r.returncode, 1)
        self.assertIn("OK       a.txt", r.stdout)
        self.assertIn("FAILED   b.txt", r.stdout)


class SecurityAudit(LabTestCase):
    def test_findings(self):
        os.chmod(self.write("ww.txt", "x"), 0o666)
        os.chmod(self.write("tool", "#!/bin/sh\n"), 0o4755)
        os.chmod(self.write("secret.key", "k" * 44), 0o644)
        self.write(".env", "DB_PASSWORD=hunter2\n")
        self.write("one.txt", "same")
        self.write("two.txt", "same")
        self.write("data.txt", "plain")
        self.write("data.enc", "cipher")
        os.symlink("/", os.path.join(self.d, "rootlink"))
        out = os.path.join(self.d, "..", os.path.basename(self.d) + "-audit.json")
        try:
            r = run("security_audit.py", ".", "-o", out, cwd=self.d)
            self.assertEqual(r.returncode, 1)  # HIGH findings present
            with open(out) as f:
                report = json.load(f)
            self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        finally:
            if os.path.exists(out):
                os.unlink(out)
        checks = {(w["check"], os.path.basename(w["path"])) for w in report["warnings"]}
        for expected in [("world-writable", "ww.txt"), ("setuid", "tool"),
                         ("readable-secret", "secret.key"), ("secret-in-file", ".env"),
                         ("duplicate", "one.txt"),
                         ("plaintext-next-to-encrypted", "data.txt")]:
            self.assertIn(expected, checks)
        # the symlink to / was recorded, not followed
        self.assertLess(report["files_scanned"], 20)

    def test_own_scripts_are_clean(self):
        out = os.path.join(tempfile.gettempdir(), "lab14-self-audit.json")
        r = run("security_audit.py", SCRIPTS, "-o", out, cwd=self.d)
        os.unlink(out)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("secret-in-file", r.stdout)


if __name__ == "__main__":
    unittest.main()
