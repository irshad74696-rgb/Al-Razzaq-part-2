#!/usr/bin/env python3
"""Unit tests for forensic_analyzer.py and html_report_generator.py on fixed sample data.
Needs no root and touches nothing outside a temporary folder.

    python3 tests/test_analyzer.py -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import forensic_analyzer as fa          # noqa: E402
import html_report_generator as hrg     # noqa: E402

AUTH = """# comment lines are ignored
2026-11-28T10:00:01+05:00 host sshd[1]: Failed password for invalid user admin from 203.0.113.50 port 50001 ssh2
""" + "".join(
    f"2026-11-28T10:00:{i:02d}+05:00 host sshd[1]: Failed password for root from 203.0.113.50 port 5{i:04d} ssh2\n"
    for i in range(2, 14)) + """Nov 28 10:01:00 host sshd[2]: Failed password for invalid user x from 10.9.9.9 port 22 from 198.51.100.9 port 4000 ssh2
2026-11-28T10:02:00+05:00 host sshd[3]: Accepted password for webadmin from 203.0.113.50 port 51210 ssh2
2026-11-28T09:00:00+05:00 host sshd[4]: Accepted publickey for alice from 192.0.2.7 port 1 ssh2: ED25519 SHA256:abc
2026-11-28T10:03:00+05:00 host sudo:  webadmin : user NOT in sudoers ; TTY=pts/3 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
2026-11-28T10:04:00+05:00 host sudo: alice : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/apt update
2026-11-28T10:05:00+05:00 host sudo: bob : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/chmod +x /tmp/x.sh
"""

PS = """USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1  10000  1000 ?        Ss   10:00   0:00 /sbin/init
root           2  0.0  0.0      0     0 ?        S    10:00   0:00 [kthreadd]
root        1168  0.0  0.0   3000   900 ?        S    10:00   0:00 nc -l 127.0.0.1 4444
root        1165  0.0  0.0   3000   900 ?        S    10:00   0:00 timeout 60m nc -l 127.0.0.1 4444
bob         2000 95.0 60.0   3000   900 ?        R    10:00   0:00 /tmp/.x/miner --pool x
alice       2100  0.0  0.0   3000   900 ?        S    10:00   0:00 grep nc
alice       2200  0.1  0.1   3000   900 ?        S    10:00   0:00 curl -s https://example.org
"""

SS = """Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0      1          127.0.0.1:4444        0.0.0.0:*    users:(("nc",pid=1168,fd=3))
tcp   LISTEN 0      4096         0.0.0.0:2222        0.0.0.0:*    users:(("sshd",pid=900,fd=3))
tcp   LISTEN 0      4096       [::]:31337           [::]:*       users:(("evil",pid=901,fd=3))
tcp   ESTAB  0      0         10.0.0.5:40000   203.0.113.66:5555  users:(("bash",pid=902,fd=3))
tcp   ESTAB  0      0         10.0.0.5:40001     8.8.8.8:443   users:(("firefox",pid=903,fd=3))
tcp   ESTAB  0      0         10.0.0.5:40002     8.8.8.8:443   users:(("firefox",pid=903,fd=4))
udp   UNCONN 0      0    127.0.0.53%lo:53          0.0.0.0:*    users:(("systemd-resolve",pid=500,fd=13))
"""

NETSTAT = """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:6666            0.0.0.0:*               LISTEN      777/socat
tcp        0      0 10.0.0.5:22             192.168.1.4:5000        ESTABLISHED 888/sshd: alice
"""

TEMP = ("d\t2026-11-28 10:00\t1777\troot\t4096\t/tmp\n"
        "f\t2026-11-28 10:00\t700\troot\t10\t/tmp/sim/backdoor.sh\n"
        "f\t2026-11-28 10:00\t755\tbob\t10\t/tmp/run.bin\n"
        "f\t2026-11-28 10:00\t644\tbob\t10\t/tmp/notes.txt\n")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


class AnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = self.tmp.name
        self.coll = os.path.join(self.base, "automated_collection_20261128_100000")
        write(os.path.join(self.coll, "logs/auth/auth_events.txt"), AUTH)
        write(os.path.join(self.coll, "processes/ps_aux.txt"), PS)
        write(os.path.join(self.coll, "processes/deleted_executables.txt"), "4242\t/usr/bin/xyz (deleted)\n")
        write(os.path.join(self.coll, "network/connections.txt"), SS)
        write(os.path.join(self.coll, "files/temp_files.txt"), TEMP)
        write(os.path.join(self.coll, "users/admins.txt"), "root\nalice\n")
        self.a = fa.LinuxForensicAnalyzer(self.coll)

    def tearDown(self):
        self.tmp.cleanup()

    def summaries(self, sev=None):
        return [f["summary"] for f in self.a.suspicious_activities if sev is None or f["severity"] == sev]

    def test_admins_loaded_from_collection(self):
        self.assertEqual(self.a.admins, {"root", "alice"})

    def test_brute_force_then_success_is_critical(self):
        self.a.analyze_auth_logs(os.path.join(self.coll, "logs/auth/auth_events.txt"))
        r = self.a.analysis_results["authentication"]
        self.assertEqual(r["failed_logins_by_ip"]["203.0.113.50"], 13)
        self.assertIn("203.0.113.50", r["brute_force_then_success"])
        self.assertIn("brute force from 203.0.113.50 (13 failures) followed by a successful login",
                      self.summaries("CRITICAL"))

    def test_success_before_failures_is_not_compromise(self):
        log = "".join(f"2026-11-28T10:00:{i:02d}+00:00 h sshd[1]: Failed password for root from 192.0.2.7 port {i} ssh2\n"
                      for i in range(20))
        write(os.path.join(self.base, "a.log"), log + AUTH)
        self.a.analyze_auth_logs(os.path.join(self.base, "a.log"))
        # alice logged in from 192.0.2.7 at 09:00+05:00, BEFORE the 10:00 UTC failures
        self.assertIn("brute force from 192.0.2.7: 20 failed logins", self.summaries("HIGH"))

    def test_threshold_is_strictly_greater(self):
        a = fa.LinuxForensicAnalyzer(self.coll, brute_force_threshold=13)
        a.analyze_auth_logs(os.path.join(self.coll, "logs/auth/auth_events.txt"))
        self.assertEqual(a.analysis_results["authentication"]["brute_force_ips"], {})

    def test_log_injection_uses_real_address(self):
        self.a.analyze_auth_logs(os.path.join(self.coll, "logs/auth/auth_events.txt"))
        r = self.a.analysis_results["authentication"]
        self.assertIn("198.51.100.9", r["failed_logins_by_ip"])
        self.assertNotIn("10.9.9.9", r["failed_logins_by_ip"])
        self.assertEqual(r["log_injection_attempts"][0]["real_ip"], "198.51.100.9")

    def test_sudo_rules(self):
        self.a.analyze_auth_logs(os.path.join(self.coll, "logs/auth/auth_events.txt"))
        high = self.summaries("HIGH")
        self.assertIn("sudo refused for webadmin", high)
        self.assertIn("sudo used by bob, who is not in an admin group", high)
        self.assertFalse(any("alice" in s for s in high))
        self.assertIn("sudo command by bob makes a temp-folder file executable", self.summaries("MEDIUM"))

    def test_classic_syslog_timestamp(self):
        t = fa.parse_time("Nov 28 10:01:00")
        self.assertEqual((t.month, t.day, t.hour), (11, 28, 10))
        self.assertIsNotNone(fa.parse_time("2026-11-28T10:00:01.123456+0500"))

    def test_processes(self):
        self.a.analyze_processes(os.path.join(self.coll, "processes/ps_aux.txt"))
        r = self.a.analysis_results["processes"]
        self.assertEqual([p["pid"] for p in r["suspicious_processes"]], [1168])  # not timeout, not grep
        self.assertEqual([p["pid"] for p in r["running_from_temp"]], [2000])
        self.assertEqual([p["pid"] for p in r["high_cpu_processes"]], [2000])
        self.assertEqual([p["pid"] for p in r["high_memory_processes"]], [2000])
        self.assertEqual([p["pid"] for p in r["download_tools"]], [2200])
        self.assertEqual(r["deleted_executables"][0]["pid"], "4242")
        self.assertNotIn(2, [p["pid"] for p in r["suspicious_processes"]])

    def test_network_ss(self):
        self.a.analyze_network_connections(os.path.join(self.coll, "network/connections.txt"))
        r = self.a.analysis_results["network"]
        self.assertEqual(r["listening_ports"], [53, 2222, 4444, 31337])
        high = self.summaries("HIGH")
        self.assertIn("listener on backdoor port 4444 (loopback only)", high)
        self.assertIn("listener on backdoor port 31337 (reachable from the network)", high)
        self.assertIn("outbound connection to backdoor port 5555 (possible reverse shell)", high)
        info = self.summaries("INFO")
        self.assertIn("2 connection(s) to public address 8.8.8.8:443 by firefox", info)

    def test_network_netstat(self):
        write(os.path.join(self.base, "netstat.txt"), NETSTAT)
        self.a.analyze_network_connections(os.path.join(self.base, "netstat.txt"))
        self.assertIn("listener on backdoor port 6666 (reachable from the network)", self.summaries("HIGH"))
        self.assertEqual(len(self.a.analysis_results["network"]["established_connections"]), 1)

    def test_temp_files(self):
        self.a.analyze_temp_files(os.path.join(self.coll, "files/temp_files.txt"))
        self.assertEqual(self.summaries(), ["suspicious file name: /tmp/sim/backdoor.sh",
                                            "executable file in a temp folder: /tmp/run.bin"])

    def test_missing_files_do_not_crash(self):
        self.a.analyze_auth_logs(["/nonexistent"])
        self.a.analyze_processes("/nonexistent")
        self.a.analyze_network_connections("/nonexistent")
        self.a.analyze_temp_files("/nonexistent")
        self.assertEqual(self.a.suspicious_activities, [])

    def test_main_end_to_end_and_reports(self):
        out = os.path.join(self.base, "out")
        rc = fa.main(["--base", self.base, "--output-dir", out])
        self.assertEqual(rc, 1)
        with open(os.path.join(out, "analysis.json")) as fh:
            rep = json.load(fh)
        self.assertEqual(rep["summary"]["CRITICAL"], 1)
        with open(os.path.join(out, "findings.tsv")) as fh:
            rows = [line.rstrip("\n").split("\t") for line in fh]
        self.assertTrue(all(len(r) == 4 for r in rows))
        self.assertEqual(rows[0][0], "CRITICAL")
        self.assertEqual(oct(os.stat(os.path.join(out, "analysis.json")).st_mode & 0o777), "0o600")
        self.assertTrue(os.path.getsize(os.path.join(out, "timeline.tsv")) > 0)

    def test_main_without_collection(self):
        self.assertEqual(fa.main(["--base", os.path.join(self.base, "empty")]), 2)

    def test_html_escapes_attacker_text(self):
        evil = "2026-11-28T10:00:00+00:00 h sshd[1]: Failed password for invalid user <script>alert(1)</script> from 10.9.9.9 port 22 from 203.0.113.9 port 1 ssh2\n"
        write(os.path.join(self.coll, "logs/auth/extra/evil.log"), evil)
        out = os.path.join(self.base, "python_analysis_x")
        fa.main(["--base", self.base, "--output-dir", out])
        page = os.path.join(self.base, "r.html")
        self.assertEqual(hrg.main(["--base", self.base, "--analysis", out, "-o", page]), 0)
        with open(page) as fh:
            text = fh.read()
        self.assertNotIn("<script>", text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("default-src 'none'", text)

    def test_html_merges_duplicate_findings(self):
        merged = hrg.merge([{"severity": "HIGH", "category": "network", "summary": "s", "evidence": "a"}],
                           [{"severity": "HIGH", "category": "network", "summary": "s", "evidence": "b",
                             "source": "live detection"}])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["source"], "live detection + data analysis")


if __name__ == "__main__":
    unittest.main()
