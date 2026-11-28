#!/usr/bin/env python3
"""
Tests for the Windows forensics automation lab.

    ~/forensics-venv/bin/python -m unittest discover -s tests -v

Needs python-evtx and python-registry. The PowerShell tests need `pwsh`
and are skipped without it. Two tests cross-check the sample files with
independent parsers (the Rust-based `evtx` package and `regipy`) and are
skipped if those are not installed.
"""

import base64
import glob
import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)
SCRIPTS = os.path.join(LAB, "scripts")
TOOLS = os.path.join(LAB, "tools")
SAMPLES = os.path.join(LAB, "samples")
PY = sys.executable
PWSH = shutil.which("pwsh")
SECRET = "SAMPLE-ONLY-not-a-real-password"

sys.path.insert(0, SCRIPTS)
sys.path.insert(0, TOOLS)

import Evtx.Evtx as evtx  # noqa: E402
from Registry import Registry  # noqa: E402

import analyze_activity  # noqa: E402
import extract_registry  # noqa: E402
from evtx_writer import Event, write_evtx  # noqa: E402


def run(args, cwd=None, env=None):
    return subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=300)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read(path, mode="r"):
    with open(path, mode) as fh:
        return fh.read()


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def build_case(folder, scenario=None, source=SAMPLES):
    """Copy (or generate) samples into folder and run both extractors."""
    if scenario:
        r = run([PY, os.path.join(TOOLS, "make_samples.py"), "--scenario", scenario, "--out", folder])
        assert r.returncode == 0, r.stderr
    else:
        for sub in ("event-logs", "registry-hives"):
            os.makedirs(os.path.join(folder, sub), exist_ok=True)
            for f in glob.glob(os.path.join(source, sub, "*")):
                if not f.endswith(".json"):
                    shutil.copy(f, os.path.join(folder, sub))
    logs = os.path.join(folder, "event-logs")
    hives = os.path.join(folder, "registry-hives")
    for name, out in (("Security.evtx", "security_events.json"), ("System.evtx", "system_events.json")):
        r = run([PY, os.path.join(SCRIPTS, "extract_eventlogs.py"), name, out], cwd=logs)
        assert r.returncode == 0, r.stderr
    for name in ("SYSTEM", "SOFTWARE"):
        r = run([PY, os.path.join(SCRIPTS, "extract_registry.py"), name], cwd=hives)
        assert r.returncode == 0, r.stderr


def run_pipeline(folder, extra_env=None, analyze_args=()):
    env = dict(os.environ, **(extra_env or {}))
    r = run([PWSH, "-NoProfile", "-File", os.path.join(SCRIPTS, "forensic_automation.ps1"),
             "-DataPath", folder, "-OutputPath", os.path.join(folder, "forensic_output")], env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    a = run([PY, os.path.join(SCRIPTS, "analyze_activity.py"), "--data-dir",
             os.path.join(folder, "forensic_output"), *analyze_args])
    return r, a


class SampleFiles(unittest.TestCase):
    def test_samples_are_reproducible(self):
        with tempfile.TemporaryDirectory() as tmp:
            run([PY, os.path.join(TOOLS, "make_samples.py"), "--out", tmp])
            for rel in ("event-logs/Security.evtx", "event-logs/System.evtx",
                        "registry-hives/SYSTEM", "registry-hives/SOFTWARE"):
                self.assertEqual(sha256(os.path.join(tmp, rel)), sha256(os.path.join(SAMPLES, rel)), rel)

    def test_evtx_checksums_and_counts(self):
        for name, count in (("Security.evtx", 1268), ("System.evtx", 50)):
            with evtx.Evtx(os.path.join(SAMPLES, "event-logs", name)) as log:
                header = log.get_file_header()
                self.assertTrue(header.verify(), name)
                chunks = list(header.chunks())
                self.assertTrue(all(c.verify() for c in chunks), name)
                self.assertEqual(sum(1 for r in log.records() if r.xml()), count)

    def test_evtx_independent_parser(self):
        try:
            from evtx import PyEvtxParser
        except ImportError:
            self.skipTest("Rust evtx parser (pip install evtx) not installed")
        records = list(PyEvtxParser(os.path.join(SAMPLES, "event-logs", "Security.evtx")).records())
        self.assertEqual(len(records), 1268)
        self.assertEqual(sum("<EventID>4625</EventID>" in r["data"] for r in records), 1201)
        self.assertIn("<LogFileCleared>", records[-1]["data"])

    def test_hives_valid(self):
        for name in ("SYSTEM", "SOFTWARE"):
            reg = Registry.Registry(os.path.join(SAMPLES, "registry-hives", name))
            self.assertTrue(reg._regf.validate_checksum())
            self.assertEqual(reg.hive_type().name, name)

    def test_hives_independent_parser(self):
        try:
            from regipy.registry import RegistryHive
        except ImportError:
            self.skipTest("regipy not installed")
        hive = RegistryHive(os.path.join(SAMPLES, "registry-hives", "SYSTEM"))
        key = hive.get_key(r"\ControlSet001\Control\ComputerName\ComputerName")
        self.assertEqual(key.get_value("ComputerName"), "WS-LAB-07")
        hive = RegistryHive(os.path.join(SAMPLES, "registry-hives", "SOFTWARE"))
        run_key = hive.get_key(r"\Microsoft\Windows\CurrentVersion\Run")
        self.assertIn("EncodedCommand", run_key.get_value("WindowsUpdate"))


class ExtractEventLogs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "security.json")
        cls.result = run([PY, os.path.join(SCRIPTS, "extract_eventlogs.py"),
                          os.path.join(SAMPLES, "event-logs", "Security.evtx"), cls.out])
        cls.doc = load(cls.out)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_counts_and_summary(self):
        self.assertEqual(self.result.returncode, 0)
        self.assertEqual(self.doc["record_count"], 1268)
        self.assertEqual(sum(e["event_id"] == 4625 for e in self.doc["events"]), 1201)
        self.assertIn("Top 10 event IDs", self.result.stdout)
        self.assertIn("4625    1201", self.result.stdout)

    def test_fields(self):
        events = self.doc["events"]
        logon = next(e for e in events if e["event_id"] == 4624
                     and e["event_data"].get("IpAddress") == "203.0.113.50")
        self.assertEqual(logon["event_data"]["TargetUserName"], "it-admin")
        self.assertEqual(logon["event_data"]["LogonType"], "3")
        self.assertEqual(logon["computer_name"], "WS-LAB-07")
        self.assertIn("<EventID>4624</EventID>", logon["xml"])
        cleared = events[-1]
        self.assertEqual(cleared["event_id"], 1102)
        self.assertEqual(cleared["event_data"]["SubjectUserName"], "it-admin")   # from UserData
        for e in events:
            self.assertRegex(e["timestamp"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z$")

    def test_chain_of_custody_and_permissions(self):
        self.assertEqual(self.doc["source_sha256"], sha256(os.path.join(SAMPLES, "event-logs", "Security.evtx")))
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o600)

    def test_no_xml_option(self):
        out = os.path.join(self.tmp, "sys.json")
        run([PY, os.path.join(SCRIPTS, "extract_eventlogs.py"),
             os.path.join(SAMPLES, "event-logs", "System.evtx"), out, "--no-xml"])
        with open(out) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["record_count"], 50)
        self.assertNotIn("xml", doc["events"][0])

    def test_bad_inputs(self):
        r = run([PY, os.path.join(SCRIPTS, "extract_eventlogs.py"), "/nonexistent.evtx", "x.json"])
        self.assertEqual(r.returncode, 2)
        r = run([PY, os.path.join(SCRIPTS, "extract_eventlogs.py"),
                 os.path.join(SAMPLES, "registry-hives", "SYSTEM"), os.path.join(self.tmp, "x.json")])
        self.assertEqual(r.returncode, 2)
        self.assertIn("not an EVTX file", r.stderr)

    def test_damaged_record_is_skipped(self):
        damaged = os.path.join(self.tmp, "damaged.evtx")
        data = bytearray(read(os.path.join(SAMPLES, "event-logs", "System.evtx"), "rb"))
        # Break the template-instance token of the 10th record in the first chunk.
        offset, count = 0x1000 + 0x200, 0
        while count < 9:
            offset += struct.unpack_from("<I", data, offset + 4)[0]
            count += 1
        data[offset + 0x18 + 4] = 0xFF
        with open(damaged, "wb") as fh:
            fh.write(bytes(data))
        out = os.path.join(self.tmp, "damaged.json")
        r = run([PY, os.path.join(SCRIPTS, "extract_eventlogs.py"), damaged, out])
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as fh:
            doc = json.load(fh)
        self.assertTrue(doc["parse_errors"])
        self.assertGreater(doc["record_count"], 40)


class ExtractRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        hives = os.path.join(SAMPLES, "registry-hives")
        cls.sys_out = os.path.join(cls.tmp, "system.json")
        cls.soft_out = os.path.join(cls.tmp, "software.json")
        cls.r_sys = run([PY, os.path.join(SCRIPTS, "extract_registry.py"), os.path.join(hives, "SYSTEM"),
                         "-o", cls.sys_out])
        cls.r_soft = run([PY, os.path.join(SCRIPTS, "extract_registry.py"), os.path.join(hives, "SOFTWARE"),
                          "-o", cls.soft_out])
        cls.system = load(cls.sys_out)
        cls.software = load(cls.soft_out)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_system_info(self):
        info = self.system["system_info"]
        self.assertEqual(info["computer_name"], "WS-LAB-07")
        self.assertEqual(info["current_control_set"], "ControlSet001")
        self.assertEqual(info["timezone"]["utc_offset_minutes"], 300)
        services = {s["name"]: s for s in info["services"]}
        self.assertEqual(services["WinUpdateHelper"]["image_path"], r"C:\Users\Public\Libraries\winupdate.exe")
        self.assertEqual(services["WinDefend"]["start_type"], "disabled")
        self.assertEqual(info["network_interfaces"][0]["ip_address"], "10.20.30.47")
        self.assertTrue(info["last_shutdown"].startswith("2026-11-19T12:52"))

    def test_software_info(self):
        names = [a["name"] for a in self.software["installed_software"]]
        self.assertIn("AnyDesk", names)
        run_entry = next(s for s in self.software["startup_entries"] if s["name"] == "WindowsUpdate")
        self.assertIn("-EncodedCommand", run_entry["command"])
        self.assertEqual(self.software["defender"]["exclusions_paths"], [r"C:\Users\Public\Libraries"])

    def test_secret_masked_unless_asked(self):
        self.assertNotIn(SECRET, read(self.soft_out))
        self.assertIn("masked", read(self.soft_out))
        out = os.path.join(self.tmp, "plain.json")
        run([PY, os.path.join(SCRIPTS, "extract_registry.py"), os.path.join(SAMPLES, "registry-hives", "SOFTWARE"),
             "-o", out, "--show-secrets"])
        self.assertIn(SECRET, read(out))

    def test_key_mode_translates_live_paths(self):
        out = os.path.join(self.tmp, "key.json")
        r = run([PY, os.path.join(SCRIPTS, "extract_registry.py"), os.path.join(SAMPLES, "registry-hives", "SYSTEM"),
                 r"HKLM\SYSTEM\CurrentControlSet\Services\WinUpdateHelper", "-o", out])
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = load(out)
        self.assertEqual(doc["resolved_key"], r"ControlSet001\Services\WinUpdateHelper")
        self.assertEqual(doc["key"]["last_written"], "2026-11-20T21:18:12.000000Z")

    def test_missing_key_and_bad_file(self):
        r = run([PY, os.path.join(SCRIPTS, "extract_registry.py"), os.path.join(SAMPLES, "registry-hives", "SYSTEM"),
                 r"No\Such\Key", "-o", os.path.join(self.tmp, "k.json")])
        self.assertEqual(r.returncode, 2)
        self.assertIn("key not found", r.stderr)
        r = run([PY, os.path.join(SCRIPTS, "extract_registry.py"), os.path.join(SAMPLES, "event-logs", "System.evtx")])
        self.assertEqual(r.returncode, 2)

    def test_sensitive_name_rules(self):
        for name in ("DefaultPassword", "ApiKey", "api_key", "AccessToken", "ClientSecret", "PrivateKey"):
            self.assertTrue(extract_registry.is_sensitive_name(name), name)
        for name in ("TimeZoneKeyName", "KeyboardDelay", "ProductName", "Shell", "AutoAdminLogon"):
            self.assertFalse(extract_registry.is_sensitive_name(name), name)


@unittest.skipUnless(PWSH, "pwsh not installed")
class Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        build_case(cls.tmp)
        cls.ps, cls.an = run_pipeline(cls.tmp)
        cls.out = os.path.join(cls.tmp, "forensic_output")
        cls.ioc = load(os.path.join(cls.out, "ioc_report.json"))
        cls.titles = [a["title"] for a in cls.ioc["anomalies"]]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def anomaly(self, category, contains=""):
        found = [a for a in self.ioc["anomalies"] if a["category"] == category and contains in a["title"]]
        self.assertTrue(found, "no %s anomaly containing %r in %s" % (category, contains, self.titles))
        return found[0]

    def test_expected_outputs(self):
        for name in ("system_events_analysis.json", "security_events_analysis.json", "registry_analysis.json",
                     "forensic_timeline.json", "ioc_report.json", "forensic_report.md", "ioc_summary.txt"):
            self.assertTrue(os.path.isfile(os.path.join(self.out, name)), name)
        self.assertEqual(self.an.returncode, 1)          # High/Critical present

    def test_brute_force_then_success(self):
        a = self.anomaly("compromised account")
        self.assertEqual(a["severity"], "Critical")
        self.assertEqual(a["evidence"]["account"], "it-admin")
        self.assertEqual(a["evidence"]["ip"], "203.0.113.50")
        b = self.anomaly("brute force")
        self.assertEqual(b["evidence"]["failed"], 1200)
        self.assertEqual(self.ioc["indicators"]["ip_addresses"], ["203.0.113.50"])

    def test_key_indicators(self):
        self.assertEqual(self.anomaly("anti-forensics")["severity"], "High")
        svc = self.anomaly("persistence", "Windows Update Helper")
        self.assertEqual(len(svc["sources"]), 2)        # System log 7045 + SYSTEM hive
        defender = self.anomaly("defense evasion", "Defender Antivirus Service disabled")
        self.assertEqual(len(defender["sources"]), 2)   # 7040 + Start=4
        self.anomaly("defense evasion", "Defender exclusion")
        self.anomaly("persistence", "Autostart entry 'WindowsUpdate'")
        self.anomaly("remote access", "AnyDesk")
        self.anomaly("account manipulation", "added to Administrators")
        self.anomaly("credential exposure", "DefaultPassword")
        self.anomaly("user behavior", "it-admin")

    def test_encoded_command_decoded_not_run(self):
        a = self.anomaly("execution")
        self.assertIn("FORENSICS-LAB SAMPLE", a["evidence"]["decoded_command"])
        self.assertEqual(len(a["sources"]), 2)          # 4688 + Run key

    def test_handout_rules(self):
        hf = self.anomaly("high frequency", "4625")
        self.assertEqual(hf["severity"], "Medium")      # >1000 but <=5000
        off = self.anomaly("off-hours activity")
        self.assertIn("02:04", off["title"])            # 21:04 UTC is 02:04 in Pakistan
        self.assertEqual(self.ioc["time_zone_used"]["utc_offset_minutes"], 300)

    def test_secret_never_in_outputs(self):
        for path in glob.glob(os.path.join(self.tmp, "**", "*"), recursive=True):
            raw_evidence = path.endswith(".evtx") or os.path.basename(path) in ("SYSTEM", "SOFTWARE")
            if os.path.isfile(path) and not raw_evidence:
                with open(path, "rb") as fh:
                    self.assertNotIn(SECRET.encode(), fh.read(), path)

    def test_timeline_sorted_and_report_sections(self):
        timeline = load(os.path.join(self.out, "forensic_timeline.json"))
        stamps = [e["Timestamp"] for e in timeline["Entries"]]
        self.assertEqual(stamps, sorted(stamps))
        report = read(os.path.join(self.out, "forensic_report.md"))
        for heading in ("## Files processed", "## Key findings", "## Suspicious activity indicators",
                        "## Timeline", "## Recommendations"):
            self.assertIn(heading, report)
        self.assertIn("1200 failed logons from 203.0.113.50", report)

    def test_utc_offset_override(self):
        r = run([PY, os.path.join(SCRIPTS, "analyze_activity.py"), "--data-dir", self.out, "--utc-offset", "+00:00"])
        self.assertEqual(r.returncode, 1)
        ioc = load(os.path.join(self.out, "ioc_report.json"))
        self.assertFalse([a for a in ioc["anomalies"] if a["category"] == "off-hours activity"])
        run([PY, os.path.join(SCRIPTS, "analyze_activity.py"), "--data-dir", self.out])   # restore

    def test_local_time_zone_does_not_change_results(self):
        other = tempfile.mkdtemp()
        try:
            build_case(other)
            ignore = {"AnalyzedAt", "Generated", "extracted_at"}
            outputs = []
            for tz in ("Asia/Karachi", "America/New_York"):
                run_pipeline(other, extra_env={"TZ": tz})
                docs = {}
                for name in ("security_events_analysis.json", "registry_analysis.json", "forensic_timeline.json"):
                    doc = load(os.path.join(other, "forensic_output", name))
                    docs[name] = {k: v for k, v in doc.items() if k not in ignore}
                outputs.append(docs)
            self.assertEqual(outputs[0], outputs[1])
        finally:
            shutil.rmtree(other)


@unittest.skipUnless(PWSH, "pwsh not installed")
class CleanBaseline(unittest.TestCase):
    def test_clean_machine_has_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            build_case(tmp, scenario="clean")
            ps, an = run_pipeline(tmp)
            self.assertEqual(an.returncode, 0, an.stdout)
            ioc = load(os.path.join(tmp, "forensic_output", "ioc_report.json"))
            self.assertEqual(ioc["total_anomalies"], 0, [a["title"] for a in ioc["anomalies"]])
            report = read(os.path.join(tmp, "forensic_output", "forensic_report.md"))
            self.assertIn("No indicators found", report)


@unittest.skipUnless(PWSH, "pwsh not installed")
class HostileInput(unittest.TestCase):
    def test_event_text_cannot_break_the_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            build_case(tmp, scenario="clean")
            nasty = "evil|svc\n## Injected heading <img src=x onerror=alert(1)> `rm -rf /`"
            when = datetime(2026, 11, 21, 1, 0, tzinfo=timezone.utc)
            write_evtx(os.path.join(tmp, "event-logs", "Extra.evtx"), [
                Event(7045, when, "Service Control Manager", "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
                      "System", "WS-LAB-07", data=[("ServiceName", nasty), ("ImagePath", r"C:\Temp\x.exe"),
                                                  ("ServiceType", "user mode service"),
                                                  ("StartType", "auto start"), ("AccountName", "LocalSystem")],
                      user_sid="S-1-5-18", event_source_name="Service Control Manager")])
            r = run([PY, os.path.join(SCRIPTS, "extract_eventlogs.py"), "Extra.evtx", "extra_events.json"],
                    cwd=os.path.join(tmp, "event-logs"))
            self.assertEqual(r.returncode, 0, r.stderr)
            run_pipeline(tmp)
            report = read(os.path.join(tmp, "forensic_output", "forensic_report.md"))
            self.assertNotIn("\n## Injected heading", report)
            self.assertNotIn("<img", report)
            self.assertIn(r"evil\|svc", report)
            ioc = load(os.path.join(tmp, "forensic_output", "ioc_report.json"))
            svc = [a for a in ioc["anomalies"] if a["category"] == "persistence"]
            self.assertEqual(svc[0]["severity"], "High")        # C:\Temp is user-writable


@unittest.skipUnless(PWSH, "pwsh not installed")
class PowerShellSyntax(unittest.TestCase):
    def test_script_parses_cleanly(self):
        cmd = ("$e=$null; [System.Management.Automation.Language.Parser]::ParseFile('%s',[ref]$null,[ref]$e)"
               " | Out-Null; $e.Count" % os.path.join(SCRIPTS, "forensic_automation.ps1"))
        r = run([PWSH, "-NoProfile", "-Command", cmd])
        self.assertEqual(r.stdout.strip(), "0", r.stdout + r.stderr)

    def test_missing_data_path(self):
        r = run([PWSH, "-NoProfile", "-File", os.path.join(SCRIPTS, "forensic_automation.ps1"),
                 "-DataPath", "/nonexistent/folder"])
        self.assertEqual(r.returncode, 2)


class AnalyzerUnits(unittest.TestCase):
    def test_parse_offset(self):
        self.assertEqual(analyze_activity.parse_offset("+05:00"), 300)
        self.assertEqual(analyze_activity.parse_offset("-0430"), -270)
        self.assertEqual(analyze_activity.parse_offset("5.5"), 330)

    def test_decode_powershell(self):
        enc = base64.b64encode("Write-Output 'hi'".encode("utf-16-le")).decode()
        self.assertEqual(analyze_activity.decode_powershell("powershell -nop -enc " + enc), "Write-Output 'hi'")
        self.assertIsNone(analyze_activity.decode_powershell("powershell -File x.ps1"))

    def test_off_hours_falls_back_to_date_range(self):
        a = analyze_activity.ForensicAnalyzer(utc_offset_minutes=0)
        a.offset_source = "test"
        a.detect_off_hours_activity({"x_analysis.json": {
            "AnalysisType": "EventLog", "DateRange": {"Start": "2026-11-20T23:30:00.000000Z",
                                                      "End": "2026-11-20T23:45:00.000000Z"}}})
        self.assertEqual(len(a.anomalies), 1)
        self.assertEqual(a.anomalies[0]["severity"], "Medium")

    def test_high_frequency_thresholds(self):
        a = analyze_activity.ForensicAnalyzer()
        a.detect_high_frequency_events({"x_analysis.json": {"AnalysisType": "EventLog", "Channel": "Security",
                                                            "TopEventIDs": [{"EventID": 4625, "Count": 6000},
                                                                            {"EventID": 4624, "Count": 1001},
                                                                            {"EventID": 4634, "Count": 1000}]}})
        self.assertEqual([x["severity"] for x in a.anomalies], ["High", "Medium"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
