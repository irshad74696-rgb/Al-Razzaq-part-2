#!/usr/bin/env python3
"""
Find abnormal activity in the output of forensic_automation.ps1 and write
an Indicators of Compromise (IOC) report.

    python3 analyze_activity.py
    python3 analyze_activity.py --data-dir ./forensic_output --utc-offset +05:00

Reads  <data-dir>/*_analysis.json (and forensic_timeline.json if present).
Writes <data-dir>/ioc_report.json and <data-dir>/ioc_summary.txt, and prints
the summary.

Every anomaly has a severity (Critical, High, Medium, Low), a category, the
evidence it rests on, the time in UTC and in the machine's local time, and
the MITRE ATT&CK technique it maps to. When the event logs and the registry
show the same thing (a service, a disabled Defender), the two are merged into
one anomaly that lists both sources.

"Off hours" is judged in the machine's own time zone: taken from the SYSTEM
hive (via registry_analysis.json) unless --utc-offset is given, UTC if
neither is available.

Exit status: 0 if nothing High or Critical was found, 1 if something was,
2 if there was nothing to analyse.
"""

import argparse
import glob
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from winevents import event_name, iso_utc, parse_timestamp, write_json  # noqa: E402

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SENSITIVE_KEYWORDS = ("password", "passwd", "pwd", "secret", "token", "key", "credential")
SECURITY_PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1$|fe80:|f[cd])")
USER_WRITABLE = re.compile(
    r"(\\Users\\Public\\|\\AppData\\|\\Temp\\|\\Windows\\Temp\\|\\PerfLogs\\|\\Downloads\\|\\ProgramData\\(?!Microsoft\\))",
    re.IGNORECASE)
CONTEXT_ONLY_IDS = {6005, 6006, 6013, 7036}

RECOMMENDATIONS = {
    "brute force": "Block the attacking addresses, enable account lockout (for example 10 attempts / 15 minutes) "
                   "and stop exposing SMB/RDP to the internet; put remote access behind a VPN with MFA.",
    "compromised account": "Reset the password of every account that logged on after a brute force, end its "
                           "sessions, and review everything it did; check other machines for the same credentials.",
    "account manipulation": "Disable and investigate accounts created or added to Administrators during the "
                            "incident; compare group membership with an approved list.",
    "persistence": "Image or copy and hash the binaries behind new services and autostart entries, then remove "
                   "them once evidence is preserved.",
    "defense evasion": "Re-enable Microsoft Defender, remove exclusions nobody approved, and run a full offline scan.",
    "anti-forensics": "The audit log was cleared: recover older events from a log forwarder/SIEM, shadow copies or "
                      "backups, and forward logs off the machine so a local clear cannot erase them.",
    "execution": "Decode and review every encoded PowerShell command; enable PowerShell script block logging "
                 "(event 4104) and process command-line auditing (event 4688).",
    "remote access": "Remove remote access tools that were not approved and check their own connection logs.",
    "credential exposure": "Remove plaintext credentials from the registry (Winlogon DefaultPassword, app "
                           "settings) and rotate those passwords.",
    "off-hours activity": "Confirm with the account owners whether the off-hours activity was theirs; alert on "
                          "admin activity outside business hours.",
    "high frequency": "Compare high event volumes with a normal day for this machine before calling them malicious.",
    "user behavior": "Review the machines and accounts with the most suspicious events first.",
}


def parse_offset(text):
    """'+05:00', '-0430', '5', '+5.5' -> minutes."""
    m = re.match(r"^([+-])?(\d{1,2})(?::?(\d{2}))?$", text.strip())
    if m:
        minutes = int(m.group(2)) * 60 + int(m.group(3) or 0)
        return -minutes if m.group(1) == "-" else minutes
    return int(round(float(text) * 60))


def decode_powershell(command):
    m = re.search(r"(?i)-e(?:nc|ncodedcommand|c)?\s+([A-Za-z0-9+/=]{16,})", command or "")
    if not m:
        return None
    import base64
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return None


class ForensicAnalyzer:
    def __init__(self, data_dir="./forensic_output", utc_offset_minutes=None,
                 business_hours=(6, 22), high_frequency=1000, very_high_frequency=5000,
                 computer_threshold=50, failed_logon_threshold=10):
        self.data_dir = data_dir
        self.anomalies = []
        self._by_key = {}
        self.utc_offset_minutes = utc_offset_minutes
        self.offset_source = "command line" if utc_offset_minutes is not None else None
        self.business_hours = business_hours
        self.high_frequency = high_frequency
        self.very_high_frequency = very_high_frequency
        self.computer_threshold = computer_threshold
        self.failed_logon_threshold = failed_logon_threshold
        self.files_loaded = []

    # ------------------------------------------------------------------
    def load_analysis_files(self):
        """Load every *_analysis.json (and the timeline) from the data folder."""
        data = {}
        patterns = [os.path.join(self.data_dir, "*_analysis.json"),
                    os.path.join(self.data_dir, "forensic_timeline.json")]
        for path in sorted(p for pattern in patterns for p in glob.glob(pattern)):
            try:
                with open(path, encoding="utf-8-sig") as fh:
                    data[os.path.basename(path)] = json.load(fh)
                self.files_loaded.append(os.path.basename(path))
            except (OSError, json.JSONDecodeError) as exc:
                print("warning: skipping %s: %s (validate it with: jq . %s)" % (path, exc, path),
                      file=sys.stderr)
        if self.utc_offset_minutes is None:
            reg = data.get("registry_analysis.json", {})
            offset = (reg.get("System") or {}).get("UtcOffsetMinutes")
            if isinstance(offset, int):
                self.utc_offset_minutes = offset
                tz_name = (reg.get("System") or {}).get("TimeZone") or "registry"
                self.offset_source = "SYSTEM hive (%s)" % tz_name
            else:
                self.utc_offset_minutes = 0
                self.offset_source = "default (UTC; no time zone in the evidence)"
        return data

    # ------------------------------------------------------------------
    def _local(self, ts):
        dt = parse_timestamp(ts) if isinstance(ts, str) else ts
        if dt is None:
            return None
        return dt + timedelta(minutes=self.utc_offset_minutes)

    def _local_text(self, ts):
        local = self._local(ts)
        if local is None:
            return None
        sign = "+" if self.utc_offset_minutes >= 0 else "-"
        off = abs(self.utc_offset_minutes)
        return local.strftime("%a %Y-%m-%d %H:%M:%S") + " (UTC%s%02d:%02d)" % (sign, off // 60, off % 60)

    def add(self, severity, category, title, description, evidence=None, timestamp=None,
            source=None, mitre=None, key=None):
        """Record one anomaly; a second finding with the same key is merged into the first."""
        if key and key in self._by_key:
            existing = self._by_key[key]
            if SEVERITY_ORDER[severity] < SEVERITY_ORDER[existing["severity"]]:
                existing["severity"] = severity
            if source and source not in existing["sources"]:
                existing["sources"].append(source)
                existing["title"] = re.sub(r" \(confirmed by \d+ sources\)$", "", existing["title"])
                existing["title"] += " (confirmed by %d sources)" % len(existing["sources"])
            for k, v in (evidence or {}).items():
                existing["evidence"].setdefault(k, v)
            if timestamp and (not existing["timestamp"] or timestamp < existing["timestamp"]):
                existing["timestamp"] = timestamp
                existing["local_time"] = self._local_text(timestamp)
            return existing
        anomaly = {
            "id": "A%03d" % (len(self.anomalies) + 1),
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "timestamp": timestamp,
            "local_time": self._local_text(timestamp) if timestamp else None,
            "sources": [source] if source else [],
            "mitre_attack": mitre,
            "evidence": dict(evidence or {}),
        }
        self.anomalies.append(anomaly)
        if key:
            self._by_key[key] = anomaly
        return anomaly

    @staticmethod
    def _event_analyses(analysis_data):
        return [(name, a) for name, a in analysis_data.items() if a.get("AnalysisType") == "EventLog"]

    @staticmethod
    def _registry(analysis_data):
        return analysis_data.get("registry_analysis.json") or next(
            (a for a in analysis_data.values() if a.get("AnalysisType") == "Registry"), {})

    # ------------------------------------------------------------------
    def detect_high_frequency_events(self, analysis_data):
        """Event IDs seen more than 1000 times (Medium) or 5000 times (High)."""
        for name, analysis in self._event_analyses(analysis_data):
            for top in analysis.get("TopEventIDs") or []:
                count = int(top.get("Count", 0))
                if count <= self.high_frequency:
                    continue
                severity = "High" if count > self.very_high_frequency else "Medium"
                event_id = top.get("EventID")
                self.add(severity, "high frequency",
                         "Event %s occurred %d times" % (event_id, count),
                         "%s (%s) appears %d times in the %s log, above the %d threshold. On a busy server "
                         "this can be normal; compare with a normal day before concluding anything."
                         % (event_id, event_name(event_id), count, analysis.get("Channel"), self.high_frequency),
                         evidence={"file": name, "event_id": event_id, "count": count,
                                   "date_range": analysis.get("DateRange")},
                         source=name)

    def detect_off_hours_activity(self, analysis_data):
        """Security-relevant activity outside business hours, in the machine's local time."""
        start_h, end_h = self.business_hours
        timeline = (analysis_data.get("forensic_timeline.json") or {}).get("Entries") or []
        items = []
        for entry in timeline:
            if entry.get("EventID") in CONTEXT_ONLY_IDS or entry.get("Category") == "system":
                continue
            local = self._local(entry.get("Timestamp"))
            if local and not (start_h <= local.hour < end_h):
                items.append((local, entry))
        if not timeline:                        # fall back to the handout's DateRange approach
            for name, analysis in self._event_analyses(analysis_data):
                for key in ("Start", "End"):
                    ts = (analysis.get("DateRange") or {}).get(key)
                    local = self._local(ts)
                    if local and not (start_h <= local.hour < end_h):
                        items.append((local, {"Timestamp": ts, "Description": "log %s" % key.lower(),
                                              "Source": name}))
        # Group into windows: entries less than two hours apart belong together.
        items.sort(key=lambda x: x[0])
        windows = []
        for local, entry in items:
            if windows and local - windows[-1][-1][0] <= timedelta(hours=2):
                windows[-1].append((local, entry))
            else:
                windows.append([(local, entry)])
        total_by_hour = [0] * 24
        for _, analysis in self._event_analyses(analysis_data):
            for hour, count in enumerate(analysis.get("EventsByHourUTC") or []):
                total_by_hour[(hour + self.utc_offset_minutes // 60) % 24] += int(count)
        off_hours_events = sum(c for h, c in enumerate(total_by_hour) if not (start_h <= h < end_h))
        for window in windows:
            first, last = window[0], window[-1]
            self.add("Medium", "off-hours activity",
                     "%d security-relevant events between %s and %s local time" % (
                         len(window), first[0].strftime("%a %d %b %H:%M"), last[0].strftime("%H:%M")),
                     "Activity outside business hours (%02d:00-%02d:00, time zone from %s)."
                     % (start_h, end_h, self.offset_source),
                     evidence={"events": [
                         {"utc": e.get("Timestamp"), "local": l.strftime("%Y-%m-%d %H:%M:%S"),
                          "what": e.get("Description")} for l, e in window[:25]],
                         "all_events_off_hours": off_hours_events,
                         "events_by_local_hour": total_by_hour},
                     timestamp=first[1].get("Timestamp"), source="forensic_timeline.json",
                     mitre="T1078 Valid Accounts (activity timing)")

    def detect_suspicious_registry_values(self, analysis_data):
        """Registry values whose names suggest stored secrets."""
        reg = self._registry(analysis_data)
        for value in reg.get("InterestingValues") or []:
            name = value.get("Name", "")
            if not any(k in name.lower() for k in SENSITIVE_KEYWORDS):
                continue
            self.add("High", "credential exposure",
                     "Possible stored secret: %s" % name,
                     "Registry value %s\\%s looks like a stored credential (keyword '%s'). Its content is "
                     "masked in this report." % (value.get("Key"), name, value.get("Keyword")),
                     evidence={"key": value.get("Key"), "value": name, "data_masked": value.get("Data"),
                               "file": value.get("File")},
                     source="registry_analysis.json", mitre="T1552.002 Credentials in Registry")

    def analyze_user_behavior(self, analysis_data):
        """Suspicious events per computer, and per account across all sources."""
        per_computer = Counter()
        for _, analysis in self._event_analyses(analysis_data):
            for computer, count in (analysis.get("SuspiciousByComputer") or {}).items():
                per_computer[computer] += int(count)
        for computer, count in per_computer.most_common():
            if count > self.computer_threshold:
                self.add("High" if count > 10 * self.computer_threshold else "Medium", "user behavior",
                         "%s: %d suspicious events" % (computer, count),
                         "More than %d events with watched IDs on one computer." % self.computer_threshold,
                         evidence={"computer": computer, "suspicious_events": count},
                         source="*_events_analysis.json")

        # Which accounts did the suspicious things, and how fast?
        actions = defaultdict(list)
        actor_fields = ("SubjectUserName",)
        for _, analysis in self._event_analyses(analysis_data):
            for n in analysis.get("NotableEvents") or []:
                details = n.get("Details") or {}
                # 4672 accompanies every admin logon, so it says nothing about behaviour.
                if n.get("EventID") in CONTEXT_ONLY_IDS or n.get("EventID") in (4624, 4672):
                    continue
                for field in actor_fields:
                    user = details.get(field)
                    if user and user not in ("-", "SYSTEM") and not user.endswith("$"):
                        actions[user].append((n.get("Timestamp"), n.get("EventID"), n.get("Description")))
        for user, all_items in actions.items():
            # Split into bursts (gaps over two hours start a new one); report the biggest.
            all_items.sort()
            bursts = []
            for item in all_items:
                t = parse_timestamp(item[0])
                if bursts and t and bursts[-1][-1][1] and t - bursts[-1][-1][1] <= timedelta(hours=2):
                    bursts[-1].append((item, t))
                else:
                    bursts.append([(item, t)])
            items = [i for i, _ in max(bursts, key=len)] if bursts else []
            if len(items) < 3:
                continue
            first, last = parse_timestamp(items[0][0]), parse_timestamp(items[-1][0])
            minutes = (last - first).total_seconds() / 60 if first and last else None
            self.add("High" if minutes is not None and minutes <= 60 else "Medium", "user behavior",
                     "Account %s performed %d sensitive actions%s" % (
                         user, len(items), " in %d minutes" % round(minutes) if minutes is not None else ""),
                     "Several high-impact actions by one account in a short time is typical of an intruder "
                     "working through a checklist.",
                     evidence={"account": user, "actions": [
                         {"utc": t, "event_id": i, "what": d} for t, i, d in items]},
                     timestamp=items[0][0], source="*_events_analysis.json", mitre="T1078 Valid Accounts")

    # ------------------------------------------------------------------
    def detect_brute_force(self, analysis_data):
        """Many failed logons from one address; worse if a logon from it then succeeded."""
        for name, analysis in self._event_analyses(analysis_data):
            for src in analysis.get("LogonsBySource") or []:
                failed = int(src.get("Failed", 0))
                ip = src.get("IpAddress") or "-"
                if failed < self.failed_logon_threshold or ip in ("-", ""):
                    continue
                tried = src.get("AccountsTried") or {}
                self.add("High", "brute force",
                         "%d failed logons from %s" % (failed, ip),
                         "Password guessing from %s%s between %s and %s against %d account names."
                         % (ip, " (a public address)" if src.get("External") else "",
                            src.get("FirstFailure"), src.get("LastFailure"), len(tried)),
                         evidence={"ip": ip, "failed": failed, "first": src.get("FirstFailure"),
                                   "last": src.get("LastFailure"),
                                   "accounts_tried": dict(Counter(tried).most_common()),
                                   "logon_types": src.get("LogonTypes")},
                         timestamp=src.get("FirstFailure"), source=name,
                         mitre="T1110.001 Brute Force: Password Guessing")
                success = src.get("FirstSuccessAfterFailure")
                if success:
                    self.add("Critical", "compromised account",
                             "Brute force succeeded: %s logged on from %s" % (success.get("User"), ip),
                             "A successful logon from the same address after %d failures: the password "
                             "for %s was guessed." % (failed, success.get("User")),
                             evidence={"ip": ip, "account": success.get("User"),
                                       "logon_time": success.get("Timestamp"),
                                       "record_id": success.get("RecordId"), "failures_before": failed},
                             timestamp=success.get("Timestamp"), source=name,
                             mitre="T1078 Valid Accounts (after T1110)")

    def detect_security_events(self, analysis_data):
        """The lab's key indicators: 1102, 7045, 7040, 4720, 4732, 4688, 4648."""
        for name, analysis in self._event_analyses(analysis_data):
            for n in analysis.get("NotableEvents") or []:
                eid, ts, d = n.get("EventID"), n.get("Timestamp"), n.get("Details") or {}
                if eid in (1102, 104):
                    self.add("High", "anti-forensics", "Audit log cleared by %s" % d.get("SubjectUserName", "?"),
                             "Event %d: the %s log was cleared. Everything before it may be gone from this "
                             "machine." % (eid, analysis.get("Channel")),
                             evidence={"account": d.get("SubjectUserName"), "record_id": n.get("RecordId")},
                             timestamp=ts, source=name, mitre="T1070.001 Clear Windows Event Logs")
                elif eid == 7045:
                    path = d.get("ImagePath", "")
                    writable = bool(USER_WRITABLE.search(path))
                    self.add("High" if writable else "Medium", "persistence",
                             "New service '%s'" % d.get("ServiceName"),
                             "Service installed with image %s (%s, runs as %s)%s." % (
                                 path, d.get("StartType"), d.get("AccountName"),
                                 "; the program lives in a folder any user can write to" if writable else ""),
                             evidence={"service": d.get("ServiceName"), "image_path": path,
                                       "start_type": d.get("StartType"), "account": d.get("AccountName"),
                                       "event_record_id": n.get("RecordId")},
                             timestamp=ts, source=name, mitre="T1543.003 Windows Service",
                             key=("service", path.lower().strip('"')))
                elif eid == 7040 and str(d.get("param3", "")).lower() == "disabled":
                    service = d.get("param4") or d.get("param1")
                    security = re.search(r"(?i)defender|windefend|firewall|security|sense|eventlog", str(service) + str(d.get("param1")))
                    self.add("High" if security else "Medium", "defense evasion",
                             "%s disabled" % d.get("param1"),
                             "Start type changed from %s to disabled." % d.get("param2"),
                             evidence={"service": service, "display_name": d.get("param1"),
                                       "event_record_id": n.get("RecordId")},
                             timestamp=ts, source=name, mitre="T1562.001 Disable or Modify Tools",
                             key=("disabled", str(service).lower()))
                elif eid == 4720:
                    self.add("Medium", "account manipulation", "User account %s created" % d.get("TargetUserName"),
                             "Created by %s." % d.get("SubjectUserName"),
                             evidence={"account": d.get("TargetUserName"), "sid": d.get("TargetSid"),
                                       "created_by": d.get("SubjectUserName")},
                             timestamp=ts, source=name, mitre="T1136.001 Create Account: Local Account")
                elif eid == 4732:
                    admins = d.get("TargetSid") == "S-1-5-32-544" or d.get("TargetUserName", "").lower() == "administrators"
                    self.add("High" if admins else "Medium", "account manipulation",
                             "%s added to %s" % (d.get("MemberSid"), d.get("TargetUserName")),
                             "Group membership changed by %s." % d.get("SubjectUserName"),
                             evidence={"member_sid": d.get("MemberSid"), "group": d.get("TargetUserName"),
                                       "changed_by": d.get("SubjectUserName")},
                             timestamp=ts, source=name, mitre="T1098 Account Manipulation")
                elif eid == 4688:
                    cmd = d.get("CommandLine", "")
                    decoded = d.get("DecodedCommand") or decode_powershell(cmd)
                    if decoded or re.search(r"(?i)-w(indowstyle)?\s+hidden|downloadstring|-nop\b", cmd):
                        self.add("High", "execution", "Hidden or encoded PowerShell run by %s" % d.get("SubjectUserName"),
                                 "%s started with an obfuscated command line." % d.get("NewProcessName"),
                                 evidence={"process": d.get("NewProcessName"), "parent": d.get("ParentProcessName"),
                                           "command_line": cmd[:300], "decoded_command": decoded},
                                 timestamp=ts, source=name,
                                 mitre="T1059.001 PowerShell; T1027 Obfuscated Files or Information",
                                 key=("encoded", (decoded or cmd)[:200]))
                elif eid == 4648:
                    self.add("Low", "account manipulation",
                             "%s used explicit credentials for %s" % (d.get("SubjectUserName"), d.get("TargetUserName")),
                             "Logon with explicit credentials via %s. Normal for runas and scheduled tasks; "
                             "suspicious right after a compromise." % d.get("ProcessName"),
                             evidence={"account": d.get("SubjectUserName"), "target": d.get("TargetUserName"),
                                       "process": d.get("ProcessName")},
                             timestamp=ts, source=name, mitre="T1078 Valid Accounts")

    def detect_registry_persistence(self, analysis_data):
        """Autostart entries, services, Defender tampering and remote tools from the registry."""
        reg = self._registry(analysis_data)
        for entry in reg.get("StartupEntries") or []:
            flags = entry.get("Flags") or []
            if not flags:
                continue
            decoded = entry.get("DecodedCommand") or decode_powershell(entry.get("Command", ""))
            self.add("High", "persistence", "Autostart entry '%s'" % entry.get("Name"),
                     "%s\\%s starts at every logon: %s." % (entry.get("Location"), entry.get("Name"), ", ".join(flags)),
                     evidence={"location": entry.get("Location"), "name": entry.get("Name"),
                               "command": str(entry.get("Command"))[:300], "decoded_command": decoded,
                               "key_last_written": entry.get("LastWritten")},
                     timestamp=entry.get("LastWritten"), source="registry_analysis.json",
                     mitre="T1547.001 Registry Run Keys / Startup Folder")
            if decoded:
                self.add("High", "execution", "Encoded PowerShell in autostart entry '%s'" % entry.get("Name"),
                         "The command is base64-encoded to hide what it does.",
                         evidence={"decoded_command": decoded}, timestamp=entry.get("LastWritten"),
                         source="registry_analysis.json",
                         mitre="T1059.001 PowerShell; T1027 Obfuscated Files or Information",
                         key=("encoded", decoded[:200]))
        for svc in reg.get("FlaggedServices") or []:
            path = svc.get("ImagePath", "")
            self.add("High", "persistence", "New service '%s'" % (svc.get("DisplayName") or svc.get("Name")),
                     "Service %s: %s." % (svc.get("Name"), ", ".join(svc.get("Flags") or [])),
                     evidence={"service_key": svc.get("Name"), "image_path": path,
                               "start_type": svc.get("StartType"), "account": svc.get("Account"),
                               "key_last_written": svc.get("LastWritten")},
                     timestamp=svc.get("LastWritten"), source="registry_analysis.json",
                     mitre="T1543.003 Windows Service", key=("service", path.lower().strip('"')))
        for svc in reg.get("DisabledSecurityServices") or []:
            self.add("High", "defense evasion", "%s disabled" % svc.get("DisplayName"),
                     "Service %s has Start = 4 (disabled) in the registry." % svc.get("Name"),
                     evidence={"service": svc.get("Name"), "key_last_written": svc.get("LastWritten")},
                     timestamp=svc.get("LastWritten"), source="registry_analysis.json",
                     mitre="T1562.001 Disable or Modify Tools", key=("disabled", str(svc.get("Name")).lower()))
        for exc in reg.get("DefenderExclusions") or []:
            self.add("High", "defense evasion", "Defender exclusion: %s" % exc.get("Value"),
                     "Microsoft Defender will not scan this %s." % exc.get("Kind", "path").rstrip("s"),
                     evidence=exc, timestamp=exc.get("LastWritten"), source="registry_analysis.json",
                     mitre="T1562.001 Disable or Modify Tools")
        for app in reg.get("RemoteAccessSoftware") or []:
            location = app.get("InstallLocation") or ""
            self.add("High" if USER_WRITABLE.search(location + "\\") else "Medium", "remote access",
                     "Remote access tool installed: %s %s" % (app.get("Name"), app.get("Version")),
                     "Installed %s%s. Legitimate tools like this are a favourite way for intruders to keep access."
                     % (app.get("InstallDate"), " in %s" % location if location else ""),
                     evidence=app, timestamp=app.get("LastWritten"), source="registry_analysis.json",
                     mitre="T1219 Remote Access Software")

    # ------------------------------------------------------------------
    def generate_ioc_report(self):
        """Severity counts, indicators, recommendations; saved to ioc_report.json."""
        self.anomalies.sort(key=lambda a: (SEVERITY_ORDER[a["severity"]], a["timestamp"] or "9999"))
        for i, anomaly in enumerate(self.anomalies, start=1):
            anomaly["id"] = "A%03d" % i
        counts = Counter(a["severity"] for a in self.anomalies)
        ioc_report = {
            "timestamp": datetime.now().isoformat(),
            "generated_utc": iso_utc(datetime.now(timezone.utc)),
            "analysed_files": self.files_loaded,
            "time_zone_used": {"utc_offset_minutes": self.utc_offset_minutes, "source": self.offset_source,
                               "business_hours": "%02d:00-%02d:00" % self.business_hours},
            "total_anomalies": len(self.anomalies),
            "critical_severity": counts.get("Critical", 0),
            "high_severity": counts.get("High", 0),
            "medium_severity": counts.get("Medium", 0),
            "low_severity": counts.get("Low", 0),
            "indicators": self._indicators(),
            "anomalies": self.anomalies,
            "recommendations": [],
        }
        seen = []
        for anomaly in self.anomalies:
            rec = RECOMMENDATIONS.get(anomaly["category"])
            if rec and rec not in seen:
                seen.append(rec)
        if not self.anomalies:
            seen.append("No anomalies found. Keep this run as a baseline for the next comparison.")
        ioc_report["recommendations"] = seen
        write_json(os.path.join(self.data_dir, "ioc_report.json"), ioc_report)
        return ioc_report

    def _indicators(self):
        ips, accounts, paths, services, keys, commands = set(), set(), set(), set(), set(), set()
        for a in self.anomalies:
            ev = a["evidence"]
            if a["category"] in ("brute force", "compromised account") and ev.get("ip"):
                ips.add(ev["ip"])
            for field in ("account", "created_by", "changed_by"):
                if ev.get(field) and a["category"] in ("compromised account", "account manipulation",
                                                        "user behavior", "anti-forensics"):
                    if field == "account" and ev.get("sid"):
                        accounts.add("%s (%s)" % (ev[field], ev["sid"]))
                    else:
                        accounts.add(ev[field])
            for field in ("image_path", "InstallLocation"):
                if ev.get(field):
                    paths.add(ev[field])
            if ev.get("service") and a["category"] == "persistence":
                services.add(ev["service"])
            if ev.get("service_key"):
                services.add(ev["service_key"])
            if ev.get("location") and ev.get("name"):
                keys.add("HKLM\\SOFTWARE\\%s\\%s" % (ev["location"], ev["name"]))
            if a["category"] == "defense evasion" and ev.get("Value"):
                keys.add("HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\%s\\%s"
                         % (str(ev.get("Kind", "paths")).title(), ev["Value"]))
            if ev.get("decoded_command"):
                commands.add(ev["decoded_command"])
        return {"ip_addresses": sorted(ips), "accounts": sorted(accounts), "file_paths": sorted(paths),
                "services": sorted(services), "registry_values": sorted(keys),
                "decoded_commands": sorted(commands)}

    def create_visual_summary(self, ioc_report, out=sys.stdout):
        """Text summary: totals, severity bars, top 10 anomalies, recommendations."""
        lines = []
        bar = "=" * 72
        lines += [bar, "  INDICATORS OF COMPROMISE - SUMMARY", bar]
        lines.append("  Files analysed: %s" % ", ".join(ioc_report["analysed_files"]))
        tz = ioc_report["time_zone_used"]
        lines.append("  Local time: UTC%+.1f h from %s; business hours %s" % (
            tz["utc_offset_minutes"] / 60, tz["source"], tz["business_hours"]))
        lines.append("  Total anomalies: %d" % ioc_report["total_anomalies"])
        lines.append("")
        biggest = max([ioc_report[k] for k in ("critical_severity", "high_severity", "medium_severity",
                                               "low_severity")] + [1])
        for label, key in (("Critical", "critical_severity"), ("High", "high_severity"),
                           ("Medium", "medium_severity"), ("Low", "low_severity")):
            n = ioc_report[key]
            lines.append("  %-8s %3d  %s" % (label, n, "#" * max(1 if n else 0, round(30 * n / biggest))))
        lines.append("")
        lines.append("  Top anomalies:")
        for a in ioc_report["anomalies"][:10]:
            when = a["local_time"] or "time unknown"
            lines.append("  [%s] %-8s %s" % (a["id"], a["severity"], a["title"]))
            lines.append("         %s | %s | %s" % (when, a["category"], a["mitre_attack"] or "-"))
        if len(ioc_report["anomalies"]) > 10:
            lines.append("  ... and %d more in ioc_report.json" % (len(ioc_report["anomalies"]) - 10))
        ind = ioc_report["indicators"]
        lines.append("")
        lines.append("  Indicators:")
        for label, key in (("IP addresses", "ip_addresses"), ("Accounts", "accounts"),
                           ("File paths", "file_paths"), ("Services", "services"),
                           ("Registry values", "registry_values"), ("Decoded commands", "decoded_commands")):
            if ind[key]:
                lines.append("    %-17s %s" % (label + ":", "; ".join(ind[key])))
        lines.append("")
        lines.append("  Recommendations:")
        for i, rec in enumerate(ioc_report["recommendations"], 1):
            lines.append("    %d. %s" % (i, rec))
        lines.append(bar)
        text = "\n".join(lines)
        print(text, file=out)
        return text


def main(argv=None):
    parser = argparse.ArgumentParser(description="Detect anomalies and write an IOC report.")
    parser.add_argument("--data-dir", default="./forensic_output",
                        help="folder with the *_analysis.json files (default ./forensic_output)")
    parser.add_argument("--utc-offset", help="machine's UTC offset, e.g. +05:00 (default: from the SYSTEM hive)")
    parser.add_argument("--business-hours", default="6-22", help="local business hours, default 6-22")
    parser.add_argument("--high-frequency", type=int, default=1000, help="event count for Medium (default 1000)")
    parser.add_argument("--very-high-frequency", type=int, default=5000, help="event count for High (default 5000)")
    parser.add_argument("--computer-threshold", type=int, default=50,
                        help="suspicious events per computer before it is flagged (default 50)")
    parser.add_argument("--failed-logons", type=int, default=10,
                        help="failed logons from one address that count as brute force (default 10)")
    args = parser.parse_args(argv)

    start, end = (int(x) for x in args.business_hours.split("-"))
    analyzer = ForensicAnalyzer(
        args.data_dir, utc_offset_minutes=parse_offset(args.utc_offset) if args.utc_offset else None,
        business_hours=(start, end), high_frequency=args.high_frequency,
        very_high_frequency=args.very_high_frequency, computer_threshold=args.computer_threshold,
        failed_logon_threshold=args.failed_logons)

    analysis_data = analyzer.load_analysis_files()
    if not any(k.endswith("_analysis.json") for k in analysis_data):
        print("error: no *_analysis.json files in %s. Run forensic_automation.ps1 first." % args.data_dir,
              file=sys.stderr)
        return 2

    analyzer.detect_high_frequency_events(analysis_data)
    analyzer.detect_brute_force(analysis_data)
    analyzer.detect_security_events(analysis_data)
    analyzer.detect_registry_persistence(analysis_data)
    analyzer.detect_suspicious_registry_values(analysis_data)
    analyzer.detect_off_hours_activity(analysis_data)
    analyzer.analyze_user_behavior(analysis_data)

    report = analyzer.generate_ioc_report()
    text = analyzer.create_visual_summary(report)
    summary_path = os.path.join(args.data_dir, "ioc_summary.txt")
    with open(summary_path, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    print("\nSaved %s and %s" % (os.path.join(args.data_dir, "ioc_report.json"), summary_path))
    if report["critical_severity"] or report["high_severity"]:
        print("Exit status 1: high or critical findings need attention.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
