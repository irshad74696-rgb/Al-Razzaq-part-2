#!/usr/bin/env python3
"""
Linux forensic data analyzer.

Reads a collection made by forensic_collector.sh and looks for signs of
unauthorised activity in three places:

  * authentication logs: brute force by source IP, brute force that ended in a
    successful login, sudo by accounts outside the admin groups, sudo refusals,
    and usernames crafted to inject a fake source address into the log line
  * processes (ps aux): netcat-style tools, programs running from temp folders,
    download tools, very high CPU or memory
  * network sockets (ss -tunap or netstat): listeners and connections on
    well-known backdoor ports, and established connections to public addresses
  * temp folders: files named like backdoors or exploits, executable files

It writes a JSON report, a plain-text report, findings.tsv and timeline.tsv
into a new python_analysis_<time>/ folder. Exit code 1 if anything is HIGH or
CRITICAL, 0 otherwise, 2 on usage errors.

    sudo python3 forensic_analyzer.py                       # newest collection
    python3 forensic_analyzer.py --collection DIR --base DIR
    python3 forensic_analyzer.py --auth-log /tmp/forensics_lab_sim/test_auth.log
"""

import argparse
import datetime
import ipaddress
import json
import os
import re
import socket
import sys
from collections import Counter

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SUSPICIOUS_PROCESS_NAMES = {"nc", "netcat", "ncat", "socat"}
DOWNLOAD_TOOLS = {"wget", "curl"}
SUSPICIOUS_PORTS = {4444, 5555, 6666, 1234, 31337}
TEMP_DIRS = ("/tmp/", "/var/tmp/", "/dev/shm/")
SUSPICIOUS_FILE_WORDS = ("backdoor", "malicious", "exploit")
SENSITIVE_SUDO = [
    (re.compile(r"/etc/(shadow|sudoers)"), "reads or edits credentials/sudo rules"),
    (re.compile(r"chmod\s+\S*\+?x\S*\s+(/tmp|/var/tmp|/dev/shm)"), "makes a temp-folder file executable"),
    (re.compile(r"\b(useradd|adduser|usermod|passwd)\b"), "changes accounts"),
    (re.compile(r"\biptables\b.*\s-F\b|\bufw\s+disable\b"), "disables the firewall"),
]

# Syslog line prefixes: RFC 3339 (rsyslog default on recent Ubuntu, and
# journalctl -o short-iso) and the classic "Nov 28 03:10:01".
ISO_LINE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<msg>.*)$")
BSD_LINE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$")

# The username is matched greedily and the address is anchored to the END of
# the line. sshd writes the attacker-chosen username before "from", so a name
# like "x from 10.9.9.9 port 22" plants a fake address earlier in the line;
# only the last "from <ip> port <n>" is the real one.
TAIL = r" from (?P<ip>[0-9A-Fa-f:.]+) port (?P<port>\d+)(?: ssh2)?(?::.*)?$"
FAILED_RE = re.compile(r"Failed (?P<method>password|publickey|none) for (?P<invalid>invalid user )?(?P<user>.*)" + TAIL)
ACCEPTED_RE = re.compile(r"Accepted (?P<method>password|publickey|keyboard-interactive/pam) for (?P<user>.*)" + TAIL)
SUDO_RE = re.compile(r"sudo(?:\[\d+\])?:\s+(?P<user>\S+)\s+:\s+(?P<rest>.*)$")


def parse_time(ts):
    """Return an aware datetime for a syslog timestamp, or None."""
    try:
        if "T" in ts:
            ts = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", ts.replace("Z", "+00:00"))
            dt = datetime.datetime.fromisoformat(ts)
            return dt if dt.tzinfo else dt.astimezone()
        # Classic syslog has no year: assume this year, last year if that is in the future.
        now = datetime.datetime.now().astimezone()
        dt = datetime.datetime.strptime(f"{now.year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=now.tzinfo)
        if dt > now + datetime.timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        return dt
    except ValueError:
        return None


def is_public(ip):
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    # TEST-NET ranges count as "outside" so the lab's simulated attacker shows up.
    for doc in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"):
        if addr.version == 4 and addr in ipaddress.ip_network(doc):
            return True
    return addr.is_global


def split_hostport(text):
    """'127.0.0.1:4444', '[::]:22', '*:68', '127.0.0.53%lo:53' -> (host, port|None)."""
    host, sep, port = text.rpartition(":")
    if not sep:
        return text, None
    host = host.strip("[]").split("%")[0]
    return host, int(port) if port.isdigit() else None


class LinuxForensicAnalyzer:
    def __init__(self, data_directory, brute_force_threshold=10, admins=None):
        self.data_dir = data_directory
        self.threshold = brute_force_threshold
        self.admins = set(admins) if admins is not None else self._load_admins()
        self.analysis_results = {}
        self.suspicious_activities = []
        self.timeline = []

    # ----------------------------------------------------------------- helpers
    def _load_admins(self):
        """Admin accounts as recorded at collection time, else from this host."""
        path = os.path.join(self.data_dir or "", "users", "admins.txt")
        if os.path.isfile(path):
            with open(path, encoding="utf-8", errors="replace") as fh:
                return {line.strip() for line in fh if line.strip()}
        admins = {"root"}
        try:
            import grp
            for g in ("sudo", "admin", "wheel"):
                try:
                    admins.update(grp.getgrnam(g).gr_mem)
                except KeyError:
                    pass
        except ImportError:
            pass
        return admins

    def add_finding(self, severity, category, summary, evidence="", when=None):
        self.suspicious_activities.append({
            "severity": severity, "category": category, "summary": summary,
            "evidence": evidence, "time": when.isoformat() if when else None,
        })

    def _event(self, when, source, text):
        if when:
            self.timeline.append((when, source, text))

    # ---------------------------------------------------------- authentication
    def analyze_auth_logs(self, auth_log_paths):
        """Failed and successful logins, brute force, sudo use, log injection."""
        print("[INFO] Analyzing authentication logs...")
        if isinstance(auth_log_paths, str):
            auth_log_paths = [auth_log_paths]
        paths = [p for p in auth_log_paths if p and os.path.isfile(p)]
        missing = [p for p in auth_log_paths if p and not os.path.isfile(p)]
        for p in missing:
            print(f"[WARN] auth log not found: {p}")

        failed_by_ip = Counter()
        failed_users = Counter()
        first_fail, last_fail = {}, {}
        successful_logins, sudo_usage, injections = [], [], []
        lines_read = 0

        for path in paths:
            source = os.path.basename(path)
            with open(path, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.rstrip("\n")
                    if not line or line.startswith("#"):
                        continue
                    lines_read += 1
                    m = ISO_LINE.match(line) or BSD_LINE.match(line)
                    when = parse_time(m["ts"]) if m else None
                    msg = m["msg"] if m else line

                    f = FAILED_RE.search(msg)
                    if f:
                        ip, user = f["ip"], f["user"]
                        failed_by_ip[ip] += 1
                        failed_users[user] += 1
                        if when:
                            first_fail.setdefault(ip, when)
                            last_fail[ip] = when
                        if " from " in user or " port " in user:
                            injections.append({"time": when.isoformat() if when else None,
                                               "claimed_user": user, "real_ip": ip, "source": source})
                        continue
                    a = ACCEPTED_RE.search(msg)
                    if a:
                        entry = {"time": when.isoformat() if when else None, "user": a["user"],
                                 "ip": a["ip"], "method": a["method"], "source": source}
                        successful_logins.append(entry)
                        self._event(when, source, f"login accepted: {a['user']} from {a['ip']} ({a['method']})")
                        continue
                    s = SUDO_RE.search(msg)
                    if s and "pam_unix" not in msg:
                        rest = s["rest"]
                        cmd = rest.split("COMMAND=", 1)[1] if "COMMAND=" in rest else ""
                        entry = {"time": when.isoformat() if when else None, "user": s["user"],
                                 "command": cmd, "refused": "NOT in sudoers" in rest
                                 or "incorrect password attempt" in rest, "source": source}
                        sudo_usage.append(entry)
                        self._event(when, source, f"sudo by {s['user']}: {cmd or rest}")

        # Brute force: many failures from one address.
        brute = {ip: n for ip, n in failed_by_ip.items() if n > self.threshold}
        compromised = []
        for ip, n in sorted(brute.items(), key=lambda kv: -kv[1]):
            span = ""
            if ip in first_fail:
                span = f"failures from {first_fail[ip]:%H:%M:%S} to {last_fail[ip]:%H:%M:%S}"
                self._event(first_fail[ip], "analysis", f"brute force from {ip} begins")
                self._event(last_fail[ip], "analysis", f"brute force from {ip}: last failure ({n} in total)")
            # Only a success AFTER the failures started means the guessing worked.
            start = first_fail.get(ip)
            later = [s for s in successful_logins if s["ip"] == ip and
                     (start is None or not s["time"] or parse_time(s["time"]) >= start)]
            if later:
                compromised.append(ip)
                users = sorted({s["user"] for s in later})
                self.add_finding("CRITICAL", "authentication",
                                 f"brute force from {ip} ({n} failures) followed by a successful login",
                                 f"logged in as {', '.join(users)} at {later[0]['time']} via {later[0]['method']}; "
                                 + (span or "failures have no timestamps"),
                                 parse_time(later[0]["time"]) if later[0]["time"] else None)
            else:
                self.add_finding("HIGH", "authentication",
                                 f"brute force from {ip}: {n} failed logins",
                                 f"threshold {self.threshold}" + (f"; {span}" if span else ""), first_fail.get(ip))

        for inj in injections:
            self.add_finding("MEDIUM", "authentication",
                             "log injection attempt: username contains a fake source address",
                             f"real source {inj['real_ip']}; username was {inj['claimed_user']!r}",
                             parse_time(inj["time"]) if inj["time"] else None)

        for entry in sudo_usage:
            when = parse_time(entry["time"]) if entry["time"] else None
            if entry["refused"]:
                self.add_finding("HIGH", "privilege", f"sudo refused for {entry['user']}",
                                 entry["command"] or "not in sudoers", when)
            elif entry["user"] not in self.admins:
                self.add_finding("HIGH", "privilege",
                                 f"sudo used by {entry['user']}, who is not in an admin group",
                                 entry["command"], when)
            for pattern, why in SENSITIVE_SUDO:
                if pattern.search(entry["command"]):
                    self.add_finding("MEDIUM", "privilege", f"sudo command by {entry['user']} {why}",
                                     entry["command"], when)
                    break

        self.analysis_results["authentication"] = {
            "files": paths,
            "lines_read": lines_read,
            "failed_logins_total": sum(failed_by_ip.values()),
            "failed_logins_by_ip": dict(failed_by_ip.most_common()),
            "top_targeted_users": dict(failed_users.most_common(10)),
            "brute_force_ips": brute,
            "brute_force_then_success": compromised,
            "successful_logins": successful_logins,
            "sudo_usage": sudo_usage,
            "log_injection_attempts": injections,
        }
        if not paths:
            print("[WARN] no authentication log to analyse")

    # --------------------------------------------------------------- processes
    def analyze_processes(self, process_file_path, cpu_limit=80.0, mem_limit=50.0):
        """ps aux output: netcat-style tools, temp-folder programs, resource hogs."""
        print("[INFO] Analyzing process information...")
        if not os.path.isfile(process_file_path):
            print(f"[WARN] process file not found: {process_file_path}")
            self.analysis_results["processes"] = {"error": "file not found"}
            return

        processes, suspicious, high_cpu, high_mem, from_temp, downloads = [], [], [], [], [], []
        with open(process_file_path, encoding="utf-8", errors="replace") as fh:
            header = fh.readline()
            if not header.startswith("USER"):
                print("[WARN] does not look like ps aux output")
            for line in fh:
                parts = line.split(None, 10)
                if len(parts) < 11:
                    continue
                user, pid, cpu, mem = parts[0], parts[1], parts[2], parts[3]
                command = parts[10].strip()
                try:
                    cpu_f, mem_f = float(cpu), float(mem)
                except ValueError:
                    continue
                if command.startswith("["):        # kernel thread
                    continue
                exe = command.split()[0]
                name = os.path.basename(exe)
                proc = {"user": user, "pid": int(pid), "cpu": cpu_f, "mem": mem_f, "command": command}
                processes.append(proc)

                if name in SUSPICIOUS_PROCESS_NAMES:
                    args = command.split()[1:]
                    listening = any(a in ("-l", "-lp", "-lvp", "-lnvp", "-k") or a.startswith("-l") for a in args)
                    execs = any(a in ("-e", "-c") for a in args) or "exec:" in command
                    proc["reason"] = "network tool " + ("listening" if listening else "") + (" with exec" if execs else "")
                    suspicious.append(proc)
                    sev = "HIGH" if (listening or execs) else "MEDIUM"
                    self.add_finding(sev, "process", f"{name} running as {user} (PID {pid})"
                                     + (" in listen or exec mode" if (listening or execs) else ""), command)
                elif name in DOWNLOAD_TOOLS:
                    downloads.append(proc)
                    self.add_finding("LOW", "process", f"{name} running as {user} (PID {pid})", command)
                if exe.startswith(TEMP_DIRS):
                    from_temp.append(proc)
                    self.add_finding("HIGH", "process", f"PID {pid} runs a program from a temp folder", f"{exe} ({user}): {command}")
                if cpu_f > cpu_limit:
                    high_cpu.append(proc)
                    self.add_finding("MEDIUM", "process", f"high CPU {cpu_f}% PID {pid} ({name})", command)
                if mem_f > mem_limit:
                    high_mem.append(proc)
                    self.add_finding("MEDIUM", "process", f"high memory {mem_f}% PID {pid} ({name})", command)

        deleted = []
        dpath = os.path.join(os.path.dirname(process_file_path), "deleted_executables.txt")
        if os.path.isfile(dpath):
            with open(dpath, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.strip():
                        pid, _, target = line.rstrip("\n").partition("\t")
                        deleted.append({"pid": pid, "exe": target})
                        self.add_finding("HIGH", "process",
                                         f"PID {pid} runs a program that was deleted from disk", target)

        users = Counter(p["user"] for p in processes)
        self.analysis_results["processes"] = {
            "total": len(processes),
            "by_user": dict(users.most_common()),
            "suspicious_processes": suspicious,
            "download_tools": downloads,
            "running_from_temp": from_temp,
            "deleted_executables": deleted,
            "high_cpu_processes": high_cpu,
            "high_memory_processes": high_mem,
        }

    # ----------------------------------------------------------------- network
    def analyze_network_connections(self, network_file_path):
        """ss -tunap (or netstat -tunap / -an) output: listeners and connections."""
        print("[INFO] Analyzing network connections...")
        if not os.path.isfile(network_file_path):
            print(f"[WARN] network file not found: {network_file_path}")
            self.analysis_results["network"] = {"error": "file not found"}
            return

        listening, established, external, flagged = [], [], [], []
        with open(network_file_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                t = line.split()
                if len(t) < 5 or not t[0].lower().startswith(("tcp", "udp")):
                    continue
                proto = t[0].lower()
                if t[1].isdigit():                 # netstat: proto recvq sendq local peer [state] [pid/prog]
                    local, peer = t[3], t[4]
                    state = t[5] if proto.startswith("tcp") and len(t) > 5 else "UNCONN"
                    rest = t[6:] if proto.startswith("tcp") else t[5:]
                    m = re.match(r"(\d+)/(\S+)", rest[0]) if rest else None
                    process = f"{m[2]} (pid {m[1]})" if m else ""
                else:                              # ss: netid state recvq sendq local peer [process]
                    if len(t) < 6:
                        continue
                    state, local, peer = t[1], t[4], t[5]
                    m = re.search(r'"([^"]+)",pid=(\d+)', line)
                    process = f"{m[1]} (pid {m[2]})" if m else ""
                state = {"ESTAB": "ESTABLISHED"}.get(state, state)
                lhost, lport = split_hostport(local)
                phost, pport = split_hostport(peer)
                conn = {"proto": proto, "state": state, "local": local, "peer": peer, "process": process}

                if state == "LISTEN" or (proto.startswith("udp") and state == "UNCONN" and phost in ("0.0.0.0", "*", "::")):
                    listening.append(conn)
                    if lport in SUSPICIOUS_PORTS:
                        flagged.append(conn)
                        scope = "loopback only" if lhost.startswith("127.") or lhost == "::1" else "reachable from the network"
                        self.add_finding("HIGH", "network", f"listener on backdoor port {lport} ({scope})",
                                         line.strip())
                elif state in ("ESTABLISHED", "SYN-SENT", "SYN_SENT"):
                    established.append(conn)
                    if pport in SUSPICIOUS_PORTS:
                        flagged.append(conn)
                        self.add_finding("HIGH", "network",
                                         f"outbound connection to backdoor port {pport} (possible reverse shell)", line.strip())
                    elif lport in SUSPICIOUS_PORTS and state == "ESTABLISHED":
                        flagged.append(conn)
                        self.add_finding("HIGH", "network",
                                         f"inbound connection on backdoor port {lport}", line.strip())
                    if is_public(phost):
                        external.append(conn)

        # One line per remote address and program, not one per socket.
        grouped = Counter((c["peer"].rpartition(":")[0] + ":" + str(split_hostport(c["peer"])[1]),
                           re.sub(r" \(pid \d+\)", "", c["process"])) for c in external)
        for (peer, prog), n in grouped.most_common():
            self.add_finding("INFO", "network", f"{n} connection(s) to public address {peer} by {prog or 'unknown program'}",
                             "check that this program is expected to talk to this address")

        self.analysis_results["network"] = {
            "listening_ports": sorted({split_hostport(c["local"])[1] for c in listening if split_hostport(c["local"])[1]}),
            "listeners": listening,
            "established_connections": established,
            "external_connections": external,
            "suspicious_port_hits": flagged,
        }

    # ------------------------------------------------------------------- files
    def analyze_temp_files(self, listing_path):
        """files/temp_files.txt: type, mtime, octal mode, owner, size, path."""
        print("[INFO] Analyzing temp-folder file listing...")
        if not os.path.isfile(listing_path):
            print(f"[WARN] file listing not found: {listing_path}")
            self.analysis_results["files"] = {"error": "file not found"}
            return
        named, executable, total = [], [], 0
        with open(listing_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) != 6 or parts[0] != "f":
                    continue
                total += 1
                _, mtime, mode, owner, _size, path = parts
                entry = {"path": path, "mode": mode, "owner": owner, "modified": mtime}
                base = os.path.basename(path).lower()
                if any(word in base for word in SUSPICIOUS_FILE_WORDS):
                    named.append(entry)
                    self.add_finding("HIGH", "file", f"suspicious file name: {path}",
                                     f"mode {mode}, owner {owner}, modified {mtime}")
                elif mode.isdigit() and int(mode, 8) & 0o111:
                    executable.append(entry)
                    self.add_finding("MEDIUM", "file", f"executable file in a temp folder: {path}",
                                     f"mode {mode}, owner {owner}, modified {mtime}")
        self.analysis_results["files"] = {"temp_files": total, "suspicious_names": named,
                                          "executables_in_temp": executable}

    # ------------------------------------------------------------------ report
    def summary(self):
        counts = Counter(f["severity"] for f in self.suspicious_activities)
        return {s: counts.get(s, 0) for s in SEVERITIES}

    def generate_report(self, output_dir):
        """Write analysis.json, analysis.txt, findings.tsv and timeline.tsv."""
        print("[INFO] Generating forensic analysis report...")
        os.makedirs(output_dir, mode=0o700, exist_ok=True)
        order = {s: i for i, s in enumerate(SEVERITIES)}
        findings = sorted(self.suspicious_activities, key=lambda f: (order[f["severity"]], f["time"] or ""))
        timeline = sorted(self.timeline, key=lambda e: e[0])
        report = {
            "analysis_timestamp": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "analyzed_on": socket.gethostname(),
            "data_directory": self.data_dir,
            "brute_force_threshold": self.threshold,
            "summary": self.summary(),
            "analysis_results": self.analysis_results,
            "suspicious_activities": findings,
            "timeline": [{"time": t.isoformat(), "source": s, "event": e} for t, s, e in timeline],
        }
        paths = {k: os.path.join(output_dir, k) for k in
                 ("analysis.json", "analysis.txt", "findings.tsv", "timeline.tsv")}
        with open(paths["analysis.json"], "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

        def clean(v):  # log text is attacker-controlled: no tabs or newlines in TSV fields
            return re.sub(r"[\t\r\n]", " ", str(v or ""))

        with open(paths["findings.tsv"], "w", encoding="utf-8") as fh:
            for f in findings:
                fh.write("\t".join(clean(f[k]) for k in ("severity", "category", "summary", "evidence")) + "\n")
        with open(paths["timeline.tsv"], "w", encoding="utf-8") as fh:
            for t, s, e in timeline:
                fh.write(f"{t.isoformat()}\t{clean(s)}\t{clean(e)}\n")

        auth = self.analysis_results.get("authentication", {})
        procs = self.analysis_results.get("processes", {})
        net = self.analysis_results.get("network", {})
        s = report["summary"]
        lines = [
            "=" * 70, "LINUX FORENSIC ANALYSIS REPORT", "=" * 70,
            f"Generated:  {report['analysis_timestamp']}",
            f"Analyzed on: {report['analyzed_on']}",
            f"Collection: {self.data_dir}", "",
            "SUMMARY",
            "  " + "  ".join(f"{k}: {v}" for k, v in s.items()),
            f"  Auth lines read: {auth.get('lines_read', 0)}, failed logins: {auth.get('failed_logins_total', 0)}, "
            f"successful logins: {len(auth.get('successful_logins', []))}, sudo events: {len(auth.get('sudo_usage', []))}",
            f"  Processes: {procs.get('total', 0)}, listening ports: {', '.join(map(str, net.get('listening_ports', []))) or 'none'}",
            "", "FINDINGS (most severe first)",
        ]
        if not findings:
            lines.append("  none")
        for f in findings:
            lines.append(f"  [{f['severity']:<8}] {f['category']:<14} {f['summary']}")
            if f["evidence"]:
                lines.append(f"  {'':<26} evidence: {f['evidence'][:160]}")
        lines += ["", "FAILED LOGINS BY SOURCE"]
        for ip, n in list(auth.get("failed_logins_by_ip", {}).items())[:10]:
            lines.append(f"  {n:>5}  {ip}")
        lines += ["", "TIMELINE"]
        for t, src, e in timeline:
            lines.append(f"  {t:%Y-%m-%d %H:%M:%S%z}  [{src}] {e}")
        lines.append("")
        with open(paths["analysis.txt"], "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        for p in paths.values():
            os.chmod(p, 0o600)
        return paths


def find_latest_collection(base):
    try:
        names = [d for d in os.listdir(base)
                 if d.startswith("automated_collection_") and os.path.isdir(os.path.join(base, d))]
    except FileNotFoundError:
        return None
    return os.path.join(base, max(names)) if names else None


def main(argv=None):
    """Find the newest collection, run every analysis, write the reports."""
    ap = argparse.ArgumentParser(description="Analyse a forensic_collector.sh collection.")
    ap.add_argument("--base", default=os.environ.get("FORENSICS_BASE", "/home/forensics"),
                    help="folder holding automated_collection_* (default /home/forensics)")
    ap.add_argument("--collection", help="a specific collection folder (default: the newest)")
    ap.add_argument("--auth-log", action="append", default=[],
                    help="extra auth-style log to include, e.g. the simulated one (repeatable)")
    ap.add_argument("--threshold", type=int, default=10, help="failed logins per IP before it is brute force (default 10)")
    ap.add_argument("--output-dir", help="where to write (default BASE/python_analysis_<time>)")
    args = ap.parse_args(argv)

    print("=== Linux Forensic Data Analyzer ===")
    data_dir = args.collection or find_latest_collection(args.base)
    if not data_dir or not os.path.isdir(data_dir):
        print(f"[ERROR] no collection found under {args.base}; run forensic_collector.sh first", file=sys.stderr)
        return 2
    print(f"[INFO] Collection: {data_dir}")

    analyzer = LinuxForensicAnalyzer(data_dir, brute_force_threshold=args.threshold)
    auth_dir = os.path.join(data_dir, "logs", "auth")
    auth_files = [os.path.join(auth_dir, "auth_events.txt")]
    extra_dir = os.path.join(auth_dir, "extra")
    if os.path.isdir(extra_dir):
        auth_files += sorted(os.path.join(extra_dir, f) for f in os.listdir(extra_dir))
    auth_files += args.auth_log
    # The same file passed twice (collected copy and original) would double-count.
    seen, unique = set(), []
    for p in auth_files:
        key = os.path.realpath(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    analyzer.analyze_auth_logs(unique)
    analyzer.analyze_processes(os.path.join(data_dir, "processes", "ps_aux.txt"))
    net = os.path.join(data_dir, "network", "connections.txt")
    if not os.path.isfile(net):
        net = os.path.join(data_dir, "network", "netstat_an.txt")
    analyzer.analyze_network_connections(net)
    analyzer.analyze_temp_files(os.path.join(data_dir, "files", "temp_files.txt"))

    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = args.output_dir or os.path.join(args.base, f"python_analysis_{stamp}")
    paths = analyzer.generate_report(out)
    s = analyzer.summary()
    print("[INFO] Findings: " + ", ".join(f"{k} {v}" for k, v in s.items()))
    for f in sorted(analyzer.suspicious_activities, key=lambda f: SEVERITIES.index(f["severity"])):
        if f["severity"] in ("CRITICAL", "HIGH"):
            print(f"  [{f['severity']}] {f['summary']}")
    print(f"[INFO] Text report: {paths['analysis.txt']}")
    print(f"[INFO] JSON report: {paths['analysis.json']}")
    return 1 if s["CRITICAL"] or s["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
