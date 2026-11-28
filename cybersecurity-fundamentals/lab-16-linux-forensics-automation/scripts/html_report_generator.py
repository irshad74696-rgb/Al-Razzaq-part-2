#!/usr/bin/env python3
"""
HTML forensic report: one self-contained page from the newest Python analysis
(analysis.json) and, if there is one, the newest live detection run
(findings.tsv). Severity colours, a severity bar chart, findings, failed logins
by source, listening sockets and the timeline.

Everything that came from a log is HTML-escaped and the page carries a
Content-Security-Policy that forbids scripts: usernames in auth.log are chosen
by whoever is attacking, so "<script>" as a username must stay text.

    python3 html_report_generator.py                      # newest runs under /home/forensics
    python3 html_report_generator.py --analysis DIR --detection DIR -o report.html
"""

import argparse
import datetime
import html
import json
import os
import sys

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
COLOURS = {"CRITICAL": "#b91c1c", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb", "INFO": "#64748b"}

CSS = """
:root { --bg:#f8fafc; --card:#fff; --ink:#0f172a; --muted:#475569; --line:#e2e8f0; }
@media (prefers-color-scheme: dark) { :root { --bg:#0b1220; --card:#111a2e; --ink:#e2e8f0; --muted:#94a3b8; --line:#1e293b; } }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 system-ui, 'Segoe UI', Ubuntu, sans-serif; background:var(--bg); color:var(--ink); }
main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { margin: 0 0 4px; font-size: 26px; } h2 { margin: 32px 0 12px; font-size: 19px; }
.meta { color: var(--muted); margin: 0 0 20px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; border-top: 4px solid var(--c); }
.card b { display:block; font-size: 28px; } .card span { color: var(--muted); font-size: 13px; letter-spacing: .04em; }
.bar { display:flex; height: 14px; border-radius: 7px; overflow: hidden; margin-top: 14px; background: var(--line); }
.bar i { display:block; background: var(--c); }
table { width: 100%; border-collapse: collapse; background: var(--card); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); }
td code { font: 12.5px ui-monospace, 'DejaVu Sans Mono', monospace; word-break: break-all; }
.sev { display:inline-block; min-width: 76px; text-align:center; color:#fff; font-weight:700; font-size:12px; padding:2px 8px; border-radius: 999px; background: var(--c); }
.hbar { height: 10px; background: #ea580c; border-radius: 5px; }
.wrap { overflow-x: auto; }
footer { color: var(--muted); margin-top: 32px; font-size: 13px; }
"""


def esc(v):
    return html.escape(str(v if v is not None else ""), quote=True)


def latest(base, prefix):
    try:
        names = [d for d in os.listdir(base) if d.startswith(prefix) and os.path.isdir(os.path.join(base, d))]
    except FileNotFoundError:
        return None
    return os.path.join(base, max(names)) if names else None


def load_detection(det_dir):
    rows = []
    path = os.path.join(det_dir, "findings.tsv") if det_dir else None
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                p = line.rstrip("\n").split("\t")
                if len(p) >= 3:
                    rows.append({"severity": p[0], "category": p[1], "summary": p[2],
                                 "evidence": p[3] if len(p) > 3 else "", "source": "live detection"})
    return rows


def merge(analysis_findings, detection_findings):
    """One row per (severity, category, summary); keep every source."""
    merged = {}
    for f in detection_findings + [dict(f, source="data analysis") for f in analysis_findings]:
        key = (f["severity"], f["category"], f["summary"])
        if key in merged:
            m = merged[key]
            if f["source"] not in m["source"]:
                m["source"] += " + " + f["source"]
            if f.get("evidence") and f["evidence"] not in m["evidence"]:
                m["evidence"] = (m["evidence"] + " | " if m["evidence"] else "") + f["evidence"]
        else:
            merged[key] = {k: f.get(k, "") or "" for k in ("severity", "category", "summary", "evidence", "source")}
    order = {s: i for i, s in enumerate(SEVERITIES)}
    return sorted(merged.values(), key=lambda f: order.get(f["severity"], 9))


def build_html(report, findings, analyst, det_dir):
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    total = sum(counts.values()) or 1
    auth = report.get("analysis_results", {}).get("authentication", {})
    net = report.get("analysis_results", {}).get("network", {})
    out = []
    w = out.append
    w("<!doctype html><html lang='en'><head><meta charset='utf-8'>")
    w("<meta name='viewport' content='width=device-width, initial-scale=1'>")
    w("<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">")
    w(f"<title>Forensic Report {esc(report.get('analyzed_on', ''))}</title><style>{CSS}</style></head><body><main>")
    w("<h1>Linux Forensic Investigation Report</h1>")
    w(f"<p class='meta'>Host <b>{esc(report.get('analyzed_on'))}</b> · analyst {esc(analyst)} · "
      f"generated {esc(datetime.datetime.now().astimezone().isoformat(timespec='seconds'))}<br>"
      f"Collection <code>{esc(report.get('data_directory'))}</code>"
      + (f" · live detection <code>{esc(det_dir)}</code>" if det_dir else "") + "</p>")

    w("<h2>Executive summary</h2><div class='cards'>")
    for s in SEVERITIES:
        w(f"<div class='card' style='--c:{COLOURS[s]}'><b>{counts[s]}</b><span>{s}</span></div>")
    w("</div><div class='bar' role='img' aria-label='findings by severity'>")
    for s in SEVERITIES:
        if counts[s]:
            w(f"<i style='--c:{COLOURS[s]};width:{100 * counts[s] / total:.1f}%' title='{s}: {counts[s]}'></i>")
    w("</div>")
    if counts["CRITICAL"]:
        w("<p><b>Assessment:</b> evidence of a successful compromise. Treat the host as untrusted.</p>")
    elif counts["HIGH"]:
        w("<p><b>Assessment:</b> suspicious activity that needs investigation.</p>")
    else:
        w("<p><b>Assessment:</b> nothing HIGH or CRITICAL. Keep this as a baseline.</p>")

    w("<h2>Findings</h2><div class='wrap'><table><tr><th>Severity</th><th>Type</th><th>Finding</th><th>Evidence</th><th>Source</th></tr>")
    for f in findings:
        c = COLOURS.get(f["severity"], "#64748b")
        w(f"<tr><td><span class='sev' style='--c:{c}'>{esc(f['severity'])}</span></td><td>{esc(f['category'])}</td>"
          f"<td>{esc(f['summary'])}</td><td><code>{esc(f['evidence'][:400])}</code></td><td>{esc(f['source'])}</td></tr>")
    if not findings:
        w("<tr><td colspan='5'>No findings.</td></tr>")
    w("</table></div>")

    by_ip = auth.get("failed_logins_by_ip", {})
    if by_ip:
        top = max(by_ip.values())
        w("<h2>Failed logins by source</h2><div class='wrap'><table><tr><th>Source address</th><th>Failures</th><th style='width:50%'></th></tr>")
        for ip, n in list(by_ip.items())[:15]:
            w(f"<tr><td><code>{esc(ip)}</code></td><td>{n}</td><td><div class='hbar' style='width:{100 * n / top:.0f}%'></div></td></tr>")
        w("</table></div>")

    listeners = net.get("listeners", [])
    if listeners:
        w("<h2>Listening sockets</h2><div class='wrap'><table><tr><th>Proto</th><th>Local</th><th>Process</th></tr>")
        for c in listeners:
            w(f"<tr><td>{esc(c['proto'])}</td><td><code>{esc(c['local'])}</code></td><td>{esc(c['process'])}</td></tr>")
        w("</table></div>")

    tl = report.get("timeline", [])
    if tl:
        w("<h2>Timeline</h2><div class='wrap'><table><tr><th>Time</th><th>Source</th><th>Event</th></tr>")
        for e in tl:
            w(f"<tr><td><code>{esc(e['time'])}</code></td><td>{esc(e['source'])}</td><td>{esc(e['event'])}</td></tr>")
        w("</table></div>")

    w("<footer>Generated by html_report_generator.py from the analyzer's JSON and the detector's findings. "
      "Nothing on this page was typed by hand.</footer></main></body></html>")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="HTML report from forensic_analyzer.py and detect_unauthorized.sh output.")
    ap.add_argument("--base", default=os.environ.get("FORENSICS_BASE", "/home/forensics"))
    ap.add_argument("--analysis", help="python_analysis_* folder (default: newest)")
    ap.add_argument("--detection", help="unauthorized_analysis_* folder (default: newest, if any)")
    ap.add_argument("--analyst", default=os.environ.get("SUDO_USER") or os.environ.get("USER", "analyst"))
    ap.add_argument("-o", "--output", help="output file (default BASE/reports/forensic_report_<time>.html)")
    args = ap.parse_args(argv)

    ana = args.analysis or latest(args.base, "python_analysis_")
    if not ana or not os.path.isfile(os.path.join(ana, "analysis.json")):
        print(f"[ERROR] no analysis.json found under {args.base}; run forensic_analyzer.py first", file=sys.stderr)
        return 2
    det = args.detection or latest(args.base, "unauthorized_analysis_")
    with open(os.path.join(ana, "analysis.json"), encoding="utf-8") as fh:
        report = json.load(fh)
    findings = merge(report.get("suspicious_activities", []), load_detection(det))
    page = build_html(report, findings, args.analyst, det)

    out = args.output or os.path.join(args.base, "reports",
                                      f"forensic_report_{datetime.datetime.now():%Y%m%d_%H%M%S}.html")
    os.makedirs(os.path.dirname(os.path.abspath(out)), mode=0o700, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(page)
    os.chmod(out, 0o600)
    print(f"[INFO] HTML report: {out} ({len(findings)} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
