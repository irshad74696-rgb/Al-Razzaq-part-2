#!/usr/bin/env python3
"""
Extract Windows event log records (.evtx) to JSON, on Linux, read-only.

    python3 extract_eventlogs.py Security.evtx security_events.json
    python3 extract_eventlogs.py System.evtx system_events.json --no-xml

For each record the JSON keeps: record number, UTC timestamp, event ID,
level, provider, channel, computer name, the user SID if any, the named
EventData/UserData fields as a dictionary, and (unless --no-xml) the full
rendered XML. The file starts with the source file's name, size and
SHA-256, so the extraction can be tied back to the exact evidence file.

A damaged record is reported and skipped; the rest of the log is still
extracted. The .evtx file is only ever opened for reading.

Exit status: 0 on success, 2 if the input is missing or not an EVTX file.
"""

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone

from winevents import (SUSPICIOUS_EVENT_IDS, event_name, iso_utc, parse_timestamp,
                       sha256_file, write_json)

try:
    import Evtx.Evtx as evtx
except ImportError:  # pragma: no cover - depends on the machine
    sys.exit("python-evtx is not installed. Run: pip install python-evtx "
             "(inside a virtual environment on recent Ubuntu, see the README)")

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def _local(tag):
    return tag.split("}", 1)[-1]


def parse_record_xml(xml_text):
    """Pull the fields we need out of one rendered record."""
    root = ET.fromstring(xml_text)
    system = root.find(NS + "System")
    if system is None:
        raise ValueError("record has no <System> element")

    def text(name):
        node = system.find(NS + name)
        return node.text if node is not None and node.text is not None else ""

    provider = system.find(NS + "Provider")
    time_created = system.find(NS + "TimeCreated")
    security = system.find(NS + "Security")
    event_id_text = text("EventID").strip()

    fields = {}
    event_data = root.find(NS + "EventData")
    if event_data is not None:
        for i, data in enumerate(event_data.findall(NS + "Data"), start=1):
            name = data.get("Name") or "Data%d" % i
            fields[name] = data.text or ""
    user_data = root.find(NS + "UserData")
    if user_data is not None:
        for wrapper in user_data:
            for child in wrapper:
                fields[_local(child.tag)] = child.text or ""

    return {
        "event_id": int(event_id_text) if event_id_text.isdigit() else None,
        "level": int(text("Level")) if text("Level").isdigit() else None,
        "provider": provider.get("Name", "") if provider is not None else "",
        "channel": text("Channel"),
        "computer_name": text("Computer"),
        "user_sid": security.get("UserID") if security is not None else None,
        "system_time": time_created.get("SystemTime") if time_created is not None else None,
        "event_data": fields,
    }


def extract_events(evtx_file, output_file, include_xml=True):
    """
    Extract events from a Windows EVTX file and save them to JSON.

    Returns the list of extracted event dictionaries.
    """
    events = []
    errors = []
    with evtx.Evtx(evtx_file) as log:
        header = log.get_file_header()
        if not header.check_magic():
            raise ValueError("%s is not an EVTX file (bad file signature)" % evtx_file)
        if not header.verify():
            errors.append({"record_id": None, "error": "file header checksum does not match "
                                                         "(file may be damaged or still open on the source machine)"})
        for record in log.records():
            record_id = None
            try:
                record_id = record.record_num()
                xml_text = record.xml()
                parsed = parse_record_xml(xml_text)
                when = parse_timestamp(parsed.pop("system_time")) or record.timestamp()
                entry = {
                    "record_id": record_id,
                    "timestamp": iso_utc(when),
                    **parsed,
                }
                if include_xml:
                    entry["xml"] = xml_text
                events.append(entry)
            except Exception as exc:  # one bad record must not stop the extraction
                errors.append({"record_id": record_id, "error": "%s: %s" % (type(exc).__name__, exc)})

    channels = Counter(e["channel"] for e in events if e.get("channel"))
    document = {
        "tool": "extract_eventlogs.py",
        "extracted_at": iso_utc(datetime.now(timezone.utc)),
        "source_file": os.path.basename(evtx_file),
        "source_path": os.path.abspath(evtx_file),
        "source_size": os.path.getsize(evtx_file),
        "source_sha256": sha256_file(evtx_file),
        "channel": channels.most_common(1)[0][0] if channels else "",
        "record_count": len(events),
        "parse_errors": errors,
        "events": events,
    }
    write_json(output_file, document)
    return events, errors


def analyze_events(events, errors=(), out=sys.stdout):
    """Print a short statistical summary of the extracted events."""
    print("Total events: %d" % len(events), file=out)
    if errors:
        print("Records skipped or warnings: %d (first: %s)" % (len(errors), errors[0]["error"]), file=out)
    if not events:
        return
    counts = Counter(e["event_id"] for e in events)
    print("\nTop 10 event IDs:", file=out)
    for event_id, count in counts.most_common(10):
        flag = "  <- " + SUSPICIOUS_EVENT_IDS[event_id] if event_id in SUSPICIOUS_EVENT_IDS else ""
        print("  %6s  %6d  %s%s" % (event_id, count, event_name(event_id), flag), file=out)
    stamps = sorted(e["timestamp"] for e in events if e.get("timestamp"))
    if stamps:
        print("\nTime range (UTC): %s  ->  %s" % (stamps[0], stamps[-1]), file=out)
    computers = Counter(e["computer_name"] for e in events)
    print("Computers: " + ", ".join("%s (%d)" % kv for kv in computers.most_common()), file=out)
    watched = {k: v for k, v in counts.items() if k in SUSPICIOUS_EVENT_IDS}
    if watched:
        print("Watched event IDs present: " +
              ", ".join("%d x%d" % (k, watched[k]) for k in sorted(watched)), file=out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract a Windows .evtx log to JSON (read-only).")
    parser.add_argument("evtx_file", help="input .evtx file")
    parser.add_argument("output_file", help="output .json file")
    parser.add_argument("--no-xml", action="store_true",
                        help="leave the full record XML out of the JSON (much smaller files)")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.evtx_file):
        print("error: %s: no such file" % args.evtx_file, file=sys.stderr)
        return 2
    with open(args.evtx_file, "rb") as fh:
        if fh.read(8) != b"ElfFile\x00":
            print("error: %s is not an EVTX file (it does not start with 'ElfFile')" % args.evtx_file,
                  file=sys.stderr)
            return 2

    events, errors = extract_events(args.evtx_file, args.output_file, include_xml=not args.no_xml)
    print("Extracted %d events from %s -> %s\n" % (len(events), args.evtx_file, args.output_file))
    analyze_events(events, errors)
    return 0


if __name__ == "__main__":
    sys.exit(main())
