"""
Shared reference data for the Windows forensics scripts: what the event IDs
mean, which ones matter, and small helpers for timestamps and file output.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone

EVENT_NAMES = {
    # Security log
    1102: "Security audit log was cleared",
    4608: "Windows is starting up",
    4624: "Successful logon",
    4625: "Failed logon",
    4634: "Logoff",
    4647: "User initiated logoff",
    4648: "Logon with explicit credentials",
    4672: "Special privileges assigned to new logon",
    4688: "New process created",
    4697: "Service installed (Security log)",
    4698: "Scheduled task created",
    4719: "Audit policy changed",
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempted",
    4728: "Member added to a global security group",
    4732: "Member added to a local security group",
    4738: "User account changed",
    4740: "User account locked out",
    4756: "Member added to a universal security group",
    4768: "Kerberos TGT requested",
    4769: "Kerberos service ticket requested",
    4776: "Credential validation (NTLM)",
    # System log
    104: "Event log was cleared",
    6005: "Event Log service started (boot)",
    6006: "Event Log service stopped (shutdown)",
    6008: "Unexpected shutdown",
    6013: "System uptime",
    7034: "Service terminated unexpectedly",
    7036: "Service changed state",
    7040: "Service start type changed",
    7045: "New service installed",
}

# The IDs the lab asks to watch, plus the ones its "key indicators" list adds.
SUSPICIOUS_EVENT_IDS = {
    1102: "anti-forensics: audit log cleared",
    104: "anti-forensics: event log cleared",
    4625: "failed logon (possible brute force)",
    4648: "explicit credentials (possible lateral movement or runas)",
    4672: "special privileges at logon (admin rights in use)",
    4688: "process creation (check the command line)",
    4720: "new user account",
    4732: "user added to a local group",
    4740: "account lockout",
    7040: "service start type changed",
    7045: "new service installed (possible persistence)",
}

LOGON_TYPES = {
    2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock",
    8: "network cleartext", 9: "new credentials", 10: "remote interactive (RDP)",
    11: "cached interactive",
}


def event_name(event_id):
    return EVENT_NAMES.get(int(event_id), "Event %s" % event_id)


def iso_utc(dt):
    """datetime -> '2026-11-20T21:04:10.250000Z' (always UTC, always microseconds)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    if dt.year < 1700:                       # zero FILETIME rendered as datetime.min
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,7}))?\s*(Z|[+-]\d{2}:?\d{2})?$")


def parse_timestamp(text):
    """
    Accepts the timestamp styles these tools meet: python-evtx's
    '2026-11-20 21:04:10.25+00:00', Windows' '2026-11-20T21:04:10.2500000Z'
    (seven fraction digits) and ISO 8601 with an offset. Returns aware UTC,
    or None if it does not look like a timestamp.
    """
    if not text:
        return None
    m = _TS_RE.match(str(text).strip())
    if not m:
        return None
    year, month, day, hh, mm, ss = (int(x) for x in m.groups()[:6])
    frac = (m.group(7) or "0")[:6].ljust(6, "0")
    tz = m.group(8)
    offset = timezone.utc
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        return datetime(year, month, day, hh, mm, ss, int(frac), tzinfo=offset).astimezone(timezone.utc)
    except ValueError:
        return None


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, data):
    """Write JSON atomically with owner-only permissions (evidence can be sensitive)."""
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    os.replace(tmp, path)
