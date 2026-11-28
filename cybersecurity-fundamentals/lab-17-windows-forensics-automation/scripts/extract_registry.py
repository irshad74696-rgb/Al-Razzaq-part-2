#!/usr/bin/env python3
"""
Extract forensic information from offline Windows registry hives, read-only.

    python3 extract_registry.py SYSTEM                 # -> system_hive.json
    python3 extract_registry.py SOFTWARE               # -> software_hive.json
    python3 extract_registry.py SOFTWARE "Microsoft\\Windows\\CurrentVersion\\Run"
                                                       # -> registry_output.json
    python3 extract_registry.py NTUSER.DAT "Software\\Microsoft\\Windows\\CurrentVersion\\Run" -o run.json

SYSTEM:   computer name, current control set, time zone, last shutdown,
          every service (start type, image path, account, last write),
          network interfaces (DHCP/static addresses, gateway, DNS).
SOFTWARE: Windows version, installed programs, autostart entries (Run,
          RunOnce, Winlogon Shell/Userinit), Defender exclusions.
Key mode: one key's values and subkeys, from any hive.

The hive type is read from the hive's own header, not guessed from the file
name. A path that starts with "HKLM\\SYSTEM\\" or uses "CurrentControlSet"
is translated, since neither exists inside an offline hive.

Values whose name looks like a secret (password, token, API key, ...) are
masked in the output; pass --show-secrets to keep them.

Exit status: 0 on success, 2 for a missing file, a non-hive file or a key
that does not exist.
"""

import argparse
import os
import re
import struct
import sys
from datetime import datetime, timedelta, timezone

from winevents import iso_utc, sha256_file, write_json

try:
    from Registry import Registry
except ImportError:  # pragma: no cover
    sys.exit("python-registry is not installed. Run: pip install python-registry "
             "(inside a virtual environment on recent Ubuntu, see the README)")

START_TYPES = {0: "boot", 1: "system", 2: "automatic", 3: "manual", 4: "disabled"}
SERVICE_TYPES = {0x1: "kernel driver", 0x2: "file system driver", 0x10: "own process",
                 0x20: "shared process", 0x50: "user own process", 0x60: "user shared process"}

# A value *name* that suggests it stores a secret. "key" alone is not
# enough: TimeZoneKeyName, KeyboardDelay and every "...Key" path would match.
SENSITIVE_NAME = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|token|credential|"
    r"(api|access|private|secret|encryption|license|product)[_-]?key)", re.IGNORECASE)


def is_sensitive_name(name):
    return bool(SENSITIVE_NAME.search(name or ""))


def mask(text):
    text = str(text)
    if not text:
        return text
    return "%s%s (%d characters, masked)" % (text[:2], "*" * min(len(text) - 2, 12), len(text))


def value_to_json(value, show_secrets=False):
    """One RegistryValue -> {name, type, data} with JSON-friendly data."""
    name = value.name()
    vtype = value.value_type_str()
    try:
        data = value.value()
    except Exception as exc:  # damaged data cell
        return {"name": name, "type": vtype, "data": None, "error": str(exc)}
    if isinstance(data, bytes):
        data = data.hex()
    elif isinstance(data, list):
        data = [item for item in data if item != ""]
    if vtype == "RegDWord" and isinstance(data, int) and data >= 0x80000000 and name in ("Bias", "ActiveTimeBias"):
        data -= 0x100000000
    entry = {"name": name, "type": vtype, "data": data}
    if is_sensitive_name(name) and isinstance(data, str) and data and not show_secrets:
        entry["data"] = mask(data)
        entry["masked"] = True
    return entry


def values_dict(key):
    out = {}
    for value in key.values():
        try:
            data = value.value()
        except Exception:
            continue
        if isinstance(data, list):
            data = [item for item in data if item != ""]
        out[value.name()] = data
    return out


def open_hive(path):
    reg = Registry.Registry(path)
    return reg


def detect_hive_type(reg, path):
    kind = reg.hive_type().name           # from the hive header
    if kind in ("SYSTEM", "SOFTWARE"):
        return kind
    base = os.path.basename(path).upper()
    if base in ("SYSTEM", "SOFTWARE"):
        return base
    root = reg.root()
    names = {k.name().lower() for k in root.subkeys()}
    if "select" in names and any(n.startswith("controlset") for n in names):
        return "SYSTEM"
    if "microsoft" in names:
        return "SOFTWARE"
    return "UNKNOWN"


def current_control_set(reg):
    try:
        number = reg.open("Select").value("Current").value()
    except Registry.RegistryKeyNotFoundException:
        number = 1
    except Registry.RegistryValueNotFoundException:
        number = 1
    return "ControlSet%03d" % number


def normalise_key_path(reg, key_path):
    """Turn what people type into a path that exists inside the offline hive."""
    path = key_path.replace("/", "\\").strip("\\")
    path = re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\(SYSTEM|SOFTWARE|SAM|SECURITY)\\?", "", path,
                  flags=re.IGNORECASE)
    path = re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\?", "", path, flags=re.IGNORECASE)
    if re.match(r"^CurrentControlSet(\\|$)", path, re.IGNORECASE):
        path = current_control_set(reg) + path[len("CurrentControlSet"):]
    return path


def key_summary(key):
    return {
        "name": key.name(),
        "last_written": iso_utc(key.timestamp()),
        "subkey_count": key.subkeys_number(),
        "value_count": key.values_number(),
    }


def dump_key(key, show_secrets=False, depth=0):
    out = {
        "path": key.path(),
        "last_written": iso_utc(key.timestamp()),
        "subkey_count": key.subkeys_number(),
        "value_count": key.values_number(),
        "values": [value_to_json(v, show_secrets) for v in key.values()],
        "subkeys": [],
    }
    for sub in key.subkeys():
        if depth > 0:
            out["subkeys"].append(dump_key(sub, show_secrets, depth - 1))
        else:
            out["subkeys"].append(key_summary(sub))
    return out


def source_info(reg_file, reg):
    return {
        "source_file": os.path.basename(reg_file),
        "source_path": os.path.abspath(reg_file),
        "source_sha256": sha256_file(reg_file),
        "hive_header_name": reg.hive_name(),
        "extracted_at": iso_utc(datetime.now(timezone.utc)),
        "tool": "extract_registry.py",
    }


def extract_registry_key(reg_file, key_path, output_file, show_secrets=False, depth=0):
    """Extract one key (values, subkeys with timestamps and counts) to JSON."""
    reg = open_hive(reg_file)
    resolved = normalise_key_path(reg, key_path)
    key = reg.open(resolved) if resolved else reg.root()
    doc = source_info(reg_file, reg)
    doc.update({"hive_type": detect_hive_type(reg, reg_file), "requested_key": key_path,
                "resolved_key": resolved, "key": dump_key(key, show_secrets, depth)})
    write_json(output_file, doc)
    return doc


def _filetime_from_hex(hex_text):
    try:
        raw = bytes.fromhex(hex_text)
        ticks = struct.unpack("<Q", raw[:8])[0]
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
    except (ValueError, struct.error, OverflowError):
        return None


def extract_system_info(system_hive, show_secrets=False):
    """Computer name, control set, time zone, services and interfaces from SYSTEM."""
    reg = open_hive(system_hive)
    ccs = current_control_set(reg)
    system_info = {
        "computer_name": "",
        "current_control_set": ccs,
        "timezone": {},
        "last_shutdown": None,
        "services": [],
        "network_interfaces": [],
    }

    def try_open(path):
        try:
            return reg.open(path)
        except Registry.RegistryKeyNotFoundException:
            return None

    key = try_open(ccs + r"\Control\ComputerName\ComputerName")
    if key:
        system_info["computer_name"] = values_dict(key).get("ComputerName", "")

    key = try_open(ccs + r"\Control\TimeZoneInformation")
    if key:
        tz = values_dict(key)
        bias = tz.get("Bias")
        if isinstance(bias, int) and bias >= 0x80000000:
            bias -= 0x100000000
        system_info["timezone"] = {
            "name": tz.get("TimeZoneKeyName") or tz.get("StandardName", ""),
            "bias_minutes": bias,
            # Windows stores UTC = local + bias, so the UTC offset is -bias.
            "utc_offset_minutes": -bias if isinstance(bias, int) else None,
        }

    key = try_open(ccs + r"\Control\Windows")
    if key:
        raw = values_dict(key).get("ShutdownTime")
        if isinstance(raw, bytes):
            raw = raw.hex()
        if raw:
            system_info["last_shutdown"] = iso_utc(_filetime_from_hex(raw))

    services = try_open(ccs + r"\Services")
    for svc in services.subkeys() if services else []:
        vals = values_dict(svc)
        start = vals.get("Start")
        stype = vals.get("Type")
        if start is None and "ImagePath" not in vals:
            continue                      # parameter-only keys, not services
        system_info["services"].append({
            "name": svc.name(),
            "display_name": vals.get("DisplayName", ""),
            "image_path": vals.get("ImagePath", ""),
            "start": start,
            "start_type": START_TYPES.get(start, str(start)),
            "service_type": SERVICE_TYPES.get(stype, str(stype)),
            "account": vals.get("ObjectName", ""),
            "last_written": iso_utc(svc.timestamp()),
        })

    ifaces = try_open(ccs + r"\Services\Tcpip\Parameters\Interfaces")
    for iface in ifaces.subkeys() if ifaces else []:
        vals = values_dict(iface)
        dhcp = vals.get("EnableDHCP") == 1
        address = vals.get("DhcpIPAddress") if dhcp else vals.get("IPAddress")
        if isinstance(address, list):
            address = ", ".join(address)
        gateway = vals.get("DhcpDefaultGateway") if dhcp else vals.get("DefaultGateway")
        if isinstance(gateway, list):
            gateway = ", ".join(gateway)
        system_info["network_interfaces"].append({
            "guid": iface.name(),
            "dhcp_enabled": dhcp,
            "ip_address": address or "",
            "subnet_mask": (vals.get("DhcpSubnetMask") if dhcp else vals.get("SubnetMask")) or "",
            "default_gateway": gateway or "",
            "dns_servers": vals.get("DhcpNameServer") or vals.get("NameServer") or "",
            "dhcp_server": vals.get("DhcpServer", ""),
            "domain": vals.get("DhcpDomain") or vals.get("Domain") or "",
            "last_written": iso_utc(iface.timestamp()),
        })
    return system_info


def extract_software_info(software_hive):
    """Installed programs (DisplayName, DisplayVersion, Publisher, ...) from SOFTWARE."""
    reg = open_hive(software_hive)
    apps = []
    for path in (r"Microsoft\Windows\CurrentVersion\Uninstall",
                 r"WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"):
        try:
            root = reg.open(path)
        except Registry.RegistryKeyNotFoundException:
            continue
        for app in root.subkeys():
            vals = values_dict(app)
            if not vals.get("DisplayName"):
                continue                  # updates and components without a name
            apps.append({
                "name": vals.get("DisplayName", ""),
                "version": vals.get("DisplayVersion", ""),
                "publisher": vals.get("Publisher", ""),
                "install_date": str(vals.get("InstallDate", "")),
                "install_location": vals.get("InstallLocation", ""),
                "registry_key": app.path(),
                "last_written": iso_utc(app.timestamp()),
                "wow64": path.startswith("WOW6432Node"),
            })
    return sorted(apps, key=lambda a: a["name"].lower())


AUTOSTART_KEYS = [
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
]


def extract_software_hive(software_hive, show_secrets=False):
    """Everything this lab needs from SOFTWARE, as one dictionary."""
    reg = open_hive(software_hive)

    def try_open(path):
        try:
            return reg.open(path)
        except Registry.RegistryKeyNotFoundException:
            return None

    doc = {"os": {}, "installed_software": extract_software_info(software_hive),
           "startup_entries": [], "winlogon": None, "defender": {}}

    key = try_open(r"Microsoft\Windows NT\CurrentVersion")
    if key:
        vals = values_dict(key)
        install = vals.get("InstallDate")
        doc["os"] = {
            "product_name": vals.get("ProductName", ""),
            "display_version": vals.get("DisplayVersion", ""),
            "build": vals.get("CurrentBuild", ""),
            "edition": vals.get("EditionID", ""),
            "registered_owner": vals.get("RegisteredOwner", ""),
            "install_date": iso_utc(datetime.fromtimestamp(install, timezone.utc))
            if isinstance(install, int) and install > 0 else None,
        }

    for path in AUTOSTART_KEYS:
        key = try_open(path)
        if not key:
            continue
        for value in key.values():
            entry = value_to_json(value, show_secrets)
            doc["startup_entries"].append({
                "location": path, "name": entry["name"], "command": entry["data"],
                "last_written": iso_utc(key.timestamp()),
            })

    key = try_open(r"Microsoft\Windows NT\CurrentVersion\Winlogon")
    if key:
        doc["winlogon"] = dump_key(key, show_secrets)
        vals = values_dict(key)
        for name in ("Shell", "Userinit"):
            if name in vals:
                doc["startup_entries"].append({
                    "location": r"Microsoft\Windows NT\CurrentVersion\Winlogon", "name": name,
                    "command": vals[name], "last_written": iso_utc(key.timestamp()),
                })

    defender = {}
    for kind in ("Paths", "Extensions", "Processes"):
        key = try_open(r"Microsoft\Windows Defender\Exclusions" + "\\" + kind)
        if key:
            defender["exclusions_" + kind.lower()] = [v.name() for v in key.values()]
            defender["exclusions_" + kind.lower() + "_last_written"] = iso_utc(key.timestamp())
    key = try_open(r"Policies\Microsoft\Windows Defender")
    if key:
        defender["policy"] = values_dict(key)
    doc["defender"] = defender
    return doc


def main(argv=None):
    parser = argparse.ArgumentParser(description="Extract forensic data from an offline registry hive.")
    parser.add_argument("hive", help="registry hive file (SYSTEM, SOFTWARE, NTUSER.DAT, ...)")
    parser.add_argument("key_path", nargs="?", help="extract only this key (any hive)")
    parser.add_argument("-o", "--output", help="output JSON file (default depends on the mode)")
    parser.add_argument("--type", choices=["auto", "system", "software"], default="auto",
                        help="override hive type detection")
    parser.add_argument("--depth", type=int, default=0,
                        help="key mode: also dump this many levels of subkeys (default 0)")
    parser.add_argument("--show-secrets", action="store_true",
                        help="do not mask values whose names look like passwords or tokens")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.hive):
        print("error: %s: no such file" % args.hive, file=sys.stderr)
        return 2
    with open(args.hive, "rb") as fh:
        if fh.read(4) != b"regf":
            print("error: %s is not a registry hive (it does not start with 'regf')" % args.hive,
                  file=sys.stderr)
            return 2

    try:
        if args.key_path:
            output = args.output or "registry_output.json"
            doc = extract_registry_key(args.hive, args.key_path, output, args.show_secrets, args.depth)
            key = doc["key"]
            print("Key %s (last written %s): %d values, %d subkeys -> %s" % (
                key["path"], key["last_written"], key["value_count"], key["subkey_count"], output))
            for v in key["values"]:
                print("  %-28s %-14s %s" % (v["name"], v["type"], v["data"]))
            for s in key["subkeys"]:
                print("  [%s]  last written %s" % (s["name"], s["last_written"]))
            return 0

        reg = open_hive(args.hive)
        kind = args.type.upper() if args.type != "auto" else detect_hive_type(reg, args.hive)
        doc = source_info(args.hive, reg)
        doc["hive_type"] = kind
        if kind == "SYSTEM":
            info = extract_system_info(args.hive, args.show_secrets)
            doc["system_info"] = info
            output = args.output or "system_hive.json"
            write_json(output, doc)
            print("SYSTEM hive -> %s" % output)
            print("  Computer name:       %s" % info["computer_name"])
            print("  Current control set: %s" % info["current_control_set"])
            tz = info["timezone"]
            if tz:
                print("  Time zone:           %s (UTC%+.1f h)" % (
                    tz["name"], (tz["utc_offset_minutes"] or 0) / 60))
            print("  Last shutdown:       %s" % (info["last_shutdown"] or "unknown"))
            auto = [s for s in info["services"] if s["start"] in (0, 1, 2)]
            print("  Services:            %d (%d start automatically)" % (len(info["services"]), len(auto)))
            for iface in info["network_interfaces"]:
                if iface["ip_address"]:
                    print("  Interface %s: %s gw %s" % (iface["guid"], iface["ip_address"], iface["default_gateway"]))
        elif kind == "SOFTWARE":
            info = extract_software_hive(args.hive, args.show_secrets)
            doc.update(info)
            output = args.output or "software_hive.json"
            write_json(output, doc)
            print("SOFTWARE hive -> %s" % output)
            os_info = info["os"]
            if os_info:
                print("  Windows: %s %s (build %s)" % (os_info["product_name"], os_info["display_version"],
                                                    os_info["build"]))
            print("  Installed programs: %d" % len(info["installed_software"]))
            for app in info["installed_software"]:
                print("    %-45s %-18s %s" % (app["name"][:45], app["version"], app["publisher"]))
            print("  Autostart entries: %d" % len(info["startup_entries"]))
            for entry in info["startup_entries"]:
                print("    %s = %s" % (entry["name"], str(entry["command"])[:90]))
            paths = info["defender"].get("exclusions_paths")
            if paths:
                print("  Defender path exclusions: %s" % ", ".join(paths))
        else:
            print("error: could not tell what kind of hive %s is; give a key path, or --type"
                  % args.hive, file=sys.stderr)
            return 2
        return 0
    except Registry.RegistryKeyNotFoundException as exc:
        print("error: key not found: %s (paths are relative to the hive root, e.g. "
              "\"ControlSet001\\Services\", not \"HKLM\\SYSTEM\\...\")" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
