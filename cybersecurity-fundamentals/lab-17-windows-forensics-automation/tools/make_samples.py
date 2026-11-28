#!/usr/bin/env python3
"""
Build the synthetic Windows artefacts this lab is tested against.

    python3 tools/make_samples.py                       # attack scenario -> samples/
    python3 tools/make_samples.py --scenario clean --out /tmp/clean

Writes:
    <out>/event-logs/System.evtx
    <out>/event-logs/Security.evtx
    <out>/registry-hives/SYSTEM
    <out>/registry-hives/SOFTWARE

Everything here is invented: the machine (WS-LAB-07), the company
(LabCorp), the people (alice, bob, it-admin), SIDs that follow an obviously
fake pattern (S-1-5-21-1111111111-2222222222-3333333333-*), internal
addresses in 10.20.30.0/24 and the attacker in 203.0.113.0/24, a range
reserved for documentation. The "password" and the encoded PowerShell are
harmless placeholders.

Scenario "clean": three ordinary working days (18-20 Nov 2026, Pakistan
time, UTC+5). Scenario "attack": the same days, then that night a password
brute force from 203.0.113.50 succeeds against it-admin and the intruder
installs a service, adds a Run key, excludes a folder from Defender,
disables Defender, creates a backdoor admin, installs AnyDesk and clears
the Security log.

Note on the cleared log: on a real machine, clearing the Security log
deletes the earlier records and event 1102 becomes the first record of the
new log. These samples keep both, so every detection has something to
find; on a real case the older events would come from a log forwarder or
a shadow copy. Output is deterministic (fixed seed), so the committed
samples can be checked by regenerating them.
"""

import argparse
import base64
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from evtx_writer import Event, write_evtx  # noqa: E402
from regf_writer import (REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,  # noqa: E402
                         REG_SZ, Key, to_filetime, write_hive)

COMPUTER = "WS-LAB-07"
PKT = timezone(timedelta(hours=5))
SID_BASE = "S-1-5-21-1111111111-2222222222-3333333333"
USERS = {
    "administrator": SID_BASE + "-500",
    "alice": SID_BASE + "-1001",
    "bob": SID_BASE + "-1002",
    "it-admin": SID_BASE + "-1005",
    "support_tmp": SID_BASE + "-1010",
}
ATTACKER_IP = "203.0.113.50"
SEC_PROVIDER = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-A5BA-3E3B0328C30D}")
SCM_PROVIDER = ("Service Control Manager", "{555908d1-a6d7-4695-8e1e-26931d2012f4}")
EVENTLOG_PROVIDER = ("EventLog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}")
CLEAR_PROVIDER = ("Microsoft-Windows-Eventlog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}")
AUDIT_SUCCESS = 0x8020000000000000
AUDIT_FAILURE = 0x8010000000000000
ADMIN_PRIVILEGES = "\n\t\t\t".join([
    "SeSecurityPrivilege", "SeTakeOwnershipPrivilege", "SeLoadDriverPrivilege",
    "SeBackupPrivilege", "SeRestorePrivilege", "SeDebugPrivilege",
    "SeSystemEnvironmentPrivilege", "SeImpersonatePrivilege",
    "SeDelegateSessionUserImpersonatePrivilege"])
# Harmless stand-in for a malicious download cradle. Decodes to a Write-Output.
PLACEHOLDER_SCRIPT = "Write-Output 'FORENSICS-LAB SAMPLE: harmless placeholder for a malicious download cradle'"
ENCODED_COMMAND = base64.b64encode(PLACEHOLDER_SCRIPT.encode("utf-16-le")).decode("ascii")
RUN_KEY_COMMAND = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " + ENCODED_COMMAND
MALWARE_PATH = r"C:\Users\Public\Libraries\winupdate.exe"


def local(day, hh, mm, ss=0):
    """Pakistan local time on 2026-11-<day> -> aware UTC datetime."""
    return datetime(2026, 11, day, hh, mm, ss, tzinfo=PKT).astimezone(timezone.utc)


class Logs:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.security = []
        self.system = []
        self.logon_id = 0x3E7 + 0x40000

    def next_logon_id(self):
        self.logon_id += self.rng.randint(0x100, 0x4000)
        return "0x%x" % self.logon_id

    # ---- Security log ------------------------------------------------
    def sec(self, event_id, when, data, task, keywords=AUDIT_SUCCESS, kind="EventData", wrapper=None,
            provider=SEC_PROVIDER):
        self.security.append(Event(
            event_id, when, provider[0], provider[1], "Security", COMPUTER,
            data=data, task=task, keywords=keywords, process_id=644,
            thread_id=self.rng.choice([712, 716, 1288, 4412]), kind=kind, wrapper=wrapper))

    def logon(self, when, user, logon_type, ip="-", workstation=COMPUTER, package="Negotiate",
              process=r"C:\Windows\System32\svchost.exe", admin=False):
        lid = self.next_logon_id()
        system_logon = user == "SYSTEM"
        self.sec(4624, when, [
            ("SubjectUserSid", "S-1-5-18"),
            ("SubjectUserName", COMPUTER + "$"),
            ("SubjectDomainName", "LABCORP"),
            ("SubjectLogonId", "0x3e7"),
            ("TargetUserSid", "S-1-5-18" if system_logon else USERS[user]),
            ("TargetUserName", user),
            ("TargetDomainName", "NT AUTHORITY" if system_logon else COMPUTER),
            ("TargetLogonId", "0x3e7" if system_logon else lid),
            ("LogonType", logon_type),
            ("LogonProcessName", "Advapi  " if logon_type != 3 else "NtLmSsp "),
            ("AuthenticationPackageName", package),
            ("WorkstationName", workstation if logon_type != 5 else "-"),
            ("ProcessName", process if logon_type != 3 else "-"),
            ("IpAddress", ip),
            ("IpPort", str(self.rng.randint(49152, 65000)) if ip not in ("-", "127.0.0.1") else "0"),
        ], task=12544)
        if admin or system_logon:
            self.sec(4672, when + timedelta(milliseconds=1), [
                ("SubjectUserSid", "S-1-5-18" if system_logon else USERS[user]),
                ("SubjectUserName", user),
                ("SubjectDomainName", "NT AUTHORITY" if system_logon else COMPUTER),
                ("SubjectLogonId", "0x3e7" if system_logon else lid),
                ("PrivilegeList", ADMIN_PRIVILEGES),
            ], task=12548)
        return lid

    def logoff(self, when, user, lid, logon_type):
        self.sec(4634, when, [
            ("TargetUserSid", USERS[user]),
            ("TargetUserName", user),
            ("TargetDomainName", COMPUTER),
            ("TargetLogonId", lid),
            ("LogonType", logon_type),
        ], task=12545)

    def failed(self, when, user, logon_type, ip="-", workstation=COMPUTER, unknown_user=False):
        self.sec(4625, when, [
            ("SubjectUserSid", "S-1-0-0" if logon_type == 3 else "S-1-5-18"),
            ("SubjectUserName", "-" if logon_type == 3 else COMPUTER + "$"),
            ("SubjectDomainName", "-" if logon_type == 3 else "LABCORP"),
            ("SubjectLogonId", "0x0" if logon_type == 3 else "0x3e7"),
            ("TargetUserSid", "S-1-0-0"),
            ("TargetUserName", user),
            ("TargetDomainName", COMPUTER if logon_type != 3 else ""),
            ("Status", "0xc000006d"),
            ("FailureReason", "%%2313"),
            ("SubStatus", "0xc0000064" if unknown_user else "0xc000006a"),
            ("LogonType", logon_type),
            ("LogonProcessName", "NtLmSsp " if logon_type == 3 else "User32 "),
            ("AuthenticationPackageName", "NTLM" if logon_type == 3 else "Negotiate"),
            ("WorkstationName", workstation),
            ("ProcessName", "-" if logon_type == 3 else r"C:\Windows\System32\svchost.exe"),
            ("IpAddress", ip),
            ("IpPort", str(self.rng.randint(49152, 65000)) if ip != "-" else "0"),
        ], task=12544, keywords=AUDIT_FAILURE)

    # ---- System log --------------------------------------------------
    def sys(self, event_id, when, provider, data, level=4, user_sid=None, keywords=0x8080000000000000,
            source=None):
        self.system.append(Event(
            event_id, when, provider[0], provider[1], "System", COMPUTER, data=data,
            level=level, keywords=keywords, process_id=self.rng.choice([680, 688]),
            thread_id=self.rng.choice([760, 2280, 6044]), user_sid=user_sid,
            event_source_name=source))

    def service_state(self, when, display_name, state):
        self.sys(7036, when, SCM_PROVIDER, [("param1", display_name), ("param2", state)],
                 source="Service Control Manager")


BOOT_SERVICES = ["Windows Event Log", "DHCP Client", "DNS Client", "Server", "Workstation",
                 "Print Spooler", "Task Scheduler", "Microsoft Defender Antivirus Service",
                 "Windows Time", "Background Intelligent Transfer Service"]


def working_day(logs, day, shutdown=True):
    rng = logs.rng
    boot = local(day, 8, 40 + rng.randint(0, 9), rng.randint(0, 59))
    logs.sys(6005, boot, EVENTLOG_PROVIDER, [], keywords=0x80000000000000)
    for i, name in enumerate(BOOT_SERVICES):
        logs.service_state(boot + timedelta(seconds=4 + i * 3), name, "running")
    for i in range(6):                                         # service logons
        logs.logon(boot + timedelta(seconds=10 + i * 7), "SYSTEM", 5,
                   process=r"C:\Windows\System32\services.exe")

    start = local(day, 9, rng.randint(0, 15), rng.randint(0, 59))
    if day == 19:                                              # one honest typo
        logs.failed(start - timedelta(seconds=20), "alice", 2)
    alice = logs.logon(start, "alice", 2, ip="127.0.0.1", process=r"C:\Windows\System32\svchost.exe")
    for hh in (11, 15):                                        # bob uses alice's shared folder
        lid = logs.logon(local(day, hh, rng.randint(0, 50), rng.randint(0, 59)), "bob", 3,
                         ip="10.20.30.15", workstation="WS-LAB-02", package="NTLM")
        logs.logoff(local(day, hh, 55, rng.randint(0, 59)), "bob", lid, 3)
    lunch = local(day, 13, rng.randint(30, 45))
    logs.logon(lunch, "alice", 7, ip="127.0.0.1")              # unlock after lunch
    if day == 19:                                              # IT does maintenance over RDP
        lid = logs.logon(local(19, 14, 5, 12), "it-admin", 10, ip="10.20.30.5",
                         workstation="IT-DESK-01", admin=True)
        logs.service_state(local(19, 14, 9, 40), "Windows Update", "running")
        logs.service_state(local(19, 14, 31, 2), "Windows Update", "stopped")
        logs.logoff(local(19, 14, 40, 0), "it-admin", lid, 10)
    for hh, mm in ((10, 30), (12, 10), (16, 45)):
        logs.service_state(local(day, hh, mm, rng.randint(0, 59)), "Windows Time", "running")
    end = local(day, 17, rng.randint(30, 59), rng.randint(0, 59))
    logs.logoff(end, "alice", alice, 2)
    if shutdown:
        logs.sys(6006, end + timedelta(minutes=2), EVENTLOG_PROVIDER, [], keywords=0x80000000000000)
    return end


def attack_night(logs):
    """Night of Fri 20 -> Sat 21 Nov 2026, Pakistan time."""
    rng = logs.rng
    t = local(21, 2, 4, 10)
    targets = ["administrator"] * 6 + ["admin", "it-admin", "test", "guest", "user", "backup"]
    for i in range(1200):
        user = rng.choice(targets)
        logs.failed(t, user, 3, ip=ATTACKER_IP, workstation="-",
                    unknown_user=user not in USERS)
        t += timedelta(milliseconds=rng.randint(250, 520))
    # The password for it-admin is guessed.
    lid = logs.logon(local(21, 2, 12, 3), "it-admin", 3, ip=ATTACKER_IP, workstation="-",
                     package="NTLM", admin=True)
    logs.sec(4648, local(21, 2, 13, 40), [
        ("SubjectUserSid", USERS["it-admin"]), ("SubjectUserName", "it-admin"),
        ("SubjectDomainName", COMPUTER), ("SubjectLogonId", lid),
        ("TargetUserName", "administrator"), ("TargetDomainName", COMPUTER),
        ("TargetServerName", "localhost"), ("TargetInfo", "localhost"),
        ("ProcessId", "0x1b3c"), ("ProcessName", r"C:\Windows\System32\runas.exe"),
        ("IpAddress", "::1"), ("IpPort", "0"),
    ], task=12544)
    logs.sec(4688, local(21, 2, 15, 2), [
        ("SubjectUserSid", USERS["it-admin"]), ("SubjectUserName", "it-admin"),
        ("SubjectDomainName", COMPUTER), ("SubjectLogonId", lid),
        ("NewProcessId", "0x2214"),
        ("NewProcessName", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        ("TokenElevationType", "%%1936"), ("ProcessId", "0x1b3c"),
        ("CommandLine", RUN_KEY_COMMAND),
        ("ParentProcessName", r"C:\Windows\System32\cmd.exe"),
    ], task=13312)
    logs.sec(4720, local(21, 2, 16, 30), [
        ("TargetUserName", "support_tmp"), ("TargetDomainName", COMPUTER),
        ("TargetSid", USERS["support_tmp"]), ("SubjectUserSid", USERS["it-admin"]),
        ("SubjectUserName", "it-admin"), ("SubjectDomainName", COMPUTER),
        ("SubjectLogonId", lid), ("SamAccountName", "support_tmp"),
    ], task=13824)
    logs.sec(4732, local(21, 2, 16, 45), [
        ("MemberName", "-"), ("MemberSid", USERS["support_tmp"]),
        ("TargetUserName", "Administrators"), ("TargetDomainName", "Builtin"),
        ("TargetSid", "S-1-5-32-544"), ("SubjectUserSid", USERS["it-admin"]),
        ("SubjectUserName", "it-admin"), ("SubjectDomainName", COMPUTER),
        ("SubjectLogonId", lid),
    ], task=13826)
    logs.sys(7045, local(21, 2, 18, 12), SCM_PROVIDER, [
        ("ServiceName", "Windows Update Helper"), ("ImagePath", MALWARE_PATH),
        ("ServiceType", "user mode service"), ("StartType", "auto start"),
        ("AccountName", "LocalSystem"),
    ], user_sid=USERS["it-admin"], source="Service Control Manager")
    logs.service_state(local(21, 2, 18, 13), "Windows Update Helper", "running")
    logs.sys(7040, local(21, 2, 19, 0), SCM_PROVIDER, [
        ("param1", "Microsoft Defender Antivirus Service"), ("param2", "auto start"),
        ("param3", "disabled"), ("param4", "WinDefend"),
    ], user_sid=USERS["it-admin"], source="Service Control Manager")
    logs.service_state(local(21, 2, 19, 1), "Microsoft Defender Antivirus Service", "stopped")
    logs.sec(1102, local(21, 2, 24, 55), [
        ("SubjectUserSid", USERS["it-admin"]), ("SubjectUserName", "it-admin"),
        ("SubjectDomainName", COMPUTER), ("SubjectLogonId", lid),
    ], task=104, keywords=0x4020000000000000, kind="UserData", wrapper="LogFileCleared",
        provider=CLEAR_PROVIDER)


def build_logs(scenario):
    logs = Logs(seed=17)
    working_day(logs, 18)
    working_day(logs, 19)
    working_day(logs, 20, shutdown=(scenario == "clean"))
    if scenario == "attack":
        attack_night(logs)
    key = lambda e: e.timestamp  # noqa: E731
    return sorted(logs.security, key=key), sorted(logs.system, key=key)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
INSTALL = datetime(2026, 3, 10, 11, 20, tzinfo=PKT).astimezone(timezone.utc)   # Windows installed

SERVICES = [
    # name, display, type, start, image path, account
    ("EventLog", "Windows Event Log", 0x20, 2,
     r"%SystemRoot%\System32\svchost.exe -k LocalServiceNetworkRestricted -p", r"NT AUTHORITY\LocalService"),
    ("Dhcp", "DHCP Client", 0x20, 2,
     r"%SystemRoot%\system32\svchost.exe -k LocalServiceNetworkRestricted -p", r"NT Authority\LocalService"),
    ("Dnscache", "DNS Client", 0x20, 2,
     r"%SystemRoot%\system32\svchost.exe -k NetworkService -p", r"NT AUTHORITY\NetworkService"),
    ("LanmanServer", "Server", 0x20, 2, r"%SystemRoot%\system32\svchost.exe -k netsvcs -p", "LocalSystem"),
    ("LanmanWorkstation", "Workstation", 0x20, 2,
     r"%SystemRoot%\System32\svchost.exe -k NetworkService -p", r"NT AUTHORITY\NetworkService"),
    ("Spooler", "Print Spooler", 0x10, 2, r"%SystemRoot%\System32\spoolsv.exe", "LocalSystem"),
    ("Schedule", "Task Scheduler", 0x20, 2, r"%systemroot%\system32\svchost.exe -k netsvcs -p", "LocalSystem"),
    ("W32Time", "Windows Time", 0x20, 3, r"%SystemRoot%\system32\svchost.exe -k LocalService", r"NT AUTHORITY\LocalService"),
    ("wuauserv", "Windows Update", 0x20, 3, r"%systemroot%\system32\svchost.exe -k netsvcs -p", "LocalSystem"),
    ("BITS", "Background Intelligent Transfer Service", 0x20, 3,
     r"%SystemRoot%\System32\svchost.exe -k netsvcs -p", "LocalSystem"),
    ("TermService", "Remote Desktop Services", 0x20, 3,
     r"%SystemRoot%\System32\svchost.exe -k NetworkService", r"NT Authority\NetworkService"),
    ("WinRM", "Windows Remote Management (WS-Management)", 0x20, 3,
     r"%SystemRoot%\System32\svchost.exe -k NetworkService -p", r"NT AUTHORITY\NetworkService"),
    ("RemoteRegistry", "Remote Registry", 0x20, 4,
     r"%SystemRoot%\system32\svchost.exe -k localService -p", r"NT AUTHORITY\LocalService"),
    ("WinDefend", "Microsoft Defender Antivirus Service", 0x10, 2,
     r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"', "LocalSystem"),
    ("Tcpip", "TCP/IP Protocol Driver", 0x01, 0, r"System32\drivers\tcpip.sys", None),
]


def build_system_hive(scenario):
    root = Key("ROOT", INSTALL)
    root.add("Select", INSTALL, [("Current", REG_DWORD, 1), ("Default", REG_DWORD, 1),
                                 ("Failed", REG_DWORD, 0), ("LastKnownGood", REG_DWORD, 1)])
    cs = "ControlSet001"
    root.add(cs + r"\Control\ComputerName\ComputerName", INSTALL,
             [("ComputerName", REG_SZ, COMPUTER)])
    root.add(cs + r"\Control\ComputerName\ActiveComputerName", local(20, 8, 44),
             [("ComputerName", REG_SZ, COMPUTER)])
    root.add(cs + r"\Control\TimeZoneInformation", INSTALL, [
        ("Bias", REG_DWORD, -300), ("ActiveTimeBias", REG_DWORD, -300),
        ("StandardName", REG_SZ, "@tzres.dll,-1162"),
        ("TimeZoneKeyName", REG_SZ, "Pakistan Standard Time"),
    ])
    last_shutdown = local(20, 17, 47) if scenario == "clean" else local(19, 17, 52)
    root.add(cs + r"\Control\Windows", last_shutdown, [
        ("ShutdownTime", REG_BINARY, to_filetime(last_shutdown).to_bytes(8, "little")),
    ])
    for name, display, stype, start, image, account in SERVICES:
        when = INSTALL
        if name == "WinDefend" and scenario == "attack":
            start, when = 4, local(21, 2, 19, 0)
        values = [("Type", REG_DWORD, stype), ("Start", REG_DWORD, start),
                  ("ErrorControl", REG_DWORD, 1), ("ImagePath", REG_EXPAND_SZ, image),
                  ("DisplayName", REG_SZ, display)]
        if account:
            values.append(("ObjectName", REG_SZ, account))
        if name == "Dhcp":
            values.append(("DependOnService", REG_MULTI_SZ, ["NSI", "Tcpip", "Afd"]))
        root.add(cs + "\\Services\\" + name, when, values)
    if scenario == "attack":
        root.add(cs + r"\Services\WinUpdateHelper", local(21, 2, 18, 12), [
            ("Type", REG_DWORD, 0x10), ("Start", REG_DWORD, 2), ("ErrorControl", REG_DWORD, 0),
            ("ImagePath", REG_EXPAND_SZ, MALWARE_PATH),
            ("DisplayName", REG_SZ, "Windows Update Helper"),
            ("ObjectName", REG_SZ, "LocalSystem"),
        ])
    root.add(cs + r"\Services\Tcpip\Parameters", INSTALL, [
        ("Hostname", REG_SZ, COMPUTER), ("Domain", REG_SZ, "labcorp.example"),
        ("NV Hostname", REG_SZ, COMPUTER),
    ])
    ifaces = cs + r"\Services\Tcpip\Parameters\Interfaces"
    root.add(ifaces + r"\{6a8f3c2e-1b4d-4e5f-9a7b-0c1d2e3f4a5b}", local(20, 8, 45), [
        ("EnableDHCP", REG_DWORD, 1), ("DhcpIPAddress", REG_SZ, "10.20.30.47"),
        ("DhcpSubnetMask", REG_SZ, "255.255.255.0"), ("DhcpServer", REG_SZ, "10.20.30.1"),
        ("DhcpDefaultGateway", REG_MULTI_SZ, ["10.20.30.1"]),
        ("DhcpNameServer", REG_SZ, "10.20.30.1"), ("DhcpDomain", REG_SZ, "labcorp.example"),
    ])
    root.add(ifaces + r"\{9c2d4e6f-8a1b-4c3d-b5e7-1f2a3b4c5d6e}", INSTALL, [
        ("EnableDHCP", REG_DWORD, 1),
    ])
    return root


INSTALLED_APPS = [
    # key, name, version, publisher, install date
    ("7-Zip", "7-Zip 23.01 (x64)", "23.01", "Igor Pavlov", "20260312"),
    ("{9A2B0C3D-1E4F-4A5B-8C6D-7E8F9A0B1C2D}", "Google Chrome", "131.0.6778.86", "Google LLC", "20260312"),
    ("Notepad++", "Notepad++ (64-bit x64)", "8.6.9", "Notepad++ Team", "20260415"),
    ("VLC media player", "VLC media player", "3.0.21", "VideoLAN", "20260502"),
    ("O365ProPlusRetail - en-us", "Microsoft 365 Apps for business - en-us", "16.0.18129.20116",
     "Microsoft Corporation", "20260311"),
]


def build_software_hive(scenario):
    root = Key("ROOT", INSTALL)
    nt = r"Microsoft\Windows NT\CurrentVersion"
    root.add(nt, INSTALL, [
        ("ProductName", REG_SZ, "Windows 10 Pro"), ("DisplayVersion", REG_SZ, "22H2"),
        ("CurrentBuild", REG_SZ, "19045"), ("EditionID", REG_SZ, "Professional"),
        ("RegisteredOwner", REG_SZ, "LabCorp IT"), ("RegisteredOrganization", REG_SZ, "LabCorp"),
        ("InstallDate", REG_DWORD, int(INSTALL.timestamp())),
    ])
    winlogon = [("Shell", REG_SZ, "explorer.exe"),
                ("Userinit", REG_SZ, "C:\\Windows\\system32\\userinit.exe,"),
                ("PasswordExpiryWarning", REG_DWORD, 5)]
    if scenario == "attack":
        # A misconfigured kiosk auto-logon left a plaintext password behind.
        winlogon += [("AutoAdminLogon", REG_SZ, "1"), ("DefaultUserName", REG_SZ, "kiosk"),
                     ("DefaultPassword", REG_SZ, "SAMPLE-ONLY-not-a-real-password")]
    root.add(nt + r"\Winlogon", INSTALL + timedelta(days=30), winlogon)

    cv = r"Microsoft\Windows\CurrentVersion"
    run = [("SecurityHealth", REG_EXPAND_SZ, r"%windir%\system32\SecurityHealthSystray.exe")]
    run_time = INSTALL
    if scenario == "attack":
        run.append(("WindowsUpdate", REG_SZ, RUN_KEY_COMMAND))
        run_time = local(21, 2, 20, 4)
    root.add(cv + r"\Run", run_time, run)
    root.add(cv + r"\RunOnce", INSTALL)

    apps = list(INSTALLED_APPS)
    for key, name, version, publisher, date in apps:
        root.add(cv + "\\Uninstall\\" + key, INSTALL + timedelta(days=2), [
            ("DisplayName", REG_SZ, name), ("DisplayVersion", REG_SZ, version),
            ("Publisher", REG_SZ, publisher), ("InstallDate", REG_SZ, date),
        ])
    if scenario == "attack":
        root.add(cv + r"\Uninstall\AnyDesk", local(21, 2, 21, 30), [
            ("DisplayName", REG_SZ, "AnyDesk"), ("DisplayVersion", REG_SZ, "8.1.0"),
            ("Publisher", REG_SZ, "AnyDesk Software GmbH"), ("InstallDate", REG_SZ, "20261121"),
            ("InstallLocation", REG_SZ, r"C:\Users\Public\Libraries\AnyDesk"),
        ])

    defender = r"Microsoft\Windows Defender"
    root.add(defender, INSTALL, [("ProductStatus", REG_DWORD, 0)])
    if scenario == "attack":
        root.add(defender + r"\Exclusions\Paths", local(21, 2, 19, 30),
                 [(r"C:\Users\Public\Libraries", REG_DWORD, 0)])
    else:
        root.add(defender + r"\Exclusions\Paths", INSTALL)
    return root


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scenario", choices=["attack", "clean"], default="attack")
    parser.add_argument("--out", default=os.path.join(here, "..", "samples"),
                        help="folder to write event-logs/ and registry-hives/ into")
    args = parser.parse_args()

    logs_dir = os.path.join(args.out, "event-logs")
    hives_dir = os.path.join(args.out, "registry-hives")
    os.makedirs(logs_dir, exist_ok=True)
    os.makedirs(hives_dir, exist_ok=True)

    security, system = build_logs(args.scenario)
    n_sec = write_evtx(os.path.join(logs_dir, "Security.evtx"), security)
    n_sys = write_evtx(os.path.join(logs_dir, "System.evtx"), system)
    write_hive(os.path.join(hives_dir, "SYSTEM"), build_system_hive(args.scenario),
               r"\SystemRoot\System32\Config\SYSTEM")
    write_hive(os.path.join(hives_dir, "SOFTWARE"), build_software_hive(args.scenario),
               r"\SystemRoot\System32\Config\SOFTWARE")
    print("scenario %s: Security.evtx %d records, System.evtx %d records, SYSTEM and SOFTWARE hives -> %s"
          % (args.scenario, n_sec, n_sys, os.path.abspath(args.out)))


if __name__ == "__main__":
    main()
