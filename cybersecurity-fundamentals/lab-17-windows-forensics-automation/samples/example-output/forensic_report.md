# Windows Forensic Analysis Report

Generated: 2026-11-28T09:23:35.063366Z by forensic_automation.ps1 (PowerShell 7.4.6 on Ubuntu 24.04.5 LTS)

All times are UTC. The graded IOC report comes from analyze_activity.py.

## Files processed

| File | Type | Items | Original evidence | SHA-256 of evidence |
| --- | --- | ---: | --- | --- |
| security_events.json | event log (Security) | 1268 | Security.evtx | `f9afdf5aba33b11dada412393249af4fee211d16c8e5dbf28d3f400c5eca3a63` |
| system_events.json | event log (System) | 50 | System.evtx | `8dafbd1f1fd7024027e7f2b72d848571c9475c4a2ca9d60152325dede15c99cd` |
| software_hive.json | registry (SOFTWARE) | 10 | SOFTWARE | `c90b48e0b71cde4a8e9f178023fec1a4a9395f58e3382228d5d8578d28caede0` |
| system_hive.json | registry (SYSTEM) | 16 | SYSTEM | `f040814f4e1404c81f981ad1b7976c7258b678745b9a8e934d7b7171c979be26` |

## Key findings

- **Computer:** WS-LAB-07, control set ControlSet001, time zone Pakistan Standard Time (UTC+5)
- **Network:** 10.20.30.47, gateway 10.20.30.1 (DHCP)
- **Last clean shutdown:** 2026-11-19T12:52:00.000000Z
- **Windows:** Windows 10 Pro 22H2 (build 19045), installed 2026-03-10T06:20:00.000000Z; 6 programs, 16 services
- **Security log:** 1268 events from 2026-11-18T03:48:36.000000Z to 2026-11-20T21:24:55.000000Z; most frequent: 4625 x1201, 4624 x32, 4672 x20
- **System log:** 50 events from 2026-11-18T03:48:26.000000Z to 2026-11-20T21:19:01.000000Z; most frequent: 7036 x43, 6005 x3, 6006 x2

## Suspicious activity indicators

- **Brute force:** 1200 failed logons from 203.0.113.50 (public address) between 2026-11-20T21:04:10.000000Z and 2026-11-20T21:11:50.778999Z; accounts tried: administrator, guest, admin, it-admin, backup
- **Brute force succeeded:** logon as it-admin from 203.0.113.50 at 2026-11-20T21:12:03.000000Z
- **Suspicious process:** Process C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe started by it-admin at 2026-11-20T21:15:02.000000Z; decoded command: Write-Output 'FORENSICS-LAB SAMPLE: harmless placeholder for a malicious download cradle'
- **Account created:** User account support_tmp created by it-admin at 2026-11-20T21:16:30.000000Z
- **Group change:** S-1-5-21-1111111111-2222222222-3333333333-1010 added to Administrators by it-admin at 2026-11-20T21:16:45.000000Z
- **Anti-forensics:** Security log cleared by it-admin at 2026-11-20T21:24:55.000000Z
- **New service:** Service 'Windows Update Helper' installed: C:\Users\Public\Libraries\winupdate.exe (auto start, LocalSystem) at 2026-11-20T21:18:12.000000Z
- **Service change:** Start type of 'Microsoft Defender Antivirus Service' changed from auto start to disabled at 2026-11-20T21:19:00.000000Z
- **Autostart:** 'WindowsUpdate' in Microsoft\Windows\CurrentVersion\Run (encoded PowerShell command, hidden window); decoded: Write-Output 'FORENSICS-LAB SAMPLE: harmless placeholder for a malicious download cradle'
- **Service in registry:** WinUpdateHelper -> C:\Users\Public\Libraries\winupdate.exe (runs from a user-writable folder, auto-start program outside Windows and Program Files, name imitates a Windows component)
- **Security service disabled:** WinDefend (Microsoft Defender Antivirus Service), key written 2026-11-20T21:19:00.000000Z
- **Defender exclusion (paths):** C:\Users\Public\Libraries, written 2026-11-20T21:19:30.000000Z
- **Remote access tool:** AnyDesk 8.1.0 installed 20261121 at C:\Users\Public\Libraries\AnyDesk
- **Stored secret:** value 'DefaultPassword' in ROOT\Microsoft\Windows NT\CurrentVersion\Winlogon (shown masked: SA************ (31 characters, masked))

## Timeline

Up to 40 of 31 entries, starting just before the first suspicious one. The full list is in forensic_timeline.json.

| Time (UTC) | Source | Description |
| --- | --- | --- |
| 2026-11-19T06:31:14.000000Z | eventlog:Security | Logon (network) by bob from 10.20.30.15 |
| 2026-11-19T09:05:12.000000Z | eventlog:Security | Logon (RDP) by it-admin from 10.20.30.5 |
| 2026-11-19T09:05:12.000999Z | eventlog:Security | Admin privileges assigned to it-admin |
| 2026-11-19T10:48:13.000000Z | eventlog:Security | Logon (network) by bob from 10.20.30.15 |
| 2026-11-19T12:50:05.000000Z | eventlog:System | Event Log service stopped (shutdown) |
| 2026-11-19T12:52:00.000000Z | registry:SYSTEM | Last clean shutdown recorded in the registry |
| 2026-11-20T03:49:57.000000Z | eventlog:System | Event Log service started (boot) |
| 2026-11-20T06:22:22.000000Z | eventlog:Security | Logon (network) by bob from 10.20.30.15 |
| 2026-11-20T10:33:48.000000Z | eventlog:Security | Logon (network) by bob from 10.20.30.15 |
| 2026-11-20T21:04:10.000000Z | eventlog:Security | First of 1200 failed logons from 203.0.113.50 |
| 2026-11-20T21:11:50.778999Z | eventlog:Security | Last of 1200 failed logons from 203.0.113.50 |
| 2026-11-20T21:12:03.000000Z | eventlog:Security | Logon (network) by it-admin from 203.0.113.50 |
| 2026-11-20T21:12:03.000000Z | eventlog:Security | Successful logon as it-admin from 203.0.113.50 after 1200 failures |
| 2026-11-20T21:12:03.000999Z | eventlog:Security | Admin privileges assigned to it-admin |
| 2026-11-20T21:13:40.000000Z | eventlog:Security | it-admin used explicit credentials for administrator via C:\Windows\System32\runas.exe |
| 2026-11-20T21:15:02.000000Z | eventlog:Security | Process C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe started by it-admin |
| 2026-11-20T21:16:30.000000Z | eventlog:Security | User account support_tmp created by it-admin |
| 2026-11-20T21:16:45.000000Z | eventlog:Security | S-1-5-21-1111111111-2222222222-3333333333-1010 added to Administrators by it-admin |
| 2026-11-20T21:18:12.000000Z | eventlog:System | Service 'Windows Update Helper' installed: C:\Users\Public\Libraries\winupdate.exe (auto start, LocalSystem) |
| 2026-11-20T21:18:12.000000Z | registry:SYSTEM | Service key WinUpdateHelper written (C:\Users\Public\Libraries\winupdate.exe) (key last written) |
| 2026-11-20T21:19:00.000000Z | registry:SYSTEM | Security service WinDefend set to disabled (key last written) |
| 2026-11-20T21:19:00.000000Z | eventlog:System | Start type of 'Microsoft Defender Antivirus Service' changed from auto start to disabled |
| 2026-11-20T21:19:30.000000Z | registry:SOFTWARE | Defender exclusion (paths): C:\Users\Public\Libraries (key last written) |
| 2026-11-20T21:20:04.000000Z | registry:SOFTWARE | Autostart 'WindowsUpdate' in Microsoft\Windows\CurrentVersion\Run: encoded PowerShell command, hidden window (key last written) |
| 2026-11-20T21:21:30.000000Z | registry:SOFTWARE | AnyDesk 8.1.0 installed (C:\Users\Public\Libraries\AnyDesk) (key last written) |
| 2026-11-20T21:24:55.000000Z | eventlog:Security | Security log cleared by it-admin |

## Recommendations

- Block the attacking addresses at the firewall, enforce account lockout, and do not expose SMB/RDP to the internet.
- Treat the compromised account as owned: reset its password, review everything done in its logon session, and check other machines for the same credentials.
- Disable and investigate accounts created or added to Administrators during the incident.
- Collect and hash the binaries behind the flagged services and autostart entries, then remove the persistence after evidence is preserved.
- Re-enable Microsoft Defender, remove the exclusions, and run a full offline scan.
- The log was cleared: recover older events from a log forwarder/SIEM, shadow copies or backups, and enable log forwarding if it is missing.
- Uninstall unapproved remote access tools and check their own logs for sessions.
- Remove plaintext credentials from the registry (for example Winlogon DefaultPassword) and rotate those passwords.
- Keep the original evidence files read-only and re-check their SHA-256 values above before sharing results.

