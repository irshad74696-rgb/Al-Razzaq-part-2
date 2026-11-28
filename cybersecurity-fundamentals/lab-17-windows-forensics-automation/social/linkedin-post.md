🪟 Can you investigate a Windows machine without Windows? I spent this lab proving you can, with Python and PowerShell 7 on Linux.

The case: a workstation where 1,200 failed logons from one address ended with a guessed admin password. Within 13 minutes the intruder ran a hidden PowerShell command, created a backdoor admin, installed a fake "Windows Update Helper" service, disabled Defender, added a Run key, installed AnyDesk and cleared the Security log.

🐍 Extract: Python reads the raw .evtx event logs and the SYSTEM and SOFTWARE registry hives, read-only. Every source file gets a SHA-256, and anything that looks like a stored password is masked before it reaches a report.

⚙️ Summarise: a PowerShell 7 script counts logons per source address, flags Run keys, services and Defender exclusions, and builds one timeline from both sources.

🔗 Correlate: the strongest findings are the ones two sources agree on. The new service shows up in the event log and in the registry; Defender's shutdown too, in the same minute.

📝 Report: a graded IOC report (Critical to Low) mapped to MITRE ATT&CK, with the attacker IP, accounts, paths and the decoded PowerShell command.

The lesson I won't forget: event logs store UTC. The attack started at 21:04 UTC, which looks like normal working hours. Read the time zone from the registry and it was 02:04 on a Saturday night.

Real Windows evidence can't be published, so I also wrote small writers for the real .evtx and registry file formats, built the scenario plus a clean baseline, and checked both against independent parsers. The clean machine gives zero findings. 34 tests pass.

Scripts, sample evidence and the write-up are on my GitHub: https://github.com/irshad74696-rgb

#CyberSecurity #DFIR #DigitalForensics #WindowsForensics #Python #PowerShell #BlueTeam #SOC #OpenToWork
