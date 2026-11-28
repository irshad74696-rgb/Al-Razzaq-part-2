🔍 If a Linux server got broken into last night, what would you collect first, and could you prove later that nobody changed it?

I built an automated Linux forensics workflow to answer that, and tested it against a staged (harmless) attack: a password brute force that ends in a successful login, sudo abuse by a non-admin account, a netcat listener on port 4444, and a file named like a backdoor.

📦 Collect: one Bash script gathers processes and network sockets first (they change by the second), then accounts, logs, cron and temp folders. Every command's exit code is logged, so "missing" never looks like "clean". Every file gets a SHA-256, the archive is read-only, and no password hashes ever enter the evidence.

🐍 Analyse: a Python analyser parses auth logs, ps and ss output and grades each finding. Many failures from one address is HIGH. A successful login from that same address after the failures began is CRITICAL.

🚨 Detect: a live check asks the same questions of the running host, so a finding confirmed by both tools shows up once, with both sources.

📝 Report: text and HTML reports are generated from the data, with the timeline, recommendations and the hashes re-verified inside the report. Change one byte of evidence and the report says VERIFICATION FAILED.

The lesson I won't forget: attackers write into your logs. sshd logs the username before the source address, so a username like "test from 10.9.9.9 port 22" makes a naive parser blame the wrong machine. My analyser reads the address from the end of the line and reports the forgery itself.

57 end-to-end checks and 16 unit tests pass. Scripts, sample reports and the write-up are on my GitHub: https://github.com/irshad74696-rgb

#CyberSecurity #DFIR #DigitalForensics #Linux #Python #BlueTeam #SOC #OpenToWork
