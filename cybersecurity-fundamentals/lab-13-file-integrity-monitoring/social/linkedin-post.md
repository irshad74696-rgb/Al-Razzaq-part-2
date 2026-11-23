🔐 If someone changed a file on your Linux server last night, would you know?

This week I built a file integrity monitoring setup on Ubuntu using only open-source tools, and the biggest lesson was that no single tool answers the whole question.

🕵️ auditd tells you WHO. Kernel watch rules on /etc/passwd, /etc/shadow, sudoers, cron, systemd units and /usr/bin record the user, the program and the result. A line like "acting as root, changed-file-permissions-of /usr/bin/id to suid using chmod" is exactly what an incident responder needs.

#️⃣ A SHA-256 baseline tells you WHAT. Hash every file while the system is known to be good, then compare. I also store permissions and owners, because a setuid bit added with chmod 4755 never changes the file's content.

⚡ inotify tells you NOW. inotifywait raises an alert the moment a file is created, changed, moved or deleted.

To test it, I played the attacker: dropped a sudoers file, set a setuid bit, planted a program in /usr/local/bin and edited /etc/hosts. All four showed up in one report, each with the program that did it.

Fixing the starting scripts taught me as much as writing new ones:
✅ A "changes found" flag set inside a pipe was lost in a subshell, so the report said "No changes detected" under a list of new files
✅ A grep substring match quietly missed new files
✅ One missing folder made auditctl skip every rule after it, so two-thirds of my watches never loaded
✅ Audit rules vanish at reboot unless they live in /etc/audit/rules.d
✅ A check that always exits 0 can never raise an alarm

The scripts, audit rules, systemd timer and a sample report are on my GitHub: https://github.com/irshad74696-rgb

Next up: comparing this with AIDE and sending the alerts to a SIEM.

#CyberSecurity #Linux #FileIntegrityMonitoring #auditd #BlueTeam #SOC #IncidentResponse #InfoSec #OpenToWork
