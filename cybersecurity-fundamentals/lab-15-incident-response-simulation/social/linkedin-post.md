🚨 A monitoring alert says one of your Linux servers is talking to an address it shouldn't. What do you do first?

I set up a realistic (and harmless) compromise on Ubuntu and worked it as a real incident, end to end: a disguised background process beaconing to an outside IP, an unauthorised account with a working password, and a hidden file in /tmp. Then I scripted every phase so the whole response can be re-run and checked.

🔎 Detect: a read-only triage script flagged the process by where its output was going (a hidden file in /tmp), the IP hard-coded in its command line, and an account nobody created.

🧱 Contain, in the right order:
1. Snapshot the process first (command line, open files, sockets, program hash). Once you kill it, that evidence is gone.
2. Block the IP with iptables -I at the top of the chain, not -A at the bottom, where an earlier ACCEPT rule can make it useless. Then send a test packet and watch the DROP counter go from 0 to 3. Proven, not assumed.
3. Kill the whole process tree. In my first test a grandchild process kept beaconing after its parent was gone.
4. Lock AND expire the account. A password lock alone doesn't stop an SSH key login.

🧾 Collect: evidence gathered most-volatile first, a SHA-256 for every file and for the archive, plus a chain-of-custody record. Change a single byte and the verify step catches it.

📝 Document: every action is written to a timeline as it happens, and the incident report is generated from it. Real PIDs, real hashes, real timestamps, nothing typed by hand.

The rule I won't forget: never flush a firewall during an incident. Add exact rules, remove exact rules.

38 automated checks cover the full cycle. Scripts, sample report and write-up are on my GitHub: https://github.com/irshad74696-rgb

#CyberSecurity #IncidentResponse #DFIR #Linux #BlueTeam #SOC #InfoSec #OpenToWork
