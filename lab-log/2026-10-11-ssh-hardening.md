# 2026-10-11 · Hardening the SSH server

| | |
| --- | --- |
| **Track** | Linux / Cyber Security |
| **Status** | Done |
| **Environment** | Ubuntu 25.10, OpenSSH server, run as root |
| **Lab folder** | [`redhat-3/lab-10`](../redhat-3/lab-10/) |

## What the lab covered

Locking down `sshd`: moving it off the default port, blocking root logins, turning off passwords so only key-based login works, and allowing a single named user.

## Commands and configs used

```ini
# /etc/ssh/sshd_config (relevant lines)
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AllowUsers irshadali
```

```bash
sshd -t                                  # syntax check; prints nothing when the file is valid
systemctl disable --now ssh.socket       # let sshd_config, not the socket unit, pick the port
systemctl restart ssh
ss -tlnp | grep :2222                    # confirm the new port is listening

# install the public key by hand (password login is already off)
install -d -m 700 -o irshadali -g irshadali /home/irshadali/.ssh
cat /root/.ssh/id_ed25519.pub >> /home/irshadali/.ssh/authorized_keys
chown irshadali:irshadali /home/irshadali/.ssh/authorized_keys
chmod 600 /home/irshadali/.ssh/authorized_keys

ssh -p 2222 irshadali@127.0.0.1          # key login works
sshd -T | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers)'
```

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| `ssh.service` failed to start, then "start request repeated too quickly" | Typo `PasswdAuthentication` in sshd_config | `sshd -t` named the line; fixed it to `PasswordAuthentication`, then `systemctl reset-failed` |
| Still listening on port 22 after changing `Port` | Ubuntu uses socket activation, so `ssh.socket` owns the port | `systemctl disable --now ssh.socket` and restart `ssh` |
| `ssh-copy-id` could not log in | Password authentication was already off, and the target account has no usable password | Copied the public key into `authorized_keys` directly as root |

## Key takeaway

Always run `sshd -t` before restarting, and check the live config with `sshd -T` rather than trusting the file. On modern Ubuntu, check whether a `.socket` unit is holding the port.

## Screenshots

None captured.
