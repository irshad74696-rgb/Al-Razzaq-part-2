# Linux System Administration Labs

Short labs on running a Red Hat-style Linux system, done on my own Ubuntu 25.10 machine. The notes below are my own summaries; lab handouts are not included.

Fuller write-ups for selected labs live in the [Lab Log](../LAB-LOG.md).

| Lab | Topic | What I practiced |
| --- | --- | --- |
| 1 | Intro to RHEL | Open-source licensing basics, RHEL vs Fedora vs CentOS Stream, checking the OS release |
| 2 | Logging in and the shell | Console and SSH logins, Bash basics, command history, tab completion |
| 3 | Files and directories | `mkdir`, `cp`, `mv`, `rm`, globbing, absolute vs relative paths |
| 4 | Local help | `man`, `--help`, `info`, `/usr/share/doc`; practice files in [`lab4/`](lab4/) |
| 5 | Editing text files | `vim` and `nano`, find and replace with `sed` |
| 6 | Users and groups | `useradd`, `usermod`, `groupadd`, `passwd`, `/etc/passwd` and `/etc/group` |
| 7 | Permissions and ownership | Reading `ls -l`, `chmod` (symbolic and octal), `chown`, `umask` |
| 8 | Processes | `ps`, `top`, signals with `kill`, job control with `bg`, `fg`, `jobs` |
| 9 | Services with systemd | `systemctl start/stop/enable/status`, unit files, `journalctl -u` |
| 10 | Securing SSH | Port change, no root login, key-only auth; see [`lab-10/sshd_config`](lab-10/sshd_config) and the [log entry](../lab-log/2026-10-11-ssh-hardening.md) |
| 11 | Logs | `journalctl` filters, `/var/log`, rsyslog, making the journal persistent |
| 12 | Network interfaces | `ip addr`, `nmcli` connection settings (address, gateway, DNS, method) |
| 14 | Software packages | Package managers, repositories, installing, updating and removing packages |
| 15 | Filesystems | `lsblk`, `blkid`, `fdisk`, `mkfs`, `mount`, `/etc/fstab` |
| 16 | Network file systems | Mounting NFS and CIFS/SMB shares, persistent mounts |
| 17 | Performance monitoring | `top`, `free`, `vmstat`, `iostat`, `df`, `du`, network usage |
| 18 | SELinux basics | Modes, `ls -Z`, `chcon`, `restorecon`, booleans |
| 19 | Customer portal and Cockpit | Where to find knowledge-base articles; Cockpit web console |
| 20 | Diagnostic data | `sos report` bundles and what Red Hat Insights does with them |

There is no lab 13 folder yet.
