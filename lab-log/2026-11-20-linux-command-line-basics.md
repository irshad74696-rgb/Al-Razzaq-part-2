# 2026-11-20 · Lab 1: Linux command-line basics

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Status** | Done (my own terminal output and screenshots still to add) |
| **Environment** | Ubuntu Linux, Bash |
| **Lab folder** | [`cybersecurity-fundamentals/lab-1-linux-command-line-basics/`](../cybersecurity-fundamentals/lab-1-linux-command-line-basics/README.md) |

## What the lab covered

Moving around the Linux filesystem, creating, copying, moving and deleting files and folders, and controlling access with `chmod` and `chown`, including how permissions behave differently on directories.

## Commands and configs used

```bash
# where am I, what is here, how do I move
pwd; ls -la; cd /; cd ..; cd ~; cd -

# create and fill files
mkdir -p project/{src,docs,tests}
touch a.txt b.txt
echo "line 1" > log.txt      # overwrite
echo "line 2" >> log.txt     # append

# copy, move, rename, delete
cp log.txt log.bak; cp -r project project-copy
mv b.txt renamed.txt; mv log.bak archive/
rm a.txt; rmdir empty/; rm -r project-copy

# permissions
chmod u+x hello.sh           # make a script runnable
chmod 600 key.txt            # private file
chmod 755 tool.sh            # runnable by everyone, editable by owner
ls -ld vault                 # the folder's own permissions
sudo chown root:root hello.sh && sudo chown "$USER":"$USER" hello.sh
```

Practice scripts: [`build-practice-area.sh`](../cybersecurity-fundamentals/lab-1-linux-command-line-basics/scripts/build-practice-area.sh), [`hello.sh`](../cybersecurity-fundamentals/lab-1-linux-command-line-basics/scripts/hello.sh), [`permissions-demo.sh`](../cybersecurity-fundamentals/lab-1-linux-command-line-basics/scripts/permissions-demo.sh).

## What broke and how I fixed it

| Problem | Cause | Fix |
| --- | --- | --- |
| `./hello.sh: Permission denied` | New files have no execute bit | `chmod u+x hello.sh` |
| `rm: cannot remove 'backup': Is a directory` | Plain `rm` only removes files | `rm -r backup` (or `rmdir` when empty) |
| `chmod 000` on a folder did not block `ls` | Running as root, which skips read/write checks | Re-ran the test as a normal user, where it was denied as expected |

## Key takeaway

Always check permissions as the user who will actually use the file, not as root. Root bypasses them, so a test run as root says nothing about who else can read a private key or edit a script.

## Screenshots

Folder: [`screenshots/2026-11-20-linux-command-line-basics/`](screenshots/)

- `01-permission-denied.png`: running a script before and after `chmod u+x`
- `02-directory-permissions.png`: `permissions-demo.sh` output run as a normal user
