# Lab 1: Linux Command-Line Basics

The shell is where security work happens: servers rarely have a desktop, logs and configs are plain text files, and most security tools are run from a terminal. This lab builds the four habits everything else depends on: knowing **where you are**, **moving around**, **handling files safely**, and **reading and setting permissions**.

| | |
| --- | --- |
| **Track** | Cyber Security (foundations) |
| **Environment** | Ubuntu Linux, Bash |
| **Skills** | Filesystem navigation, file and directory management, `chmod`, `chown`, directory permissions |
| **Artifacts** | [`scripts/`](scripts/): practice scripts written for this lab |

## Contents

1. [How the Linux filesystem is laid out](#1-how-the-linux-filesystem-is-laid-out)
2. [Finding your way around](#2-finding-your-way-around)
3. [Creating, copying, moving and deleting](#3-creating-copying-moving-and-deleting)
4. [File permissions with chmod and chown](#4-file-permissions-with-chmod-and-chown)
5. [Directory permissions](#5-directory-permissions)
6. [Self-check](#6-self-check)
7. [Common mistakes and fixes](#7-common-mistakes-and-fixes)
8. [Command reference](#8-command-reference)
9. [Takeaway](#9-takeaway)

---

## 1. How the Linux filesystem is laid out

Everything lives under a single top folder, `/` (called "root"). There are no drive letters. A few folders worth knowing on day one:

| Path | What lives there |
| --- | --- |
| `/home/<user>` | Each user's personal files. Your "home" is written `~` |
| `/root` | The root (administrator) account's home |
| `/etc` | System configuration (for example `/etc/ssh/sshd_config`) |
| `/var/log` | Log files, the first place to look during an incident |
| `/tmp` | Scratch space, often cleared on reboot |
| `/bin`, `/usr/bin` | The programs you run, like `ls` and `cp` |

A path can be written two ways:

- **Absolute**: starts at `/` and works from anywhere, e.g. `/var/log/auth.log`
- **Relative**: starts from the folder you are in, e.g. `notes/todo.txt`

Two shortcuts appear everywhere: `.` means "this folder" and `..` means "the folder above".

## 2. Finding your way around

```bash
pwd          # print the folder you are in right now
ls           # list what is in it
ls -l        # long listing: permissions, owner, size, date
ls -la       # long listing including hidden files (names starting with a dot)
```

Hidden files matter in security. Files like `~/.bashrc` or `~/.ssh/authorized_keys` control how a shell starts and who can log in, and plain `ls` will not show them.

Moving between folders:

```bash
cd /         # jump to the top of the filesystem
cd /var/log  # jump to an absolute path
cd ..        # go up one level
cd ~         # go home (plain `cd` does the same)
cd -         # go back to the folder you were in before
```

Run `pwd` after any `cd` you are unsure about. It costs nothing and prevents running a command in the wrong place.

## 3. Creating, copying, moving and deleting

The commands below were run inside a scratch folder. [`scripts/build-practice-area.sh`](scripts/build-practice-area.sh) recreates the same layout in one step, so the exercises can be repeated from a clean start.

### Create

```bash
mkdir ~/cli-practice && cd ~/cli-practice   # make a folder and step into it
touch alpha.txt                              # create an empty file
touch beta.txt gamma.txt                     # several files at once
mkdir notes                                  # a subfolder
mkdir -p project/{src,docs,tests}            # nested folders in one go; -p creates parents as needed
```

`touch` on a file that already exists does not empty it; it only updates its timestamp.

### Write and read file contents

```bash
echo "first line"  >  journal.txt   # >  creates the file or REPLACES its contents
echo "second line" >> journal.txt   # >> adds to the end
cat journal.txt                     # print the file

cat > notes/why-cli.txt <<'TEXT'    # a here-document: everything up to TEXT goes into the file
Servers usually have no desktop.
Logs and configs are plain text.
TEXT
```

The difference between `>` and `>>` is one character and it is the difference between appending to a log and wiping it.

### Copy

```bash
cp journal.txt journal.bak          # copy under a new name
cp alpha.txt notes/                 # copy into a folder, keeping the name
cp beta.txt gamma.txt notes/        # several files into one folder
cp journal.txt notes/journal-copy.txt   # copy into a folder with a new name
cp -r notes notes-backup            # copy a whole folder (-r = recursive)
```

### Move and rename

`mv` does both jobs. Moving to a new name in the same folder is a rename.

```bash
mkdir archive
mv journal.bak archive/             # move into a folder
mv beta.txt important.txt           # rename
mv gamma.txt archive/old-gamma.txt  # move and rename at once
mv notes-backup archive/            # folders move the same way, no -r needed
```

### Delete

There is no recycle bin on the command line. Deleted means gone.

```bash
rm important.txt                    # delete a file
rm alpha.txt journal.txt            # delete several
rmdir empty-folder                  # delete a folder only if it is empty
rm -r archive                       # delete a folder and everything in it
rm -ri archive                      # same, but ask before each item
```

Safe habit: run `ls` with the exact same path first, check the list, then swap `ls` for `rm`.

## 4. File permissions with chmod and chown

### Reading a permission string

```
$ ls -l tool.sh
-rwxr-x---  1  irshad  devs  38  Nov 20 03:17  tool.sh
│└┬┘└┬┘└┬┘     └─┬──┘  └┬─┘
│ │  │  │        │      └── group that owns the file
│ │  │  │        └── user that owns the file
│ │  │  └── others: everyone else  (---  nothing)
│ │  └── group                      (r-x  read, execute)
│ └── owner                         (rwx  read, write, execute)
└── type: - file, d directory, l link
```

| Letter | On a file | Number |
| --- | --- | --- |
| `r` | read the contents | 4 |
| `w` | change the contents | 2 |
| `x` | run it as a program | 1 |

### Symbolic mode: add or remove one thing

Pick **who** (`u` owner, `g` group, `o` others, `a` all), an **action** (`+` add, `-` remove, `=` set exactly), and **what** (`r`, `w`, `x`).

```bash
chmod u+x tool.sh      # let the owner run it
chmod go-w tool.sh     # stop group and others from editing it
chmod a+r notes.txt    # let everyone read it
chmod o= secrets.txt   # remove every permission for others
```

### Numeric mode: set all three at once

Add up the numbers for each group: owner, then group, then others.

| Number | Letters | Typical use |
| --- | --- | --- |
| `755` | `rwxr-xr-x` | Scripts and programs others may run, public folders |
| `750` | `rwxr-x---` | Scripts only your team should run |
| `644` | `rw-r--r--` | Normal documents and config files |
| `600` | `rw-------` | Private keys, password files, `.env` files |
| `700` | `rwx------` | Private folders such as `~/.ssh` |
| `444` | `r--r--r--` | Read-only for everyone |

Each digit is just a sum: 7 = 4+2+1, 6 = 4+2, 5 = 4+1, 0 = nothing.

### Making a script runnable

[`scripts/hello.sh`](scripts/hello.sh) is a two-line script used for this:

```bash
ls -l hello.sh     # -rw-r--r--  no x anywhere
./hello.sh         # bash: ./hello.sh: Permission denied
chmod u+x hello.sh
./hello.sh         # Hello from irshad on ...
```

A script without `x` can still be run with `bash hello.sh`, because bash only needs to read it. So removing `x` is not a security control on its own; removing `r` is what stops people.

### Changing the owner with chown

Only root can give a file away to another user, so these need `sudo` (or a root shell).

```bash
whoami                               # which user am I?
groups                               # which groups am I in?
sudo chown root:root hello.sh        # owner and group both root
sudo chown "$USER":"$USER" hello.sh  # give it back
sudo chown alice report.txt          # change only the owner
sudo chown :devs report.txt          # change only the group (chgrp does the same)
sudo chown -R www-data /srv/site     # a whole folder tree
```

## 5. Directory permissions

The same three letters mean different things on a folder:

| Letter | On a directory |
| --- | --- |
| `r` | list the names inside (`ls`) |
| `w` | create, rename or delete files inside it |
| `x` | enter it (`cd`) and reach the files inside by name |

`x` is the one that matters most. Without it, nothing inside is reachable even if the files themselves are readable. [`scripts/permissions-demo.sh`](scripts/permissions-demo.sh) runs every case below in a throwaway folder and prints the result of each step:

| Mode on `vault/` | `ls vault` | `cat vault/file.txt` |
| --- | --- | --- |
| `700` | works | works |
| `600` (r, no x) | shows names | Permission denied |
| `100` (x, no r) | Permission denied | works if you know the name |
| `000` | Permission denied | Permission denied |

Use `ls -ld vault` (with `d`) to see the folder's own permissions instead of its contents.

A folder's `w` also explains a surprise: anyone with write access to a folder can delete files in it, even files they do not own and cannot read. That is why shared folders like `/tmp` carry the "sticky bit" (`drwxrwxrwt`), which limits deletion to each file's owner.

## 6. Self-check

If all of these work without looking anything up, the lab is done:

```bash
cd / && pwd && cd ~ && pwd                      # navigate and confirm
mkdir -p check/project/{src,docs,tests}         # build a tree
touch check/project/README.md check/project/docs/manual.txt
cp check/project/README.md check/project/docs/  # copy
mv check/project/docs/manual.txt check/project/docs/user-guide.txt   # rename
printf '#!/usr/bin/env bash\necho "self-check passed"\n' > check/done.sh
chmod 755 check/done.sh && ls -l check/done.sh && ./check/done.sh    # permissions
rm -r check                                     # clean up
```

## 7. Common mistakes and fixes

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `Permission denied` when running `./script.sh` | No execute bit | `chmod u+x script.sh`, or run it with `bash script.sh` |
| `rm: cannot remove 'dir': Is a directory` | Plain `rm` only deletes files | `rmdir dir` if empty, `rm -r dir` if not |
| `No such file or directory` for a file you can see in the file manager | You are in a different folder | `pwd`, then use the absolute path or `cd` to the right place |
| `command not found` | Typo, or the program is not installed | Check spelling, then `which name` or `type name`; install the package if missing |
| A file's contents vanished | Used `>` instead of `>>` | Use `>>` to append; set `set -o noclobber` to make `>` refuse to overwrite |
| `chmod 000` did not lock a folder | You were root; root skips read/write checks | Test permissions as a normal user (`su - username`, or `sudo -u username ls dir`) |
| `chown: changing ownership ...: Operation not permitted` | Normal users cannot give files away | Run it with `sudo` |
| `ls dir` works but `cd dir` fails | Folder has `r` but not `x` | `chmod u+x dir` |

The root one is easy to miss: when practising as root, every "this should fail" step succeeds, and it looks as if permissions do nothing. They do; root just ignores them.

## 8. Command reference

| Command | What it does | Example |
| --- | --- | --- |
| `pwd` | Show the current folder | `pwd` |
| `ls` | List folder contents | `ls -la /etc` |
| `cd` | Change folder | `cd ..`, `cd ~`, `cd -` |
| `mkdir` | Make a folder | `mkdir -p a/b/c` |
| `touch` | Create an empty file / update its time | `touch notes.txt` |
| `echo` | Print text (redirect it into a file) | `echo hi >> log.txt` |
| `cat` | Print a file | `cat /etc/os-release` |
| `cp` | Copy files or folders | `cp -r src/ backup/` |
| `mv` | Move or rename | `mv old.txt new.txt` |
| `rm` | Delete files (`-r` for folders) | `rm -ri old/` |
| `rmdir` | Delete an empty folder | `rmdir empty/` |
| `chmod` | Change permissions | `chmod 640 app.conf`, `chmod u+x run.sh` |
| `chown` | Change owner and group | `sudo chown alice:devs report.txt` |
| `whoami` / `groups` / `id` | Show who you are and your groups | `id` |
| `which` / `type` | Find where a command lives | `which python3` |

## 9. Takeaway

Permissions are the first line of access control on any Linux box, and reading `ls -l` output quickly is a daily skill in security work: a world-writable script, a private key set to `644`, or a config owned by the wrong user are all real findings. The biggest lesson from this lab was that **testing as root proves nothing about permissions**, because root bypasses them; check access as the user who will actually use the file.
