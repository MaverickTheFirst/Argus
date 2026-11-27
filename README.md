# Argus

A file integrity checker for Linux and other Unix-like systems (partial Windows
support). Snapshot a directory once, then detect modified, added, deleted, and
renamed files and permission changes. The snapshot is HMAC-signed, so tampering
with it is detected. Pure Python 3, no dependencies.

## Features

- **Content hashing:** SHA-256 of every file, read in 64 KB chunks so large files
  never have to fit in memory.
- **What it detects:**
  - modified files (content changed)
  - added and deleted files
  - renamed files (see [How renames are detected](#how-renames-are-detected))
  - permission and ownership changes (mode, owner, group), even when the content
    is identical
  - changes to symbolic links (their target) and to directories
- **Signed baseline:** the baseline carries an HMAC-SHA256 signature, checked on
  every run. A modified, corrupted, or wrongly keyed baseline is reported as an
  alert.
- **Safe baseline handling:**
  - the baseline is written atomically, so a crash never leaves a half-written file
  - `init` refuses to overwrite an existing baseline
  - `update` shows you every change and asks for confirmation before accepting it
- **Self-describing baseline:** the scanned directory and the exclusion patterns
  are stored inside the baseline, so `check` always scans the same thing the same way.
- **Exclusions:** skip files and folders that change constantly (logs, caches,
  `.git`) with shell-style patterns.
- **Audit log:** every run is recorded with UTC timestamps and severity levels.
- **Automation friendly:** meaningful exit codes, and a ready-made systemd timer
  for scheduled checks.
- **Defensive details:**
  - reported file names are quoted, so a file named with a newline cannot forge
    extra lines in the output or the log
  - files that cannot be read are reported, never silently treated as deleted
  - a file that changes while it is being hashed is flagged instead of being
    recorded with an inconsistent hash
  - symlinks are never followed

## Requirements

- Python 3.8 or newer
- Linux or another Unix-like system. Argus uses Unix file ownership and
  permission details; see [Windows](#windows) for what carries over there.

There is nothing to install: copy `argus.py` somewhere and run it.

### Windows

Argus has only been developed on Linux and has **not been tested on Windows**. The
core should work there, because content hashing, detection of modified, added,
deleted, and renamed files, and the signed baseline all use portable Python. These
parts do not carry over:

- **Permission and ownership checks:** Windows does not expose Unix mode, user, and
  group, so these checks are not meaningful (at most, the read-only flag shows up).
- **Key file protection:** the `0600` mode cannot make `argus.key` owner-only on
  Windows, and Argus's permission warning (written for Unix) is likely to appear on
  every run. Protect the key with NTFS permissions instead, for example with `icacls`.
- **Scheduling:** the systemd timer is Linux-only. Use Task Scheduler to run
  `argus.py check` on Windows.
- **Tests:** the test suite assumes Unix permission behaviour, so the permission
  test will fail on Windows.
- **Directory junctions** may not be recognised as links, so they could be followed.

## Quick start

```bash
# 1. Take a baseline of a directory you currently trust
python3 argus.py init /path/to/directory

# 2. Later, check whether anything has changed
python3 argus.py check

# 3. After reviewing legitimate changes, accept them as the new baseline
python3 argus.py update
```

The first `init` also creates a secret key file, `argus.key`, in the current
directory. Argus needs this key every time it runs. **Keep a backup of it**: without
the key, the baseline can no longer be verified.

## Commands

### `init DIRECTORY`

Scans `DIRECTORY`, creates the baseline, and signs it. If no key file exists yet, a
new random 32-byte key is generated with owner-only permissions (`0600`).

```bash
python3 argus.py init /etc/myapp --exclude "*.log" --exclude __pycache__
```

| Option | Meaning |
|---|---|
| `--exclude PATTERN` | Ignore files and folders whose **name** matches the pattern. Repeat the option to add more patterns. |

`init` stops with an error if the baseline already exists. Use `update` to replace it.

### `check`

Re-scans the directory recorded in the baseline, verifies the baseline's signature,
and reports every difference. It needs no directory argument and no exclusions,
because both are read from the baseline.

### `update`

Re-scans the directory, shows the differences, and asks:

```
Accept these changes as the new baseline? [y/N]
```

Only a `y` or `yes` replaces the baseline. Use `--yes` to skip the question
(for example in a script). `update` always uses the directory and exclusions stored
in the baseline; to change them, delete the baseline and run `init` again.

### Options available on every command

| Option | Default | Meaning |
|---|---|---|
| `--baseline FILE` | `baseline.json` | Where the baseline is stored |
| `--key FILE` | `argus.key` | The HMAC key file |
| `--log FILE` | `argus.log` | The log file (appended to) |

Keep the baseline, key, and log **outside** the monitored directory. Argus skips
them if they are inside, but it is cleaner and safer to keep them apart.

## Example

```
$ python3 argus.py init ~/test_folder --exclude "*.log"
Created key argus.key. Keep a copy somewhere safe, away from this machine.
Baseline created: 3 entries -> baseline.json

$ echo "tampered" > ~/test_folder/a.txt
$ touch ~/test_folder/new.txt
$ chmod 777 ~/test_folder/sub/b.txt

$ python3 argus.py check
Scanning '/home/you/test_folder'
Exclusions: '*.log'
Modified: '/home/you/test_folder/a.txt'
Added: '/home/you/test_folder/new.txt'
Metadata: '/home/you/test_folder/sub/b.txt'
    mode: 0644 -> 0777

Summary: 1 modified, 1 added, 0 deleted, 0 renamed, 1 metadata, 0 unreadable.
$ echo $?
1
```

If someone edits `baseline.json` to hide a change:

```
$ python3 argus.py check
ALERT: Baseline authentication FAILED: the file was modified, or a different key is being used. Do not trust this baseline.
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean: no changes, and everything was verified |
| `1` | Integrity problem: changes were found, the baseline failed authentication, the monitored directory is missing, or an `update` was declined |
| `2` | Argus could not do its job: missing or invalid baseline or key, paths that could not be read and so could not be verified, or an unexpected error |

Keeping `1` and `2` apart means a script can tell "something changed" from "the
tool itself is broken". A broken tool is never reported as a clean result.

## How it works

1. **Scan:** Argus walks the directory (without following symlinks) and records an
   entry for each file, symlink, and directory.
2. **Record:** each file entry holds its SHA-256 hash, size, permission bits,
   owner, group, and modification time. Symlinks store their target, and
   directories store their permissions and ownership.
3. **Sign:** the whole baseline is serialised in a fixed, canonical form and
   signed with HMAC-SHA256 using the key file.
4. **Check:** Argus verifies the signature first (in constant time), then scans
   again and compares the new scan against the baseline.

The modification time is stored for reference but is **not** treated as a change on
its own. It changes on every harmless `touch`, and an attacker can set it to any
value. The content hash is what decides whether a file changed.

### The baseline format

```json
{
  "hmac": "<hex signature>",
  "payload": {
    "version": 2,
    "root": "/absolute/path/to/directory",
    "exclude": ["*.log"],
    "files": {
      "/absolute/path/to/directory/a.txt": {
        "type": "file",
        "sha256": "…",
        "size": 5,
        "mode": 420,
        "uid": 1000,
        "gid": 1000,
        "mtime": 1700000000.0
      }
    }
  }
}
```

Modes are stored as plain numbers (`420` is octal `0644`) and displayed in octal in
reports.

### How renames are detected

If exactly one deleted path and exactly one added path have identical content, Argus
reports them as a single `Renamed` entry. If several files share the same content
(for example, a few empty files), Argus cannot tell which one moved where, so it
reports them honestly as separate `Added` and `Deleted` entries.

### Exclusion patterns

Patterns use shell-style wildcards (`*.log`, `cache*`, `.git`) and are matched
against a single file or folder **name**, not a full path. An excluded folder is
never entered at all.

## Scheduled checks with systemd

Create `~/.config/systemd/user/argus-check.service` (adjust the paths to where you
keep Argus):

```ini
[Unit]
Description=Argus integrity check

[Service]
Type=oneshot
WorkingDirectory=%h/argus
ExecStart=/usr/bin/python3 %h/argus/argus.py check --baseline %h/argus/baseline.json --key %h/argus/argus.key --log %h/argus/argus.log
```

Create `~/.config/systemd/user/argus-check.timer`:

```ini
[Unit]
Description=Run the Argus integrity check hourly

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

Enable it:

```bash
systemctl --user daemon-reload
systemctl --user enable --now argus-check.timer
systemctl --user list-timers
```

Because Argus exits non-zero when it finds a problem, systemd marks that run as
failed, so `systemctl --user --failed` shows when a check found something. Output
from past runs is available with `journalctl --user -u argus-check.service`. To keep
timers running while you are logged out, run `loginctl enable-linger $USER`.

## Running the tests

```bash
python3 -m unittest -v
```

The tests build a temporary directory for each case, run Argus against it, and check
the output and exit code. They cover clean checks, modified, added, and deleted
files, permission changes, timestamp-only changes, and detection of a tampered
baseline.

## Project files

| File | Purpose |
|---|---|
| `argus.py` | The tool |
| `test_argus.py` | The test suite |
| `baseline.json` | Generated: the signed baseline |
| `argus.key` | Generated: the secret HMAC key |
| `argus.log` | Generated: the audit log |

**Never commit `argus.key` or `baseline.json` to a public repository.** Add them to
`.gitignore`:

```
argus.key
baseline.json
argus.log
```

## Security notes and limitations

Argus is a learning project, and it is honest about what it does not do.

- **The key is the weak point.** An HMAC only protects the baseline if an attacker
  cannot read the key. If the key sits next to the baseline and an attacker can read
  both, they can modify the baseline and sign it again. Store the key somewhere the
  monitored account cannot read, or supply it from separate media. A scheduled job
  needs unattended access to the key, which is a trade-off between convenience and
  protection.
- **An attacker with root can defeat it.** Anyone who controls the machine can alter
  Argus itself, the key, the baseline, and the log.
- **The log is not tamper-proof.** Someone with write access can edit `argus.log`.
  For stronger guarantees, forward logs to another machine or make the file
  append-only.
- **Changes between checks can be missed.** A file that is modified and then
  restored between two scheduled runs leaves no trace. Argus is not a real-time
  monitor.
- **Not everything is tracked.** Sockets, named pipes, and device files are ignored.
  Extended attributes and ACLs are not recorded. Directory modification times are
  not compared.
- **Exclusions are by name only,** and are fixed when the baseline is created.
- **Some filesystems are unsupported by `init`.** Its no-overwrite check uses a hard
  link, which a few filesystems (such as FAT or some network mounts) do not allow.
- **Argus is Unix-oriented.** See [Windows](#windows) for the limits there.