import argparse
import fnmatch
import hashlib
import hmac
import json
import os
import stat
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

# Exit codes: 0 = clean, 1 = integrity problem found, 2 = the tool could not do its job
BASELINE_VERSION = 2
KEY_BYTES = 32
META_FIELDS = ("mode", "uid", "gid")


# The tool could not do its job (bad setup, missing file, ...). Exit code 2.
class ArgusError(Exception):
    pass


# The baseline failed authentication. Exit code 1.
class TamperError(Exception):
    pass


# ---------------------------------------------------------------- helpers

# Quote text so control characters in file names cannot fake lines in the report.
def safe(text):
    return repr(str(text))


# Return True if a file or folder name matches any exclusion pattern.
def is_excluded(name, patterns):
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


# Format a metadata value for display; permission bits are shown in octal (0644).
def fmt(field, value):
    return format(value, "04o") if field == "mode" else str(value)


# Return True if path is an unreadable path or sits inside an unreadable folder.
def is_unreadable(path, unreadable):
    return any(path == u or path.startswith(u + os.sep) for u in unreadable)


# ---------------------------------------------------------------- keys

# Create a new random key file readable only by its owner. Fails if it already exists.
def create_key(key_path):
    key = os.urandom(KEY_BYTES)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.hex() + "\n")
    return key


# Load the HMAC key from a file of hex characters.
def load_key(key_path):
    try:
        key = bytes.fromhex(Path(key_path).read_text().strip())
    except FileNotFoundError:
        raise ArgusError(f"Key file {key_path} not found. 'init' creates it.")
    except ValueError:
        raise ArgusError(f"Key file {key_path} is not valid (expected hexadecimal text).")
    if len(key) < KEY_BYTES:
        raise ArgusError(f"Key file {key_path} is too short (need {KEY_BYTES} bytes).")
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    if mode & 0o077:
        print(f"WARNING: key file {key_path} is accessible to other users "
              f"(mode {mode:04o}). Run: chmod 600 {key_path}", file=sys.stderr)
    return key


# ---------------------------------------------------------------- scanning

# Return the SHA-256 hex digest of an open binary file, read in 64 KB chunks.
def hash_stream(f):
    sha = hashlib.sha256()
    while chunk := f.read(65536):
        sha.update(chunk)
    return sha.hexdigest()


# Hash and describe one regular file using a single open file, so hash and metadata agree.
def file_record(path):
    # O_NOFOLLOW refuses symlinks and O_NONBLOCK stops a swapped-in named pipe from hanging us
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise OSError("not a regular file")
        digest = hash_stream(f)
        after = os.fstat(f.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError("file changed while it was being read")
    return {
        "type": "file",
        "sha256": digest,
        "size": before.st_size,
        "mode": stat.S_IMODE(before.st_mode),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mtime": before.st_mtime,
    }


# Describe a file, symlink or directory. Returns None for sockets, pipes and devices.
def make_record(path):
    st = os.lstat(path)
    common = {
        "mode": stat.S_IMODE(st.st_mode),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mtime": st.st_mtime,
    }
    if stat.S_ISLNK(st.st_mode):
        return {"type": "symlink", "target": os.readlink(path), **common}
    if stat.S_ISDIR(st.st_mode):
        return {"type": "dir", **common}
    if stat.S_ISREG(st.st_mode):
        return file_record(path)
    return None


# Walk a directory tree and return (records, unreadable).
def scan(root, exclude=(), skip_paths=()):
    root = Path(root).resolve()
    skip = {str(Path(p).resolve()) for p in skip_paths}
    # unreadable maps each path we could not read to the reason, so callers can report it
    records, unreadable = {}, {}

    def on_walk_error(err):
        unreadable[str(err.filename)] = err.strerror or str(err)

    def add(path):
        if str(path) in skip:
            return
        try:
            record = make_record(path)
        except OSError as e:
            unreadable[str(path)] = e.strerror or str(e)
            return
        if record is not None:
            records[str(path)] = record

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_walk_error):
        dirnames[:] = sorted(d for d in dirnames if not is_excluded(d, exclude))
        dirpath = Path(dirpath)
        add(dirpath)
        links = [d for d in dirnames if (dirpath / d).is_symlink()]
        for name in sorted(filenames + links):
            if not is_excluded(name, exclude):
                add(dirpath / name)
    return records, unreadable


# ---------------------------------------------------------------- baseline file

# Serialise the payload the same way every time, so its signature is reproducible.
def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Return the HMAC-SHA256 of the whole payload.
def sign(payload, key):
    return hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()


# Sign the baseline and save it atomically; overwrite=False fails if it already exists.
def save_baseline(files, baseline_path, root, exclude, key, overwrite=True):
    payload = {
        "version": BASELINE_VERSION,
        "root": str(Path(root).resolve()),
        "exclude": list(exclude),
        "files": files,
    }
    document = {"hmac": sign(payload, key), "payload": payload}

    directory = os.path.dirname(os.path.abspath(baseline_path))
    # write to a temporary file first, then swap it in so a crash never leaves a half-written baseline
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".argus-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(document, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        if overwrite:
            os.replace(tmp, baseline_path)
        else:
            os.link(tmp, baseline_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# Load a baseline and verify its signature. Returns the payload.
def load_baseline(baseline_path, key):
    try:
        with open(baseline_path) as f:
            document = json.load(f)
    except FileNotFoundError:
        raise ArgusError(f"No baseline at {baseline_path}. Run 'init' first.")
    except ValueError:
        raise TamperError(f"{baseline_path} is not valid JSON; it is corrupted or was edited.")

    if isinstance(document, dict) and document.get("version") == 1:
        raise ArgusError("This baseline uses the old unsigned format. Delete it and run 'init' again.")
    if (not isinstance(document, dict) or set(document) != {"hmac", "payload"}
            or not isinstance(document["hmac"], str) or not isinstance(document["payload"], dict)):
        raise TamperError(f"{baseline_path} is not a valid signed baseline.")

    payload = document["payload"]
    expected = sign(payload, key)
    if not hmac.compare_digest(document["hmac"].encode("utf-8"), expected.encode("utf-8")):
        raise TamperError("Baseline authentication FAILED: the file was modified, or a "
                          "different key is being used. Do not trust this baseline.")

    if (payload.get("version") != BASELINE_VERSION
            or not isinstance(payload.get("root"), str)
            or not isinstance(payload.get("exclude"), list)
            or not isinstance(payload.get("files"), dict)):
        raise ArgusError("Baseline has an unexpected structure. Delete it and run 'init' again.")
    return payload


# ---------------------------------------------------------------- comparing

# Return a value that is equal for two entries exactly when their content is the same.
def content_id(record):
    if record["type"] == "file":
        return record["sha256"]
    if record["type"] == "symlink":
        return "symlink:" + record["target"]
    return "dir"


# Return readable descriptions of permission or ownership changes between two records.
def meta_diffs(old_record, new_record):
    return [
        f"{field}: {fmt(field, old_record[field])} -> {fmt(field, new_record[field])}"
        for field in META_FIELDS
        if old_record[field] != new_record[field]
    ]


# Compare old records with a new scan; returns (modified, added, deleted, renamed, meta).
def compare_baseline(old, new, unreadable=()):
    old_paths, new_paths = set(old), set(new)
    # paths we could not read are never reported as deleted
    deleted = sorted(p for p in old_paths - new_paths if not is_unreadable(p, unreadable))
    added = sorted(new_paths - old_paths)

    modified, meta = [], {}
    for p in sorted(old_paths & new_paths):
        if content_id(old[p]) != content_id(new[p]):
            modified.append(p)
        diffs = meta_diffs(old[p], new[p])
        if diffs:
            meta[p] = diffs

    # pair a rename only when exactly one deleted and one added path share the same content
    deleted_by_id = defaultdict(list)
    for p in deleted:
        if old[p]["type"] != "dir":
            deleted_by_id[content_id(old[p])].append(p)
    added_by_id = defaultdict(list)
    for p in added:
        if new[p]["type"] != "dir":
            added_by_id[content_id(new[p])].append(p)

    renamed = []
    for cid, old_list in deleted_by_id.items():
        new_list = added_by_id.get(cid, [])
        if len(old_list) == 1 and len(new_list) == 1:
            renamed.append((old_list[0], new_list[0]))
            diffs = meta_diffs(old[old_list[0]], new[new_list[0]])
            if diffs:
                meta[new_list[0]] = diffs

    moved_from = {o for o, _ in renamed}
    moved_to = {n for _, n in renamed}
    still_deleted = [p for p in deleted if p not in moved_from]
    still_added = [p for p in added if p not in moved_to]
    return modified, still_added, still_deleted, sorted(renamed), meta


# Print every difference. Returns True if anything changed.
def report_changes(modified, added, deleted, renamed, meta, unreadable):
    for p in modified:
        print(f"Modified: {safe(p)}")
    for p in added:
        print(f"Added: {safe(p)}")
    for p in deleted:
        print(f"Deleted: {safe(p)}")
    for old, new in renamed:
        print(f"Renamed: {safe(old)} -> {safe(new)}")
    for p, diffs in sorted(meta.items()):
        print(f"Metadata: {safe(p)}")
        for d in diffs:
            print(f"    {d}")
    for p, why in sorted(unreadable.items()):
        print(f"Unreadable: {safe(p)} ({why})")

    changed = bool(modified or added or deleted or renamed or meta)
    if changed:
        print(f"\nSummary: {len(modified)} modified, {len(added)} added, {len(deleted)} deleted, "
              f"{len(renamed)} renamed, {len(meta)} metadata, {len(unreadable)} unreadable.")
    return changed


# Ask a yes/no question; anything but yes (or a closed input) counts as no.
def confirm(question):
    try:
        answer = input(f"{question} [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in ("y", "yes")


# ---------------------------------------------------------------- commands

# Create a signed baseline for a directory.
def cmd_init(args):
    if Path(args.baseline).exists():
        print(f"Baseline {args.baseline} already exists. Use 'update' to replace it.")
        return 2
    if not Path(args.directory).is_dir():
        raise ArgusError(f"{args.directory} is not a directory.")

    if Path(args.key).exists():
        key = load_key(args.key)
        print(f"Using existing key {args.key}")
    else:
        key = create_key(args.key)
        print(f"Created key {args.key}. Keep a copy somewhere safe, away from this machine.")

    files, unreadable = scan(args.directory, args.exclude, [args.baseline, args.key])
    try:
        save_baseline(files, args.baseline, args.directory, args.exclude, key, overwrite=False)
    except FileExistsError:
        print(f"Baseline {args.baseline} already exists. Use 'update' to replace it.")
        return 2

    print(f"Baseline created: {len(files)} entries -> {args.baseline}")
    for p, why in sorted(unreadable.items()):
        print(f"WARNING: could not read {safe(p)} ({why}); it is NOT protected")
    return 2 if unreadable else 0


# Compare the directory against the baseline. Returns 0 clean, 1 changes, 2 problem.
def cmd_check(args):
    key = load_key(args.key)
    payload = load_baseline(args.baseline, key)
    root, exclude = payload["root"], payload["exclude"]

    print(f"Scanning {safe(root)}")
    if exclude:
        print("Exclusions: " + ", ".join(safe(p) for p in exclude))
    if not os.path.isdir(root):
        print(f"ALERT: monitored directory {safe(root)} is missing or is no longer a directory")
        return 1

    new_scan, unreadable = scan(root, exclude, [args.baseline, args.key])
    modified, added, deleted, renamed, meta = compare_baseline(payload["files"], new_scan, unreadable)
    if report_changes(modified, added, deleted, renamed, meta, unreadable):
        return 1
    if unreadable:
        print("No changes found, but some paths could not be verified.")
        return 2
    print("No changes detected.")
    return 0


# Show the differences and, once confirmed, save the current state as the new baseline.
def cmd_update(args):
    key = load_key(args.key)
    payload = load_baseline(args.baseline, key)
    root, exclude = payload["root"], payload["exclude"]
    if not os.path.isdir(root):
        raise ArgusError(f"Monitored directory {root} is missing; cannot update.")

    new_scan, unreadable = scan(root, exclude, [args.baseline, args.key])
    modified, added, deleted, renamed, meta = compare_baseline(payload["files"], new_scan, unreadable)
    if not report_changes(modified, added, deleted, renamed, meta, unreadable):
        print("No changes to accept.")
        return 2 if unreadable else 0

    if not args.yes and not confirm("Accept these changes as the new baseline?"):
        print("Aborted. Baseline unchanged.")
        return 1

    # keep the old record of anything we could not read, so it stays protected
    for p, record in payload["files"].items():
        if p not in new_scan and is_unreadable(p, unreadable):
            new_scan[p] = record

    save_baseline(new_scan, args.baseline, root, exclude, key)
    print(f"Baseline updated: {len(new_scan)} entries -> {args.baseline}")
    return 2 if unreadable else 0


# Define the commands, run the chosen one and turn every outcome into an exit code.
def main():
    parser = argparse.ArgumentParser(description="Argus: file integrity checker")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create a new signed baseline")
    p_init.add_argument("directory", help="directory to scan")
    p_init.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                        help="name pattern to ignore (repeatable)")
    p_init.set_defaults(func=cmd_init)

    p_check = sub.add_parser("check", help="compare against the baseline")
    p_check.set_defaults(func=cmd_check)

    p_update = sub.add_parser("update", help="review changes and accept them as the new baseline")
    p_update.add_argument("--yes", action="store_true", help="accept without asking")
    p_update.set_defaults(func=cmd_update)

    for p in (p_init, p_check, p_update):
        p.add_argument("--baseline", default="baseline.json", help="baseline file path")
        p.add_argument("--key", default="argus.key", help="HMAC key file path")

    args = parser.parse_args()
    try:
        return args.func(args)
    except TamperError as e:
        print(f"ALERT: {e}")
        return 1
    except ArgusError as e:
        print(f"Error: {e}")
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 2
    except Exception as e:
        print(f"Unexpected error ({type(e).__name__}): {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())