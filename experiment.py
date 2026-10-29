import hashlib, json, sys, fnmatch, os
from pathlib import Path
from collections import defaultdict

#computes the SHA256 hash of a file at the given path.
def hash_file(path):
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

#checks if a given file or directory name matches any of the provided exclusion patterns.
def is_excluded(name, patterns):
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)

#scans the directory tree starting from the given root path, computes the SHA256 hash for each file, and returns a dictionary mapping file paths to their hashes. It can exclude files or directories based on specified patterns and skip certain paths.
def scan(root, exclude=(), skip_paths=()):
    root = Path(root).resolve()
    skip = {str(Path(p).resolve()) for p in skip_paths}
    results = {}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not is_excluded(d, exclude))
        for name in sorted(filenames):
            if is_excluded(name, exclude):
                continue
            p = Path(dirpath) / name
            if str(p) in skip or p.is_symlink() or not p.is_file():
                continue
            try:
                results[str(p)] = hash_file(p)
            except OSError as e:
                print(f"skipped {p}: {e}")
    return results

#saves the baseline data (a dictionary of file paths and their hashes) to a JSON file at the specified baseline path.
def save_baseline(data, baseline_path):
    with open(baseline_path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)

#loads the baseline data from a JSON file at the specified baseline path and returns it as a dictionary.
def load_baseline(baseline_path):
    with open(baseline_path, "r") as f:
        return json.load(f)

#compares the baseline data with a new scan and returns four lists: modified, added, deleted, and renamed.
#renamed is a list of (old_path, new_path) pairs, matched by identical file hash.
def compare_baseline(baseline, new_scan):
    old_paths, new_paths = set(baseline), set(new_scan)

    deleted = sorted(old_paths - new_paths)
    added = sorted(new_paths - old_paths)
    modified = sorted(p for p in old_paths & new_paths if baseline[p] != new_scan[p])

    #hash -> list of deleted paths with that content
    old_by_hash = defaultdict(list)
    for p in deleted:
        old_by_hash[baseline[p]].append(p)

    renamed, still_added = [], []
    for p in added:
        candidates = old_by_hash[new_scan[p]]
        if candidates:
            renamed.append((candidates.pop(0), p))
        else:
            still_added.append(p)

    #deleted files that never found a matching added file
    still_deleted = sorted(p for paths in old_by_hash.values() for p in paths)

    return modified, still_added, still_deleted, renamed

#main function
if __name__ == "__main__":
    baseline = load_baseline("baseline.json")
    new_scan = scan("test_folder")
    modified, added, deleted, renamed = compare_baseline(baseline, new_scan)

    for p in modified:
        print(f"Modified: {p}")

    for p in added:
        print(f"Added: {p}")

    for p in deleted:
        print(f"Deleted: {p}")

    for old, new in renamed:
        print(f"Renamed: {old} -> {new}")

    if not (modified or added or deleted or renamed):
        print("No changes detected.")
        sys.exit(0)

    print(f"\nSummary: {len(modified)} modified, {len(added)} added, {len(deleted)} deleted, {len(renamed)} renamed.")
    sys.exit(1)