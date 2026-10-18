import hashlib, json, sys
from pathlib import Path

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

#scans the directory tree starting from the root path and returns a dictionary mapping file paths to their SHA256 hashes.
def scan(root):
    results = {}
    for p in sorted(Path(root).rglob("*")):
        if p.is_file() and not p.is_symlink():
            try:
                results[str(p)] = hash_file(p)
            except OSError as e:
                print(f"Error reading file {p}: {e}")
    return results

#saves the baseline data (a dictionary of file paths and their hashes) to a JSON file at the specified baseline path.
def save_baseline(data, baseline_path):
    with open(baseline_path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)

#loads the baseline data from a JSON file at the specified baseline path and returns it as a dictionary.
def load_baseline(baseline_path):
    with open(baseline_path, "r") as f:
        return json.load(f)

#compares the baseline data with a new scan and returns four lists: renamed files, modified files, added files, and deleted files.
def compare_baseline(baseline, new_scan):
    old_paths = set(baseline.keys());
    new_paths = set(new_scan);

    deleted = sorted(old_paths - new_paths)
    added = sorted(new_paths - old_paths)
    modified = sorted(p for p in old_paths & new_paths if baseline[p] != new_scan[p])

    old_by_hash = {baseline[p]: p for p in deleted}
    new_by_hash = {new_scan[p]: p for p in added}

    renamed_hashes = old_by_hash.keys() & new_by_hash.keys()
    renamed = sorted((old_by_hash[h], new_by_hash[h]) for h in renamed_hashes)

    added = sorted(p for p in added if new_scan[p] not in renamed_hashes)
    deleted = sorted(p for p in deleted if baseline[p] not in renamed_hashes)

    return modified, added, deleted, renamed

#main function
if __name__ == "__main__":
    baseline_path = load_baseline("baseline.json")
    new_scan = scan("test_folder")
    modified, added, deleted, renamed = compare_baseline(baseline_path, new_scan)

    for p in modified:
        print(f"Modified: {p}")

    for p in added:
        print(f"Added: {p}")

    for p in deleted:
        print(f"Deleted: {p}")

    for p in renamed:
        print(f"Renamed: {p}")

    if not (modified or added or deleted or renamed):
        print("No changes detected.")
        sys.exit(0)

    print(f"\nSummary: {len(modified)} modified, {len(added)} added, {len(deleted)} deleted, {len(renamed)} renamed.")
    sys.exit(1)