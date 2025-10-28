"""Command-line File Integrity Monitor (Sentinel FIM).

This module provides the ``sentinel_fim`` command which is capable of
initialising a baseline of file hashes, scanning for changes, and watching a
directory for modifications.  Only the Python standard library is used.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


BASELINE_FILENAME = ".sentinel_fim.json"
IGNORE_FILENAME = ".sentinelignore"
HASH_CHUNK_SIZE = 64 * 1024


@dataclass
class BaselineMeta:
    """Metadata collected while building a baseline."""

    total_bytes: int
    skipped: List[Dict[str, str]]


def load_ignore_file(root: Path) -> List[str]:
    """Return ignore patterns read from ``.sentinelignore`` if present."""

    ignore_path = root / IGNORE_FILENAME
    if not ignore_path.exists():
        return []
    patterns: List[str] = []
    try:
        for line in ignore_path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            patterns.append(stripped)
    except OSError as exc:  # pragma: no cover - unlikely during tests
        print(f"warning: unable to read {IGNORE_FILENAME}: {exc}", file=sys.stderr)
    return patterns


def walk_files(root: Path, ignore: List[str]) -> List[Path]:
    """Return a sorted list of regular files under *root* obeying ignore rules."""

    root = root.resolve()
    patterns = list(ignore)
    patterns.extend([BASELINE_FILENAME, IGNORE_FILENAME])
    collected: List[Tuple[str, Path]] = []

    for current_root, dirnames, filenames in os.walk(root):
        current_path = Path(current_root)

        # Remove ignored directories in-place for os.walk
        for dirname in list(dirnames):
            if dirname.startswith("."):
                dirnames.remove(dirname)
                continue
            rel_dir = (current_path / dirname).relative_to(root).as_posix()
            if _matches_ignore(rel_dir, patterns):
                dirnames.remove(dirname)
                continue

        for filename in filenames:
            rel_path = (current_path / filename).relative_to(root).as_posix()
            if _matches_ignore(rel_path, patterns):
                continue
            file_path = current_path / filename
            if file_path.is_symlink():
                continue
            if not file_path.is_file():
                continue
            collected.append((rel_path, file_path))

    collected.sort(key=lambda item: item[0])
    return [path for _, path in collected]


def _matches_ignore(path: str, patterns: Iterable[str]) -> bool:
    """Return True if *path* matches any ignore pattern."""

    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


def compute_sha256(path: Path) -> str:
    """Return the SHA-256 hex digest for *path* using streaming reads."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def build_baseline(root: Path, ignore: List[str]) -> Dict[str, Dict[str, int | str]]:
    """Return a mapping of relative file paths to their metadata."""

    files: Dict[str, Dict[str, int | str]] = {}
    skipped: List[Dict[str, str]] = []
    total_bytes = 0

    for file_path in walk_files(root, ignore):
        rel_path = file_path.relative_to(root).as_posix()
        try:
            stat_result = file_path.stat()
            sha256 = compute_sha256(file_path)
        except OSError as exc:
            skipped.append({"path": rel_path, "reason": str(exc)})
            continue
        files[rel_path] = {
            "size": stat_result.st_size,
            "mtime_ns": stat_result.st_mtime_ns,
            "sha256": sha256,
        }
        total_bytes += stat_result.st_size

    build_baseline.meta = BaselineMeta(total_bytes=total_bytes, skipped=skipped)  # type: ignore[attr-defined]
    return files


def diff_states(
    old: Dict[str, Dict[str, int | str]],
    new: Dict[str, Dict[str, int | str]],
) -> Tuple[Dict[str, Dict[str, int | str]], Dict[str, Dict[str, Dict[str, int | str]]], Dict[str, Dict[str, int | str]]]:
    """Return dictionaries describing added, modified, and deleted files."""

    added: Dict[str, Dict[str, int | str]] = {}
    deleted: Dict[str, Dict[str, int | str]] = {}
    modified: Dict[str, Dict[str, Dict[str, int | str]]] = {}

    for path in sorted(new.keys() - old.keys()):
        added[path] = new[path]
    for path in sorted(old.keys() - new.keys()):
        deleted[path] = old[path]
    for path in sorted(new.keys() & old.keys()):
        if new[path] != old[path]:
            modified[path] = {"old": old[path], "new": new[path]}

    return added, modified, deleted


def save_json(path: Path, data: Dict) -> None:
    """Serialize *data* as JSON to *path* with UTF-8 encoding."""

    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> Dict:
    """Load JSON data from *path* and return it."""

    return json.loads(path.read_text(encoding="utf-8"))


def _ensure_directory(path: Path) -> Path:
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f"path does not exist or is not a directory: {path}")
    return path.resolve()


def _build_report_structure(
    root: Path,
    added: Dict[str, Dict[str, int | str]],
    modified: Dict[str, Dict[str, Dict[str, int | str]]],
    deleted: Dict[str, Dict[str, int | str]],
    skipped: List[Dict[str, str]],
) -> Dict:
    timestamp = datetime.now(timezone.utc).isoformat()

    def _metadata(data: Dict[str, int | str]) -> Dict[str, int | str]:
        return {
            "size": data.get("size", 0),
            "mtime_ns": data.get("mtime_ns", 0),
            "sha256": data.get("sha256", ""),
        }

    return {
        "root": str(root),
        "timestamp": timestamp,
        "added": [
            {"path": path, **_metadata(data)}
            for path, data in added.items()
        ],
        "modified": [
            {
                "path": path,
                "old": _metadata(data["old"]),
                "new": _metadata(data["new"]),
            }
            for path, data in modified.items()
        ],
        "deleted": [
            {"path": path, "old": _metadata(data)}
            for path, data in deleted.items()
        ],
        "skipped": skipped,
    }


def _print_diff(
    added: Dict[str, Dict[str, int | str]],
    modified: Dict[str, Dict[str, Dict[str, int | str]]],
    deleted: Dict[str, Dict[str, int | str]],
    skipped: List[Dict[str, str]],
) -> None:
    def section(title: str, symbol: str, entries: Iterable[Tuple[str, str]]) -> None:
        entries = list(entries)
        print(f"{title} ({len(entries)})")
        for path, description in entries:
            print(f"  {symbol} {path}{description}")

    section("ADDED", "+", ((path, "") for path in added))
    section("MODIFIED", "~", ((path, "") for path in modified))
    section("DELETED", "-", ((path, "") for path in deleted))
    section(
        "SKIPPED",
        "!",
        ((entry["path"], f"  ({entry['reason']})") for entry in skipped),
    )


def _load_baseline(root: Path) -> Dict:
    baseline_path = root / BASELINE_FILENAME
    if not baseline_path.exists():
        raise FileNotFoundError(f"baseline file not found at {baseline_path}")
    return load_json(baseline_path)


def _perform_scan(
    root: Path, ignore: List[str]
) -> Tuple[
    Dict[str, Dict[str, int | str]],
    Dict[str, Dict[str, Dict[str, int | str]]],
    Dict[str, Dict[str, int | str]],
    List[Dict[str, str]],
]:
    baseline_data = _load_baseline(root)
    old_state = baseline_data.get("files", {})
    new_state = build_baseline(root, ignore)
    meta: BaselineMeta = getattr(build_baseline, "meta", BaselineMeta(0, []))
    added, modified, deleted = diff_states(old_state, new_state)
    return added, modified, deleted, meta.skipped


def cmd_init(path: Path) -> int:
    root = _ensure_directory(path)
    ignore_patterns = load_ignore_file(root)
    state = build_baseline(root, ignore_patterns)
    meta: BaselineMeta = getattr(build_baseline, "meta", BaselineMeta(0, []))

    baseline = {
        "version": 1,
        "root": str(root),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "files": state,
        "skipped": meta.skipped,
    }
    save_json(root / BASELINE_FILENAME, baseline)

    message = f"Indexed {len(state)} files ({meta.total_bytes} bytes)."
    if meta.skipped:
        message += f" Skipped {len(meta.skipped)} files."
    print(message)
    return 0


def cmd_scan(path: Path, report: Path | None) -> int:
    root = _ensure_directory(path)
    ignore_patterns = load_ignore_file(root)
    try:
        added, modified, deleted, skipped = _perform_scan(root, ignore_patterns)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    _print_diff(added, modified, deleted, skipped)

    if report is not None:
        report_data = _build_report_structure(root, added, modified, deleted, skipped)
        save_json(report, report_data)

    if added or modified or deleted:
        return 2
    return 0


def cmd_watch(path: Path, interval: float) -> int:
    root = _ensure_directory(path)
    ignore_patterns = load_ignore_file(root)
    try:
        _load_baseline(root)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    try:
        while True:
            added, modified, deleted, skipped = _perform_scan(root, ignore_patterns)
            if added or modified or deleted or skipped:
                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
                print(f"[{timestamp}] Changes detected:")
                _print_diff(added, modified, deleted, skipped)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Exiting watch mode.")
        return 0


def parse_arguments(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sentinel File Integrity Monitor")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="create or refresh a baseline")
    init_parser.add_argument("path", type=Path)

    scan_parser = subparsers.add_parser("scan", help="scan for filesystem changes")
    scan_parser.add_argument("path", type=Path)
    scan_parser.add_argument("--report", type=Path, help="write JSON report to file")

    watch_parser = subparsers.add_parser("watch", help="watch for filesystem changes")
    watch_parser.add_argument("path", type=Path)
    watch_parser.add_argument(
        "--interval",
        type=float,
        default=10.0,
        help="scan interval in seconds (default: 10)",
    )

    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_arguments(argv or sys.argv[1:])
    if args.command == "init":
        return cmd_init(args.path)
    if args.command == "scan":
        return cmd_scan(args.path, args.report)
    if args.command == "watch":
        return cmd_watch(args.path, args.interval)
    raise AssertionError("unreachable")


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
