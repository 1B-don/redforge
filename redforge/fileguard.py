"""Offline, bounded file integrity baselines for operator-selected folders."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from threading import Event

from .core import audit, connect, now, workspace

NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MAX_FILES = 10_000
MAX_FILE_SIZE = 1_000_000_000


def _manifest_path(root: Path, name: str) -> Path:
    if not NAME.fullmatch(name):
        raise ValueError("Baseline name must use 1–64 letters, numbers, hyphens, or underscores")
    return workspace(root) / "file-baselines" / f"{name}.json"


def _digest(path: Path, cancel: Event | None = None) -> str:
    before = path.stat()
    if before.st_size > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds 1 GB limit: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            if cancel is not None and cancel.is_set():
                raise InterruptedError("File integrity operation cancelled")
            digest.update(chunk)
    after = path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise ValueError(f"File changed while hashing: {path}")
    return digest.hexdigest()


def _files(directory: Path, excluded: Path, cancel: Event | None = None) -> dict[str, str]:
    if not directory.is_dir():
        raise ValueError(f"Folder does not exist: {directory}")
    hashes = {}
    for current, dirs, files in os.walk(directory, followlinks=False):
        if cancel is not None and cancel.is_set():
            raise InterruptedError("File integrity operation cancelled")
        dirs[:] = sorted(d for d in dirs if not (Path(current) / d).is_symlink())
        for name in sorted(files):
            path = Path(current) / name
            if path.is_symlink() or path == excluded:
                continue
            if not path.is_file():
                continue
            if len(hashes) >= MAX_FILES:
                raise ValueError("Folder exceeds 10,000 file limit")
            hashes[path.relative_to(directory).as_posix()] = _digest(path, cancel)
    return hashes


def create_baseline(root: Path, name: str, directory: Path, cancel: Event | None = None) -> Path:
    output = _manifest_path(root, name)
    directory = workspace(directory)
    with connect(root) as db:
        audit(db, "file_baseline_start", json.dumps({"name": name, "directory": str(directory)}))
    files = _files(directory, output, cancel)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({"format": "redforge-file-baseline-v1", "created_at": now(),
                                  "directory": str(directory), "files": files}, indent=2, sort_keys=True) + "\n")
    return output


def verify_baseline(root: Path, name: str, cancel: Event | None = None) -> dict:
    manifest_path = _manifest_path(root, name)
    if not manifest_path.is_file():
        raise ValueError(f"Baseline {name!r} does not exist")
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    if data.get("format") != "redforge-file-baseline-v1" or not isinstance(data.get("files"), dict):
        raise ValueError("Invalid file baseline")
    directory = workspace(Path(data["directory"]))
    actual = _files(directory, manifest_path, cancel)
    expected = data["files"]
    result = {"ok": actual == expected, "directory": str(directory),
              "matched": sorted(k for k in expected if actual.get(k) == expected[k]),
              "changed": sorted(k for k in expected if k in actual and actual[k] != expected[k]),
              "missing": sorted(set(expected) - set(actual)),
              "untracked": sorted(set(actual) - set(expected))}
    return result
