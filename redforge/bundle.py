"""Portable engagement report and evidence archive."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import tempfile
import zipfile
from pathlib import Path

from .core import db_path, workspace
from .report import report


def export_bundle(root: Path, output: Path) -> Path:
    root = workspace(root)
    if not db_path(root).is_file():
        raise ValueError("Engagement not initialized")
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp:
        stage = Path(temp)
        report(root, stage / "report.html")
        report(root, stage / "report.json", "json")
        with sqlite3.connect(db_path(root)) as source, sqlite3.connect(stage / "engagement.sqlite3") as dest:
            source.backup(dest)
        evidence = root / "evidence"
        if evidence.is_dir():
            for path in evidence.iterdir():
                if path.is_file() and not path.is_symlink() and path.suffix == ".json":
                    target = stage / "evidence" / path.name
                    target.parent.mkdir(exist_ok=True)
                    target.write_bytes(path.read_bytes())
        baselines = root / "file-baselines"
        if baselines.is_dir():
            for path in baselines.iterdir():
                if path.is_file() and not path.is_symlink() and path.suffix == ".json":
                    target = stage / "file-baselines" / path.name
                    target.parent.mkdir(exist_ok=True)
                    target.write_bytes(path.read_bytes())
        files = sorted(p for p in stage.rglob("*") if p.is_file())
        manifest = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        (stage / "SHA256.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(p for p in stage.rglob("*") if p.is_file()):
                archive.write(path, path.relative_to(stage))
    return output


def verify_bundle(path: Path) -> dict:
    """Verify an exported archive without extracting or trusting member paths."""
    path = path.expanduser().resolve()
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or len(names) > 10000:
            raise ValueError("Bundle has duplicate or excessive entries")
        if any(entry.is_dir() or entry.filename.startswith("/") or ".." in Path(entry.filename).parts
               or "\\" in entry.filename for entry in entries):
            raise ValueError("Bundle contains an unsafe member path")
        if sum(entry.file_size for entry in entries) > 1_000_000_000:
            raise ValueError("Bundle is too large to verify")
        if "SHA256.json" not in names:
            raise ValueError("Bundle is missing SHA256.json")
        if archive.getinfo("SHA256.json").file_size > 5_000_000:
            raise ValueError("Bundle manifest is too large")
        try:
            manifest = json.loads(archive.read("SHA256.json"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid bundle manifest") from exc
        if not isinstance(manifest, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                                 or not re.fullmatch(r"[0-9a-f]{64}", v)
                                                 for k, v in manifest.items()):
            raise ValueError("Invalid bundle manifest")
        if not {"report.html", "report.json", "engagement.sqlite3"} <= set(names):
            raise ValueError("Bundle is missing required report or database files")
        actual_names = set(names) - {"SHA256.json"}
        if set(manifest) != actual_names:
            return {"ok": False, "missing": sorted(set(manifest) - actual_names),
                    "untracked": sorted(actual_names - set(manifest)), "changed": []}
        changed = []
        for name in sorted(actual_names):
            digest = hashlib.sha256()
            with archive.open(name) as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != manifest[name]:
                changed.append(name)
        return {"ok": not changed, "missing": [], "untracked": [], "changed": changed}
