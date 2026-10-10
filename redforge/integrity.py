"""Read-only evidence integrity manifest and verification."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
from .core import workspace


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _evidence_files(root: Path):
    folder = workspace(root) / 'evidence'
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir() if p.is_file() and not p.is_symlink() and p.suffix == '.json')


def create_manifest(root: Path) -> Path:
    root = workspace(root)
    if not (root / 'engagement.sqlite3').is_file():
        raise ValueError('Engagement not initialized')
    manifest = {'format': 'redforge-evidence-sha256-v1',
                'files': {p.name: _digest(p) for p in _evidence_files(root)}}
    output = root / 'evidence-manifest.json'
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return output


def verify_manifest(root: Path) -> dict:
    root = workspace(root)
    manifest_path = root / 'evidence-manifest.json'
    if not manifest_path.is_file():
        raise ValueError('No manifest; generate one first')
    data = json.loads(manifest_path.read_text(encoding='utf-8'))
    if data.get('format') != 'redforge-evidence-sha256-v1' or not isinstance(data.get('files'), dict):
        raise ValueError('Invalid evidence manifest')
    actual = {p.name: _digest(p) for p in _evidence_files(root)}
    expected = data['files']
    return {'ok': actual == expected,
            'matched': sorted(k for k in expected if actual.get(k) == expected[k]),
            'changed': sorted(k for k in expected if k in actual and actual[k] != expected[k]),
            'missing': sorted(set(expected) - set(actual)),
            'untracked': sorted(set(actual) - set(expected))}
