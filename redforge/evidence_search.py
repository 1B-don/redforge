"""Search recorded JSON evidence, including checks with no findings."""
from __future__ import annotations

import json
from pathlib import Path

from .core import connect, workspace


def search_evidence(root: Path, *, host: str | None = None, port: int | None = None,
                    check: str | None = None, severity: str | None = None,
                    since: str | None = None, until: str | None = None,
                    text: str | None = None, limit: int = 500) -> list[dict]:
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    if not 1 <= limit <= 2000:
        raise ValueError("Limit must be between 1 and 2000")
    folder = workspace(root) / "evidence"
    with connect(root) as db:
        severities = {}
        for row in db.execute("SELECT evidence,severity FROM findings WHERE evidence IS NOT NULL"):
            severities.setdefault(row["evidence"], set()).add(row["severity"])
    results = []
    if not folder.is_dir():
        return results
    for path in sorted(folder.iterdir(), reverse=True):
        if not path.is_file() or path.is_symlink() or path.suffix != ".json":
            continue
        relative = f"evidence/{path.name}"
        kind = path.name.split("-", 1)[0]
        if check and kind != check:
            continue
        if severity and severity not in severities.get(relative, set()):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if host and data.get("target") != host:
            continue
        open_ports = data.get("open_ports", [])
        if not isinstance(open_ports, list):
            open_ports = []
        if port is not None and data.get("port") != port and not any(
                isinstance(p, dict) and p.get("port") == port for p in open_ports):
            continue
        at = str(data.get("at", ""))
        if since and at < since or until and at > until:
            continue
        if text and text.casefold() not in json.dumps(data, ensure_ascii=False).casefold():
            continue
        results.append({"file": relative, "check": kind, "host": data.get("target"),
                        "port": data.get("port"), "at": at,
                        "severities": sorted(severities.get(relative, set()))})
        if len(results) >= limit:
            break
    return results
