"""Persist automatic assessment snapshots and compare observed changes."""
from __future__ import annotations

import json
from pathlib import Path

from .core import connect


def ensure_runs_table(db):
    db.execute("CREATE TABLE IF NOT EXISTS assessment_runs (id INTEGER PRIMARY KEY, at TEXT NOT NULL, snapshot TEXT NOT NULL)")
    db.commit()


def save_run(root: Path, snapshot: dict) -> int:
    with connect(root) as db:
        ensure_runs_table(db)
        cursor = db.execute("INSERT INTO assessment_runs(at,snapshot) VALUES (?,?)",
                            (snapshot["at"], json.dumps(snapshot, sort_keys=True)))
        db.commit()
        return cursor.lastrowid


def list_runs(root: Path) -> list[dict]:
    with connect(root) as db:
        ensure_runs_table(db)
        return [dict(row) for row in db.execute("SELECT id,at FROM assessment_runs ORDER BY id DESC")]


def compare_runs(root: Path, before: int | None = None, after: int | None = None) -> dict:
    if (before is None) != (after is None):
        raise ValueError("Provide both run IDs, or omit both to compare the latest two")
    with connect(root) as db:
        ensure_runs_table(db)
        if before is None or after is None:
            latest = db.execute("SELECT id FROM assessment_runs ORDER BY id DESC LIMIT 2").fetchall()
            if len(latest) < 2:
                raise ValueError("At least two automatic assessments are required")
            after = latest[0][0]
            before = latest[1][0]
        rows = db.execute("SELECT id,at,snapshot FROM assessment_runs WHERE id IN (?,?)", (before, after)).fetchall()
    runs = {row["id"]: {"at": row["at"], "snapshot": json.loads(row["snapshot"])} for row in rows}
    if before == after or before not in runs or after not in runs:
        raise ValueError("Select two distinct existing run IDs")
    old = {row["target"]: row for row in runs[before]["snapshot"]["targets"]}
    new = {row["target"]: row for row in runs[after]["snapshot"]["targets"]}
    changes = []
    for target in sorted(old.keys() & new.keys()):
        first, second = old[target], new[target]
        if first.get("scan_ok") and second.get("scan_ok"):
            old_ports = {p["port"] for p in first["open_ports"]}
            new_ports = {p["port"] for p in second["open_ports"]}
            for port in sorted(new_ports - old_ports):
                changes.append({"target": target, "kind": "port_opened", "port": port})
            for port in sorted(old_ports - new_ports):
                changes.append({"target": target, "kind": "port_closed", "port": port})
        old_observations = first.get("observations", {})
        new_observations = second.get("observations", {})
        for key in sorted(old_observations.keys() & new_observations.keys()):
            if old_observations[key] != new_observations[key]:
                changes.append({"target": target, "kind": "observation_changed", "check": key,
                                "before": old_observations[key], "after": new_observations[key]})
    return {"before": before, "after": after, "before_at": runs[before]["at"],
            "after_at": runs[after]["at"], "changes": changes,
            "not_compared": sorted(old.keys() ^ new.keys())}
