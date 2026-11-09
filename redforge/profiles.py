"""Saved target and port selections; scope is rechecked at execution time."""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from .core import connect, require_target, audit, now


def ensure_profiles_table(db):
    db.execute("""CREATE TABLE IF NOT EXISTS assessment_profiles (
        name TEXT PRIMARY KEY, targets TEXT NOT NULL, ports TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    db.commit()


def save_profile(root: Path, name: str, targets: list[str], ports: str) -> None:
    name = name.strip()
    if not name or len(name) > 80 or not targets or len(targets) > 16:
        raise ValueError("Provide a profile name (1–80 characters) and 1–16 IP targets")
    from .scanner import parse_ports
    parse_ports(ports)
    canonical = []
    with connect(root) as db:
        ensure_profiles_table(db)
        for target in targets:
            try:
                address = str(ipaddress.ip_address(target))
            except ValueError as exc:
                raise ValueError(f"Target must be a literal IP address: {target}") from exc
            require_target(db, address)
            if address not in canonical:
                canonical.append(address)
        db.execute("INSERT INTO assessment_profiles VALUES (?,?,?,?) ON CONFLICT(name) DO UPDATE SET targets=excluded.targets, ports=excluded.ports, updated_at=excluded.updated_at",
                   (name, json.dumps(canonical), ports, now()))
        audit(db, "profile_save", name)


def list_profiles(root: Path) -> list[dict]:
    with connect(root) as db:
        ensure_profiles_table(db)
        return [{"name": row["name"], "targets": json.loads(row["targets"]),
                 "ports": row["ports"], "updated_at": row["updated_at"]}
                for row in db.execute("SELECT * FROM assessment_profiles ORDER BY name")]


def run_profile(root: Path, name: str, cancel=None) -> dict:
    with connect(root) as db:
        ensure_profiles_table(db)
        row = db.execute("SELECT targets,ports FROM assessment_profiles WHERE name=?", (name,)).fetchone()
    if row is None:
        raise ValueError(f"Profile {name!r} does not exist")
    from .auto import assess
    return assess(root, json.loads(row["targets"]), row["ports"], cancel=cancel)
