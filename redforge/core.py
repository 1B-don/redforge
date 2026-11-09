"""Engagement storage, scope validation, and audit logging."""
from __future__ import annotations
import ipaddress
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def workspace(path: Path) -> Path:
    return path.expanduser().resolve()


def db_path(root: Path) -> Path:
    return workspace(root) / "engagement.sqlite3"


def initialize(root: Path, name: str) -> None:
    root = workspace(root)
    root.mkdir(parents=True, exist_ok=True)
    (root / "evidence").mkdir(exist_ok=True)
    with sqlite3.connect(db_path(root)) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scope (cidr TEXT PRIMARY KEY, justification TEXT NOT NULL, added_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS scope_expiry (cidr TEXT PRIMARY KEY, expires_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at TEXT NOT NULL, action TEXT NOT NULL, details TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY, at TEXT NOT NULL, host TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, detail TEXT NOT NULL, evidence TEXT);
        """)
        db.execute("INSERT OR IGNORE INTO settings VALUES ('name', ?)", (name,))
        db.execute("INSERT OR IGNORE INTO settings VALUES ('authorized', 'false')")
        db.commit()


def connect(root: Path) -> sqlite3.Connection:
    path = db_path(root)
    if not path.is_file():
        raise ValueError(f"No engagement at {workspace(root)}. Run 'redforge init' first.")
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    return db


def audit(db: sqlite3.Connection, action: str, details: str) -> None:
    db.execute("INSERT INTO audit(at,action,details) VALUES (?,?,?)", (now(), action, details))
    db.commit()


def authorize(db: sqlite3.Connection, confirmed: bool) -> None:
    db.execute("UPDATE settings SET value=? WHERE key='authorized'", ("true" if confirmed else "false",))
    audit(db, "authorization", str(confirmed))


def require_authorized(db: sqlite3.Connection) -> None:
    row = db.execute("SELECT value FROM settings WHERE key='authorized'").fetchone()
    if not row or row[0] != "true":
        raise ValueError("Authorization not confirmed. Run 'redforge authorize' after obtaining permission.")


def ensure_scope_expiry(db: sqlite3.Connection) -> None:
    db.execute("CREATE TABLE IF NOT EXISTS scope_expiry (cidr TEXT PRIMARY KEY, expires_at TEXT NOT NULL)")


def add_scope(db: sqlite3.Connection, cidr: str, justification: str, expires_at: str | None = None) -> str:
    network = ipaddress.ip_network(cidr, strict=False)
    canonical = str(network)
    if not justification.strip():
        raise ValueError("Scope requires an authorization reference")
    expiry = None
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Expiry must be an ISO 8601 date/time with timezone") from exc
        if expiry.tzinfo is None:
            raise ValueError("Expiry must include a timezone")
        expiry = expiry.astimezone(timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise ValueError("Scope expiry must be in the future")
    ensure_scope_expiry(db)
    db.execute("INSERT OR REPLACE INTO scope VALUES (?,?,?)", (canonical, justification, now()))
    if expiry:
        db.execute("INSERT INTO scope_expiry VALUES (?,?) ON CONFLICT(cidr) DO UPDATE SET expires_at=excluded.expires_at",
                   (canonical, expiry.isoformat()))
    else:
        db.execute("DELETE FROM scope_expiry WHERE cidr=?", (canonical,))
    audit(db, "scope_add", canonical)
    return canonical


def remove_scope(db: sqlite3.Connection, cidr: str) -> None:
    canonical = str(ipaddress.ip_network(cidr, strict=False))
    if db.execute("DELETE FROM scope WHERE cidr=?", (canonical,)).rowcount == 0:
        raise ValueError(f"Scope {canonical} does not exist")
    ensure_scope_expiry(db)
    db.execute("DELETE FROM scope_expiry WHERE cidr=?", (canonical,))
    audit(db, "scope_remove", canonical)


def allowed(db: sqlite3.Connection, address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False  # Hostnames deliberately unsupported in active checks in v0.1
    ensure_scope_expiry(db)
    for row in db.execute("SELECT s.cidr,e.expires_at FROM scope s LEFT JOIN scope_expiry e ON e.cidr=s.cidr"):
        if row[1] and datetime.fromisoformat(row[1]) <= datetime.now(timezone.utc):
            continue
        if ip in ipaddress.ip_network(row[0]):
            return True
    return False


def require_target(db: sqlite3.Connection, address: str) -> str:
    require_authorized(db)
    try:
        ip = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("Targets must be literal IPv4/IPv6 addresses in v0.1; DNS names are not accepted.") from exc
    if not allowed(db, str(ip)):
        raise ValueError(f"Target {ip} is outside the configured engagement scope.")
    return str(ip)


def add_finding(db: sqlite3.Connection, host: str, title: str, severity: str, detail: str, evidence: str | None = None) -> None:
    db.execute("INSERT INTO findings(at,host,title,severity,detail,evidence) VALUES (?,?,?,?,?,?)", (now(), host, title, severity, detail, evidence))
    db.commit()


def evidence_file(root: Path, stem: str, content: str) -> str:
    from uuid import uuid4
    filename = f"{stem}-{uuid4().hex[:12]}.json"
    dest = workspace(root) / "evidence" / filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return str(dest.relative_to(workspace(root)))
