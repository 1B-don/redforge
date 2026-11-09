"""Analyst disposition and searchable engagement observations."""
from __future__ import annotations

from pathlib import Path
from .core import connect, audit, now

STATUSES = {"unreviewed", "confirmed", "false_positive", "resolved"}


def ensure_review_table(db):
    db.execute("""CREATE TABLE IF NOT EXISTS finding_reviews (
        finding_id INTEGER PRIMARY KEY REFERENCES findings(id),
        status TEXT NOT NULL, note TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    db.commit()


def set_review(root: Path, finding_id: int, status: str, note: str = "") -> None:
    if status not in STATUSES:
        raise ValueError("Status must be unreviewed, confirmed, false_positive, or resolved")
    if len(note) > 2000:
        raise ValueError("Review note must be 2000 characters or fewer")
    with connect(root) as db:
        ensure_review_table(db)
        if db.execute("SELECT 1 FROM findings WHERE id=?", (finding_id,)).fetchone() is None:
            raise ValueError(f"Finding {finding_id} does not exist")
        db.execute("""INSERT INTO finding_reviews VALUES (?,?,?,?)
            ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status,
            note=excluded.note, updated_at=excluded.updated_at""",
            (finding_id, status, note, now()))
        audit(db, "finding_review", f"{finding_id}: {status}")


def search_findings(root: Path, *, host: str | None = None, severity: str | None = None,
                    status: str | None = None, text: str | None = None,
                    since: str | None = None, until: str | None = None,
                    port: int | None = None, limit: int = 500) -> list[dict]:
    if status is not None and status not in STATUSES:
        raise ValueError("Invalid review status")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    if not 1 <= limit <= 2000:
        raise ValueError("Limit must be between 1 and 2000")
    clauses, params = [], []
    for expression, value in (("f.host = ?", host), ("f.severity = ?", severity),
                              ("COALESCE(r.status,'unreviewed') = ?", status),
                              ("f.at >= ?", since), ("f.at <= ?", until)):
        if value is not None:
            clauses.append(expression)
            params.append(value)
    if text:
        clauses.append("(f.title LIKE ? OR f.detail LIKE ? OR COALESCE(r.note,'') LIKE ?)")
        params.extend([f"%{text}%"] * 3)
    if port is not None:
        clauses.append("f.title = ?")
        # Port search is intentionally exact for TCP finding titles. Other check
        # evidence remains discoverable through text/host filters.
        params.append(f"TCP port {port} open")
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connect(root) as db:
        ensure_review_table(db)
        rows = db.execute("""SELECT f.*, COALESCE(r.status,'unreviewed') AS review_status,
            COALESCE(r.note,'') AS review_note, r.updated_at AS reviewed_at
            FROM findings f LEFT JOIN finding_reviews r ON r.finding_id=f.id""" + where +
            " ORDER BY f.id DESC LIMIT ?", (*params, limit)).fetchall()
        return [dict(row) for row in rows]
