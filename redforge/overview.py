"""Compact engagement status for operators and reports."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .core import connect, ensure_scope_expiry
from .review import ensure_review_table
from .compare import ensure_runs_table


def overview(root: Path) -> dict:
    with connect(root) as db:
        ensure_scope_expiry(db)
        ensure_review_table(db)
        ensure_runs_table(db)
        name = db.execute("SELECT value FROM settings WHERE key='name'").fetchone()[0]
        authorized = db.execute("SELECT value FROM settings WHERE key='authorized'").fetchone()[0] == "true"
        scopes = db.execute("SELECT s.cidr,e.expires_at FROM scope s LEFT JOIN scope_expiry e ON e.cidr=s.cidr").fetchall()
        active = sum(not row[1] or datetime.fromisoformat(row[1]) > datetime.now(timezone.utc) for row in scopes)
        reviews = {row[0]: row[1] for row in db.execute("""SELECT COALESCE(r.status,'unreviewed'),COUNT(*)
            FROM findings f LEFT JOIN finding_reviews r ON r.finding_id=f.id GROUP BY COALESCE(r.status,'unreviewed')""")}
        latest = db.execute("SELECT id,at FROM assessment_runs ORDER BY id DESC LIMIT 1").fetchone()
        alerts = db.execute("SELECT COUNT(*) FROM audit WHERE action='change_alert'").fetchone()[0]
        return {"engagement": name, "authorized": authorized,
                "scope_active": active, "scope_expired": len(scopes) - active,
                "findings": reviews, "latest_run": dict(latest) if latest else None,
                "runs": db.execute("SELECT COUNT(*) FROM assessment_runs").fetchone()[0],
                "runs_with_changes": alerts}
