"""Offline HTML/JSON engagement reporting with escaped content."""
from __future__ import annotations
import html
import json
from pathlib import Path
from .core import connect, workspace, now, ensure_scope_expiry
from .review import ensure_review_table
from .overview import overview


def report(root: Path, output: Path, format: str = "html") -> Path:
    with connect(root) as db:
        ensure_review_table(db)
        ensure_scope_expiry(db)
        name = db.execute("SELECT value FROM settings WHERE key='name'").fetchone()[0]
        scope = [dict(r) for r in db.execute("SELECT s.*,e.expires_at FROM scope s LEFT JOIN scope_expiry e ON e.cidr=s.cidr ORDER BY s.cidr")]
        findings = [dict(r) for r in db.execute("""SELECT f.*,
            COALESCE(r.status,'unreviewed') AS review_status,
            COALESCE(r.note,'') AS review_note, r.updated_at AS reviewed_at
            FROM findings f LEFT JOIN finding_reviews r ON r.finding_id=f.id ORDER BY f.id""")]
        audits = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id")]
    summary = overview(root)
    baseline_dir = workspace(root) / 'file-baselines'
    baselines = sorted(p.stem for p in baseline_dir.glob('*.json') if p.is_file() and not p.is_symlink()) if baseline_dir.is_dir() else []
    payload = {"generated_at": now(), "engagement": name, "summary": summary,
               "scope": scope, "findings": findings, "audit": audits,
               "file_baselines": baselines}
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if format == "json":
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif format == "html":
        e = lambda x: html.escape(str(x), quote=True)
        rows = "".join(f"<tr><td>{e(f['host'])}</td><td>{e(f['severity'])}</td><td>{e(f['title'])}</td><td>{e(f['detail'])}</td><td>{e(f['review_status'])}</td><td>{e(f['review_note'])}</td><td>{e(f['evidence'] or '')}</td></tr>" for f in findings)
        scopes = ", ".join(e(s["cidr"] + (f" (expires {s['expires_at']})" if s["expires_at"] else "")) for s in scope) or "None"
        output.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RedForge Report</title><style>body{{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem;line-height:1.5}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #bbb;padding:.6rem;text-align:left;vertical-align:top}}th{{background:#eee}}td{{overflow-wrap:anywhere}}</style><h1>RedForge — {e(name)}</h1><p>Generated {e(payload['generated_at'])}</p><p><strong>Authorized scope:</strong> {scopes}</p><p><strong>Scope:</strong> {summary['scope_active']} active, {summary['scope_expired']} expired. <strong>Assessment runs:</strong> {summary['runs']}. <strong>Review status:</strong> {e(summary['findings'])}. <strong>File baselines:</strong> {len(baselines)}.</p><p>Observations are not proof of exploitable vulnerabilities; validate findings before remediation.</p><h2>Findings ({len(findings)})</h2><table><thead><tr><th>Host</th><th>Severity</th><th>Finding</th><th>Details</th><th>Review</th><th>Analyst note</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></html>''', encoding="utf-8")
    else:
        raise ValueError("Format must be html or json")
    return output
