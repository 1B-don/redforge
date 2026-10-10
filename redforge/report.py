"""Offline HTML/JSON engagement reporting with escaped content."""
from __future__ import annotations
import html
import json
from pathlib import Path
from .core import connect, workspace, now


def report(root: Path, output: Path, format: str = "html") -> Path:
    with connect(root) as db:
        name = db.execute("SELECT value FROM settings WHERE key='name'").fetchone()[0]
        scope = [dict(r) for r in db.execute("SELECT * FROM scope ORDER BY cidr")]
        findings = [dict(r) for r in db.execute("SELECT * FROM findings ORDER BY id")]
        audits = [dict(r) for r in db.execute("SELECT * FROM audit ORDER BY id")]
    payload = {"generated_at": now(), "engagement": name, "scope": scope, "findings": findings, "audit": audits}
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if format == "json":
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    elif format == "html":
        e = lambda x: html.escape(str(x), quote=True)
        rows = "".join(f"<tr><td>{e(f['host'])}</td><td>{e(f['severity'])}</td><td>{e(f['title'])}</td><td>{e(f['detail'])}</td><td>{e(f['evidence'] or '')}</td></tr>" for f in findings)
        scopes = ", ".join(e(s["cidr"]) for s in scope) or "None"
        output.write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>RedForge Report</title><style>body{{font:16px system-ui;max-width:1100px;margin:3rem auto;padding:0 1rem;line-height:1.5}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #bbb;padding:.6rem;text-align:left;vertical-align:top}}th{{background:#eee}}td{{overflow-wrap:anywhere}}</style><h1>RedForge — {e(name)}</h1><p>Generated {e(payload['generated_at'])}</p><p><strong>Authorized scope:</strong> {scopes}</p><p>Observations are not proof of exploitable vulnerabilities; validate findings before remediation.</p><h2>Findings ({len(findings)})</h2><table><thead><tr><th>Host</th><th>Severity</th><th>Finding</th><th>Details</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></html>''', encoding="utf-8")
    else:
        raise ValueError("Format must be html or json")
    return output
