"""RedForge command line interface."""
from __future__ import annotations
from pathlib import Path
import zipfile
import typer
from rich.console import Console
from rich.table import Table
from .core import initialize, connect, add_scope, remove_scope, ensure_scope_expiry, authorize as record_authorization, allowed
from .scanner import scan
from .webcheck import check
from .report import report
from .auto import assess
from .bundle import export_bundle, verify_bundle
from .compare import list_runs, compare_runs
from .review import set_review, search_findings
from .profiles import save_profile, list_profiles, run_profile
from .evidence_search import search_evidence
from .overview import overview

app = typer.Typer(help="RedForge: scope-controlled security assessment workbench", no_args_is_help=False)
scope_app = typer.Typer(help="Manage explicitly approved IP/CIDR scope")
app.add_typer(scope_app, name="scope")
console = Console()
DEFAULT = Path("./redforge-engagement")


def fail(exc: Exception):
    console.print(f"[red]Error:[/red] {exc}")
    raise typer.Exit(code=1)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Open the classic terminal menu when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        from .tui import launch
        launch(DEFAULT)


@app.command("gui")
def gui(root: Path = typer.Option(DEFAULT, help="Engagement directory")):
    """Launch the interactive terminal dashboard (arrow keys, Tab, Enter, Esc)."""
    from .tui import launch
    launch(root)


@app.command()
def init(name: str = typer.Option("Local Assessment", help="Engagement name"), root: Path = typer.Option(DEFAULT, help="Engagement directory")):
    """Create an engagement and local evidence database."""
    try:
        initialize(root, name)
        console.print(f"[green]Initialized[/green] {root.resolve()}")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command()
def authorize(root: Path = typer.Option(DEFAULT), confirm: bool = typer.Option(False, "--confirm", help="Confirm you have written permission for all configured targets")):
    """Record operator confirmation of permission (not an external authorization check)."""
    if not confirm:
        console.print("Use --confirm only after you have obtained permission for this engagement.")
        raise typer.Exit(code=2)
    try:
        with connect(root) as db:
            record_authorization(db, True)
        console.print("[green]Operator authorization acknowledgement recorded.[/green]")
    except (ValueError, OSError) as exc:
        fail(exc)


@scope_app.command("add")
def scope_add(cidr: str, reason: str = typer.Option(..., "--reason", help="Scope authorization reference"),
              expires_at: str | None = typer.Option(None, help="Optional ISO 8601 expiry with timezone"),
              root: Path = typer.Option(DEFAULT)):
    """Add a literal IP address or CIDR network to scope."""
    try:
        with connect(root) as db:
            canonical = add_scope(db, cidr, reason, expires_at)
        console.print(f"[green]Added scope:[/green] {canonical}")
    except (ValueError, OSError) as exc:
        fail(exc)


@scope_app.command("show")
def scope_show(root: Path = typer.Option(DEFAULT)):
    """List approved ranges and authorization references."""
    try:
        with connect(root) as db:
            ensure_scope_expiry(db)
            rows = db.execute("SELECT s.cidr,s.justification,e.expires_at FROM scope s LEFT JOIN scope_expiry e ON e.cidr=s.cidr ORDER BY s.cidr").fetchall()
        table = Table("CIDR", "Authorization reference", "Expires (UTC)")
        for r in rows:
            table.add_row(r[0], r[1], r[2] or "No expiry recorded")
        console.print(table)
    except (ValueError, OSError) as exc:
        fail(exc)


@scope_app.command("remove")
def scope_remove(cidr: str, root: Path = typer.Option(DEFAULT)):
    """Revoke a configured IP or CIDR from assessment scope."""
    try:
        with connect(root) as db:
            remove_scope(db, cidr)
        console.print(f"[green]Removed scope {cidr}.[/green]")
    except (ValueError, OSError) as exc:
        fail(exc)


@scope_app.command("check")
def scope_check(address: str, root: Path = typer.Option(DEFAULT)):
    """Check whether a literal IP falls in configured scope."""
    try:
        with connect(root) as db:
            ok = allowed(db, address)
        console.print("[green]IN SCOPE[/green]" if ok else "[red]OUT OF SCOPE[/red]")
        if not ok:
            raise typer.Exit(code=1)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("scan-tcp")
def scan_tcp(target: str, ports: str = typer.Option("22,80,443,8080"), root: Path = typer.Option(DEFAULT)):
    """Run a bounded Nmap TCP connect scan of one scoped IP."""
    try:
        result = scan(root, target, ports)
        console.print(f"[green]Scan complete:[/green] {target}")
        for p in result["open_ports"]:
            console.print(f"  {p['port']}/tcp open ({p['service']})")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("web-headers")
def web_headers(target: str, port: int = typer.Option(80), tls: bool = typer.Option(False, "--tls"), root: Path = typer.Option(DEFAULT)):
    """Send one HEAD request to a scoped literal IP; no redirects or proxy."""
    try:
        result = check(root, target, port, tls)
        console.print(f"[green]HTTP status:[/green] {result['status']}")
        console.print("Not observed:", ", ".join(result["missing_security_headers"]) or "none")
    except (ValueError, OSError, TimeoutError) as exc:
        fail(exc)
    except Exception as exc:
        fail(exc)


@app.command("findings")
def findings(root: Path = typer.Option(DEFAULT)):
    """Display stored assessment observations."""
    try:
        with connect(root) as db:
            rows = db.execute("SELECT id,host,severity,title FROM findings ORDER BY id DESC").fetchall()
        table = Table("ID", "Host", "Severity", "Finding")
        for r in rows:
            table.add_row(*map(str, r))
        console.print(table)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("report")
def create_report(output: Path = typer.Option(Path("redforge-report.html")), format: str = typer.Option("html", help="html or json"), root: Path = typer.Option(DEFAULT)):
    """Export an offline engagement report."""
    try:
        path = report(root, output, format)
        console.print(f"[green]Report created:[/green] {path}")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("auto-assess")
def auto_assess(targets: list[str] = typer.Argument(..., help="One to sixteen approved IP addresses"),
                ports: str = typer.Option("22,80,443,8080,8443"), root: Path = typer.Option(DEFAULT)):
    """Scan selected IPs; inspect HTTP and TLS on discovered common ports."""
    try:
        summary = assess(root, targets, ports)
        for item in summary["targets"]:
            console.print(f"{item['target']}: {len(item['open_ports'])} open ports, {len(item['checks'])} checks")
            for error in item["errors"]:
                console.print(f"  [yellow]{error}[/yellow]")
        for alert in summary["alerts"]:
            console.print(f"[yellow]Change from previous run:[/yellow] {alert}")
        if any(item["errors"] for item in summary["targets"]):
            raise typer.Exit(code=1)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("export-bundle")
def bundle(output: Path = typer.Option(Path("redforge-bundle.zip")), root: Path = typer.Option(DEFAULT)):
    """Export reports, a database snapshot, evidence, and SHA-256 hashes."""
    try:
        console.print(f"[green]Bundle created:[/green] {export_bundle(root, output)}")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("verify-bundle")
def verify_exported_bundle(path: Path):
    """Check every file against the SHA-256 manifest in an exported ZIP."""
    try:
        result = verify_bundle(path)
        console.print(result)
        if not result["ok"]:
            raise typer.Exit(code=1)
    except (ValueError, OSError, zipfile.BadZipFile) as exc:
        fail(exc)


@app.command("runs")
def runs(root: Path = typer.Option(DEFAULT)):
    """List saved automatic assessments."""
    try:
        table = Table("Run ID", "Time (UTC)")
        for row in list_runs(root):
            table.add_row(str(row["id"]), row["at"])
        console.print(table)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("overview")
def engagement_overview(root: Path = typer.Option(DEFAULT)):
    """Show scope, review progress, run count, and recent activity."""
    try:
        result = overview(root)
        console.print(f"[bold]{result['engagement']}[/bold] | authorized: {result['authorized']}")
        console.print(f"Scope: {result['scope_active']} active, {result['scope_expired']} expired")
        console.print(f"Findings: {result['findings']}")
        console.print(f"Runs: {result['runs']} | runs with changes: {result['runs_with_changes']}")
        if result['latest_run']:
            console.print(f"Latest run: {result['latest_run']['id']} at {result['latest_run']['at']}")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("review-finding")
def review_finding(finding_id: int, status: str, note: str = typer.Option(""), root: Path = typer.Option(DEFAULT)):
    """Set an analyst disposition and note for a finding."""
    try:
        set_review(root, finding_id, status, note)
        console.print(f"[green]Finding {finding_id} marked {status}.[/green]")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("search-findings")
def search_saved_findings(host: str | None = typer.Option(None), severity: str | None = typer.Option(None),
                          status: str | None = typer.Option(None), text: str | None = typer.Option(None),
                          since: str | None = typer.Option(None), until: str | None = typer.Option(None),
                          port: int | None = typer.Option(None), root: Path = typer.Option(DEFAULT)):
    """Filter stored findings by host, severity, review, text, date, or TCP port."""
    try:
        rows = search_findings(root, host=host, severity=severity, status=status,
                               text=text, since=since, until=until, port=port)
        table = Table("ID", "Time", "Host", "Severity", "Status", "Finding", "Evidence")
        for row in rows:
            table.add_row(*(str(row[k] or "") for k in ("id", "at", "host", "severity", "review_status", "title", "evidence")))
        console.print(table)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("search-evidence")
def search_saved_evidence(host: str | None = typer.Option(None), port: int | None = typer.Option(None),
                          check: str | None = typer.Option(None), severity: str | None = typer.Option(None),
                          since: str | None = typer.Option(None), until: str | None = typer.Option(None),
                          text: str | None = typer.Option(None), root: Path = typer.Option(DEFAULT)):
    """Search JSON evidence by host, port, check, severity, date, or text."""
    try:
        rows = search_evidence(root, host=host, port=port, check=check,
                               severity=severity, since=since, until=until, text=text)
        table = Table("Time", "Host", "Check", "Port", "Severity", "Evidence")
        for row in rows:
            table.add_row(row["at"], str(row["host"] or ""), row["check"],
                          str(row["port"] or ""), ", ".join(row["severities"]), row["file"])
        console.print(table)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("profile-save")
def profile_save(name: str, targets: list[str] = typer.Argument(...),
                 ports: str = typer.Option("22,80,443,8080,8443"), root: Path = typer.Option(DEFAULT)):
    """Save explicitly selected targets and ports for later rechecks."""
    try:
        save_profile(root, name, targets, ports)
        console.print(f"[green]Saved profile {name}.[/green]")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("profiles")
def profiles(root: Path = typer.Option(DEFAULT)):
    """List saved assessment profiles."""
    try:
        table = Table("Name", "Targets", "Ports")
        for row in list_profiles(root):
            table.add_row(row["name"], ", ".join(row["targets"]), row["ports"])
        console.print(table)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("profile-run")
def profile_run(name: str, root: Path = typer.Option(DEFAULT)):
    """Run a saved profile after rechecking current authorization and scope."""
    try:
        result = run_profile(root, name)
        console.print(f"[green]Run {result['run_id']} complete.[/green]")
        for alert in result.get("alerts", []):
            console.print(f"[yellow]Change: {alert}[/yellow]")
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command("compare-runs")
def compare_saved_runs(before: int | None = typer.Option(None), after: int | None = typer.Option(None),
                       root: Path = typer.Option(DEFAULT)):
    """Compare two runs (defaults to the latest two)."""
    try:
        result = compare_runs(root, before, after)
        console.print(f"Comparing run {result['before']} → {result['after']}")
        for change in result["changes"]:
            if change["kind"] == "observation_changed":
                console.print(f"{change['target']} {change['check']}: {change['before']} → {change['after']}")
            else:
                console.print(f"{change['target']}: {change['kind']} TCP {change['port']}")
        if not result["changes"]:
            console.print("No changes among comparable observations.")
        if result["not_compared"]:
            console.print("Targets present in only one run: " + ", ".join(result["not_compared"]))
    except (ValueError, OSError) as exc:
        fail(exc)



@app.command('tls-inspect')
def tls_inspect(target: str, port: int = typer.Option(443), root: Path = typer.Option(DEFAULT)):
    """Inspect TLS negotiation on one authorized literal IP."""
    from .tlscheck import inspect
    try:
        result = inspect(root, target, port)
        console.print(f"[green]TLS:[/green] {result['protocol']} | Cipher: {result['cipher']}")
        if result['certificate_not_after']:
            console.print(f"Certificate expires: {result['certificate_not_after']} ({result['certificate_days_remaining']} days remaining)")
            console.print(f"Subject: {result['certificate_subject_cn']} | Issuer: {result['certificate_issuer_cn']}")
        console.print('[yellow]Certificate trust and hostname not verified.[/yellow]')
    except (ValueError, OSError, InterruptedError) as exc:
        fail(exc)


@app.command('ssh-inspect')
def ssh_inspect(target: str, port: int = typer.Option(22), root: Path = typer.Option(DEFAULT)):
    """Read one SSH identification banner from an authorized IP."""
    from .sshcheck import inspect
    try:
        result = inspect(root, target, port)
        console.print(f"[green]SSH banner:[/green] {result['banner']}")
    except (ValueError, OSError, InterruptedError) as exc:
        fail(exc)


@app.command('evidence-manifest')
def evidence_manifest(root: Path = typer.Option(DEFAULT)):
    """Record SHA-256 hashes for the current evidence files."""
    from .integrity import create_manifest
    try:
        console.print(f'[green]Manifest:[/green] {create_manifest(root)}')
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command('evidence-verify')
def evidence_verify(root: Path = typer.Option(DEFAULT)):
    """Check evidence against a previously generated SHA-256 manifest."""
    from .integrity import verify_manifest
    try:
        result = verify_manifest(root)
        console.print(result)
        if not result['ok']:
            raise typer.Exit(code=1)
    except (ValueError, OSError) as exc:
        fail(exc)


@app.command('findings-summary')
def findings_summary(root: Path = typer.Option(DEFAULT)):
    """Group repeated observations while retaining original evidence records."""
    try:
        with connect(root) as db:
            rows = db.execute('SELECT host, severity, title, COUNT(*) FROM findings GROUP BY host, severity, title ORDER BY COUNT(*) DESC, host').fetchall()
        table = Table('Host', 'Severity', 'Finding', 'Occurrences')
        for row in rows:
            table.add_row(*map(str, row))
        console.print(table)
    except (ValueError, OSError) as exc:
        fail(exc)

if __name__ == "__main__":
    app()
