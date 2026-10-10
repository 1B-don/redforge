"""RedForge command line interface."""
from __future__ import annotations
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from .core import initialize, connect, add_scope, authorize as record_authorization, allowed
from .scanner import scan
from .webcheck import check
from .report import report

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
def scope_add(cidr: str, reason: str = typer.Option(..., "--reason", help="Scope authorization reference"), root: Path = typer.Option(DEFAULT)):
    """Add a literal IP address or CIDR network to scope."""
    try:
        with connect(root) as db:
            canonical = add_scope(db, cidr, reason)
        console.print(f"[green]Added scope:[/green] {canonical}")
    except (ValueError, OSError) as exc:
        fail(exc)


@scope_app.command("show")
def scope_show(root: Path = typer.Option(DEFAULT)):
    """List approved ranges and authorization references."""
    try:
        with connect(root) as db:
            rows = db.execute("SELECT cidr,justification FROM scope ORDER BY cidr").fetchall()
        table = Table("CIDR", "Authorization reference")
        for r in rows:
            table.add_row(r[0], r[1])
        console.print(table)
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



@app.command('tls-inspect')
def tls_inspect(target: str, port: int = typer.Option(443), root: Path = typer.Option(DEFAULT)):
    """Inspect TLS negotiation on one authorized literal IP."""
    from .tlscheck import inspect
    try:
        result = inspect(root, target, port)
        console.print(f"[green]TLS:[/green] {result['protocol']} | Cipher: {result['cipher']}")
        console.print('[yellow]Certificate trust and hostname not verified.[/yellow]')
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
