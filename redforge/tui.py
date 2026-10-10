"""Interactive, keyboard-driven RedForge workbench.

All active checks call the existing scope-enforcing core functions.
"""
from __future__ import annotations

from pathlib import Path
from threading import Event
from textual.app import App, ComposeResult
from textual import events
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Static, DataTable, RichLog, OptionList
from textual.widgets.option_list import Option
from textual import work
from textual.binding import Binding

from .core import initialize, connect, add_scope, authorize, allowed
from .scanner import scan
from .webcheck import check
from .report import report

DEFAULT_ROOT = Path('redforge-engagement')


class Home(Screen):
    """Classic numbered menu. Arrow keys select, Enter activates."""
    MENU = (
        ("01  Engagement / Authorization", "engagement"),
        ("02  Scope Management", "scope"),
        ("03  Reconnaissance / TCP Scan", "scan"),
        ("04  HTTP Security Inspection", "web"),
        ("05  Discovered Assets", "assets"),
        ("06  Findings & Evidence", "findings"),
        ("07  Assessment History", "history"),
        ("08  Reports", "reports"),
        ("09  Advanced Tools / Help", "advanced"),
        ("10  Auto Scope / Local Interfaces", "autoscope"),
        ("11  Wi-Fi Interface Modes", "wifi"),
        ("12  Exit RedForge", "quit"),
    )

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id='panel'):
            yield Static(r"""[bold green]  ____  _____ ____  _____ ___  ____   ____ _____
 |  _ \| ____|  _ \|  ___/ _ \|  _ \ / ___| ____|
 | |_) |  _| | | | | |_ | | | | |_) | |  _|  _|
 |  _ <| |___| |_| |  _|| |_| |  _ <| |_| | |___
 |_| \_\_____|____/|_|   \___/|_| \_\____|_____|[/]
[dim]     LINUX SECURITY OPERATIONS // v0.9[/]""", classes='banner', markup=True)
            yield Static('ENGAGEMENT STATUS', classes='heading')
            yield Static('Loading engagement...', id='status')
            yield Static('SELECT: 1–9 | A=Auto Scope | B=Wi-Fi Modes | 0=Exit | Arrows+Enter', classes='heading')
            yield OptionList(*(Option(label, id=screen) for label, screen in self.MENU), id='menu')
            yield Static('Only assess assets you own or have explicit permission to test.', classes='hint')
        yield Footer()

    def on_mount(self):
        self.refresh_status()
        self.query_one('#menu', OptionList).focus()

    def on_screen_resume(self):
        self.refresh_status()
        self.query_one('#menu', OptionList).focus()

    def on_resume(self):
        # Textual versions differ in when the resumed screen receives focus.
        self.refresh_status()
        self.query_one('#menu', OptionList).focus()

    def on_key(self, event: events.Key) -> None:
        # Airgeddon-style instant numbered selection on the home screen.
        if event.character and event.character.lower() in '1234567890ab':
            event.stop()
            event.prevent_default()
            key = event.character.lower()
            self.select_number({'0': 12, 'a': 10, 'b': 11}.get(key, int(key) if key.isdigit() else 0))

    def select_number(self, number: int) -> None:
        if not 1 <= number <= len(self.MENU):
            return
        screen = self.MENU[number - 1][1]
        if screen == 'quit':
            self.app.exit()
        else:
            self.app.push_screen(screen)

    def refresh_status(self):
        try:
            with connect(self.app.engagement_root) as db:
                name = db.execute("SELECT value FROM settings WHERE key='name'").fetchone()[0]
                authorized = db.execute("SELECT value FROM settings WHERE key='authorized'").fetchone()[0]
                scope = db.execute('SELECT COUNT(*) FROM scope').fetchone()[0]
                findings = db.execute('SELECT COUNT(*) FROM findings').fetchone()[0]
            message = f'[bold]{name}[/]  |  AUTH: {authorized.upper()}  |  SCOPE: {scope}  |  OBSERVATIONS: {findings}'
        except (ValueError, OSError, TypeError):
            message = '[yellow]No engagement loaded. Select 01 to create or open one.[/]'
        self.query_one('#status', Static).update(message)

    def on_option_list_option_selected(self, event: OptionList.OptionSelected):
        if event.option_id == 'quit':
            self.app.exit()
        elif event.option_id:
            self.app.push_screen(event.option_id)


class BaseScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id='panel'):
            yield Static(self.title_text, classes='heading')
            yield from self.content()
            yield Static('', id='message')
            yield Static('[dim]0 Back  |  Esc Back  |  Tab Navigate  |  Enter Select[/]', classes='hint')
            yield Button('0  ← Back to menu', id='back')
        yield Footer()

    title_text = ''
    ACTIONS: tuple[tuple[str, str], ...] = ()

    def on_key(self, event: events.Key) -> None:
        # Digits typed inside Input must remain editable target/port values.
        if isinstance(self.app.focused, Input):
            return
        if event.character and event.character.isdigit():
            number = int(event.character)
            if number == 0:
                event.stop()
                event.prevent_default()
                self.app.action_back()
            elif 1 <= number <= len(self.ACTIONS):
                event.stop()
                event.prevent_default()
                self.handle_action(self.ACTIONS[number - 1][1])

    def on_mount(self):
        # Every module opens ready for keyboard input: no mouse click needed.
        fields = self.query(Input)
        if fields:
            fields.first().focus()
        else:
            buttons = self.query(Button)
            if buttons:
                buttons.first().focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        # Enter advances to the next field, then to the first action button.
        fields = list(self.query(Input))
        if event.input in fields:
            position = fields.index(event.input)
            if position + 1 < len(fields):
                fields[position + 1].focus()
            else:
                buttons = [b for b in self.query(Button) if b.id != 'back']
                if buttons:
                    buttons[0].focus()
            event.stop()

    def content(self):
        return []

    def show_message(self, value: str) -> None:
        self.query_one('#message', Static).update(value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == 'back':
            self.app.action_back()
        else:
            self.handle_action(event.button.id or '')

    def handle_action(self, action: str) -> None:
        pass

    @property
    def root(self) -> Path:
        return self.app.engagement_root


class Engagement(BaseScreen):
    ACTIONS = (('create', 'create'), ('authorize', 'authorize'), ('status', 'status'))
    title_text = 'Engagement Setup'

    def content(self):
        yield Label('Engagement directory (relative to current terminal folder or absolute path)')
        yield Input(value=str(self.app.engagement_root), id='root')
        yield Label('New engagement name')
        yield Input(value='RedForge Security Lab', id='name')
        yield Button('1  Create / Open Engagement', id='create', variant='primary')
        yield Label('Only acknowledge authorization for systems you have permission to assess.')
        yield Button('2  Record Authorization Acknowledgement', id='authorize', variant='warning')
        yield Button('3  Refresh Status', id='status')

    def handle_action(self, action):
        try:
            if action == 'create':
                self.app.engagement_root = Path(self.query_one('#root', Input).value).expanduser()
                initialize(self.root, self.query_one('#name', Input).value.strip() or 'RedForge Lab')
                self.show_message(f'Engagement ready: {self.root.resolve()}')
            elif action == 'authorize':
                with connect(self.root) as db:
                    authorize(db, True)
                self.show_message('Authorization acknowledgement recorded. This does not independently verify permission.')
            elif action == 'status':
                with connect(self.root) as db:
                    name = db.execute("SELECT value FROM settings WHERE key='name'").fetchone()[0]
                    auth = db.execute("SELECT value FROM settings WHERE key='authorized'").fetchone()[0]
                    count = db.execute('SELECT COUNT(*) FROM scope').fetchone()[0]
                self.show_message(f'{name} | authorized: {auth} | scope entries: {count}')
        except (ValueError, OSError) as exc:
            self.show_message(f'Error: {exc}')


class Scope(BaseScreen):
    ACTIONS = (('add', 'add'), ('show', 'show'))
    title_text = 'Scope Management'

    def content(self):
        yield Label('Authorized literal IP / CIDR')
        yield Input(placeholder='127.0.0.1/32', id='cidr')
        yield Label('Permission / engagement reference')
        yield Input(placeholder='My own local system', id='reason')
        yield Button('1  Add Scope', id='add', variant='primary')
        yield Button('2  Show Scope', id='show')
        yield DataTable(id='table')

    def on_mount(self):
        super().on_mount()
        self.query_one('#table', DataTable).add_columns('CIDR', 'Authorization reference')
        self.refresh_table()

    def refresh_table(self):
        table = self.query_one('#table', DataTable)
        table.clear()
        try:
            with connect(self.root) as db:
                for row in db.execute('SELECT cidr, justification FROM scope ORDER BY cidr'):
                    table.add_row(str(row[0]), str(row[1]))
        except ValueError:
            pass

    def handle_action(self, action):
        try:
            if action == 'add':
                reason = self.query_one('#reason', Input).value.strip()
                if not reason:
                    raise ValueError('Enter an authorization reference.')
                with connect(self.root) as db:
                    cidr = add_scope(db, self.query_one('#cidr', Input).value.strip(), reason)
                self.show_message(f'Added {cidr}')
            self.refresh_table()
        except (ValueError, OSError) as exc:
            self.show_message(f'Error: {exc}')


class Scan(BaseScreen):
    ACTIONS = (('run', 'run'),)
    title_text = 'Scoped TCP Scan'

    def content(self):
        yield Label('Target literal IP (must be in scope)')
        yield Input(value='127.0.0.1', id='target')
        yield Label('TCP ports (1–32 comma-separated ports)')
        yield Input(value='22,80,443,8080', id='ports')
        yield Button('1  Run TCP Scan', id='run', variant='primary')
        yield RichLog(id='results', highlight=True, markup=True, wrap=True)

    def on_mount(self):
        super().on_mount()
        self.cancel_event = Event()

    def on_screen_suspend(self):
        self.cancel_event.set()

    def on_unmount(self):
        self.cancel_event.set()

    def handle_action(self, action):
        if action == 'run':
            self.cancel_event.clear()
            target = self.query_one('#target', Input).value.strip()
            ports = self.query_one('#ports', Input).value.strip()
            self.query_one('#run', Button).disabled = True
            self.show_message('Scanning...')
            self.run_scan(target, ports)

    @work(thread=True, exclusive=True)
    def run_scan(self, target, ports):
        try:
            result = scan(self.root, target, ports, cancel=self.cancel_event)
            message = f"Completed {target}: {len(result['open_ports'])} open port(s)"
            lines = [f"{p['port']}/tcp  {p['service']}" for p in result['open_ports']]
        except Exception as exc:
            message, lines = f'Error: {exc}', []
        if self.is_mounted and not self.cancel_event.is_set():
            self.app.call_from_thread(self.finish, message, lines)

    def finish(self, message, lines):
        self.show_message(message)
        log = self.query_one('#results', RichLog)
        for line in lines:
            log.write(line)
        self.query_one('#run', Button).disabled = False


class Web(BaseScreen):
    ACTIONS = (('http', 'http'), ('https', 'https'))
    title_text = 'HTTP Header Inspection'

    def content(self):
        yield Label('Target literal IP (must be in scope)')
        yield Input(value='127.0.0.1', id='target')
        yield Label('TCP port')
        yield Input(value='80', id='port')
        yield Button('1  Inspect HTTP', id='http', variant='primary')
        yield Button('2  Inspect HTTPS', id='https')
        yield RichLog(id='results', highlight=True, markup=True, wrap=True)

    def on_mount(self):
        super().on_mount()
        self.cancel_event = Event()
        self.active_connection = None

    def stop_request(self):
        self.cancel_event.set()
        connection = self.active_connection
        if connection is not None:
            try:
                # Closing an active socket interrupts an in-flight request.
                if connection.sock is not None:
                    connection.sock.shutdown(2)
            except OSError:
                pass
            connection.close()
            self.active_connection = None

    def on_screen_suspend(self):
        self.stop_request()

    def on_unmount(self):
        self.stop_request()

    def handle_action(self, action):
        if action in ('http', 'https'):
            try:
                port = int(self.query_one('#port', Input).value)
            except ValueError:
                self.show_message('Error: Port must be a number')
                return
            self.cancel_event.clear()
            target = self.query_one('#target', Input).value.strip()
            self.query_one('#http', Button).disabled = True
            self.query_one('#https', Button).disabled = True
            self.show_message('Inspecting...')
            self.run_web(target, port, action == 'https')

    @work(thread=True, exclusive=True)
    def run_web(self, target, port, tls):
        try:
            result = check(self.root, target, port, tls, cancel=self.cancel_event, on_connection=self.register_connection)
            message = f"HTTP status: {result['status']}"
            lines = [f"Not observed: {h}" for h in result['missing_security_headers']]
            if not lines:
                lines = ['All checked headers were observed.']
        except Exception as exc:
            message, lines = f'Error: {exc}', []
        if self.is_mounted and not self.cancel_event.is_set():
            self.app.call_from_thread(self.finish, message, lines)

    def register_connection(self, conn):
        self.active_connection = conn
        if self.cancel_event.is_set():
            conn.close()

    def finish(self, message, lines):
        self.active_connection = None
        self.show_message(message)
        for line in lines:
            self.query_one('#results', RichLog).write(line)
        self.query_one('#http', Button).disabled = False
        self.query_one('#https', Button).disabled = False


class Findings(BaseScreen):
    ACTIONS = (('refresh', 'refresh'),)
    title_text = 'Findings and Observations'

    def content(self):
        yield Label('Every assessment observation is preserved; repeated findings may appear more than once.')
        yield Button('1  Refresh Findings', id='refresh', variant='primary')
        yield DataTable(id='table')

    def on_mount(self):
        super().on_mount()
        self.query_one('#table', DataTable).add_columns('ID', 'Host', 'Severity', 'Finding', 'Evidence')
        self.refresh_table()

    def refresh_table(self):
        table = self.query_one('#table', DataTable)
        table.clear()
        try:
            with connect(self.root) as db:
                for row in db.execute('SELECT id,host,severity,title,evidence FROM findings ORDER BY id DESC LIMIT 500'):
                    table.add_row(*(str(v or '') for v in row))
        except ValueError as exc:
            self.show_message(str(exc))

    def handle_action(self, action):
        if action == 'refresh':
            self.refresh_table()


class Assets(BaseScreen):
    ACTIONS = (('refresh', 'refresh'),)
    title_text = 'Discovered Assets / Open Services'

    def content(self):
        yield Label('Inventory is derived from previously recorded TCP findings.')
        yield Button('1  Refresh Inventory', id='refresh', variant='primary')
        yield DataTable(id='table')

    def on_mount(self):
        super().on_mount()
        self.query_one('#table', DataTable).add_columns('Host', 'Observed service', 'Observations')
        self.refresh_table()

    def refresh_table(self):
        table = self.query_one('#table', DataTable)
        table.clear()
        try:
            with connect(self.root) as db:
                rows = db.execute("""SELECT host, title, COUNT(*) FROM findings
                    WHERE title LIKE 'TCP port % open'
                    GROUP BY host, title ORDER BY host, title""").fetchall()
                for host, title, count in rows:
                    table.add_row(str(host), str(title), str(count))
                self.show_message(f'{len(rows)} observed host/service combinations. Results may be historical.')
        except ValueError as exc:
            self.show_message(str(exc))

    def handle_action(self, action):
        if action == 'refresh':
            self.refresh_table()


class History(BaseScreen):
    ACTIONS = (('refresh', 'refresh'),)
    title_text = 'Assessment / Audit History'

    def content(self):
        yield Label('Chronological actions recorded in the existing engagement database.')
        yield Button('1  Refresh History', id='refresh', variant='primary')
        yield DataTable(id='table')

    def on_mount(self):
        super().on_mount()
        self.query_one('#table', DataTable).add_columns('Time (UTC)', 'Action', 'Details')
        self.refresh_table()

    def refresh_table(self):
        table = self.query_one('#table', DataTable)
        table.clear()
        try:
            with connect(self.root) as db:
                for row in db.execute('SELECT at, action, details FROM audit ORDER BY id DESC LIMIT 200'):
                    table.add_row(*(str(v or '')[:180] for v in row))
        except ValueError as exc:
            self.show_message(str(exc))

    def handle_action(self, action):
        if action == 'refresh':
            self.refresh_table()


class Reports(BaseScreen):
    ACTIONS = (('html', 'html'), ('json', 'json'))
    title_text = 'Export Engagement Report'

    def content(self):
        yield Label('Output filename')
        yield Input(value='redforge-report.html', id='filename')
        yield Button('1  Export HTML', id='html', variant='primary')
        yield Button('2  Export JSON', id='json')

    def handle_action(self, action):
        if action in ('html', 'json'):
            try:
                dest = Path(self.query_one('#filename', Input).value.strip())
                if not dest.name:
                    raise ValueError('Enter an output filename')
                dest = dest.with_suffix('.' + action)
                result = report(self.root, dest, action)
                self.show_message(f'Exported: {result}')
            except (ValueError, OSError) as exc:
                self.show_message(f'Error: {exc}')


class Help(BaseScreen):
    title_text = 'Help / User Guide'
    ACTIONS = ()

    def content(self):
        yield Static("""[bold green]REDFORGE // QUICK START[/]

[bold]1. ENGAGEMENT[/]
Select [bold]1[/] from Home. Enter an engagement folder and name, then choose
Create / Open. Record authorization only for systems you are permitted to assess.

[bold]2. SCOPE[/]
Select [bold]2[/] from Home. Enter an approved literal IP or CIDR, such as
127.0.0.1/32, and an authorization reference. Choose Add Scope.

[bold]3. TCP RECONNAISSANCE[/]
Select [bold]3[/]. Type the target IP, press Enter, type a comma-separated
port list (maximum 32), press Enter, then activate Run TCP Scan.
Requires Nmap, a valid scope entry, and authorization acknowledgement.

[bold]4. HTTP INSPECTION[/]
Select [bold]4[/]. Enter a scoped IP and port. Choose HTTP or HTTPS.
Missing headers are observations, not proof of an exploitable weakness.

[bold]5–7. REVIEW RESULTS[/]
Browse discovered assets, stored findings/evidence, and audit history.

[bold]8. REPORTS[/]
Enter a filename and choose HTML or JSON export.

[bold]KEYBOARD SHORTCUTS[/]
Home: 1–9 select modules; A = Auto Scope; B = Wi-Fi Modes; 0 exits. Advanced Tools → 5 opens Help. Arrow keys and Enter also work.
Within modules: Tab / Shift+Tab change focus; Enter advances fields.
Esc returns to Home. Ctrl+Q exits. No mouse required.

[bold]DATA LOCATION[/]
Desktop installation: ~/.local/share/redforge/redforge-engagement
Terminal CLI with --root: uses the selected engagement directory.
Original assessment records remain in the directory you selected.

[bold]TROUBLESHOOTING[/]
If a scan fails, verify Nmap is installed, your target is a literal IP,
the IP is in scope, and authorization is recorded. Inspect the message
panel for details. For terminal compatibility use Konsole.

[bold]SAFETY[/]
Only test systems you own or are explicitly authorized to assess.
RedForge does not verify legal permission independently.
""", markup=True)



class Advanced(BaseScreen):
    title_text = 'Advanced Tools / Help'
    ACTIONS = (('tls', 'tls'), ('manifest', 'manifest'), ('verify', 'verify'),
               ('summary', 'summary'), ('help', 'help'))

    def content(self):
        yield Static('TLS checks require a scoped, authorized literal IP. Evidence tools are local-only.')
        yield Label('TLS target IP')
        yield Input(value='127.0.0.1', id='target')
        yield Label('TLS port')
        yield Input(value='443', id='port')
        yield Button('1  Inspect TLS', id='tls', variant='primary')
        yield Button('2  Create SHA-256 Evidence Manifest', id='manifest')
        yield Button('3  Verify Evidence Manifest', id='verify')
        yield Button('4  Summarize Duplicate Findings', id='summary')
        yield Button('5  Open Help / User Guide', id='help')
        yield RichLog(id='results', wrap=True, markup=False)

    def on_mount(self):
        super().on_mount()
        self.cancel_event = Event()

    def on_unmount(self):
        self.cancel_event.set()

    def handle_action(self, action):
        if action == 'help':
            self.app.push_screen('help')
            return
        if action == 'tls':
            try:
                port = int(self.query_one('#port', Input).value)
            except ValueError:
                self.show_message('Port must be an integer')
                return
            self.query_one('#tls', Button).disabled = True
            self.show_message('Inspecting TLS...')
            self.inspect_tls(self.query_one('#target', Input).value.strip(), port)
            return
        try:
            if action == 'manifest':
                from .integrity import create_manifest
                self.show_message(f'Manifest created: {create_manifest(self.root)}')
            elif action == 'verify':
                from .integrity import verify_manifest
                result = verify_manifest(self.root)
                self.query_one('#results', RichLog).write(str(result))
                self.show_message('Integrity OK' if result['ok'] else 'Evidence mismatch detected')
            elif action == 'summary':
                with connect(self.root) as db:
                    rows = db.execute('SELECT host, title, COUNT(*) FROM findings GROUP BY host, title ORDER BY COUNT(*) DESC LIMIT 100').fetchall()
                log = self.query_one('#results', RichLog)
                log.clear()
                for host, title, count in rows:
                    log.write(f'{host} | {count} observation(s) | {title}')
                self.show_message(f'{len(rows)} grouped findings')
        except (ValueError, OSError) as exc:
            self.show_message(f'Error: {exc}')

    @work(thread=True, exclusive=True)
    def inspect_tls(self, target, port):
        from .tlscheck import inspect
        try:
            result = inspect(self.root, target, port, cancel=self.cancel_event)
            message = f"TLS {result['protocol']} | {result['cipher']} | Trust NOT verified"
        except Exception as exc:
            message = f'Error: {exc}'
        if self.is_mounted and not self.cancel_event.is_set():
            self.app.call_from_thread(self.finish_tls, message)

    def finish_tls(self, message):
        self.show_message(message)
        self.query_one('#tls', Button).disabled = False

class AutoScope(BaseScreen):
    title_text = 'Auto Scope / Local Network Suggestions'
    ACTIONS = (('refresh', 'refresh'), ('add', 'add'))

    def content(self):
        yield Static('Read-only discovery. Local interfaces are NOT automatically authorized.')
        yield Button('1  Detect Private Local Networks', id='refresh', variant='primary')
        yield DataTable(id='networks')
        yield Label('Select a row with arrow keys, then Tab to Add.')
        yield Input(placeholder='Authorization reference / written permission', id='reason')
        yield Button('2  Add Selected Network to Scope', id='add')

    def on_mount(self):
        super().on_mount()
        table = self.query_one('#networks', DataTable)
        table.cursor_type = 'row'
        table.add_columns('Interface', 'Address', 'Suggested CIDR')
        self.suggestions = []
        self.refresh_suggestions()
        table.focus()

    def refresh_suggestions(self):
        from .network import suggest_local_scopes
        table = self.query_one('#networks', DataTable)
        table.clear()
        try:
            self.suggestions = suggest_local_scopes()
            for suggestion in self.suggestions:
                table.add_row(suggestion.interface, suggestion.address, suggestion.cidr)
            self.show_message(f'{len(self.suggestions)} private network suggestion(s). Choose only authorized ranges.')
        except (RuntimeError, OSError, ValueError) as exc:
            self.show_message(f'Error: {exc}')

    def handle_action(self, action):
        if action == 'refresh':
            self.refresh_suggestions()
        elif action == 'add':
            table = self.query_one('#networks', DataTable)
            index = table.cursor_row
            if not self.suggestions or index < 0 or index >= len(self.suggestions):
                self.show_message('Select a suggested network first.')
                return
            reason = self.query_one('#reason', Input).value.strip()
            if not reason:
                self.show_message('Enter a permission reference before adding a network.')
                self.query_one('#reason', Input).focus()
                return
            suggestion = self.suggestions[index]
            try:
                with connect(self.root) as db:
                    add_scope(db, suggestion.cidr, reason)
                self.show_message(f'Added {suggestion.cidr} to scope. Authorization acknowledgement is separate.')
            except (ValueError, OSError) as exc:
                self.show_message(f'Error: {exc}')


class WiFiModes(BaseScreen):
    title_text = 'Wi-Fi Interface Management'
    ACTIONS = (('refresh', 'refresh'), ('monitor', 'monitor'), ('managed', 'managed'))

    def content(self):
        yield Static("CAUTION: Changing Wi-Fi mode can disconnect your network.\n"
                     "Monitor mode requires a compatible adapter and driver.\n"
                     "Polkit may request administrator authentication.")
        yield Button('1  Refresh Wi-Fi Adapters', id='refresh', variant='primary')
        yield DataTable(id='interfaces')
        yield Static('Select an interface with arrow keys. Type SWITCH in the confirmation field.')
        yield Input(placeholder='Type SWITCH to confirm interruption', id='confirm')
        yield Button('2  Switch Selected Interface to MONITOR', id='monitor')
        yield Button('3  Switch Selected Interface to MANAGED', id='managed')

    def on_mount(self):
        super().on_mount()
        table = self.query_one('#interfaces', DataTable)
        table.cursor_type = 'row'
        table.add_columns('Wireless interface', 'Current mode')
        self.interfaces = []
        self.refresh_interfaces()
        table.focus()

    def refresh_interfaces(self):
        from .network import wifi_interfaces
        table = self.query_one('#interfaces', DataTable)
        table.clear()
        try:
            self.interfaces = wifi_interfaces()
            for name, mode in self.interfaces:
                table.add_row(name, mode)
            self.show_message(f'{len(self.interfaces)} Wi-Fi adapter(s) detected.')
        except (RuntimeError, OSError, ValueError) as exc:
            self.show_message(f'Error: {exc}')

    def handle_action(self, action):
        if action == 'refresh':
            self.refresh_interfaces()
        elif action in ('monitor', 'managed'):
            if self.query_one('#confirm', Input).value.strip() != 'SWITCH':
                self.show_message('Type SWITCH to confirm potential network disconnection.')
                self.query_one('#confirm', Input).focus()
                return
            table = self.query_one('#interfaces', DataTable)
            index = table.cursor_row
            if not self.interfaces or index < 0 or index >= len(self.interfaces):
                self.show_message('Select a Wi-Fi interface first.')
                return
            name = self.interfaces[index][0]
            self.query_one('#confirm', Input).value = ''
            self.show_message(f'Switching {name} to {action}; authentication may be required...')
            self.switch_mode(name, action)

    @work(thread=True, exclusive=True)
    def switch_mode(self, name, mode):
        from .network import change_wifi_mode
        try:
            message = change_wifi_mode(name, mode, confirmed=True)
        except Exception as exc:
            message = f'Mode change failed: {exc}'
        if self.is_mounted:
            self.app.call_from_thread(self.finish_mode, message)

    def finish_mode(self, message):
        self.show_message(message)
        self.refresh_interfaces()
        self.show_message(message)


class RedForgeTUI(App):
    CSS = """
    Screen { background: #050805; color: #a6f5b8; }
    Header { background: #091709; color: #6bff83; text-style: bold; }
    Footer { background: #091709; color: #8ae89c; }
    #panel { width: 96%; max-width: 116; height: auto; max-height: 98%;
             margin: 0 1; padding: 1 2; border: ascii #3a9b54; background: #050b06; }
    .banner { color: #6bff83; margin-bottom: 1; }
    .heading { text-style: bold; color: #6bff83; margin: 1 0; }
    .hint { color: #7fae88; margin-top: 1; }
    #status { color: #b5edbc; margin-bottom: 1; }
    OptionList { height: 18; background: #050b06; border: none; color: #a6f5b8; }
    OptionList > .option-list--option-highlighted { background: #164c25; color: #ffffff; text-style: bold; }
    Button { margin: 1 0 0 0; width: 100%; background: #0c2813; color: #a6f5b8; border: none; }
    Button:focus { background: #256f37; color: #ffffff; text-style: bold; }
    Input { margin-bottom: 1; border: ascii #27693a; background: #050b06; }
    Input:focus { border: ascii #6bff83; }
    #message { margin: 1 0; color: #6bff83; }
    DataTable { height: 15; margin-top: 1; background: #050b06; }
    RichLog { height: 12; margin-top: 1; border: ascii #27693a; }
    """
    TITLE = 'REDFORGE // Security Operations'
    BINDINGS = [Binding('escape', 'back', 'Back', priority=True), Binding('ctrl+q', 'quit', 'Quit', priority=True)]
    SCREENS = {'home': Home, 'engagement': Engagement, 'scope': Scope, 'scan': Scan,
               'web': Web, 'assets': Assets, 'findings': Findings,
               'history': History, 'reports': Reports, 'help': Help, 'advanced': Advanced,
               'autoscope': AutoScope, 'wifi': WiFiModes}

    def __init__(self, root: Path = DEFAULT_ROOT):
        super().__init__()
        self.engagement_root = root

    def on_mount(self):
        self.push_screen('home')

    def on_key(self, event: events.Key) -> None:
        """Fallback numeric navigation when a focused widget bubbles key events."""
        if isinstance(self.focused, Input):
            return  # Never steal digits while editing IPs, ports or paths.
        digit = event.character
        if not digit or digit.lower() not in '0123456789ab':
            return
        current = self.screen
        if isinstance(current, Home):
            key = digit.lower()
            current.select_number({'0': 12, 'a': 10, 'b': 11}.get(key, int(key) if key.isdigit() else 0))
            event.stop()
            event.prevent_default()
        elif isinstance(current, BaseScreen):
            if digit == '0':
                self.action_back()
                event.stop()
                event.prevent_default()
            elif 1 <= int(digit) <= len(current.ACTIONS):
                current.handle_action(current.ACTIONS[int(digit) - 1][1])
                event.stop()
                event.prevent_default()

    def action_quit(self):
        current = self.screen
        if hasattr(current, 'cancel_event'):
            if hasattr(current, 'stop_request'):
                current.stop_request()
            else:
                current.cancel_event.set()
        self.exit()

    def action_back(self):
        """Return directly to Home, never the blank underlying default screen."""
        current = self.screen
        if isinstance(current, Home):
            current.refresh_status()
            current.query_one('#menu', OptionList).focus()
            return
        if hasattr(current, 'stop_request'):
            current.stop_request()
        elif hasattr(current, 'cancel_event'):
            current.cancel_event.set()
        # The Home screen is always pushed on mount. Pop only the module
        # screen, rather than popping Home and revealing the default screen.
        while len(self.screen_stack) > 2:
            self.pop_screen()
        # Schedule focus after navigation; no mouse interaction is necessary.
        self.call_after_refresh(self._focus_home)

    def _focus_home(self):
        if isinstance(self.screen, Home):
            self.screen.refresh_status()
            self.screen.query_one('#menu', OptionList).focus()


def launch(root: Path = DEFAULT_ROOT):
    RedForgeTUI(root).run()
