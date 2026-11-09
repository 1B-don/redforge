"""Read-only network discovery and explicit, locally authorized Wi-Fi mode changes.

No active scan or scope change is performed by interface discovery.
"""
from __future__ import annotations
import ipaddress
import json
import re
import shutil
import subprocess
from dataclasses import dataclass

IFNAME = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")

@dataclass(frozen=True)
class NetworkSuggestion:
    interface: str
    address: str
    cidr: str


def _run(argv: list[str], timeout: int = 12) -> str:
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode:
        raise RuntimeError((proc.stderr or proc.stdout or 'Command failed').strip()[:350])
    return proc.stdout


def suggest_local_scopes() -> list[NetworkSuggestion]:
    """Suggest RFC1918/ULA subnets; never save or authorize them automatically."""
    ip = shutil.which('ip')
    if not ip:
        raise RuntimeError('Install iproute2 to discover interfaces.')
    entries = json.loads(_run([ip, '-j', 'address', 'show']))
    suggestions = set()
    for item in entries:
        iface = item.get('ifname', '')
        if not IFNAME.fullmatch(iface) or iface == 'lo':
            continue
        if item.get('operstate') == 'DOWN':
            continue
        for addr in item.get('addr_info', []):
            address = addr.get('local', '')
            prefix = addr.get('prefixlen')
            if prefix is None:
                continue
            try:
                ip_obj = ipaddress.ip_address(address)
                net = ipaddress.ip_network(f'{address}/{int(prefix)}', strict=False)
            except (ValueError, TypeError):
                continue
            if ip_obj.is_loopback or ip_obj.is_link_local:
                continue
            if isinstance(ip_obj, ipaddress.IPv4Address):
                if not any(ip_obj in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
                    continue
            elif ip_obj not in ipaddress.ip_network('fc00::/7'):
                continue
            suggestions.add(NetworkSuggestion(iface, address, str(net)))
    return sorted(suggestions, key=lambda s: (s.interface, s.cidr))


def wifi_interfaces() -> list[tuple[str, str]]:
    """Return (interface, current type) for interfaces reported by iw."""
    iw = shutil.which('iw')
    if not iw:
        raise RuntimeError('Install iw to inspect Wi-Fi interfaces.')
    output = _run([iw, 'dev'])
    found = []
    iface = None
    mode = None
    for line in output.splitlines() + ['\tInterface END']:
        match = re.match(r'^\s*Interface\s+(\S+)', line)
        if match:
            if iface and IFNAME.fullmatch(iface):
                found.append((iface, mode or 'unknown'))
            iface, mode = match.group(1), None
        elif iface:
            match = re.match(r'^\s*type\s+(\S+)', line)
            if match:
                mode = match.group(1)
    return found


def change_wifi_mode(interface: str, mode: str, *, confirmed: bool = False) -> str:
    """Switch a selected Wi-Fi interface via polkit, with explicit confirmation.

    This disconnects the interface. No arbitrary command strings or shell are used.
    """
    if not confirmed:
        raise ValueError('Explicit confirmation required before changing wireless mode.')
    if not IFNAME.fullmatch(interface):
        raise ValueError('Invalid interface name.')
    if mode not in {'monitor', 'managed'}:
        raise ValueError('Mode must be monitor or managed.')
    interfaces = dict(wifi_interfaces())
    if interface not in interfaces:
        raise ValueError('Selected interface is not a detected Wi-Fi interface.')
    if interfaces[interface] == mode:
        return f'{interface} is already in {mode} mode.'
    pkexec = shutil.which('pkexec')
    iw = shutil.which('iw')
    ip = shutil.which('ip')
    nmcli = shutil.which('nmcli')
    if not pkexec or not iw or not ip:
        raise RuntimeError('Install policykit-1, iw, and iproute2 to change Wi-Fi modes.')
    previous_mode = interfaces[interface]
    previous_nm = None
    if nmcli:
        try:
            previous_nm = _run([nmcli, '-g', 'GENERAL.NM-MANAGED', 'device', 'show', interface]).strip().lower()
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            pass
    try:
        if mode == 'monitor' and nmcli:
            _run([nmcli, 'device', 'set', interface, 'managed', 'no'])
        _run([pkexec, ip, 'link', 'set', 'dev', interface, 'down'], timeout=40)
        _run([pkexec, iw, 'dev', interface, 'set', 'type', mode], timeout=40)
        _run([pkexec, ip, 'link', 'set', 'dev', interface, 'up'], timeout=40)
        if mode == 'managed' and nmcli:
            _run([nmcli, 'device', 'set', interface, 'managed', 'yes'])
        actual = dict(wifi_interfaces()).get(interface)
        if actual != mode:
            raise RuntimeError(f'Mode change not confirmed: {interface} reports {actual}.')
    except Exception as original:
        # Best effort: restore the prior mode, bring the link up, and restore
        # NetworkManager's recorded management state after any failure.
        recovery_errors = []
        try:
            _run([pkexec, ip, 'link', 'set', 'dev', interface, 'down'], timeout=40)
            _run([pkexec, iw, 'dev', interface, 'set', 'type', previous_mode], timeout=40)
            _run([pkexec, ip, 'link', 'set', 'dev', interface, 'up'], timeout=40)
        except Exception as exc:
            recovery_errors.append(str(exc))
        if nmcli and previous_nm in {'yes', 'no'}:
            try:
                _run([nmcli, 'device', 'set', interface, 'managed', previous_nm])
            except Exception as exc:
                recovery_errors.append(str(exc))
        if recovery_errors:
            raise RuntimeError(f'Mode change failed: {original}; recovery may be incomplete: {"; ".join(recovery_errors)}') from original
        raise
    return f'{interface} switched to {mode} mode.'
