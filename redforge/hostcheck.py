"""Read-only, local host security posture observations."""
from __future__ import annotations

import json
import platform
import shutil
import subprocess
from pathlib import Path

from .core import add_finding, audit, connect, evidence_file, now


def _run(argv: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=6, check=False)
        return result.returncode, (result.stdout + result.stderr).strip()[:1000]
    except (OSError, subprocess.TimeoutExpired) as exc:
        return -1, str(exc)[:300]


def _state(code: int, output: str, enabled: str, disabled: str) -> str:
    if code != 0:
        return 'unknown'
    lower = output.lower()
    if enabled in lower:
        return 'enabled'
    if disabled in lower:
        return 'disabled'
    return 'unknown'


def inspect(root: Path) -> dict:
    with connect(root):
        pass
    system = platform.system()
    checks = []
    if system == 'Darwin':
        commands = (
            ('Application firewall', ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
             'firewall is enabled', 'firewall is disabled'),
            ('FileVault', ['/usr/bin/fdesetup', 'status'], 'filevault is on', 'filevault is off'),
            ('System Integrity Protection', ['/usr/bin/csrutil', 'status'],
             'system integrity protection status: enabled', 'system integrity protection status: disabled'),
        )
        for name, argv, enabled, disabled in commands:
            code, output = _run(argv)
            checks.append({'name': name, 'status': _state(code, output, enabled, disabled)})
    elif system == 'Linux':
        observations = []
        ufw = shutil.which('ufw')
        if ufw:
            code, output = _run([ufw, 'status'])
            observations.append(_state(code, output, 'status: active', 'status: inactive'))
        firewalld = shutil.which('firewall-cmd')
        if firewalld:
            code, output = _run([firewalld, '--state'])
            observations.append(_state(code, output, 'running', 'not running'))
        firewall = ('enabled' if 'enabled' in observations else
                    'disabled' if observations and all(state == 'disabled' for state in observations) else
                    'unknown')
        checks.append({'name': 'Host firewall', 'status': firewall})
    else:
        raise ValueError(f'Host audit is unsupported on {system}')
    result = {'at': now(), 'platform': system, 'checks': checks,
              'note': 'Read-only local observations; verify against your organization policy.'}
    with connect(root) as db:
        evidence = evidence_file(root, 'host', json.dumps(result, indent=2))
        audit(db, 'host_audit', json.dumps({'platform': system, 'evidence': evidence}))
        for check in checks:
            if check['status'] == 'disabled':
                add_finding(db, 'localhost', f"Local control disabled: {check['name']}", 'low',
                            'Observed disabled status. Confirm system context and applicable security policy.', evidence)
    return result
