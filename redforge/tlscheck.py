"""Bounded, scope-controlled TLS certificate inspection (not a vulnerability scanner)."""
from __future__ import annotations
import json
import socket
import ssl
import threading
from pathlib import Path
from .core import connect, require_target, audit, evidence_file, add_finding, now


def inspect(root: Path, target: str, port: int = 443, cancel: threading.Event | None = None) -> dict:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    if cancel is not None and cancel.is_set():
        raise InterruptedError('Inspection cancelled')
    with connect(root) as db:
        target = require_target(db, target)
        audit(db, 'tls_start', json.dumps({'target': target, 'port': port}))
        # Certificate verification is disabled for *inspection* only, so an
        # expired or self-signed certificate can still be inspected. This
        # does NOT establish whether a chain is trusted or the name matches.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((target, port), timeout=5) as sock:
                sock.settimeout(5)
                with context.wrap_socket(sock, server_hostname=None) as tls:
                    result = {
                        'at': now(), 'target': target, 'port': port,
                        'protocol': tls.version(), 'cipher': tls.cipher()[0] if tls.cipher() else None,
                        'peer_certificate_der_length': len(tls.getpeercert(binary_form=True) or b''),
                        'chain_trust_verified': False, 'hostname_verified': False,
                        'note': 'Inspection only; certificate trust and hostname have not been verified.'
                    }
        except (OSError, ssl.SSLError) as exc:
            audit(db, 'tls_failed', str(exc)[:300])
            raise ValueError(f'TLS inspection failed: {exc}') from exc
        if cancel is not None and cancel.is_set():
            audit(db, 'tls_cancelled', target)
            raise InterruptedError('Inspection cancelled')
        ev = evidence_file(root, 'tls', json.dumps(result, indent=2))
        audit(db, 'tls_complete', json.dumps({'target': target, 'port': port, 'evidence': ev}))
        if result['protocol'] in ('TLSv1', 'TLSv1.1', 'SSLv3'):
            add_finding(db, target, 'Legacy TLS protocol observed', 'medium',
                        f"Negotiated {result['protocol']} on TCP {port}; verify supported protocols and client requirements.", ev)
        return result
