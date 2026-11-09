"""Bounded, scope-controlled TLS certificate inspection (not a vulnerability scanner)."""
from __future__ import annotations
import json
import hashlib
import socket
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
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
                    cert_der = tls.getpeercert(binary_form=True) or b''
                    certificate = x509.load_der_x509_certificate(cert_der) if cert_der else None
                    expiry = certificate.not_valid_after_utc if certificate else None
                    start = certificate.not_valid_before_utc if certificate else None
                    days_remaining = (expiry - datetime.now(timezone.utc)).days if expiry else None
                    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME) if certificate else []
                    issuer_names = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) if certificate else []
                    try:
                        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value if certificate else None
                        dns_names = san.get_values_for_type(x509.DNSName) if san else []
                        ip_names = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] if san else []
                    except x509.ExtensionNotFound:
                        dns_names, ip_names = [], []
                    result = {
                        'at': now(), 'target': target, 'port': port,
                        'protocol': tls.version(), 'cipher': tls.cipher()[0] if tls.cipher() else None,
                        'peer_certificate_der_length': len(cert_der),
                        'peer_certificate_sha256': hashlib.sha256(cert_der).hexdigest() if cert_der else None,
                        'certificate_subject_cn': common_names[0].value if common_names else None,
                        'certificate_issuer_cn': issuer_names[0].value if issuer_names else None,
                        'certificate_dns_names': dns_names[:100], 'certificate_ip_names': ip_names[:100],
                        'certificate_not_before': start.isoformat() if start else None,
                        'certificate_not_after': expiry.isoformat() if expiry else None,
                        'certificate_days_remaining': days_remaining,
                        'chain_trust_verified': False, 'hostname_verified': False,
                        'note': 'Inspection only; certificate trust and hostname have not been verified.'
                    }
        except (OSError, ssl.SSLError, ValueError) as exc:
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
        if result['certificate_days_remaining'] is not None:
            days = result['certificate_days_remaining']
            if days < 0:
                add_finding(db, target, 'Expired TLS certificate observed', 'medium',
                            f'Peer certificate expired {abs(days)} day(s) ago on TCP {port}. Trust and hostname were not verified.', ev)
            elif days <= 30:
                add_finding(db, target, 'TLS certificate expires soon', 'low',
                            f'Peer certificate expires in {days} day(s) on TCP {port}. Trust and hostname were not verified.', ev)
        return result
