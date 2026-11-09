from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from redforge.core import initialize, connect, add_scope, authorize
from redforge.tlscheck import inspect


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, _):
        pass


class FakeTLS(FakeConnection):
    def __init__(self, cert):
        self.cert = cert

    def version(self):
        return 'TLSv1.3'

    def cipher(self):
        return ('TLS_AES_256_GCM_SHA384', '', 256)

    def getpeercert(self, binary_form=False):
        return self.cert


class FakeContext:
    def __init__(self, cert):
        self.cert = cert

    def wrap_socket(self, *_args, **_kwargs):
        return FakeTLS(self.cert)


def test_tls_near_expiry_records_metadata_and_finding(tmp_path):
    initialize(tmp_path, 'Test')
    with connect(tmp_path) as db:
        add_scope(db, '127.0.0.1/32', 'Local')
        authorize(db, True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.test')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    with patch('redforge.tlscheck.socket.create_connection', return_value=FakeConnection()), \
         patch('redforge.tlscheck.ssl.SSLContext', return_value=FakeContext(cert)):
        result = inspect(tmp_path, '127.0.0.1')
    assert result['certificate_subject_cn'] == 'example.test'
    assert 8 <= result['certificate_days_remaining'] <= 10
    assert len(result['peer_certificate_sha256']) == 64
    with connect(tmp_path) as db:
        assert db.execute("SELECT title FROM findings WHERE title='TLS certificate expires soon'").fetchone()


def test_weak_rsa_certificate_is_observed(tmp_path):
    initialize(tmp_path, 'Test')
    with connect(tmp_path) as db:
        add_scope(db, '127.0.0.1/32', 'Local')
        authorize(db, True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'weak.test')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    with patch('redforge.tlscheck.socket.create_connection', return_value=FakeConnection()), \
         patch('redforge.tlscheck.ssl.SSLContext', return_value=FakeContext(cert)):
        result = inspect(tmp_path, '127.0.0.1')
    assert result['certificate_key_type'] == 'RSA'
    assert result['certificate_key_bits'] == 1024
    with connect(tmp_path) as db:
        assert db.execute("SELECT 1 FROM findings WHERE title='Weak TLS certificate public key observed'").fetchone()
