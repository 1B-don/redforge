from pathlib import Path
from threading import Event
import pytest
from redforge.core import initialize, connect, add_scope, authorize
from redforge.integrity import create_manifest, verify_manifest
from redforge.tlscheck import inspect


def test_manifest_detects_modification(tmp_path):
    initialize(tmp_path, 'Test')
    ev = tmp_path / 'evidence' / 'sample.json'
    ev.write_text('{"sample": true}')
    create_manifest(tmp_path)
    assert verify_manifest(tmp_path)['ok']
    ev.write_text('{"sample": false}')
    result = verify_manifest(tmp_path)
    assert not result['ok']
    assert result['changed'] == ['sample.json']


def test_manifest_detects_missing_and_untracked(tmp_path):
    initialize(tmp_path, 'Test')
    ev = tmp_path / 'evidence' / 'first.json'
    ev.write_text('{}')
    create_manifest(tmp_path)
    ev.unlink()
    (tmp_path / 'evidence' / 'new.json').write_text('{}')
    result = verify_manifest(tmp_path)
    assert result['missing'] == ['first.json']
    assert result['untracked'] == ['new.json']


def test_tls_rejects_out_of_scope_without_network(tmp_path):
    initialize(tmp_path, 'Test')
    with connect(tmp_path) as db:
        add_scope(db, '127.0.0.1/32', 'Local')
        authorize(db, True)
    with pytest.raises(ValueError, match='outside'):
        inspect(tmp_path, '192.0.2.1')


def test_tls_cancelled_before_network(tmp_path):
    with pytest.raises(InterruptedError):
        inspect(tmp_path, '127.0.0.1', cancel=Event_with_set())


def Event_with_set():
    event = Event()
    event.set()
    return event


def test_tls_rejects_bad_port(tmp_path):
    with pytest.raises(ValueError, match='Port'):
        inspect(tmp_path, '127.0.0.1', 65536)
