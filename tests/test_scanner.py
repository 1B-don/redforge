import pytest
from redforge.core import initialize, connect, add_scope, authorize
from redforge.scanner import scan


def test_reject_invalid_ports_before_execution(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local test")
        authorize(db, True)
    with pytest.raises(ValueError, match="Ports must"):
        scan(tmp_path, "127.0.0.1", "22,-sS")
    with pytest.raises(ValueError, match="outside"):
        scan(tmp_path, "8.8.8.8", "80")


def test_successful_nmap_output_is_parsed(tmp_path, monkeypatch):
    """Regression: successful scans must not raise NameError on stdout."""
    from unittest.mock import Mock
    import redforge.scanner as scanner

    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local test")
        authorize(db, True)
    xml = ("<?xml version='1.0'?><nmaprun><host><ports>"
           "<port protocol='tcp' portid='8080'><state state='open'/>"
           "<service name='http'/></port></ports></host></nmaprun>")
    fake = Mock()
    fake.poll.return_value = 0
    fake.communicate.return_value = (xml, "")
    fake.returncode = 0
    fake.stdout.close = Mock()
    fake.stderr.close = Mock()
    monkeypatch.setattr(scanner.shutil, "which", lambda command: "/usr/bin/nmap")
    monkeypatch.setattr(scanner.subprocess, "Popen", lambda *args, **kwargs: fake)
    result = scan(tmp_path, "127.0.0.1", "8080")
    assert result["open_ports"] == [{"port": 8080, "protocol": "tcp", "service": "http"}]
