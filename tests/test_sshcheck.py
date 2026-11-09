from io import BytesIO
from unittest.mock import patch

import pytest

from redforge.core import initialize, connect, add_scope, authorize
from redforge.sshcheck import inspect


class FakeSocket:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, _):
        pass

    def makefile(self, _):
        return BytesIO(b"Welcome\r\nSSH-2.0-OpenSSH_9.0\r\n")


def test_ssh_banner_recorded(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local test")
        authorize(db, True)
    with patch("redforge.sshcheck.socket.create_connection", return_value=FakeSocket()) as network:
        result = inspect(tmp_path, "127.0.0.1")
    assert result["protocol"] == "2.0"
    assert result["banner"] == "SSH-2.0-OpenSSH_9.0"
    network.assert_called_once()
    assert len(list((tmp_path / "evidence").glob("ssh-*.json"))) == 1


def test_ssh_rejects_out_of_scope_without_network(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local test")
        authorize(db, True)
    with patch("redforge.sshcheck.socket.create_connection") as network:
        with pytest.raises(ValueError, match="outside"):
            inspect(tmp_path, "192.0.2.1")
        network.assert_not_called()
