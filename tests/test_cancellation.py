from threading import Event
from unittest.mock import patch
import pytest
from redforge.core import initialize, connect, add_scope, authorize
from redforge.scanner import scan


def test_cancelled_scan_never_launches_nmap(tmp_path):
    initialize(tmp_path, "Cancellation test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Owned test machine")
        authorize(db, True)
    stopped = Event()
    stopped.set()
    with patch("redforge.scanner.shutil.which", return_value="/usr/bin/nmap"):
        with patch("redforge.scanner.subprocess.Popen") as popen:
            with pytest.raises(InterruptedError, match="cancelled"):
                scan(tmp_path, "127.0.0.1", "80", cancel=stopped)
            popen.assert_not_called()


def test_out_of_scope_rejected_before_process(tmp_path):
    initialize(tmp_path, "Scope test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Owned test machine")
        authorize(db, True)
    with patch("redforge.scanner.subprocess.Popen") as popen:
        with pytest.raises(ValueError, match="outside"):
            scan(tmp_path, "192.0.2.2", "80")
        popen.assert_not_called()
