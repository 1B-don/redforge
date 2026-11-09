import json
from unittest.mock import patch

import pytest

from redforge.core import initialize, connect, add_scope, authorize, add_finding
from redforge.review import set_review, search_findings
from redforge.profiles import save_profile, list_profiles, run_profile
from redforge.report import report


def ready(root):
    initialize(root, "Test")
    with connect(root) as db:
        add_scope(db, "127.0.0.1/32", "Local test")
        authorize(db, True)


def test_review_search_and_report(tmp_path):
    ready(tmp_path)
    with connect(tmp_path) as db:
        add_finding(db, "127.0.0.1", "TCP port 22 open", "info", "Observed SSH")
    set_review(tmp_path, 1, "confirmed", "Approved service")
    rows = search_findings(tmp_path, host="127.0.0.1", status="confirmed", port=22)
    assert len(rows) == 1 and rows[0]["review_note"] == "Approved service"
    assert search_findings(tmp_path, status="resolved") == []
    output = report(tmp_path, tmp_path / "report.json", "json")
    assert json.loads(output.read_text())["findings"][0]["review_status"] == "confirmed"


def test_profile_rechecks_scope(tmp_path):
    ready(tmp_path)
    save_profile(tmp_path, "local", ["127.0.0.1"], "22,443")
    assert list_profiles(tmp_path)[0]["name"] == "local"
    with connect(tmp_path) as db:
        db.execute("DELETE FROM scope")
        db.commit()
    with patch("redforge.auto.scan") as network:
        with pytest.raises(ValueError, match="outside"):
            run_profile(tmp_path, "local")
        network.assert_not_called()


def test_profile_rejects_invalid_ports(tmp_path):
    ready(tmp_path)
    with pytest.raises(ValueError, match="Ports"):
        save_profile(tmp_path, "bad", ["127.0.0.1"], "-sV")
