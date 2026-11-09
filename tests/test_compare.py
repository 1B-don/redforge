from redforge.compare import save_run, compare_runs, list_runs
from redforge.core import initialize
from redforge.core import connect, add_scope, authorize
from redforge.auto import assess
from unittest.mock import patch


def test_compare_ports_and_observations(tmp_path):
    initialize(tmp_path, "Test")
    before = {"at": "2026-01-01T00:00:00Z", "targets": [
        {"target": "192.0.2.1", "scan_ok": True, "open_ports": [{"port": 22}],
         "observations": {"ssh:22": "SSH-2.0-old"}}]}
    after = {"at": "2026-01-02T00:00:00Z", "targets": [
        {"target": "192.0.2.1", "scan_ok": True, "open_ports": [{"port": 22}, {"port": 443}],
         "observations": {"ssh:22": "SSH-2.0-new", "tls:443": {"protocol": "TLSv1.3"}}}]}
    save_run(tmp_path, before)
    save_run(tmp_path, after)
    result = compare_runs(tmp_path)
    assert [change["kind"] for change in result["changes"]] == ["port_opened", "observation_changed"]
    assert len(list_runs(tmp_path)) == 2


def test_failed_scan_does_not_report_closed_ports(tmp_path):
    initialize(tmp_path, "Test")
    save_run(tmp_path, {"at": "one", "targets": [
        {"target": "192.0.2.1", "scan_ok": True, "open_ports": [{"port": 22}]}]})
    save_run(tmp_path, {"at": "two", "targets": [
        {"target": "192.0.2.1", "scan_ok": False, "open_ports": []}]})
    assert compare_runs(tmp_path)["changes"] == []


def test_auto_run_emits_change_alert_for_new_port(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local")
        authorize(db, True)
    with patch("redforge.auto.scan", side_effect=[
            {"open_ports": []}, {"open_ports": [{"port": 9000}]}]):
        first = assess(tmp_path, ["127.0.0.1"], "9000")
        second = assess(tmp_path, ["127.0.0.1"], "9000")
    assert first["alerts"] == []
    assert second["alerts"][0]["kind"] == "port_opened"
    with connect(tmp_path) as db:
        assert db.execute("SELECT 1 FROM audit WHERE action='change_alert'").fetchone()
