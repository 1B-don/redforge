import json

from redforge.core import initialize, connect, add_finding, evidence_file
from redforge.evidence_search import search_evidence


def test_search_evidence_includes_checks_without_findings(tmp_path):
    initialize(tmp_path, "Test")
    ssh = evidence_file(tmp_path, "ssh", json.dumps({"at": "2026-01-01", "target": "127.0.0.1", "port": 22, "banner": "SSH-2.0-test"}))
    tcp = evidence_file(tmp_path, "tcp", json.dumps({"at": "2026-01-02", "target": "127.0.0.1", "open_ports": [{"port": 443}]}))
    with connect(tmp_path) as db:
        add_finding(db, "127.0.0.1", "TCP port 443 open", "info", "Observed", tcp)
    assert [r["file"] for r in search_evidence(tmp_path, check="ssh", port=22)] == [ssh]
    assert [r["file"] for r in search_evidence(tmp_path, port=443, severity="info")] == [tcp]
    assert search_evidence(tmp_path, since="2026-01-03") == []
