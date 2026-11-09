import hashlib
import json
import zipfile
from unittest.mock import patch

import pytest

from redforge.auto import assess
from redforge.bundle import export_bundle, verify_bundle
from redforge.core import initialize, connect, add_scope, authorize, evidence_file


def test_auto_rejects_any_out_of_scope_target_before_scanning(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local test")
        authorize(db, True)
    with patch("redforge.auto.scan") as scanner:
        with pytest.raises(ValueError, match="outside"):
            assess(tmp_path, ["127.0.0.1", "8.8.8.8"])
        scanner.assert_not_called()


def test_auto_inspects_only_discovered_common_ports(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local test")
        authorize(db, True)
    with patch("redforge.auto.scan", return_value={"open_ports": [{"port": 22}, {"port": 80}, {"port": 443}]}), \
         patch("redforge.auto.check") as web, patch("redforge.auto.inspect") as tls, \
         patch("redforge.auto.inspect_ssh") as ssh:
        web.return_value = {"status": 200, "missing_security_headers": []}
        tls.return_value = {"protocol": "TLSv1.3", "peer_certificate_sha256": "abc"}
        ssh.return_value = {"banner": "SSH-2.0-test"}
        result = assess(tmp_path, ["127.0.0.1"])
    assert len(result["targets"][0]["checks"]) == 4
    assert web.call_count == 2
    tls.assert_called_once()
    ssh.assert_called_once()
    assert result["run_id"] == 1


def test_bundle_contains_database_reports_and_hashed_evidence(tmp_path):
    root = tmp_path / "engagement"
    initialize(root, "Test")
    evidence_file(root, "test", '{"sample": true}')
    output = export_bundle(root, tmp_path / "bundle.zip")
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert {"engagement.sqlite3", "report.html", "report.json", "SHA256.json"} <= names
        manifest = json.loads(archive.read("SHA256.json"))
        assert any(name.startswith("evidence/") for name in manifest)
        for name, digest in manifest.items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == digest
    assert verify_bundle(output)["ok"]


def test_bundle_detects_changed_member(tmp_path):
    root = tmp_path / "engagement"
    initialize(root, "Test")
    output = export_bundle(root, tmp_path / "bundle.zip")
    with zipfile.ZipFile(output) as source:
        members = {name: source.read(name) for name in source.namelist()}
    members["report.json"] = b"changed"
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    assert verify_bundle(output)["changed"] == ["report.json"]
