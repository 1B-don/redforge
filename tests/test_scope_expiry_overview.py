import json
from datetime import datetime, timedelta, timezone

import pytest

from redforge.core import initialize, connect, add_scope, remove_scope, allowed, authorize, require_target
from redforge.overview import overview
from redforge.report import report


def test_expired_scope_is_not_allowed(tmp_path):
    initialize(tmp_path, "Test")
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local", future)
        authorize(db, True)
        assert allowed(db, "127.0.0.1")
        db.execute("UPDATE scope_expiry SET expires_at=?", ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),))
        db.commit()
        assert not allowed(db, "127.0.0.1")
        with pytest.raises(ValueError, match="outside"):
            require_target(db, "127.0.0.1")
    state = overview(tmp_path)
    assert state["scope_expired"] == 1 and state["scope_active"] == 0
    payload = json.loads(report(tmp_path, tmp_path / "report.json", "json").read_text())
    assert payload["summary"]["scope_expired"] == 1


def test_scope_rejects_expiry_without_timezone(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        with pytest.raises(ValueError, match="timezone"):
            add_scope(db, "127.0.0.1/32", "Local", "2027-01-01T00:00:00")


def test_scope_removal_revokes_access(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "127.0.0.1/32", "Local")
        authorize(db, True)
        remove_scope(db, "127.0.0.1/32")
        assert not allowed(db, "127.0.0.1")
        with pytest.raises(ValueError, match="does not exist"):
            remove_scope(db, "127.0.0.1/32")
