import pytest
from redforge.core import initialize, connect, add_scope, allowed, require_target, authorize


def test_scope_enforcement(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "192.0.2.0/28", "Lab authorization")
        assert allowed(db, "192.0.2.4")
        assert not allowed(db, "192.0.2.33")
        assert not allowed(db, "example.com")
        with pytest.raises(ValueError, match="Authorization"):
            require_target(db, "192.0.2.4")
        authorize(db, True)
        assert require_target(db, "192.0.2.4") == "192.0.2.4"
        with pytest.raises(ValueError, match="outside"):
            require_target(db, "192.0.2.33")
        with pytest.raises(ValueError, match="literal"):
            require_target(db, "example.com")


def test_ipv6(tmp_path):
    initialize(tmp_path, "Test")
    with connect(tmp_path) as db:
        add_scope(db, "2001:db8::/126", "Lab")
        authorize(db, True)
        assert require_target(db, "2001:db8::2") == "2001:db8::2"
        with pytest.raises(ValueError):
            require_target(db, "2001:db8::9")
