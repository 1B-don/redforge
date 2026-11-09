from unittest.mock import patch

from redforge.core import initialize, connect
from redforge.hostcheck import inspect


def test_macos_host_audit_records_only_definite_disabled_control(tmp_path):
    initialize(tmp_path, 'Test')
    outputs = iter([
        (0, 'Firewall is disabled. (State = 0)'),
        (1, 'Unknown volume'),
        (0, 'System Integrity Protection status: enabled.'),
    ])
    with patch('redforge.hostcheck.platform.system', return_value='Darwin'), \
         patch('redforge.hostcheck._run', side_effect=lambda argv: next(outputs)):
        result = inspect(tmp_path)
    assert [item['status'] for item in result['checks']] == ['disabled', 'unknown', 'enabled']
    with connect(tmp_path) as db:
        rows = db.execute("SELECT title FROM findings").fetchall()
        assert [row[0] for row in rows] == ['Local control disabled: Application firewall']
    assert len(list((tmp_path / 'evidence').glob('host-*.json'))) == 1


def test_linux_host_audit_does_not_mislabel_unknown_firewall(tmp_path):
    initialize(tmp_path, 'Test')
    with patch('redforge.hostcheck.platform.system', return_value='Linux'), \
         patch('redforge.hostcheck.shutil.which', return_value=None):
        result = inspect(tmp_path)
    assert result['checks'] == [{'name': 'Host firewall', 'status': 'unknown'}]
    with connect(tmp_path) as db:
        assert db.execute('SELECT COUNT(*) FROM findings').fetchone()[0] == 0
