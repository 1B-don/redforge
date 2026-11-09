from unittest.mock import patch

from redforge.core import initialize, connect, add_scope, authorize, audit
from redforge.diagnostics import diagnose


def test_doctor_guides_engagement_setup(tmp_path):
    with patch('redforge.diagnostics.shutil.which', return_value=None):
        assert diagnose(tmp_path)['next_step']['screen'] == 'engagement'
    initialize(tmp_path, 'Test')
    with patch('redforge.diagnostics.shutil.which', return_value='/usr/bin/nmap'):
        assert diagnose(tmp_path)['next_step']['screen'] == 'hostaudit'
    with connect(tmp_path) as db:
        audit(db, 'host_audit', 'test')
    with patch('redforge.diagnostics.shutil.which', return_value='/usr/bin/nmap'):
        assert diagnose(tmp_path)['next_step']['screen'] == 'scope'
    with connect(tmp_path) as db:
        add_scope(db, '127.0.0.1/32', 'Local')
    with patch('redforge.diagnostics.shutil.which', return_value='/usr/bin/nmap'):
        assert diagnose(tmp_path)['next_step']['screen'] == 'engagement'
    with connect(tmp_path) as db:
        authorize(db, True)
    with patch('redforge.diagnostics.shutil.which', return_value='/usr/bin/nmap'):
        assert diagnose(tmp_path)['next_step']['screen'] == 'auto'


def test_doctor_reports_missing_nmap(tmp_path):
    initialize(tmp_path, 'Test')
    with connect(tmp_path) as db:
        add_scope(db, '127.0.0.1/32', 'Local')
        authorize(db, True)
        audit(db, 'host_audit', 'test')
    with patch('redforge.diagnostics.shutil.which', return_value=None):
        result = diagnose(tmp_path)
    assert result['next_step']['screen'] == 'readiness'
    assert any(item['name'] == 'Nmap' and item['status'] == 'setup' for item in result['checks'])
