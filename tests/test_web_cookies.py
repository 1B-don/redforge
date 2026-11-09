import json
from unittest.mock import patch

from redforge.core import initialize, connect, add_scope, authorize
from redforge.webcheck import check


class FakeResponse:
    status = 200

    def read(self, _):
        return b''

    def getheaders(self):
        return [('Content-Type', 'text/html'),
                ('Set-Cookie', 'session=very-secret; HttpOnly; SameSite=None'),
                ('Set-Cookie', 'theme=dark; Secure; SameSite=Lax')]


class FakeConnection:
    def __init__(self, *_args, **_kwargs):
        pass

    def request(self, *_args, **_kwargs):
        pass

    def getresponse(self):
        return FakeResponse()

    def close(self):
        pass


def test_cookie_flags_recorded_without_values(tmp_path):
    initialize(tmp_path, 'Test')
    with connect(tmp_path) as db:
        add_scope(db, '127.0.0.1/32', 'Local')
        authorize(db, True)
    with patch('redforge.webcheck.http.client.HTTPSConnection', FakeConnection):
        result = check(tmp_path, '127.0.0.1', 443, tls=True)
    assert len(result['cookies']) == 2
    assert 'SameSite=None without Secure' in result['cookies'][0]['issues']
    evidence = next((tmp_path / 'evidence').glob('http-*.json')).read_text()
    assert 'very-secret' not in evidence
    assert 'session' in evidence
    with connect(tmp_path) as db:
        assert db.execute("SELECT 1 FROM findings WHERE title LIKE 'Cookie flag observation:%'").fetchone()
