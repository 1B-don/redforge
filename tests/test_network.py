import json
import pytest
from redforge import network


def test_suggest_local_scope_filters_public_and_loopback(monkeypatch):
    rows = [
        {'ifname': 'lo', 'operstate': 'UNKNOWN', 'addr_info': [{'local': '127.0.0.1', 'prefixlen': 8}]},
        {'ifname': 'wlan0', 'operstate': 'UP', 'addr_info': [
            {'local': '192.168.68.102', 'prefixlen': 24},
            {'local': '8.8.8.8', 'prefixlen': 24},
            {'local': 'fe80::1', 'prefixlen': 64}]},
        {'ifname': 'eth0', 'operstate': 'DOWN', 'addr_info': [{'local': '10.2.3.4', 'prefixlen': 16}]},
    ]
    monkeypatch.setattr(network.shutil, 'which', lambda name: '/usr/bin/ip')
    monkeypatch.setattr(network, '_run', lambda argv, timeout=12: json.dumps(rows))
    suggestions = network.suggest_local_scopes()
    assert len(suggestions) == 1
    assert suggestions[0].cidr == '192.168.68.0/24'
    assert suggestions[0].interface == 'wlan0'


def test_wifi_parser(monkeypatch):
    monkeypatch.setattr(network.shutil, 'which', lambda name: '/usr/sbin/iw')
    monkeypatch.setattr(network, '_run', lambda argv, timeout=12: 'phy#0\n\tInterface wlan0\n\t\ttype managed\nphy#1\n\tInterface wlan1\n\t\ttype monitor\n')
    assert network.wifi_interfaces() == [('wlan0', 'managed'), ('wlan1', 'monitor')]


def test_wifi_requires_confirmation_without_running_commands():
    with pytest.raises(ValueError, match='confirmation'):
        network.change_wifi_mode('wlan0', 'monitor')


def test_wifi_rejects_invalid_interface(monkeypatch):
    with pytest.raises(ValueError, match='Invalid interface'):
        network.change_wifi_mode('wlan0;shutdown', 'monitor', confirmed=True)


def test_wifi_rejects_unlisted_interface(monkeypatch):
    monkeypatch.setattr(network, 'wifi_interfaces', lambda: [('wlan0', 'managed')])
    with pytest.raises(ValueError, match='not a detected'):
        network.change_wifi_mode('eth0', 'monitor', confirmed=True)
