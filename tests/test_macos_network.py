from unittest.mock import patch

import pytest

from redforge import network


def test_macos_scope_suggestions_filter_public_loopback_and_linklocal():
    sample = """lo0: flags=8049<UP,LOOPBACK,RUNNING> mtu 16384
    inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
    inet 10.1.2.3 netmask 0xffffff00 broadcast 10.1.2.255
    inet6 fe80::1%en0 prefixlen 64
en1: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
    inet 8.8.8.8 netmask 0xffffff00
en2: flags=8863<UP,BROADCAST,RUNNING> mtu 1500
    inet6 fd12::5 prefixlen 64
"""
    with patch.object(network.platform, 'system', return_value='Darwin'), \
         patch.object(network.shutil, 'which', return_value='/sbin/ifconfig'), \
         patch.object(network, '_run', return_value=sample):
        suggestions = network.suggest_local_scopes()
    assert {(s.interface, s.cidr) for s in suggestions} == {
        ('en0', '10.1.2.0/24'), ('en2', 'fd12::/64')}


def test_macos_wifi_mode_control_is_explicitly_unavailable():
    with patch.object(network.platform, 'system', return_value='Darwin'):
        with pytest.raises(RuntimeError, match='only on Linux'):
            network.wifi_interfaces()
        with pytest.raises(RuntimeError, match='only on Linux'):
            network.change_wifi_mode('en0', 'monitor', confirmed=True)
