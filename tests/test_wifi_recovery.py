from unittest.mock import patch

import pytest

from redforge.network import change_wifi_mode


def test_wifi_restores_previous_mode_after_verification_failure():
    commands = []
    states = iter([[('wlan0', 'managed')], [('wlan0', 'managed')]])

    def run(argv, timeout=12):
        commands.append(argv)
        if 'GENERAL.NM-MANAGED' in argv:
            return 'yes\n'
        return ''

    with patch('redforge.network.wifi_interfaces', side_effect=lambda: next(states)), \
         patch('redforge.network.shutil.which', side_effect=lambda name: f'/usr/bin/{name}'), \
         patch('redforge.network._run', side_effect=run):
        with pytest.raises(RuntimeError, match='not confirmed'):
            change_wifi_mode('wlan0', 'monitor', confirmed=True)
    assert any(cmd[-1] == 'managed' and 'set' in cmd for cmd in commands)
    assert commands[-1][-1] == 'yes'
