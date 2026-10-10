# RedForge 0.9.1 — TCP Scan Hotfix

Fixes `NameError: name 'stdout' is not defined` during successful TCP scans. Adds a regression test for successful Nmap XML parsing. Other 0.9 features remain unchanged.

## Install

```bash
cd ~/Downloads
unzip RedForge-0.9.1-Scanner-Fix.zip
cd redforge-0.9.1
./install-desktop.sh
```

Reopen RedForge from the application menu. Existing engagement data in `~/.local/share/redforge` is preserved.

To validate locally: `python3 -m pytest -q` after installing developer dependencies.
