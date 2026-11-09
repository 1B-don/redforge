# RedForge 0.15

RedForge is a macOS and Linux terminal workbench for explicitly authorized security assessments. It records scope, observations, evidence, and audit history in a local engagement directory. Active checks require an authorization acknowledgement and a literal IP address within configured scope.

## macOS app

Requires macOS 11 or newer and Python 3.10 or newer. From this repository, run:

```bash
./install-macos.sh
```

The installer creates `~/Applications/RedForge.app` with a branded icon. Double-clicking it opens the keyboard-driven dashboard in Terminal. The Python runtime is installed at `~/Library/Application Support/RedForge/venv`; engagement data is stored at `~/Library/Application Support/RedForge/engagement` and is preserved on reinstall or uninstall. TCP scans require Nmap (`brew install nmap`). Local network suggestions use macOS `ifconfig`; adding a suggested range still requires an authorization reference. Wi-Fi monitor/managed mode switching remains Linux only. Run `./uninstall-macos.sh` to remove the app and runtime while retaining engagement data.

## Linux desktop install

Requires Python 3.10 or newer. The desktop launcher requires a supported Linux terminal emulator. TCP scanning requires Nmap; local interface discovery requires `iproute2`; Wi-Fi tools require `iw`, and mode changes also require `pkexec`.

```bash
git clone https://github.com/1B-don/redforge.git
cd redforge
./install-desktop.sh
```

Or install just the CLI in a virtual environment with `python3 -m pip install .`. Launch the dashboard with `redforge gui`.

In the dashboard, press **C** for Automatic Assessment. The Reports screen offers a complete ZIP export. Press Esc while an assessment is running to cancel it.

## Start an assessment

```bash
redforge init --name "Authorized lab" --root ./redforge-engagement
redforge scope add 192.0.2.10/32 --reason "Written lab authorization" --root ./redforge-engagement
redforge scope add 192.0.2.11/32 --reason "Time-limited authorization" --expires-at 2027-01-01T00:00:00Z --root ./redforge-engagement
redforge authorize --confirm --root ./redforge-engagement
redforge auto-assess 192.0.2.10 --root ./redforge-engagement
redforge runs --root ./redforge-engagement
redforge compare-runs --root ./redforge-engagement
redforge profile-save lab 192.0.2.10 --root ./redforge-engagement
redforge profile-run lab --root ./redforge-engagement
redforge search-findings --host 192.0.2.10 --root ./redforge-engagement
redforge search-evidence --host 192.0.2.10 --check tls --root ./redforge-engagement
redforge overview --root ./redforge-engagement
redforge export-bundle --output ./redforge-bundle.zip --root ./redforge-engagement
redforge verify-bundle ./redforge-bundle.zip
```

`auto-assess` accepts up to 16 explicit IP addresses. It validates all targets before scanning, performs a bounded TCP scan, and checks SSH banners (22), HTTP headers (80/8080), and TLS certificates plus HTTPS headers (443/8443) only when those ports are open. It does not enumerate entire CIDR ranges. Individual check errors are reported while other selected targets continue. TLS evidence includes the peer certificate SHA-256 fingerprint; certificate trust and hostname are not verified by this inspection.

Each automatic assessment saves a numbered snapshot. `compare-runs` compares the latest two by default, or accepts `--before ID --after ID`. It reports opened or closed ports and changed SSH banners, TLS protocols or certificate fingerprints, and HTTP status or missing security headers. Only targets and checks successfully observed in both runs are compared; a failed scan is never treated as a closed port. The dashboard's Advanced Tools screen also compares the latest two runs.

`profile-save` stores target and port selections; `profile-run` rechecks current authorization and scope before any network activity. Automatic runs display change alerts and record them in audit history. The Findings screen and `review-finding` command let an analyst mark an observation `confirmed`, `false_positive`, `resolved`, or `unreviewed` and add a note. Reports include these decisions. `search-findings` and `search-evidence` filter stored records; evidence search includes successful checks that produced no finding. A port filter on findings matches exact TCP port observations, while evidence search includes port fields and TCP scan results.

TLS inspection records subject and issuer common names, DNS and IP subject alternative names, validity dates, and days remaining. It adds observations for expired or soon-to-expire peer certificates. This inspection still does not verify certificate trust or hostname matching.

Scope entries can have an ISO 8601 expiry with timezone. Expired entries remain in history and reports, but no longer permit active checks. `redforge scope remove CIDR` revokes an entry immediately. The dashboard shows active and expired scope counts, and `overview` summarizes scope, finding review progress, assessment runs, and change alerts. `verify-bundle` checks every archive member against the bundled SHA-256 manifest without extracting it. The manifest detects changes but is not a digital signature or proof of origin.

The ZIP export contains HTML and JSON reports, a consistent SQLite snapshot, JSON evidence files, and `SHA256.json` hashes. Treat the export as sensitive engagement data. Hashes detect accidental changes but do not prove who created the bundle.

## Existing data

The desktop launcher uses `~/.local/share/redforge/redforge-engagement`. Reinstalling preserves that directory. To use a different existing engagement, run `redforge gui --root /path/to/engagement`. Back up its entire directory before moving it.

## Development

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

GitHub Actions runs the unit suite on three Python versions. Separate Linux and macOS jobs validate their installers. The Linux job also runs a real loopback Nmap scan and headless dashboard navigation check. Wi-Fi recovery is covered by a simulated failure test; hardware-specific Wi-Fi behavior still requires a compatible Linux adapter for live validation.
