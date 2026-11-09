#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer runs on macOS only." >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APPS_DIR="${REDFORGE_MAC_APPS_DIR:-${HOME}/Applications}"
SUPPORT_DIR="${REDFORGE_MAC_SUPPORT_DIR:-${HOME}/Library/Application Support/RedForge}"
APP_DIR="${APPS_DIR}/RedForge.app"
PYTHON="${REDFORGE_MAC_PYTHON:-$(command -v python3 || true)}"

if [[ -z "$PYTHON" ]] || ! "$PYTHON" -c 'import sys; assert sys.version_info >= (3, 10)' 2>/dev/null; then
  echo "Python 3.10 or newer is required. Install it, then rerun this installer." >&2
  exit 1
fi
for tool in sips open; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Required macOS tool is missing: $tool" >&2
    exit 1
  fi
done

mkdir -p "$APPS_DIR" "$SUPPORT_DIR"
if [[ ! -x "$SUPPORT_DIR/venv/bin/python" ]]; then
  "$PYTHON" -m venv "$SUPPORT_DIR/venv"
fi
"$SUPPORT_DIR/venv/bin/python" -m pip install --disable-pip-version-check --upgrade "$SOURCE_DIR"

STAGE="$(mktemp -d "${APPS_DIR}/.redforge-install.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
STAGED_APP="$STAGE/RedForge.app"
mkdir -p "$STAGED_APP/Contents/MacOS" "$STAGED_APP/Contents/Resources"

cat > "$STAGED_APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>RedForge</string>
  <key>CFBundleExecutable</key><string>RedForge</string>
  <key>CFBundleIconFile</key><string>RedForge</string>
  <key>CFBundleIdentifier</key><string>io.github.1b-don.redforge</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>RedForge</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.17.0</string>
  <key>CFBundleVersion</key><string>17</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST

cat > "$STAGED_APP/Contents/MacOS/RedForge" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="$(cd -- "$(dirname -- "$0")/../.." && pwd)"
exec open -a Terminal "$APP_DIR/Contents/Resources/launch.command"
LAUNCHER

cat > "$STAGED_APP/Contents/Resources/launch.command" <<'COMMAND'
#!/usr/bin/env bash
set -euo pipefail
SUPPORT_DIR="${HOME}/Library/Application Support/RedForge"
if [[ ! -x "$SUPPORT_DIR/venv/bin/redforge" ]]; then
  echo "RedForge is not installed. Run install-macos.sh from the RedForge package." >&2
  read -r -p "Press Return to close..." _ || true
  exit 1
fi
mkdir -p "$SUPPORT_DIR/engagement"
exec "$SUPPORT_DIR/venv/bin/redforge" gui --root "$SUPPORT_DIR/engagement"
COMMAND
chmod 755 "$STAGED_APP/Contents/MacOS/RedForge" "$STAGED_APP/Contents/Resources/launch.command"

sips -s format icns "$SOURCE_DIR/assets/redforge-512.png" \
  --out "$STAGED_APP/Contents/Resources/RedForge.icns" >/dev/null

if [[ -e "$APP_DIR" ]]; then
  mv "$APP_DIR" "$STAGE/previous.app"
fi
if ! mv "$STAGED_APP" "$APP_DIR"; then
  if [[ -e "$STAGE/previous.app" ]]; then mv "$STAGE/previous.app" "$APP_DIR"; fi
  exit 1
fi
echo "Installed $APP_DIR"
echo "Engagement data: $SUPPORT_DIR/engagement"
echo "Nmap is optional for TCP scans: brew install nmap"
