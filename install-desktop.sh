#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/.local/opt/redforge"
BIN_DIR="${HOME}/.local/bin"
DESKTOP_DIR="${HOME}/.local/share/applications"
DATA_DIR="${HOME}/.local/share/redforge/redforge-engagement"
ICON_ROOT="${HOME}/.local/share/icons/hicolor"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required." >&2
  exit 1
fi

mkdir -p "$APP_DIR" "$BIN_DIR" "$DESKTOP_DIR" "$(dirname "$DATA_DIR")"
# Copy application code, never copy a developer virtualenv or test caches.
cp -r "$SOURCE_DIR/redforge" "$APP_DIR/"
cp "$SOURCE_DIR/pyproject.toml" "$SOURCE_DIR/README.md" "$APP_DIR/"
rm -rf "$APP_DIR/redforge/__pycache__"
# Install branded icons into freedesktop.org hicolor theme directories.
for size in 32 48 64 128 256 512; do
  install -Dm644 "$SOURCE_DIR/assets/redforge-${size}.png" "$ICON_ROOT/${size}x${size}/apps/redforge.png"
done
if [ ! -x "$APP_DIR/.venv/bin/python" ]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/python" -m pip install --disable-pip-version-check "$APP_DIR"

cat > "$BIN_DIR/redforge-desktop" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${HOME}/.local/opt/redforge"
DATA_DIR="${HOME}/.local/share/redforge/redforge-engagement"
cd "${HOME}"
exec "$APP_DIR/.venv/bin/redforge" gui --root "$DATA_DIR"
EOF
cat > "$BIN_DIR/redforge-launch" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
TARGET="${HOME}/.local/bin/redforge-desktop"
if command -v konsole >/dev/null 2>&1; then
  exec konsole --hold -e "$TARGET"
elif command -v xfce4-terminal >/dev/null 2>&1; then
  exec xfce4-terminal --hold --command="$TARGET"
elif command -v gnome-terminal >/dev/null 2>&1; then
  exec gnome-terminal -- "$TARGET"
elif command -v mate-terminal >/dev/null 2>&1; then
  exec mate-terminal -- "$TARGET"
elif command -v xterm >/dev/null 2>&1; then
  exec xterm -e "$TARGET"
else
  echo 'Install a terminal emulator (Konsole, GNOME Terminal, XFCE Terminal, MATE Terminal, or xterm).' >&2
  exit 1
fi
EOF
chmod 755 "$BIN_DIR/redforge-desktop" "$BIN_DIR/redforge-launch"

cat > "$DESKTOP_DIR/redforge.desktop" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=RedForge
GenericName=Security Assessment Workbench
Comment=Launch the keyboard-driven RedForge terminal workbench
Exec=${BIN_DIR}/redforge-launch
Icon=redforge
Terminal=false
Categories=Development;System;Utility;
StartupNotify=true
EOF
chmod 644 "$DESKTOP_DIR/redforge.desktop"
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$DESKTOP_DIR" >/dev/null 2>&1 || true
fi

if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t "$ICON_ROOT" >/dev/null 2>&1 || true
fi
echo "Installed RedForge with branded app icon."
echo "Open your application launcher and search for RedForge."
echo "Your engagement data is stored at: $DATA_DIR"
echo "To use an existing engagement, see the README migration instructions."
