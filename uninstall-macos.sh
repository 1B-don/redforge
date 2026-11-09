#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This uninstaller runs on macOS only." >&2
  exit 1
fi
APPS_DIR="${REDFORGE_MAC_APPS_DIR:-${HOME}/Applications}"
SUPPORT_DIR="${REDFORGE_MAC_SUPPORT_DIR:-${HOME}/Library/Application Support/RedForge}"
rm -rf "$APPS_DIR/RedForge.app" "$SUPPORT_DIR/venv"
echo "Removed RedForge app and runtime. Engagement data remains at $SUPPORT_DIR/engagement"
