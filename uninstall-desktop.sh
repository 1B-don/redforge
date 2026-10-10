#!/usr/bin/env bash
set -euo pipefail
rm -f "${HOME}/.local/share/applications/redforge.desktop"
rm -f "${HOME}/.local/bin/redforge-desktop" "${HOME}/.local/bin/redforge-launch"
rm -rf "${HOME}/.local/opt/redforge"
for size in 32 48 64 128 256 512; do
  rm -f "${HOME}/.local/share/icons/hicolor/${size}x${size}/apps/redforge.png"
done
echo "RedForge application removed. Engagement data in ~/.local/share/redforge was preserved."
