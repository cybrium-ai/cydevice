#!/usr/bin/env bash
# Convenience installer — drops the right unit file for the OS, after
# `cydevice register` has been run.
set -euo pipefail

OS="$(uname -s)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$OS" in
  Darwin)
    DEST="$HOME/Library/LaunchAgents/ai.cybrium.cydevice.plist"
    cp "$HERE/ai.cybrium.cydevice.plist" "$DEST"
    launchctl bootstrap "gui/$(id -u)" "$DEST" 2>/dev/null || launchctl load "$DEST"
    echo "Installed launchd agent at $DEST"
    echo "Logs: tail -f /tmp/cydevice.out /tmp/cydevice.err"
    ;;
  Linux)
    sudo cp "$HERE/cydevice.service" "$HERE/cydevice.timer" /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now cydevice.timer
    echo "Installed systemd timer."
    echo "Logs: journalctl -u cydevice.service -f"
    ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac
