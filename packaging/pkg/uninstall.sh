#!/bin/sh
# Remove bacscan: the app, the 'bacscan' command and the installer receipt.
# Your saved scans (~/Library/Application Support/bacscan) are kept unless you pass --purge.
#   sudo /Applications/bacscan.app/Contents/Resources/uninstall.sh [--purge]
set -eu
ROOT="${BACSCAN_UNINSTALL_ROOT:-}"   # for testing only
LINK="$ROOT/usr/local/bin/bacscan"
APP="$ROOT/Applications/bacscan.app"
if [ -z "$ROOT" ] && [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo: sudo $0 $*" >&2
    exit 1
fi
if [ -L "$LINK" ] && readlink "$LINK" | grep -q "bacscan.app/Contents/MacOS/bacscan"; then
    rm -f "$LINK"
    echo "removed $LINK"
fi
if [ -d "$APP" ]; then
    rm -rf "$APP"
    echo "removed $APP"
fi
if [ -z "$ROOT" ]; then
    pkgutil --forget net.bacscan.app >/dev/null 2>&1 && echo "removed installer receipt" || true
fi
if [ "${1:-}" = "--purge" ]; then
    USER_HOME=$(eval echo "~${SUDO_USER:-$USER}")
    rm -rf "$ROOT$USER_HOME/Library/Application Support/bacscan" "$ROOT$USER_HOME/Library/Preferences/bacscan.plist" \
           "$ROOT$USER_HOME/Library/Preferences/com.bacscan.bacscan.plist"
    echo "removed saved scans and settings of ${SUDO_USER:-$USER}"
fi
echo "bacscan uninstalled"
