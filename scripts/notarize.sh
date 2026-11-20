#!/bin/sh
# Notarize and staple signed release files, e.g.: scripts/notarize.sh dist/bacscan-0.1.2.pkg dist/bacscan-0.1.0.dmg
# One-time setup (app-specific password from account.apple.com):
#   xcrun notarytool store-credentials bacscan --apple-id <apple id> --team-id <TEAM>
set -eu
PROFILE="${BACSCAN_NOTARY_PROFILE:-bacscan}"
[ $# -gt 0 ] || { echo "usage: $0 FILE.pkg|FILE.dmg ..." >&2; exit 2; }
for f in "$@"; do
    echo "notarizing $f ..."
    xcrun notarytool submit "$f" --keychain-profile "$PROFILE" --wait
    xcrun stapler staple "$f"
    xcrun stapler validate "$f"
    case "$f" in
        *.pkg) spctl --assess --type install -vv "$f" ;;
        *.dmg) spctl --assess --type open --context context:primary-signature -vv "$f" ;;
    esac
done
