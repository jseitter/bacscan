#!/bin/sh
# Build dist/bacscan.app (and dist/bacscan-<version>.dmg) on macOS.
# Signing: ad-hoc by default; set BACSCAN_APP_IDENTITY="Developer ID Application: Name (TEAM)" for distribution.
set -eu
cd "$(dirname "$0")/.."
uv sync --quiet
[ -f packaging/bacscan.icns ] || uv run python packaging/make_icon.py
rm -rf build dist
uv run pyinstaller --noconfirm --clean --log-level WARN --distpath dist --workpath build packaging/bacscan.spec
VERSION=$(uv run python -c "import bacscan; print(bacscan.__version__)")
install -m 755 packaging/pkg/uninstall.sh dist/bacscan.app/Contents/Resources/uninstall.sh
if [ -n "${BACSCAN_APP_IDENTITY:-}" ]; then
    codesign --force --deep --options runtime --timestamp --entitlements packaging/entitlements.plist \
        --sign "$BACSCAN_APP_IDENTITY" dist/bacscan.app
else
    codesign --force --deep --sign - dist/bacscan.app  # ad-hoc signature (local use)
fi
codesign --verify --deep --strict dist/bacscan.app

# disk image: the app, an Applications shortcut to drag it onto, and the app icon as volume icon
DMG="dist/bacscan-$VERSION.dmg"
STAGE=build/dmg
rm -rf "$STAGE" build/rw.dmg
mkdir -p "$STAGE"
ditto dist/bacscan.app "$STAGE/bacscan.app"
ln -s /Applications "$STAGE/Applications"
cp packaging/bacscan.icns "$STAGE/.VolumeIcon.icns"
hdiutil create -quiet -volname "bacscan $VERSION" -srcfolder "$STAGE" -fs HFS+ -format UDRW -ov build/rw.dmg
MNT=$(mktemp -d /tmp/bacscan-dmg.XXXXXX)
hdiutil attach -quiet -nobrowse -noautoopen -mountpoint "$MNT" build/rw.dmg
# Finder flag "has custom icon" (byte 8 of FinderInfo) on the volume root
xattr -wx com.apple.FinderInfo 0000000000000000040000000000000000000000000000000000000000000000 "$MNT"
hdiutil detach -quiet "$MNT"
rmdir "$MNT" 2>/dev/null || true
hdiutil convert -quiet build/rw.dmg -format UDZO -ov -o "$DMG"
rm -f build/rw.dmg
if [ -n "${BACSCAN_APP_IDENTITY:-}" ]; then
    codesign --force --timestamp --sign "$BACSCAN_APP_IDENTITY" "$DMG"
fi
du -sh dist/bacscan.app "$DMG"
echo "CLI: dist/bacscan.app/Contents/MacOS/bacscan --help"
