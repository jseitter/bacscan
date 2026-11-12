#!/bin/sh
# Build dist/bacscan-<version>.pkg: bacscan.app -> /Applications, 'bacscan' -> /usr/local/bin.
# Uses an existing dist/bacscan.app, or builds it (always with --rebuild).
# Signing: set BACSCAN_INSTALLER_IDENTITY="Developer ID Installer: Name (TEAM)".
set -eu
cd "$(dirname "$0")/.."
if [ "${1:-}" = "--rebuild" ] || [ ! -d dist/bacscan.app ]; then
    ./scripts/build_app.sh
fi
VERSION=$(uv run python -c "import bacscan; print(bacscan.__version__)")
ARCH=$(lipo -archs dist/bacscan.app/Contents/MacOS/bacscan | tr ' ' ',')
WORK=build/pkg
rm -rf "$WORK"
mkdir -p "$WORK/root/Applications"
ditto --noextattr --noqtn dist/bacscan.app "$WORK/root/Applications/bacscan.app"
codesign --verify --deep --strict "$WORK/root/Applications/bacscan.app"  # still intact without xattrs

# component package; not relocatable, so an update never lands in some other copy of the app
pkgbuild --analyze --root "$WORK/root" "$WORK/component.plist" >/dev/null
plutil -replace 0.BundleIsRelocatable -bool NO "$WORK/component.plist"
COPYFILE_DISABLE=1 pkgbuild --quiet --root "$WORK/root" --component-plist "$WORK/component.plist" \
    --identifier net.bacscan.app --version "$VERSION" --install-location / \
    --scripts packaging/pkg/scripts "$WORK/bacscan-app.pkg"

cat > "$WORK/distribution.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>bacscan $VERSION</title>
    <welcome file="welcome.html" mime-type="text/html"/>
    <conclusion file="conclusion.html" mime-type="text/html"/>
    <options customize="never" require-scripts="false" hostArchitectures="$ARCH"/>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <allowed-os-versions><os-version min="13.0"/></allowed-os-versions>
    <choices-outline><line choice="default"><line choice="net.bacscan.app"/></line></choices-outline>
    <choice id="default"/>
    <choice id="net.bacscan.app" visible="false"><pkg-ref id="net.bacscan.app"/></choice>
    <pkg-ref id="net.bacscan.app" version="$VERSION" onConclusion="none">bacscan-app.pkg</pkg-ref>
</installer-gui-script>
XML

OUT="dist/bacscan-$VERSION.pkg"
if [ -n "${BACSCAN_INSTALLER_IDENTITY:-}" ]; then
    productbuild --quiet --distribution "$WORK/distribution.xml" --resources packaging/pkg/resources \
        --package-path "$WORK" --sign "$BACSCAN_INSTALLER_IDENTITY" --timestamp "$OUT"
else
    productbuild --quiet --distribution "$WORK/distribution.xml" --resources packaging/pkg/resources \
        --package-path "$WORK" "$OUT"
fi
du -sh "$OUT"
echo "install: sudo installer -pkg $OUT -target /   (or double-click it)"
