#!/bin/sh
# Build dist/bacscan.app (and dist/bacscan-<version>.dmg) on macOS.
set -eu
cd "$(dirname "$0")/.."
uv sync --quiet
[ -f packaging/bacscan.icns ] || uv run python packaging/make_icon.py
rm -rf build dist
uv run pyinstaller --noconfirm --clean --log-level WARN --distpath dist --workpath build packaging/bacscan.spec
VERSION=$(uv run python -c "import bacscan; print(bacscan.__version__)")
codesign --force --deep --sign - dist/bacscan.app  # ad-hoc signature (local use)
hdiutil create -quiet -volname "bacscan $VERSION" -srcfolder dist/bacscan.app -ov -format UDZO \
    "dist/bacscan-$VERSION.dmg"
du -sh dist/bacscan.app "dist/bacscan-$VERSION.dmg"
echo "CLI: dist/bacscan.app/Contents/MacOS/bacscan --help"
