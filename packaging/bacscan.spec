# PyInstaller spec for bacscan.app  —  build with: scripts/build_app.sh
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent
version = {}
exec((ROOT / "src" / "bacscan" / "__init__.py").read_text(), version)
VERSION = version["__version__"]

hidden = [m for m in collect_submodules("bacpypes3") if not m.startswith(("bacpypes3.sc", "bacpypes3.mcp"))] + collect_submodules("bacscan") + collect_submodules("websockets")
datas = collect_data_files("bacscan") + collect_data_files("bacpypes3")

a = Analysis(
    [str(ROOT / "src" / "bacscan" / "__main__.py")],
    pathex=[str(ROOT / "src")],
    hiddenimports=hidden,
    datas=datas,
    excludes=["tkinter", "bacpypes3.sc", "bacpypes3.mcp", "PySide6.QtWebEngineCore", "PySide6.QtQml", "PySide6.QtQuick",
              "PySide6.QtMultimedia", "PySide6.Qt3DCore", "PySide6.QtPdf", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="bacscan",
    console=False,           # still prints normally when started from a terminal
    argv_emulation=False,
    target_arch=None,        # build machine's architecture (arm64 on Apple Silicon)
    codesign_identity=None,  # ad-hoc; see README for Developer ID signing
    entitlements_file=None,
)
coll = COLLECT(exe, a.binaries, a.datas, name="bacscan")
app = BUNDLE(
    coll,
    name="bacscan.app",
    icon=str(ROOT / "packaging" / "bacscan.icns"),
    bundle_identifier="net.bacscan.app",
    version=VERSION,
    info_plist={
        "CFBundleName": "bacscan",
        "CFBundleDisplayName": "bacscan",
        "CFBundleShortVersionString": VERSION,
        "CFBundleVersion": VERSION,
        "LSMinimumSystemVersion": "13.0",
        "NSHighResolutionCapable": True,
        "NSLocalNetworkUsageDescription":
            "bacscan searches the local network for BACnet building automation devices "
            "and collects network information (DHCP, DNS, gateway, hosts).",
        "LSApplicationCategoryType": "public.app-category.developer-tools",
    },
)
