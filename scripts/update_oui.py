"""Refresh the bundled MAC vendor table from Wireshark's manuf file.

Usage: uv run python scripts/update_oui.py [path-to-manuf]
Without a path the file is downloaded from https://www.wireshark.org/download/automated/data/manuf
"""
import sys
import tempfile
import urllib.request
from pathlib import Path

from bacscan.core.oui import build_table

URL = "https://www.wireshark.org/download/automated/data/manuf"
OUT = Path(__file__).resolve().parent.parent / "src" / "bacscan" / "data" / "oui.tsv.gz"

if len(sys.argv) > 1:
    src = Path(sys.argv[1])
else:
    tmp = tempfile.mkdtemp()
    src = Path(tmp) / "manuf"
    print(f"downloading {URL}")
    urllib.request.urlretrieve(URL, src)
n = build_table(src, OUT)
print(f"wrote {n} entries to {OUT} ({OUT.stat().st_size // 1024} KiB)")
