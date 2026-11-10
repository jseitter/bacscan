"""Offline MAC address vendor (OUI) lookup.

Data: src/bacscan/data/oui.tsv.gz, built from the Wireshark 'manuf' file with
`uv run python scripts/update_oui.py`.
"""
from __future__ import annotations

import gzip
import re
from functools import lru_cache
from importlib import resources
from pathlib import Path

_HEX = re.compile(r"[^0-9a-f]")


def normalize_mac(mac: str | None) -> str | None:
    """'f2:23:3a:7d:66:1' / 'F223.3A7D.6601' / 'f2-23-...' -> 'f2:23:3a:7d:66:01'."""
    if not mac:
        return None
    mac = mac.strip().lower()
    if ":" in mac or "-" in mac:
        parts = re.split(r"[:-]", mac)
        if len(parts) != 6:
            return None
        try:
            return ":".join(f"{int(p, 16):02x}" for p in parts)
        except ValueError:
            return None
    h = _HEX.sub("", mac)
    if len(h) != 12:
        return None
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac: str) -> bool:
    """Randomized / virtual MACs have bit 1 of the first octet set."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    table: dict[str, str] = {}
    try:
        data = resources.files("bacscan").joinpath("data/oui.tsv.gz").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError):
        return table
    for line in gzip.decompress(data).decode("utf-8").splitlines():
        prefix, _, vendor = line.partition("\t")
        if prefix and vendor:
            table[prefix] = vendor
    return table


def vendor(mac: str | None) -> str:
    """Vendor name for a MAC, '' if unknown. Longest prefix wins (MA-S/MA-M blocks)."""
    mac = normalize_mac(mac)
    if not mac:
        return ""
    h = mac.replace(":", "")
    t = _table()
    for n in (9, 7, 6):
        v = t.get(h[:n])
        if v:
            return v
    if is_locally_administered(mac):
        return "(random/local MAC)"
    return ""


def build_table(manuf_path: str | Path, out_path: str | Path) -> int:
    """Convert a Wireshark 'manuf' file into the compact gzipped TSV. Returns entry count."""
    rows = []
    for line in Path(manuf_path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) < 2:
            continue
        prefix, _, bits = cols[0].strip().partition("/")
        h = _HEX.sub("", prefix.lower())
        nbits = int(bits) if bits else 24
        n = {24: 6, 28: 7, 36: 9}.get(nbits)
        if n is None or len(h) < n:
            continue
        name = (cols[2] if len(cols) > 2 and cols[2].strip() else cols[1]).strip()
        rows.append(f"{h[:n]}\t{name}")
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out_path, "wt", encoding="utf-8", compresslevel=9) as f:
        f.write("\n".join(rows))
    return len(rows)
