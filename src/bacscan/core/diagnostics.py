"""Human readable view of the per-device read diagnostics (Device.diag)."""
from __future__ import annotations

from .models import Device


def diag_rows(d: Device) -> list[tuple[str, str]]:
    """(label, text) rows describing how reading this device went; empty if nothing was recorded."""
    g = d.diag
    if not g:
        return []
    rows: list[tuple[str, str]] = [
        ("requests", f"{g.get('requests', 0)} sent, {g.get('timeouts', 0)} without answer, "
                     f"{g.get('failures', 0)} refused/failed, {g.get('busy_seconds', 0)} s waiting"),
        ("read mode", f"{g.get('read_mode', '?')}, {g.get('props_per_rpm', '?')} properties and "
                      f"{g.get('objects_per_rpm', '?')} object(s) per request"),
        ("device limits", f"max APDU {g.get('max_apdu') or '?'}, segmentation {g.get('segmentation') or '?'}"),
        ("timeout", f"{g.get('apdu_timeout', '?')} s x {int(g.get('retries', 0)) + 1} tries"),
    ]
    if g.get("object_list_mode"):
        rows.append(("object list", g["object_list_mode"]))
    for s in g.get("slowest", [])[:3]:
        rows.append(("slow request", f"{s['seconds']} s  {s['request']}"))
    for e in g.get("events", []):
        rows.append(("event", e))
    if d.status in ("failed", "partial") and g.get("last_request"):
        rows.append(("last request", g["last_request"]))
    return rows


def hint(d: Device) -> str:
    """One-line guess why a device is slow or incomplete; empty when it looks fine."""
    g = d.diag
    if not g:
        return ""
    if g.get("timeouts", 0) >= 3 and g.get("requests", 0) <= g.get("timeouts", 0) + 2:
        return "device hardly answers: check routing / firewall, or raise the timeout"
    if g.get("timeouts", 0):
        return "some requests got no answer: device busy, or reply too large for its max APDU"
    if "element by element" in (g.get("object_list_mode") or "") and (g.get("busy_seconds") or 0) > 60:
        return "long object list on a small max APDU is read one object at a time (slow but complete)"
    return ""
