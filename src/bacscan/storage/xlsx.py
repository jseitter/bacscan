"""Excel export: summary, devices, all objects, one sheet per device, network, hosts."""
from __future__ import annotations

import re
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from ..core import netinfo
from ..core.models import Device, Scan

HEADER_FONT = Font(bold=True, color="FFFFFF")
HEADER_FILL = PatternFill("solid", fgColor="305496")
ERROR_FONT = Font(color="C62828")
_BAD_SHEET_CHARS = re.compile(r"[\[\]:*?/\\]")
_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

DEVICE_COLUMNS = [
    ("Instance", lambda d: d.instance),
    ("Name", lambda d: d.name),
    ("Address", lambda d: d.address),
    ("BACnet network", lambda d: d.network),
    ("BACnet MAC", lambda d: d.mac),
    ("Router", lambda d: d.router),
    ("Vendor", lambda d: d.text("vendor-name")),
    ("Vendor ID", lambda d: d.vendor_id),
    ("Model", lambda d: d.text("model-name")),
    ("Firmware", lambda d: d.text("firmware-revision")),
    ("Application version", lambda d: d.text("application-software-version")),
    ("Description", lambda d: d.text("description")),
    ("Location", lambda d: d.text("location")),
    ("Protocol revision", lambda d: d.text("protocol-revision")),
    ("Max APDU", lambda d: d.max_apdu),
    ("Segmentation", lambda d: d.segmentation),
    ("Ethernet MAC", lambda d: d.eth_mac),
    ("MAC vendor", lambda d: (d.eth_vendor + (" (router)" if d.eth_mac_source == "router" else "")).strip()),
    ("Objects", lambda d: len(d.objects)),
    ("Status", lambda d: d.status),
    ("Errors", lambda d: "; ".join(d.errors)),
]

OBJECT_PROPS = ["object-name", "description", "present-value", "units", "status-flags",
                "reliability", "out-of-service", "event-state"]


def _clean(v):
    if isinstance(v, str):
        return _ILLEGAL_XML.sub("", v)
    return v


def _header(ws: Worksheet, headers: list[str]) -> None:
    ws.append(headers)
    for cell in ws[1]:
        cell.font = HEADER_FONT
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(vertical="center")
    ws.freeze_panes = "A2"


def _finish(ws: Worksheet, max_width: int = 60) -> None:
    if ws.max_row > 1:
        ws.auto_filter.ref = ws.dimensions
    for col in ws.columns:
        width = max((len(str(c.value)) for c in col if c.value is not None), default=8)
        ws.column_dimensions[get_column_letter(col[0].column)].width = min(max(width + 2, 8), max_width)


def _sheet_name(d: Device, used: set[str]) -> str:
    base = _BAD_SHEET_CHARS.sub("_", f"{d.instance} {d.name}".strip())[:31]
    name, n = base, 2
    while name.lower() in used:
        suffix = f" ({n})"
        name = base[:31 - len(suffix)] + suffix
        n += 1
    used.add(name.lower())
    return name


def _object_rows(d: Device):
    for o in d.objects:
        other = "; ".join(f"{k}={v.text if v.error is None else 'ERR ' + v.error}"
                          for k, v in o.props.items() if k not in OBJECT_PROPS)
        yield [o.object_type, o.instance] + [o.text(p) for p in OBJECT_PROPS] + [other]


def export_xlsx(scan: Scan, path: str | Path, per_device_sheets: bool = True) -> None:
    wb = Workbook()

    # summary
    ws = wb.active
    ws.title = "Summary"
    rows = [
        ("Scan", scan.id), ("Site", scan.site), ("Notes", scan.notes), ("Started", scan.started_at),
        ("Finished", scan.finished_at), ("Status", scan.status), ("Level", scan.level),
        ("Interface", scan.interface), ("Local address", scan.local_address),
        ("Devices", len(scan.devices)), ("Objects", scan.object_count), ("Hosts", len(scan.hosts)),
        ("Routers", ", ".join(f"{r.address} -> {r.networks}" for r in scan.routers)),
        ("Tool version", scan.tool_version),
    ]
    for k, v in rows:
        ws.append([k, _clean(v)])
        ws.cell(ws.max_row, 1).font = Font(bold=True)
    ws.column_dimensions["A"].width = 18
    ws.column_dimensions["B"].width = 70

    # devices
    ws = wb.create_sheet("Devices")
    _header(ws, [c[0] for c in DEVICE_COLUMNS])
    for d in scan.devices:
        ws.append([_clean(f(d)) for _, f in DEVICE_COLUMNS])
    _finish(ws)

    # all objects
    obj_headers = ["Type", "Instance"] + OBJECT_PROPS + ["Other properties"]
    ws = wb.create_sheet("Objects")
    _header(ws, ["Device", "Device name"] + obj_headers)
    for d in scan.devices:
        for row in _object_rows(d):
            ws.append([d.instance, _clean(d.name)] + [_clean(v) for v in row])
    _finish(ws)

    # network + hosts
    if scan.network:
        ws = wb.create_sheet("Network")
        _header(ws, ["Item", "Value"])
        for k, v in netinfo.summarize(scan.network):
            ws.append([k, _clean(v)])
        traffic = scan.network.get("bacnet_traffic")
        _finish(ws, max_width=90)
        if traffic:
            ws = wb.create_sheet("BACnet traffic")
            _header(ws, ["Source", "Service", "Count", "First", "Last", "Detail"])
            for e in traffic:
                ws.append([e["source"], e["service"], e["count"], e["first"], e["last"], _clean(e["detail"])])
            _finish(ws)
    if scan.hosts:
        names = {d.instance: d.name for d in scan.devices}
        ws = wb.create_sheet("Hosts")
        _header(ws, ["IP", "MAC", "Vendor", "Hostname", "BACnet instance", "BACnet name", "Note", "Source"])
        for h in scan.hosts:
            ws.append([h.ip, h.mac, _clean(h.vendor), _clean(h.hostname), h.bacnet_instance,
                       _clean(names.get(h.bacnet_instance, "")) if h.bacnet_instance is not None else "",
                       h.note, h.source])
        _finish(ws)

    # one sheet per device: properties, then objects
    if per_device_sheets:
        used = {s.lower() for s in wb.sheetnames}
        for d in scan.devices:
            ws = wb.create_sheet(_sheet_name(d, used))
            _header(ws, ["Property", "Value"])
            for k, v in d.props.items():
                ws.append([k, _clean(v.text if v.error is None else f"error: {v.error}")])
                if v.error:
                    ws.cell(ws.max_row, 2).font = ERROR_FONT
            ws.append([])
            start = ws.max_row + 1
            ws.append(obj_headers)
            for cell in ws[start]:
                cell.font = HEADER_FONT
                cell.fill = HEADER_FILL
            for row in _object_rows(d):
                ws.append([_clean(v) for v in row])
            for col in ws.columns:
                width = max((len(str(c.value)) for c in col if c.value is not None), default=8)
                ws.column_dimensions[get_column_letter(col[0].column)].width = min(max(width + 2, 8), 50)
    wb.save(path)
