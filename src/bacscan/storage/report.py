"""Site report (spec §4.8): one self-contained HTML file, or PDF rendered with Qt.

The HTML sticks to what Qt's rich-text engine understands (tables with attributes, simple CSS),
so the PDF and the browser view show the same content.
"""
from __future__ import annotations

import os
from collections import Counter
from html import escape
from pathlib import Path
from typing import Any, Iterable

from .. import __version__
from ..core import netinfo
from ..core.findings import SEVERITIES, Finding, findings
from ..core.models import Device, Scan

SEV_COLOR = {"critical": "#c62828", "warning": "#e65100", "info": "#1565c0"}
HEAD_BG = "#305496"
ZEBRA = "#f2f5fa"

CSS = """
body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 10pt;
       color: #222; margin: 24px; }
h1 { font-size: 20pt; margin-bottom: 2px; color: #1f3864; }
h2 { font-size: 14pt; margin-top: 22px; color: #1f3864; border-bottom: 1px solid #c5d0e6; }
h3 { font-size: 11pt; margin-top: 14px; margin-bottom: 4px; }
table { border-collapse: collapse; margin-top: 4px; }
th { background-color: #305496; color: white; text-align: left; font-weight: bold; }
td, th { padding: 3px 6px; vertical-align: top; }
.muted { color: #666; }
.small { font-size: 8.5pt; }
.sev { font-weight: bold; }
@media print { body { margin: 0; } h2 { page-break-after: avoid; } }
"""


def _e(v: Any) -> str:
    return "" if v is None else escape(str(v))


def _table(headers: list[str], rows: Iterable[list[Any]], widths: list[int] | None = None,
           small: bool = False) -> str:
    cls = ' class="small"' if small else ""
    out = [f'<table width="100%" border="0" cellspacing="0" cellpadding="3"{cls}><tr>']
    for i, h in enumerate(headers):
        w = f' width="{widths[i]}%"' if widths else ""
        out.append(f'<th bgcolor="{HEAD_BG}"{w}><font color="white">{_e(h)}</font></th>')
    out.append("</tr>")
    for n, row in enumerate(rows):
        bg = f' bgcolor="{ZEBRA}"' if n % 2 else ""
        out.append(f"<tr{bg}>" + "".join(f"<td>{c if isinstance(c, _Raw) else _e(c)}</td>" for c in row) + "</tr>")
    out.append("</table>")
    return "".join(out)


class _Raw(str):
    """Cell content that is already HTML."""


def _service_order(key: str) -> tuple[int, str]:
    head = key.split("/", 1)[0]
    return (int(head), key) if head.isdigit() else (-1, key)


def _kv(rows: list[tuple[str, Any]]) -> str:
    return _table(["Item", "Value"], [[k, v] for k, v in rows if v not in (None, "")], widths=[28, 72])


def _type_counts(d: Device) -> str:
    c = Counter(o.object_type for o in d.objects)
    return ", ".join(f"{t} {n}" for t, n in sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))


def _options(scan: Scan) -> str:
    s = scan.settings or {}
    opts = []
    if s.get("deep"):
        opts.append("deep discovery")
    elif s.get("sweep"):
        opts.append("subnet sweep")
    if s.get("switch_info"):
        opts.append("switch port (LLDP/CDP)")
    if (scan.network or {}).get("snmp"):
        opts.append("SNMP")
    if s.get("bbmd"):
        opts.append(f"BBMD {s['bbmd']}")
    if s.get("targets"):
        opts.append("targets " + ", ".join(s["targets"]))
    return ", ".join(opts)


def _finding_html(f: Finding) -> str:
    color = SEV_COLOR[f.severity]
    items = ""
    if f.items:
        shown = f.items[:25]
        more = f" … and {len(f.items) - 25} more" if len(f.items) > 25 else ""
        items = '<br/><span class="small">' + _e("; ".join(shown)) + _e(more) + "</span>"
    return (f'<tr><td width="12%"><font color="{color}"><b>{f.severity.upper()}</b></font></td>'
            f"<td><b>{_e(f.title)}</b><br/>{_e(f.detail)}{items}</td></tr>")


def build_html(scan: Scan, objects: bool = False, author: str = "") -> str:
    fs = findings(scan)
    net = scan.network or {}
    title = f"BACnet & network site report — {scan.site or 'unnamed site'}"
    p: list[str] = [f"<html><head><meta charset='utf-8'><title>{_e(title)}</title>"
                    f"<style>{CSS}</style></head><body>"]
    p.append(f"<h1>{_e(scan.site or 'Unnamed site')}</h1>")
    p.append(f'<p class="muted">BACnet &amp; network site report · scan {_e(scan.id or "-")} · '
             f"{_e((scan.started_at or '')[:16].replace('T', ' '))}"
             + (f" · {_e(author)}" if author else "") + "</p>")
    if scan.notes:
        p.append(f"<p>{_e(scan.notes)}</p>")

    # summary
    hosts_with_ports = sum(1 for h in scan.hosts if h.ports)
    services = sum(len(h.ports) for h in scan.hosts)
    remote_nets = sorted({n for r in scan.routers for n in r.networks})
    sev = Counter(f.severity for f in fs)
    p.append("<h2>Summary</h2>")
    p.append(_kv([
        ("BACnet devices", len(scan.devices)),
        ("BACnet objects", scan.object_count),
        ("BACnet routers", f"{len(scan.routers)} (remote networks: {', '.join(map(str, remote_nets))})"
         if scan.routers else "none found"),
        ("IP hosts seen", len(scan.hosts)),
        ("Open TCP services", f"{services} on {hosts_with_ports} host(s)" if any(h.layers for h in scan.hosts)
         else "not checked (no deep discovery)"),
        ("Internet", (net.get("internet") or {}).get("status", "not checked")),
        ("Findings", ", ".join(f"{sev[s]} {s}" for s in SEVERITIES if sev[s]) or "none"),
        ("Interface", f"{scan.interface} {scan.local_address}".strip()),
        ("Scan", f"level {scan.level}, {scan.status}" + (f", {_options(scan)}" if _options(scan) else "")),
        ("Started / finished", f"{scan.started_at or ''} / {scan.finished_at or ''}"),
        ("Tool", f"bacscan {scan.tool_version or __version__}"),
    ]))

    # findings
    p.append("<h2>Findings</h2>")
    if fs:
        p.append('<table width="100%" border="0" cellspacing="0" cellpadding="4">')
        p.extend(_finding_html(f) for f in fs)
        p.append("</table>")
        p.append('<p class="small muted">Findings are observations from this scan, not a security audit.</p>')
    else:
        p.append("<p>No findings.</p>")

    # network
    if net:
        p.append("<h2>Network environment</h2>")
        p.append(_kv(netinfo.summarize(net)))

    # BACnet devices
    p.append("<h2>BACnet devices</h2>")
    if scan.devices:
        p.append(_table(
            ["Inst.", "Name", "Address", "Vendor / model", "Firmware", "MAC", "Obj.", "Status"],
            [[d.instance, d.name, d.address + (f" (net {d.network})" if d.network is not None else ""),
              " / ".join(x for x in (d.text("vendor-name"), d.text("model-name")) if x),
              " / ".join(x for x in (d.text("firmware-revision"), d.text("application-software-version")) if x),
              (f"{d.eth_mac} {d.eth_vendor}" + (" (router)" if d.eth_mac_source == "router" else "")).strip()
              if d.eth_mac else "",
              len(d.objects), d.status] for d in scan.devices],
            widths=[8, 16, 14, 18, 14, 16, 6, 8], small=True))
        if scan.routers:
            p.append("<h3>Routers</h3>")
            p.append(_table(["Router", "Remote networks"],
                            [[r.address, ", ".join(map(str, r.networks))] for r in scan.routers], widths=[30, 70]))
        if any(d.objects for d in scan.devices):
            p.append("<h3>Objects per device</h3>")
            p.append(_table(["Device", "Object types"],
                            [[f"{d.instance} {d.name}", _type_counts(d)] for d in scan.devices if d.objects],
                            widths=[30, 70], small=True))
        located = [d for d in scan.devices if d.text("location") or d.text("description")]
        if located:
            p.append("<h3>Description / location</h3>")
            p.append(_table(["Device", "Description", "Location"],
                            [[f"{d.instance} {d.name}", d.text("description"), d.text("location")] for d in located],
                            widths=[30, 40, 30], small=True))
    else:
        p.append("<p>No BACnet devices found.</p>")

    # hosts
    if scan.hosts:
        names = {d.instance: d.name for d in scan.devices}
        deep = any(h.layers for h in scan.hosts)
        p.append("<h2>IP hosts</h2>")
        headers = ["IP", "MAC / vendor", "Name", "Kind / note"] + (["Ping", "Open TCP ports"] if deep else [])
        rows = []
        for h in scan.hosts:
            note = "" if h.note and h.note in h.kind else h.note
            kind = ", ".join(x for x in (
                h.kind, note,
                f"BACnet {h.bacnet_instance} {names.get(h.bacnet_instance, '')}".strip()
                if h.bacnet_instance is not None and h.kind != "BACnet device" else "") if x)
            row = [h.ip, f"{h.mac} {h.vendor}".strip(), h.hostname, kind]
            if deep:
                row += [f"{h.rtt_ms:.1f} ms" if h.rtt_ms is not None else "", " ".join(map(str, sorted(h.ports)))]
            rows.append(row)
        p.append(_table(headers, rows, widths=[11, 24, 20, 20, 8, 17] if deep else [14, 32, 27, 27], small=True))
        with_services = [h for h in scan.hosts if h.services]
        if with_services:
            p.append("<h3>Services</h3>")
            srows = []
            for h in with_services:
                for k, v in sorted(h.services.items(), key=lambda kv: _service_order(kv[0])):
                    srows.append([f"{h.ip} {h.hostname}".strip(), k, v])
            p.append(_table(["Host", "Service", "Detail"], srows, widths=[22, 18, 60], small=True))

    # SNMP (M9)
    snmp = net.get("snmp") or {}
    if snmp.get("agents"):
        p.append("<h2>SNMP</h2>")
        def agent_row(a: dict) -> list:
            if not a.get("ok"):
                return [a.get("ip"), "", "", f"no data: {a.get('error', 'no answer')}", ""]
            e = a.get("entity") or {}
            model = " / ".join(x for x in (e.get("model"), e.get("serial") and f"S/N {e['serial']}") if x)
            return [a.get("ip"), a.get("sysName", ""), model, a.get("sysDescr", "")[:120], a.get("sysLocation", "")]
        p.append(_table(["Agent", "Name", "Model / serial", "Description", "Location"],
                        [agent_row(a) for a in snmp["agents"]], widths=[11, 16, 20, 37, 16], small=True))
        p.append(f'<p class="small muted">Credentials: {_e(snmp.get("credentials", ""))}</p>')
        port_rows = [[f"BACnet {d.instance} {d.name}".strip(), d.eth_mac or "", d.switch_port]
                     for d in scan.devices if d.switch_port]
        port_rows += [[f"{h.ip} {h.hostname}".strip(), h.mac, h.switch_port] for h in scan.hosts if h.switch_port]
        if port_rows:
            p.append("<h3>Switch ports</h3>")
            p.append(_table(["Device / host", "MAC", "Switch port"], port_rows, widths=[38, 20, 42], small=True))
        lldp_rows = [[a.get("sysName") or a["ip"], n["local_port"], n["remote_name"] or n["remote_chassis"],
                      n["remote_port_desc"] or n["remote_port"]]
                     for a in snmp["agents"] for n in a.get("lldp", [])]
        if lldp_rows:
            p.append("<h3>Switch neighbours (LLDP)</h3>")
            p.append(_table(["Switch", "Port", "Neighbour", "Neighbour port"], lldp_rows,
                            widths=[25, 20, 30, 25], small=True))

    # appendix
    if objects and any(d.objects for d in scan.devices):
        p.append('<h2 style="page-break-before: always">Appendix: object lists</h2>')
        for d in scan.devices:
            if not d.objects:
                continue
            p.append(f"<h3>{_e(d.instance)} {_e(d.name)}</h3>")
            p.append(_table(["Object", "Name", "Present value", "Units", "Description"],
                            [[o.key, o.name, o.text("present-value"), o.text("units"), o.text("description")]
                             for o in d.objects], widths=[18, 24, 16, 14, 28], small=True))

    p.append(f'<p class="small muted">Generated by bacscan {_e(__version__)}. Read-only scan: BACnet Who-Is / '
             "ReadProperty(Multiple) and standard network queries only.</p>")
    p.append("</body></html>")
    return "\n".join(p)


def write_html(scan: Scan, path: str | Path, objects: bool = False, author: str = "") -> None:
    Path(path).write_text(build_html(scan, objects, author), encoding="utf-8")


def write_pdf(scan: Scan, path: str | Path, objects: bool = False, author: str = "") -> None:
    """A4 PDF with a footer (site, page n of m) on every page."""
    from PySide6.QtCore import QMarginsF, QRectF, QSizeF, Qt
    from PySide6.QtGui import (QAbstractTextDocumentLayout, QColor, QFont, QGuiApplication, QPageLayout,
                               QPageSize, QPainter, QPdfWriter, QTextDocument)

    app = None
    if QGuiApplication.instance() is None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # CLI: no window needed
        app = QGuiApplication([])  # noqa: F841 - must live while printing
    writer = QPdfWriter(str(path))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setPageMargins(QMarginsF(14, 14, 14, 12), QPageLayout.Unit.Millimeter)
    writer.setResolution(96)
    writer.setTitle(f"Site report {scan.site}".strip())
    writer.setCreator(f"bacscan {__version__}")

    doc = QTextDocument()
    doc.setDocumentMargin(0)
    font = QFont("Helvetica Neue")
    font.setPointSizeF(9)
    doc.setDefaultFont(font)
    doc.setHtml(build_html(scan, objects, author).replace("margin: 24px", "margin: 0"))
    rect = writer.pageLayout().paintRectPixels(writer.resolution())
    w, footer = rect.width(), 24
    body = rect.height() - footer
    doc.setPageSize(QSizeF(w, body))
    pages = doc.pageCount()
    label = " · ".join(x for x in (scan.site, f"scan {scan.id}" if scan.id else "",
                                   (scan.started_at or "")[:10]) if x)
    painter = QPainter(writer)
    try:
        for i in range(pages):
            if i:
                writer.newPage()
            painter.save()
            clip = QRectF(0, i * body, w, body)
            painter.translate(0, -i * body)
            painter.setClipRect(clip)
            ctx = QAbstractTextDocumentLayout.PaintContext()
            ctx.clip = clip
            doc.documentLayout().draw(painter, ctx)
            painter.restore()
            painter.setPen(QColor("#777777"))
            f = QFont(font)
            f.setPointSizeF(7.5)
            painter.setFont(f)
            r = QRectF(0, body + 6, w, footer - 6)
            painter.drawText(r, Qt.AlignmentFlag.AlignLeft, label)
            painter.drawText(r, Qt.AlignmentFlag.AlignRight, f"page {i + 1} of {pages}")
    finally:
        painter.end()
