"""Qt table models for devices, objects and properties."""
from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QColor

from ..core.models import BacnetObject, Device, Host, PropValue

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
STATUS_COLORS = {"done": "#2e7d32", "partial": "#ef6c00", "failed": "#c62828", "reading": "#1565c0"}
ERROR_COLOR = QColor("#c62828")


class _ListModel(QAbstractTableModel):
    """Table over a list of items; columns are (header, getter) pairs."""

    columns: list[tuple[str, Callable[[Any], Any]]] = []

    def __init__(self, parent=None):
        super().__init__(parent)
        self.items: list[Any] = []

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.items)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.columns[section][0]
        return None

    def raw(self, item: Any, column: int) -> Any:
        return self.columns[column][1](item)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        item = self.items[index.row()]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            v = self.raw(item, index.column())
            return "" if v is None else str(v)
        if role == SORT_ROLE:
            v = self.raw(item, index.column())
            return v if isinstance(v, (int, float)) else ("" if v is None else str(v).lower())
        return self.extra_data(item, index.column(), role)

    def extra_data(self, item: Any, column: int, role: int) -> Any:
        return None

    def set_items(self, items: list[Any]) -> None:
        self.beginResetModel()
        self.items = list(items)
        self.endResetModel()

    def sync(self, items: list[Any]) -> None:
        """Append new items (lists only grow during a scan) and refresh the rest."""
        known = {id(x) for x in self.items}
        new = [x for x in list(items) if id(x) not in known]
        if new:
            self.beginInsertRows(QModelIndex(), len(self.items), len(self.items) + len(new) - 1)
            self.items.extend(new)
            self.endInsertRows()
        if self.items:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self.items) - 1, len(self.columns) - 1))


class DeviceModel(_ListModel):
    columns = [
        ("Instance", lambda d: d.instance),
        ("Name", lambda d: d.name),
        ("Address", lambda d: d.address),
        ("Net", lambda d: d.network),
        ("Vendor", lambda d: d.text("vendor-name") or d.vendor_id),
        ("Model", lambda d: d.text("model-name")),
        ("Firmware", lambda d: d.text("firmware-revision")),
        ("App version", lambda d: d.text("application-software-version")),
        ("Location", lambda d: d.text("location")),
        ("MAC", lambda d: d.eth_mac),
        ("MAC vendor", lambda d: (d.eth_vendor + (" (router)" if d.eth_mac_source == "router" else "")).strip()),
        ("Switch port", lambda d: d.switch_port),
        ("Objects", lambda d: len(d.objects)),
        ("Status", lambda d: d.status + (f" ({len(d.errors)} err)" if d.errors else "")),
    ]

    def extra_data(self, item: Device, column: int, role: int) -> Any:
        if role == Qt.ItemDataRole.ForegroundRole and self.columns[column][0] == "Status":
            c = STATUS_COLORS.get(item.status)
            return QColor(c) if c else None
        if role == Qt.ItemDataRole.ToolTipRole and item.errors:
            return "\n".join(item.errors)
        return None


def display_value(o: BacnetObject) -> str:
    """Present value with its state text for binary / multi-state objects."""
    pv = o.props.get("present-value")
    if pv is None or pv.error:
        return ""
    if o.object_type.startswith("multi-state"):
        states = o.props.get("state-text")
        if states and isinstance(states.value, list) and isinstance(pv.value, int) \
                and 1 <= pv.value <= len(states.value):
            return f"{pv.text} ({states.value[pv.value - 1]})"
    if o.object_type.startswith("binary"):
        label = o.text("active-text" if pv.value == "active" else "inactive-text")
        if label:
            return f"{pv.text} ({label})"
    return pv.text


class ObjectModel(_ListModel):
    columns = [
        ("Type", lambda o: o.object_type),
        ("Instance", lambda o: o.instance),
        ("Name", lambda o: o.name),
        ("Present value", display_value),
        ("Units", lambda o: o.text("units")),
        ("Description", lambda o: o.text("description")),
        ("Status flags", lambda o: o.text("status-flags")),
        ("Reliability", lambda o: o.text("reliability")),
        ("Out of service", lambda o: o.text("out-of-service")),
    ]

    def extra_data(self, item: BacnetObject, column: int, role: int) -> Any:
        if role == Qt.ItemDataRole.ForegroundRole:
            if item.text("out-of-service") == "true" or item.text("status-flags"):
                return QColor("#ef6c00")
        return None


class PropertyModel(_ListModel):
    """Key/value rows. Items are (name, PropValue-or-str)."""

    columns = [
        ("Property", lambda kv: kv[0]),
        ("Value", lambda kv: kv[1] if isinstance(kv[1], str)
         else (kv[1].text if kv[1].error is None else f"error: {kv[1].error}")),
    ]

    def extra_data(self, item, column: int, role: int) -> Any:
        if role == Qt.ItemDataRole.ForegroundRole and isinstance(item[1], PropValue) and item[1].error:
            return ERROR_COLOR
        return None

    def show_device(self, d: Device | None) -> None:
        if d is None:
            self.set_items([])
            return
        meta: list[tuple[str, Any]] = [
            ("(address)", d.address),
            ("(status)", d.status),
            ("(vendor id)", str(d.vendor_id or "")),
            ("(max APDU)", str(d.max_apdu or "")),
            ("(segmentation)", d.segmentation or ""),
            ("(first seen)", d.first_seen),
        ]
        if d.network is not None:
            meta += [("(network)", str(d.network)), ("(MAC)", d.mac or ""), ("(router)", d.router or "")]
        meta += [(f"(error {i + 1})", e) for i, e in enumerate(d.errors)]
        self.set_items(meta + list(d.props.items()))

    def show_object(self, o: BacnetObject | None) -> None:
        self.set_items([] if o is None else [("(object)", o.key)] + list(o.props.items()))


class HostModel(_ListModel):
    columns = [
        ("IP", lambda h: _ip_sort(h.ip)),
        ("MAC", lambda h: h.mac),
        ("Vendor", lambda h: h.vendor),
        ("Hostname", lambda h: h.hostname),
        ("BACnet", lambda h: h.bacnet_instance),
        ("Note", lambda h: h.note),
        ("Kind", lambda h: h.kind),
        ("Ping ms", lambda h: h.rtt_ms),
        ("Open TCP ports", lambda h: " ".join(map(str, h.ports))),
        ("Switch port", lambda h: h.switch_port),
        ("Source", lambda h: h.source),
    ]

    @staticmethod
    def detail_rows(h: Host) -> list[tuple[str, str]]:
        rows = [("IP", h.ip), ("MAC", f"{h.mac} {h.vendor}".strip()), ("Hostname", h.hostname),
                ("Kind", h.kind), ("Note", h.note), ("Switch port", h.switch_port)]
        if h.rtt_ms is not None:
            rows.append(("Ping", f"{h.rtt_ms:.1f} ms, TTL {h.ttl} ({h.os_hint})"))
        if h.layers:
            rows.append(("Answered on", ", ".join(h.layers)))
        rows += list(h.services.items())
        return [(k, v) for k, v in rows if v]

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if index.isValid() and index.column() == 0 and role in (Qt.ItemDataRole.DisplayRole,
                                                                 Qt.ItemDataRole.ToolTipRole):
            return self.items[index.row()].ip
        return super().data(index, role)

    def extra_data(self, item: Host, column: int, role: int) -> Any:
        if role == Qt.ItemDataRole.ForegroundRole and item.bacnet_instance is not None:
            return QColor(STATUS_COLORS["done"])
        return None


class TrafficModel(_ListModel):
    """Rows of scan.network['bacnet_traffic'] (listen mode)."""

    columns = [
        ("Source", lambda e: e["source"]),
        ("Service", lambda e: e["service"]),
        ("Count", lambda e: e["count"]),
        ("Detail", lambda e: e["detail"]),
        ("First", lambda e: e["first"][11:19]),
        ("Last", lambda e: e["last"][11:19]),
    ]


def _ip_sort(ip: str) -> int:
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
        return (a << 24) | (b << 16) | (c << 8) | d
    except ValueError:
        return 0


class FilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSortRole(SORT_ROLE)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setFilterKeyColumn(-1)
