"""bacscan desktop GUI (PySide6)."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QTimer
from PySide6.QtGui import QAction, QBrush, QColor, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDockWidget,
    QDoubleSpinBox,
    QFileDialog,
    QInputDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTabWidget,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from ..core import netinfo
from ..core import network as netmod
from ..core.models import Device, Scan
from ..core.scanner import LEVELS, ScanConfig, ScanEvent
from ..storage.db import Store
from ..storage.diff import diff_lines, diff_scans
from ..storage.export import export_csv, export_hosts_csv, export_json, import_json
from ..storage.xlsx import export_xlsx
from .models import DeviceModel, FilterProxy, HostModel, ObjectModel, PropertyModel, TrafficModel
from .worker import ScanWorker

log = logging.getLogger("bacscan.gui")

LEVEL_HELP = {
    "discover": "only find devices",
    "device": "devices + device details",
    "full": "devices + all objects (standard properties)",
    "all": "everything (all properties, slow)",
}


# ---------------------------------------------------------------- dialogs


class SettingsDialog(QDialog):
    """Advanced scan settings, persisted in QSettings."""

    def __init__(self, settings: QSettings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan settings")
        self.settings = settings
        form = QFormLayout(self)
        self.apdu_timeout = QDoubleSpinBox(minimum=0.5, maximum=30, singleStep=0.5, suffix=" s")
        self.retries = QSpinBox(minimum=0, maximum=5)
        self.concurrency = QSpinBox(minimum=1, maximum=16)
        self.remote_delay = QSpinBox(minimum=0, maximum=1000, suffix=" ms")
        self.local_instance = QSpinBox(minimum=0, maximum=4194302, specialValueText="random")
        self.apdu_timeout.setValue(float(settings.value("apdu_timeout", 3.0)))
        self.retries.setValue(int(settings.value("retries", 2)))
        self.concurrency.setValue(int(settings.value("concurrency", 4)))
        self.remote_delay.setValue(int(settings.value("remote_delay_ms", 50)))
        self.local_instance.setValue(int(settings.value("local_instance", 0)))
        form.addRow("Request timeout", self.apdu_timeout)
        form.addRow("Retries", self.retries)
        form.addRow("Devices in parallel", self.concurrency)
        form.addRow("Pause between requests\n(devices behind routers)", self.remote_delay)
        form.addRow("Own device instance", self.local_instance)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def accept(self) -> None:
        s = self.settings
        s.setValue("apdu_timeout", self.apdu_timeout.value())
        s.setValue("retries", self.retries.value())
        s.setValue("concurrency", self.concurrency.value())
        s.setValue("remote_delay_ms", self.remote_delay.value())
        s.setValue("local_instance", self.local_instance.value())
        super().accept()


class ScanInfoDialog(QDialog):
    """Edit site name and notes of a scan."""

    def __init__(self, site: str, notes: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan details")
        form = QFormLayout(self)
        self.site = QLineEdit(site)
        self.notes = QPlainTextEdit(notes)
        self.notes.setMinimumHeight(120)
        form.addRow("Site", self.site)
        form.addRow("Notes", self.notes)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)


class CompareDialog(QDialog):
    """Pick two saved scans and show what changed."""

    COLORS = {"+": "#2e7d32", "-": "#c62828", "~": "#ef6c00"}

    def __init__(self, store: Store, current_id: int | None, parent=None):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Compare scans")
        self.resize(900, 620)
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        self.a_combo, self.b_combo = QComboBox(), QComboBox()
        scans = store.list()
        for s in scans:
            label = f"{s.id}: {s.started_at.replace('T', ' ')[:16]} · {s.site or '(no site)'} · {s.devices} dev"
            self.a_combo.addItem(label, s.id)
            self.b_combo.addItem(label, s.id)
        ids = [s.id for s in scans]
        b = ids.index(current_id) if current_id in ids else 0
        self.b_combo.setCurrentIndex(b)
        self.a_combo.setCurrentIndex(min(b + 1, len(ids) - 1) if ids else 0)  # list is newest first
        self.values_cb = QCheckBox("Include present values")
        go = QPushButton("Compare")
        go.clicked.connect(self.compare)
        row.addWidget(QLabel("Older"))
        row.addWidget(self.a_combo, 1)
        row.addWidget(QLabel("Newer"))
        row.addWidget(self.b_combo, 1)
        row.addWidget(self.values_cb)
        row.addWidget(go)
        v.addLayout(row)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        v.addWidget(self.tree, 1)
        self.summary = QLabel()
        v.addWidget(self.summary)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        v.addWidget(buttons)
        if len(ids) >= 2:
            self.compare()

    def compare(self) -> None:
        a, b = self.a_combo.currentData(), self.b_combo.currentData()
        if a is None or b is None:
            return
        d = diff_scans(self.store.load(a), self.store.load(b), values=self.values_cb.isChecked())
        self.tree.clear()
        parent = None
        counts = {"+": 0, "-": 0, "~": 0}
        for kind, text in diff_lines(d):
            if kind == "#":
                parent = QTreeWidgetItem(self.tree, [text])
                font = parent.font(0)
                font.setBold(True)
                parent.setFont(0, font)
                continue
            counts[kind] += 1
            item = QTreeWidgetItem(parent or self.tree, [f"{kind} {text}"])
            item.setForeground(0, QBrush(QColor(self.COLORS[kind])))
        self.tree.expandAll()
        self.summary.setText(f"{counts['+']} added · {counts['-']} removed · {counts['~']} changed")


# ---------------------------------------------------------------- main window


def _table(model, stretch_col: int | None = None) -> QTableView:
    t = QTableView()
    t.setModel(model)
    t.setSortingEnabled(True)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(22)
    t.horizontalHeader().setHighlightSections(False)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    if stretch_col is not None:
        t.horizontalHeader().setStretchLastSection(True)
    t.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    t.setWordWrap(False)
    return t


class MainWindow(QMainWindow):
    def __init__(self, db_path: str | Path | None = None, settings: QSettings | None = None):
        super().__init__()
        self.setWindowTitle("bacscan — BACnet scanner")
        self.resize(1400, 860)
        self.settings = settings or QSettings("bacscan", "bacscan")
        self.store = Store(db_path)
        self.scan: Scan | None = None  # scan currently displayed
        self.worker: ScanWorker | None = None
        self.rescan_worker: ScanWorker | None = None
        self._refresh_pending = False

        self._build_toolbar()
        self._build_body()
        self._build_log_dock()
        self._build_menus()
        self._build_statusbar()
        self.reload_history()
        self._set_busy(False)

    # ------------------------------------------------------------ layout

    def _build_toolbar(self) -> None:
        bar = QWidget()
        g = QGridLayout(bar)
        g.setContentsMargins(8, 6, 8, 6)

        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(320)
        refresh = QToolButton(text="↻")
        refresh.setToolTip("Reload network interfaces")
        refresh.clicked.connect(self.reload_interfaces)
        self.port_spin = QSpinBox(minimum=1, maximum=65535, value=int(self.settings.value("port", 47808)))
        self.level_combo = QComboBox()
        for lv in LEVELS:
            self.level_combo.addItem(f"{lv} — {LEVEL_HELP[lv]}", lv)
        self.level_combo.setCurrentIndex(LEVELS.index(self.settings.value("level", "full")))
        self.wait_spin = QDoubleSpinBox(minimum=1, maximum=60, value=float(self.settings.value("wait", 5)), suffix=" s")
        self.wait_spin.setToolTip("How long to wait for devices to answer the Who-Is")
        self.port_spin.setMaximumWidth(90)
        self.wait_spin.setMaximumWidth(90)

        self.site_edit = QLineEdit(placeholderText="Site / building name")
        self.targets_edit = QLineEdit(placeholderText="optional: unicast targets, e.g. 10.1.2.0/24, 10.1.3.5")
        self.targets_edit.setToolTip("Who-Is is also sent directly to these addresses (when broadcasts are blocked)")
        self.bbmd_edit = QLineEdit(placeholderText="optional: BBMD ip[:port]")
        self.range_edit = QLineEdit(placeholderText="optional: 1000-1999")
        self.range_edit.setToolTip("Only devices with an instance number in this range")

        self.scan_btn = QPushButton("▶  Scan")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self.start_scan_from_ui)
        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.listen_btn = QPushButton("Listen…")
        self.listen_btn.setToolTip("Passive mode: record BACnet broadcasts without sending anything")
        self.listen_btn.clicked.connect(self.start_listen_from_ui)

        g.addWidget(QLabel("Interface"), 0, 0)
        row = QHBoxLayout()
        row.addWidget(self.iface_combo, 1)
        row.addWidget(refresh)
        g.addLayout(row, 0, 1)
        g.addWidget(QLabel("Port"), 0, 2)
        port_row = QHBoxLayout()
        port_row.addWidget(self.port_spin)
        port_row.addStretch(1)
        g.addLayout(port_row, 0, 3)
        g.addWidget(QLabel("Level"), 0, 4)
        g.addWidget(self.level_combo, 0, 5)
        g.addWidget(QLabel("Wait"), 0, 6)
        g.addWidget(self.wait_spin, 0, 7)
        g.addWidget(self.scan_btn, 0, 8)

        g.addWidget(QLabel("Site"), 1, 0)
        g.addWidget(self.site_edit, 1, 1)
        g.addWidget(QLabel("Targets"), 1, 2)
        g.addWidget(self.targets_edit, 1, 3)
        g.addWidget(QLabel("Range"), 1, 4)
        g.addWidget(self.range_edit, 1, 5)
        g.addWidget(QLabel("BBMD"), 1, 6)
        g.addWidget(self.bbmd_edit, 1, 7)
        g.addWidget(self.stop_btn, 1, 8)

        def check(text: str, key: str, default: bool, tip: str) -> QCheckBox:
            cb = QCheckBox(text)
            cb.setChecked(str(self.settings.value(key, default)).lower() == "true")
            cb.setToolTip(tip)
            cb.toggled.connect(lambda v: self.settings.setValue(key, v))
            return cb

        self.netinfo_cb = check("Network info", "network_info", True,
                                "Collect DHCP, DNS, gateway, MAC addresses and other hosts")
        self.internet_cb = check("Internet check", "internet_checks", True,
                                 "Test DNS / HTTP / HTTPS reachability of the internet")
        self.sweep_cb = check("Sweep subnet", "sweep", False,
                              "Probe every address of the local subnet (max /22) to find all hosts")
        self.public_ip_cb = check("Public IP", "public_ip", False,
                                  "Look up the public IP address (contacts api.ipify.org)")
        self.switch_cb = check("Switch port (LLDP/CDP)", "switch_info", False,
                               "Wait up to 35 s for the switch to announce itself (name, port, VLAN). "
                               "Needs packet capture rights.")
        self.netinfo_cb.toggled.connect(lambda on: [w.setEnabled(on) for w in
                                                     (self.internet_cb, self.sweep_cb, self.public_ip_cb)])
        checks = QHBoxLayout()
        for cb in (self.netinfo_cb, self.internet_cb, self.sweep_cb, self.public_ip_cb, self.switch_cb):
            checks.addWidget(cb)
        checks.addStretch(1)
        g.addLayout(checks, 2, 1, 1, 7)
        g.addWidget(self.listen_btn, 2, 8)
        g.setColumnStretch(1, 2)
        g.setColumnStretch(3, 2)
        g.setColumnStretch(5, 1)
        self.reload_interfaces()
        self.toolbar_widget = bar

    def _build_body(self) -> None:
        # left: scan history
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(0, 0, 0, 0)
        lv.addWidget(QLabel("<b>Saved scans</b>"))
        self.history = QListWidget()
        self.history.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history.customContextMenuRequested.connect(self._history_menu)
        self.history.currentItemChanged.connect(self._history_selected)
        self.history.itemDoubleClicked.connect(lambda _i: self.edit_scan_info())
        lv.addWidget(self.history)

        # right: devices / objects / properties
        self.device_model = DeviceModel(self)
        self.device_proxy = FilterProxy(self)
        self.device_proxy.setSourceModel(self.device_model)
        self.device_view = _table(self.device_proxy, stretch_col=-1)
        self.device_view.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.device_view.selectionModel().currentRowChanged.connect(self._device_selected)
        self.device_view.customContextMenuRequested.connect(self._device_menu)

        self.object_model = ObjectModel(self)
        self.object_proxy = FilterProxy(self)
        self.object_proxy.setSourceModel(self.object_model)
        self.object_view = _table(self.object_proxy, stretch_col=-1)
        self.object_view.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.object_view.selectionModel().currentRowChanged.connect(self._object_selected)
        self.object_view.customContextMenuRequested.connect(
            lambda pos: self._copy_menu(self.object_view, pos))

        self.prop_model = PropertyModel(self)
        self.prop_view = _table(self.prop_model, stretch_col=1)
        self.prop_view.setSortingEnabled(False)
        self.prop_view.customContextMenuRequested.connect(lambda pos: self._copy_menu(self.prop_view, pos))

        self.device_filter = QLineEdit(placeholderText="Filter devices…", clearButtonEnabled=True)
        self.device_filter.textChanged.connect(self.device_proxy.setFilterFixedString)
        self.object_filter = QLineEdit(placeholderText="Filter objects (name, type, description, value…)",
                                       clearButtonEnabled=True)
        self.object_filter.textChanged.connect(self.object_proxy.setFilterFixedString)

        self.scan_title = QLabel()
        self.scan_title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        dev_box = QWidget()
        dv = QVBoxLayout(dev_box)
        dv.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        head.addWidget(self.scan_title, 1)
        head.addWidget(self.device_filter)
        dv.addLayout(head)
        dv.addWidget(self.device_view)

        self.objects_title = QLabel("<b>Objects</b>")
        obj_box = QWidget()
        ov = QVBoxLayout(obj_box)
        ov.setContentsMargins(0, 0, 0, 0)
        oh = QHBoxLayout()
        oh.addWidget(self.objects_title, 1)
        oh.addWidget(self.object_filter, 2)
        ov.addLayout(oh)
        ov.addWidget(self.object_view)

        self.props_title = QLabel("<b>Properties</b>")
        prop_box = QWidget()
        pv = QVBoxLayout(prop_box)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.addWidget(self.props_title)
        pv.addWidget(self.prop_view)

        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.addWidget(obj_box)
        lower.addWidget(prop_box)
        lower.setSizes([800, 420])
        right = QSplitter(Qt.Orientation.Vertical)
        right.addWidget(dev_box)
        right.addWidget(lower)
        right.setSizes([300, 500])

        # network tab: environment summary | hosts
        self.env_model = PropertyModel(self)
        self.env_view = _table(self.env_model, stretch_col=1)
        self.env_view.setSortingEnabled(False)
        self.env_view.customContextMenuRequested.connect(lambda pos: self._copy_menu(self.env_view, pos))
        self.host_model = HostModel(self)
        self.host_proxy = FilterProxy(self)
        self.host_proxy.setSourceModel(self.host_model)
        self.host_view = _table(self.host_proxy, stretch_col=-1)
        self.host_view.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.host_view.customContextMenuRequested.connect(lambda pos: self._copy_menu(self.host_view, pos))
        self.host_view.doubleClicked.connect(self._host_activated)
        self.host_filter = QLineEdit(placeholderText="Filter hosts (IP, MAC, vendor, name…)", clearButtonEnabled=True)
        self.host_filter.textChanged.connect(self.host_proxy.setFilterFixedString)
        self.hosts_title = QLabel("<b>Hosts</b>")
        env_box = QWidget()
        ev = QVBoxLayout(env_box)
        ev.setContentsMargins(0, 0, 0, 0)
        ev.addWidget(QLabel("<b>Network environment</b>"))
        ev.addWidget(self.env_view)
        host_box = QWidget()
        hv = QVBoxLayout(host_box)
        hv.setContentsMargins(0, 0, 0, 0)
        hh = QHBoxLayout()
        hh.addWidget(self.hosts_title, 1)
        hh.addWidget(self.host_filter, 2)
        hv.addLayout(hh)
        hv.addWidget(self.host_view)
        self.traffic_model = TrafficModel(self)
        self.traffic_proxy = FilterProxy(self)
        self.traffic_proxy.setSourceModel(self.traffic_model)
        self.traffic_view = _table(self.traffic_proxy, stretch_col=-1)
        self.traffic_view.customContextMenuRequested.connect(
            lambda pos: self._copy_menu(self.traffic_view, pos))
        self.traffic_box = QWidget()
        tv = QVBoxLayout(self.traffic_box)
        tv.setContentsMargins(0, 6, 0, 0)
        tv.addWidget(QLabel("<b>BACnet traffic heard</b> (listen mode)"))
        tv.addWidget(self.traffic_view)
        hv.addWidget(self.traffic_box)
        self.traffic_box.hide()
        net_split = QSplitter(Qt.Orientation.Horizontal)
        net_split.addWidget(env_box)
        net_split.addWidget(host_box)
        net_split.setSizes([480, 700])

        self.tabs = QTabWidget()
        self.tabs.addTab(right, "BACnet")
        self.tabs.addTab(net_split, "Network")

        main = QSplitter(Qt.Orientation.Horizontal)
        main.addWidget(left)
        main.addWidget(self.tabs)
        main.setSizes([230, 1170])
        main.setStretchFactor(1, 1)

        central = QWidget()
        cv = QVBoxLayout(central)
        cv.setContentsMargins(6, 0, 6, 6)
        cv.addWidget(self.toolbar_widget)
        cv.addWidget(main, 1)
        self.setCentralWidget(central)

    def _build_log_dock(self) -> None:
        self.log_view = QPlainTextEdit(readOnly=True)
        self.log_view.setMaximumBlockCount(5000)
        dock = QDockWidget("Log", self)
        dock.setObjectName("log")
        dock.setWidget(self.log_view)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, dock)
        dock.hide()
        self.log_dock = dock

    def _build_menus(self) -> None:
        m = self.menuBar()
        f = m.addMenu("&File")
        self._action(f, "Import scan (JSON)…", self.import_scan, "Ctrl+I")
        self.export_json_act = self._action(f, "Export scan as JSON…", lambda: self.export_scan("json"), "Ctrl+E")
        self.export_csv_act = self._action(f, "Export scan as CSV…", lambda: self.export_scan("csv"))
        self.export_hosts_act = self._action(f, "Export hosts as CSV…", lambda: self.export_scan("hosts"))
        self.export_xlsx_act = self._action(f, "Export scan as Excel…", lambda: self.export_scan("xlsx"))
        f.addSeparator()
        self.compare_act = self._action(f, "Compare scans…", self.compare_scans, "Ctrl+D")
        f.addSeparator()
        self.edit_info_act = self._action(f, "Edit site / notes…", self.edit_scan_info)
        self.delete_act = self._action(f, "Delete scan", self.delete_scan)
        f.addSeparator()
        self._action(f, "Quit", self.close, QKeySequence.StandardKey.Quit)

        s = m.addMenu("&Scan")
        self.start_act = self._action(s, "Start scan", self.start_scan_from_ui, "Ctrl+R")
        self.listen_act = self._action(s, "Listen (passive)…", self.start_listen_from_ui)
        self.stop_act = self._action(s, "Stop scan", self.stop_scan, "Ctrl+.")
        s.addSeparator()
        self._action(s, "Settings…", self.open_settings, QKeySequence.StandardKey.Preferences)

        v = m.addMenu("&View")
        v.addAction(self.log_dock.toggleViewAction())
        self.log_dock.toggleViewAction().setShortcut("Ctrl+L")

        h = m.addMenu("&Help")
        self._action(h, "About bacscan", self.about)

    def _action(self, menu: QMenu, text: str, slot, shortcut=None) -> QAction:
        act = QAction(text, self)
        if shortcut is not None:
            act.setShortcut(shortcut)
        act.triggered.connect(slot)
        menu.addAction(act)
        return act

    def _build_statusbar(self) -> None:
        self.status_label = QLabel("Ready")
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(260)
        self.progress.setTextVisible(True)
        self.progress.hide()
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(self.progress)

    # ------------------------------------------------------------ interfaces

    def reload_interfaces(self) -> None:
        current = self.iface_combo.currentData() or self.settings.value("interface")
        self.iface_combo.clear()
        for i in netmod.list_interfaces(include_all=True):
            self.iface_combo.addItem(i.label() + ("" if i.likely_building_network else "  (virtual)"), i.name)
        idx = self.iface_combo.findData(current) if current else -1
        if idx < 0:
            best = netmod.list_interfaces()
            idx = self.iface_combo.findData(best[0].name) if best else 0
        self.iface_combo.setCurrentIndex(max(idx, 0))

    # ------------------------------------------------------------ history

    def reload_history(self, select_id: int | None = None) -> None:
        self.history.blockSignals(True)
        self.history.clear()
        for s in self.store.list():
            when = s.started_at.replace("T", " ")[:16]
            item = QListWidgetItem(f"{when}\n{s.site or '(no site)'} · {s.devices} dev · {s.objects} obj"
                                   + ("" if s.status == "completed" else f" · {s.status}"))
            item.setData(Qt.ItemDataRole.UserRole, s.id)
            item.setToolTip(f"Scan {s.id} · level {s.level}\n{s.interface}\n{s.notes}")
            self.history.addItem(item)
            if s.id == select_id:
                self.history.setCurrentItem(item)
        self.history.blockSignals(False)

    def _history_selected(self, item: QListWidgetItem | None, _prev=None) -> None:
        if item is None or self.worker is not None:
            return
        self.show_scan(self.store.load(item.data(Qt.ItemDataRole.UserRole)))

    def _history_menu(self, pos) -> None:
        item = self.history.itemAt(pos)
        if not item:
            return
        self.history.setCurrentItem(item)
        menu = QMenu(self)
        menu.addAction("Edit site / notes…", self.edit_scan_info)
        menu.addAction("Export as JSON…", lambda: self.export_scan("json"))
        menu.addAction("Export as CSV…", lambda: self.export_scan("csv"))
        menu.addAction("Export hosts as CSV…", lambda: self.export_scan("hosts"))
        menu.addAction("Export as Excel…", lambda: self.export_scan("xlsx"))
        menu.addAction("Compare with…", self.compare_scans)
        menu.addSeparator()
        menu.addAction("Delete", self.delete_scan)
        menu.exec(self.history.mapToGlobal(pos))

    # ------------------------------------------------------------ display

    def show_scan(self, scan: Scan | None) -> None:
        self.scan = scan
        self.device_model.set_items(scan.devices if scan else [])
        self.object_model.set_items([])
        self.prop_model.set_items([])
        self.show_network()
        self._update_titles()
        self._fit_columns(self.device_view)
        if scan and scan.devices:
            self.device_view.selectRow(0)

    def show_network(self) -> None:
        s = self.scan
        self.env_model.set_items(netinfo.summarize(s.network) if s and s.network else [])
        self.host_model.set_items(s.hosts if s else [])
        traffic = s.network.get("bacnet_traffic", []) if s and s.network else []
        self.traffic_model.set_items(traffic)
        self.traffic_box.setVisible(bool(traffic))
        if traffic:
            self._fit_columns(self.traffic_view)
        self.env_view.resizeColumnToContents(0)
        self._fit_columns(self.host_view)
        n = len(s.hosts) if s else 0
        self.hosts_title.setText(f"<b>Hosts</b> ({n})")
        inet = (s.network.get("internet", {}).get("status") if s and s.network else None)
        label = "Network"
        if s and (s.network or s.hosts):
            label += f" ({n} host{'s' if n != 1 else ''}" + (f" · internet {inet}" if inet else "") + ")"
        self.tabs.setTabText(1, label)

    def _host_activated(self, index) -> None:
        """Double-click on a BACnet host jumps to the device."""
        h = self.host_model.items[self.host_proxy.mapToSource(index).row()]
        if h.bacnet_instance is None:
            return
        for row in range(self.device_proxy.rowCount()):
            src = self.device_model.items[self.device_proxy.mapToSource(self.device_proxy.index(row, 0)).row()]
            if src.instance == h.bacnet_instance:
                self.tabs.setCurrentIndex(0)
                self.device_view.selectRow(row)
                return

    def _update_titles(self) -> None:
        s = self.scan
        if s is None:
            self.scan_title.setText("<b>Devices</b>")
        else:
            routers = f" · routers: {', '.join(f'{r.address}→{r.networks}' for r in s.routers)}" if s.routers else ""
            label = f"scan {s.id}" if s.id else "live scan"
            self.scan_title.setText(
                f"<b>Devices</b> ({len(s.devices)}) — {label} · {s.site or 'no site'} · "
                f"{s.started_at.replace('T', ' ')[:19]} · {s.level} · {s.status}{routers}")
        has = s is not None and s.id is not None
        for act in (self.export_json_act, self.export_csv_act, self.export_hosts_act, self.export_xlsx_act,
                    self.edit_info_act, self.delete_act):
            act.setEnabled(has and self.worker is None)

    def selected_device(self) -> Device | None:
        idx = self.device_view.currentIndex()
        if not idx.isValid():
            return None
        return self.device_model.items[self.device_proxy.mapToSource(idx).row()]

    def _device_selected(self, current, _previous=None) -> None:
        d = self.selected_device()
        self.object_model.set_items(d.objects if d else [])
        self.prop_model.show_device(d)
        self.objects_title.setText(f"<b>Objects</b> ({len(d.objects)})" if d else "<b>Objects</b>")
        self.props_title.setText(f"<b>Device {d.instance}</b> {d.name}" if d else "<b>Properties</b>")
        self.prop_view.resizeColumnToContents(0)
        self._fit_columns(self.object_view)

    @staticmethod
    def _fit_columns(view: QTableView, max_width: int = 280) -> None:
        header = view.horizontalHeader()
        for c in range(view.model().columnCount() - 1):
            view.resizeColumnToContents(c)
            header.resizeSection(c, min(header.sectionSize(c) + 8, max_width))

    def _object_selected(self, current, _previous=None) -> None:
        if not current.isValid():
            return
        o = self.object_model.items[self.object_proxy.mapToSource(current).row()]
        self.prop_model.show_object(o)
        self.props_title.setText(f"<b>{o.key}</b> {o.name}")
        self.prop_view.resizeColumnToContents(0)

    def _device_menu(self, pos) -> None:
        d = self.selected_device()
        if not d:
            return
        menu = QMenu(self)
        act = menu.addAction(f"Re-scan device {d.instance}", lambda: self.rescan_device(d))
        act.setEnabled(self.worker is None and self.rescan_worker is None and self.scan is not None)
        menu.addSeparator()
        self._add_copy_actions(menu, self.device_view, pos)
        menu.exec(self.device_view.viewport().mapToGlobal(pos))

    def _copy_menu(self, view: QTableView, pos) -> None:
        menu = QMenu(self)
        self._add_copy_actions(menu, view, pos)
        if not menu.isEmpty():
            menu.exec(view.viewport().mapToGlobal(pos))

    def _add_copy_actions(self, menu: QMenu, view: QTableView, pos) -> None:
        idx = view.indexAt(pos)
        if not idx.isValid():
            return
        model = view.model()
        cell = str(model.data(idx) or "")
        row = "\t".join(str(model.data(model.index(idx.row(), c)) or "") for c in range(model.columnCount()))
        menu.addAction("Copy value", lambda: QGuiApplication.clipboard().setText(cell))
        menu.addAction("Copy row", lambda: QGuiApplication.clipboard().setText(row))

    # ------------------------------------------------------------ scanning

    def config_from_ui(self) -> ScanConfig:
        s = self.settings
        cfg = ScanConfig(
            interface=self.iface_combo.currentData(),
            port=self.port_spin.value(),
            level=self.level_combo.currentData(),
            whois_timeout=self.wait_spin.value(),
            site=self.site_edit.text().strip(),
            bbmd=self.bbmd_edit.text().strip() or None,
            targets=[t.strip() for t in self.targets_edit.text().replace(";", ",").split(",") if t.strip()],
            apdu_timeout=float(s.value("apdu_timeout", 3.0)),
            retries=int(s.value("retries", 2)),
            device_concurrency=int(s.value("concurrency", 4)),
            remote_delay=int(s.value("remote_delay_ms", 50)) / 1000,
            device_instance=int(s.value("local_instance", 0)) or None,
            network_info=self.netinfo_cb.isChecked(),
            internet_checks=self.internet_cb.isChecked(),
            sweep=self.sweep_cb.isChecked(),
            public_ip=self.public_ip_cb.isChecked(),
            switch_info=self.switch_cb.isChecked(),
        )
        rng = self.range_edit.text().strip()
        if rng:
            lo, _, hi = rng.partition("-")
            cfg.low, cfg.high = int(lo), int(hi or lo)
        for t in cfg.targets:
            netmod.expand_targets(t)  # validate early
        return cfg

    def start_scan_from_ui(self) -> None:
        if self.worker is not None:
            return
        try:
            cfg = self.config_from_ui()
        except ValueError as e:
            QMessageBox.warning(self, "Invalid input", str(e))
            return
        for key, val in (("interface", cfg.interface), ("port", cfg.port), ("level", cfg.level),
                         ("wait", cfg.whois_timeout)):
            self.settings.setValue(key, val)
        self.start_scan(cfg)

    def start_listen_from_ui(self) -> None:
        if self.worker is not None:
            return
        seconds, ok = QInputDialog.getInt(self, "Listen (passive)",
                                          "Record BACnet broadcasts for how many seconds?\n"
                                          "Nothing is sent to the network.",
                                          int(self.settings.value("listen_seconds", 60)), 5, 3600, 5)
        if not ok:
            return
        self.settings.setValue("listen_seconds", seconds)
        try:
            cfg = self.config_from_ui()
        except ValueError as e:
            QMessageBox.warning(self, "Invalid input", str(e))
            return
        self.start_scan(cfg, listen_seconds=seconds)

    def start_scan(self, cfg: ScanConfig, listen_seconds: float | None = None) -> None:
        """Start a scan (or a passive listen) with an explicit configuration (also used by tests)."""
        self.worker = ScanWorker(cfg, self, listen_seconds=listen_seconds)
        self.worker.event.connect(self._on_event)
        self.worker.finished_scan.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)
        self.history.clearSelection()
        self.show_scan(self.worker.scan)
        mode = f"listen {listen_seconds:.0f} s" if listen_seconds is not None else cfg.level
        self.log_view.appendPlainText(f"--- {'listen' if listen_seconds is not None else 'scan'} started ({mode}) ---")
        self._set_busy(True)
        self.status_label.setText("Listening (nothing is sent)…" if listen_seconds is not None
                                  else "Discovering devices…")
        self.worker.start()

    def stop_scan(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.status_label.setText("Stopping… (finishing current requests)")
            self.stop_btn.setEnabled(False)

    def _on_event(self, e: ScanEvent) -> None:
        if e.kind == "network":
            self.show_network()
        if e.kind in ("log", "routers", "finished", "network") and e.message:
            self.log_view.appendPlainText(e.message)
        if e.kind == "device_found":
            self.log_view.appendPlainText(e.message)
            self.status_label.setText(f"Discovering… {len(self.scan.devices) if self.scan else 0} device(s) found")
        elif e.kind == "progress":
            self.progress.setMaximum(max(e.total, 1))
            self.progress.setValue(e.done)
            self.status_label.setText(e.message)
        elif e.kind == "device_updated" and e.message:
            self.status_label.setText(e.message)
        self._schedule_refresh()

    def _schedule_refresh(self) -> None:
        """Coalesce frequent scan events into one UI refresh every 250 ms."""
        if not self._refresh_pending:
            self._refresh_pending = True
            QTimer.singleShot(250, self._refresh_live)

    def _refresh_live(self) -> None:
        self._refresh_pending = False
        if self.scan is None:
            return
        first = not self.device_model.items
        n_dev = len(self.device_model.items)
        self.device_model.sync(self.scan.devices)
        if first and self.device_model.items:
            self.device_view.selectRow(0)
        if len(self.device_model.items) != n_dev or self.scan.status != "running":
            self._fit_columns(self.device_view)
        d = self.selected_device()
        if d is not None:
            n_obj = len(self.object_model.items)
            self.object_model.sync(d.objects)
            if n_obj < 50 and len(self.object_model.items) != n_obj:
                self._fit_columns(self.object_view)
            self.objects_title.setText(f"<b>Objects</b> ({len(d.objects)})")
            if not self.object_view.currentIndex().isValid():
                self.prop_model.show_device(d)
        self._update_titles()

    def _on_finished(self, scan: Scan) -> None:
        self.worker = None
        self._set_busy(False)
        try:
            self.store.save(scan)
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))
        self._refresh_live()
        self.reload_history(select_id=scan.id)
        self._update_titles()
        n = len(scan.devices)
        self.status_label.setText(
            f"Scan {scan.status}: {n} device(s), {scan.object_count} object(s) — saved as scan {scan.id}")
        if scan.level == "listen":
            heard = len(scan.network.get("bacnet_traffic", []))
            self.status_label.setText(f"Listen {scan.status}: {heard} traffic source/service pair(s), "
                                      f"{n} device(s) — saved as scan {scan.id}")
            if heard:
                self.tabs.setCurrentIndex(1)
        elif n == 0 and scan.status == "completed":
            QMessageBox.information(
                self, "No devices found",
                "No BACnet device answered.\n\nCheck: correct interface and cable, macOS firewall "
                "allows incoming connections for bacscan, or try longer wait time / unicast targets.")

    def _on_failed(self, message: str) -> None:
        self.worker = None
        self._set_busy(False)
        self.status_label.setText("Scan failed")
        self.log_view.appendPlainText(f"ERROR: {message}")
        QMessageBox.critical(self, "Scan failed", message)

    def rescan_device(self, d: Device) -> None:
        if self.scan is None:
            return
        cfg = self.config_from_ui()
        cfg.low = cfg.high = d.instance
        cfg.whois_timeout = 3
        if d.network is None:
            cfg.targets = [d.address]
            cfg.broadcast = False
        if self.scan.settings.get("bind_address"):  # keep the original binding (tests / expert use)
            cfg.bind_address = self.scan.settings["bind_address"]
        worker = ScanWorker(cfg, self)
        self.rescan_worker = worker
        target_scan = self.scan

        def done(result: Scan) -> None:
            self.rescan_worker = None
            self._set_busy(False)
            new = result.device(d.instance)
            if new is None:
                self.status_label.setText(f"Device {d.instance} did not answer")
                return
            i = next(i for i, x in enumerate(target_scan.devices) if x.instance == d.instance)
            target_scan.devices[i] = new
            if target_scan.id is not None:
                self.store.save(target_scan)
            self.show_scan(target_scan)
            self.reload_history(select_id=target_scan.id)
            self.status_label.setText(f"Device {d.instance} re-scanned: {new.status}, {len(new.objects)} objects")

        def failed(msg: str) -> None:
            self.rescan_worker = None
            self._set_busy(False)
            QMessageBox.critical(self, "Re-scan failed", msg)

        worker.finished_scan.connect(done)
        worker.failed.connect(failed)
        worker.event.connect(lambda e: e.kind == "progress" and self.status_label.setText(e.message))
        self._set_busy(True, allow_stop=False)
        self.status_label.setText(f"Re-scanning device {d.instance}…")
        worker.start()

    def _set_busy(self, busy: bool, allow_stop: bool = True) -> None:
        for w in (self.scan_btn, self.start_act, self.listen_btn, self.listen_act, self.iface_combo, self.port_spin, self.level_combo,
                  self.wait_spin, self.site_edit, self.targets_edit, self.bbmd_edit, self.range_edit,
                  self.history, self.netinfo_cb):
            w.setEnabled(not busy)
        self.stop_btn.setEnabled(busy and allow_stop)
        self.stop_act.setEnabled(busy and allow_stop)
        self.progress.setVisible(busy)
        if busy:
            self.progress.setRange(0, 0)  # indeterminate until objects are counted
        self._update_titles()

    # ------------------------------------------------------------ file actions

    def _selected_scan_id(self) -> int | None:
        return self.scan.id if self.scan and self.scan.id is not None else None

    def export_scan(self, fmt: str) -> None:
        if self._selected_scan_id() is None:
            return
        ext = "csv" if fmt == "hosts" else fmt
        suffix = "-hosts" if fmt == "hosts" else ""
        name = (self.scan.site or "scan").replace("/", "-") + f"-{self.scan.id}{suffix}.{ext}"
        start = str(Path(self.settings.value("export_dir", str(Path.home()))) / name)
        path, _ = QFileDialog.getSaveFileName(self, f"Export {fmt.upper()}", start,
                                              f"{ext.upper()} (*.{ext})")
        if not path:
            return
        self.settings.setValue("export_dir", str(Path(path).parent))
        if fmt == "xlsx":
            export_xlsx(self.scan, path)
            self.status_label.setText(f"Exported to {path}")
        elif fmt == "hosts":
            n = export_hosts_csv(self.scan, path)
            self.status_label.setText(f"Exported {n} hosts to {path}")
        elif fmt == "csv":
            n = export_csv(self.scan, path)
            self.status_label.setText(f"Exported {n} rows to {path}")
        else:
            export_json(self.scan, path)
            self.status_label.setText(f"Exported to {path}")

    def import_scan(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import scan", str(Path.home()), "bacscan JSON (*.json)")
        if not path:
            return
        try:
            scan = import_json(path)
        except Exception as e:
            QMessageBox.critical(self, "Import failed", str(e))
            return
        self.store.save(scan)
        self.reload_history(select_id=scan.id)
        self.show_scan(scan)

    def edit_scan_info(self) -> None:
        sid = self._selected_scan_id()
        if sid is None or self.worker is not None:
            return
        dlg = ScanInfoDialog(self.scan.site, self.scan.notes, self)
        if dlg.exec():
            self.scan.site = dlg.site.text().strip()
            self.scan.notes = dlg.notes.toPlainText()
            self.store.update_meta(sid, site=self.scan.site, notes=self.scan.notes)
            self.reload_history(select_id=sid)
            self._update_titles()

    def delete_scan(self) -> None:
        sid = self._selected_scan_id()
        if sid is None:
            return
        if QMessageBox.question(self, "Delete scan", f"Delete scan {sid} ({self.scan.site or 'no site'})?"
                                ) != QMessageBox.StandardButton.Yes:
            return
        self.store.delete(sid)
        self.show_scan(None)
        self.reload_history()

    def compare_scans(self) -> None:
        if len(self.store.list()) < 2:
            QMessageBox.information(self, "Compare scans", "At least two saved scans are needed.")
            return
        CompareDialog(self.store, self._selected_scan_id(), self).exec()

    def open_settings(self) -> None:
        SettingsDialog(self.settings, self).exec()

    def about(self) -> None:
        QMessageBox.about(self, "About bacscan",
                          f"<b>bacscan {__version__}</b><br>Read-only BACnet/IP discovery and inventory."
                          f"<br><br>Database: {self.store.path}")

    def closeEvent(self, event) -> None:
        for w in (self.worker, self.rescan_worker):
            if w is not None:
                w.cancel()
                w.wait(15000)
        self.store.close()
        super().closeEvent(event)


def main(db_path: str | None = None) -> int:
    logging.basicConfig(level=logging.WARNING)
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("bacscan")
    app.setOrganizationName("bacscan")
    win = MainWindow(db_path)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
