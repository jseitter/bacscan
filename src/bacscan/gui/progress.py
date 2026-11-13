"""Progress dialog shown while a scan runs: phase, progress bar, live messages and SNMP results."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from ..core.models import Scan
from ..core.scanner import ScanEvent

SNMP_HEADERS = ["Agent", "Status", "Name", "Description", "Details"]


def snmp_rows(snmp: dict) -> list[list[str]]:
    """One row per SNMP agent of a finished scan: result or the reason it failed."""
    rows = []
    for a in snmp.get("agents", []):
        if a.get("ok"):
            ent = a.get("entity", {})
            bits = []
            if a.get("fdb_entries"):
                bits.append(f"{a['fdb_entries']} MAC table entries")
            if a.get("lldp"):
                bits.append(f"{len(a['lldp'])} LLDP neighbour(s)")
            if a.get("interfaces"):
                bits.append(f"{len(a['interfaces'])} interface(s)")
            if ent.get("model"):
                bits.append(ent["model"])
            rows.append([a["ip"], "answered", a.get("sysName") or "", (a.get("sysDescr") or "")[:100],
                         " · ".join(bits)])
        else:
            rows.append([a["ip"], "no result", "", "", a.get("error") or "no answer"])
    return rows


class ScanProgressDialog(QDialog):
    """Non-modal: closing it only hides it, the scan keeps running (Stop cancels)."""

    stop_requested = Signal()

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 520)
        lay = QVBoxLayout(self)

        self.phase = QLabel("Starting…")
        font = self.phase.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * 1.15)
        self.phase.setFont(font)
        lay.addWidget(self.phase)

        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        lay.addWidget(self.bar)
        self.detail = QLabel("")
        self.detail.setStyleSheet("color: gray")
        lay.addWidget(self.detail)

        self.snmp_label = QLabel("<b>SNMP</b>")
        self.snmp_table = QTableWidget(0, len(SNMP_HEADERS))
        self.snmp_table.setHorizontalHeaderLabels(SNMP_HEADERS)
        self.snmp_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.snmp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.snmp_table.verticalHeader().hide()
        self.snmp_table.horizontalHeader().setStretchLastSection(True)
        self.snmp_table.setMaximumHeight(170)
        for w in (self.snmp_label, self.snmp_table):
            w.hide()
            lay.addWidget(w)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(2000)
        lay.addWidget(self.log, 1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self._stop)
        self.close_btn = QPushButton("Hide")
        self.close_btn.clicked.connect(self.hide)
        buttons.addWidget(self.stop_btn)
        buttons.addWidget(self.close_btn)
        lay.addLayout(buttons)
        self.finished_ok = False

    def _stop(self) -> None:
        self.stop_btn.setEnabled(False)
        self.phase.setText("Stopping… (finishing current requests)")
        self.stop_requested.emit()

    # -- events

    def on_event(self, e: ScanEvent) -> None:
        if e.kind == "phase":
            self.phase.setText(e.message)
            self.detail.setText("")
            self.bar.setRange(0, 0)  # indeterminate until a progress event gives a total
            self.log.appendPlainText(f"== {e.message}")
        elif e.kind == "progress":
            self.bar.setRange(0, max(e.total, 1))
            self.bar.setValue(e.done)
            self.detail.setText(e.message)
        elif e.kind == "snmp":
            if e.total:
                self.bar.setRange(0, e.total)
                self.bar.setValue(e.done)
                self.detail.setText(f"SNMP: {e.done}/{e.total} agent(s) done")
            self.log.appendPlainText(e.message)
        elif e.kind in ("log", "device_found", "routers", "network", "finished") and e.message:
            self.log.appendPlainText(e.message)

    def finish(self, scan: Scan, summary: str) -> None:
        self.finished_ok = True
        self.phase.setText(summary)
        self.detail.setText("")
        self.bar.setRange(0, 1)
        self.bar.setValue(1)
        self.stop_btn.setEnabled(False)
        self.close_btn.setText("Close")
        self.close_btn.setDefault(True)
        snmp = (scan.network or {}).get("snmp")
        if snmp:
            rows = snmp_rows(snmp)
            self.snmp_label.setText(f"<b>SNMP</b> — {sum(r[1] == 'answered' for r in rows)} of {len(rows)} "
                                    f"agent(s) answered · {snmp.get('credentials', '')} · "
                                    f"{sum(1 for h in scan.hosts if h.switch_port)} host(s) located on switch ports")
            self.snmp_table.setRowCount(len(rows))
            for r, row in enumerate(rows):
                for c, text in enumerate(row):
                    item = QTableWidgetItem(text)
                    if c == 1 and text != "answered":
                        item.setForeground(Qt.GlobalColor.red)
                    self.snmp_table.setItem(r, c, item)
            self.snmp_table.resizeColumnsToContents()
            self.snmp_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
            self.snmp_label.show()
            self.snmp_table.show()

    def fail(self, message: str) -> None:
        self.phase.setText("Scan failed")
        self.log.appendPlainText(f"ERROR: {message}")
        self.bar.setRange(0, 1)
        self.stop_btn.setEnabled(False)
        self.close_btn.setText("Close")
