"""Schedule object viewer: weekly grid, exceptions, controlled properties."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from ..core.schedules import DAY_NAMES, ScheduleView


class ScheduleDialog(QDialog):
    def __init__(self, s: ScheduleView, device_label: str = "", parent=None):
        super().__init__(parent)
        self.view = s
        self.setWindowTitle(f"Schedule {s.key} {s.name}".strip())
        self.resize(900, 640)
        v = QVBoxLayout(self)
        title = QLabel(f"<b>{s.name or s.key}</b> &nbsp; <span style='color:gray'>{device_label}</span>")
        title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(title)

        form = QFormLayout()
        for label, text in (("Description", s.description), ("Present value now", s.present_value),
                            ("Effective period", s.effective), ("Default value", s.default),
                            ("Write priority", s.priority_for_writing)):
            if text:
                form.addRow(label, QLabel(text))
        v.addLayout(form)

        v.addWidget(QLabel("<b>Weekly schedule</b>"))
        self.grid = QTableWidget()
        self.grid.setColumnCount(7)
        self.grid.setHorizontalHeaderLabels(DAY_NAMES)
        self.grid.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.grid.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.grid.setAlternatingRowColors(True)
        rows = max([len(d) for d in s.days if d] or [0])
        self.grid.setRowCount(max(rows, 1))
        for c in range(7):
            day = s.days[c] if c < len(s.days) else None
            if day is None:
                self.grid.setItem(0, c, QTableWidgetItem("not readable" if s.days else "not read"))
                continue
            if not day:
                self.grid.setItem(0, c, QTableWidgetItem("—"))
            for r, (t, val) in enumerate(day):
                self.grid.setItem(r, c, QTableWidgetItem(f"{t}  →  {val}"))
        v.addWidget(self.grid, 3)

        v.addWidget(QLabel(f"<b>Exceptions</b> ({len(s.exceptions)})"))
        self.exceptions = QTreeWidget()
        self.exceptions.setHeaderHidden(True)
        for e in s.exceptions:
            top = QTreeWidgetItem(self.exceptions, [e.period + (f"   (priority {e.priority})"
                                                                if e.priority is not None else "")])
            for t, val in e.entries:
                QTreeWidgetItem(top, [f"{t}  →  {val}"])
        self.exceptions.expandAll()
        v.addWidget(self.exceptions, 2)

        v.addWidget(QLabel(f"<b>Controls</b> ({len(s.controls)})"))
        self.controls = QListWidget()
        self.controls.addItems(s.controls)
        v.addWidget(self.controls, 1)

        if s.errors:
            v.addWidget(QLabel("<span style='color:#c62828'>" + "; ".join(s.errors) + "</span>"))
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        v.addWidget(buttons)
