"""Help window: guide, BACnet object types, properties, glossary, with search."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QLineEdit,
    QSplitter,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import help as helpmod

GROUPS = ("Guide", "Object types", "Properties", "Glossary")
ID_ROLE = Qt.ItemDataRole.UserRole


class HelpWindow(QWidget):
    """Non-modal, so it can stay open beside the scan results."""

    def __init__(self, parent=None):
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle("bacscan Help")
        self.resize(980, 640)
        self.topics = {t.id: t for t in helpmod.all_topics()}
        v = QVBoxLayout(self)
        self.search = QLineEdit(placeholderText="Search help (e.g. segmentation, schedule, analog)…",
                                clearButtonEnabled=True)
        self.search.textChanged.connect(self._filter)
        v.addWidget(self.search)
        split = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.currentItemChanged.connect(self._selected)
        split.addWidget(self.tree)
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)
        split.addWidget(self.browser)
        split.setSizes([380, 600])
        v.addWidget(split, 1)
        self._fill(list(self.topics.values()), expand_all=False)
        self.show_topic("start")

    def _fill(self, topics, expand_all: bool) -> None:
        self.tree.blockSignals(True)
        self.tree.clear()
        for g in GROUPS:
            items = [t for t in topics if t.group == g]
            if not items:
                continue
            top = QTreeWidgetItem(self.tree, [f"{g} ({len(items)})" if g != "Guide" else g])
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            top.setFlags(top.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            for t in items:
                it = QTreeWidgetItem(top, [t.title])
                it.setData(0, ID_ROLE, t.id)
            top.setExpanded(expand_all or g == "Guide")
        self.tree.blockSignals(False)

    def _filter(self, text: str) -> None:
        if text.strip():
            self._fill(helpmod.search(text), expand_all=True)
        else:
            self._fill(list(self.topics.values()), expand_all=False)

    def _selected(self, current, _previous=None) -> None:
        tid = current.data(0, ID_ROLE) if current else None
        if tid:
            self._render(tid)

    def _render(self, tid: str) -> None:
        t = self.topics.get(tid)
        if t:
            self.browser.setHtml(helpmod.render_html(t))

    def show_topic(self, tid: str) -> None:
        """Select and show a topic (clears the search so the entry is in the tree)."""
        if tid not in self.topics:
            tid = "start"
        if self.search.text():
            self.search.clear()
        it = self._find(tid)
        if it is not None:
            it.parent().setExpanded(True)
            self.tree.setCurrentItem(it)
            self.tree.scrollToItem(it)
        self._render(tid)

    def _find(self, tid: str) -> QTreeWidgetItem | None:
        for i in range(self.tree.topLevelItemCount()):
            top = self.tree.topLevelItem(i)
            for j in range(top.childCount()):
                if top.child(j).data(0, ID_ROLE) == tid:
                    return top.child(j)
        return None
