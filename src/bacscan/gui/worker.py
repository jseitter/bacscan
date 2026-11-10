"""Runs a Scanner (asyncio) in a background thread and forwards events as Qt signals."""
from __future__ import annotations

import asyncio
import logging

from PySide6.QtCore import QThread, Signal

from ..core.scanner import ScanConfig, ScanError, Scanner
from ..core.values import error_text

log = logging.getLogger("bacscan.gui")


class ScanWorker(QThread):
    event = Signal(object)  # ScanEvent (queued to the GUI thread)
    finished_scan = Signal(object)  # Scan
    failed = Signal(str)

    def __init__(self, cfg: ScanConfig, parent=None):
        super().__init__(parent)
        self.cfg = cfg
        self.scanner = Scanner(cfg, self.event.emit)

    @property
    def scan(self):
        return self.scanner.scan

    def cancel(self) -> None:
        self.scanner.cancel()

    def run(self) -> None:
        try:
            scan = asyncio.run(self.scanner.run())
        except ScanError as e:
            self.failed.emit(str(e))
            return
        except Exception as e:  # never let the thread die silently
            log.exception("scan crashed")
            self.failed.emit(error_text(e))
            return
        self.finished_scan.emit(scan)
