"""GUI smoke test (offscreen): live scan against the simulator through the main window."""
import asyncio
import os
import threading

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QSettings, QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from bacscan.core.scanner import ScanConfig  # noqa: E402
from bacscan.gui.app import MainWindow  # noqa: E402
from sim_device import build_app  # noqa: E402


@pytest.fixture(scope="module")
def qapp():
    return QApplication.instance() or QApplication([])


class SimThread(threading.Thread):
    def __init__(self, port):
        super().__init__(daemon=True)
        self.port = port
        self.ready = threading.Event()
        self.stop = None

    def run(self):
        async def main():
            app = build_app(f"127.0.0.1/32:{self.port}", 1001)
            self.stop = asyncio.Event()
            self.loop = asyncio.get_running_loop()
            self.ready.set()
            await self.stop.wait()
            app.close()
        asyncio.run(main())

    def close(self):
        self.loop.call_soon_threadsafe(self.stop.set)
        self.join(5)


def wait_until(cond, timeout=20.0):
    loop = QEventLoop()
    timer = QTimer()
    timer.timeout.connect(lambda: cond() and loop.quit())
    timer.start(50)
    QTimer.singleShot(int(timeout * 1000), loop.quit)
    loop.exec()
    timer.stop()
    return cond()


def test_gui_scan(qapp, tmp_path, port_pair):
    sim_port, scan_port = port_pair
    sim = SimThread(sim_port)
    sim.start()
    sim.ready.wait(5)
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    win = MainWindow(tmp_path / "gui.db", settings)
    win.show()
    try:
        cfg = ScanConfig(bind_address=f"127.0.0.1/32:{scan_port}", broadcast=False,
                         targets=[f"127.0.0.1:{sim_port}"], whois_timeout=0.8, site="GUI test",
                         internet_checks=False)
        win.start_scan(cfg)
        assert win.worker is not None and not win.scan_btn.isEnabled()
        assert wait_until(lambda: win.worker is None), "scan did not finish"
        assert win.scan.id is not None and win.scan.status == "completed"
        assert win.history.count() == 1
        assert win.device_model.rowCount() == 1
        win.device_view.selectRow(0)
        assert win.object_model.rowCount() == 9
        win.object_filter.setText("room")
        assert win.object_proxy.rowCount() == 5
        win.object_view.selectRow(0)
        names = [k for k, _ in win.prop_model.items]
        assert "present-value" in names
        win.object_filter.setText("")
        win.object_view.selectRow(1)
        qapp.processEvents()
        shot = os.environ.get("BACSCAN_SCREENSHOT")
        if shot:
            win.grab().save(shot)

        # network tab filled from the loopback survey
        assert win.env_model.rowCount() > 0 and win.host_model.rowCount() >= 1
        assert win.tabs.tabText(1).startswith("Network (")
        win.tabs.setCurrentIndex(1)
        qapp.processEvents()
        if shot:
            win.grab().save(shot.replace(".png", "-network.png"))
        win.host_view.selectRow(0)
        win._host_activated(win.host_view.currentIndex())  # 127.0.0.1 is the BACnet simulator
        assert win.tabs.currentIndex() == 0

        # re-scan a device keeps the scan and its id
        sid = win.scan.id
        win.rescan_device(win.scan.devices[0])
        assert wait_until(lambda: win.rescan_worker is None), "re-scan did not finish"
        assert win.scan.id == sid and len(win.scan.devices[0].objects) == 9

        # reload from history
        win.show_scan(None)
        win.history.setCurrentRow(-1)
        win.history.setCurrentRow(0)
        assert win.scan.id == sid and win.device_model.rowCount() == 1
    finally:
        win.close()
        sim.close()
