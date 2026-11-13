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
        assert len(win.history_items()) == 1
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

        # passive listen produces a second saved scan; compare dialog works on the two
        cfg2 = ScanConfig(bind_address=f"127.0.0.1/32:{scan_port}", network_info=False)
        win.start_scan(cfg2, listen_seconds=1)
        assert wait_until(lambda: win.worker is None), "listen did not finish"
        assert win.scan.level == "listen" and len(win.history_items()) == 2
        from bacscan.gui.app import CompareDialog
        dlg = CompareDialog(win.store, win.scan.id)
        assert dlg.tree.topLevelItemCount() > 0 and "removed" in dlg.summary.text()
        from bacscan.storage.xlsx import export_xlsx
        export_xlsx(win.store.load(sid), tmp_path / "gui.xlsx")

        # reload from history
        win.show_scan(None)
        # site "GUI test" holds the first scan; the listen scan has no site and sits in the last node
        assert win.history.topLevelItem(0).data(0, win.SITE_ROLE) == "GUI test"
        win.history.setCurrentItem(win.history_items()[1])
        win.history.setCurrentItem(win.history_items()[0])
        assert win.scan.id == sid and win.device_model.rowCount() == 1
    finally:
        win.close()
        sim.close()


def test_gui_host_details(qapp, tmp_path):
    from bacscan.core.models import Host, Scan

    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    win = MainWindow(tmp_path / "gui.db", settings)
    try:
        assert hasattr(win, "deep_cb") and not win.deep_cb.isChecked()
        from bacscan.gui.app import ReportDialog
        dlg = ReportDialog(settings, win)
        assert dlg.format.currentData() == "pdf" and win.report_act.text() == "Create site report…"
        h = Host(ip="10.0.0.3", mac="00:11:22:33:44:55", rtt_ms=1.5, ttl=128, os_hint="Windows",
                 kind="Niagara station (Tridium)", ports=[443, 4911], layers=["arp", "icmp", "tcp"],
                 services={"443/tcp https": "200 OK · title Workbench"})
        win.show_scan(Scan(hosts=[h], network={"deep_discovery": {"hosts": 1, "ports": [443, 4911]}}))
        win.host_view.selectRow(0)
        rows = dict(win.host_detail_model.items)
        assert rows["Kind"] == "Niagara station (Tridium)"
        assert rows["443/tcp https"] == "200 OK · title Workbench"
        assert rows["Ping"] == "1.5 ms, TTL 128 (Windows)"
        assert ("Deep discovery", "1 host(s) answered; TCP ports checked: 2") in win.env_model.items
    finally:
        win.close()


def test_gui_snmp_dialog(qapp, tmp_path):
    from bacscan.gui.app import SnmpDialog

    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    win = MainWindow(tmp_path / "gui.db", settings)
    try:
        dlg = SnmpDialog(settings, None, win)
        dlg.version.setCurrentIndex(dlg.version.findData("v3"))
        assert not dlg.community.isEnabled() and dlg.user.isEnabled()
        dlg.user.setText("ops")
        dlg.auth_pass.setText("authpass123")
        dlg.priv_pass.setText("privpass123")
        dlg.targets.setText("10.0.0.2, 10.0.0.3")
        dlg.accept()
        assert dlg.result() == 1 and dlg.creds.level == "authPriv"
        # nothing secret ends up in the settings file
        settings.sync()
        text = (tmp_path / "s.ini").read_text()
        assert "authpass123" not in text and "privpass123" not in text and "10.0.0.2" in text
        win.snmp_creds = dlg.creds
        win.snmp_cb.setChecked(True)
        cfg = win.config_from_ui()
        assert cfg.snmp_targets == ["10.0.0.2", "10.0.0.3"] and cfg.snmp_credentials.user == "ops"
        assert "authpass123" not in str(cfg.to_dict())
    finally:
        win.close()


def test_gui_site_tree(qapp, tmp_path):
    from bacscan.core.models import Scan
    from bacscan.storage.db import Store
    db = tmp_path / "gui.db"
    with Store(db) as st:
        for when, site in [("2026-11-01T10:00", "Plant A"), ("2026-11-03T10:00", "Plant B"),
                           ("2026-11-05T10:00", "Plant A"), ("2026-11-06T10:00", ""),
                           ("2026-11-07T09:00", "Plant A")]:
            st.save(Scan(started_at=when, site=site, status="completed"))
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.Format.IniFormat)
    win = MainWindow(db, settings)
    try:
        h = win.history
        sites = [h.topLevelItem(i).data(0, win.SITE_ROLE) for i in range(h.topLevelItemCount())]
        assert sites == ["Plant A", "Plant B", ""]  # most recent site first, no site last
        a = h.topLevelItem(0)
        assert a.text(0) == "Plant A  (3)"
        assert [a.child(i).text(0)[:16] for i in range(3)] == ["2026-11-07 09:00", "2026-11-05 10:00",
                                                                "2026-11-01 10:00"]
        h.setCurrentItem(a.child(1))
        assert win.scan.started_at.startswith("2026-11-05")
        h.setCurrentItem(a)  # a site node does not change the shown scan
        assert win.scan.started_at.startswith("2026-11-05")

        # the site dropdown lists known sites (most recent first); selecting fills in the site of the next scan
        box = win.site_edit
        assert [box.itemText(i) for i in range(box.count())] == ["Plant A", "Plant B"]
        h.setCurrentItem(h.topLevelItem(1).child(0))
        assert box.currentText() == "Plant B"
        h.setCurrentItem(h.topLevelItem(2).child(0))  # (no site)
        assert box.currentText() == ""
        h.setCurrentItem(h.topLevelItem(0))
        assert box.currentText() == "Plant A"
        box.setEditText("New building")
        win.reload_history()  # refilling the list keeps what was typed
        assert box.currentText() == "New building"

        # collapse state survives a reload; the selected scan's site is always opened
        h.topLevelItem(0).setExpanded(False)
        win.reload_history()
        assert not h.topLevelItem(0).isExpanded() and h.topLevelItem(1).isExpanded()
        win.reload_history(select_id=h.topLevelItem(0).child(0).data(0, 256))
        assert h.topLevelItem(0).isExpanded()

        # rename merges into an existing site
        win.store.rename_site("Plant B", "Plant A")
        win.reload_history()
        assert h.topLevelItem(0).text(0) == "Plant A  (4)" and h.topLevelItemCount() == 2

        # compare defaults to the previous scan of the same site
        from bacscan.gui.app import CompareDialog
        newest = h.topLevelItem(0).child(0).data(0, 256)
        dlg = CompareDialog(win.store, newest)
        older = win.store.load(dlg.a_combo.currentData())
        assert older.site == "Plant A" and older.started_at.startswith("2026-11-05")
    finally:
        win.close()
