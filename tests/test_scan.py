"""Integration tests: real bacpypes3 stack on loopback against the simulator."""
import asyncio

import pytest

from bacscan.core import scanner as scanner_mod
from bacscan.core.scanner import ScanConfig, Scanner
from sim_device import build_app


def run_scan(sim_port, scan_port, level="full", patch=None, n_analog=5, on_event=None, network_info=False):
    async def main():
        sim = build_app(f"127.0.0.1/32:{sim_port}", 1001, n_analog)
        try:
            await asyncio.sleep(0.2)
            cfg = ScanConfig(bind_address=f"127.0.0.1/32:{scan_port}", broadcast=False,
                             targets=[f"127.0.0.1:{sim_port}"], whois_timeout=0.8, level=level,
                             apdu_timeout=1.0, retries=0, network_info=network_info,
                             internet_checks=False)
            sc = Scanner(cfg, on_event)
            if patch:
                patch(sc)
            return await sc.run()
        finally:
            sim.close()
    return asyncio.run(main())


def test_full_scan(port_pair):
    scan = run_scan(*port_pair)
    assert scan.status == "completed"
    assert len(scan.devices) == 1
    d = scan.devices[0]
    assert d.instance == 1001 and d.status == "done"
    assert d.name == "SimDevice-1001"
    assert d.text("model-name") == "SIM-1000"
    assert d.text("firmware-revision") == "1.2.3"
    keys = {o.key for o in d.objects}
    assert "device,1001" not in keys
    assert {"analog-input,1", "analog-value,1", "binary-value,1", "multi-state-value,1"} <= keys
    ai = next(o for o in d.objects if o.key == "analog-input,3")
    assert ai.name == "Room03.Temp"
    assert ai.props["present-value"].value == pytest.approx(21.5)
    assert ai.text("units") == "degrees-celsius"
    msv = next(o for o in d.objects if o.key == "multi-state-value,1")
    assert msv.props["state-text"].value == ["Off", "Comfort", "Eco"]
    # unknown properties are dropped, not stored as errors
    assert "units" not in next(o for o in d.objects if o.key == "binary-value,1").props


def test_readproperty_fallback(port_pair, monkeypatch):
    """Device without ReadPropertyMultiple: everything via ReadProperty."""
    orig = scanner_mod.DeviceReader.__init__

    def init(self, *a, **kw):
        orig(self, *a, **kw)
        self.use_rpm = False

    monkeypatch.setattr(scanner_mod.DeviceReader, "__init__", init)

    async def no_rpm(self, *a, **kw):
        raise AssertionError("RPM must not be used")

    monkeypatch.setattr(scanner_mod.DeviceReader, "rpm", no_rpm)
    scan = run_scan(*port_pair)
    d = scan.devices[0]
    assert d.status == "done"
    assert d.text("vendor-name") == "bacscan"
    ai = next(o for o in d.objects if o.key == "analog-input,1")
    assert ai.text("description") == "Room 1 temperature"


def test_level_all_reads_every_property(port_pair):
    scan = run_scan(*port_pair, level="all")
    d = scan.devices[0]
    assert "object-list" in d.props
    ai = next(o for o in d.objects if o.key == "analog-input,1")
    assert "object-identifier" in ai.props and "cov-increment" in ai.props
    assert ai.props["cov-increment"].value == 0.1  # float32 noise rounded away


def test_level_device_skips_objects(port_pair):
    scan = run_scan(*port_pair, level="device")
    assert scan.devices[0].name == "SimDevice-1001"
    assert scan.devices[0].objects == []


def test_cancel_keeps_partial_results(port_pair):
    holder = {}

    def patch(sc):
        holder["sc"] = sc

    def on_event(e):
        if e.kind == "progress" and e.done >= 20:
            holder["sc"].cancel()

    scan = run_scan(*port_pair, patch=patch, n_analog=200, on_event=on_event)
    assert scan.status == "cancelled"
    d = scan.devices[0]
    assert 20 <= len(d.objects) < 204
    assert d.status == "partial"


def test_no_device(port_pair):
    sim_port, scan_port = port_pair

    async def main():
        cfg = ScanConfig(bind_address=f"127.0.0.1/32:{scan_port}", broadcast=False,
                         targets=[f"127.0.0.1:{sim_port}"], whois_timeout=0.5, network_info=False)
        return await Scanner(cfg).run()

    scan = asyncio.run(main())
    assert scan.status == "completed" and scan.devices == []


def test_object_list_element_fallback(port_pair, monkeypatch):
    """Whole object-list read rejected (e.g. no segmentation) -> read element by element."""
    from bacpypes3.apdu import AbortPDU
    calls = []

    def patch(sc):
        orig_build = scanner_mod.build_application

        def build(cfg):
            app, label, bind = orig_build(cfg)
            orig_rp = app.read_property

            async def rp(addr, objid, prop, index=None):
                if str(prop) == "object-list":
                    calls.append(index)
                    if index is None:
                        raise AbortPDU(apduAbortRejectReason="segmentation-not-supported")
                return await orig_rp(addr, objid, prop, index)

            app.read_property = rp
            return app, label, bind

        monkeypatch.setattr(scanner_mod, "build_application", build)

    scan = run_scan(*port_pair, patch=patch)
    d = scan.devices[0]
    assert calls[:2] == [None, 0] and len(calls) == 2 + 10
    assert len(d.objects) == 9 and d.status == "done"


def test_scan_with_network_survey(port_pair):
    """Survey runs on the loopback interface (no internet checks in tests)."""
    scan = run_scan(*port_pair, network_info=True)
    assert scan.status == "completed"
    assert scan.network["interface"]["name"] == "lo0"
    assert "internet" not in scan.network
    me = next(h for h in scan.hosts if h.ip == "127.0.0.1")
    assert me.note == "this Mac" and me.bacnet_instance == 1001
