import csv

from bacscan.core.models import BacnetObject, Device, Host, PropValue, Router, Scan
from bacscan.core.network import expand_targets
from bacscan.storage.db import Store
from bacscan.storage.export import export_csv, export_hosts_csv, export_json, import_json


def sample_scan() -> Scan:
    d = Device(instance=7, address="10.0.0.7", vendor_id=5, max_apdu=1476, segmentation="segmented-both",
               props={"object-name": PropValue("AHU-1", "AHU-1"),
                      "vendor-name": PropValue("ACME", "ACME"),
                      "serial-number": PropValue(error="property: unknown-property")})
    d.objects.append(BacnetObject("analog-input", 1, {
        "object-name": PropValue("T1", "T1"),
        "present-value": PropValue(21.25, "21.25"),
        "units": PropValue("degrees-celsius", "degrees-celsius"),
        "state-text": PropValue(["a", "b"], "a; b"),
    }))
    d.eth_mac, d.eth_vendor, d.eth_mac_source = "00:01:f0:11:22:33", "Tridium, Inc.", "arp"
    r = Device(instance=8, address="2001:0x05", network=2001, mac="05", router="10.0.0.1")
    return Scan(site="Bldg A", level="full", status="completed", devices=[d, r],
                routers=[Router("10.0.0.1", [2001])], settings={"port": 47808},
                network={"internet": {"status": "full"}, "dhcp": {"used": True, "server": "10.0.0.1"}},
                hosts=[Host("10.0.0.1", "bc:24:11:30:41:32", "Proxmox", note="gateway"),
                       Host("10.0.0.7", "00:01:f0:11:22:33", "Tridium, Inc.", bacnet_instance=7)])


def test_roundtrip(tmp_path):
    with Store(tmp_path / "x.db") as st:
        sid = st.save(sample_scan())
        s = st.load(sid)
        assert s.site == "Bldg A" and s.routers[0].networks == [2001]
        d = s.device(7)
        assert d.name == "AHU-1" and d.props["serial-number"].error
        assert d.objects[0].props["present-value"].value == 21.25
        assert s.device(8).network == 2001
        assert d.eth_mac == "00:01:f0:11:22:33" and d.eth_vendor == "Tridium, Inc."
        assert s.network["internet"]["status"] == "full"
        assert [h.ip for h in s.hosts] == ["10.0.0.1", "10.0.0.7"] and s.hosts[1].bacnet_instance == 7
        [summary] = st.list()
        assert summary.devices == 2 and summary.objects == 1
        st.update_meta(sid, notes="hello")
        assert st.load(sid).notes == "hello"
        assert st.latest_id() == sid
        assert st.delete(sid) and st.list() == []


def test_json_export_import(tmp_path):
    scan = sample_scan()
    scan.id = 99
    export_json(scan, tmp_path / "s.json")
    back = import_json(tmp_path / "s.json")
    assert back.id is None
    assert back.to_dict() | {"id": 99} == scan.to_dict()


def test_csv_export(tmp_path):
    n = export_csv(sample_scan(), tmp_path / "s.csv")
    rows = list(csv.reader(open(tmp_path / "s.csv", encoding="utf-8-sig"), delimiter=";"))
    assert n == 2 and len(rows) == 3
    assert rows[1][11] == "T1" and rows[1][13] == "21.25"
    assert "state-text=a; b" in rows[1][-1]


def test_expand_targets():
    assert expand_targets("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert expand_targets("10.0.0.1-10.0.0.3:47809") == ["10.0.0.1:47809", "10.0.0.2:47809", "10.0.0.3:47809"]


def test_hosts_csv(tmp_path):
    n = export_hosts_csv(sample_scan(), tmp_path / "h.csv")
    rows = list(csv.reader(open(tmp_path / "h.csv", encoding="utf-8-sig"), delimiter=";"))
    assert n == 2 and rows[2][:6] == ["10.0.0.7", "00:01:f0:11:22:33", "Tridium, Inc.", "", "7", "AHU-1"]


def test_migrates_v01_database(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE scan (id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT,
            site TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', interface TEXT NOT NULL DEFAULT '',
            local_address TEXT NOT NULL DEFAULT '', level TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT '',
            settings_json TEXT NOT NULL DEFAULT '{}', routers_json TEXT NOT NULL DEFAULT '[]',
            tool_version TEXT NOT NULL DEFAULT '');
        CREATE TABLE device (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, instance INTEGER NOT NULL,
            address TEXT NOT NULL, network INTEGER, mac TEXT, router TEXT, vendor_id INTEGER, vendor_name TEXT,
            model_name TEXT, object_name TEXT, firmware TEXT, app_version TEXT, max_apdu INTEGER, segmentation TEXT,
            first_seen TEXT, status TEXT, props_json TEXT NOT NULL DEFAULT '{}', errors_json TEXT NOT NULL DEFAULT '[]');
        INSERT INTO scan (started_at, site) VALUES ('2026-11-01T10:00:00', 'old');
        INSERT INTO device (scan_id, instance, address) VALUES (1, 5, '10.0.0.5');
    """)
    old.commit()
    old.close()
    with Store(path) as st:
        s = st.load(1)
        assert s.site == "old" and s.network == {} and s.hosts == [] and s.device(5).eth_mac is None
        st.save(sample_scan())
        assert len(st.list()) == 2


def test_diff():
    import copy

    from bacscan.storage.diff import diff_lines, diff_scans

    a = sample_scan()
    b = copy.deepcopy(a)
    b.devices[0].props["firmware-revision"] = PropValue("2.0", "2.0")
    b.devices[0].objects[0].props["units"] = PropValue("degrees-fahrenheit", "degrees-fahrenheit")
    b.devices[0].objects[0].props["present-value"] = PropValue(70.0, "70")
    b.devices[0].objects.append(BacnetObject("binary-input", 1, {"object-name": PropValue("Alarm", "Alarm")}))
    b.devices.pop(1)
    b.devices.append(Device(instance=9, address="10.0.0.9", props={"object-name": PropValue("New", "New")}))
    b.network["internet"]["status"] = "none"
    b.hosts[0].ip = "10.0.0.254"
    b.hosts.append(Host("10.0.0.50", "00:11:22:33:44:55", "X"))

    d = diff_scans(a, b)
    assert d.devices_added == [(9, "New")] and d.devices_removed == [(8, "")]
    [dd] = d.devices_changed
    assert {c.what for c in dd.changes} == {"firmware", "object count"}
    assert dd.objects_added == ["binary-input,1"]
    assert [c.what for c in dd.object_changes] == ["analog-input,1 units"]  # values ignored by default
    assert [c.what for c in d.network_changes] == ["internet"]
    assert d.hosts_added == ["10.0.0.50 00:11:22:33:44:55 X"] and d.hosts_changed[0].new == "10.0.0.254"
    assert any(c.what == "analog-input,1 present-value" for c in diff_scans(a, b, values=True).devices_changed[0].object_changes)
    assert ("+", "device 9 New") in diff_lines(d)
    assert diff_lines(diff_scans(a, copy.deepcopy(a))) == [("#", "no differences")]


def test_xlsx_export(tmp_path):
    from openpyxl import load_workbook

    from bacscan.storage.xlsx import export_xlsx

    scan = sample_scan()
    scan.network["switch"] = {"found": True, "protocol": "LLDP", "system_name": "sw1", "port_id": "Gi1/0/1"}
    export_xlsx(scan, tmp_path / "s.xlsx")
    wb = load_workbook(tmp_path / "s.xlsx")
    assert wb.sheetnames[:6] == ["Summary", "Devices", "Objects", "Network", "Hosts", "7 AHU-1"]
    assert wb["Devices"]["B2"].value == "AHU-1" and wb["Objects"]["G2"].value == "21.25"
    assert any(r[0].value == "Switch" and "sw1" in r[1].value for r in wb["Network"].iter_rows(min_row=2))
