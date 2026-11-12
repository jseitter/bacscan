"""A realistic, made-up scan for report/export tests."""
from bacscan.core.findings import DUPLICATE_PREFIX
from bacscan.core.models import BacnetObject, Device, Host, PropValue, Router, Scan


def _p(text, value=None):
    return PropValue(value if value is not None else text, str(text), None)


def _dev(inst, name, addr, vendor, model, fw, n_ai=3, status="done", **kw):
    d = Device(instance=inst, address=addr, vendor_id=5, max_apdu=1476, segmentation="segmented-both",
               status=status, **kw)
    d.props = {"object-name": _p(name), "vendor-name": _p(vendor), "model-name": _p(model),
               "firmware-revision": _p(fw), "location": _p("Plant room B1"), "description": _p(f"{name} controller")}
    for i in range(1, n_ai + 1):
        d.objects.append(BacnetObject("analog-input", i, {"object-name": _p(f"AI {i} temp"),
                                                          "present-value": _p("21.5", 21.5),
                                                          "units": _p("degrees-celsius")}))
    d.objects.append(BacnetObject("binary-value", 1, {"object-name": _p("Pump run"), "present-value": _p("active")}))
    return d


def sample_scan() -> Scan:
    s = Scan(id=7, started_at="2026-11-12T09:30:00+01:00", finished_at="2026-11-12T09:34:10+01:00",
             site="Riverside Office, building A", notes="Plant room and floors 1-3", interface="en7",
             local_address="10.20.0.50/24", level="full", status="completed", tool_version="0.1.0",
             settings={"deep": True, "switch_info": True})
    ahu = _dev(1001, "AHU-1", "10.20.0.11", "Siemens", "PXC5", "3.2.1", eth_mac="00:a0:03:11:22:33",
               eth_vendor="Siemens Building Technologies", eth_mac_source="arp")
    ahu.errors.append(f"{DUPLICATE_PREFIX} 10.20.0.19")
    ahu.switch_port = "sw-plant-01 Gi1/0/5 (VLAN 20)"
    s.devices = [
        ahu,
        _dev(1002, "Boiler", "10.20.0.12", "Honeywell", "Excel Web", "2.0", status="partial"),
        _dev(2001, "VAV 2.01", "2001:0x05", "Belimo", "VAV-Compact", "1.4", network=2001, mac="05",
             router="10.20.0.13:47808", eth_mac="00:1e:c0:aa:bb:cc", eth_vendor="Loytec", eth_mac_source="router"),
        _dev(2002, "VAV 2.02", "2001:0x06", "Belimo", "VAV-Compact", "1.4", n_ai=0, status="failed",
             network=2001, mac="06"),
    ]
    s.routers = [Router("10.20.0.13:47808", [2001, 2002])]
    s.network = {
        "interface": {"name": "en7", "ip": "10.20.0.50", "prefix": 24, "network": "10.20.0.0/24",
                      "mac": "a0:ce:c8:01:02:03", "hardware_port": "USB 10/100/1000 LAN"},
        "dhcp": {"used": True, "server": "10.20.0.1", "lease_seconds": 86400, "routers": ["10.20.0.1"]},
        "gateway": {"ip": "10.20.0.1", "reachable": False, "mac": "00:1b:17:00:01:02", "vendor": "Palo Alto"},
        "internet": {"status": "none"},
        "switch": {"found": True, "protocol": "LLDP", "system_name": "sw-plant-01", "port_id": "Gi1/0/12",
                   "vlan": 20, "source_mac": "00:11:22:33:44:55"},
        "deep_discovery": {"hosts": 6, "ports": [21, 23, 80, 443, 502, 1911, 4911]},
        "snmp": {"credentials": "v2c (community not stored)", "port": 161, "mac_ports": {}, "agents": [
            {"ip": "10.20.0.2", "version": "v2c", "ok": True, "sysName": "sw-plant-01",
             "sysDescr": "Cisco IOS Software, C2960X", "sysLocation": "Plant room B1", "fdb_entries": 14,
             "entity": {"model": "WS-C2960X-24PS-L", "serial": "FOC1234X0AB"},
             "lldp": [{"local_port": "Gi1/0/24", "local_port_num": 24, "remote_name": "sw-core",
                       "remote_port": "Te1/0/3", "remote_port_desc": "", "remote_chassis": ""}]},
            {"ip": "10.20.0.1", "version": "v2c", "ok": False, "error": "no answer"}]},
    }
    s.hosts = [
        Host("10.20.0.1", "00:1b:17:00:01:02", "Palo Alto", "fw.local", note="gateway", ports=[443],
             layers=["arp", "tcp"], kind="router / gateway"),
        Host("10.20.0.11", "00:a0:03:11:22:33", "Siemens", bacnet_instance=1001, ports=[80, 23],
             services={"80/tcp http": "200 OK · title PXC Web", "23/tcp telnet": ""},
             layers=["arp", "icmp", "tcp", "bacnet"], rtt_ms=1.2, ttl=64, kind="BACnet device",
             switch_port="sw-plant-01 Gi1/0/5 (VLAN 20)"),
        Host("10.20.0.13", "00:1e:c0:aa:bb:cc", "Loytec", note="BACnet router", ports=[80, 443],
             layers=["arp", "tcp"], services={"443/tcp https": "200 OK · cert LROC-603 (self-signed)"}),
        Host("10.20.0.20", "00:01:f0:00:00:01", "Tridium", "jace-1", ports=[1911, 4911],
             layers=["arp", "tcp"], kind="Niagara station (Tridium)",
             services={"4911/tcp niagara-fox-tls": "cert jace-1 (self-signed)"}),
        Host("10.20.0.30", "00:80:f4:00:00:02", "Schneider", ports=[502, 21], layers=["arp", "tcp"],
             kind="Modbus TCP device", services={"21/tcp ftp": "220 FTP server ready <script>"}),
        Host("10.20.0.50", "a0:ce:c8:01:02:03", "Apple", note="this Mac", source="local"),
    ]
    return s
