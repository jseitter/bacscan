"""SNMP read-out (M9): BER, USM key localization, port mapping; live against a local net-snmp agent."""
import asyncio
import json
import os
import shutil
import socket
import subprocess
import time

import pytest

from bacscan.core import snmp
from bacscan.core.findings import findings
from bacscan.core.models import Device, Host, Scan
from bacscan.core.scanner import ScanConfig, Scanner
from bacscan.storage.db import Store


def test_ber_roundtrip():
    oid = "1.3.6.1.4.1.8072.3.2.255"
    tag, val, _ = snmp.dec(snmp.enc_oid(oid))
    assert tag == 6 and snmp.dec_oid(val) == oid
    for n in (0, 1, 127, 128, 255, 256, -1, -129, 2**31 - 1):
        t, v, _ = snmp.dec(snmp.enc_int(n))
        assert snmp.decode_value(t, v) == n
    long = snmp.enc_oct(b"x" * 300)
    assert long[:4] == b"\x04\x82\x01\x2c"
    assert snmp.dec(long)[1] == b"x" * 300
    p = snmp.pdu(snmp.GETBULK, 42, ["1.3.6.1.2.1.1"], 0, 20)
    tag, rid, a, b, vbs = snmp.parse_pdu(p)
    assert (tag, rid, a, b, vbs) == (snmp.GETBULK, 42, 0, 20, [("1.3.6.1.2.1.1", None)])


def test_key_localization_rfc3414():
    engine = bytes.fromhex("000000000000000000000002")
    assert snmp.password_to_key("maplesyrup", engine, "md5").hex() == "526f5eed9fcce26f8964c2930787d82b"
    assert snmp.password_to_key("maplesyrup", engine, "sha1").hex() == "6695febc9288e36282235fc7151f128497b38f3f"


def test_credentials_validation_and_describe(monkeypatch):
    with pytest.raises(ValueError):
        snmp.Credentials("v2c")
    with pytest.raises(ValueError):
        snmp.Credentials("v3", user="u", auth_proto="SHA", auth_pass="short")
    with pytest.raises(ValueError):
        snmp.Credentials("v3", user="u", priv_proto="AES", priv_pass="longenough")
    c = snmp.Credentials("v3", user="ops", auth_proto="sha-256", auth_pass="secret-auth", priv_proto="aes128",
                         priv_pass="secret-priv")
    assert (c.auth_proto, c.priv_proto, c.level) == ("SHA256", "AES", "authPriv")
    assert "secret" not in c.describe() and "ops" in c.describe()
    monkeypatch.setenv("BACSCAN_SNMP_AUTH", "from-env-pass")
    e = snmp.Credentials.from_env(user="ops")
    assert (e.auth_proto, e.auth_pass, e.priv_proto) == ("SHA", "from-env-pass", "")
    cfg = ScanConfig(snmp_credentials=snmp.Credentials("v2c", community="topsecret"), snmp_targets=["10.0.0.1"])
    assert "topsecret" not in json.dumps(cfg.to_dict())
    assert cfg.to_dict()["snmp"] == "v2c (community not stored)"


def _agent(ip, name, fdb, lldp=(), ifs=()):
    return {"ip": ip, "ok": True, "sysName": name, "version": "v2c", "fdb": fdb, "lldp": list(lldp),
            "interfaces": list(ifs)}


def test_map_ports_skips_uplinks():
    edge = _agent("10.0.0.2", "sw-edge", [
        {"mac": "00:00:00:00:00:01", "interface": "Gi1/0/5", "vlan": 20},
        {"mac": "00:00:00:00:00:02", "interface": "Gi1/0/6", "vlan": 20},
    ] + [{"mac": f"00:00:00:00:01:{i:02x}", "interface": "Gi1/0/48", "vlan": 20} for i in range(10)])
    core = _agent("10.0.0.1", "sw-core", [
        {"mac": "00:00:00:00:00:01", "interface": "Te1/1", "vlan": 20},  # seen via the uplink to sw-edge
        {"mac": "00:00:00:00:00:03", "interface": "Gi2/3", "vlan": 30},
    ], lldp=[{"local_port": "Te1/1", "local_port_num": 1, "remote_name": "sw-edge"}])
    m = snmp.map_ports([edge, core])
    assert m["00:00:00:00:00:01"] == {"switch": "sw-edge", "switch_ip": "10.0.0.2", "port": "Gi1/0/5", "vlan": 20}
    assert m["00:00:00:00:00:03"]["switch"] == "sw-core"
    assert "00:00:00:00:01:00" not in m  # 10 MACs on Gi1/0/48: uplink
    assert edge["port_mac_counts"]["Gi1/0/48"] == 10

    hosts = [Host("10.0.0.50", "00:00:00:00:00:01"), Host("10.0.0.2", "00:00:00:00:00:99")]
    dev = Device(instance=5, address="10.0.0.50", eth_mac="00:00:00:00:00:01", eth_mac_source="arp")
    result = {"mac_ports": m, "agents": [dict(edge, fdb_entries=12)]}
    assert snmp.apply(result, hosts, [dev]) == 1
    assert hosts[0].switch_port == "sw-edge Gi1/0/5 (VLAN 20)"
    assert dev.switch_port == "sw-edge Gi1/0/5 (VLAN 20)"
    assert hosts[1].hostname == "sw-edge" and hosts[1].kind == "switch" and "snmp" in hosts[1].layers


def test_collect_targets():
    net = {"gateway": {"ip": "10.0.0.1"}, "switch": {"management_addresses": ["10.0.0.2"]}}
    hosts = [Host("10.0.0.7"), Host("10.0.0.50")]
    assert snmp.collect_targets(["10.0.0.9"], net, hosts, True, False) == ["10.0.0.9", "10.0.0.1", "10.0.0.2"]
    assert snmp.collect_targets([], net, hosts, False, True, own_ip="10.0.0.50") == ["10.0.0.7"]
    with pytest.raises(ValueError):
        snmp.collect_targets(["10.0.0.0/23"], {}, [], False, False)


def test_finding_and_storage(tmp_path):
    h = Host("10.0.0.2", "00:00:00:00:00:02", switch_port="sw1 Gi1/0/1 (VLAN 5)")
    d = Device(instance=1, address="10.0.0.3", switch_port="sw1 Gi1/0/2")
    s = Scan(devices=[d], hosts=[h], network={"snmp": {"agents": [{"ip": "10.0.0.2", "ok": True, "version": "v2c",
                                                                    "sysName": "sw1"}]}})
    assert any(f.title == "SNMP v1/v2c answering" and f.items == ["10.0.0.2 (sw1)"] for f in findings(s))
    with Store(tmp_path / "t.db") as st:
        st.save(s)
        back = st.load(s.id)
    assert back.hosts[0].switch_port == h.switch_port and back.devices[0].switch_port == "sw1 Gi1/0/2"


# ---------------------------------------------------------------- live: net-snmp agent on loopback

SNMPD = "/usr/libexec/snmpd" if os.path.exists("/usr/libexec/snmpd") else shutil.which("snmpd")


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def agent(tmp_path_factory):
    if not SNMPD:
        pytest.skip("net-snmp agent not available")
    d = tmp_path_factory.mktemp("snmpd")
    port = _free_udp_port()
    conf = d / "snmpd.conf"
    conf.write_text(f"""agentaddress udp:127.0.0.1:{port}
rocommunity testcomm 127.0.0.1
createUser privuser SHA "authpass123" AES "privpass123"
createUser authonly SHA "authpass123"
rouser privuser priv
rouser authonly auth
sysName testagent
sysLocation Lab rack 3
""")
    proc = subprocess.Popen([SNMPD, "-f", "-Lo", "-C", "-c", str(conf), "-p", str(d / "pid"),
                             f"--persistentDir={d / 'persist'}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    creds = snmp.Credentials("v2c", community="testcomm")
    for _ in range(30):
        time.sleep(0.1)
        if snmp.read_agent("127.0.0.1", creds, port, tables=False, timeout=0.3, retries=0).get("ok"):
            break
    else:
        proc.kill()
        pytest.skip("net-snmp agent did not start")
    yield port
    proc.terminate()
    proc.wait(5)


@pytest.mark.parametrize("creds", [
    snmp.Credentials("v2c", community="testcomm"),
    snmp.Credentials("v3", user="authonly", auth_proto="SHA", auth_pass="authpass123"),
    snmp.Credentials("v3", user="privuser", auth_proto="SHA", auth_pass="authpass123", priv_proto="AES",
                     priv_pass="privpass123"),
], ids=["v2c", "v3-auth", "v3-priv"])
def test_live_read(agent, creds):
    r = snmp.read_agent("127.0.0.1", creds, agent, timeout=1.0)
    assert r["ok"], r.get("error")
    assert r["sysName"] == "testagent" and r["sysLocation"] == "Lab rack 3"
    assert any(i["name"] == "lo0" for i in r["interfaces"])


@pytest.mark.parametrize("creds,error", [
    (snmp.Credentials("v3", user="privuser", auth_proto="SHA", auth_pass="wrongpass1", priv_proto="AES",
                      priv_pass="privpass123"), "wrong authentication"),
    (snmp.Credentials("v3", user="nobody", auth_proto="SHA", auth_pass="authpass123"), "unknown user"),
])
def test_live_errors(agent, creds, error):
    r = snmp.read_agent("127.0.0.1", creds, agent, tables=False, timeout=1.0, retries=0)
    assert not r["ok"] and error in r["error"]


def test_live_walk_and_no_answer(agent):
    with snmp.SnmpClient("127.0.0.1", snmp.Credentials("v2c", community="testcomm"), agent) as c:
        rows = c.walk("1.3.6.1.2.1.1")
        assert rows[0][0] == "1.3.6.1.2.1.1.1.0" and len(rows) >= 6
        assert all(o.startswith("1.3.6.1.2.1.1.") for o, _ in rows)
    r = snmp.read_agent("127.0.0.1", snmp.Credentials("v2c", community="x"), _free_udp_port(), timeout=0.3,
                        retries=0)
    assert not r["ok"] and r["error"]


def test_live_scanner_integration(agent, port_pair):
    cfg = ScanConfig(bind_address=f"127.0.0.1/32:{port_pair[1]}", broadcast=False, targets=[], whois_timeout=0.3,
                     network_info=False, snmp_credentials=snmp.Credentials("v2c", community="testcomm"),
                     snmp_targets=["127.0.0.1"], snmp_port=agent)
    scan = asyncio.run(Scanner(cfg).run())
    a = scan.network["snmp"]["agents"][0]
    assert a["ok"] and a["sysName"] == "testagent"
    assert scan.settings["snmp"] == "v2c (community not stored)"
    assert "testcomm" not in json.dumps(scan.to_dict())


def test_cli_snmp(agent, capsys):
    from bacscan.cli.main import main
    assert main(["snmp", "127.0.0.1", "-c", "testcomm", "--snmp-port", str(agent), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["agents"][0]["sysName"] == "testagent"
    assert "testcomm" not in json.dumps(out)
