"""Deep discovery (E11): parsers offline, ping / TCP / HTTP / TLS against localhost."""
import asyncio
import shutil
import socket
import ssl
import struct
import subprocess

import pytest

from bacscan.core import discover as d
from bacscan.core.models import Host, Scan
from bacscan.storage.db import Store
from bacscan.storage.diff import diff_scans


def test_parse_ports():
    assert d.parse_ports("80, 443,8000-8002") == [80, 443, 8000, 8001, 8002]
    assert d.parse_ports(None) == sorted(d.PORTS)
    with pytest.raises(ValueError):
        d.parse_ports("0-5")


def test_echo_roundtrip():
    req = d.echo_request(0x1234, 7)
    assert d._checksum(req) == 0
    reply = bytes([0x45, 0, 0, 35, 0, 0, 0, 0, 117, 1, 0, 0]) + bytes(8) + b"\x00" + req[1:]
    assert d.parse_echo_reply(reply) == (117, 0x1234, 7)
    assert d.os_hint(117) == "Windows"
    assert d.os_hint(60) == "Linux/Unix/macOS/embedded"
    assert d.os_hint(250) == "network device / RTOS"


def _rr(name: bytes, typ: int, rdata: bytes) -> bytes:
    return name + struct.pack("!HHIH", typ, 1, 120, len(rdata)) + rdata


def test_mdns_parse_and_interpret():
    # answer with name compression: PTR -> instance, SRV -> host, A -> ip, TXT
    head = struct.pack("!6H", 0, 0x8400, 0, 4, 0, 0)
    stype = d._encode_name("_http._tcp.local")
    off_stype = 12
    inst = b"\x07Printer" + struct.pack("!H", 0xC000 | off_stype)
    a1 = _rr(stype, 12, inst)
    off_inst = 12 + len(stype) + 10
    host = d._encode_name("prn1.local")
    a2 = _rr(struct.pack("!H", 0xC000 | off_inst), 33, struct.pack("!HHH", 0, 0, 80) + host)
    a3 = _rr(d._encode_name("prn1.local"), 1, socket.inet_aton("10.0.0.9"))
    a4 = _rr(struct.pack("!H", 0xC000 | off_inst), 16, b"\x04txtv")
    pkt = head + a1 + a2 + a3 + a4
    recs = d.parse_dns(pkt)
    types = [t for _, t, _ in recs]
    assert types == [12, 33, 1, 16]
    assert recs[0][2] == "Printer._http._tcp.local"
    out = d.interpret_mdns(recs)
    assert out["10.0.0.9"]["name"] == "prn1.local"
    assert out["10.0.0.9"]["services"] == ["_http._tcp:80 (Printer)"]


def test_dns_query_layout():
    q = d.dns_query([("_services._dns-sd._udp.local", 12)])
    assert q[:12] == struct.pack("!6H", 0, 0, 1, 0, 0, 0)
    assert q.endswith(b"\x05local\x00\x00\x0c\x00\x01")


def test_ssdp_and_upnp():
    h = d.parse_ssdp(b"HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nSERVER: Linux UPnP/1.0 Foo/2\r\n"
                     b"LOCATION: http://10.0.0.5:49152/desc.xml\r\n\r\n")
    assert h["st"] == "upnp:rootdevice" and h["location"].endswith("desc.xml")
    assert d.parse_ssdp(b"NOTIFY * HTTP/1.1\r\n\r\n") == {}
    xml = (b'<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
           b"<friendlyName>Room 4 Display</friendlyName><manufacturer>ACME</manufacturer>"
           b"<modelName>D-100</modelName></device></root>")
    assert d.parse_upnp_description(xml) == {"friendlyName": "Room 4 Display", "manufacturer": "ACME",
                                             "modelName": "D-100"}


def test_nbstat():
    q = d.nbstat_query(5)
    assert len(q) == 50 and q[13:15] == b"CK"
    names = [(b"WS-0815        ", 0x00, 0x0400), (b"BUILDING       ", 0x00, 0x8400),
             (b"WS-0815        ", 0x20, 0x0400)]
    rdata = bytes([len(names)]) + b"".join(n + bytes([s]) + struct.pack("!H", f) for n, s, f in names)
    rdata += bytes.fromhex("001122334455") + bytes(40)
    resp = (struct.pack("!6H", 5, 0x8400, 0, 1, 0, 0) + q[12:46] + struct.pack("!HHIH", 0x21, 1, 0, len(rdata))
            + rdata)
    r = d.parse_nbstat(resp)
    assert r == {"name": "WS-0815", "group": "BUILDING", "mac": "00:11:22:33:44:55",
                 "names": ["BUILDING", "WS-0815"]}


def test_parse_http():
    r = d.parse_http(b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd/1.4\r\n"
                     b'WWW-Authenticate: Digest realm="AHU-3 controller", nonce="x"\r\n\r\n'
                     b"<html><TITLE> Login\n page </TITLE>")
    assert r == {"status": "401 Unauthorized", "server": "lighttpd/1.4", "realm": "AHU-3 controller",
                 "title": "Login page"}
    assert d.parse_http(b"SSH-2.0-x") == {}


def test_guess_kind_and_merge():
    hosts = [Host(ip="10.0.0.2", mac="00:11:22:33:44:55", note="gateway"), Host(ip="10.0.0.3")]
    res = {"10.0.0.3": {"icmp": {"rtt_ms": 1.2, "ttl": 127},
                        "ports": [{"port": 4911, "service": "niagara-fox-tls", "detail": "cert x"}],
                        "netbios": {"name": "JACE", "group": "", "mac": "", "names": ["JACE"]}},
           "10.0.0.4": {"ssdp": {"friendlyName": "Cam", "types": [], "manufacturer": "Axis"},
                        "ports": [{"port": 554, "service": "rtsp", "detail": ""}]}}
    out = d.merge(hosts, res)
    by = {h.ip: h for h in out}
    assert [h.ip for h in out] == ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
    assert by["10.0.0.2"].kind == "router / gateway"
    j = by["10.0.0.3"]
    assert (j.kind, j.ttl, j.os_hint, j.hostname, j.ports) == ("Niagara station (Tridium)", 127, "Windows",
                                                               "JACE", [4911])
    assert j.layers == ["icmp", "netbios", "tcp"]
    assert j.services["4911/tcp niagara-fox-tls"] == "cert x"
    assert by["10.0.0.4"].kind == "camera / video" and by["10.0.0.4"].source == "deep"


def test_details_stored_and_diffed(tmp_path):
    h = Host(ip="10.0.0.3", mac="00:11:22:33:44:55", rtt_ms=1.5, ttl=64, ports=[80], kind="x",
             services={"80/tcp http": "200 OK"}, layers=["arp", "tcp"])
    a = Scan(hosts=[h])
    with Store(tmp_path / "t.db") as st:
        st.save(a)
        b = st.load(a.id)
    assert b.hosts[0].details() == h.details()
    assert Scan.from_dict(a.to_dict()).hosts[0].services == h.services
    b.hosts[0].ports = [80, 22]
    changes = diff_scans(a, b).hosts_changed
    assert any("open TCP ports" in c.what and c.new == "80 22" for c in changes)


# ---------------------------------------------------------------- live, localhost only


def test_ping_localhost():
    r = d.ping_sweep(["127.0.0.1"], "127.0.0.1", wait=1.0)
    assert r["127.0.0.1"]["ttl"] > 0


async def _serve(handler, ssl_ctx=None):
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_ctx)
    return server, server.sockets[0].getsockname()[1]


async def _http_handler(reader, writer):
    await reader.readuntil(b"\r\n\r\n")
    writer.write(b"HTTP/1.0 200 OK\r\nServer: TestCtl/1.0\r\n\r\n<title>Plant room</title>")
    await writer.drain()
    writer.close()


def test_port_scan_http(monkeypatch):
    async def run():
        server, port = await _serve(_http_handler)
        monkeypatch.setitem(d.PORTS, port, "http-test")
        monkeypatch.setattr(d, "HTTP_PORTS", d.HTTP_PORTS | {port})
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        async with server:
            return port, await d.port_scan(["127.0.0.1"], [port, closed_port])
    port, res = asyncio.run(run())
    assert [r["port"] for r in res["127.0.0.1"]] == [port]
    assert res["127.0.0.1"][0]["detail"] == "200 OK · server TestCtl/1.0 · title Plant room"


@pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl to make a test certificate")
def test_port_scan_tls_cert(monkeypatch, tmp_path):
    key, crt = tmp_path / "k.pem", tmp_path / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(crt), "-days", "2", "-subj", "/CN=jace-8000.local"],
                   check=True, capture_output=True)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)

    async def run():
        server, port = await _serve(_http_handler, ctx)
        monkeypatch.setattr(d, "TLS_PORTS", d.TLS_PORTS | {port})
        async with server:
            return await d.probe_port("127.0.0.1", port)
    r = asyncio.run(run())
    assert "cert jace-8000.local (self-signed)" in r["detail"]
    assert "title Plant room" in r["detail"]
