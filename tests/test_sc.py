"""BACnet/SC: wire format, TLS/handshake errors, and scans through a simulated hub (with and without direct connect)."""
import asyncio
import os

import pytest

from bacpypes3.pdu import PDU
from bacpypes3.sc import bvll

from bacscan.core import sc
from bacscan.core.scanner import ScanConfig, ScanError, Scanner, read_single
from sim_sc import SimHub, SimSCDevice, make_pki, server_context


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- wire format


def _theirs(raw: bytes):
    """Decode with bacpypes3's independent implementation."""
    pdu = PDU(raw)
    lpci = bvll.LPCI.decode(pdu)
    lpdu = bvll.pdu_types[lpci.bvlcFunction].decode(pdu)
    bvll.LPCI.update(lpdu, lpci)
    return lpdu


def test_codec_vectors():
    assert sc.encode(sc.Message(sc.HEARTBEAT_REQUEST, 0x1234)) == bytes.fromhex("0a001234")
    raw = sc.encode(sc.Message(sc.ENCAPSULATED_NPDU, 1, dest=b"\xff" * 6, payload=b"\x01\x20\xff"))
    assert raw == bytes.fromhex("010400" "01" "ffffffffffff" "0120ff")
    m = sc.decode(bytes.fromhex("010c0009" "0a0a0a0a0a0a" "ffffffffffff" "0120"))
    assert (m.function, m.message_id, m.origin, m.dest, m.payload) == (1, 9, b"\x0a" * 6, b"\xff" * 6, b"\x01\x20")


def test_codec_matches_bacpypes3():
    vmac, uid = bytes.fromhex("0211223344f5"), bytes(range(16))
    ours = sc.encode(sc.Message(sc.CONNECT_REQUEST, 7, payload=sc.connect_payload(vmac, uid)))
    theirs = _theirs(ours)
    assert theirs.bvlcMessageID == 7 and bytes(theirs.vmac_address.addrAddr) == vmac
    assert theirs.device_uuid.bytes == uid and theirs.maximum_npdu_length == sc.MAX_NPDU
    m = sc.decode(ours)
    assert sc.parse_connect(m.payload) == (vmac, uid, sc.MAX_BVLC, sc.MAX_NPDU)
    enc = _theirs(sc.encode(sc.Message(sc.ENCAPSULATED_NPDU, 3, origin=vmac, dest=b"\xff" * 6, payload=b"\x01\x00")))
    assert bytes(enc.bvlcOriginatingVirtualAddress.addrAddr) == vmac


def test_header_options_are_skipped():
    # destination option: more-follows + data present (type 1, 2 bytes), then a last empty option; payload after
    opts = bytes([0x80 | 0x20 | 0x01, 0x00, 0x02, 0xAA, 0xBB, 0x02])
    m = sc.decode(bytes.fromhex("01020005") + opts + b"\x01\x20")
    assert m.dest_options == opts and m.payload == b"\x01\x20"
    with pytest.raises(ValueError):
        sc.decode(bytes.fromhex("0102000580"))


def test_result_nak_text():
    func, nak, text = sc.parse_result(sc.result_payload(6, (7, 33, "node VMAC collision")))
    assert (func, nak) == (6, True) and "collision" in text
    assert sc.parse_result(sc.result_payload(6)) == (6, False, "")


def test_random_vmac_is_local_unicast():
    for _ in range(50):
        v = sc.random_vmac()
        assert len(v) == 6 and v[0] & 0x03 == 0x02 and v != sc.BROADCAST_VMAC


def test_settings_validation(tmp_path):
    with pytest.raises(sc.SCError, match="wss://"):
        sc.SCSettings(hub="http://x").validate()
    with pytest.raises(sc.SCError, match="together"):
        sc.SCSettings(hub="wss://x", cert="a").validate()
    with pytest.raises(sc.SCError, match="not found"):
        sc.SCSettings(hub="wss://x", ca=str(tmp_path / "nope.pem")).validate()


def test_key_password_never_stored():
    cfg = ScanConfig(sc_hub="wss://h:443", sc_key_password="hunter2")
    assert "hunter2" not in str(cfg.to_dict())


# ---------------------------------------------------------------- scans through a hub


@pytest.fixture()
def pki(tmp_path):
    return make_pki(tmp_path / "pki", other_ca=True)


def cfg_for(hub: SimHub, pki, **kw) -> ScanConfig:
    base = dict(sc_hub=hub.uri, sc_cert=pki["cert"], sc_key=pki["key"], sc_ca=pki["ca"], whois_timeout=1.5,
                network_info=False, apdu_timeout=2.0, retries=1, site="SC test")
    base.update(kw)
    return ScanConfig(**base)


async def with_network(pki, body, direct_port=None, n_devices=1):
    hub = await SimHub(server_context(pki["hub_cert"], pki["hub_key"], pki["ca"])).start()
    devices = []
    try:
        for i in range(n_devices):
            devices.append(await SimSCDevice(hub.uri, pki, 2001 + i,
                                             direct_port=(direct_port + i) if direct_port else None).start())
        return await body(hub, devices)
    finally:
        for d in devices:
            await d.stop()
        await hub.stop()


def test_scan_through_hub(pki):
    async def body(hub, devices):
        events = []
        scan = await Scanner(cfg_for(hub, pki), events.append).run()
        return scan, events, devices[0]

    scan, events, dev = run(with_network(pki, body))
    assert scan.status == "completed", [e.message for e in events if e.kind == "log"]
    assert scan.interface.startswith("BACnet/SC wss://127.0.0.1")
    assert len(scan.devices) == 1
    d = scan.devices[0]
    assert d.instance == 2001 and d.status == "done" and len(d.objects) == 8
    assert d.address == "0x" + dev.vmac.hex()
    assert any("connected to hub" in e.message for e in events)
    assert "sc_key_password" not in scan.settings


def test_scan_two_devices_and_broadcast(pki):
    async def body(hub, devices):
        return await Scanner(cfg_for(hub, pki, level="discover"), None).run()

    scan = run(with_network(pki, body, n_devices=2))
    assert sorted(d.instance for d in scan.devices) == [2001, 2002]


def test_direct_connect(pki):
    async def body(hub, devices):
        scan = await Scanner(cfg_for(hub, pki, sc_direct=True), None).run()
        return scan, devices[0]

    scan, dev = run(with_network(pki, body, direct_port=18701))
    assert scan.status == "completed" and len(scan.devices[0].objects) == 8
    assert dev.direct_frames > 0, "no request reached the device over its direct connection"


def test_read_single_through_hub(pki):
    async def body(hub, devices):
        v = await read_single(cfg_for(hub, pki), "0x" + devices[0].vmac.hex(), "device,2001", "object-name")
        return v

    v = run(with_network(pki, body))
    assert "SimSC-2001" in str(v.text or v.value)


def test_vmac_collision_is_reported(pki):
    async def body(hub, devices):
        s = sc.SCSettings(hub=hub.uri, cert=pki["cert"], key=pki["key"], ca=pki["ca"], vmac=devices[0].vmac)
        link = sc.SCLinkLayer(s)
        with pytest.raises(sc.SCError, match="collision"):
            await link.start()

    run(with_network(pki, body))


def test_untrusted_hub_certificate(pki):
    async def body(hub, devices):
        cfg = cfg_for(hub, pki, sc_ca=pki["rogue_ca"])
        with pytest.raises(ScanError, match="certificate was rejected"):
            await Scanner(cfg, None).run()

    run(with_network(pki, body, n_devices=0))


def test_missing_client_certificate(pki):
    async def body(hub, devices):
        cfg = cfg_for(hub, pki, sc_cert=None, sc_key=None)
        with pytest.raises(ScanError, match="BACnet/SC"):
            await Scanner(cfg, None).run()

    run(with_network(pki, body, n_devices=0))


def test_verification_can_be_disabled(pki):
    async def body(hub, devices):
        scan = await Scanner(cfg_for(hub, pki, sc_ca=None, sc_verify=False, level="discover"), None).run()
        return scan

    scan = run(with_network(pki, body))
    assert len(scan.devices) == 1


def test_hub_down():
    async def body():
        cfg = ScanConfig(sc_hub="wss://127.0.0.1:1", network_info=False)
        with pytest.raises(ScanError, match="refused|timeout|failed"):
            await Scanner(cfg, None).run()

    run(body())


def test_cli_scan_over_sc(pki, capsys, tmp_path):
    import threading

    from bacscan.cli.main import main

    ready, stop, info = threading.Event(), threading.Event(), {}

    def network():
        async def go():
            hub = await SimHub(server_context(pki["hub_cert"], pki["hub_key"], pki["ca"])).start()
            dev = await SimSCDevice(hub.uri, pki, 2001).start()
            info["uri"] = hub.uri
            ready.set()
            while not stop.is_set():
                await asyncio.sleep(0.1)
            await dev.stop()
            await hub.stop()
        asyncio.run(go())

    t = threading.Thread(target=network, daemon=True)
    t.start()
    assert ready.wait(10)
    try:
        rc = main(["--db", str(tmp_path / "cli.db"), "scan", "--sc-hub", info["uri"], "--sc-cert", pki["cert"],
                   "--sc-key", pki["key"], "--sc-ca", pki["ca"], "--level", "device", "--timeout", "1.5",
                   "--no-network-info", "--site", "CLI SC"])
    finally:
        stop.set()
        t.join(10)
    out = capsys.readouterr().out
    assert rc == 0 and "2001" in out and "0x" in out, out
