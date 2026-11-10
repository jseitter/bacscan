from bacscan.core import lldp


def tlv(t, value: bytes) -> bytes:
    return ((t << 9) | len(value)).to_bytes(2, "big") + value


def lldp_frame(vlan_tagged=False) -> bytes:
    body = (tlv(1, b"\x04" + bytes.fromhex("001122334455"))
            + tlv(2, b"\x05" + b"Gi1/0/12")
            + tlv(3, (120).to_bytes(2, "big"))
            + tlv(4, b"BMS uplink")
            + tlv(5, b"core-sw-01")
            + tlv(6, b"Cisco IOS Software, C2960X")
            + tlv(7, (0x0014).to_bytes(2, "big") + (0x0004).to_bytes(2, "big"))
            + tlv(8, b"\x05\x01" + bytes([10, 1, 2, 3]) + b"\x02\x00\x00\x00\x01\x00")
            + tlv(127, b"\x00\x80\xc2\x01" + (42).to_bytes(2, "big"))
            + tlv(0, b""))
    eth = bytes.fromhex("0180c200000e") + bytes.fromhex("00000c112233")
    if vlan_tagged:
        eth += b"\x81\x00" + (42).to_bytes(2, "big")
    return eth + b"\x88\xcc" + body


def cdp_frame() -> bytes:
    def t(typ, value: bytes) -> bytes:
        return typ.to_bytes(2, "big") + (len(value) + 4).to_bytes(2, "big") + value
    addr = (1).to_bytes(4, "big") + b"\x01\x01\xcc" + (4).to_bytes(2, "big") + bytes([192, 168, 5, 1])
    body = (t(1, b"floor3-sw") + t(3, b"FastEthernet0/7") + t(4, (0x08).to_bytes(4, "big"))
            + t(6, b"cisco WS-C3560") + t(10, (100).to_bytes(2, "big")) + t(11, b"\x01") + t(2, addr))
    cdp = b"\x02\xb4\x00\x00" + body
    llc = bytes.fromhex("aaaa0300000c2000")
    payload = llc + cdp
    return bytes.fromhex("01000ccccccc") + bytes.fromhex("00000c445566") + len(payload).to_bytes(2, "big") + payload


def test_lldp():
    info = lldp.parse_frame(lldp_frame())
    assert info["protocol"] == "LLDP"
    assert info["chassis_id"] == "00:11:22:33:44:55" and info["port_id"] == "Gi1/0/12"
    assert info["system_name"] == "core-sw-01" and info["port_description"] == "BMS uplink"
    assert info["vlan"] == 42 and info["management_addresses"] == ["10.1.2.3"]
    assert info["capabilities"] == ["bridge"] and info["ttl"] == 120
    assert "Cisco" in info["source_vendor"]


def test_lldp_vlan_tagged():
    info = lldp.parse_frame(lldp_frame(vlan_tagged=True))
    assert info["frame_vlan"] == 42 and info["system_name"] == "core-sw-01"


def test_cdp():
    info = lldp.parse_frame(cdp_frame())
    assert info["protocol"] == "CDP" and info["system_name"] == "floor3-sw"
    assert info["port_id"] == "FastEthernet0/7" and info["vlan"] == 100
    assert info["capabilities"] == ["switch"] and info["duplex"] == "full"
    assert info["addresses"] == ["192.168.5.1"] and info["platform"] == "cisco WS-C3560"


def test_other_frames_ignored():
    assert lldp.parse_frame(bytes(60)) is None


def test_tcpdump_hex_roundtrip():
    frame = lldp_frame()
    lines = ["08:00:00.000000 LLDP, length %d" % len(frame)]
    for off in range(0, len(frame), 16):
        chunk = frame[off:off + 16].hex()
        words = " ".join(chunk[i:i + 4] for i in range(0, len(chunk), 4))
        lines.append(f"\t0x{off:04x}:  {words}")
    lines.append("08:00:01.000000 other, length 60")
    frames = lldp.parse_tcpdump_hex("\n".join(lines))
    assert frames == [frame]


def test_summarize():
    rows = dict(lldp.summarize(lldp.parse_frame(lldp_frame()) | {"found": True}))
    assert rows["Switch"] == "core-sw-01 (LLDP)" and rows["Switch port"] == "Gi1/0/12 - BMS uplink"
    assert rows["Switch VLAN"] == "42"
    assert lldp.summarize({"found": False, "waited_s": 35}) == [
        ("Switch", "no LLDP/CDP frame received within 35 s")]
