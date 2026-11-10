from bacscan.core import netinfo, oui

GETPACKET = """op = BOOTREPLY
yiaddr = 172.20.15.130
siaddr = 172.20.0.1
chaddr = 02:11:22:33:44:55
options:
Options count is 8
dhcp_message_type (uint8): ACK 0x5
subnet_mask (ip): 255.255.240.0
router (ip_mult): {172.20.0.1}
domain_name_server (ip_mult): {172.20.0.1, 8.8.8.8}
domain_name (string): site.local
lease_time (uint32): 0x15180
server_identifier (ip): 172.20.0.1
end (none):
"""

SCUTIL = """DNS configuration

resolver #1
  search domain[0] : example.lan
  nameserver[0] : 192.168.1.1
  if_index : 29 (utun6)
  flags    : Supplemental

resolver #2
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 172.20.0.1
  if_index : 14 (en0)
"""

IFCONFIG = """en0: flags=8863<UP,BROADCAST> mtu 1500
\tether 02:11:22:33:44:55
\tinet6 fe80::1:2:3:4%en0 prefixlen 64 secured scopeid 0xe
\tinet 172.20.15.130 netmask 0xfffff000 broadcast 172.20.15.255
\tmedia: autoselect (1000baseT <full-duplex>)
\tstatus: active
"""

ARP = """? (172.20.0.1) at bc:24:11:30:41:32 on en0 ifscope [ethernet]
? (172.20.0.33) at (incomplete) on en0 ifscope [ethernet]
? (172.20.0.35) at f2:23:3a:7d:66:1 on en0 ifscope [ethernet]
? (172.20.15.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (10.0.0.9) at 0:1:f0:aa:bb:cc on en7 ifscope [ethernet]
"""


def test_parse_getpacket():
    d = netinfo.parse_getpacket(GETPACKET)
    assert d["used"] and d["server"] == "172.20.0.1"
    assert d["routers"] == ["172.20.0.1"] and d["dns_servers"] == ["172.20.0.1", "8.8.8.8"]
    assert d["lease_seconds"] == 86400 and d["domain"] == "site.local"
    assert netinfo.parse_getpacket("") == {}


def test_parse_scutil_ignores_mdns_and_scoped():
    r = netinfo.parse_scutil_dns(SCUTIL)
    assert r == [{"nameservers": ["192.168.1.1"], "search": ["example.lan"], "domain": "", "interface": "utun6"}]


def test_parse_ifconfig():
    d = netinfo.parse_ifconfig(IFCONFIG)
    assert d["mtu"] == 1500 and d["mac"] == "02:11:22:33:44:55" and d["status"] == "active"
    assert d["media"].startswith("autoselect (1000baseT") and d["ipv6"] == ["fe80::1:2:3:4/64"]


def test_parse_arp():
    rows = netinfo.parse_arp(ARP)
    assert rows == [("172.20.0.1", "bc:24:11:30:41:32", "en0"), ("172.20.0.35", "f2:23:3a:7d:66:01", "en0"),
                    ("10.0.0.9", "00:01:f0:aa:bb:cc", "en7")]


def test_parse_ping_and_route():
    ping = "3 packets transmitted, 3 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 1.1/2.5/4.0/1.0 ms"
    assert netinfo.parse_ping(ping) == {"sent": 3, "received": 3, "rtt_ms": 2.5}
    assert netinfo.parse_route_get("   gateway: 172.20.0.1\n  interface: en0\n") == {"gateway": "172.20.0.1", "interface": "en0"}


def test_oui():
    assert oui.normalize_mac("0:1:F0:a:b:c") == "00:01:f0:0a:0b:0c"
    assert oui.normalize_mac("0001.f00a.0b0c") == "00:01:f0:0a:0b:0c"
    assert oui.normalize_mac("nonsense") is None
    assert "Tridium" in oui.vendor("00:01:f0:00:00:01")
    assert oui.vendor("02:11:22:33:44:55") == "(random/local MAC)"


def test_summarize():
    info = {"interface": {"name": "en5", "ip": "10.0.0.2", "prefix": 24, "mac": "00:01:f0:00:00:01"},
            "dhcp": {"used": False}, "gateway": {"ip": "10.0.0.1", "reachable": False},
            "internet": {"status": "none", "route_interface": "utun3", "via_vpn": True}}
    rows = dict(netinfo.summarize(info))
    assert rows["DHCP"] == "not used (static address)"
    assert rows["Gateway"] == "10.0.0.1 (no ping reply)"
    assert rows["Internet"] == "none" and rows["Internet route"] == "utun3 (VPN!)"
