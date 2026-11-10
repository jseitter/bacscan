"""Local network interface discovery and port checks."""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import psutil

BACNET_PORT = 47808

# interface name prefixes that are never a building network
_SKIP_PREFIXES = ("lo", "utun", "awdl", "llw", "gif", "stf", "anpi", "ap", "bridge", "vmenet")


@dataclass
class Interface:
    name: str
    ip: str
    netmask: str
    prefix: int
    broadcast: str
    is_up: bool
    speed: int  # Mbit/s, 0 if unknown (Wi-Fi often reports 0)

    @property
    def cidr(self) -> str:
        return f"{self.ip}/{self.prefix}"

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.cidr, strict=False)

    @property
    def likely_building_network(self) -> bool:
        return self.is_up and not self.name.startswith(_SKIP_PREFIXES)

    def label(self) -> str:
        return f"{self.name}  {self.cidr}  (bcast {self.broadcast})"


def list_interfaces(include_all: bool = False) -> list[Interface]:
    """IPv4 interfaces, most likely candidates first."""
    stats = psutil.net_if_stats()
    result: list[Interface] = []
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            net = ipaddress.ip_network(f"{a.address}/{a.netmask}", strict=False)
            st = stats.get(name)
            iface = Interface(
                name=name,
                ip=a.address,
                netmask=a.netmask,
                prefix=net.prefixlen,
                broadcast=a.broadcast or str(net.broadcast_address),
                is_up=bool(st and st.isup),
                speed=st.speed if st else 0,
            )
            if include_all or iface.likely_building_network:
                result.append(iface)
    # wired (speed known) before Wi-Fi, en0..enN by name
    result.sort(key=lambda i: (not i.likely_building_network, i.speed == 0, i.name))
    return result


def find_interface(name_or_ip: str | None) -> Interface:
    """Resolve an interface name ("en0") or IP address; None picks the best candidate."""
    candidates = list_interfaces(include_all=True)
    if name_or_ip:
        for i in candidates:
            if name_or_ip in (i.name, i.ip):
                return i
        raise ValueError(f"no IPv4 interface named or with address {name_or_ip!r}")
    best = list_interfaces()
    if not best:
        raise ValueError("no usable IPv4 network interface found (is the cable plugged in?)")
    return best[0]


def port_in_use(ip: str, port: int) -> bool:
    """True if a UDP socket cannot be bound on ip:port (another BACnet tool running?)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((ip, port))
        return False
    except OSError:
        return True
    finally:
        s.close()


def free_port(ip: str, start: int = BACNET_PORT + 1) -> int:
    for p in range(start, start + 100):
        if not port_in_use(ip, p):
            return p
    raise RuntimeError("no free UDP port found")


def expand_targets(spec: str) -> list[str]:
    """'10.0.0.5', '10.0.0.0/28', '10.0.0.5-10.0.0.20', optional ':port' suffix
    -> list of 'ip' or 'ip:port' strings (max 4096)."""
    spec = spec.strip()
    port = ""
    if spec.count(":") == 1:
        spec, p = spec.split(":")
        port = f":{int(p)}"
    if "-" in spec:
        lo, hi = (ipaddress.IPv4Address(x.strip()) for x in spec.split("-", 1))
        hosts = [str(ipaddress.IPv4Address(n)) for n in range(int(lo), int(hi) + 1)]
    elif "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    else:
        hosts = [str(ipaddress.IPv4Address(spec))]
    if len(hosts) > 4096:
        raise ValueError(f"target range {spec} too large ({len(hosts)} hosts, max 4096)")
    return [h + port for h in hosts]
