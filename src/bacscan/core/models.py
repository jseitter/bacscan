"""Plain data model shared by scanner, storage, CLI and GUI."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


@dataclass
class PropValue:
    """One property as read from a device."""

    value: Any = None  # JSON-serialisable value
    text: str = ""  # human-readable rendering
    error: str | None = None  # error/reject/abort text if the read failed

    @classmethod
    def from_dict(cls, d: dict) -> "PropValue":
        return cls(value=d.get("value"), text=d.get("text", ""), error=d.get("error"))


@dataclass
class BacnetObject:
    object_type: str  # e.g. "analog-input"
    instance: int
    props: dict[str, PropValue] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.object_type},{self.instance}"

    def text(self, prop: str) -> str:
        p = self.props.get(prop)
        return p.text if p and p.error is None else ""

    @property
    def name(self) -> str:
        return self.text("object-name")

    def to_dict(self) -> dict:
        return {
            "object_type": self.object_type,
            "instance": self.instance,
            "props": {k: asdict(v) for k, v in self.props.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BacnetObject":
        return cls(
            object_type=d["object_type"],
            instance=d["instance"],
            props={k: PropValue.from_dict(v) for k, v in d.get("props", {}).items()},
        )


@dataclass
class Device:
    instance: int
    address: str  # bacpypes address string, e.g. "10.0.0.5" or "2001:0x05"
    network: int | None = None  # remote network number (None = local)
    mac: str | None = None  # MAC on remote network, hex
    router: str | None = None  # router address for remote devices
    vendor_id: int | None = None
    max_apdu: int | None = None
    segmentation: str | None = None
    first_seen: str = field(default_factory=now_iso)
    props: dict[str, PropValue] = field(default_factory=dict)  # device object properties
    objects: list[BacnetObject] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    status: str = "discovered"  # discovered | reading | done | partial | failed
    eth_mac: str | None = None  # Ethernet MAC (from ARP) of the device or, if remote, its router
    eth_vendor: str = ""  # vendor from the MAC's OUI prefix
    eth_mac_source: str = ""  # "arp" (device itself) | "router" (device is behind a BACnet router)
    switch_port: str = ""  # switch / port / VLAN of eth_mac, from SNMP (S4)
    diag: dict = field(default_factory=dict)  # read diagnostics (requests, timeouts, events), see DeviceReader

    @property
    def ip(self) -> str | None:
        """IPv4 address for BACnet/IP devices on the local network, else None."""
        if self.network is not None:
            return None
        host = self.address.split(":")[0]
        return host if host.count(".") == 3 else None

    def text(self, prop: str) -> str:
        p = self.props.get(prop)
        return p.text if p and p.error is None else ""

    @property
    def name(self) -> str:
        return self.text("object-name")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["props"] = {k: asdict(v) for k, v in self.props.items()}
        d["objects"] = [o.to_dict() for o in self.objects]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Device":
        d = dict(d)
        props = {k: PropValue.from_dict(v) for k, v in d.pop("props", {}).items()}
        objects = [BacnetObject.from_dict(o) for o in d.pop("objects", [])]
        return cls(**d, props=props, objects=objects)


@dataclass
class Host:
    """Any IP host seen on the scan interface (ARP table / sweep)."""

    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    bacnet_instance: int | None = None  # set when this host is a BACnet device
    source: str = "arp"  # arp | sweep | local | deep
    note: str = ""  # e.g. "gateway", "this Mac", "BACnet router"
    # deep discovery (E11)
    rtt_ms: float | None = None  # ICMP echo round trip
    ttl: int | None = None
    os_hint: str = ""  # from TTL
    kind: str = ""  # best guess, e.g. "Niagara station (Tridium)", "printer"
    ports: list[int] = field(default_factory=list)  # open TCP ports
    services: dict[str, str] = field(default_factory=dict)  # "80/tcp http" -> "200 OK · title …"
    layers: list[str] = field(default_factory=list)  # where it answered: arp, icmp, tcp, mdns, ssdp, netbios
    switch_port: str = ""  # from SNMP forwarding tables (S4), e.g. "sw-01 Gi1/0/5 (VLAN 20)"

    DETAIL_FIELDS = ("rtt_ms", "ttl", "os_hint", "kind", "ports", "services", "layers", "switch_port")

    def details(self) -> dict:
        return {k: getattr(self, k) for k in self.DETAIL_FIELDS}


@dataclass
class Router:
    address: str
    networks: list[int] = field(default_factory=list)


@dataclass
class Scan:
    id: int | None = None
    started_at: str = field(default_factory=now_iso)
    finished_at: str | None = None
    site: str = ""
    notes: str = ""
    interface: str = ""
    local_address: str = ""
    level: str = "full"
    settings: dict = field(default_factory=dict)
    tool_version: str = ""
    status: str = "running"  # running | completed | cancelled | failed
    devices: list[Device] = field(default_factory=list)
    routers: list[Router] = field(default_factory=list)
    network: dict = field(default_factory=dict)  # environment survey (see core/netinfo.py)
    hosts: list[Host] = field(default_factory=list)

    def device(self, instance: int) -> Device | None:
        return next((d for d in self.devices if d.instance == instance), None)

    @property
    def object_count(self) -> int:
        return sum(len(d.objects) for d in self.devices)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["devices"] = [x.to_dict() for x in self.devices]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Scan":
        d = dict(d)
        devices = [Device.from_dict(x) for x in d.pop("devices", [])]
        routers = [Router(**r) for r in d.pop("routers", [])]
        hosts = [Host(**h) for h in d.pop("hosts", [])]
        return cls(**d, devices=devices, routers=routers, hosts=hosts)
