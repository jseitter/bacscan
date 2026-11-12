"""Compare two scans: devices, objects, network environment, hosts."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..core.models import Device, Scan

DEVICE_FIELDS = {
    "name": lambda d: d.name,
    "address": lambda d: d.address,
    "vendor": lambda d: d.text("vendor-name"),
    "model": lambda d: d.text("model-name"),
    "firmware": lambda d: d.text("firmware-revision"),
    "application version": lambda d: d.text("application-software-version"),
    "description": lambda d: d.text("description"),
    "location": lambda d: d.text("location"),
    "database revision": lambda d: d.text("database-revision"),
    "ethernet MAC": lambda d: d.eth_mac or "",
    "switch port": lambda d: d.switch_port or "",
    "object count": lambda d: str(len(d.objects)),
}
OBJECT_FIELDS = ["object-name", "description", "units"]
NETWORK_FIELDS = {
    "network": ("interface", "network"),
    "DHCP used": ("dhcp", "used"),
    "DHCP server": ("dhcp", "server"),
    "DNS servers (DHCP)": ("dhcp", "dns_servers"),
    "gateway": ("gateway", "ip"),
    "gateway MAC": ("gateway", "mac"),
    "internet": ("internet", "status"),
    "switch": ("switch", "system_name"),
    "switch port": ("switch", "port_id"),
    "switch VLAN": ("switch", "vlan"),
}


@dataclass
class Change:
    what: str
    old: str
    new: str


@dataclass
class DeviceDiff:
    instance: int
    name: str
    changes: list[Change] = field(default_factory=list)
    objects_added: list[str] = field(default_factory=list)
    objects_removed: list[str] = field(default_factory=list)
    object_changes: list[Change] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.changes or self.objects_added or self.objects_removed or self.object_changes)


@dataclass
class ScanDiff:
    a: int | None
    b: int | None
    devices_added: list[tuple[int, str]] = field(default_factory=list)
    devices_removed: list[tuple[int, str]] = field(default_factory=list)
    devices_changed: list[DeviceDiff] = field(default_factory=list)
    network_changes: list[Change] = field(default_factory=list)
    hosts_added: list[str] = field(default_factory=list)
    hosts_removed: list[str] = field(default_factory=list)
    hosts_changed: list[Change] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not any((self.devices_added, self.devices_removed, self.devices_changed, self.network_changes,
                        self.hosts_added, self.hosts_removed, self.hosts_changed))

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


def _diff_device(a: Device, b: Device, values: bool) -> DeviceDiff:
    dd = DeviceDiff(instance=b.instance, name=b.name or a.name)
    for label, f in DEVICE_FIELDS.items():
        if f(a) != f(b):
            dd.changes.append(Change(label, f(a), f(b)))
    oa = {o.key: o for o in a.objects}
    ob = {o.key: o for o in b.objects}
    # only compare objects if both scans read them (level device/discover has none)
    if a.objects and b.objects:
        dd.objects_added = sorted(k for k in ob if k not in oa)
        dd.objects_removed = sorted(k for k in oa if k not in ob)
        props = OBJECT_FIELDS + (["present-value", "out-of-service", "reliability"] if values else [])
        for k in sorted(set(oa) & set(ob)):
            for p in props:
                va, vb = oa[k].text(p), ob[k].text(p)
                if va != vb:
                    dd.object_changes.append(Change(f"{k} {p}", va, vb))
    return dd


def _get(net: dict, path: tuple[str, str]) -> str:
    v = net.get(path[0], {}).get(path[1])
    if isinstance(v, list):
        return ", ".join(map(str, v))
    return "" if v is None else str(v)


def diff_scans(a: Scan, b: Scan, values: bool = False) -> ScanDiff:
    """What changed from scan a (older) to scan b (newer). values=True also compares present values."""
    d = ScanDiff(a=a.id, b=b.id)
    da = {x.instance: x for x in a.devices}
    db = {x.instance: x for x in b.devices}
    d.devices_added = [(i, db[i].name) for i in sorted(db) if i not in da]
    d.devices_removed = [(i, da[i].name) for i in sorted(da) if i not in db]
    for i in sorted(set(da) & set(db)):
        dd = _diff_device(da[i], db[i], values)
        if not dd.empty:
            d.devices_changed.append(dd)
    if a.network and b.network:
        for label, path in NETWORK_FIELDS.items():
            va, vb = _get(a.network, path), _get(b.network, path)
            if va != vb:
                d.network_changes.append(Change(label, va, vb))
    if a.hosts and b.hosts:
        # identify hosts by MAC where known (IPs move with DHCP), else by IP
        def key(h):
            return h.mac or h.ip
        ha = {key(h): h for h in a.hosts}
        hb = {key(h): h for h in b.hosts}
        d.hosts_added = [f"{hb[k].ip} {hb[k].mac} {hb[k].vendor}".strip() for k in hb if k not in ha]
        d.hosts_removed = [f"{ha[k].ip} {ha[k].mac} {ha[k].vendor}".strip() for k in ha if k not in hb]
        for k in set(ha) & set(hb):
            if ha[k].ip != hb[k].ip:
                d.hosts_changed.append(Change(f"{k} ip", ha[k].ip, hb[k].ip))
            if ha[k].switch_port and hb[k].switch_port and ha[k].switch_port != hb[k].switch_port:
                d.hosts_changed.append(Change(f"{hb[k].ip} switch port", ha[k].switch_port, hb[k].switch_port))
            # open ports only compared when both scans ran deep discovery
            if ha[k].layers and hb[k].layers and ha[k].ports != hb[k].ports:
                d.hosts_changed.append(Change(f"{hb[k].ip} open TCP ports",
                                              " ".join(map(str, ha[k].ports)) or "none",
                                              " ".join(map(str, hb[k].ports)) or "none"))
    return d


def diff_lines(d: ScanDiff) -> list[tuple[str, str]]:
    """(kind, text) lines; kind is one of + - ~ for added / removed / changed, '#' for headings."""
    out: list[tuple[str, str]] = []
    if d.empty:
        return [("#", "no differences")]
    if d.devices_added or d.devices_removed:
        out.append(("#", "Devices"))
        out += [("+", f"device {i} {n}") for i, n in d.devices_added]
        out += [("-", f"device {i} {n}") for i, n in d.devices_removed]
    for dd in d.devices_changed:
        out.append(("#", f"Device {dd.instance} {dd.name}"))
        out += [("~", f"{c.what}: {c.old!r} -> {c.new!r}") for c in dd.changes]
        out += [("+", f"object {k}") for k in dd.objects_added]
        out += [("-", f"object {k}") for k in dd.objects_removed]
        out += [("~", f"{c.what}: {c.old!r} -> {c.new!r}") for c in dd.object_changes]
    if d.network_changes:
        out.append(("#", "Network"))
        out += [("~", f"{c.what}: {c.old!r} -> {c.new!r}") for c in d.network_changes]
    if d.hosts_added or d.hosts_removed or d.hosts_changed:
        out.append(("#", "Hosts"))
        out += [("+", h) for h in d.hosts_added]
        out += [("-", h) for h in d.hosts_removed]
        out += [("~", f"{c.what}: {c.old} -> {c.new}") for c in d.hosts_changed]
    return out
