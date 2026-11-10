"""BACnet/IP scan engine: discovery (Who-Is / routers) and read-only device read-out.

Only read-only services are ever sent: Who-Is, Who-Is-Router-To-Network,
ReadProperty and ReadPropertyMultiple.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
import types
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from bacpypes3.apdu import ErrorRejectAbortNack, WhoIsRequest
from bacpypes3.app import Application
from bacpypes3.basetypes import ErrorType, PropertyIdentifier
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier

from .. import __version__
from . import lldp, netinfo
from . import network as netmod
from .models import BacnetObject, Device, PropValue, Router, Scan, now_iso
from .values import error_text, is_unknown_property, to_json, to_text

log = logging.getLogger("bacscan")

LEVELS = ("discover", "device", "full", "all")

# ---------------------------------------------------------------- property sets


def _props(*names: str) -> list[str]:
    """Keep only names bacpypes3 knows (guards against typos / old versions)."""
    ok = []
    for n in names:
        try:
            PropertyIdentifier(n)
            ok.append(n)
        except ValueError:
            log.debug("unknown property name %s ignored", n)
    return ok


DEVICE_PROPS = _props(
    "object-name", "vendor-name", "vendor-identifier", "model-name",
    "firmware-revision", "application-software-version", "description",
    "location", "serial-number", "protocol-version", "protocol-revision",
    "protocol-services-supported", "protocol-object-types-supported",
    "max-apdu-length-accepted", "segmentation-supported", "max-segments-accepted",
    "system-status", "database-revision", "local-date", "local-time",
    "utc-offset", "daylight-savings-status", "apdu-timeout",
    "number-of-apdu-retries", "max-master", "max-info-frames",
    "last-restart-reason", "time-of-device-restart",
)

COMMON_PROPS = _props(
    "object-name", "description", "present-value", "units", "status-flags",
    "event-state", "reliability", "out-of-service",
)

_TYPE_PROPS = {
    "analog-input": ("cov-increment", "min-pres-value", "max-pres-value", "resolution", "device-type"),
    "analog-output": ("cov-increment", "min-pres-value", "max-pres-value", "relinquish-default", "priority-array", "device-type"),
    "analog-value": ("cov-increment", "min-pres-value", "max-pres-value", "relinquish-default"),
    "binary-input": ("active-text", "inactive-text", "polarity", "device-type"),
    "binary-output": ("active-text", "inactive-text", "polarity", "relinquish-default", "priority-array", "device-type"),
    "binary-value": ("active-text", "inactive-text", "relinquish-default"),
    "multi-state-input": ("number-of-states", "state-text", "device-type"),
    "multi-state-output": ("number-of-states", "state-text", "relinquish-default", "priority-array", "device-type"),
    "multi-state-value": ("number-of-states", "state-text", "relinquish-default"),
    "trend-log": ("log-device-object-property", "log-interval", "enable", "record-count", "buffer-size", "logging-type"),
    "trend-log-multiple": ("log-interval", "enable", "record-count", "buffer-size", "logging-type"),
    "schedule": ("effective-period", "schedule-default", "priority-for-writing"),
    "network-port": ("network-type", "network-number", "mac-address", "ip-address", "ip-subnet-mask", "bacnet-ip-udp-port", "max-master"),
    "program": ("program-state", "program-location"),
    "notification-class": ("notification-class", "priority"),
}
TYPE_PROPS = {k: _props(*v) for k, v in _TYPE_PROPS.items()}


_IP_PROPS = {"ip-address", "ip-subnet-mask", "ip-default-gateway", "ip-dns-server"}


def make_value(prop: str, value: Any) -> PropValue:
    """PropValue from a decoded value, with friendlier text for some properties."""
    pv = PropValue(value=to_json(value), text=to_text(value))
    base = prop.split("[")[0]
    if base in _IP_PROPS and isinstance(pv.value, str) and len(pv.value) == 8:
        try:
            pv.text = ".".join(str(b) for b in bytes.fromhex(pv.value))
        except ValueError:
            pass
    elif base == "mac-address" and isinstance(pv.value, str) and len(pv.value) == 12:
        try:
            b = bytes.fromhex(pv.value)  # BACnet/IP MAC = 4 byte IP + 2 byte port
            pv.text = ".".join(str(x) for x in b[:4]) + f":{int.from_bytes(b[4:], 'big')}"
        except ValueError:
            pass
    return pv


def props_for_type(object_type: str) -> list[str]:
    return COMMON_PROPS + [p for p in TYPE_PROPS.get(object_type, []) if p not in COMMON_PROPS]


# ---------------------------------------------------------------- config/events


@dataclass
class ScanConfig:
    interface: str | None = None  # name ("en0") or IP; None = auto
    port: int = netmod.BACNET_PORT
    level: str = "full"
    whois_timeout: float = 5.0  # seconds to collect I-Am answers
    low: int | None = None  # Who-Is instance range
    high: int | None = None
    broadcast: bool = True  # send global broadcast Who-Is
    targets: list[str] = field(default_factory=list)  # unicast Who-Is targets (IP / CIDR / range)
    bbmd: str | None = None  # "ip[:port]" -> register as foreign device
    bbmd_ttl: int = 300
    device_instance: int | None = None  # our own instance; None = random high number
    apdu_timeout: float = 3.0
    retries: int = 2
    device_concurrency: int = 4
    remote_delay: float = 0.05  # pause between requests to devices behind routers (MS/TP)
    site: str = ""
    network_info: bool = True  # collect DHCP/DNS/gateway/ARP environment (spec §4.7)
    internet_checks: bool = True  # DNS/HTTP/HTTPS internet reachability tests
    public_ip: bool = False  # opt-in: ask an external service for the public IP
    sweep: bool = False  # opt-in: probe every address of the local subnet to fill the ARP table
    switch_info: bool = False  # opt-in: wait for an LLDP/CDP frame (passive, needs capture rights)
    switch_wait: float = lldp.DEFAULT_WAIT
    notes: str = ""
    bind_address: str | None = None  # expert/test override, e.g. "127.0.0.1/32:47810"

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class ScanEvent:
    kind: str  # log | device_found | device_updated | progress | routers | network | finished
    message: str = ""
    device: Device | None = None
    done: int = 0
    total: int = 0
    level: int = logging.INFO


EventCallback = Callable[[ScanEvent], None]


class ScanError(Exception):
    pass


class ScanCancelled(Exception):
    pass


class DeviceUnreachable(Exception):
    pass


# ---------------------------------------------------------------- application


class ScanApplication(Application):
    """bacpypes3 application that reports every I-Am as it arrives."""

    iam_callback: Callable[[Any], None] | None = None

    async def do_IAmRequest(self, apdu) -> None:  # type: ignore[override]
        await super().do_IAmRequest(apdu)
        if self.iam_callback:
            self.iam_callback(apdu)


def build_application(cfg: ScanConfig, app_class: type[ScanApplication] | None = None
                      ) -> tuple[ScanApplication, str, str]:
    """Create the BACnet stack. Returns (app, interface label, bind address)."""
    if cfg.bind_address:
        bind = cfg.bind_address
        label = cfg.bind_address
    else:
        iface = netmod.find_interface(cfg.interface)
        label = iface.label()
        if netmod.port_in_use(iface.ip, cfg.port) or netmod.port_in_use(iface.broadcast, cfg.port):
            alt = netmod.free_port(iface.ip)
            raise ScanError(
                f"UDP port {cfg.port} on {iface.ip} is already in use (another BACnet tool running?). "
                f"Close it, or use --port {alt} (note: with a non-standard port, devices that "
                f"answer by broadcast may be missed)."
            )
        bind = f"{iface.cidr}:{cfg.port}"

    instance = cfg.device_instance or random.randint(4_000_000, 4_194_302)
    args = types.SimpleNamespace(
        name=f"bacscan-{instance}",
        instance=instance,
        network=0,
        address=bind,
        vendoridentifier=999,
        foreign=cfg.bbmd if cfg.bbmd else None,
        ttl=cfg.bbmd_ttl,
        bbmd=None,
    )
    if cfg.bbmd and ":" not in cfg.bbmd:
        args.foreign = f"{cfg.bbmd}:{netmod.BACNET_PORT}"
    app = (app_class or ScanApplication).from_args(args)
    if cfg.port != netmod.BACNET_PORT:
        # bacpypes3 broadcasts to its own port; devices listen on 47808, so redirect
        # Who-Is broadcasts there when we had to use a different local port.
        for link_layer in app.link_layers.values():
            server = getattr(link_layer, "server", None)
            if server is not None and getattr(server, "broadcast_address", None):
                server.broadcast_address = (server.broadcast_address[0], netmod.BACNET_PORT)
    dev = app.device_object
    dev.apduTimeout = int(cfg.apdu_timeout * 1000)
    dev.numberOfApduRetries = cfg.retries
    return app, label, bind


# ---------------------------------------------------------------- device reader


class DeviceReader:
    """Reads one device. One request in flight at a time (network friendly)."""

    def __init__(self, app: ScanApplication, device: Device, cfg: ScanConfig,
                 check_cancel: Callable[[], None]):
        self.app = app
        self.device = device
        self.cfg = cfg
        self.check_cancel = check_cancel
        self.addr = Address(device.address)
        self.remote = device.network is not None
        self.use_rpm = True
        max_apdu = device.max_apdu or 480
        small = max_apdu < 1024 or device.segmentation in (None, "no-segmentation")
        self.props_per_rpm = 8 if small else 30
        self.objects_per_rpm = 1 if small else 3
        self.consecutive_timeouts = 0

    # -- low level

    async def _request(self, factory: Callable[[], Awaitable[Any]]) -> Any:
        self.check_cancel()
        if self.remote and self.cfg.remote_delay:
            await asyncio.sleep(self.cfg.remote_delay)
        limit = self.cfg.apdu_timeout * (self.cfg.retries + 1) + 2
        try:
            result = await asyncio.wait_for(factory(), timeout=limit)
        except (asyncio.TimeoutError, TimeoutError):
            self.consecutive_timeouts += 1
            if self.consecutive_timeouts >= 3:
                raise DeviceUnreachable("device stopped responding (3 timeouts in a row)")
            raise TimeoutError()
        self.consecutive_timeouts = 0
        return result

    async def rp(self, objid: ObjectIdentifier, prop: str, index: int | None = None) -> PropValue | None:
        """ReadProperty. None means the object does not have this property."""
        try:
            value = await self._request(
                lambda: self.app.read_property(self.addr, objid, PropertyIdentifier(prop), index)
            )
        except DeviceUnreachable:
            raise
        except ScanCancelled:
            raise
        except (ErrorRejectAbortNack, TimeoutError) as e:
            if is_unknown_property(e):
                return None
            return PropValue(error=error_text(e))
        except Exception as e:  # decoding problems etc. — never fatal
            log.debug("rp %s %s %s failed", self.device.instance, objid, prop, exc_info=True)
            return PropValue(error=error_text(e))
        if isinstance(value, ErrorType):
            return None if is_unknown_property(value) else PropValue(error=error_text(value))
        return make_value(prop, value)

    async def rpm(self, specs: list[tuple[ObjectIdentifier, list[str]]]) -> dict[str, dict[str, PropValue]]:
        """ReadPropertyMultiple. Raises on whole-request failure."""
        params: list[Any] = []
        for objid, props in specs:
            params.append(objid)
            params.append([PropertyIdentifier(p) for p in props])
        result = await self._request(lambda: self.app.read_property_multiple(self.addr, params))
        if result is None:
            raise ScanError("invalid RPM response")
        out: dict[str, dict[str, PropValue]] = {}
        for objid, prop, index, value in result:
            key = str(objid)
            pname = str(prop) if index is None else f"{prop}[{index}]"
            if isinstance(value, ErrorType) or isinstance(value, ErrorRejectAbortNack):
                if is_unknown_property(value):
                    continue
                pv = PropValue(error=error_text(value))
            else:
                pv = make_value(pname, value)
            out.setdefault(key, {})[pname] = pv
        return out

    # -- mid level

    async def read_props(self, objid: ObjectIdentifier, props: list[str]) -> dict[str, PropValue]:
        """Read a property set of one object with RPM (chunked) or RP fallback."""
        result: dict[str, PropValue] = {}
        if self.use_rpm:
            try:
                for i in range(0, len(props), self.props_per_rpm):
                    chunk = props[i:i + self.props_per_rpm]
                    got = await self.rpm([(objid, chunk)])
                    result.update(got.get(str(objid), {}))
                return result
            except (DeviceUnreachable, ScanCancelled):
                raise
            except Exception as e:
                self._rpm_failed(e)
        for p in props:
            if p in result:
                continue
            pv = await self.rp(objid, p)
            if pv is not None:
                result[p] = pv
        return result

    async def read_many(self, objids: list[ObjectIdentifier], props_of: Callable[[ObjectIdentifier], list[str]]) -> dict[str, dict[str, PropValue]]:
        """Read several objects in one RPM where possible."""
        if self.use_rpm and self.objects_per_rpm > 1 and len(objids) > 1:
            try:
                return await self.rpm([(o, props_of(o)) for o in objids])
            except (DeviceUnreachable, ScanCancelled):
                raise
            except Exception as e:
                log.debug("multi-object RPM failed on %s: %s; using 1 object per request",
                          self.device.instance, error_text(e))
                self.objects_per_rpm = 1
        return {str(o): await self.read_props(o, props_of(o)) for o in objids}

    async def read_all_props(self, objid: ObjectIdentifier) -> dict[str, PropValue]:
        """Every property of an object: RPM 'all', else property-list + RP."""
        if self.use_rpm:
            try:
                got = await self.rpm([(objid, ["all"])])
                return got.get(str(objid), {})
            except (DeviceUnreachable, ScanCancelled):
                raise
            except Exception as e:
                self._rpm_failed(e)
        plist = await self.rp(objid, "property-list")
        names = list(props_for_type(str(objid[0])))
        if plist and plist.error is None and isinstance(plist.value, list):
            names = ["object-name"] + [str(p) for p in plist.value]
        names = list(dict.fromkeys(names))
        return {p: v for p in names if (v := await self.rp(objid, p)) is not None}

    def _rpm_failed(self, e: Exception) -> None:
        text = error_text(e)
        if "unrecognized-service" in text or "service-request-denied" in text:
            log.info("device %s does not support ReadPropertyMultiple, using ReadProperty", self.device.instance)
            self.use_rpm = False
        elif self.props_per_rpm > 4:
            self.props_per_rpm = 4
            log.debug("RPM failed on %s (%s); smaller requests", self.device.instance, text)
        else:
            log.info("RPM unreliable on %s (%s), using ReadProperty", self.device.instance, text)
            self.use_rpm = False

    async def read_object_list(self) -> list[ObjectIdentifier]:
        dev_id = ObjectIdentifier(("device", self.device.instance))
        try:
            value = await self._request(
                lambda: self.app.read_property(self.addr, dev_id, PropertyIdentifier("object-list"))
            )
            return [ObjectIdentifier(v) for v in value]
        except (DeviceUnreachable, ScanCancelled):
            raise
        except Exception as e:
            log.info("device %s: whole object-list read failed (%s), reading element by element",
                     self.device.instance, error_text(e))
        length = await self._request(
            lambda: self.app.read_property(self.addr, dev_id, PropertyIdentifier("object-list"), 0)
        )
        result = []
        for i in range(1, int(length) + 1):
            try:
                v = await self._request(
                    lambda i=i: self.app.read_property(self.addr, dev_id, PropertyIdentifier("object-list"), i)
                )
                result.append(ObjectIdentifier(v))
            except (DeviceUnreachable, ScanCancelled):
                raise
            except Exception as e:
                self.device.errors.append(f"object-list[{i}]: {error_text(e)}")
        return result


# ---------------------------------------------------------------- scanner


class Scanner:
    def __init__(self, cfg: ScanConfig, on_event: EventCallback | None = None):
        if cfg.level not in LEVELS:
            raise ValueError(f"level must be one of {LEVELS}")
        self.cfg = cfg
        self.on_event = on_event or (lambda e: None)
        self.scan = Scan(site=cfg.site, notes=cfg.notes, level=cfg.level,
                         settings=cfg.to_dict(), tool_version=__version__)
        self._cancelled = False
        self._own_instance: int | None = None
        self._objects_total = 0
        self._objects_done = 0

    # -- public

    def cancel(self) -> None:
        """Request cancellation; partial results are kept. Thread-safe enough (flag)."""
        self._cancelled = True

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    async def run(self) -> Scan:
        t0 = time.monotonic()
        try:
            app, label, bind = build_application(self.cfg)
        except ScanError:
            self.scan.status = "failed"
            raise
        self.scan.interface = label
        self.scan.local_address = bind
        self._own_instance = app.device_object.objectIdentifier[1]
        app.iam_callback = self._on_iam
        self._emit("log", f"BACnet stack on {bind} as device {self._own_instance}")
        iface = self._interface(bind) if (self.cfg.network_info or self.cfg.switch_info) else None
        env_task = switch_task = None
        if iface is not None and self.cfg.switch_info:
            self._emit("log", f"listening for LLDP/CDP on {iface.name} (up to {self.cfg.switch_wait:.0f} s)")
            switch_task = asyncio.ensure_future(asyncio.to_thread(
                lldp.capture, iface.name, self.cfg.switch_wait, lambda: self._cancelled))
        if iface is not None and self.cfg.network_info:
            self._emit("log", f"collecting network environment of {iface.name}")
            env_task = asyncio.ensure_future(asyncio.to_thread(
                netinfo.survey_environment, iface, self.cfg.internet_checks, self.cfg.public_ip))
        try:
            await asyncio.sleep(0.5)  # let the UDP endpoints come up
            if self.cfg.bbmd:
                self._emit("log", f"registering as foreign device with BBMD {self.cfg.bbmd}")
                await asyncio.sleep(2)
            await self._discover(app)
            if self.cfg.level != "discover" and self.scan.devices and not self._cancelled:
                await self._read_devices(app)
            self.scan.status = "cancelled" if self._cancelled else "completed"
        except ScanCancelled:
            self.scan.status = "cancelled"
        except Exception as e:
            self.scan.status = "failed"
            self._emit("log", f"scan failed: {error_text(e)}", level=logging.ERROR)
            log.debug("scan failed", exc_info=True)
        finally:
            app.close()
        if iface is not None and self.cfg.network_info:
            await self._network_survey(iface, env_task)
        if switch_task is not None:
            self._emit("log", "waiting for LLDP/CDP announcement from the switch…")
            sw = await switch_task
            self.scan.network["switch"] = sw
            rows = dict(lldp.summarize(sw))
            self._emit("network", "switch: " + " · ".join(
                v for k, v in rows.items() if k in ("Switch", "Switch port", "Switch VLAN")))
        self.scan.finished_at = now_iso()
        n = len(self.scan.devices)
        self._emit("finished", f"{self.scan.status}: {n} device(s), {self.scan.object_count} object(s) "
                               f"in {time.monotonic() - t0:.1f}s")
        return self.scan

    # -- network environment (spec §4.7)

    def _interface(self, bind: str) -> netmod.Interface | None:
        ip = bind.split("/")[0].split(":")[0]
        try:
            return netmod.find_interface(ip if self.cfg.bind_address else (self.cfg.interface or ip))
        except ValueError:
            return None

    async def _network_survey(self, iface: netmod.Interface, env_task) -> None:
        try:
            if env_task is not None:
                self.scan.network = await env_task
                inet = self.scan.network.get("internet", {}).get("status", "not checked")
                self._emit("network", f"network: internet {inet}")
            swept = False
            if self.cfg.sweep and not self._cancelled:
                self._emit("log", f"sweeping {iface.network} to find all hosts")
                try:
                    n = await asyncio.to_thread(netinfo.sweep, iface, lambda: self._cancelled)
                    swept = True
                    self._emit("log", f"sweep probed {n} address(es)")
                except ValueError as e:  # subnet too large
                    self._emit("log", f"sweep skipped: {e}", level=logging.WARNING)
            bacnet = {d.ip: d.instance for d in self.scan.devices if d.ip}
            gateway = self.scan.network.get("gateway", {}).get("ip")
            hosts = await asyncio.to_thread(netinfo.collect_hosts, iface, bacnet, gateway, swept)
            self.scan.hosts = hosts
            self._apply_macs()
            self._emit("network", f"network: {len(hosts)} host(s) on {iface.network}")
        except Exception as e:
            log.debug("network survey failed", exc_info=True)
            self.scan.network.setdefault("error", error_text(e))
            self._emit("log", f"network survey failed: {error_text(e)}", level=logging.WARNING)

    def _apply_macs(self) -> None:
        """E7: MAC + vendor for BACnet devices (router's MAC for devices behind routers)."""
        by_ip = {h.ip: h for h in self.scan.hosts}
        router_ips = set()
        for d in self.scan.devices:
            if d.ip and d.ip in by_ip:
                h = by_ip[d.ip]
                d.eth_mac, d.eth_vendor, d.eth_mac_source = h.mac, h.vendor, "arp"
            elif d.network is not None and d.router:
                rip = d.router.split(":")[0]
                router_ips.add(rip)
                if rip in by_ip:
                    h = by_ip[rip]
                    d.eth_mac, d.eth_vendor, d.eth_mac_source = h.mac, h.vendor, "router"
        for r in self.scan.routers:
            router_ips.add(r.address.split(":")[0])
        for rip in router_ips:
            if rip in by_ip and not by_ip[rip].note:
                by_ip[rip].note = "BACnet router"

    # -- internals

    def _emit(self, kind: str, message: str = "", **kw: Any) -> None:
        if kind == "log":
            log.log(kw.get("level", logging.INFO), message)
        try:
            self.on_event(ScanEvent(kind=kind, message=message, **kw))
        except Exception:
            log.exception("event callback failed")

    def _check_cancel(self) -> None:
        if self._cancelled:
            raise ScanCancelled()

    async def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self._cancelled and time.monotonic() < end:
            await asyncio.sleep(min(0.2, end - time.monotonic()))

    def _on_iam(self, apdu) -> None:
        instance = apdu.iAmDeviceIdentifier[1]
        if instance == self._own_instance or self.scan.device(instance):
            return
        if self.cfg.low is not None and not (self.cfg.low <= instance <= (self.cfg.high or instance)):
            return
        src: Address = apdu.pduSource
        dev = Device(
            instance=instance,
            address=str(src),
            vendor_id=int(apdu.vendorID),
            max_apdu=int(apdu.maxAPDULengthAccepted),
            segmentation=to_text(apdu.segmentationSupported),
        )
        if src.addrType == Address.remoteStationAddr:
            dev.network = src.addrNet
            dev.mac = src.addrAddr.hex() if src.addrAddr else None
            dev.router = str(src.addrRoute) if getattr(src, "addrRoute", None) else None
        self.scan.devices.append(dev)
        self._emit("device_found", f"found device {instance} at {dev.address}", device=dev)

    async def _discover(self, app: ScanApplication) -> None:
        cfg = self.cfg
        tasks = []
        if cfg.broadcast:
            # routers (MS/TP trunks etc. behind BACnet routers)
            try:
                tasks.append(asyncio.ensure_future(app.nse.who_is_router_to_network()))
            except Exception as e:
                log.debug("who-is-router-to-network not sent: %s", e)
            self._emit("log", "broadcasting Who-Is" + (f" ({cfg.low}-{cfg.high})" if cfg.low is not None else ""))
            app.who_is(cfg.low, cfg.high, timeout=int(cfg.whois_timeout))

        hosts: list[str] = []
        for spec in cfg.targets:
            hosts.extend(netmod.expand_targets(spec))
        if hosts:
            self._emit("log", f"sending unicast Who-Is to {len(hosts)} address(es)")
            for i, h in enumerate(hosts):
                self._check_cancel()
                addr = h if ":" in h else f"{h}:{netmod.BACNET_PORT}"
                req = WhoIsRequest(destination=Address(addr))
                if cfg.low is not None:
                    req.deviceInstanceRangeLowLimit = cfg.low
                    req.deviceInstanceRangeHighLimit = cfg.high
                await app.request(req)
                if i % 32 == 31:
                    await asyncio.sleep(0.01)

        await self._sleep(cfg.whois_timeout)
        for t in tasks:
            try:
                results = await asyncio.wait_for(t, timeout=5)
                for _adapter, npdu in results or []:
                    r = Router(address=str(npdu.pduSource), networks=[int(n) for n in npdu.iartnNetworkList])
                    self.scan.routers.append(r)
            except Exception as e:
                log.debug("router discovery: %s", e)
        if self.scan.routers:
            self._emit("routers", ", ".join(f"{r.address} -> {r.networks}" for r in self.scan.routers))
        self.scan.devices.sort(key=lambda d: d.instance)
        self._emit("log", f"discovery done: {len(self.scan.devices)} device(s)")

    async def _read_devices(self, app: ScanApplication) -> None:
        sem = asyncio.Semaphore(max(1, self.cfg.device_concurrency))

        async def one(dev: Device) -> None:
            async with sem:
                if self._cancelled:
                    return
                await self._read_device(app, dev)

        await asyncio.gather(*(one(d) for d in list(self.scan.devices)))

    async def _read_device(self, app: ScanApplication, dev: Device) -> None:
        reader = DeviceReader(app, dev, self.cfg, self._check_cancel)
        dev.status = "reading"
        self._emit("device_updated", f"reading device {dev.instance}", device=dev)
        dev_id = ObjectIdentifier(("device", dev.instance))
        try:
            if self.cfg.level == "all":
                dev.props = await reader.read_all_props(dev_id)
            else:
                dev.props = await reader.read_props(dev_id, DEVICE_PROPS)
            if not dev.props or all(p.error for p in dev.props.values()):
                raise DeviceUnreachable("device does not answer property reads")
            self._apply_services(reader, dev)
            self._emit("device_updated", f"device {dev.instance}: {dev.name}", device=dev)

            if self.cfg.level in ("full", "all"):
                objids = [o for o in await reader.read_object_list()
                          if not (str(o[0]) == "device" and int(o[1]) == dev.instance)]
                self._objects_total += len(objids)
                self._emit("log", f"device {dev.instance}: {len(objids)} object(s)")
                await self._read_objects(reader, dev, objids)
            dev.status = "partial" if dev.errors else "done"
        except ScanCancelled:
            dev.status = "partial"
        except DeviceUnreachable as e:
            dev.status = "failed" if not dev.objects else "partial"
            dev.errors.append(str(e))
            self._emit("log", f"device {dev.instance}: {e}", level=logging.WARNING)
        except Exception as e:
            dev.status = "failed"
            dev.errors.append(error_text(e))
            self._emit("log", f"device {dev.instance}: {error_text(e)}", level=logging.WARNING)
            log.debug("device read failed", exc_info=True)
        self._emit("device_updated", f"device {dev.instance} {dev.status}", device=dev)

    def _apply_services(self, reader: DeviceReader, dev: Device) -> None:
        services = dev.props.get("protocol-services-supported")
        if services and services.error is None and isinstance(services.value, list):
            if "read-property-multiple" not in services.value:
                reader.use_rpm = False
        seg = dev.props.get("segmentation-supported")
        if seg and seg.error is None:
            dev.segmentation = seg.text

    async def _read_objects(self, reader: DeviceReader, dev: Device, objids: list[ObjectIdentifier]) -> None:
        def props_of(o: ObjectIdentifier) -> list[str]:
            return props_for_type(str(o[0]))

        i = 0
        while i < len(objids):
            self._check_cancel()
            if self.cfg.level == "all":
                batch = objids[i:i + 1]
                results = {str(batch[0]): await reader.read_all_props(batch[0])}
            else:
                batch = objids[i:i + max(1, reader.objects_per_rpm)]
                results = await reader.read_many(batch, props_of)
            for o in batch:
                obj = BacnetObject(object_type=str(o[0]), instance=int(o[1]), props=results.get(str(o), {}))
                dev.objects.append(obj)
            i += len(batch)
            self._objects_done += len(batch)
            self._emit("progress", f"device {dev.instance}: {i}/{len(objids)} objects",
                       device=dev, done=self._objects_done, total=self._objects_total)


async def read_single(cfg: ScanConfig, address: str, objid: str, prop: str) -> PropValue:
    """Ad-hoc single ReadProperty (for `bacscan read`)."""
    app, _label, _bind = build_application(cfg)
    try:
        await asyncio.sleep(0.5)
        dev = Device(instance=0, address=address)
        reader = DeviceReader(app, dev, cfg, lambda: None)
        oid = ObjectIdentifier(objid)
        pv = await reader.rp(oid, prop)
        return pv or PropValue(error="unknown-property")
    finally:
        app.close()
