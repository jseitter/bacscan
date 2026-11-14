"""Passive listen mode (spec D6): record BACnet broadcasts without sending anything.

On a switched network only broadcasts (Who-Is, I-Am, Who-Has, I-Have, time sync,
unconfirmed COV/event notifications, ...) and traffic addressed to us reach the Mac.
The stack never answers: not even Who-Is requests get an I-Am.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from bacpypes3.pdu import Address

from .. import __version__
from . import netinfo
from .models import Device, Scan, now_iso
from .scanner import EventCallback, ScanApplication, ScanConfig, ScanError, ScanEvent, build_application
from .values import to_text

log = logging.getLogger("bacscan.listen")

_SERVICE_NAMES = {
    "WhoIsRequest": "who-is", "IAmRequest": "i-am", "WhoHasRequest": "who-has", "IHaveRequest": "i-have",
    "TimeSynchronizationRequest": "time-synchronization",
    "UTCTimeSynchronizationRequest": "utc-time-synchronization",
    "UnconfirmedCOVNotificationRequest": "unconfirmed-cov-notification",
    "UnconfirmedEventNotificationRequest": "unconfirmed-event-notification",
    "UnconfirmedTextMessageRequest": "unconfirmed-text-message",
    "UnconfirmedPrivateTransferRequest": "unconfirmed-private-transfer",
    "WriteGroupRequest": "write-group",
}


@dataclass
class TrafficEntry:
    source: str
    service: str
    count: int = 0
    first: str = field(default_factory=now_iso)
    last: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _detail(apdu: Any) -> str:
    name = type(apdu).__name__
    try:
        if name == "WhoIsRequest":
            lo, hi = apdu.deviceInstanceRangeLowLimit, apdu.deviceInstanceRangeHighLimit
            return "all devices" if lo is None else f"range {lo}-{hi}"
        if name == "IAmRequest":
            return f"device {apdu.iAmDeviceIdentifier[1]}, vendor {apdu.vendorID}"
        if name == "WhoHasRequest":
            target = apdu.object.objectIdentifier or apdu.object.objectName
            return f"looking for {to_text(target)}"
        if name == "IHaveRequest":
            return f"device {apdu.deviceIdentifier[1]} has {to_text(apdu.objectIdentifier)} {apdu.objectName}"
        if name in ("UnconfirmedCOVNotificationRequest", "UnconfirmedEventNotificationRequest"):
            return f"from device {apdu.initiatingDeviceIdentifier[1]}, " \
                   f"object {to_text(getattr(apdu, 'monitoredObjectIdentifier', None) or getattr(apdu, 'eventObjectIdentifier', None))}"
        if name in ("TimeSynchronizationRequest", "UTCTimeSynchronizationRequest"):
            return f"{apdu.time}"
    except Exception:  # decoding detail is best effort
        pass
    return ""


class PassiveApplication(ScanApplication):
    """Records every incoming request and never responds."""

    record_callback = None

    async def indication(self, apdu) -> None:  # type: ignore[override]
        if self.record_callback:
            self.record_callback(apdu)
        # deliberately no processing: no I-Am replies, no errors, nothing sent


class Listener:
    def __init__(self, cfg: ScanConfig, duration: float, on_event: EventCallback | None = None):
        self.cfg = cfg
        self.duration = duration
        self.on_event = on_event or (lambda e: None)
        self.scan = Scan(site=cfg.site, notes=cfg.notes, level="listen",
                         settings=cfg.to_dict() | {"listen_duration": duration}, tool_version=__version__)
        self.traffic: dict[tuple[str, str], TrafficEntry] = {}
        self._cancelled = False
        self.packets = 0

    def cancel(self) -> None:
        self._cancelled = True

    def _emit(self, kind: str, message: str = "", **kw: Any) -> None:
        try:
            self.on_event(ScanEvent(kind=kind, message=message, **kw))
        except Exception:
            log.exception("event callback failed")

    def _record(self, apdu: Any) -> None:
        self.packets += 1
        src = str(apdu.pduSource)
        name = type(apdu).__name__
        service = _SERVICE_NAMES.get(name, name.removesuffix("Request").lower())
        key = (src, service)
        entry = self.traffic.get(key)
        if entry is None:
            entry = self.traffic[key] = TrafficEntry(source=src, service=service, detail=_detail(apdu))
            self._emit("log", f"{src}: {service} {entry.detail}".rstrip())
        entry.count += 1
        entry.last = now_iso()
        if name == "IAmRequest":
            instance = apdu.iAmDeviceIdentifier[1]
            if not self.scan.device(instance):
                addr: Address = apdu.pduSource
                dev = Device(instance=instance, address=src, vendor_id=int(apdu.vendorID),
                             max_apdu=int(apdu.maxAPDULengthAccepted),
                             segmentation=to_text(apdu.segmentationSupported))
                if addr.addrType == Address.remoteStationAddr:
                    dev.network = addr.addrNet
                    dev.mac = addr.addrAddr.hex() if addr.addrAddr else None
                    dev.router = str(addr.addrRoute) if getattr(addr, "addrRoute", None) else None
                self.scan.devices.append(dev)
                self._emit("device_found", f"heard I-Am from device {instance} at {src}", device=dev)
        self._emit("progress", f"{self.packets} packet(s), {len(self.scan.devices)} device(s)",
                   done=self.packets, total=0)

    async def run(self) -> Scan:
        t0 = time.monotonic()
        if self.cfg.sc_hub:
            self.scan.status = "failed"
            raise ScanError("passive listening is not possible on BACnet/SC (the hub only forwards what is addressed to us)")
        try:
            app, label, bind = build_application(self.cfg, PassiveApplication)
        except ScanError:
            self.scan.status = "failed"
            raise
        app.record_callback = self._record
        self.scan.interface, self.scan.local_address = label, bind
        self._emit("log", f"listening on {bind} for {self.duration:.0f} s (nothing is sent)")
        try:
            end = time.monotonic() + self.duration
            while not self._cancelled and time.monotonic() < end:
                await asyncio.sleep(0.2)
            self.scan.status = "cancelled" if self._cancelled else "completed"
        finally:
            app.close()
        self.scan.devices.sort(key=lambda d: d.instance)
        traffic = sorted(self.traffic.values(), key=lambda e: (-e.count, e.source))
        self.scan.network["bacnet_traffic"] = [e.to_dict() for e in traffic]
        # passive: only local information, no probes (no ping / DNS / HTTP)
        if self.cfg.network_info and not self.cfg.bind_address:
            try:
                from .network import find_interface
                iface = find_interface(self.cfg.interface)
                link = await asyncio.to_thread(netinfo.survey_link, iface)
                link.pop("_lease", None)
                self.scan.network["interface"] = link
                bacnet = {d.ip: d.instance for d in self.scan.devices if d.ip}
                self.scan.hosts = await asyncio.to_thread(
                    netinfo.collect_hosts, iface, bacnet, None, False, False)
                clients = {e.source.split(":")[0] for e in traffic if e.service in ("who-is", "who-has")}
                for h in self.scan.hosts:
                    if h.ip in clients and not h.note:
                        h.note = "BACnet client (sends Who-Is)"
            except Exception as e:
                log.debug("passive network info failed", exc_info=True)
                self.scan.network["error"] = str(e)
        self.scan.finished_at = now_iso()
        self._emit("finished", f"{self.scan.status}: {self.packets} packet(s) from "
                               f"{len({e.source for e in traffic})} source(s), {len(self.scan.devices)} device(s) "
                               f"in {time.monotonic() - t0:.0f}s")
        return self.scan
