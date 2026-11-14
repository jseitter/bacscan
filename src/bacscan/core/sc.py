"""BACnet/SC (secure connect, ASHRAE 135 Annex AB) client link layer.

bacscan joins an existing SC network as an ordinary node: it opens a secure WebSocket (mutual TLS)
to the hub, performs the Connect-Request/Accept handshake, and then exchanges Encapsulated-NPDUs
with the other nodes through the hub. Optionally it resolves the direct-connect URIs of devices
(Address-Resolution) and talks to them directly. Nothing is ever written to devices.

`SCLinkLayer` plugs into the bacpypes3 network layer in place of the BACnet/IP link layer: SC
nodes are addressed by their 6-byte VMAC, which bacpypes3 treats as a normal local station address.
"""
from __future__ import annotations

import asyncio
import logging
import os
import ssl
import struct
import uuid
from dataclasses import dataclass, field

import websockets
from bacpypes3.comm import Client, Server
from bacpypes3.pdu import PDU, Address, LocalBroadcast, LocalStation

log = logging.getLogger("bacscan.sc")

HUB_SUBPROTOCOL = "hub.bsc.bacnet.org"
DC_SUBPROTOCOL = "dc.bsc.bacnet.org"
BROADCAST_VMAC = b"\xff" * 6

# BVLC-SC functions (AB.2)
RESULT = 0x00
ENCAPSULATED_NPDU = 0x01
ADDRESS_RESOLUTION = 0x02
ADDRESS_RESOLUTION_ACK = 0x03
ADVERTISEMENT = 0x04
ADVERTISEMENT_SOLICITATION = 0x05
CONNECT_REQUEST = 0x06
CONNECT_ACCEPT = 0x07
DISCONNECT_REQUEST = 0x08
DISCONNECT_ACK = 0x09
HEARTBEAT_REQUEST = 0x0A
HEARTBEAT_ACK = 0x0B
PROPRIETARY = 0x0C

FUNCTION_NAMES = {
    RESULT: "BVLC-Result", ENCAPSULATED_NPDU: "Encapsulated-NPDU", ADDRESS_RESOLUTION: "Address-Resolution",
    ADDRESS_RESOLUTION_ACK: "Address-Resolution-ACK", ADVERTISEMENT: "Advertisement",
    ADVERTISEMENT_SOLICITATION: "Advertisement-Solicitation", CONNECT_REQUEST: "Connect-Request",
    CONNECT_ACCEPT: "Connect-Accept", DISCONNECT_REQUEST: "Disconnect-Request", DISCONNECT_ACK: "Disconnect-ACK",
    HEARTBEAT_REQUEST: "Heartbeat-Request", HEARTBEAT_ACK: "Heartbeat-ACK", PROPRIETARY: "Proprietary-Message",
}

# control flags
F_ORIGIN = 0x08
F_DEST = 0x04
F_DEST_OPTIONS = 0x02
F_DATA_OPTIONS = 0x01

MAX_BVLC = 1600  # largest BVLC-SC message we accept
MAX_NPDU = 1497
HEARTBEAT_SECONDS = 60.0
CONNECT_TIMEOUT = 10.0


class SCError(Exception):
    """Connection / handshake problem, with a message fit for the user."""


@dataclass
class Message:
    function: int
    message_id: int = 0
    origin: bytes | None = None  # originating VMAC (added by the hub)
    dest: bytes | None = None  # destination VMAC
    payload: bytes = b""
    dest_options: bytes = b""  # raw header options (kept opaque)
    data_options: bytes = b""

    @property
    def name(self) -> str:
        return FUNCTION_NAMES.get(self.function, f"function 0x{self.function:02x}")


def random_vmac() -> bytes:
    """A random locally administered unicast VMAC (AB.1.5.2: Random-48)."""
    b = bytearray(os.urandom(6))
    b[0] = (b[0] & 0xF0) | 0x02
    return bytes(b)


def encode(m: Message) -> bytes:
    flags = 0
    body = b""
    if m.origin:
        flags |= F_ORIGIN
        body += m.origin
    if m.dest:
        flags |= F_DEST
        body += m.dest
    if m.dest_options:
        flags |= F_DEST_OPTIONS
        body += m.dest_options
    if m.data_options:
        flags |= F_DATA_OPTIONS
        body += m.data_options
    return struct.pack(">BBH", m.function, flags, m.message_id & 0xFFFF) + body + m.payload


def _skip_options(data: bytes, pos: int) -> tuple[bytes, int]:
    """Header options are a chain: marker (more-flag 0x80, must-understand 0x40, data-flag 0x20, type 0x1F)."""
    start = pos
    while True:
        if pos >= len(data):
            raise ValueError("truncated header options")
        marker = data[pos]
        pos += 1
        if marker & 0x20:
            if pos + 2 > len(data):
                raise ValueError("truncated header option")
            (n,) = struct.unpack_from(">H", data, pos)
            pos += 2 + n
        if not marker & 0x80:
            break
    if pos > len(data):
        raise ValueError("truncated header option")
    return data[start:pos], pos


def decode(data: bytes) -> Message:
    if len(data) < 4:
        raise ValueError("BVLC-SC message too short")
    function, flags, message_id = struct.unpack_from(">BBH", data)
    pos = 4
    m = Message(function, message_id)
    if flags & F_ORIGIN:
        m.origin, pos = data[pos:pos + 6], pos + 6
    if flags & F_DEST:
        m.dest, pos = data[pos:pos + 6], pos + 6
    if pos > len(data):
        raise ValueError("truncated VMAC")
    if flags & F_DEST_OPTIONS:
        m.dest_options, pos = _skip_options(data, pos)
    if flags & F_DATA_OPTIONS:
        m.data_options, pos = _skip_options(data, pos)
    m.payload = data[pos:]
    return m


def connect_payload(vmac: bytes, device_uuid: bytes, max_bvlc: int = MAX_BVLC, max_npdu: int = MAX_NPDU) -> bytes:
    return vmac + device_uuid + struct.pack(">HH", max_bvlc, max_npdu)


def parse_connect(payload: bytes) -> tuple[bytes, bytes, int, int]:
    if len(payload) < 26:
        raise ValueError("Connect payload too short")
    vmac, dev_uuid = payload[:6], payload[6:22]
    max_bvlc, max_npdu = struct.unpack_from(">HH", payload, 22)
    return vmac, dev_uuid, max_bvlc, max_npdu


def result_payload(for_function: int, error: tuple[int, int, str] | None = None) -> bytes:
    """BVLC-Result payload: ACK, or NAK with (error class, error code, details)."""
    if error is None:
        return bytes([for_function, 0x00])
    cls, code, text = error
    return bytes([for_function, 0x01, 0x00]) + struct.pack(">HH", cls, code) + text.encode()


def parse_result(payload: bytes) -> tuple[int, bool, str]:
    """-> (function the result is for, is_nak, error text)"""
    if len(payload) < 2:
        return 0, False, ""
    func, code = payload[0], payload[1]
    if code == 0:
        return func, False, ""
    text = ""
    if len(payload) >= 7:
        cls, err = struct.unpack_from(">HH", payload, 3)
        text = payload[7:].decode(errors="replace")
        text = f"error class {cls} code {err}" + (f": {text}" if text else "")
    return func, True, text


def hex_vmac(vmac: bytes) -> str:
    return vmac.hex(":")


# ------------------------------------------------------------------ TLS / URIs


@dataclass
class SCSettings:
    hub: str  # wss://host:port
    failover: str | None = None
    cert: str | None = None  # operational certificate (PEM), presented to the hub
    key: str | None = None  # its private key (PEM)
    key_password: str | None = None  # memory only, never stored
    ca: str | None = None  # CA certificate(s) (PEM) that signed the hub's certificate
    verify: bool = True  # False: do not verify the hub's certificate (lab use)
    direct: bool = False  # resolve device URIs and connect directly where possible
    vmac: bytes = field(default_factory=random_vmac)
    device_uuid: bytes = field(default_factory=lambda: uuid.uuid4().bytes)

    def validate(self) -> None:
        for uri in (self.hub, self.failover):
            if uri and not uri.startswith(("wss://", "ws://")):
                raise SCError(f"hub URI must start with wss:// (got {uri!r})")
        if self.hub.startswith("ws://"):
            log.warning("unencrypted ws:// hub connection (BACnet/SC requires wss://)")
        if bool(self.cert) != bool(self.key):
            raise SCError("certificate and private key must be given together")
        for label, path in (("certificate", self.cert), ("private key", self.key), ("CA certificate", self.ca)):
            if path and not os.path.isfile(path):
                raise SCError(f"{label} file not found: {path}")


def make_ssl_context(s: SCSettings) -> ssl.SSLContext | None:
    if s.hub.startswith("ws://"):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if s.ca:
        try:
            ctx.load_verify_locations(cafile=s.ca)
        except (ssl.SSLError, OSError) as e:
            raise SCError(f"cannot load CA certificate {s.ca}: {e}") from e
    else:
        ctx.load_default_certs()
    if s.cert and s.key:
        try:
            ctx.load_cert_chain(s.cert, s.key, password=s.key_password)
        except (ssl.SSLError, OSError, TypeError) as e:
            raise SCError(f"cannot load certificate/key ({s.cert}, {s.key}): {e}") from e
    if not s.verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def explain_connect_error(e: Exception, uri: str) -> str:
    if isinstance(e, ssl.SSLCertVerificationError):
        return (f"TLS: the hub's certificate was rejected ({e.verify_message}). Give the CA certificate that "
                f"signed it, or disable verification for lab use")
    if isinstance(e, ssl.SSLError):
        return (f"TLS handshake with {uri} failed ({e}). The hub probably requires a client certificate "
                f"signed by the site CA")
    if isinstance(e, (TimeoutError, asyncio.TimeoutError)):
        return f"{uri}: no answer (timeout)"
    if isinstance(e, ConnectionRefusedError):
        return f"{uri}: connection refused"
    if isinstance(e, websockets.exceptions.InvalidStatus):
        return f"{uri}: HTTP {e.response.status_code} (is this the hub's WebSocket URL?)"
    if isinstance(e, websockets.exceptions.InvalidMessage | websockets.exceptions.InvalidHandshake):
        return f"{uri}: not a BACnet/SC hub ({e})"
    if isinstance(e, OSError):
        return f"{uri}: {e.strerror or e}"
    return f"{uri}: {type(e).__name__}: {e}"


# ------------------------------------------------------------------ connection


class Connection:
    """One WebSocket (to the hub or directly to a node) after a successful Connect handshake."""

    def __init__(self, ws, uri: str, peer_vmac: bytes, peer_uuid: bytes, hub: bool):
        self.ws = ws
        self.uri = uri
        self.peer_vmac = peer_vmac
        self.peer_uuid = peer_uuid
        self.hub = hub
        self.max_bvlc = MAX_BVLC
        self.max_npdu = MAX_NPDU
        self.task: asyncio.Task | None = None
        self.closed = False

    async def send(self, m: Message) -> None:
        await self.ws.send(encode(m))


async def open_connection(uri: str, ctx: ssl.SSLContext | None, s: SCSettings, hub: bool,
                          message_id: int = 1) -> Connection:
    """Open the WebSocket and run the Connect-Request / Connect-Accept handshake (AB.6.2)."""
    sub = HUB_SUBPROTOCOL if hub else DC_SUBPROTOCOL
    try:
        ws = await asyncio.wait_for(websockets.connect(
            uri, subprotocols=[sub], ssl=ctx if uri.startswith("wss://") else None,
            max_size=MAX_BVLC * 2, open_timeout=CONNECT_TIMEOUT, ping_interval=None), CONNECT_TIMEOUT + 2)
    except Exception as e:
        raise SCError(explain_connect_error(e, uri)) from e
    try:
        await ws.send(encode(Message(CONNECT_REQUEST, message_id,
                                     payload=connect_payload(s.vmac, s.device_uuid))))
        while True:
            raw = await asyncio.wait_for(ws.recv(), CONNECT_TIMEOUT)
            if isinstance(raw, str):
                continue
            m = decode(raw)
            if m.function == CONNECT_ACCEPT:
                vmac, dev_uuid, max_bvlc, max_npdu = parse_connect(m.payload)
                conn = Connection(ws, uri, vmac, dev_uuid, hub)
                conn.max_bvlc, conn.max_npdu = max_bvlc, max_npdu
                return conn
            if m.function == RESULT:
                func, nak, text = parse_result(m.payload)
                if nak:
                    raise SCError(f"{uri} refused the connection ({text or 'NAK'})"
                                  + (" - the VMAC or device UUID may already be in use" if "ollision" in text
                                     or "in use" in text else ""))
            # anything else before the accept is ignored
    except SCError:
        await ws.close()
        raise
    except Exception as e:
        await ws.close()
        raise SCError(f"{uri}: handshake failed ({type(e).__name__}: {e})") from e


class SCLinkLayer(Client[PDU], Server[PDU]):
    """bacpypes3 link layer over BACnet/SC. Call `await start()` once the event loop runs."""

    def __init__(self, settings: SCSettings, on_event=lambda msg: None):
        settings.validate()
        self.s = settings
        self.local_address = LocalStation(settings.vmac)
        self.on_event = on_event
        self.ctx = make_ssl_context(settings)
        self.hub_conn: Connection | None = None
        self.direct: dict[bytes, Connection] = {}  # peer VMAC -> direct connection
        self.no_direct: set[bytes] = set()  # peers we could not (or need not) reach directly
        self._resolving: set[bytes] = set()
        self._pending: dict[int, asyncio.Future] = {}  # message id -> reply future
        self._next_id = 100
        self._tasks: set[asyncio.Task] = set()
        self._closing = False
        self.hub_uri: str | None = None
        self.stats = {"sent": 0, "received": 0, "direct_sent": 0}

    # -- life cycle

    async def start(self) -> None:
        errors = []
        for uri in [u for u in (self.s.hub, self.s.failover) if u]:
            try:
                self.hub_conn = await open_connection(uri, self.ctx, self.s, hub=True)
            except SCError as e:
                errors.append(str(e))
                self.on_event(f"BACnet/SC: {e}")
                continue
            self.hub_uri = uri
            self.hub_conn.task = self._spawn(self._reader(self.hub_conn))
            self._spawn(self._heartbeat())
            self.on_event(f"BACnet/SC: connected to hub {uri} as VMAC {hex_vmac(self.s.vmac)} "
                          f"(hub VMAC {hex_vmac(self.hub_conn.peer_vmac)})")
            return
        raise SCError("; ".join(errors) or "no hub URI")

    def close(self) -> None:
        """Synchronous (called from Application.close): schedules an orderly disconnect."""
        if self._closing:
            return
        self._closing = True
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(self.aclose())

    async def aclose(self) -> None:
        self._closing = True
        for conn in [self.hub_conn, *self.direct.values()]:
            if conn is None or conn.closed:
                continue
            try:
                await asyncio.wait_for(conn.send(Message(DISCONNECT_REQUEST, self._id())), 1.0)
            except Exception:
                pass
            conn.closed = True
            try:
                await asyncio.wait_for(conn.ws.close(), 2.0)
            except Exception:
                pass
        for t in list(self._tasks):
            t.cancel()

    def _spawn(self, coro) -> asyncio.Task:
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    def _id(self) -> int:
        self._next_id = (self._next_id + 1) & 0xFFFF or 100
        return self._next_id

    # -- receive

    async def _reader(self, conn: Connection) -> None:
        try:
            async for raw in conn.ws:
                if isinstance(raw, str):
                    continue
                try:
                    m = decode(raw)
                except ValueError as e:
                    log.debug("bad BVLC-SC message from %s: %s", conn.uri, e)
                    continue
                await self._handle(conn, m)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.debug("SC reader for %s ended: %s", conn.uri, e)
        finally:
            conn.closed = True
            if not conn.hub:
                self.direct.pop(conn.peer_vmac, None)
            elif not self._closing:
                self.on_event("BACnet/SC: connection to the hub was lost")

    async def _handle(self, conn: Connection, m: Message) -> None:
        f = m.function
        if f == ENCAPSULATED_NPDU:
            src = m.origin or conn.peer_vmac
            dest = BROADCAST_VMAC if m.dest == BROADCAST_VMAC else self.s.vmac
            self.stats["received"] += 1
            pdu = PDU(m.payload, source=LocalStation(src),
                      destination=LocalBroadcast() if dest == BROADCAST_VMAC else self.local_address)
            await self.response(pdu)
        elif f in (RESULT, ADDRESS_RESOLUTION_ACK, CONNECT_ACCEPT, HEARTBEAT_ACK, ADVERTISEMENT, DISCONNECT_ACK):
            fut = self._pending.pop(m.message_id, None)
            if fut is not None and not fut.done():
                fut.set_result(m)
        elif f == HEARTBEAT_REQUEST:
            await conn.send(Message(HEARTBEAT_ACK, m.message_id, dest=m.origin))
        elif f == DISCONNECT_REQUEST:
            await conn.send(Message(DISCONNECT_ACK, m.message_id, dest=m.origin))
            conn.closed = True
            await conn.ws.close()
        elif f in (ADDRESS_RESOLUTION, ADVERTISEMENT_SOLICITATION):
            # we accept no incoming direct connections: say so politely
            await conn.send(Message(RESULT, m.message_id, dest=m.origin,
                                    payload=result_payload(f, (7, 31, "not supported"))))
        # proprietary and unknown messages are ignored

    async def _request(self, conn: Connection, m: Message, timeout: float = 5.0) -> Message:
        m.message_id = self._id()
        fut = asyncio.get_running_loop().create_future()
        self._pending[m.message_id] = fut
        await conn.send(m)
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(m.message_id, None)

    async def _heartbeat(self) -> None:
        while not self._closing:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            for conn in [self.hub_conn, *self.direct.values()]:
                if conn and not conn.closed:
                    try:
                        await self._request(conn, Message(HEARTBEAT_REQUEST), 10.0)
                    except Exception as e:
                        log.debug("heartbeat to %s failed: %s", conn.uri, e)

    # -- send (bacpypes3 indication)

    async def indication(self, pdu: PDU) -> None:
        dest = pdu.pduDestination
        if dest.addrType == Address.localBroadcastAddr or dest.addrType == Address.globalBroadcastAddr:
            vmac = BROADCAST_VMAC
        elif dest.addrType == Address.localStationAddr and len(dest.addrAddr) == 6:
            vmac = bytes(dest.addrAddr)
        else:
            raise SCError(f"BACnet/SC needs a 6-byte VMAC destination, got {dest}")
        data = bytes(pdu.pduData)
        self.stats["sent"] += 1
        conn = self.direct.get(vmac)
        if conn is not None and not conn.closed:
            self.stats["direct_sent"] += 1
            await conn.send(Message(ENCAPSULATED_NPDU, self._id(), payload=data))
            return
        if self.hub_conn is None or self.hub_conn.closed:
            raise SCError("not connected to a BACnet/SC hub")
        await self.hub_conn.send(Message(ENCAPSULATED_NPDU, self._id(), dest=vmac, payload=data))
        if self.s.direct and vmac != BROADCAST_VMAC and vmac not in self.no_direct and vmac not in self._resolving:
            self._resolving.add(vmac)
            self._spawn(self._try_direct(vmac))

    # -- direct connections (AB.5.3)

    async def _try_direct(self, vmac: bytes) -> None:
        try:
            ack = await self._request(self.hub_conn, Message(ADDRESS_RESOLUTION, dest=vmac), 5.0)
            if ack.function != ADDRESS_RESOLUTION_ACK:
                return
            uris = [u for u in ack.payload.decode(errors="replace").split() if u.startswith(("wss://", "ws://"))]
            for uri in uris:
                try:
                    conn = await open_connection(uri, self.ctx, self.s, hub=False, message_id=self._id())
                except SCError as e:
                    log.debug("direct connect to %s failed: %s", uri, e)
                    continue
                conn.task = self._spawn(self._reader(conn))
                self.direct[vmac] = conn
                self.on_event(f"BACnet/SC: direct connection to {hex_vmac(vmac)} via {uri}")
                return
        except Exception as e:
            log.debug("address resolution for %s failed: %s", hex_vmac(vmac), e)
        finally:
            self._resolving.discard(vmac)
            if vmac not in self.direct:
                self.no_direct.add(vmac)
