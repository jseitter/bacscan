"""Simulated BACnet/SC network for tests: a hub, devices that join it, and self-signed certificates.

The hub implements just enough of Annex AB for a node: Connect handshake (with VMAC collision NAK),
Encapsulated-NPDU unicast/broadcast forwarding, Address-Resolution forwarding, heartbeat, disconnect.
Devices are normal bacpypes3 applications on bacscan's own SC link layer plus an optional
direct-connect WebSocket server, so the hub/device wire format is checked by an independent
implementation of the hub side.
"""
from __future__ import annotations

import asyncio
import datetime
import ssl
from pathlib import Path

import websockets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from bacscan.core import sc
from bacscan.core.scanner import ScanApplication
from sim_device import populate


# ----------------------------------------------------------------- certificates


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path: Path, key=None, cert=None) -> str:
    data = b""
    if key is not None:
        data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    if cert is not None:
        data = cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(data)
    return str(path)


def make_pki(directory: Path, other_ca: bool = False) -> dict[str, str]:
    """CA + hub (server) certificate for 127.0.0.1 + client certificate. -> dict of file paths."""
    now = datetime.datetime.now(datetime.timezone.utc)

    def new_ca(cn: str):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        return key, cert

    def issue(ca_key, ca_cert, cn: str, server: bool):
        key = ec.generate_private_key(ec.SECP256R1())
        b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_cert.subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server
                                                   else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
        if server:
            import ipaddress
            b = b.add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        return key, b.sign(ca_key, hashes.SHA256())

    directory.mkdir(parents=True, exist_ok=True)
    ca_key, ca = new_ca("bacscan test CA")
    hub_key, hub = issue(ca_key, ca, "hub", True)
    cli_key, cli = issue(ca_key, ca, "node", False)
    out = {
        "ca": _write(directory / "ca.pem", cert=ca),
        "hub_cert": _write(directory / "hub.pem", cert=hub), "hub_key": _write(directory / "hub.key", key=hub_key),
        "cert": _write(directory / "node.pem", cert=cli), "key": _write(directory / "node.key", key=cli_key),
    }
    if other_ca:  # a certificate from a CA the hub does not trust
        k2, ca2 = new_ca("rogue CA")
        k3, c3 = issue(k2, ca2, "rogue", False)
        out["rogue_cert"] = _write(directory / "rogue.pem", cert=c3)
        out["rogue_key"] = _write(directory / "rogue.key", key=k3)
        out["rogue_ca"] = _write(directory / "rogue_ca.pem", cert=ca2)
    return out


def server_context(cert: str, key: str, ca: str, require_client_cert: bool = True) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(cafile=ca)
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    return ctx


# ----------------------------------------------------------------- hub


class SimHub:
    def __init__(self, ctx: ssl.SSLContext | None, port: int = 0):
        self.ctx = ctx
        self.port = port
        self.vmac = bytes.fromhex("0200deadbeef")
        self.nodes: dict[bytes, websockets.ServerConnection] = {}
        self.log: list[str] = []
        self.server = None

    @property
    def uri(self) -> str:
        return f"{'wss' if self.ctx else 'ws'}://127.0.0.1:{self.port}"

    async def start(self) -> "SimHub":
        self.server = await websockets.serve(self._handler, "127.0.0.1", self.port, ssl=self.ctx,
                                             subprotocols=[sc.HUB_SUBPROTOCOL])
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _handler(self, ws) -> None:
        node = None
        try:
            first = sc.decode(await asyncio.wait_for(ws.recv(), 5))
            if first.function != sc.CONNECT_REQUEST:
                return
            vmac, dev_uuid, _, _ = sc.parse_connect(first.payload)
            if vmac in self.nodes:
                self.log.append(f"NAK vmac collision {vmac.hex()}")
                await ws.send(sc.encode(sc.Message(sc.RESULT, first.message_id, payload=sc.result_payload(
                    sc.CONNECT_REQUEST, (7, 33, "node VMAC collision")))))
                return
            await ws.send(sc.encode(sc.Message(sc.CONNECT_ACCEPT, first.message_id,
                                               payload=sc.connect_payload(self.vmac, b"\x99" * 16))))
            node = vmac
            self.nodes[vmac] = ws
            self.log.append(f"connect {vmac.hex()}")
            async for raw in ws:
                m = sc.decode(raw)
                m.origin = vmac
                if m.function in (sc.ENCAPSULATED_NPDU, sc.ADDRESS_RESOLUTION, sc.ADDRESS_RESOLUTION_ACK,
                                  sc.ADVERTISEMENT, sc.ADVERTISEMENT_SOLICITATION, sc.RESULT):
                    self.log.append(f"{m.name} {vmac.hex()} -> {m.dest.hex() if m.dest else '-'}")
                    if m.dest == sc.BROADCAST_VMAC:
                        for other, w in list(self.nodes.items()):
                            if other != vmac:
                                await w.send(sc.encode(m))
                    elif m.dest in self.nodes:
                        await self.nodes[m.dest].send(sc.encode(m))
                    m.dest = None
                elif m.function == sc.HEARTBEAT_REQUEST:
                    await ws.send(sc.encode(sc.Message(sc.HEARTBEAT_ACK, m.message_id)))
                elif m.function == sc.DISCONNECT_REQUEST:
                    await ws.send(sc.encode(sc.Message(sc.DISCONNECT_ACK, m.message_id)))
                    return
        except (websockets.ConnectionClosed, asyncio.TimeoutError, ValueError):
            pass
        finally:
            if node is not None and self.nodes.get(node) is ws:
                del self.nodes[node]


# ----------------------------------------------------------------- device on the SC network


class SimSCDevice:
    """A bacpypes3 device that joins the hub; optionally accepts direct connections on its own port."""

    def __init__(self, hub_uri: str, pki: dict[str, str], instance: int, direct_port: int | None = None,
                 n_analog: int = 5):
        self.instance = instance
        self.direct_port = direct_port
        self.settings = sc.SCSettings(hub=hub_uri, cert=pki["cert"], key=pki["key"], ca=pki["ca"])
        self.pki = pki
        self.n_analog = n_analog
        self.link: sc.SCLinkLayer | None = None
        self.app = None
        self.direct_server = None
        self.direct_peers: dict[bytes, websockets.ServerConnection] = {}
        self.direct_frames = 0

    async def start(self) -> "SimSCDevice":
        from bacpypes3.primitivedata import ObjectType
        from bacpypes3.vendor import get_vendor_info
        device = get_vendor_info(999).get_object_class(ObjectType.device)(
            objectIdentifier=("device", self.instance), objectName=f"SimSC-{self.instance}", vendorIdentifier=999)
        self.app = populate(ScanApplication.from_object_list([device]), self.n_analog)
        self.link = sc.SCLinkLayer(self.settings)
        self.app.sc_link = self.link
        self.app.nsap.bind(self.link, address=self.link.local_address)
        if self.direct_port is not None:
            self._wrap_resolution()
            ctx = server_context(self.pki["hub_cert"], self.pki["hub_key"], self.pki["ca"])
            self.direct_server = await websockets.serve(
                self._direct_handler, "127.0.0.1", self.direct_port, ssl=ctx, subprotocols=[sc.DC_SUBPROTOCOL])
        await self.link.start()
        return self

    @property
    def vmac(self) -> bytes:
        return self.settings.vmac

    def _wrap_resolution(self) -> None:
        """Answer Address-Resolution from the hub with our direct-connect URI."""
        link = self.link
        orig = link._handle

        async def handle(conn, m):
            if m.function == sc.ADDRESS_RESOLUTION:
                uri = f"wss://127.0.0.1:{self.direct_port}"
                await conn.send(sc.Message(sc.ADDRESS_RESOLUTION_ACK, m.message_id, dest=m.origin,
                                           payload=uri.encode()))
                return
            await orig(conn, m)

        link._handle = handle

    async def _direct_handler(self, ws) -> None:
        try:
            first = sc.decode(await asyncio.wait_for(ws.recv(), 5))
            vmac, _, _, _ = sc.parse_connect(first.payload)
            await ws.send(sc.encode(sc.Message(sc.CONNECT_ACCEPT, first.message_id, payload=sc.connect_payload(
                self.vmac, b"\x77" * 16))))
            self.direct_peers[vmac] = ws
            async for raw in ws:
                m = sc.decode(raw)
                if m.function == sc.ENCAPSULATED_NPDU:
                    self.direct_frames += 1
                    from bacpypes3.pdu import PDU, LocalStation
                    await self.link.response(PDU(m.payload, source=LocalStation(vmac),
                                                 destination=self.link.local_address))
                elif m.function == sc.HEARTBEAT_REQUEST:
                    await ws.send(sc.encode(sc.Message(sc.HEARTBEAT_ACK, m.message_id)))
                elif m.function == sc.DISCONNECT_REQUEST:
                    await ws.send(sc.encode(sc.Message(sc.DISCONNECT_ACK, m.message_id)))
                    return
        except (websockets.ConnectionClosed, asyncio.TimeoutError, ValueError):
            pass

    async def stop(self) -> None:
        await self.link.aclose()
        if self.direct_server:
            self.direct_server.close()
            await self.direct_server.wait_closed()
