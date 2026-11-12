"""SNMP read-out (spec §4.9): a small read-only SNMP v2c / v3 client.

Only GET, GETNEXT and GETBULK are implemented - there is no SET in this module.
v3: USM with HMAC-MD5-96 / HMAC-SHA-96 / HMAC-SHA-256-192 authentication and AES-128 (CFB) privacy.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

log = logging.getLogger("bacscan.snmp")

DEFAULT_PORT = 161
MAX_TARGETS = 256
WALK_LIMIT = 5000
MAX_REPETITIONS = 20

# PDU tags
GET, GETNEXT, RESPONSE, GETBULK, REPORT = 0xA0, 0xA1, 0xA2, 0xA5, 0xA8


class SnmpError(Exception):
    pass


class _Special:
    def __init__(self, name: str):
        self.name = name

    def __repr__(self) -> str:
        return self.name


NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB = _Special("noSuchObject"), _Special("noSuchInstance"), \
    _Special("endOfMibView")
SPECIALS = {0x80: NO_SUCH_OBJECT, 0x81: NO_SUCH_INSTANCE, 0x82: END_OF_MIB}


# ---------------------------------------------------------------- BER


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len(len(payload)) + payload


def enc_int(v: int, tag: int = 0x02) -> bytes:
    n = max(1, (v.bit_length() + 8) // 8)
    return tlv(tag, v.to_bytes(n, "big", signed=True))


def enc_oct(b: bytes | str) -> bytes:
    return tlv(0x04, b.encode() if isinstance(b, str) else b)


def enc_null() -> bytes:
    return b"\x05\x00"


def enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError(f"bad OID {oid}")
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out.extend(reversed(chunk))
    return tlv(0x06, bytes(out))


def seq(*items: bytes, tag: int = 0x30) -> bytes:
    return tlv(tag, b"".join(items))


def dec(data: bytes, off: int = 0) -> tuple[int, bytes, int]:
    """(tag, value, next offset)."""
    if off + 2 > len(data):
        raise SnmpError("truncated BER")
    tag = data[off]
    n = data[off + 1]
    off += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(data[off:off + k], "big")
        off += k
    if off + n > len(data):
        raise SnmpError("truncated BER value")
    return tag, data[off:off + n], off + n


def dec_all(data: bytes) -> list[tuple[int, bytes]]:
    out, off = [], 0
    while off < len(data):
        tag, v, off = dec(data, off)
        out.append((tag, v))
    return out


def dec_oid(b: bytes) -> str:
    if not b:
        return ""
    parts = [b[0] // 40, b[0] % 40] if b[0] < 80 else [2, b[0] - 80]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(map(str, parts))


def decode_value(tag: int, b: bytes) -> Any:
    if tag == 0x02:
        return int.from_bytes(b, "big", signed=True) if b else 0
    if tag == 0x04:
        return b
    if tag == 0x05:
        return None
    if tag == 0x06:
        return dec_oid(b)
    if tag == 0x40 and len(b) == 4:
        return socket.inet_ntoa(b)
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32, Gauge32, TimeTicks, Counter64
        return int.from_bytes(b, "big")
    if tag in SPECIALS:
        return SPECIALS[tag]
    return b


def pdu(tag: int, request_id: int, oids: Iterable[str], a: int = 0, b: int = 0) -> bytes:
    """GET/GETNEXT: a, b = error-status/index (0); GETBULK: a = non-repeaters, b = max-repetitions."""
    vbs = seq(*(seq(enc_oid(o), enc_null()) for o in oids))
    return tlv(tag, enc_int(request_id) + enc_int(a) + enc_int(b) + vbs)


def parse_pdu(data: bytes) -> tuple[int, int, int, int, list[tuple[str, Any]]]:
    tag, body, _ = dec(data)
    items = dec_all(body)
    if len(items) < 4:
        raise SnmpError("bad PDU")
    rid, err, idx = (decode_value(0x02, items[i][1]) for i in range(3))
    vbs = []
    for _, vb in dec_all(items[3][1]):
        (_, oid_b), (vtag, vval) = dec_all(vb)[:2]
        vbs.append((dec_oid(oid_b), decode_value(vtag, vval)))
    return tag, rid, err, idx, vbs


ERROR_STATUS = {1: "tooBig", 2: "noSuchName", 3: "badValue", 4: "readOnly", 5: "genErr", 6: "noAccess",
                16: "authorizationError"}


# ---------------------------------------------------------------- credentials & USM


AUTH = {"MD5": ("md5", 12), "SHA": ("sha1", 12), "SHA256": ("sha256", 24)}
PRIV = ("AES",)


@dataclass
class Credentials:
    version: str = "v2c"  # v2c | v3
    community: str = ""
    user: str = ""
    auth_proto: str = ""  # "" | MD5 | SHA | SHA256
    auth_pass: str = ""
    priv_proto: str = ""  # "" | AES
    priv_pass: str = ""

    def __post_init__(self) -> None:
        self.auth_proto = self.auth_proto.upper().replace("-", "")
        self.priv_proto = self.priv_proto.upper().replace("-", "").replace("AES128", "AES")
        if self.version == "v3":
            if not self.user:
                raise ValueError("SNMP v3 needs a user name")
            if self.auth_proto and self.auth_proto not in AUTH:
                raise ValueError(f"auth protocol must be one of {', '.join(AUTH)}")
            if self.priv_proto and self.priv_proto not in PRIV:
                raise ValueError("privacy protocol must be AES")
            if self.priv_proto and not self.auth_proto:
                raise ValueError("privacy needs authentication")
            if self.auth_proto and len(self.auth_pass) < 8 or self.priv_proto and len(self.priv_pass) < 8:
                raise ValueError("SNMP v3 passwords must have at least 8 characters")
        elif self.version == "v2c":
            if not self.community:
                raise ValueError("SNMP v2c needs a community string")
        else:
            raise ValueError("SNMP version must be v2c or v3")

    @property
    def level(self) -> str:
        return "authPriv" if self.priv_proto else "authNoPriv" if self.auth_proto else "noAuthNoPriv"

    def describe(self) -> str:
        """For storage and reports - never contains secrets."""
        if self.version == "v2c":
            return "v2c (community not stored)"
        protos = "/".join(x for x in (self.auth_proto, self.priv_proto) if x)
        return f"v3 user {self.user} ({self.level}{', ' + protos if protos else ''})"

    @classmethod
    def from_env(cls, community: str | None = None, user: str | None = None, auth_proto: str = "",
                 auth_pass: str | None = None, priv_proto: str = "", priv_pass: str | None = None) -> "Credentials":
        """Command-line values, falling back to BACSCAN_SNMP_* environment variables for the secrets."""
        community = community or os.environ.get("BACSCAN_SNMP_COMMUNITY", "")
        if user:
            auth_pass = auth_pass or os.environ.get("BACSCAN_SNMP_AUTH", "")
            priv_pass = priv_pass or os.environ.get("BACSCAN_SNMP_PRIV", "")
            if auth_pass and not auth_proto:
                auth_proto = "SHA"
            if priv_pass and not priv_proto:
                priv_proto = "AES"
            return cls("v3", user=user, auth_proto=auth_proto, auth_pass=auth_pass or "",
                       priv_proto=priv_proto, priv_pass=priv_pass or "")
        return cls("v2c", community=community)


def password_to_key(password: str, engine_id: bytes, hash_name: str) -> bytes:
    """RFC 3414 A.2 key localization (also used for SHA-256 per RFC 7860)."""
    pw = password.encode()
    ku = hashlib.new(hash_name, (pw * (1048576 // len(pw) + 1))[:1048576]).digest()
    return hashlib.new(hash_name, ku + engine_id + ku).digest()


def _aes_cfb(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        try:  # cryptography >= 47 moved CFB to the "decrepit" module
            from cryptography.hazmat.decrepit.ciphers.modes import CFB
        except ImportError:  # pragma: no cover
            from cryptography.hazmat.primitives.ciphers.modes import CFB
    except ImportError as e:  # pragma: no cover - dependency is installed
        raise SnmpError("SNMP v3 privacy needs the 'cryptography' package") from e
    c = Cipher(algorithms.AES(key[:16]), CFB(iv))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


USM_REPORTS = {
    "1.3.6.1.6.3.15.1.1.1.0": "unsupported security level",
    "1.3.6.1.6.3.15.1.1.2.0": "not in time window",
    "1.3.6.1.6.3.15.1.1.3.0": "unknown user name",
    "1.3.6.1.6.3.15.1.1.4.0": "unknown engine ID",
    "1.3.6.1.6.3.15.1.1.5.0": "wrong authentication (password or protocol)",
    "1.3.6.1.6.3.15.1.1.6.0": "decryption error (privacy password or protocol)",
}


# ---------------------------------------------------------------- client


class SnmpClient:
    """Blocking client for one agent. Read-only: get / getnext / getbulk / walk."""

    def __init__(self, ip: str, creds: Credentials, port: int = DEFAULT_PORT, timeout: float = 2.0,
                 retries: int = 1, source_ip: str | None = None):
        self.ip, self.port, self.creds = ip, port, creds
        self.timeout, self.retries = timeout, retries
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        if source_ip and family == socket.AF_INET:
            self.sock.bind((source_ip, 0))
        self._rid = random.randint(1, 0x3FFFFFFF)
        self._salt = random.getrandbits(64)
        # v3 engine state
        self.engine_id = b""
        self.boots = 0
        self.time = 0
        self._time_ref = 0.0
        self._auth_key = self._priv_key = b""

    def close(self) -> None:
        self.sock.close()

    def __enter__(self) -> "SnmpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _next_id(self) -> int:
        self._rid = (self._rid + 1) & 0x7FFFFFFF or 1
        return self._rid

    # -- transport

    def _roundtrip(self, msg: bytes, match: Callable[[bytes], Any]) -> Any:
        last: Exception | None = None
        for _ in range(self.retries + 1):
            self.sock.sendto(msg, (self.ip, self.port))
            end = time.monotonic() + self.timeout
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    break
                self.sock.settimeout(left)
                try:
                    data, _ = self.sock.recvfrom(65535)
                except socket.timeout:
                    break
                except OSError as e:  # e.g. ICMP port unreachable
                    last = e
                    break
                try:
                    r = match(data)
                except SnmpError as e:
                    last = e
                    continue
                if r is not None:
                    return r
        if isinstance(last, SnmpError):
            raise last
        raise SnmpError("no answer" + (f" ({last})" if last else ""))

    # -- v2c

    def _v2c(self, pdu_bytes: bytes, rid: int):
        msg = seq(enc_int(1), enc_oct(self.creds.community), pdu_bytes)

        def match(data: bytes):
            items = dec_all(dec(data)[1])
            if len(items) < 3:
                return None
            p = parse_pdu(tlv(items[2][0], items[2][1]))
            return p if p[1] == rid else None
        return self._roundtrip(msg, match)

    # -- v3

    def _discover_engine(self) -> None:
        rid = self._next_id()
        msg_id = self._next_id()
        scoped = seq(enc_oct(b""), enc_oct(b""), pdu(GET, rid, []))
        msg = self._v3_message(msg_id, 0x04, b"", 0, 0, "", b"", b"", scoped)

        def match(data: bytes):
            m = self._parse_v3(data)
            if m["msg_id"] != msg_id:
                return None
            return m
        m = self._roundtrip(msg, match)
        self.engine_id, self.boots, self.time = m["engine_id"], m["boots"], m["time"]
        self._time_ref = time.monotonic()
        if not self.engine_id:
            raise SnmpError("agent did not report its engine ID")
        c = self.creds
        if c.auth_proto:
            h = AUTH[c.auth_proto][0]
            self._auth_key = password_to_key(c.auth_pass, self.engine_id, h)
            if c.priv_proto:
                self._priv_key = password_to_key(c.priv_pass, self.engine_id, h)

    def _v3_message(self, msg_id: int, flags: int, engine_id: bytes, boots: int, etime: int, user: str,
                    auth: bytes, priv: bytes, scoped_or_encrypted: bytes) -> bytes:
        sec = seq(enc_oct(engine_id), enc_int(boots), enc_int(etime), enc_oct(user), enc_oct(auth), enc_oct(priv))
        glob = seq(enc_int(msg_id), enc_int(65507), enc_oct(bytes([flags])), enc_int(3))
        return seq(enc_int(3), glob, enc_oct(sec), scoped_or_encrypted)

    def _parse_v3(self, data: bytes) -> dict:
        top = dec_all(dec(data)[1])
        if len(top) < 4 or decode_value(0x02, top[0][1]) != 3:
            raise SnmpError("not an SNMPv3 message")
        glob = dec_all(top[1][1])
        msg_id = decode_value(0x02, glob[0][1])
        flags = glob[2][1][0] if glob[2][1] else 0
        sec = dec_all(dec(top[2][1])[1])
        engine_id, boots, etime = sec[0][1], decode_value(0x02, sec[1][1]), decode_value(0x02, sec[2][1])
        auth_params, priv_params = sec[4][1], sec[5][1]
        out = {"msg_id": msg_id, "flags": flags, "engine_id": engine_id, "boots": boots, "time": etime}
        if flags & 0x01 and self._auth_key:
            name, n = AUTH[self.creds.auth_proto]
            i = data.find(auth_params)
            zeroed = data[:i] + b"\0" * len(auth_params) + data[i + len(auth_params):]
            if hmac.new(self._auth_key, zeroed, name).digest()[:n] != auth_params:
                raise SnmpError("response failed authentication check")
        tag, payload = top[3]
        if tag == 0x04:  # encrypted scoped PDU
            if not self._priv_key:
                raise SnmpError("encrypted response but no privacy key")
            iv = struct.pack("!II", boots, etime) + priv_params
            payload = dec(_aes_cfb(self._priv_key, iv, payload, False))[1]
        scoped = dec_all(payload)
        out["pdu"] = parse_pdu(tlv(scoped[2][0], scoped[2][1]))
        return out

    def _v3(self, pdu_bytes: bytes, rid: int, _retry: bool = True):
        if not self.engine_id:
            self._discover_engine()
        c = self.creds
        etime = self.time + int(time.monotonic() - self._time_ref)
        msg_id = self._next_id()
        flags = 0x04 | (0x01 if c.auth_proto else 0) | (0x02 if c.priv_proto else 0)
        scoped = seq(enc_oct(self.engine_id), enc_oct(b""), pdu_bytes)
        priv = b""
        if c.priv_proto:
            self._salt = (self._salt + 1) & 0xFFFFFFFFFFFFFFFF
            priv = self._salt.to_bytes(8, "big")
            iv = struct.pack("!II", self.boots, etime) + priv
            body = enc_oct(_aes_cfb(self._priv_key, iv, scoped, True))
        else:
            body = scoped
        if c.auth_proto:
            name, n = AUTH[c.auth_proto]
            placeholder = b"\0" * n
            msg = self._v3_message(msg_id, flags, self.engine_id, self.boots, etime, c.user, placeholder, priv, body)
            marker = enc_oct(c.user) + enc_oct(placeholder)
            i = msg.index(marker) + len(enc_oct(c.user)) + 2
            digest = hmac.new(self._auth_key, msg, name).digest()[:n]
            msg = msg[:i] + digest + msg[i + n:]
        else:
            msg = self._v3_message(msg_id, flags, self.engine_id, self.boots, etime, c.user, b"", b"", body)

        def match(data: bytes):
            m = self._parse_v3(data)
            return m if m["msg_id"] == msg_id else None
        m = self._roundtrip(msg, match)
        tag, prid, err, idx, vbs = m["pdu"]
        if tag == REPORT:
            oid = vbs[0][0] if vbs else ""
            reason = USM_REPORTS.get(oid, f"report {oid}")
            if oid == "1.3.6.1.6.3.15.1.1.2.0" and _retry:  # resync clock and try once more
                self.boots, self.time, self._time_ref = m["boots"], m["time"], time.monotonic()
                return self._v3(pdu_bytes, rid, _retry=False)
            raise SnmpError(reason)
        return m["pdu"]

    # -- public, read-only

    def _request(self, tag: int, oids: list[str], a: int = 0, b: int = 0) -> list[tuple[str, Any]]:
        rid = self._next_id()
        p = pdu(tag, rid, oids, a, b)
        res = self._v3(p, rid) if self.creds.version == "v3" else self._v2c(p, rid)
        _, _, err, idx, vbs = res
        if err:
            raise SnmpError(f"agent error {ERROR_STATUS.get(err, err)} (index {idx})")
        return vbs

    def get(self, oids: list[str]) -> dict[str, Any]:
        return {o: v for o, v in self._request(GET, oids) if not isinstance(v, _Special)}

    def getnext(self, oids: list[str]) -> list[tuple[str, Any]]:
        return self._request(GETNEXT, oids)

    def getbulk(self, oids: list[str], max_repetitions: int = MAX_REPETITIONS) -> list[tuple[str, Any]]:
        return self._request(GETBULK, oids, 0, max_repetitions)

    def walk(self, base: str, limit: int = WALK_LIMIT) -> list[tuple[str, Any]]:
        """All (oid, value) below `base`, using GETBULK."""
        out: list[tuple[str, Any]] = []
        prefix = base.strip(".") + "."
        cur = base.strip(".")
        while len(out) < limit:
            vbs = self.getbulk([cur])
            if not vbs:
                break
            for oid, v in vbs:
                if not oid.startswith(prefix) or v is END_OF_MIB:
                    return out
                if not _oid_greater(oid, cur):
                    return out  # agent went backwards: stop rather than loop
                out.append((oid, v))
                cur = oid
                if len(out) >= limit:
                    break
        return out


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(x) for x in oid.split("."))


def _oid_greater(a: str, b: str) -> bool:
    return _oid_key(a) > _oid_key(b)


# ---------------------------------------------------------------- what we read (S3)

SYSTEM = {
    "sysDescr": "1.3.6.1.2.1.1.1.0", "sysObjectID": "1.3.6.1.2.1.1.2.0", "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0", "sysName": "1.3.6.1.2.1.1.5.0", "sysLocation": "1.3.6.1.2.1.1.6.0",
}
IF_COLUMNS = {
    "descr": "1.3.6.1.2.1.2.2.1.2", "type": "1.3.6.1.2.1.2.2.1.3", "speed": "1.3.6.1.2.1.2.2.1.5",
    "mac": "1.3.6.1.2.1.2.2.1.6", "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8",
    "name": "1.3.6.1.2.1.31.1.1.1.1", "high_speed": "1.3.6.1.2.1.31.1.1.1.15", "alias": "1.3.6.1.2.1.31.1.1.1.18",
}
IP_ADDR_IFINDEX = "1.3.6.1.2.1.4.20.1.2"
IP_ADDR_MASK = "1.3.6.1.2.1.4.20.1.3"
ENTITY = {"descr": "1.3.6.1.2.1.47.1.1.1.1.2", "class": "1.3.6.1.2.1.47.1.1.1.1.5",
          "firmware": "1.3.6.1.2.1.47.1.1.1.1.9", "software": "1.3.6.1.2.1.47.1.1.1.1.10",
          "serial": "1.3.6.1.2.1.47.1.1.1.1.11", "model": "1.3.6.1.2.1.47.1.1.1.1.13"}
LLDP_REM = {"chassis": "1.0.8802.1.1.2.1.4.1.1.5", "port_id": "1.0.8802.1.1.2.1.4.1.1.7",
            "port_desc": "1.0.8802.1.1.2.1.4.1.1.8", "sys_name": "1.0.8802.1.1.2.1.4.1.1.9"}
LLDP_LOC_PORT = {"port_id": "1.0.8802.1.1.2.1.3.7.1.3", "port_desc": "1.0.8802.1.1.2.1.3.7.1.4"}
BRIDGE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"  # BRIDGE-MIB dot1dTpFdbPort, index = MAC
QFDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # Q-BRIDGE dot1qTpFdbPort, index = fdbId.MAC
VLAN_FDB_ID = "1.3.6.1.2.1.17.7.1.4.2.1.3"  # dot1qVlanFdbId, index = timeMark.vlan
IF_OPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}
IF_TYPES = {6: "ethernet", 24: "loopback", 53: "virtual", 71: "wifi", 131: "tunnel", 135: "vlan", 136: "vlan",
            161: "lag", 117: "gigabit-ethernet"}


def text(v: Any) -> str:
    if isinstance(v, bytes):
        try:
            s = v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex(":")
        return s.strip("\x00").strip() if s.isprintable() or "\n" in s else v.hex(":")
    return "" if v is None or isinstance(v, _Special) else str(v)


def mac_text(v: Any) -> str:
    return v.hex(":") if isinstance(v, bytes) and len(v) == 6 else ""


def uptime_text(ticks: int | None) -> str:
    if not isinstance(ticks, int):
        return ""
    s = ticks // 100
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    return f"{d} d {h} h {s // 60} min" if d else f"{h} h {s // 60} min"


def _table(client: SnmpClient, columns: dict[str, str], limit: int = WALK_LIMIT) -> dict[str, dict[str, Any]]:
    """Walk several columns of one table -> {index: {column: value}}."""
    rows: dict[str, dict[str, Any]] = {}
    for name, base in columns.items():
        try:
            for oid, v in client.walk(base, limit):
                rows.setdefault(oid[len(base) + 1:], {})[name] = v
        except SnmpError as e:
            if "no answer" in str(e):
                raise
            log.debug("%s %s: %s", client.ip, name, e)
    return rows


def _mac_from_index(parts: list[str]) -> str:
    return ":".join(f"{int(x):02x}" for x in parts)


def read_agent(ip: str, creds: Credentials, port: int = DEFAULT_PORT, tables: bool = True,
               timeout: float = 2.0, retries: int = 1, source_ip: str | None = None) -> dict:
    """Everything of S3 from one agent. Never raises; errors land in 'error'."""
    r: dict[str, Any] = {"ip": ip, "version": creds.version, "ok": False}
    try:
        with SnmpClient(ip, creds, port, timeout, retries, source_ip) as c:
            sysvals = c.get(list(SYSTEM.values()))
            if not sysvals:
                r["error"] = "no system information"
                return r
            r["ok"] = True
            for k, oid in SYSTEM.items():
                v = sysvals.get(oid)
                r[k] = uptime_text(v) if k == "sysUpTime" else text(v)
            if c.engine_id:
                r["engine_id"] = c.engine_id.hex()
            if not tables:
                return r
            # interfaces
            ifs = _table(c, IF_COLUMNS, 2048)
            interfaces = []
            for idx, row in sorted(ifs.items(), key=lambda kv: int(kv[0]) if kv[0].isdigit() else 0):
                speed = row.get("high_speed") or ((row.get("speed") or 0) // 1_000_000)
                interfaces.append({
                    "index": int(idx) if idx.isdigit() else idx, "name": text(row.get("name")) or text(row.get("descr")),
                    "descr": text(row.get("descr")), "alias": text(row.get("alias")),
                    "type": IF_TYPES.get(row.get("type"), str(row.get("type", ""))),
                    "speed_mbps": speed or None, "mac": mac_text(row.get("mac")),
                    "admin": IF_OPER.get(row.get("admin"), ""), "oper": IF_OPER.get(row.get("oper"), ""),
                })
            r["interfaces"] = interfaces
            if_names = {i["index"]: i["name"] for i in interfaces}
            # IPv4 addresses
            ips = _table(c, {"ifindex": IP_ADDR_IFINDEX, "mask": IP_ADDR_MASK}, 512)
            r["ip_addresses"] = [
                {"ip": idx, "mask": v.get("mask", ""), "interface": if_names.get(v.get("ifindex"), v.get("ifindex"))}
                for idx, v in ips.items()]
            # chassis (ENTITY-MIB): chassis rows, else the first one
            ent = _table(c, ENTITY, 200)
            chassis = [v for v in ent.values() if v.get("class") == 3] or list(ent.values())[:1]
            if chassis:
                e = chassis[0]
                r["entity"] = {k: text(e.get(k)) for k in ("model", "serial", "software", "firmware", "descr")
                               if text(e.get(k))}
            # LLDP neighbours
            loc = _table(c, LLDP_LOC_PORT, 1024)
            rem = _table(c, LLDP_REM, 2048)
            neighbours = []
            for idx, v in rem.items():
                parts = idx.split(".")
                local = parts[1] if len(parts) >= 3 else ""
                lp = loc.get(local, {})
                neighbours.append({
                    "local_port": text(lp.get("port_desc")) or text(lp.get("port_id")) or
                    if_names.get(int(local) if local.isdigit() else local, local),
                    "local_port_num": int(local) if local.isdigit() else local,
                    "remote_name": text(v.get("sys_name")), "remote_port": text(v.get("port_id")),
                    "remote_port_desc": text(v.get("port_desc")),
                    "remote_chassis": mac_text(v.get("chassis")) or text(v.get("chassis")),
                })
            r["lldp"] = neighbours
            # forwarding database
            base_ports = {int(k): row.get("ifindex")
                          for k, row in _table(c, {"ifindex": BRIDGE_PORT_IFINDEX}, 2048).items() if k.isdigit()}
            fdb: list[dict] = []
            vlan_of_fdb = {}
            for idx, v in _table(c, {"fdb": VLAN_FDB_ID}, 4096).items():
                parts = idx.split(".")
                if len(parts) == 2 and isinstance(v.get("fdb"), int):
                    vlan_of_fdb[v["fdb"]] = int(parts[1])
            for idx, v in _table(c, {"port": QFDB_PORT}, WALK_LIMIT).items():
                parts = idx.split(".")
                if len(parts) == 7 and v.get("port"):
                    fdb_id = int(parts[0])
                    fdb.append({"mac": _mac_from_index(parts[1:]), "bridge_port": v["port"],
                                "vlan": vlan_of_fdb.get(fdb_id, fdb_id)})
            if not fdb:
                for idx, v in _table(c, {"port": FDB_PORT}, WALK_LIMIT).items():
                    parts = idx.split(".")
                    if len(parts) == 6 and v.get("port"):
                        fdb.append({"mac": _mac_from_index(parts), "bridge_port": v["port"], "vlan": None})
            for e in fdb:
                ifindex = base_ports.get(e["bridge_port"], e["bridge_port"])
                e["interface"] = if_names.get(ifindex, str(ifindex))
            r["fdb"] = fdb
    except SnmpError as e:
        r["error"] = str(e)
    except OSError as e:
        r["error"] = f"{type(e).__name__}: {e}"
    return r


# ---------------------------------------------------------------- S4: MAC -> switch port


UPLINK_MACS = 4


def map_ports(agents: list[dict]) -> dict[str, dict]:
    """{mac: {"switch", "port", "vlan", "switch_ip"}} for MACs learned on access ports."""
    candidates: dict[str, list[tuple[int, dict]]] = {}
    for a in agents:
        fdb = a.get("fdb") or []
        if not fdb:
            continue
        per_port: dict[str, int] = {}
        for e in fdb:
            per_port[e["interface"]] = per_port.get(e["interface"], 0) + 1
        lldp_ports = {n["local_port"] for n in a.get("lldp", [])} | {
            next((i["name"] for i in a.get("interfaces", []) if i["index"] == n.get("local_port_num")), "")
            for n in a.get("lldp", [])}
        a["port_mac_counts"] = per_port
        for e in fdb:
            port = e["interface"]
            if per_port[port] > UPLINK_MACS or port in lldp_ports:
                continue
            candidates.setdefault(e["mac"], []).append((per_port[port], {
                "switch": a.get("sysName") or a["ip"], "switch_ip": a["ip"], "port": port, "vlan": e.get("vlan")}))
    return {mac: sorted(c, key=lambda x: x[0])[0][1] for mac, c in candidates.items()}


def port_text(p: dict | None) -> str:
    if not p:
        return ""
    vlan = f" (VLAN {p['vlan']})" if p.get("vlan") not in (None, "") else ""
    return f"{p['switch']} {p['port']}{vlan}"


def expand_targets(specs: Iterable[str]) -> list[str]:
    from .network import expand_targets as expand
    out: list[str] = []
    for s in specs:
        for t in expand(s):
            ip = t.split(":")[0] if t.count(":") == 1 else t
            if ip not in out:
                out.append(ip)
    if len(out) > MAX_TARGETS:
        raise ValueError(f"at most {MAX_TARGETS} SNMP targets ({len(out)} given)")
    return out


def survey(targets: list[str], creds: Credentials, port: int = DEFAULT_PORT, tables: bool = True,
           parallel: int = 4, should_stop: Callable[[], bool] = lambda: False,
           emit: Callable[[str], None] = lambda m: None, source_ip: str | None = None) -> dict:
    """S2-S5: query all targets (max 4 at a time); returns the network['snmp'] structure."""
    from concurrent.futures import ThreadPoolExecutor

    agents: list[dict] = []
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = [pool.submit(lambda ip=ip: {"ip": ip, "version": creds.version, "ok": False, "error": "cancelled"}
                               if should_stop() else read_agent(ip, creds, port, tables, source_ip=source_ip))
                   for ip in targets]
        for f in futures:
            a = f.result()
            agents.append(a)
            if a.get("ok"):
                emit(f"SNMP {a['ip']}: {a.get('sysName') or '?'} - {a.get('sysDescr', '')[:60]}")
    mac_ports = map_ports(agents)
    for a in agents:
        a["fdb_entries"] = len(a.pop("fdb", []) or [])
    agents.sort(key=lambda a: _ip_sort(a["ip"]))
    return {"credentials": creds.describe(), "port": port, "agents": agents, "mac_ports": mac_ports}


def _ip_sort(ip: str):
    try:
        return (0, ipaddress.ip_address(ip))
    except ValueError:
        return (1, ip)


def summarize(snmp: dict) -> list[tuple[str, str]]:
    rows = []
    if not snmp:
        return rows
    rows.append(("SNMP", f"{sum(1 for a in snmp.get('agents', []) if a.get('ok'))} of "
                         f"{len(snmp.get('agents', []))} agent(s) answered · {snmp.get('credentials', '')}"))
    for a in snmp.get("agents", []):
        if a.get("ok"):
            ent = a.get("entity", {})
            extra = " · ".join(x for x in (ent.get("model"), ent.get("serial") and f"S/N {ent['serial']}",
                                           a.get("sysLocation")) if x)
            rows.append((f"SNMP {a['ip']}", " · ".join(x for x in (a.get("sysName"), a.get("sysDescr", "")[:80],
                                                                    extra) if x)))
            for n in a.get("lldp", [])[:16]:
                rows.append((f"  LLDP {a.get('sysName') or a['ip']} {n['local_port']}",
                             f"{n['remote_name'] or n['remote_chassis']} {n['remote_port_desc'] or n['remote_port']}"))
        else:
            rows.append((f"SNMP {a['ip']}", a.get("error", "no answer")))
    if snmp.get("mac_ports"):
        rows.append(("SNMP MAC → port", f"{len(snmp['mac_ports'])} MAC address(es) located on switch ports"))
    return rows


# ---------------------------------------------------------------- integration with a scan


def collect_targets(explicit: Iterable[str], network: dict, hosts: list, auto: bool, all_hosts: bool,
                    own_ip: str | None = None) -> list[str]:
    """S2: explicit targets, plus gateway and LLDP/CDP switch (auto), plus every host found (all_hosts)."""
    out = expand_targets(explicit)
    extra: list[str] = []
    if auto:
        gw = (network.get("gateway") or {}).get("ip")
        if gw:
            extra.append(gw)
        sw = network.get("switch") or {}
        extra += sw.get("management_addresses") or sw.get("addresses") or []
    if all_hosts:
        extra += [h.ip for h in hosts]
    for ip in extra:
        if ip and ip != own_ip and ip not in out and ":" not in ip:
            out.append(ip)
    if len(out) > MAX_TARGETS:
        raise ValueError(f"at most {MAX_TARGETS} SNMP targets ({len(out)})")
    return out


def apply(result: dict, hosts: list, devices: list) -> int:
    """S4: switch port on hosts and BACnet devices; agent names on their hosts. Returns hosts located."""
    mac_ports = result.get("mac_ports") or {}
    n = 0
    for h in hosts:
        p = mac_ports.get(h.mac)
        if p:
            h.switch_port = port_text(p)
            n += 1
    for d in devices:
        p = mac_ports.get(d.eth_mac or "")
        if p:
            d.switch_port = port_text(p) + (" (router)" if d.eth_mac_source == "router" else "")
    by_ip = {h.ip: h for h in hosts}
    for a in result.get("agents", []):
        h = by_ip.get(a["ip"])
        if h is None or not a.get("ok"):
            continue
        h.services["snmp"] = " · ".join(x for x in (a.get("sysName"), a.get("sysDescr", "")[:120],
                                                     a.get("sysLocation")) if x)
        if not h.hostname and a.get("sysName"):
            h.hostname = a["sysName"]
        if "snmp" not in h.layers:
            h.layers = sorted(set(h.layers) | {"snmp"})
        if not h.kind and a.get("fdb_entries"):
            h.kind = "switch"
    return n
