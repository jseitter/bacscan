"""Deep host discovery (spec E11): find and identify every host on the local subnet, layer by layer.

Opt-in and active. Everything sent is a query; nothing is configured or written:
  L2   ARP           - filled by the kernel while we probe (netinfo.sweep), read with `arp -an`
  L3   ICMP echo     - round-trip time and TTL (rough OS hint); unprivileged ICMP socket, no root
  L4   TCP connect   - a short list of building-automation and IT ports; connect, then close
  L7   HTTP(S)       - GET / for status, Server header, page title, auth realm, TLS certificate name
       banners       - first line sent by SSH / FTP / Telnet / SMTP servers
       mDNS / DNS-SD - Bonjour services and .local names (legacy unicast query)
       SSDP / UPnP   - M-SEARCH, then the device description (friendly name, maker, model)
       NetBIOS       - node status query (Windows / Samba name, workgroup)
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import select
import socket
import ssl
import struct
import time
import urllib.request
import warnings
from typing import Any, Callable
from xml.etree import ElementTree

from . import oui
from .models import Host
from .network import Interface

log = logging.getLogger("bacscan.discover")

MAX_HOSTS = 1022  # /22, same limit as the sweep

# port -> service name. Chosen for building networks: BMS / PLC protocols plus common IT services.
PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 102: "siemens-s7",
    135: "ms-rpc", 139: "netbios-ssn", 443: "https", 445: "smb", 502: "modbus", 554: "rtsp",
    631: "ipp", 1883: "mqtt", 1911: "niagara-fox", 2404: "iec-104", 3389: "rdp", 4840: "opc-ua",
    4911: "niagara-fox-tls", 5000: "http-alt", 5900: "vnc", 8000: "http-alt", 8080: "http-alt",
    8443: "https-alt", 8883: "mqtt-tls", 9100: "printer", 20000: "dnp3", 44818: "ethernet-ip",
    47808: "bacnet-tcp?",
}
HTTP_PORTS = {80, 5000, 8000, 8080}
TLS_PORTS = {443, 4911, 8443}
BANNER_PORTS = {21, 22, 23, 25}

MDNS_ADDR = ("224.0.0.251", 5353)
SSDP_ADDR = ("239.255.255.250", 1900)
USER_AGENT = "bacscan"

Emit = Callable[[str], None]


def parse_ports(spec: str | None) -> list[int]:
    """'80,443,8000-8010' -> sorted list; empty/None -> default list."""
    if not spec:
        return sorted(PORTS)
    out: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        a, b = int(lo), int(hi or lo)
        if not (0 < a <= b <= 65535):
            raise ValueError(f"bad port range: {part}")
        out.update(range(a, b + 1))
    if len(out) > 1024:
        raise ValueError("at most 1024 ports")
    return sorted(out)


def _printable(b: bytes | str, limit: int = 160) -> str:
    s = b.decode("utf-8", "replace") if isinstance(b, bytes) else b
    s = re.sub(r"[^\x20-\x7e -￿]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()[:limit]


# ---------------------------------------------------------------- ICMP


def _checksum(b: bytes) -> int:
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def echo_request(ident: int, seq: int, payload: bytes = b"bacscan") -> bytes:
    pkt = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    return pkt[:2] + struct.pack("!H", _checksum(pkt)) + pkt[4:]


def parse_echo_reply(data: bytes) -> tuple[int, int, int] | None:
    """(ttl, ident, seq) from an IPv4 packet carrying an ICMP echo reply."""
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    icmp = data[ihl:]
    if len(icmp) < 8 or icmp[0] != 0:
        return None
    _, _, _, ident, seq = struct.unpack("!BBHHH", icmp[:8])
    return data[8], ident, seq


def os_hint(ttl: int | None) -> str:
    """Initial TTL 64 / 128 / 255 gives a rough idea of the IP stack."""
    if ttl is None:
        return ""
    if ttl <= 64:
        return "Linux/Unix/macOS/embedded"
    if ttl <= 128:
        return "Windows"
    return "network device / RTOS"


def ping_sweep(ips: list[str], source_ip: str, wait: float = 1.5,
               should_stop: Callable[[], bool] = lambda: False) -> dict[str, dict]:
    """One echo request per address; returns {ip: {"rtt_ms", "ttl"}} for those that answered."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError as e:
        log.warning("ICMP socket not available: %s", e)
        return {}
    ident = os.getpid() & 0xFFFF
    sent: dict[int, tuple[str, float]] = {}
    found: dict[str, dict] = {}
    try:
        s.bind((source_ip, 0))
        s.setblocking(False)

        def drain(timeout: float) -> None:
            end = time.monotonic() + timeout
            while True:
                left = end - time.monotonic()
                if left <= 0 or not select.select([s], [], [], left)[0]:
                    return
                try:
                    data, (src, _) = s.recvfrom(2048)
                except BlockingIOError:
                    continue
                r = parse_echo_reply(data)
                if not r or r[2] not in sent:
                    continue
                ip, t0 = sent[r[2]]
                if src == ip and ip not in found:
                    found[ip] = {"rtt_ms": round((time.monotonic() - t0) * 1000, 2), "ttl": r[0]}

        for seq, ip in enumerate(ips, 1):
            if should_stop():
                break
            sent[seq & 0xFFFF] = (ip, time.monotonic())
            try:
                s.sendto(echo_request(ident, seq & 0xFFFF), (ip, 0))
            except OSError:
                pass
            if seq % 16 == 0:
                drain(0.02)  # ~800 packets/s max, and keep receiving
        drain(wait)
    finally:
        s.close()
    return found


# ---------------------------------------------------------------- DNS (for mDNS)


def _dns_name(data: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    end = None
    for _ in range(128):
        if off >= len(data):
            raise ValueError("truncated name")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            continue
        labels.append(data[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    else:
        raise ValueError("name loop")
    return ".".join(labels), end if end is not None else off


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("utf-8")
        out += bytes([len(b)]) + b
    return out + b"\0"


def dns_query(questions: list[tuple[str, int]], txid: int = 0) -> bytes:
    head = struct.pack("!HHHHHH", txid, 0, len(questions), 0, 0, 0)
    return head + b"".join(_encode_name(n) + struct.pack("!HH", t, 1) for n, t in questions)


def parse_dns(data: bytes) -> list[tuple[str, int, Any]]:
    """Answer/authority/additional records as (name, type, value) for A, PTR, SRV, TXT."""
    if len(data) < 12:
        return []
    qd, an, ns, ar = struct.unpack("!4H", data[4:12])
    off = 12
    recs: list[tuple[str, int, Any]] = []
    try:
        for _ in range(qd):
            _, off = _dns_name(data, off)
            off += 4
        for _ in range(an + ns + ar):
            name, off = _dns_name(data, off)
            typ, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            start, off = off, off + rdlen
            rd = data[start:off]
            if typ == 1 and rdlen == 4:
                recs.append((name, typ, socket.inet_ntoa(rd)))
            elif typ == 12:
                recs.append((name, typ, _dns_name(data, start)[0]))
            elif typ == 33 and rdlen >= 7:
                recs.append((name, typ, (_dns_name(data, start + 6)[0], struct.unpack("!H", rd[4:6])[0])))
            elif typ == 16:
                txt, i = [], 0
                while i < len(rd):
                    txt.append(rd[i + 1:i + 1 + rd[i]].decode("utf-8", "replace"))
                    i += 1 + rd[i]
                recs.append((name, typ, txt))
    except (ValueError, struct.error, IndexError):
        pass  # keep what was parsed
    return recs


def _udp_collect(sock: socket.socket, wait: float, should_stop: Callable[[], bool]) -> list[tuple[bytes, str]]:
    out = []
    end = time.monotonic() + wait
    while not should_stop():
        left = end - time.monotonic()
        if left <= 0 or not select.select([sock], [], [], min(left, 0.25))[0]:
            if left <= 0:
                break
            continue
        try:
            data, (src, _) = sock.recvfrom(9000)
        except OSError:
            continue
        out.append((data, src))
    return out


def _mcast_socket(source_ip: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((source_ip, 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(source_ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)  # never leaves the subnet
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    return s


def interpret_mdns(records: list[tuple[str, int, Any]], src_ips: dict[str, str] | None = None) -> dict[str, dict]:
    """Combine DNS-SD records into {ip: {"name": "host.local", "services": [...]}}."""
    a: dict[str, str] = {}
    srv: dict[str, tuple[str, int]] = {}
    ptr: list[tuple[str, str]] = []
    for name, typ, val in records:
        if typ == 1:
            a.setdefault(name.lower(), val)
        elif typ == 33:
            srv[name.lower()] = val
        elif typ == 12 and not name.startswith("_services."):
            ptr.append((name, val))
    out: dict[str, dict] = {}
    for target, ip in a.items():
        out.setdefault(ip, {"name": target, "services": []})
    for stype, instance in ptr:
        target = srv.get(instance.lower())
        ip = a.get(target[0].lower()) if target else None
        if ip is None and src_ips:
            ip = src_ips.get(instance.lower())
        if ip is None:
            continue
        entry = out.setdefault(ip, {"name": target[0] if target else "", "services": []})
        label = instance[:-len(stype) - 1] if instance.lower().endswith("." + stype.lower()) else instance
        stype_short = stype.removesuffix(".local")
        port = f":{target[1]}" if target else ""
        svc = f"{stype_short}{port} ({label})"
        if svc not in entry["services"]:
            entry["services"].append(svc)
    return out


def mdns_browse(source_ip: str, wait: float = 2.5, should_stop: Callable[[], bool] = lambda: False) -> dict[str, dict]:
    """Ask for all DNS-SD service types, then for all instances of each type."""
    try:
        s = _mcast_socket(source_ip)
    except OSError as e:
        log.warning("mDNS not available: %s", e)
        return {}
    records: list[tuple[str, int, Any]] = []
    src_ips: dict[str, str] = {}

    def take(replies: list[tuple[bytes, str]]) -> None:
        for data, src in replies:
            recs = parse_dns(data)
            records.extend(recs)
            for name, typ, val in recs:
                if typ == 12:
                    src_ips.setdefault(val.lower(), src)

    try:
        s.sendto(dns_query([("_services._dns-sd._udp.local", 12)]), MDNS_ADDR)
        take(_udp_collect(s, 1.2, should_stop))
        types = sorted({v for n, t, v in records if t == 12 and n.startswith("_services.")})
        for i in range(0, len(types), 12):
            s.sendto(dns_query([(t, 12) for t in types[i:i + 12]]), MDNS_ADDR)
        if types:
            take(_udp_collect(s, wait, should_stop))
        # SRV targets without an address record: ask for A
        known = {n.lower() for n, t, _ in records if t == 1}
        missing = sorted({v[0] for _, t, v in records if t == 33 and v[0].lower() not in known})
        for i in range(0, len(missing), 12):
            s.sendto(dns_query([(n, 1) for n in missing[i:i + 12]]), MDNS_ADDR)
        if missing:
            take(_udp_collect(s, 1.0, should_stop))
    except OSError as e:
        log.warning("mDNS query failed: %s", e)
    finally:
        s.close()
    return interpret_mdns(records, src_ips)


# ---------------------------------------------------------------- SSDP / UPnP


def parse_ssdp(data: bytes) -> dict[str, str]:
    lines = data.decode("utf-8", "replace").split("\r\n")
    if not lines or not lines[0].upper().startswith("HTTP/1.1 200"):
        return {}
    headers = {}
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        if sep:
            headers[k.strip().lower()] = v.strip()
    return headers


def parse_upnp_description(xml: bytes) -> dict[str, str]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return {}
    out = {}
    for el in root.iter():
        tag = el.tag.rsplit("}", 1)[-1]
        if tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "modelDescription",
                   "serialNumber", "presentationURL") and el.text and tag not in out:
            out[tag] = el.text.strip()
    return out


def ssdp_search(source_ip: str, net: ipaddress.IPv4Network, wait: float = 3.0,
                should_stop: Callable[[], bool] = lambda: False) -> dict[str, dict]:
    """{ip: {"server", "location", "types", friendlyName, manufacturer, modelName, ...}}."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\nUSER-AGENT: bacscan\r\n\r\n").encode()
    try:
        s = _mcast_socket(source_ip)
    except OSError as e:
        log.warning("SSDP not available: %s", e)
        return {}
    out: dict[str, dict] = {}
    try:
        s.sendto(msg, SSDP_ADDR)
        time.sleep(0.1)
        s.sendto(msg, SSDP_ADDR)  # UDP may drop one
        for data, src in _udp_collect(s, wait, should_stop):
            h = parse_ssdp(data)
            if not h:
                continue
            e = out.setdefault(src, {"types": []})
            for k in ("server", "location"):
                if h.get(k) and k not in e:
                    e[k] = h[k]
            st = h.get("st", "")
            if st and st not in e["types"] and len(e["types"]) < 12:
                e["types"].append(st)
    except OSError as ex:
        log.warning("SSDP search failed: %s", ex)
    finally:
        s.close()
    # device description: only from the host that answered, only on the local subnet
    for ip, e in out.items():
        loc = e.get("location", "")
        m = re.match(r"https?://([^/:]+)", loc)
        if should_stop() or not m or m.group(1) != ip or ipaddress.ip_address(ip) not in net:
            continue
        try:
            req = urllib.request.Request(loc, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=3) as r:
                e.update(parse_upnp_description(r.read(65536)))
        except Exception as ex:  # noqa: BLE001 - description is optional
            log.debug("UPnP description %s: %s", loc, ex)
    return out


# ---------------------------------------------------------------- NetBIOS


def nbstat_query(txid: int) -> bytes:
    name = b"*" + b"\0" * 15
    encoded = bytes(c for b in name for c in (0x41 + (b >> 4), 0x41 + (b & 0x0F)))
    return struct.pack("!HHHHHH", txid, 0, 1, 0, 0, 0) + b"\x20" + encoded + b"\0" + struct.pack("!HH", 0x21, 1)


def parse_nbstat(data: bytes) -> dict | None:
    """Node status response -> {"name", "group", "mac", "names"}."""
    try:
        if len(data) < 12 or struct.unpack("!H", data[6:8])[0] < 1:
            return None
        _, off = _dns_name(data, 12)
        typ = struct.unpack("!H", data[off:off + 2])[0]
        if typ != 0x21:
            return None
        off += 10
        count = data[off]
        off += 1
        names = []
        for _ in range(count):
            raw, suffix, flags = data[off:off + 15], data[off + 15], struct.unpack("!H", data[off + 16:off + 18])[0]
            names.append((raw.decode("ascii", "replace").strip(), suffix, bool(flags & 0x8000)))
            off += 18
        mac = data[off:off + 6]
    except (IndexError, struct.error, ValueError):
        return None
    unique = [n for n, sfx, group in names if sfx == 0x00 and not group]
    groups = [n for n, sfx, group in names if sfx == 0x00 and group]
    mac_s = ":".join(f"{b:02x}" for b in mac) if len(mac) == 6 and any(mac) else ""
    return {"name": unique[0] if unique else (names[0][0] if names else ""),
            "group": groups[0] if groups else "", "mac": mac_s,
            "names": sorted({n for n, _, _ in names})}


def netbios_sweep(ips: list[str], source_ip: str, wait: float = 1.5,
                  should_stop: Callable[[], bool] = lambda: False) -> dict[str, dict]:
    if not ips:
        return {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out: dict[str, dict] = {}
    try:
        s.bind((source_ip, 0))
        for i, ip in enumerate(ips):
            if should_stop():
                break
            try:
                s.sendto(nbstat_query(0x4200 + i), (ip, 137))
            except OSError:
                pass
            if i % 16 == 15:
                time.sleep(0.02)
        for data, src in _udp_collect(s, wait, should_stop):
            r = parse_nbstat(data)
            if r:
                out[src] = r
    finally:
        s.close()
    return out


# ---------------------------------------------------------------- TCP / HTTP / TLS


def parse_http(data: bytes) -> dict[str, str]:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", "replace").split("\r\n")
    out: dict[str, str] = {}
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})\s*(.*)", lines[0] if lines else "")
    if not m:
        return out
    out["status"] = f"{m.group(1)} {m.group(2)}".strip()
    for line in lines[1:]:
        k, sep, v = line.partition(":")
        k = k.strip().lower()
        if not sep:
            continue
        if k == "server":
            out["server"] = _printable(v)
        elif k == "location":
            out["location"] = _printable(v)
        elif k == "www-authenticate":
            r = re.search(r'realm="([^"]*)"', v, re.I)
            out["realm"] = _printable(r.group(1) if r else v)
    t = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if t:
        out["title"] = _printable(t.group(1).decode("utf-8", "replace"), 120)
    return out


def cert_names(der: bytes) -> tuple[str, str]:
    """(subject CN, issuer CN) from a DER certificate without a full ASN.1 parser.

    The CN attribute (OID 2.5.4.3) appears first in the issuer and last in the subject.
    """
    found = []
    for m in re.finditer(re.escape(b"\x06\x03\x55\x04\x03"), der):
        i = m.end()
        if i + 2 <= len(der) and der[i] in (0x0C, 0x13, 0x14, 0x16, 0x1E):
            n = der[i + 1]
            if n < 0x80:
                found.append(_printable(der[i + 2:i + 2 + n]))
    if not found:
        return "", ""
    return found[-1], found[0]


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only read the name; old controllers have self-signed certs
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ssl.TLSVersion.TLSv1  # old controllers still speak TLS 1.0
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


async def _read_some(reader: asyncio.StreamReader, limit: int, timeout: float) -> bytes:
    buf = b""
    end = time.monotonic() + timeout
    while len(buf) < limit:
        left = end - time.monotonic()
        if left <= 0:
            break
        try:
            chunk = await asyncio.wait_for(reader.read(limit - len(buf)), left)
        except (asyncio.TimeoutError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        pass


async def _http_get(ip: str, port: int, tls: bool, timeout: float) -> dict[str, str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=_tls_context() if tls else None), timeout + 2)
    except (OSError, asyncio.TimeoutError, ssl.SSLError, ValueError) as e:
        return {"error": type(e).__name__} if tls else {}
    info: dict[str, str] = {}
    try:
        if tls:
            obj = writer.get_extra_info("ssl_object")
            der = obj.getpeercert(binary_form=True) if obj else None
            if der:
                subj, issuer = cert_names(der)
                if subj:
                    info["cert"] = subj + (" (self-signed)" if subj == issuer else f" (issuer {issuer})" if issuer else "")
        host = ip if port in (80, 443) else f"{ip}:{port}"
        writer.write(f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        info.update(parse_http(await _read_some(reader, 32768, timeout)))
    except (OSError, ssl.SSLError):
        pass
    finally:
        await _close(writer)
    return info


def describe_service(port: int, info: dict[str, str]) -> str:
    parts = []
    for k in ("banner", "status", "server", "title", "realm", "cert", "location"):
        v = info.get(k)
        if v:
            parts.append(v if k in ("banner", "status") else f"{k} {v}")
    return " · ".join(parts)


async def probe_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    """None if closed/filtered, else {"port", "service", "detail"}."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except (OSError, asyncio.TimeoutError):
        return None
    info: dict[str, str] = {}
    try:
        if port in BANNER_PORTS:
            info["banner"] = _printable(await _read_some(reader, 256, 2.0))
    finally:
        await _close(writer)
    if port in HTTP_PORTS or port in TLS_PORTS:
        info.update(await _http_get(ip, port, port in TLS_PORTS, 3.0))
        info.pop("error", None)
    return {"port": port, "service": PORTS.get(port, ""), "detail": describe_service(port, info)}


async def port_scan(ips: list[str], ports: list[int], concurrency: int = 64, timeout: float = 1.0,
                    should_stop: Callable[[], bool] = lambda: False,
                    progress: Callable[[int, int], None] | None = None) -> dict[str, list[dict]]:
    sem = asyncio.Semaphore(concurrency)
    results: dict[str, list[dict]] = {}
    done = 0
    total = len(ips) * len(ports)

    async def one(ip: str, port: int) -> None:
        nonlocal done
        async with sem:
            if should_stop():
                return
            r = await probe_port(ip, port, timeout)
        done += 1
        if r:
            results.setdefault(ip, []).append(r)
        if progress and done % 200 == 0:
            progress(done, total)

    await asyncio.gather(*(one(ip, p) for ip in ips for p in ports))
    for v in results.values():
        v.sort(key=lambda r: r["port"])
    return results


# ---------------------------------------------------------------- classification


def guess_kind(h: Host) -> str:
    ports = set(h.ports)
    text = " ".join(list(h.services.values()) + [h.vendor, h.hostname]).lower()
    rules = [
        (bool(ports & {1911, 4911}) or "niagara" in text, "Niagara station (Tridium)"),
        (102 in ports, "Siemens S7 PLC"),
        (44818 in ports, "EtherNet/IP device (PLC)"),
        (20000 in ports, "DNP3 device"),
        (2404 in ports, "IEC 60870-5-104 device"),
        (4840 in ports, "OPC UA server"),
        (502 in ports, "Modbus TCP device"),
        (h.bacnet_instance is not None, "BACnet device"),
        (bool(ports & {9100, 631}) or "_ipp." in text or "printer" in text, "printer"),
        (554 in ports or "camera" in text or "_rtsp." in text, "camera / video"),
        (3389 in ports or (135 in ports and 445 in ports), "Windows computer"),
        ("_airplay." in text or "_companion-link." in text or "apple" in h.vendor.lower(), "Apple device"),
        (1883 in ports or 8883 in ports, "MQTT broker"),
        (h.note == "gateway", "router / gateway"),
    ]
    for cond, kind in rules:
        if cond:
            return kind
    return ""


# ---------------------------------------------------------------- orchestration


def subnet_ips(iface: Interface) -> list[str]:
    net = iface.network
    if net.num_addresses - 2 > MAX_HOSTS:
        raise ValueError(f"subnet {net} too large for deep discovery (max /22)")
    return [str(h) for h in net.hosts() if str(h) != iface.ip]


async def deep_scan(iface: Interface, ports: list[int] | None = None, emit: Emit = lambda m: None,
                    should_stop: Callable[[], bool] = lambda: False, alive_hint: set[str] | None = None,
                    tcp: bool = True) -> dict[str, dict]:
    """Run all layers; returns {ip: {"icmp": {...}, "mdns": {...}, "ssdp": {...}, "netbios": {...},
    "ports": [...]}}. `alive_hint` adds hosts already known (e.g. ARP table)."""
    from . import netinfo

    ports = ports if ports is not None else sorted(PORTS)
    ips = subnet_ips(iface)
    emit(f"deep discovery: ICMP ping, mDNS and SSDP on {iface.network}")
    icmp_t = asyncio.to_thread(ping_sweep, ips, iface.ip, 1.5, should_stop)
    mdns_t = asyncio.to_thread(mdns_browse, iface.ip, 2.5, should_stop)
    ssdp_t = asyncio.to_thread(ssdp_search, iface.ip, iface.network, 3.0, should_stop)
    icmp, mdns, ssdp = await asyncio.gather(icmp_t, mdns_t, ssdp_t)
    emit(f"deep discovery: {len(icmp)} ping repl{'y' if len(icmp) == 1 else 'ies'}, "
         f"{len(mdns)} mDNS host(s), {len(ssdp)} UPnP device(s)")

    arp = {ip for ip, _, ifn in netinfo.parse_arp(netinfo.run(["arp", "-an"])) if ifn == iface.name}
    net = iface.network
    alive = {ip for ip in set(icmp) | set(mdns) | set(ssdp) | arp | (alive_hint or set())
             if ip != iface.ip and _in(ip, net)}
    alive_sorted = sorted(alive, key=ipaddress.ip_address)

    result: dict[str, dict] = {ip: {} for ip in alive_sorted}
    for ip, v in icmp.items():
        result.setdefault(ip, {})["icmp"] = v
    for ip, v in mdns.items():
        if ip in result:
            result[ip]["mdns"] = v
    for ip, v in ssdp.items():
        if ip in result:
            result[ip]["ssdp"] = v
    if should_stop():
        return result

    nb = await asyncio.to_thread(netbios_sweep, alive_sorted, iface.ip, 1.5, should_stop)
    for ip, v in nb.items():
        if ip in result:
            result[ip]["netbios"] = v
    if nb:
        emit(f"deep discovery: {len(nb)} NetBIOS name(s)")

    if tcp and ports and alive_sorted and not should_stop():
        emit(f"deep discovery: checking {len(ports)} TCP port(s) on {len(alive_sorted)} host(s)")
        open_ports = await port_scan(
            alive_sorted, ports, should_stop=should_stop,
            progress=lambda d, t: emit(f"deep discovery: {d}/{t} port checks"))
        for ip, v in open_ports.items():
            result[ip]["ports"] = v
        emit(f"deep discovery: {sum(len(v) for v in open_ports.values())} open port(s) "
             f"on {len(open_ports)} host(s)")
    return result


def _in(ip: str, net: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(ip) in net and ip != str(net.broadcast_address)
    except ValueError:
        return False


def merge(hosts: list[Host], result: dict[str, dict]) -> list[Host]:
    """Fill Host fields from deep_scan() results; adds hosts that were not in the ARP table."""
    by_ip = {h.ip: h for h in hosts}
    for ip, r in result.items():
        h = by_ip.get(ip)
        if h is None:
            h = by_ip[ip] = Host(ip=ip, source="deep")
        layers = set(h.layers)
        if h.mac:
            layers.add("arp")
        if "icmp" in r:
            h.rtt_ms, h.ttl = r["icmp"]["rtt_ms"], r["icmp"]["ttl"]
            h.os_hint = os_hint(h.ttl)
            layers.add("icmp")
        if "mdns" in r:
            m = r["mdns"]
            layers.add("mdns")
            if m.get("name"):
                h.services["mdns name"] = m["name"]
            if m.get("services"):
                h.services["mdns"] = ", ".join(m["services"])
            if not h.hostname and m.get("name"):
                h.hostname = m["name"]
        if "ssdp" in r:
            s = r["ssdp"]
            layers.add("ssdp")
            desc = " ".join(x for x in (s.get("manufacturer"), s.get("modelName"), s.get("modelNumber")) if x)
            h.services["upnp"] = " · ".join(x for x in (s.get("friendlyName"), desc, s.get("server")) if x)
            if not h.hostname and s.get("friendlyName"):
                h.hostname = s["friendlyName"]
        if "netbios" in r:
            n = r["netbios"]
            layers.add("netbios")
            h.services["netbios"] = n["name"] + (f" (workgroup {n['group']})" if n.get("group") else "")
            if not h.hostname and n.get("name"):
                h.hostname = n["name"]
            if not h.mac and n.get("mac"):
                h.mac = oui.normalize_mac(n["mac"]) or ""
                h.vendor = oui.vendor(h.mac)
        if "ports" in r:
            layers.add("tcp")
            h.ports = [p["port"] for p in r["ports"]]
            for p in r["ports"]:
                h.services[f"{p['port']}/tcp {p['service']}".strip()] = p["detail"]
        if h.bacnet_instance is not None:
            layers.add("bacnet")
        h.layers = sorted(layers)
        h.kind = guess_kind(h)
    for h in by_ip.values():
        if not h.kind:
            h.kind = guess_kind(h)
    return sorted(by_ip.values(), key=lambda h: ipaddress.ip_address(h.ip))
