"""Network environment survey (spec §4.7): link, DHCP, DNS, gateway, internet, ARP hosts.

macOS-first: uses ifconfig, ipconfig, scutil, route, arp, ping, networksetup. Every
probe is optional and failures are recorded, never raised. Only harmless traffic is sent:
DNS lookups, one ping burst to the gateway, an HTTP + HTTPS request to Apple's captive
portal check, and - opt-in - a public IP lookup and a UDP "sweep" that fills the ARP table.
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import logging
import re
import socket
import subprocess
import time
import urllib.request
from typing import Any, Callable

from . import oui
from .models import Host, now_iso
from .network import Interface

log = logging.getLogger("bacscan.netinfo")

VPN_PREFIXES = ("utun", "ipsec", "ppp", "tun", "tap", "wg")
CAPTIVE_URL = "http://captive.apple.com/hotspot-detect.html"
HTTPS_URL = "https://www.apple.com/"
DNS_TEST_NAME = "www.apple.com"
PUBLIC_IP_URL = "https://api.ipify.org"
MAX_SWEEP_HOSTS = 1022  # /22
MAX_REVERSE_LOOKUPS = 512


# ---------------------------------------------------------------- command runner


def run(cmd: list[str], timeout: float = 5.0) -> str:
    """Run a command, return stdout ('' on any failure)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (OSError, subprocess.SubprocessError) as e:
        log.debug("%s failed: %s", cmd, e)
        return ""


# ---------------------------------------------------------------- parsers (pure, unit-tested)


def parse_ifconfig(text: str) -> dict:
    out: dict[str, Any] = {"ipv6": []}
    m = re.search(r"\bmtu (\d+)", text)
    if m:
        out["mtu"] = int(m.group(1))
    m = re.search(r"^\s*ether ([0-9a-f:]+)", text, re.M)
    if m:
        out["mac"] = oui.normalize_mac(m.group(1))
    m = re.search(r"^\s*media: (.+)$", text, re.M)
    if m:
        out["media"] = m.group(1).strip()
    m = re.search(r"^\s*status: (\w+)", text, re.M)
    if m:
        out["status"] = m.group(1)
    for m in re.finditer(r"^\s*inet6 ([0-9a-f:]+)(?:%\S+)? prefixlen (\d+)", text, re.M):
        out["ipv6"].append(f"{m.group(1)}/{m.group(2)}")
    return out


def parse_getpacket(text: str) -> dict:
    """`ipconfig getpacket IF` -> DHCP fields. Empty dict when no DHCP lease."""
    if "options:" not in text:
        return {}
    opts: dict[str, str] = {}
    for m in re.finditer(r"^(\w+) \(([\w_]+)\): (.*)$", text, re.M):
        name, _typ, value = m.groups()
        if name != "end":
            opts[name] = value.strip()

    def ips(v: str | None) -> list[str]:
        return re.findall(r"\d+\.\d+\.\d+\.\d+", v or "")

    d: dict[str, Any] = {"used": True, "options": opts}
    m = re.search(r"^yiaddr = (\S+)", text, re.M)
    if m:
        d["address"] = m.group(1)
    d["server"] = (ips(opts.get("server_identifier")) or [None])[0]
    d["routers"] = ips(opts.get("router"))
    d["dns_servers"] = ips(opts.get("domain_name_server"))
    d["ntp_servers"] = ips(opts.get("ntp_servers") or opts.get("network_time_protocol_servers"))
    d["domain"] = opts.get("domain_name", "")
    d["subnet_mask"] = (ips(opts.get("subnet_mask")) or [None])[0]
    if opts.get("captive_portal_url"):
        d["captive_portal_url"] = opts["captive_portal_url"]
    lease = opts.get("lease_time")
    if lease:
        try:
            d["lease_seconds"] = int(lease, 16) if lease.startswith("0x") else int(lease)
        except ValueError:
            pass
    return d


def parse_getsummary(text: str) -> dict:
    d: dict[str, Any] = {}
    for key, name in (("ConfigMethod", "config_method"), ("LeaseStartTime", "lease_start"),
                      ("LeaseExpirationTime", "lease_expires"), ("SSID", "ssid"),
                      ("InterfaceType", "interface_type")):
        m = re.search(rf"^\s*{key} : (.+)$", text, re.M)
        if m:
            d[name] = m.group(1).strip()
    if d.get("ssid") == "<redacted>":
        d["ssid"] = "(hidden by macOS - grant location access to show)"
    return d


def parse_scutil_dns(text: str) -> list[dict]:
    """`scutil --dns` -> resolvers with nameservers (mDNS-only resolvers dropped)."""
    resolvers = []
    seen = set()
    section = text.split("DNS configuration (for scoped queries)")[0]
    for block in re.split(r"\n(?=resolver #\d+)", section):
        ns = re.findall(r"nameserver\[\d+\] : (\S+)", block)
        if not ns:
            continue
        r = {
            "nameservers": ns,
            "search": re.findall(r"search domain\[\d+\] : (\S+)", block),
            "domain": (re.findall(r"^\s*domain\s+: (\S+)", block, re.M) or [""])[0],
            "interface": (re.findall(r"if_index : \d+ \((\S+)\)", block) or [""])[0],
        }
        key = (tuple(r["nameservers"]), r["domain"], r["interface"])
        if key not in seen:
            seen.add(key)
            resolvers.append(r)
    return resolvers


def parse_route_get(text: str) -> dict:
    d = {}
    for key in ("gateway", "interface"):
        m = re.search(rf"^\s*{key}: (\S+)", text, re.M)
        if m:
            d[key] = m.group(1)
    return d


def parse_arp(text: str) -> list[tuple[str, str, str]]:
    """`arp -an` -> [(ip, mac, interface)] without incomplete entries / broadcast."""
    out = []
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at (\S+) on (\S+)", text):
        ip, mac, iface = m.groups()
        mac = oui.normalize_mac(mac)
        if not mac or mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac.startswith("01:00:5e"):
            continue
        out.append((ip, mac, iface))
    return out


def parse_hardware_ports(text: str) -> dict[str, dict]:
    """`networksetup -listallhardwareports` -> {device: {port, mac}}."""
    out = {}
    for block in text.split("\n\n"):
        port = re.search(r"Hardware Port: (.+)", block)
        dev = re.search(r"Device: (\S+)", block)
        mac = re.search(r"Ethernet Address: (\S+)", block)
        if port and dev:
            out[dev.group(1)] = {"port": port.group(1).strip(),
                                 "mac": oui.normalize_mac(mac.group(1)) if mac else None}
    return out


def parse_ping(text: str) -> dict:
    d: dict[str, Any] = {}
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text)
    if m:
        d["sent"], d["received"] = int(m.group(1)), int(m.group(2))
    m = re.search(r"= [\d.]+/([\d.]+)/", text)
    if m:
        d["rtt_ms"] = float(m.group(1))
    return d


# ---------------------------------------------------------------- probes


def _timed(fn: Callable[[], Any], timeout: float) -> tuple[Any, float, str | None]:
    """Run fn in a worker thread with a hard timeout. Returns (result, ms, error)."""
    ex = cf.ThreadPoolExecutor(max_workers=1)
    t0 = time.monotonic()
    fut = ex.submit(fn)
    try:
        res = fut.result(timeout=timeout)
        return res, round((time.monotonic() - t0) * 1000, 1), None
    except cf.TimeoutError:
        return None, round((time.monotonic() - t0) * 1000, 1), "timeout"
    except Exception as e:
        return None, round((time.monotonic() - t0) * 1000, 1), f"{type(e).__name__}: {e}"
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


def _http(url: str, method: str = "GET", timeout: float = 5.0) -> tuple[int, str]:
    req = urllib.request.Request(url, method=method, headers={"User-Agent": "bacscan"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed URLs)
        body = r.read(4096).decode("utf-8", "replace") if method == "GET" else ""
        return r.status, body


def reverse_lookup(ips: list[str], timeout: float = 4.0) -> dict[str, str]:
    """Parallel reverse DNS with an overall time budget."""
    result: dict[str, str] = {}
    ips = ips[:MAX_REVERSE_LOOKUPS]
    if not ips:
        return result
    ex = cf.ThreadPoolExecutor(max_workers=32)
    futs = {ex.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    try:
        for f in cf.as_completed(futs, timeout=timeout):
            try:
                result[futs[f]] = f.result()[0]
            except OSError:
                pass
    except cf.TimeoutError:
        pass
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return result


def survey_link(iface: Interface) -> dict:
    d: dict[str, Any] = {"name": iface.name, "ip": iface.ip, "prefix": iface.prefix,
                         "netmask": iface.netmask, "broadcast": iface.broadcast,
                         "network": str(iface.network)}
    d.update(parse_ifconfig(run(["ifconfig", iface.name])))
    hw = parse_hardware_ports(run(["networksetup", "-listallhardwareports"])).get(iface.name, {})
    if hw:
        d["hardware_port"] = hw.get("port")
        if hw.get("mac") and hw["mac"] != d.get("mac"):
            d["hardware_mac"] = hw["mac"]
    if d.get("mac"):
        d["mac_randomized"] = oui.is_locally_administered(d["mac"])
    summary = parse_getsummary(run(["ipconfig", "getsummary", iface.name]))
    d["config_method"] = summary.get("config_method", "")
    d["wifi"] = summary.get("interface_type", "").lower() == "wifi" or "wi-fi" in (d.get("hardware_port") or "").lower()
    if d["wifi"] and "ssid" in summary:
        d["ssid"] = summary["ssid"]
    d["_lease"] = {k: summary[k] for k in ("lease_start", "lease_expires") if k in summary}
    return d


def survey_dhcp(iface: Interface, lease: dict) -> dict:
    d = parse_getpacket(run(["ipconfig", "getpacket", iface.name]))
    if not d:
        return {"used": False}
    d.update(lease)
    return d


def survey_gateway(iface: Interface, dhcp: dict) -> dict:
    gw = (dhcp.get("routers") or [None])[0]
    if not gw:
        gw = parse_route_get(run(["route", "-n", "get", "-ifscope", iface.name, "default"])).get("gateway")
    if not gw or not re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
        return {"ip": None}
    d: dict[str, Any] = {"ip": gw}
    ping = parse_ping(run(["ping", "-c", "3", "-i", "0.2", "-t", "3", gw], timeout=6))
    d["reachable"] = ping.get("received", 0) > 0
    if "rtt_ms" in ping:
        d["rtt_ms"] = ping["rtt_ms"]
    arp = parse_arp(run(["arp", "-n", gw]))
    if arp:
        d["mac"] = arp[0][1]
        d["vendor"] = oui.vendor(arp[0][1])
    name = reverse_lookup([gw], timeout=3).get(gw)
    if name:
        d["hostname"] = name
    return d


def survey_dns(dhcp: dict) -> dict:
    d: dict[str, Any] = {"resolvers": parse_scutil_dns(run(["scutil", "--dns"]))}
    if dhcp.get("dns_servers"):
        d["dhcp_dns_servers"] = dhcp["dns_servers"]
    res, ms, err = _timed(lambda: sorted({a[4][0] for a in socket.getaddrinfo(DNS_TEST_NAME, 443)}), 6)
    d["lookup"] = {"name": DNS_TEST_NAME, "ok": err is None and bool(res), "ms": ms,
                   "addresses": res or [], "error": err}
    return d


def survey_internet(iface: Interface, dns_ok: bool, public_ip: bool) -> dict:
    route = parse_route_get(run(["route", "-n", "get", "1.1.1.1"]))
    d: dict[str, Any] = {"route_interface": route.get("interface", ""), "route_gateway": route.get("gateway", "")}
    d["via_vpn"] = d["route_interface"].startswith(VPN_PREFIXES)
    d["via_scan_interface"] = d["route_interface"] == iface.name
    res, ms, err = _timed(lambda: _http(CAPTIVE_URL), 7)
    d["http"] = {"url": CAPTIVE_URL, "ok": err is None, "ms": ms, "error": err}
    captive = err is None and "Success" not in (res[1] if res else "")
    res2, ms2, err2 = _timed(lambda: _http(HTTPS_URL, "HEAD"), 7)
    d["https"] = {"url": HTTPS_URL, "ok": err2 is None, "ms": ms2, "error": err2}
    if captive:
        d["status"] = "captive-portal"
    elif d["https"]["ok"] or d["http"]["ok"]:
        d["status"] = "full"
    elif dns_ok:
        d["status"] = "dns-only"
    else:
        d["status"] = "none"
    if public_ip and d["status"] == "full":
        res3, _ms3, err3 = _timed(lambda: _http(PUBLIC_IP_URL), 7)
        d["public_ip"] = res3[1].strip() if res3 and not err3 else None
        if err3:
            d["public_ip_error"] = err3
    return d


def survey_environment(iface: Interface, internet: bool = True, public_ip: bool = False) -> dict:
    """E1-E6. Never raises; problems end up as 'error' entries."""
    info: dict[str, Any] = {"collected_at": now_iso()}
    try:
        link = survey_link(iface)
        lease = link.pop("_lease", {})
        info["interface"] = link
        info["dhcp"] = survey_dhcp(iface, lease)
        info["gateway"] = survey_gateway(iface, info["dhcp"])
        info["dns"] = survey_dns(info["dhcp"])
        if internet:
            info["internet"] = survey_internet(iface, info["dns"]["lookup"]["ok"], public_ip)
    except Exception as e:  # pragma: no cover - defensive
        log.exception("network survey failed")
        info["error"] = f"{type(e).__name__}: {e}"
    return info


def sweep(iface: Interface, should_stop: Callable[[], bool] = lambda: False) -> int:
    """Fill the ARP table by sending one tiny UDP datagram (port 9, discard) to every host.

    Limited to subnets of /22 or smaller. Returns the number of addresses probed.
    """
    net = iface.network
    if net.num_addresses - 2 > MAX_SWEEP_HOSTS:
        raise ValueError(f"subnet {net} too large for a sweep (max /22)")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    n = 0
    try:
        s.bind((iface.ip, 0))
        for i, host in enumerate(net.hosts()):
            if should_stop():
                break
            if str(host) == iface.ip:
                continue
            try:
                s.sendto(b"\0", (str(host), 9))
                n += 1
            except OSError:
                pass
            if i % 16 == 15:
                time.sleep(0.02)  # ~800 packets/s max
    finally:
        s.close()
    time.sleep(2.0)  # let ARP replies arrive
    return n


def collect_hosts(iface: Interface, bacnet: dict[str, int] | None = None, gateway: str | None = None,
                  swept: bool = False, resolve_names: bool = True) -> list[Host]:
    """E8: ARP neighbours on the scan interface, tagged with BACnet instances."""
    bacnet = bacnet or {}
    net = iface.network
    hosts: dict[str, Host] = {}
    for ip, mac, ifname in parse_arp(run(["arp", "-an"])):
        if ifname != iface.name:
            continue
        try:
            if ipaddress.ip_address(ip) not in net or ip == str(net.broadcast_address):
                continue
        except ValueError:
            continue
        hosts[ip] = Host(ip=ip, mac=mac, vendor=oui.vendor(mac), source="sweep" if swept else "arp")
    own_mac = parse_ifconfig(run(["ifconfig", iface.name])).get("mac") or ""
    hosts.setdefault(iface.ip, Host(ip=iface.ip, mac=own_mac, vendor=oui.vendor(own_mac), source="local"))
    hosts[iface.ip].note = "this Mac"
    hosts[iface.ip].source = "local"
    if gateway and gateway in hosts:
        hosts[gateway].note = "gateway"
    for ip, inst in bacnet.items():
        if ip in hosts:
            hosts[ip].bacnet_instance = inst
    if resolve_names:
        for ip, name in reverse_lookup([h for h in hosts if h != iface.ip]).items():
            hosts[ip].hostname = name
    return sorted(hosts.values(), key=lambda h: ipaddress.ip_address(h.ip))


def summarize(info: dict) -> list[tuple[str, str]]:
    """Flatten a survey dict into readable (label, value) rows for CLI / GUI."""
    rows: list[tuple[str, str]] = []
    i, dh, gw, dns, inet = (info.get(k, {}) for k in ("interface", "dhcp", "gateway", "dns", "internet"))

    def add(label: str, value: Any) -> None:
        if value not in (None, "", [], {}):
            rows.append((label, ", ".join(map(str, value)) if isinstance(value, list) else str(value)))

    add("Interface", f"{i.get('name', '')} ({i.get('hardware_port', '')})".replace(" ()", ""))
    add("IPv4", f"{i.get('ip')}/{i.get('prefix')}" if i.get("ip") else None)
    add("Network", i.get("network"))
    mac = i.get("mac")
    if mac:
        add("MAC", mac + (" (randomized/private)" if i.get("mac_randomized") else ""))
    add("Hardware MAC", i.get("hardware_mac"))
    add("IPv6", i.get("ipv6"))
    add("Media", i.get("media"))
    add("MTU", i.get("mtu"))
    add("Wi-Fi SSID", i.get("ssid"))
    add("Address config", i.get("config_method"))
    if dh.get("used"):
        add("DHCP server", dh.get("server"))
        add("DHCP lease", f"{dh['lease_seconds'] // 3600} h" if dh.get("lease_seconds") else None)
        add("DHCP lease expires", dh.get("lease_expires"))
        add("DHCP routers", dh.get("routers"))
        add("DHCP DNS", dh.get("dns_servers"))
        add("DHCP domain", dh.get("domain"))
        add("DHCP NTP", dh.get("ntp_servers"))
        add("DHCP captive portal", dh.get("captive_portal_url"))
    elif dh:
        add("DHCP", "not used (static address)")
    if gw.get("ip"):
        state = "reachable" if gw.get("reachable") else "no ping reply"
        rtt = f", {gw['rtt_ms']:.1f} ms" if gw.get("rtt_ms") is not None else ""
        add("Gateway", f"{gw['ip']} ({state}{rtt})")
        add("Gateway MAC", f"{gw.get('mac')} {gw.get('vendor', '')}".strip() if gw.get("mac") else None)
        add("Gateway name", gw.get("hostname"))
    else:
        add("Gateway", "none")
    for n, r in enumerate(dns.get("resolvers", []), 1):
        extra = f" [{r['interface']}]" if r.get("interface") else ""
        scope = f" for {r['domain']}" if r.get("domain") else ""
        add(f"DNS resolver {n}", ", ".join(r["nameservers"]) + scope + extra)
        add(f"DNS search {n}", r.get("search"))
    lk = dns.get("lookup")
    if lk:
        add("DNS test", f"{lk['name']}: " + (f"ok, {lk['ms']:.0f} ms" if lk["ok"] else f"failed ({lk.get('error')})"))
    if inet:
        add("Internet", inet.get("status"))
        via = inet.get("route_interface", "")
        note = " (VPN!)" if inet.get("via_vpn") else ("" if inet.get("via_scan_interface") else " (not the scan interface)")
        gw_txt = f" via {inet['route_gateway']}" if inet.get("route_gateway") else ""
        add("Internet route", f"{via}{gw_txt}{note}" if via else None)
        for k in ("http", "https"):
            t = inet.get(k)
            if t:
                add(f"Internet {k.upper()}", f"ok, {t['ms']:.0f} ms" if t["ok"] else f"failed ({t.get('error')})")
        add("Public IP", inet.get("public_ip"))
    dd = info.get("deep_discovery")
    if dd:
        add("Deep discovery", f"{dd.get('hosts', 0)} host(s) answered; TCP ports checked: "
                              f"{len(dd.get('ports') or [])}")
    if info.get("switch"):
        from .lldp import summarize as summarize_switch
        rows.extend(summarize_switch(info["switch"]))
    if info.get("snmp"):
        from .snmp import summarize as summarize_snmp
        rows.extend(summarize_snmp(info["snmp"]))
    add("Collected", info.get("collected_at"))
    if info.get("error"):
        add("Survey error", info["error"])
    return rows
