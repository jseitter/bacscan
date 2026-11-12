"""Rule-based observations for the site report (spec R4).

Hints from what the scan saw - not a security audit. Severity: critical / warning / info.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Host, Scan

SEVERITIES = ("critical", "warning", "info")
DUPLICATE_PREFIX = "duplicate device instance, also answered from"


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    items: list[str] = field(default_factory=list)


def _host_label(h: Host) -> str:
    name = h.hostname or h.kind or h.vendor
    return f"{h.ip} ({name})" if name else h.ip


# port -> (severity, title, explanation)
CLEARTEXT = {
    23: ("critical", "Telnet open", "Telnet sends logins and commands unencrypted. Use SSH or switch it off."),
    21: ("warning", "FTP open", "FTP sends passwords unencrypted. Use SFTP/FTPS or switch it off."),
    5900: ("warning", "VNC open", "Remote screen access; often weakly protected. Restrict or switch it off."),
    1911: ("warning", "Niagara Fox without TLS (1911)",
           "Unencrypted Fox connection to a Niagara station. Use Foxs (4911) only."),
    1883: ("warning", "MQTT without TLS (1883)", "Unencrypted MQTT broker. Use MQTT over TLS (8883)."),
}
CONTROL = {
    502: "Modbus TCP", 102: "Siemens S7", 20000: "DNP3", 2404: "IEC 60870-5-104", 44818: "EtherNet/IP",
}
WEB_PLAIN = {80, 8000, 8080, 5000}
WEB_TLS = {443, 8443}


def findings(scan: Scan) -> list[Finding]:
    out: list[Finding] = []
    net = scan.network or {}

    # --- BACnet
    dups = [f"{d.instance} {d.name}: {d.address} and {e[len(DUPLICATE_PREFIX):].strip()}"
            for d in scan.devices for e in d.errors if e.startswith(DUPLICATE_PREFIX)]
    if dups:
        out.append(Finding("critical", "Duplicate BACnet device instance",
                           "Two devices answer with the same device instance. Head-ends will mix them up; "
                           "every device instance must be unique across the whole BACnet internetwork.", dups))
    failed = [f"{d.instance} {d.name} ({d.address})".replace("  ", " ") for d in scan.devices if d.status == "failed"]
    if failed:
        out.append(Finding("warning", "BACnet devices not readable",
                           "These devices answered Who-Is but did not answer read requests.", failed))
    partial = [f"{d.instance} {d.name} ({d.address})".replace("  ", " ") for d in scan.devices if d.status == "partial"]
    if partial:
        out.append(Finding("info", "BACnet devices read only partly",
                           "Some properties or objects could not be read (timeouts or errors); see the device details.",
                           partial))
    if scan.devices:
        out.append(Finding("info", "BACnet/IP has no authentication",
                           f"{len(scan.devices)} BACnet device(s) can be read - and written - by anyone on this "
                           "network. Keep the building network separated from office/guest networks "
                           "(VLAN, firewall) or use BACnet/SC."))
    traffic = net.get("bacnet_traffic") or []
    whois_sources = sorted({e["source"] for e in traffic if e.get("service") == "who-is"})
    if len(whois_sources) > 1:
        out.append(Finding("info", "Several BACnet clients searching",
                           "More than one station sends Who-Is (head-ends, tools, gateways).", whois_sources))

    # --- network environment
    inet = net.get("internet") or {}
    status = inet.get("status")
    if status == "captive-portal":
        out.append(Finding("warning", "Captive portal", "Internet access needs a login page (guest network?)."))
    elif status == "dns-only":
        out.append(Finding("warning", "Internet only partly reachable", "DNS works but HTTP/HTTPS does not."))
    elif status == "none":
        out.append(Finding("info", "No internet access", "No internet access from this network (may be intended)."))
    if inet.get("via_vpn"):
        out.append(Finding("info", "Internet tests went through a VPN",
                           "This Mac routed the internet checks through a VPN, so they say nothing about the "
                           "building network's own internet access."))
    gw = net.get("gateway") or {}
    if gw.get("ip") and not gw.get("reachable"):
        out.append(Finding("warning", "Gateway does not answer ping", f"Default gateway {gw['ip']} did not reply "
                           "(may only block ping)."))
    dhcp = net.get("dhcp") or {}
    if dhcp and not dhcp.get("used"):
        out.append(Finding("info", "No DHCP", "This Mac used a static address; DHCP may not be available."))

    # --- services (deep discovery)
    hosts = [h for h in scan.hosts if h.ports]
    for port, (sev, title, text) in CLEARTEXT.items():
        items = [_host_label(h) for h in hosts if port in h.ports]
        if items:
            out.append(Finding(sev, title, text, items))
    web_plain = [_host_label(h) for h in hosts if set(h.ports) & WEB_PLAIN and not set(h.ports) & WEB_TLS]
    if web_plain:
        out.append(Finding("warning", "Web interface only over HTTP",
                           "Logins to these web interfaces are sent unencrypted.", web_plain))
    control = [f"{_host_label(h)}: {', '.join(CONTROL[p] for p in h.ports if p in CONTROL)}"
               for h in hosts if set(h.ports) & set(CONTROL)]
    if control:
        out.append(Finding("warning", "Unauthenticated control protocols reachable",
                           "These protocols allow reading and writing values without a login. "
                           "Restrict access with a firewall.", control))
    win = [_host_label(h) for h in hosts if {445, 3389} & set(h.ports)]
    if win:
        out.append(Finding("info", "Windows file sharing / remote desktop on this network",
                           "SMB (445) or RDP (3389) is open; keep these systems patched and separated.", win))
    selfsigned = [_host_label(h) for h in scan.hosts
                  if any("(self-signed)" in v for v in h.services.values())]
    if selfsigned:
        out.append(Finding("info", "Self-signed TLS certificates",
                           "Browsers will warn, and users get used to clicking warnings away.", selfsigned))

    # --- SNMP (M9)
    snmp = net.get("snmp") or {}
    v2 = [a.get("ip", "?") + (f" ({a['sysName']})" if a.get("sysName") else "")
          for a in snmp.get("agents", []) if a.get("version") in ("v1", "v2c") and a.get("ok")]
    if v2:
        out.append(Finding("info", "SNMP v1/v2c answering",
                           "SNMP v1/v2c uses a clear-text community string. Prefer SNMP v3.", v2))

    order = {s: i for i, s in enumerate(SEVERITIES)}
    out.sort(key=lambda f: order[f.severity])
    return out
