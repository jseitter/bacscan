"""bacscan command line interface."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.markup import escape
from rich.table import Table
from rich.tree import Tree

from .. import __version__
from ..core import discover, lldp, netinfo, snmp
from ..core.listener import Listener
from ..core import network as netmod
from ..core.models import Scan
from ..core.scanner import LEVELS, ScanConfig, ScanError, ScanEvent, Scanner, read_single
from ..storage.db import Store
from ..storage.diff import diff_lines, diff_scans
from ..storage.export import export_csv, export_hosts_csv, export_json, import_json
from ..storage.xlsx import export_xlsx

console = Console()
err = Console(stderr=True)


# ---------------------------------------------------------------- helpers


def _range(s: str) -> tuple[int, int]:
    lo, _, hi = s.partition("-")
    return int(lo), int(hi or lo)


def _config_from_args(a: argparse.Namespace) -> ScanConfig:
    cfg = ScanConfig(
        interface=a.interface,
        port=a.port,
        apdu_timeout=a.apdu_timeout,
        retries=a.retries,
        bbmd=a.bbmd,
        device_instance=a.local_instance,
        bind_address=a.bind,
    )
    if getattr(a, "sc_hub", None):
        cfg.sc_hub = a.sc_hub
        cfg.sc_failover = a.sc_failover
        cfg.sc_cert, cfg.sc_key, cfg.sc_ca = a.sc_cert, a.sc_key, a.sc_ca
        cfg.sc_key_password = a.sc_key_password or os.environ.get("BACSCAN_SC_KEY_PASSWORD") or None
        cfg.sc_verify = not a.sc_insecure
        cfg.sc_direct = a.sc_direct
    for name in ("level", "site", "notes"):
        if hasattr(a, name) and getattr(a, name) is not None:
            setattr(cfg, name, getattr(a, name))
    if getattr(a, "timeout", None) is not None:
        cfg.whois_timeout = a.timeout
    if getattr(a, "range", None):
        cfg.low, cfg.high = _range(a.range)
    if getattr(a, "target", None):
        cfg.targets = a.target
    if getattr(a, "no_broadcast", False):
        cfg.broadcast = False
    if getattr(a, "concurrency", None):
        cfg.device_concurrency = a.concurrency
    if getattr(a, "no_network_info", False):
        cfg.network_info = False
    if getattr(a, "no_internet", False):
        cfg.internet_checks = False
    cfg.public_ip = getattr(a, "public_ip", False)
    cfg.sweep = getattr(a, "sweep", False)
    if getattr(a, "snmp", None) or getattr(a, "snmp_auto", False) or getattr(a, "snmp_all_hosts", False):
        cfg.snmp_credentials = _snmp_creds(a, required=True)
        cfg.snmp_targets = a.snmp or []
        cfg.snmp_auto = a.snmp_auto
        cfg.snmp_hosts = a.snmp_all_hosts
        cfg.snmp_port = a.snmp_port
        try:
            snmp.expand_targets(cfg.snmp_targets)
        except ValueError as e:
            raise SystemExit(f"error: --snmp: {e}")
    cfg.deep = getattr(a, "deep", False)
    cfg.deep_ports = _ports(getattr(a, "ports", None))
    cfg.switch_info = getattr(a, "lldp", False)
    if getattr(a, "lldp_wait", None):
        cfg.switch_wait = a.lldp_wait
    return cfg


def _snmp_creds(a: argparse.Namespace, required: bool = False) -> "snmp.Credentials | None":
    community = getattr(a, "community", None)
    user = getattr(a, "snmp_user", None)
    import os
    if not (community or user or os.environ.get("BACSCAN_SNMP_COMMUNITY")):
        if required:
            raise SystemExit("error: SNMP needs --community (v2c) or --snmp-user (v3)")
        return None
    try:
        return snmp.Credentials.from_env(community, user, a.auth_proto, a.auth_pass, a.priv_proto, a.priv_pass)
    except ValueError as e:
        raise SystemExit(f"error: SNMP: {e}")


def _ports(spec: str | None) -> list[int] | None:
    if not spec:
        return None
    if spec.strip().lower() == "none":
        return []
    try:
        return discover.parse_ports(spec)
    except ValueError as e:
        raise SystemExit(f"error: --ports: {e}")


def _devices_table(scan: Scan) -> Table:
    t = Table(title=f"Scan {scan.id or '(unsaved)'} — {scan.site or 'no site'} — {scan.started_at}",
              header_style="bold")
    for col in ("Instance", "Name", "Address", "Vendor", "Model", "Firmware", "Objects", "Status"):
        t.add_column(col, overflow="fold")
    for d in scan.devices:
        addr = d.address + (f" (net {d.network})" if d.network is not None else "")
        status = d.status if not d.errors else f"{d.status} ({len(d.errors)} err)"
        t.add_row(str(d.instance), d.name, addr, d.text("vendor-name") or str(d.vendor_id or ""),
                  d.text("model-name"), d.text("firmware-revision"), str(len(d.objects)), status)
    return t


def _network_table(info: dict) -> Table:
    t = Table(title="Network environment", header_style="bold", show_header=False)
    t.add_column("Item", style="bold")
    t.add_column("Value", overflow="fold")
    for k, v in netinfo.summarize(info):
        style = ""
        if k == "Internet":
            style = {"full": "green", "none": "red"}.get(v, "yellow")
        elif "VPN" in v or "failed" in v or "no ping" in v:
            style = "yellow"
        t.add_row(k, f"[{style}]{v}[/{style}]" if style else v)
    return t


def _hosts_table(hosts, devices=None) -> Table:
    names = {d.instance: d.name for d in (devices or [])}
    deep = any(h.layers for h in hosts)
    t = Table(title=f"Hosts on the network ({len(hosts)})", header_style="bold")
    t.add_column("IP", no_wrap=True)
    t.add_column("MAC", no_wrap=True)
    sw = any(h.switch_port for h in hosts)
    cols = ["Vendor", "Hostname", "BACnet", "Note"] + (["Ping", "Open TCP ports", "Kind"] if deep else []) + \
        (["Switch port"] if sw else [])
    for c in cols:
        t.add_column(c, overflow="fold")
    for h in hosts:
        bac = "" if h.bacnet_instance is None else f"{h.bacnet_instance} {names.get(h.bacnet_instance, '')}".strip()
        row = [h.ip, h.mac, h.vendor, h.hostname, f"[green]{bac}[/green]" if bac else "", h.note]
        if deep:
            ping = f"{h.rtt_ms:.1f} ms ttl {h.ttl}" if h.rtt_ms is not None else "-"
            row += [ping, " ".join(map(str, h.ports)), h.kind]
        if sw:
            row.append(h.switch_port)
        t.add_row(*row)
    return t


def _services_tree(hosts) -> Tree | None:
    """Per-host service details found by deep discovery."""
    tree = Tree("[bold]Services[/bold]")
    for h in hosts:
        if not h.services:
            continue
        label = f"[bold]{h.ip}[/bold] {h.hostname}".strip()
        extra = " · ".join(x for x in (h.kind, h.os_hint and f"TTL: {h.os_hint}",
                                       "answered: " + ", ".join(h.layers) if h.layers else "") if x)
        node = tree.add(f"{label} [dim]{extra}[/dim]")
        for k, v in h.services.items():
            node.add(f"[cyan]{k}[/cyan] {escape(v)}" if v else f"[cyan]{k}[/cyan]")
    return tree if tree.children else None


def _open_store(a: argparse.Namespace) -> Store:
    return Store(a.db)


# ---------------------------------------------------------------- commands


def cmd_interfaces(a: argparse.Namespace) -> int:
    ifaces = netmod.list_interfaces(include_all=a.all)
    if a.json:
        print(json.dumps([i.__dict__ | {"cidr": i.cidr} for i in ifaces], indent=2))
        return 0
    t = Table(header_style="bold")
    for c in ("", "Name", "Address", "Broadcast", "Up", "Port 47808"):
        t.add_column(c)
    for n, i in enumerate(ifaces):
        busy = netmod.port_in_use(i.ip, netmod.BACNET_PORT)
        t.add_row("*" if n == 0 else "", i.name, i.cidr, i.broadcast, "yes" if i.is_up else "no",
                  "[red]in use[/red]" if busy else "free")
    console.print(t)
    if ifaces:
        console.print("[dim]* = used by default (override with -i NAME)[/dim]")
    else:
        console.print("[yellow]No usable interface. Plug in the network cable or use --all.[/yellow]")
    return 0


def cmd_scan(a: argparse.Namespace) -> int:
    cfg = _config_from_args(a)
    found = 0

    with Progress(TextColumn("{task.description}"), BarColumn(), MofNCompleteColumn(),
                  TimeElapsedColumn(), console=console, transient=True) as progress:
        task = progress.add_task("discovering…", total=None)

        def on_event(e: ScanEvent) -> None:
            nonlocal found
            if e.kind == "device_found":
                found += 1
                d = e.device
                net = f" net {d.network}" if d.network is not None else ""
                progress.console.print(f"[green]+[/green] device [bold]{d.instance}[/bold] at {d.address}{net}")
                progress.update(task, description=f"discovering… {found} device(s)")
            elif e.kind == "progress":
                progress.update(task, description="reading objects", completed=e.done, total=e.total or None)
            elif e.kind == "device_updated" and e.device and e.device.status in ("done", "partial", "failed"):
                d = e.device
                color = {"done": "green", "partial": "yellow", "failed": "red"}[d.status]
                progress.console.print(f"  [{color}]{d.status}[/{color}] {d.instance} {d.name} "
                                       f"({len(d.objects)} objects)")
            elif e.kind == "routers":
                progress.console.print(f"[cyan]routers:[/cyan] {e.message}")
            elif e.kind == "network":
                progress.console.print(f"[cyan]{e.message}[/cyan]")
            elif e.kind == "log" and (a.verbose or e.level >= logging.WARNING):
                progress.console.print(f"[dim]{e.message}[/dim]")
            elif e.kind == "finished":
                progress.console.print(e.message)

        scanner = Scanner(cfg, on_event)

        async def run() -> Scan:
            loop = asyncio.get_running_loop()
            try:
                loop.add_signal_handler(signal.SIGINT, scanner.cancel)
            except NotImplementedError:
                pass
            return await scanner.run()

        try:
            scan = asyncio.run(run())
        except (ScanError, ValueError) as e:
            err.print(f"[red]error:[/red] {e}")
            return 1

    if not a.no_save:
        with _open_store(a) as store:
            store.save(scan)
    if scan.devices:
        console.print(_devices_table(scan))
    if scan.network:
        console.print(_network_table(scan.network))
        console.print(f"[dim]{len(scan.hosts)} host(s) seen on the network — "
                      f"'bacscan scans show {scan.id or 'latest'} --network' lists them[/dim]")
    if not a.no_save:
        console.print(f"saved as scan [bold]{scan.id}[/bold] in {store.path}")
    if a.output:
        ext = Path(a.output).suffix.lower()
        {".csv": export_csv, ".xlsx": export_xlsx}.get(ext, export_json)(scan, a.output)
        console.print(f"exported to {a.output}")
    if scan.status == "failed":
        return 1
    return 0 if scan.devices else 2


def cmd_netinfo(a: argparse.Namespace) -> int:
    """Network environment survey without BACnet."""
    try:
        iface = netmod.find_interface(a.interface)
    except ValueError as e:
        err.print(f"[red]error:[/red] {e}")
        return 1
    with console.status(f"surveying {iface.name}…"):
        info = netinfo.survey_environment(iface, internet=not a.no_internet, public_ip=a.public_ip)
        swept = False
        if a.sweep or a.deep:
            console.log(f"sweeping {iface.network}…")
            try:
                netinfo.sweep(iface)
                swept = True
            except ValueError as e:
                err.print(f"[yellow]sweep skipped:[/yellow] {e}")
        deep = None
        if a.deep:
            try:
                deep = asyncio.run(discover.deep_scan(iface, _ports(a.ports), lambda m: console.print(f"[dim]{m}[/dim]")))
            except ValueError as e:
                err.print(f"[yellow]deep discovery skipped:[/yellow] {e}")
        hosts = netinfo.collect_hosts(iface, gateway=info.get("gateway", {}).get("ip"), swept=swept)
        if deep is not None:
            hosts = discover.merge(hosts, deep)
        if a.lldp:
            console.log(f"waiting up to {a.lldp_wait:.0f} s for LLDP/CDP from the switch…")
            info["switch"] = lldp.capture(iface.name, a.lldp_wait)
        if a.snmp or a.snmp_auto or a.snmp_all_hosts:
            creds = _snmp_creds(a, required=True)
            try:
                targets = snmp.collect_targets(a.snmp or [], info, hosts, a.snmp_auto, a.snmp_all_hosts, iface.ip)
            except ValueError as e:
                raise SystemExit(f"error: --snmp: {e}")
            console.print(f"[dim]SNMP: querying {len(targets)} agent(s), {creds.describe()}[/dim]")
            def show_agent(ag: dict) -> None:
                if ag.get("ok"):
                    console.print(f"[dim]SNMP {ag['ip']}: {ag.get('sysName') or '?'} - {ag.get('sysDescr', '')[:60]}[/dim]")
                else:
                    console.print(f"[dim]SNMP {ag['ip']}: no result ({ag.get('error') or 'no answer'})[/dim]")

            info["snmp"] = snmp.survey(targets, creds, a.snmp_port, emit=show_agent, source_ip=iface.ip)
            snmp.apply(info["snmp"], hosts, [])
    if a.json:
        print(json.dumps({"network": info, "hosts": [h.__dict__ for h in hosts]}, indent=2, ensure_ascii=False))
        return 0
    console.print(_network_table(info))
    console.print(_hosts_table(hosts))
    tree = _services_tree(hosts)
    if tree:
        console.print(tree)
    return 0


def cmd_snmp(a: argparse.Namespace) -> int:
    """Standalone read-only SNMP read-out."""
    creds = _snmp_creds(a, required=True)
    try:
        targets = snmp.expand_targets(a.targets)
    except ValueError as e:
        err.print(f"[red]error:[/red] {e}")
        return 1
    with console.status(f"SNMP: querying {len(targets)} agent(s)…"):
        if len(targets) == 1:
            agents = [snmp.read_agent(targets[0], creds, a.snmp_port, not a.system_only, a.timeout)]
            result = {"credentials": creds.describe(), "agents": agents, "mac_ports": snmp.map_ports(agents)}
            for ag in agents:
                ag["fdb_entries"] = len(ag.pop("fdb", []) or [])
        else:
            result = snmp.survey(targets, creds, a.snmp_port, not a.system_only)
    if a.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 0 if any(x.get("ok") for x in result["agents"]) else 2
    for ag in result["agents"]:
        _print_agent(ag)
    if result.get("mac_ports"):
        t = Table(title="MAC addresses on switch ports", header_style="bold")
        for c in ("MAC", "Vendor", "Switch", "Port", "VLAN"):
            t.add_column(c)
        for mac, p in sorted(result["mac_ports"].items(), key=lambda kv: (kv[1]["switch"], kv[1]["port"])):
            t.add_row(mac, oui_vendor(mac), p["switch"], p["port"], "" if p.get("vlan") is None else str(p["vlan"]))
        console.print(t)
    return 0 if any(x.get("ok") for x in result["agents"]) else 2


def oui_vendor(mac: str) -> str:
    from ..core import oui
    return oui.vendor(mac)


def _print_agent(ag: dict) -> None:
    if not ag.get("ok"):
        console.print(f"[red]{ag['ip']}[/red]: {escape(ag.get('error', 'no answer'))}")
        return
    rows = [(k, ag.get(k, "")) for k in ("sysName", "sysDescr", "sysLocation", "sysContact", "sysUpTime",
                                          "sysObjectID")]
    rows += [(f"entity {k}", v) for k, v in (ag.get("entity") or {}).items()]
    t = Table(title=f"SNMP {ag['ip']} ({ag['version']})", show_header=False)
    t.add_column(style="bold")
    t.add_column(overflow="fold")
    for k, v in rows:
        if v:
            t.add_row(k, escape(str(v)))
    if ag.get("fdb_entries") is not None and "interfaces" in ag:
        t.add_row("forwarding table", f"{ag['fdb_entries']} MAC entries")
    console.print(t)
    counts = ag.get("port_mac_counts") or {}
    ifs = [i for i in ag.get("interfaces", []) if i.get("oper") == "up" or i.get("alias")]
    if ifs:
        it = Table(title=f"Interfaces up ({len(ifs)} of {len(ag['interfaces'])})", header_style="bold")
        for c in ("#", "Name", "Alias", "Type", "Speed", "MAC", "MACs learned"):
            it.add_column(c, overflow="fold", no_wrap=c in ("#", "MAC"))
        for i in ifs:
            it.add_row(str(i["index"]), i["name"], i["alias"], i["type"],
                       f"{i['speed_mbps']} Mb/s" if i.get("speed_mbps") else "", i["mac"],
                       str(counts.get(i["name"], "")))
        console.print(it)
    if ag.get("lldp"):
        lt = Table(title="LLDP neighbours", header_style="bold")
        for c in ("Local port", "Neighbour", "Neighbour port", "Chassis"):
            lt.add_column(c, overflow="fold")
        for n in ag["lldp"]:
            lt.add_row(n["local_port"], n["remote_name"], n["remote_port_desc"] or n["remote_port"],
                       n["remote_chassis"])
        console.print(lt)
    if ag.get("ip_addresses"):
        console.print("IPv4: " + ", ".join(f"{x['ip']}/{x['mask']} ({x['interface']})" for x in ag["ip_addresses"]))


def cmd_listen(a: argparse.Namespace) -> int:
    """Passive mode: record BACnet broadcasts, send nothing."""
    cfg = _config_from_args(a)
    cfg.network_info = not a.no_network_info
    listener = Listener(cfg, a.duration)

    def on_event(e: ScanEvent) -> None:
        if e.kind == "device_found":
            console.print(f"[green]+[/green] {e.message}")
        elif e.kind == "log":
            console.print(f"[dim]{e.message}[/dim]")
        elif e.kind == "finished":
            console.print(e.message)

    listener.on_event = on_event

    async def run() -> Scan:
        loop = asyncio.get_running_loop()
        try:
            loop.add_signal_handler(signal.SIGINT, listener.cancel)
        except NotImplementedError:
            pass
        return await listener.run()

    try:
        scan = asyncio.run(run())
    except (ScanError, ValueError) as e:
        err.print(f"[red]error:[/red] {e}")
        return 1
    traffic = scan.network.get("bacnet_traffic", [])
    if traffic:
        t = Table(title="BACnet traffic heard", header_style="bold")
        for c in ("Source", "Service", "Count", "Detail"):
            t.add_column(c, overflow="fold")
        for e in traffic:
            t.add_row(e["source"], e["service"], str(e["count"]), e["detail"])
        console.print(t)
    if not a.no_save:
        with _open_store(a) as store:
            store.save(scan)
        console.print(f"saved as scan [bold]{scan.id}[/bold]")
    return 0 if traffic else 2


def cmd_scans_diff(a: argparse.Namespace) -> int:
    with _open_store(a) as store:
        try:
            sa, sb = _load(a, store, a.scan_a), _load(a, store, a.scan_b)
        except KeyError as e:
            err.print(f"[red]{e.args[0]}[/red]")
            return 1
    d = diff_scans(sa, sb, values=a.values)
    if a.json:
        print(json.dumps(d.to_dict(), indent=2, ensure_ascii=False))
        return 0
    console.print(f"[bold]scan {sa.id}[/bold] ({sa.started_at[:16]}, {sa.site or 'no site'}) → "
                  f"[bold]scan {sb.id}[/bold] ({sb.started_at[:16]}, {sb.site or 'no site'})")
    colors = {"+": "green", "-": "red", "~": "yellow"}
    for kind, text in diff_lines(d):
        if kind == "#":
            console.print(f"\n[bold]{text}[/bold]")
        else:
            console.print(f"  [{colors[kind]}]{kind} {text}[/{colors[kind]}]", highlight=False)
    return 0 if d.empty else 3


def cmd_read(a: argparse.Namespace) -> int:
    cfg = _config_from_args(a)
    try:
        pv = asyncio.run(read_single(cfg, a.address, a.object, a.property))
    except (ScanError, ValueError) as e:
        err.print(f"[red]error:[/red] {e}")
        return 1
    if a.json:
        print(json.dumps(pv.__dict__, indent=2))
    elif pv.error:
        err.print(f"[red]{pv.error}[/red]")
    else:
        console.print(pv.text)
    return 1 if pv.error else 0


def cmd_scans_list(a: argparse.Namespace) -> int:
    with _open_store(a) as store:
        scans = store.list()
    if a.json:
        print(json.dumps([s.__dict__ for s in scans], indent=2))
        return 0
    t = Table(header_style="bold")
    for c in ("ID", "Started", "Site", "Level", "Status", "Devices", "Objects", "Notes"):
        t.add_column(c, overflow="fold")
    for s in scans:
        t.add_row(str(s.id), s.started_at, s.site, s.level, s.status, str(s.devices), str(s.objects), s.notes)
    console.print(t)
    return 0


def _load(a: argparse.Namespace, store: Store, scan_id: str) -> Scan:
    if scan_id == "latest":
        sid = store.latest_id()
        if sid is None:
            raise KeyError("no scans saved yet")
        return store.load(sid)
    return store.load(int(scan_id))


def cmd_scans_show(a: argparse.Namespace) -> int:
    with _open_store(a) as store:
        try:
            scan = _load(a, store, a.scan_id)
        except KeyError as e:
            err.print(f"[red]{e.args[0]}[/red]")
            return 1
    if a.device is not None:
        dev = scan.device(a.device)
        if not dev:
            err.print(f"[red]device {a.device} not in scan {scan.id}[/red]")
            return 1
        if a.json:
            print(json.dumps(dev.to_dict(), indent=2, ensure_ascii=False))
            return 0
        t = Table(title=f"Device {dev.instance} — {dev.name}", header_style="bold", show_header=False)
        t.add_column("Property", style="bold")
        t.add_column("Value", overflow="fold")
        t.add_row("address", dev.address + (f" (net {dev.network}, mac {dev.mac})" if dev.network is not None else ""))
        if dev.eth_mac:
            via = " (MAC of the BACnet router)" if dev.eth_mac_source == "router" else ""
            t.add_row("ethernet MAC", f"{dev.eth_mac} {dev.eth_vendor}{via}".strip())
        for k, v in dev.props.items():
            t.add_row(k, v.text if v.error is None else f"[red]{v.error}[/red]")
        console.print(t)
        o = Table(title="Objects", header_style="bold")
        for c in ("Type", "Inst", "Name", "Present value", "Units", "Description"):
            o.add_column(c, overflow="fold")
        for ob in dev.objects:
            o.add_row(ob.object_type, str(ob.instance), ob.name, ob.text("present-value"),
                      ob.text("units"), ob.text("description"))
        console.print(o)
        if dev.errors:
            console.print("[yellow]errors:[/yellow] " + "; ".join(dev.errors))
        return 0
    if a.json:
        print(json.dumps(scan.to_dict(), indent=2, ensure_ascii=False))
        return 0
    if a.network:
        if not scan.network and not scan.hosts:
            console.print("[yellow]no network information stored with this scan[/yellow]")
            return 0
        console.print(_network_table(scan.network))
        console.print(_hosts_table(scan.hosts, scan.devices))
        tree = _services_tree(scan.hosts)
        if tree:
            console.print(tree)
        return 0
    console.print(_devices_table(scan))
    inet = scan.network.get("internet", {}).get("status")
    if scan.network:
        gw = scan.network.get("gateway", {}).get("ip") or "none"
        dhcp = "DHCP" if scan.network.get("dhcp", {}).get("used") else "static"
        console.print(f"network: {scan.network.get('interface', {}).get('network', '')} ({dhcp}) · gateway {gw} · "
                      f"internet {inet or 'not checked'} · {len(scan.hosts)} host(s)  [dim](--network for details)[/dim]")
    if scan.routers:
        console.print("routers: " + ", ".join(f"{r.address} -> {r.networks}" for r in scan.routers))
    console.print(f"[dim]interface {scan.interface} · level {scan.level} · status {scan.status}[/dim]")
    return 0


def cmd_scans_report(a: argparse.Namespace) -> int:
    from ..core.findings import findings
    from ..storage import report

    with _open_store(a) as store:
        scan = _load(a, store, a.scan_id)
    ext = Path(a.output).suffix.lower()
    if ext == ".pdf":
        report.write_pdf(scan, a.output, objects=a.objects, author=a.author)
    elif ext in (".html", ".htm"):
        report.write_html(scan, a.output, objects=a.objects, author=a.author)
    else:
        err.print("[red]error:[/red] output must end in .html or .pdf")
        return 1
    fs = findings(scan)
    counts = ", ".join(f"{sum(f.severity == s for f in fs)} {s}" for s in ("critical", "warning", "info"))
    console.print(f"wrote {a.output} ({len(fs)} finding(s): {counts})")
    return 0


def cmd_scans_export(a: argparse.Namespace) -> int:
    with _open_store(a) as store:
        scan = _load(a, store, a.scan_id)
    fmt = a.format or {".csv": "csv", ".xlsx": "xlsx"}.get(Path(a.output).suffix.lower(), "json")
    if fmt == "xlsx":
        export_xlsx(scan, a.output)
        console.print(f"wrote {a.output}")
    elif fmt == "hosts":
        n = export_hosts_csv(scan, a.output)
        console.print(f"wrote {n} hosts to {a.output}")
    elif fmt == "csv":
        n = export_csv(scan, a.output)
        console.print(f"wrote {n} rows to {a.output}")
    else:
        export_json(scan, a.output)
        console.print(f"wrote {a.output}")
    return 0


def cmd_scans_import(a: argparse.Namespace) -> int:
    scan = import_json(a.file)
    with _open_store(a) as store:
        sid = store.save(scan)
    console.print(f"imported as scan {sid}")
    return 0


def cmd_scans_delete(a: argparse.Namespace) -> int:
    with _open_store(a) as store:
        ok = store.delete(int(a.scan_id))
    console.print(f"deleted scan {a.scan_id}" if ok else f"[red]scan {a.scan_id} not found[/red]")
    return 0 if ok else 1


def cmd_scans_edit(a: argparse.Namespace) -> int:
    with _open_store(a) as store:
        store.update_meta(int(a.scan_id), site=a.site, notes=a.notes)
    return 0


def cmd_gui(a: argparse.Namespace) -> int:
    try:
        from ..gui.app import main as gui_main
    except ImportError as e:
        err.print(f"[red]GUI not available:[/red] {e}")
        return 1
    return gui_main(db_path=a.db)


# ---------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bacscan", description="BACnet/IP discovery and inventory (read-only).")
    p.add_argument("--version", action="version", version=f"bacscan {__version__}")
    p.add_argument("--db", help="SQLite database file (default: ~/Library/Application Support/bacscan/bacscan.db)")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose output")
    p.add_argument("--debug", action="store_true", help="debug logging")
    sub = p.add_subparsers(dest="cmd", required=True)

    def net_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("-i", "--interface", help="interface name or IP (default: auto)")
        sp.add_argument("--port", type=int, default=netmod.BACNET_PORT, help="local UDP port (default 47808)")
        sp.add_argument("--bbmd", help="register as foreign device with BBMD ip[:port]")
        sp.add_argument("--apdu-timeout", type=float, default=3.0, help="seconds per request (default 3)")
        sp.add_argument("--retries", type=int, default=2, help="retries per request (default 2)")
        sp.add_argument("--local-instance", type=int, help="our own device instance (default: random)")
        sp.add_argument("--bind", help=argparse.SUPPRESS)  # expert/test: explicit 'ip/prefix:port'
        g = sp.add_argument_group("BACnet/SC (secure connect; replaces BACnet/IP when --sc-hub is given)")
        g.add_argument("--sc-hub", metavar="URI", help="hub WebSocket URI, e.g. wss://hub.example.com:4443")
        g.add_argument("--sc-failover", metavar="URI", help="failover hub URI")
        g.add_argument("--sc-cert", metavar="PEM", help="operational certificate of this node")
        g.add_argument("--sc-key", metavar="PEM", help="private key of that certificate")
        g.add_argument("--sc-key-password", help="password of the private key (or env BACSCAN_SC_KEY_PASSWORD)")
        g.add_argument("--sc-ca", metavar="PEM", help="CA certificate(s) that signed the hub's certificate")
        g.add_argument("--sc-insecure", action="store_true",
                       help="do not verify the hub's certificate (lab use only)")
        g.add_argument("--sc-direct", action="store_true",
                       help="connect directly to devices that offer a direct-connect URI")

    def survey_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--no-internet", action="store_true", help="skip internet reachability checks")
        sp.add_argument("--public-ip", action="store_true", help="look up the public IP (contacts api.ipify.org)")
        sp.add_argument("--sweep", action="store_true",
                        help="probe every address of the local subnet (max /22) to find all hosts")
        sp.add_argument("--deep", action="store_true",
                        help="deep host discovery on the local subnet (max /22): ARP, ping, TCP ports, "
                             "HTTP/TLS, mDNS, SSDP/UPnP, NetBIOS; implies --sweep")
        sp.add_argument("--ports", metavar="LIST",
                        help="TCP ports for --deep, e.g. 80,443,8000-8100 (default: building/IT list; "
                             "'none' = no TCP)")
        sp.add_argument("--lldp", action="store_true",
                        help="wait for an LLDP/CDP announcement to identify switch, port and VLAN")
        sp.add_argument("--lldp-wait", type=float, default=lldp.DEFAULT_WAIT,
                        help=f"seconds to wait for LLDP/CDP (default {lldp.DEFAULT_WAIT:.0f})")

    def snmp_cred_opts(sp: argparse.ArgumentParser, short: bool = False) -> None:
        g = sp.add_argument_group("SNMP credentials (read-only; never stored)")
        g.add_argument(*(["-c"] if short else []), "--community",
                       help="SNMP v2c community (or env BACSCAN_SNMP_COMMUNITY)")
        g.add_argument(*(["-u"] if short else []), "--snmp-user", help="SNMP v3 user name")
        g.add_argument("--auth-proto", default="", choices=["", "MD5", "SHA", "SHA256"],
                       help="SNMP v3 authentication (default SHA when a password is given)")
        g.add_argument("--auth-pass", help="SNMP v3 authentication password (or env BACSCAN_SNMP_AUTH)")
        g.add_argument("--priv-proto", default="", choices=["", "AES"], help="SNMP v3 privacy")
        g.add_argument("--priv-pass", help="SNMP v3 privacy password (or env BACSCAN_SNMP_PRIV)")
        g.add_argument("--snmp-port", type=int, default=snmp.DEFAULT_PORT, help="agent UDP port (default 161)")

    def snmp_scan_opts(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--snmp", action="append", metavar="TARGET",
                        help="read SNMP from IP, CIDR or IP-IP (repeatable; needs --community or --snmp-user)")
        sp.add_argument("--snmp-auto", action="store_true",
                        help="SNMP: also query the gateway and the switch found via LLDP/CDP")
        sp.add_argument("--snmp-all-hosts", action="store_true", help="SNMP: also query every host found")
        snmp_cred_opts(sp)

    sp = sub.add_parser("interfaces", help="list network interfaces")
    sp.add_argument("--all", action="store_true", help="include virtual/VPN interfaces")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_interfaces)

    sp = sub.add_parser("scan", help="discover devices and read them out")
    net_opts(sp)
    sp.add_argument("-l", "--level", choices=LEVELS, default="full",
                    help="discover | device | full (default) | all")
    sp.add_argument("-t", "--timeout", type=float, default=5.0, help="seconds to wait for I-Am (default 5)")
    sp.add_argument("-r", "--range", help="device instance range LOW-HIGH")
    sp.add_argument("--target", action="append", help="unicast Who-Is to IP, CIDR or IP-IP (repeatable)")
    sp.add_argument("--no-broadcast", action="store_true", help="do not broadcast (use with --target)")
    sp.add_argument("-c", "--concurrency", type=int, help="devices read in parallel (default 4)")
    sp.add_argument("--site", help="site name stored with the scan")
    sp.add_argument("--notes", help="notes stored with the scan")
    sp.add_argument("--no-save", action="store_true", help="do not store the scan")
    sp.add_argument("-o", "--output", help="also export to FILE (.json or .csv)")
    survey_opts(sp)
    snmp_scan_opts(sp)
    sp.add_argument("--no-network-info", action="store_true", help="skip the network environment survey")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("netinfo", help="network environment survey only (DHCP, DNS, gateway, internet, hosts)")
    sp.add_argument("-i", "--interface", help="interface name or IP (default: auto)")
    survey_opts(sp)
    snmp_scan_opts(sp)
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_netinfo)

    sp = sub.add_parser("snmp", help="read-only SNMP read-out of switches / routers / devices")
    sp.add_argument("targets", nargs="+", help="IP, CIDR or IP-IP")
    snmp_cred_opts(sp, short=True)
    sp.add_argument("--system-only", action="store_true", help="only the system group, no tables")
    sp.add_argument("--timeout", type=float, default=2.0, help="seconds per request (default 2)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_snmp)

    sp = sub.add_parser("listen", help="passive mode: record BACnet broadcasts without sending anything")
    net_opts(sp)
    sp.add_argument("-d", "--duration", type=float, default=60, help="seconds to listen (default 60)")
    sp.add_argument("--site", help="site name stored with the result")
    sp.add_argument("--notes", help="notes stored with the result")
    sp.add_argument("--no-network-info", action="store_true", help="do not record interface/ARP information")
    sp.add_argument("--no-save", action="store_true")
    sp.set_defaults(func=cmd_listen)

    sp = sub.add_parser("read", help="read a single property (read-only)")
    net_opts(sp)
    sp.add_argument("address", help="device address, e.g. 10.0.0.5 or 2001:5")
    sp.add_argument("object", help="object id, e.g. analog-input,1 or device,1001")
    sp.add_argument("property", nargs="?", default="present-value")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_read)

    sc = sub.add_parser("scans", help="manage saved scans").add_subparsers(dest="scmd", required=True)
    sp = sc.add_parser("list", help="list saved scans")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_scans_list)
    sp = sc.add_parser("show", help="show a saved scan ('latest' for the newest)")
    sp.add_argument("scan_id")
    sp.add_argument("-d", "--device", type=int, help="show one device with its objects")
    sp.add_argument("-n", "--network", action="store_true", help="show network environment and hosts")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_scans_show)
    sp = sc.add_parser("export", help="export a scan: json (everything), csv (objects), xlsx (Excel), hosts (CSV)")
    sp.add_argument("scan_id")
    sp.add_argument("-o", "--output", required=True)
    sp.add_argument("-f", "--format", choices=("json", "csv", "xlsx", "hosts"))
    sp.set_defaults(func=cmd_scans_export)
    sp = sc.add_parser("report", help="site report with findings as HTML or PDF")
    sp.add_argument("scan_id")
    sp.add_argument("-o", "--output", required=True, help="FILE.html or FILE.pdf")
    sp.add_argument("--objects", action="store_true", help="append the full object list of every device")
    sp.add_argument("--author", default="", help="author / company line in the header")
    sp.set_defaults(func=cmd_scans_report)
    sp = sc.add_parser("diff", help="compare two scans (older first; 'latest' allowed)")
    sp.add_argument("scan_a")
    sp.add_argument("scan_b")
    sp.add_argument("--values", action="store_true", help="also compare present values / status")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_scans_diff)
    sp = sc.add_parser("import", help="import a JSON export")
    sp.add_argument("file")
    sp.set_defaults(func=cmd_scans_import)
    sp = sc.add_parser("edit", help="set site name / notes")
    sp.add_argument("scan_id")
    sp.add_argument("--site")
    sp.add_argument("--notes")
    sp.set_defaults(func=cmd_scans_edit)
    sp = sc.add_parser("delete", help="delete a saved scan")
    sp.add_argument("scan_id")
    sp.set_defaults(func=cmd_scans_delete)

    sp = sub.add_parser("gui", help="start the graphical user interface")
    sp.set_defaults(func=cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.debug else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    if not a.debug:
        logging.getLogger("bacscan").setLevel(logging.ERROR)  # CLI shows its own messages
    try:
        return a.func(a)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
