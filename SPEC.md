# bacscan — Specification

Status: **v0.3** (2026-11-10) — v0.2 approved; v0.3 adds the network environment survey (§4.7, M4)

## 1. Purpose

A portable BACnet/IP discovery and inventory tool for a MacBook. A technician plugs into
an unknown building-automation network, finds all BACnet devices, reads out everything
they expose, and saves the result locally for later review, comparison and export.

Usable both from the **command line** and through a **desktop GUI (Qt)**.

## 2. Goals / Non-goals

### Goals
- Zero-config discovery: plug in, pick the network interface, press "Scan".
- Read **all** device details and the full object list with its properties.
- Store scans locally (offline); reopen, compare and export them later.
- Read-only by default: the tool must not change anything on the network.
- Capture the surrounding **IP network environment** (DHCP, DNS, gateway, internet access, MAC addresses) so every scan gives a holistic picture of the site network.
- Runs on macOS (Apple Silicon + Intel); Linux/Windows nice-to-have, not tested.

### Non-goals (v1)
- Writing values, commanding outputs, or changing device configuration — the tool stays **strictly read-only** (confirmed, also for later versions).
- Native BACnet MS/TP over RS-485 (MS/TP devices are reached **through** BACnet/IP routers only — confirmed).
- BACnet/SC (secure connect), BACnet Ethernet (ISO 8802-3).
- Trend log / history download, alarm acknowledgement, COV subscriptions (later candidates).

## 3. Users & typical workflow

1. Connect MacBook to the site network (Ethernet/USB adapter or Wi-Fi).
2. Start `bacscan gui` (or `bacscan scan` in the terminal).
3. Select the interface → tool shows IP, subnet, broadcast address.
4. Start discovery → devices appear live as I-Am answers arrive.
5. Deep scan runs per device (objects + properties), with progress.
6. Scan is saved automatically, with site name / notes added by the user.
7. Back at the office: open the saved scan, browse, search, export to CSV/JSON/Excel.

## 4. Functional requirements

### 4.1 Network setup
| ID | Requirement |
|----|-------------|
| N1 | List local IPv4 interfaces with address, netmask, broadcast; preselect the active wired one. |
| N2 | Bind the BACnet/IP stack to the chosen interface, default UDP port **47808 (0xBAC0)**; port configurable. |
| N3 | Detect "port 47808 already in use" (another BACnet tool running) and suggest an alternative port. |
| N4 | Optional **Foreign Device Registration** with a BBMD (IP:port, TTL) to discover devices on other subnets. |
| N5 | Configurable local device instance ID (default: random in 4 000 000–4 194 302 range to avoid collisions). |

### 4.2 Discovery
| ID | Requirement |
|----|-------------|
| D1 | Broadcast **Who-Is** (global and local broadcast); collect **I-Am** responses for a configurable time (default 5 s). |
| D2 | Optional instance range limits (low/high) for Who-Is, to split large networks. |
| D3 | **Who-Is-Router-To-Network** to discover BACnet routers and the network numbers behind them (MS/TP trunks etc.). |
| D4 | Devices behind routers are addressed via network number + MAC; shown with their route. |
| D5 | Targeted discovery: unicast Who-Is to a single IP or IP range (for networks where broadcast is blocked). |
| D6 | Passive listen mode: only log I-Am / other broadcasts without sending anything. |
| D7 | Record per device: instance, address (IP:port or net:mac), max APDU, segmentation support, vendor ID, first-seen time. |

### 4.3 Device detail read-out ("deep scan")
| ID | Requirement |
|----|-------------|
| R1 | Read Device object properties: object-name, vendor-name, vendor-identifier, model-name, firmware-revision, application-software-version, description, location, protocol-version/revision, services-supported, object-types-supported, max-apdu, segmentation, system-status, database-revision, local time/date, UTC offset, serial number (if present). |
| R2 | Read the **object-list**. If the full array read fails (no segmentation / too large), fall back to reading index 0 (length) then each element individually. |
| R3 | For every object read the standard set: object-name, object-type, description, present-value, units, status-flags, out-of-service, reliability, event-state; plus type-specific ones (e.g. state-text, number-of-states, priority-array, relinquish-default, cov-increment, min/max-pres-value). |
| R4 | Option "all properties": read `propertyList` / `ALL` for each object. |
| R5 | Prefer **ReadPropertyMultiple** if the device supports it; fall back to ReadProperty automatically. |
| R6 | Respect device limits: max APDU, segmentation; throttle requests (configurable concurrency, default 1 request in flight per device, 4 devices in parallel). |
| R7 | Timeouts and retries configurable (default 3 s, 2 retries); errors per property are recorded, not fatal. |
| R8 | Scan levels: `discover` (D only), `device` (D + R1), `full` (D + R1–R3), `all` (+R4). |
| R9 | Scan can be cancelled; partial results are kept. |

### 4.4 Storage
| ID | Requirement |
|----|-------------|
| S1 | Local **SQLite** database, default `~/Library/Application Support/bacscan/bacscan.db` (overridable via `--db`). |
| S2 | Each scan stored as a *Scan* with metadata: timestamp, site name, notes, interface, local IP, scan settings, duration, tool version. |
| S3 | Raw values stored as JSON-serialisable values plus a human-readable string. |
| S4 | List, open, rename, annotate, delete scans. |
| S5 | **Export** a scan to JSON (full fidelity), CSV (one row per object), and XLSX (sheet per device + summary). |
| S6 | **Import** a JSON export (to move scans between machines). |
| S7 | **Diff** two scans: devices added/removed, changed properties (firmware, names, object count). |

### 4.5 Command line interface
```
bacscan interfaces                         # list usable network interfaces
bacscan scan [-i en0] [--port 47808] [--level full]
             [--timeout 5] [--range LOW-HIGH] [--target 10.0.0.0/24]
             [--bbmd 10.1.1.1:47808] [--site "Building A"] [--no-save]
bacscan listen [-i en0] [--duration 60]   # passive mode
bacscan read <device-instance> [object] [property]   # ad-hoc single read
bacscan scans list
bacscan scans show <scan-id> [--device N]
bacscan scans export <scan-id> --format json|csv|xlsx -o FILE
bacscan scans import FILE
bacscan scans diff <scan-a> <scan-b>
bacscan scans delete <scan-id>
bacscan gui                                # launch the Qt GUI
```
- Live progress output (devices found, objects read) using `rich`.
- `--json` flag for machine-readable output on list/show commands.
- Exit codes: 0 ok, 1 error, 2 no devices found.

### 4.6 GUI (PySide6 / Qt 6)
Main window layout:
```
┌────────────────────────────────────────────────────────────────────┐
│ Interface [en0 172.20.15.130/20 ▾]  Port [47808]  Level [full ▾]  │
│ [▶ Scan] [■ Stop] [Listen]   Site: [__________]   BBMD: [_______] │
├───────────────────┬────────────────────────────────────────────────┤
│ Scans (history)   │ Devices                                        │
│  2026-11-10 Bldg A│  Inst │ Name │ Vendor │ Model │ IP │ FW │ #Obj │
│  2026-11-03 Bldg B│  ...                                           │
│                   ├────────────────────────────────────────────────┤
│                   │ Objects of selected device   [Filter: ____]    │
│                   │  Type │ Inst │ Name │ Present value │ Units │…  │
│                   ├────────────────────────────────────────────────┤
│                   │ Properties of selected object (key / value)    │
├───────────────────┴────────────────────────────────────────────────┤
│ Status: 12 devices · reading 4711/2000 objects ·  ████████░░ 63 %  │
└────────────────────────────────────────────────────────────────────┘
```
- Devices appear live during discovery; deep-scan progress per device.
- Filter/search across names and descriptions; sortable columns.
- Context menu: re-scan device, refresh object, copy value, export selection.
- Menu: File → Open scan / Import / Export / Diff; Settings (timeouts, concurrency, local device ID).
- The BACnet stack runs in a background asyncio thread; the UI never blocks.

### 4.7 Network environment survey
Collected with every scan (can be switched off with `--no-network-info`) and stored with it.
Everything is read from the Mac itself or gathered with harmless standard traffic; active probing is opt-in.

| ID | Requirement |
|----|-------------|
| E1 | **Local link**: interface name, MAC address, IPv4/IPv6 addresses, netmask, media/link speed, MTU, Wi-Fi SSID when on Wi-Fi. |
| E2 | **DHCP**: whether the address came from DHCP; DHCP server, lease time, offered router, DNS servers, domain name, NTP servers and other options (macOS: `ipconfig getpacket`). Static configuration is reported as such. |
| E3 | **Default gateway**: IP and MAC; reachable (ping) yes/no and round-trip time. |
| E4 | **DNS**: configured resolvers and search domains (`scutil --dns`); test lookup of a well-known public name and of the gateway's reverse name; timings. |
| E5 | **Internet access**: DNS works / HTTPS to a well-known endpoint works / captive portal detected; result shown as *none / DNS only / full / captive portal*. |
| E6 | **Public IP** (opt-in `--public-ip`, because it contacts an external service). |
| E7 | **MAC addresses of BACnet devices**: for devices on the local subnet, the MAC from the ARP table after communicating with them; vendor name from the OUI prefix (offline OUI list bundled). Devices behind routers show the router's MAC, flagged as such. |
| E8 | **Other hosts seen**: all entries of the ARP/neighbour table (IP, MAC, OUI vendor, reverse DNS name), marked whether they are a BACnet device. |
| E9 | **Active host discovery** (opt-in `--sweep`): ARP/ping sweep of the local subnet (limited to /22 or smaller, throttled) to complete E8. |
| E10 | **Switch port info** (optional, later): passively listen for LLDP/CDP frames to show switch name, port and VLAN (needs elevated rights; only if available). |

Results are stored per scan (`network` section in JSON export; separate CSV `hosts` export) and shown in the GUI on a *Network* tab next to the BACnet devices.

## 5. Architecture

```
src/bacscan/
  core/
    network.py     # interface enumeration (psutil), port checks
    stack.py       # bacpypes3 application setup, BBMD/foreign registration
    discovery.py   # Who-Is / I-Am / router discovery, passive listen
    reader.py      # device + object read-out, RPM/RP fallback, throttling
    models.py      # dataclasses: Scan, Device, BacnetObject, PropertyValue
    scanner.py     # orchestrates a scan, emits progress events (async generator / callbacks)
    netinfo.py     # network environment survey: DHCP, DNS, gateway, internet, ARP/OUI
  storage/
    db.py          # SQLite schema + repository
    export.py      # JSON / CSV / XLSX, import, diff
  cli/main.py      # argparse/typer commands, rich output
  gui/
    app.py         # QApplication, main window
    worker.py      # asyncio-in-QThread bridge, Qt signals for progress
    models.py      # QAbstractTableModels for devices/objects/properties
```
- **One core, two front-ends**: CLI and GUI both call `scanner.Scanner` and the storage layer; no BACnet logic in UI code.
- Core emits typed events (`DeviceFound`, `DeviceRead`, `ObjectRead`, `Progress`, `Error`, `Finished`).

### Tech stack
| Component | Choice | Reason |
|-----------|--------|--------|
| Language | Python 3.12 | Fast iteration, good BACnet libs |
| BACnet stack | **bacpypes3** | Maintained, asyncio-native, BACnet/IP + routing + BBMD |
| GUI | **PySide6** (Qt 6, LGPL) | Native look on macOS, official Qt binding |
| CLI | argparse + rich | Clean progress & tables |
| Storage | SQLite (stdlib) | Single file, no server, queryable |
| XLSX export | openpyxl | |
| Packaging | uv for development; **macOS `.app` bundle** (PyInstaller) as the delivered product | double-clickable, no Python install needed |

### Data model (SQLite)
```
scan(id, started_at, finished_at, site, notes, interface, local_ip, port, level, settings_json, tool_version)
device(id, scan_id, instance, address, network, mac, vendor_id, vendor_name, model_name,
       object_name, firmware, app_version, max_apdu, segmentation, props_json, error)
scan.network_json   -- environment survey result (E1–E6)
host(id, scan_id, ip, mac, oui_vendor, hostname, is_bacnet, source)   -- E7–E9
device.mac_address, device.oui_vendor
object(id, device_id, object_type, instance, object_name, description, present_value, units, props_json)
```
`props_json` holds every read property: `{name: {"value": <json>, "text": "...", "error": null}}`.

## 6. Non-functional requirements
- **Safety**: network survey only sends standard harmless traffic (DNS lookups, one HTTPS request, ping to the gateway); subnet sweep and public-IP lookup are opt-in.
- **Safety (BACnet)**: read-only services only (Who-Is, Who-Is-Router-To-Network, ReadProperty, ReadPropertyMultiple). No Write/Reinitialize/DCC.
- **Network friendliness**: throttled requests; a full scan must not flood slow MS/TP trunks (per-network rate limit, default ≥ 50 ms between requests to devices behind routers).
- **Sizing**: typical site has 20–40 devices. Defaults are tuned for that size.
- **Performance target**: 40 devices × 200 objects at level `full` in < 5 min.
- **Robustness**: one misbehaving device never aborts the scan.
- **Logging**: debug log file per scan (optional packet-level trace) for troubleshooting.
- **Privacy**: everything stays local; no telemetry.

## 7. macOS specifics
- macOS firewall may prompt to allow incoming UDP for Python — documented in README.
- Broadcast reception requires binding to the interface's broadcast address/0.0.0.0 as well as the unicast IP; handled in `stack.py`.
- Only one process can own UDP 47808 normally; detect and report conflicts (N3).
- Network permission prompt ("Local Network") on macOS 15+: the `.app` Info.plist declares `NSLocalNetworkUsageDescription`.
- The `.app` bundles the CLI too (`bacscan.app/Contents/MacOS/bacscan <command>`), so one artifact serves both.

## 8. Testing
- Unit tests for models, storage, export/diff.
- Integration tests against a **simulated BACnet device** (bacpypes3 sample server on a second port/loopback) run in CI.
- Manual test against a real site / a virtual device (e.g. YABE room simulator).

## 9. Milestones
1. **M1 — Core + CLI**: interfaces, discovery, device read-out, SQLite save, `scans list/show`.
2. **M2 — Full read-out**: object lists, RPM fallback, routers/MS/TP, BBMD, export JSON/CSV.
3. **M3 — GUI**: main window, live scan, saved scan browser, filters.
4. **M4 — Network environment survey** (§4.7): local link, DHCP, DNS, gateway, internet access, ARP/MAC + OUI vendors, hosts list, optional sweep; CLI + GUI *Network* tab.
5. **M5 — Extras**: XLSX export, diff, passive listen, LLDP/CDP (E10).
6. **M6 — Delivery**: signed-ready macOS `.app` bundle (PyInstaller), README.

## 10. Implementation status (2026-11-10)
- **M1 done**: interfaces, discovery (broadcast, unicast targets, instance range), device read-out, SQLite storage, CLI (`interfaces`, `scan`, `read`, `scans list/show/export/import/edit/delete`).
- **M2 mostly done**: object lists incl. element-by-element fallback, RPM→RP fallback, JSON/CSV export. Router discovery and BBMD registration are implemented but **not yet tested against real hardware**.
- **M3 GUI done**: live scan view, saved-scan browser, device/object/property tables with filter & sort, re-scan device, edit site/notes, JSON/CSV export & import, settings dialog, log panel.
- **M4 network survey done**: E1–E9 (link/MAC incl. randomized-MAC detection, DHCP, gateway, DNS, internet incl. VPN-route detection, public IP opt-in, BACnet device MACs + OUI vendor, ARP hosts, opt-in sweep ≤ /22); CLI `netinfo`, `scans show --network`, hosts CSV; GUI *Network* tab; DB migration for older databases. Wi-Fi SSID is hidden by macOS unless location access is granted. E10 (LLDP/CDP) moved to M5.
- **M5 done**: XLSX export (summary, devices, objects, network, hosts, BACnet traffic, sheet per device); scan diff (devices, device fields, objects, optional values, network, hosts by MAC) in CLI `scans diff` and GUI *Compare scans*; passive listen (D6) that never replies, CLI `listen` and GUI *Listen…*; LLDP/CDP switch port (E10) via tcpdump, decoded in Python, CLI `--lldp`, GUI checkbox.
- Not yet verified against real equipment: BBMD, BACnet routers / MS/TP, LLDP/CDP from a real switch (tested with an injected frame).
- Open: M6 `.app` bundle.

## 11. Decisions (answers to open questions, 2026-11-10)
1. MS/TP: reached via BACnet/IP routers only; no RS-485 adapter support.
2. Network size: 20–40 devices max per site.
3. Export formats: JSON + CSV + XLSX.
4. Strictly read-only, now and later.
5. Distribution: macOS `.app` bundle.
