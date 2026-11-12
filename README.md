# bacscan

Read-only BACnet/IP discovery and inventory tool for macOS. Plug into a site network,
find all BACnet devices (including MS/TP devices behind BACnet routers), read out device
details and objects, and keep every scan in a local database for later use.

See [SPEC.md](SPEC.md) for the full specification.

## Install the macOS app

```sh
./scripts/build_pkg.sh --rebuild   # -> dist/bacscan-<version>.pkg (+ dist/bacscan.app and a .dmg)
```

Double-click the `.pkg` (or `sudo installer -pkg dist/bacscan-0.1.0.pkg -target /`). It installs
`bacscan.app` into `/Applications` and the command `bacscan` into `/usr/local/bin`, so both work:

```sh
open -a bacscan                     # GUI
bacscan scan --site "Building A"    # command line
```

Without the installer: copy `bacscan.app` from the `.dmg` to `/Applications` and link the
command yourself: `sudo ln -sf /Applications/bacscan.app/Contents/MacOS/bacscan /usr/local/bin/bacscan`.

Uninstall (keeps your saved scans; add `--purge` to delete them and the settings too):

```sh
sudo /Applications/bacscan.app/Contents/Resources/uninstall.sh
```

### Signing for other Macs

Local builds are ad-hoc signed: fine on the Mac that built them, but macOS asks again for the
firewall / *Local Network* permission after each rebuild, and other Macs need right-click →
*Open* the first time. For distribution, sign with your Developer ID certificates and notarize:

```sh
export BACSCAN_APP_IDENTITY="Developer ID Application: <name> (<team>)"
export BACSCAN_INSTALLER_IDENTITY="Developer ID Installer: <name> (<team>)"
./scripts/build_pkg.sh --rebuild
xcrun notarytool submit dist/bacscan-0.1.0.pkg --keychain-profile <profile> --wait
xcrun stapler staple dist/bacscan-0.1.0.pkg
```

The app is signed with the hardened runtime and `packaging/entitlements.plist` (needed by the
embedded Python). Developer ID signing has not been tested yet.

## Setup (development)

```sh
uv sync
uv run bacscan --help
```

## GUI

```sh
uv run bacscan gui        # or: uv run bacscan-gui
```

Pick the interface, enter a site name, press **Scan**. Devices appear as they answer; select a
device to see its objects, select an object to see all its properties. Every scan is saved and
listed on the left (double-click to edit site/notes, right-click to export or delete).
Right-click a device to re-scan just that device. *Scan → Settings* holds timeouts and
parallelism; *View → Log* shows what happens on the wire.

## Network environment

Every scan also records the surrounding IP network: interface and MAC address, DHCP
(server, lease, offered router/DNS/NTP), gateway (ping, MAC, vendor), DNS resolvers and a
test lookup, internet access (none / DNS only / full / captive portal, and whether traffic
leaves via a VPN), and all hosts in the ARP table with MAC vendor - BACnet devices marked.
In the GUI this is the **Network** tab.

```sh
uv run bacscan netinfo                     # survey only, no BACnet
uv run bacscan scan --sweep                # also probe the whole subnet (max /22) to find all hosts
uv run bacscan scan --public-ip            # also look up the public IP (contacts api.ipify.org)
uv run bacscan scan --no-network-info      # BACnet only
uv run bacscan scans show latest --network
uv run bacscan scans export latest -f hosts -o hosts.csv
```

**Deep discovery** (`--deep`, GUI: *Deep discovery* checkbox) goes further and identifies every
host on the local subnet (max /22), layer by layer: ARP, ping (round-trip time and TTL as an OS
hint), a TCP connect check of building and IT ports (HTTP(S), SSH, Telnet, Modbus, S7, Niagara
Fox, OPC UA, MQTT, RDP, SMB, printers, cameras …), web page titles, server headers and TLS
certificate names, SSH/FTP banners, Bonjour/mDNS services, UPnP device descriptions and NetBIOS
names. Each host gets a best-guess kind (e.g. *Niagara station*, *Modbus TCP device*, *printer*).
It only sends queries — no logins, no writes — but it does contact every address, so use it
only where you are allowed to scan. A /24 takes about 10–30 s.

```sh
uv run bacscan netinfo --deep              # survey + deep discovery, no BACnet
uv run bacscan scan --deep                 # BACnet scan plus deep discovery
uv run bacscan scan --deep --ports 80,443,502,1911,4911,47808   # own port list ('none' = no TCP)
uv run bacscan scans show latest --network # hosts table plus per-host service details
```

Switch port (which switch, port and VLAN you are plugged into) is read from LLDP/CDP
announcements, passively: `--lldp` (GUI: *Switch port* checkbox) waits up to 35 s. This needs
packet-capture rights: run with `sudo`, or install Wireshark (its *ChmodBPF* lets your user capture).

MAC vendors come from a bundled offline list (`src/bacscan/data/oui.tsv.gz`, from Wireshark's
`manuf`); refresh it with `uv run python scripts/update_oui.py`.

## SNMP (switch ports)

With SNMP credentials from the customer, bacscan reads switches, routers and other agents -
system info, model/serial, interfaces, LLDP neighbours and the MAC forwarding tables - and
shows **which switch port every BACnet device and host is plugged into**. Read-only: only
GET / GETNEXT / GETBULK; v2c, or v3 with SHA/SHA-256/MD5 authentication and AES privacy.
Credentials are never saved; pass secrets via environment variables to keep them out of
your shell history.

```sh
uv run bacscan snmp 10.0.0.2 -c COMMUNITY                       # one switch, all tables
export BACSCAN_SNMP_AUTH=… BACSCAN_SNMP_PRIV=…
uv run bacscan snmp 10.0.0.0/28 -u monitor --auth-proto SHA --priv-proto AES
uv run bacscan scan --snmp 10.0.0.2 --snmp-auto -u monitor     # with the scan: + gateway + LLDP switch
uv run bacscan netinfo --deep --snmp-auto --community COMMUNITY
```

GUI: tick *SNMP* and enter credentials and targets in *SNMP…*; the switch port appears in the
device and host tables, the agents on the *Network* tab, in Excel (*SNMP* sheets) and the report.

## Site report

A report for the customer or the project file, made from any saved scan: summary, findings
(duplicate device instances, unreadable devices, Telnet/FTP/HTTP-only web interfaces, open
Modbus/S7, Niagara Fox without TLS, self-signed certificates, internet/gateway problems …),
network environment, BACnet devices, routers, object counts, hosts and services.
Findings are hints from what the scan saw, not a security audit.

```sh
uv run bacscan scans report latest -o site.pdf                 # A4 PDF with page numbers
uv run bacscan scans report 12 -o site.html --objects --author "Name, Company"
```

GUI: *File → Create site report…* (Ctrl+P).

## Listen mode, comparing scans, Excel

```sh
uv run bacscan listen -d 120 --site "Building A"   # passive: record BACnet broadcasts, send nothing
uv run bacscan scans diff 12 latest                 # what changed between two visits
uv run bacscan scans diff 12 latest --values        # ... including present values
uv run bacscan scans export latest -o building-a.xlsx
```

Listen mode never answers anything (not even Who-Is), so it is safe on sensitive networks. On a
switched network it only hears broadcasts: who is searching (BMS head-ends send Who-Is), I-Am
answers, time synchronisation, unconfirmed COV/event notifications.

The Excel file has a summary, a devices sheet, all objects, network, hosts, and one sheet per
device. In the GUI: *File → Compare scans…*, *File → Export scan as Excel…*, and **Listen…**.

## Command line

```sh
uv run bacscan interfaces                 # which network port will be used?
uv run bacscan scan --site "Building A"   # discover + full read-out, saved automatically
uv run bacscan scans list
uv run bacscan scans show latest          # device overview
uv run bacscan scans show latest -d 1001  # one device with all its objects
uv run bacscan scans export latest -o building-a.csv
```

Useful scan options:

| Option | Meaning |
|--------|---------|
| `-i en5` | use a specific interface (e.g. USB Ethernet adapter) |
| `-l discover\|device\|full\|all` | how deep to read (default `full`) |
| `-t 10` | wait longer for answers on slow networks |
| `-r 1000-1999` | only device instances in this range |
| `--target 10.1.2.0/24` | unicast Who-Is when broadcasts are blocked |
| `--bbmd 10.1.1.1` | register at a BBMD to reach other subnets |
| `-o scan.json` | also export the result directly |

Ctrl+C during a scan stops it and keeps (and saves) everything read so far.

Scans are stored in `~/Library/Application Support/bacscan/bacscan.db`
(override with `--db FILE` or `BACSCAN_DB`).

## macOS notes

- On first run macOS may ask whether Python may accept incoming network connections — allow it,
  otherwise device answers are blocked.
- Only one program can use UDP port 47808. If another BACnet tool is running, bacscan tells you
  and suggests another port. With a non-standard port, devices that answer by broadcast may be missed.

## Tests

```sh
uv run pytest
```

Tests run a simulated BACnet device on the loopback interface; no network access needed.
`uv run python tests/sim_device.py` starts the simulator by hand.
