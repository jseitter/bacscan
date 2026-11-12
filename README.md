# bacscan

Read-only BACnet/IP discovery and inventory tool for macOS. Plug into a site network,
find all BACnet devices (including MS/TP devices behind BACnet routers), read out device
details and objects, and keep every scan in a local database for later use.

See [SPEC.md](SPEC.md) for the full specification.

## Install the macOS app

```sh
./scripts/build_app.sh          # -> dist/bacscan.app and dist/bacscan-<version>.dmg
```

Copy `bacscan.app` to `/Applications` and double-click it for the GUI. The same app is the
command line tool:

```sh
sudo ln -sf /Applications/bacscan.app/Contents/MacOS/bacscan /usr/local/bin/bacscan
bacscan scan --site "Building A"
```

The build is ad-hoc signed, which is fine on the Mac that built it. Because an ad-hoc signature
changes with every build, macOS asks again for the firewall / *Local Network* permission after
each rebuild. To give the app to other Macs, sign it with a Developer ID and notarize it:

```sh
codesign --force --deep --options runtime --sign "Developer ID Application: <name> (<team>)" dist/bacscan.app
ditto -c -k --keepParent dist/bacscan.app bacscan.zip
xcrun notarytool submit bacscan.zip --keychain-profile <profile> --wait
xcrun stapler staple dist/bacscan.app
```

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
