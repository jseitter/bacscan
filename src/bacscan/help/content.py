"""Help topics and glossary. Light markup: blank line = new paragraph, '- ' = bullet, **bold**."""
from __future__ import annotations

# (id, title, body)
GUIDE: list[tuple[str, str, str]] = [
    ("start", "Getting started", """
bacscan finds BACnet devices on a network, reads them out and keeps every scan in a local database. It only reads: \
it sends Who-Is, ReadProperty and ReadPropertyMultiple and standard network queries. It never writes to a device.

**To scan**
- Pick the network interface, type a site name and press **Scan**.
- Devices appear as they answer. Select a device to see its objects, select an object to see all its properties.
- Every scan is saved and listed on the left. Double-click it to edit site and notes; right-click to export or delete.
- Right-click a device to re-scan only that device.

Press **F1** at any time. With an object selected, F1 explains that object's type.
"""),
    ("levels", "Scan levels", """
The level decides how much is read from each device. Higher levels take longer.

- **discover**: only Who-Is / I-Am. You get the list of devices, their address, vendor and limits, nothing is read.
- **device**: also reads the device object (name, model, firmware, supported services, clock, ...).
- **full** (default): also reads every object with its common properties (name, description, present value, units, \
status) plus a few per type, such as the schedule of a Schedule object.
- **all**: reads every property of every object. Most complete, slowest, and the most likely to hit devices that \
cannot answer very large requests.

Devices behind a BACnet router (for example MS/TP trunks) are read more gently, with a short pause between requests.
"""),
    ("results", "Reading the results", """
**Device status**
- **discovered**: the device answered Who-Is but has not been read yet (or the level was *discover*).
- **reading**: being read right now.
- **done**: everything requested was read.
- **partial**: some properties or objects could not be read; see the errors and the diagnostics of the device.
- **failed**: the device answered Who-Is but not the read requests.

**Columns**
- *Address* is the IP address and port; for devices behind a router it is the router's network and MAC.
- *Net* is the BACnet network number (empty = the local network).
- *MAC / MAC vendor* are the Ethernet address and its manufacturer, taken from the ARP table. For a device behind a \
router this is the router's MAC.

The **Properties** pane shows the properties of the selected device or object. Rows in brackets, like *(status)*, \
come from bacscan, not from the device. Right-click to copy a value or a row.
"""),
    ("diagnostics", "Scan diagnostics and troubleshooting", """
Each device keeps a record of how reading it went. You find it in the Properties pane of the device as \
*(diag: ...)* rows, with `bacscan scans show <id> -d <device>`, and in the site report for devices that had \
problems.

**What the entries mean**
- *requests*: how many were sent, how many got no answer (timeouts) and how many were refused.
- *read mode*: ReadPropertyMultiple (several properties per request) or plain ReadProperty. bacscan switches to \
the slower mode when a device refuses or aborts the faster one.
- *object list*: whether the list of objects came in one request, as a segmented reply, or one object at a time.
- *slow request*: the slowest requests; *last request*: what was being asked when a device stopped answering.

**Typical causes**
- **Small max APDU (e.g. 480).** Replies must fit into 480 bytes. A long object list or a weekly schedule does not. \
If the device can segment, the reply is split; if not, bacscan reads element by element.
- **No answer to large requests.** Some devices stay silent instead of returning an error. bacscan waits for the \
timeout and falls back to smaller requests.
- **Behind a router (MS/TP).** Slow trunks mean long waits; raise the timeout in *Scan → Settings*.
- **Duplicate device instance.** Two devices with the same number confuse tools; it is reported as a finding.
"""),
    ("network", "Network environment and hosts", """
Besides BACnet, every scan records the IP network around it: interface and MAC, DHCP (server, lease, offered router \
and DNS), gateway, DNS, internet access, and all hosts in the ARP table with the MAC vendor. BACnet devices are marked.

- **Subnet sweep** probes every address of the local subnet (up to /22) so the ARP table is complete.
- **Deep discovery** also checks ping, a list of building and IT TCP ports, web page titles, banners, mDNS, UPnP and \
NetBIOS names, and guesses what each host is. It contacts every address: use it only where you are allowed to scan.
- **Switch port** waits for an LLDP/CDP frame to learn which switch port you are plugged into. It is passive and \
needs packet-capture rights.
"""),
    ("findings", "Findings", """
Findings are hints derived from what the scan saw, rated **critical**, **warning** or **info**. Examples are \
duplicate device instances, devices that are not readable, open Telnet or FTP, Niagara Fox without TLS, unauthenticated \
control protocols and SNMP v1/v2c.

They are observations, not a security audit: a clean list does not mean a network is secure.
"""),
    ("reports", "Reports and comparing scans", """
**Site report** (*File → Create site report*, or `bacscan scans report`) is a PDF or HTML document with a summary, \
findings, network environment, devices, schedules, hosts and SNMP data. Optionally it appends every device's object list.

**Change report** compares two scans and lists devices, objects, properties, network and hosts that were added, \
removed or changed, plus findings that appeared or disappeared. Open *Compare scans* and press \
*Save change report*, or use `bacscan scans diff <older> <newer> -o changes.pdf`.

Present values are only compared when you ask for it, because they change all the time.

Other exports: JSON (everything, can be imported again), CSV, Excel and a hosts CSV.
"""),
    ("schedules", "Schedules", """
Double-click a Schedule object (or right-click, *Show schedule...*) to see it as a week grid: for each day the \
times and the value that applies from then on.

- **null** means the schedule stops writing: the target falls back to other priorities or its default.
- **Exceptions** override the weekly schedule on special days; the priority decides which exception wins.
- **Controls** lists what the schedule writes to, with names resolved from the same device.
- **Default value** applies when nothing else matches. **Effective period** limits the dates it runs.

Days that could not be read are marked *not readable*; the device probably cannot return them in one APDU.
"""),
    ("snmp", "SNMP", """
SNMP is optional and read-only. Enter credentials (v2c community or v3 user) in the SNMP dialog and choose what to \
query: given addresses, the gateway and LLDP/CDP switch, or every host found. bacscan reads system data, model and \
serial, switch ports and LLDP neighbours, and uses them to show which switch port each device is on.

Credentials are kept in memory only and never stored in the database.
"""),
    ("sc", "BACnet/SC", """
BACnet Secure Connect runs over TLS and WebSocket instead of UDP. Instead of broadcasting, a node joins a **hub**. \
Configure the hub URL, the operational certificate and key and the CA certificate in the BACnet/SC dialog. \
With *direct connect* bacscan can also connect straight to devices that offer it.
"""),
    ("safety", "Safety and scope", """
bacscan is read-only: it does not write properties, change objects or reinitialize devices. It still generates \
traffic. Some very old or small controllers react badly to many requests, so on a live site start with level \
*device*, keep the default concurrency, and scan outside critical hours when in doubt.

Only scan networks you are authorised to scan.
"""),
]

# term -> explanation
GLOSSARY: dict[str, str] = {
    "APDU": "Application Protocol Data Unit: one BACnet message. Its maximum size (50 to 1476 bytes) is announced by "
            "each device as max-apdu-length-accepted.",
    "BBMD": "BACnet Broadcast Management Device: forwards broadcasts between IP subnets. Devices on other subnets can "
            "register with it as foreign devices.",
    "BACnet/IP": "BACnet over UDP, normally port 47808 (0xBAC0).",
    "BACnet/SC": "BACnet Secure Connect: BACnet over TLS and WebSocket, through a hub.",
    "MS/TP": "Master-Slave/Token-Passing: BACnet over RS-485 twisted pair. Slow, so reading takes longer.",
    "Who-Is / I-Am": "Who-Is is the broadcast asking for devices; each device answers with an I-Am that carries its "
                     "instance number, max APDU, segmentation and vendor.",
    "Device instance": "The unique number of a device (0 to 4194302) across the whole BACnet internetwork.",
    "Object instance": "Number of an object within its device and type. analog-input,3 is the third analog input.",
    "Network number": "Number of a BACnet network (1-65534). Routers connect networks with different numbers.",
    "Router": "Connects BACnet networks, e.g. IP to MS/TP. Devices behind it have a network number and a MAC.",
    "ReadProperty (RP)": "Reads one property of one object.",
    "ReadPropertyMultiple (RPM)": "Reads several properties of several objects in one request. Faster, but replies "
                                  "can exceed a small APDU.",
    "Segmentation": "Splitting a message that is bigger than the APDU into numbered segments. Both sides must support it.",
    "COV": "Change Of Value: a device pushes a notification when a value changes by more than cov-increment. bacscan "
           "does not subscribe, it only reads.",
    "Priority array": "16 command slots of an output, 1 = most important. The value of the highest occupied slot wins. "
                      "Writing null releases (relinquishes) a slot.",
    "Commandable": "An object whose present value can be written with a priority (has a priority-array).",
    "Out of service": "An object disconnected from its hardware so its value can be set by hand.",
    "Intrinsic reporting": "Alarm detection built into an object (limits, deadband, notification class), as opposed to "
                           "a separate Event Enrollment object.",
    "VMAC": "Virtual MAC address used by BACnet/SC nodes instead of an IP address.",
    "Vendor ID": "Number assigned by ASHRAE to each manufacturer.",
    "Protocol revision": "The edition of the BACnet standard a device implements; later revisions add object types "
                         "and services.",
}
