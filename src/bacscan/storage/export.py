"""Export / import of scans (JSON full fidelity, CSV one row per object)."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from ..core.models import Scan

FORMAT_VERSION = 1

CSV_COLUMNS = [
    "device_instance", "device_name", "device_address", "network", "vendor", "model",
    "firmware", "device_mac", "device_mac_vendor", "object_type", "object_instance", "object_name", "description",
    "present_value", "units", "status_flags", "reliability", "out_of_service", "other_properties",
]
_MAIN = {"object-name", "description", "present-value", "units", "status-flags",
         "reliability", "out-of-service"}


def export_json(scan: Scan, path: str | Path) -> None:
    data = {"format": "bacscan", "format_version": FORMAT_VERSION, "scan": scan.to_dict()}
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def import_json(path: str | Path) -> Scan:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != "bacscan":
        raise ValueError(f"{path} is not a bacscan JSON export")
    scan = Scan.from_dict(data["scan"])
    scan.id = None  # gets a new id in the target database
    return scan


def export_csv(scan: Scan, path: str | Path) -> int:
    """One row per object (devices without objects get one row). Returns row count."""
    rows = 0
    with open(path, "w", newline="", encoding="utf-8-sig") as f:  # BOM: Excel-friendly
        w = csv.writer(f, delimiter=";")
        w.writerow(CSV_COLUMNS)
        for d in scan.devices:
            base = [d.instance, d.name, d.address, d.network if d.network is not None else "",
                    d.text("vendor-name") or d.vendor_id or "", d.text("model-name"),
                    d.text("firmware-revision"), d.eth_mac or "",
                    (d.eth_vendor + (" (router)" if d.eth_mac_source == "router" else "")).strip()]
            if not d.objects:
                w.writerow(base + [""] * (len(CSV_COLUMNS) - len(base)))
                rows += 1
            for o in d.objects:
                other = "; ".join(f"{k}={v.text if v.error is None else 'ERR ' + v.error}"
                                  for k, v in o.props.items() if k not in _MAIN)
                w.writerow(base + [o.object_type, o.instance, o.name, o.text("description"),
                                   o.text("present-value"), o.text("units"), o.text("status-flags"),
                                   o.text("reliability"), o.text("out-of-service"), other])
                rows += 1
    return rows


HOST_COLUMNS = ["ip", "mac", "mac_vendor", "hostname", "bacnet_instance", "bacnet_device_name", "note", "source"]


def export_hosts_csv(scan: Scan, path: str | Path) -> int:
    """All hosts seen on the network (E8), BACnet devices marked. Returns row count."""
    names = {d.instance: d.name for d in scan.devices}
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(HOST_COLUMNS)
        for h in scan.hosts:
            w.writerow([h.ip, h.mac, h.vendor, h.hostname,
                        "" if h.bacnet_instance is None else h.bacnet_instance,
                        names.get(h.bacnet_instance, "") if h.bacnet_instance is not None else "",
                        h.note, h.source])
    return len(scan.hosts)
