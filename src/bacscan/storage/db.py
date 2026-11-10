"""Local SQLite storage for scans."""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path

from ..core.models import BacnetObject, Device, Host, PropValue, Router, Scan

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    site          TEXT NOT NULL DEFAULT '',
    notes         TEXT NOT NULL DEFAULT '',
    interface     TEXT NOT NULL DEFAULT '',
    local_address TEXT NOT NULL DEFAULT '',
    level         TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT '',
    settings_json TEXT NOT NULL DEFAULT '{}',
    routers_json  TEXT NOT NULL DEFAULT '[]',
    tool_version  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS device (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    instance      INTEGER NOT NULL,
    address       TEXT NOT NULL,
    network       INTEGER,
    mac           TEXT,
    router        TEXT,
    vendor_id     INTEGER,
    vendor_name   TEXT,
    model_name    TEXT,
    object_name   TEXT,
    firmware      TEXT,
    app_version   TEXT,
    max_apdu      INTEGER,
    segmentation  TEXT,
    first_seen    TEXT,
    status        TEXT,
    props_json    TEXT NOT NULL DEFAULT '{}',
    errors_json   TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS device_scan ON device(scan_id);
CREATE TABLE IF NOT EXISTS object (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     INTEGER NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    object_type   TEXT NOT NULL,
    instance      INTEGER NOT NULL,
    object_name   TEXT,
    description   TEXT,
    present_value TEXT,
    units         TEXT,
    props_json    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS object_device ON object(device_id);
CREATE TABLE IF NOT EXISTS host (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    ip              TEXT NOT NULL,
    mac             TEXT,
    vendor          TEXT,
    hostname        TEXT,
    bacnet_instance INTEGER,
    source          TEXT,
    note            TEXT
);
CREATE INDEX IF NOT EXISTS host_scan ON host(scan_id);
"""

# columns added after v0.1 databases were created: (table, column, definition)
MIGRATIONS = [
    ("scan", "network_json", "TEXT NOT NULL DEFAULT '{}'"),
    ("device", "eth_mac", "TEXT"),
    ("device", "eth_vendor", "TEXT NOT NULL DEFAULT ''"),
    ("device", "eth_mac_source", "TEXT NOT NULL DEFAULT ''"),
]


def default_db_path() -> Path:
    env = os.environ.get("BACSCAN_DB")
    if env:
        return Path(env).expanduser()
    return Path.home() / "Library" / "Application Support" / "bacscan" / "bacscan.db"


@dataclass
class ScanSummary:
    id: int
    started_at: str
    site: str
    status: str
    level: str
    interface: str
    devices: int
    objects: int
    notes: str


def _props_to_json(props: dict[str, PropValue]) -> str:
    return json.dumps({k: asdict(v) for k, v in props.items()}, ensure_ascii=False)


def _props_from_json(s: str) -> dict[str, PropValue]:
    return {k: PropValue.from_dict(v) for k, v in json.loads(s or "{}").items()}


class Store:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path).expanduser() if path else default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        with self.conn:
            for table, column, definition in MIGRATIONS:
                cols = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
                if column not in cols:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- write

    def save(self, scan: Scan) -> int:
        """Insert a scan (or replace it if scan.id is set). Returns the id."""
        with self.conn:
            if scan.id is not None:
                self.conn.execute("DELETE FROM scan WHERE id = ?", (scan.id,))
            cur = self.conn.execute(
                """INSERT INTO scan (id, started_at, finished_at, site, notes, interface, local_address,
                                     level, status, settings_json, routers_json, tool_version, network_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan.id, scan.started_at, scan.finished_at, scan.site, scan.notes, scan.interface,
                 scan.local_address, scan.level, scan.status, json.dumps(scan.settings),
                 json.dumps([asdict(r) for r in scan.routers]), scan.tool_version,
                 json.dumps(scan.network, ensure_ascii=False)),
            )
            scan.id = cur.lastrowid
            self.conn.executemany(
                """INSERT INTO host (scan_id, ip, mac, vendor, hostname, bacnet_instance, source, note)
                   VALUES (?,?,?,?,?,?,?,?)""",
                [(scan.id, h.ip, h.mac, h.vendor, h.hostname, h.bacnet_instance, h.source, h.note)
                 for h in scan.hosts],
            )
            for d in scan.devices:
                dcur = self.conn.execute(
                    """INSERT INTO device (scan_id, instance, address, network, mac, router, vendor_id,
                           vendor_name, model_name, object_name, firmware, app_version, max_apdu,
                           segmentation, first_seen, status, props_json, errors_json,
                           eth_mac, eth_vendor, eth_mac_source)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (scan.id, d.instance, d.address, d.network, d.mac, d.router, d.vendor_id,
                     d.text("vendor-name"), d.text("model-name"), d.name, d.text("firmware-revision"),
                     d.text("application-software-version"), d.max_apdu, d.segmentation,
                     d.first_seen, d.status, _props_to_json(d.props), json.dumps(d.errors),
                     d.eth_mac, d.eth_vendor, d.eth_mac_source),
                )
                self.conn.executemany(
                    """INSERT INTO object (device_id, object_type, instance, object_name, description,
                           present_value, units, props_json) VALUES (?,?,?,?,?,?,?,?)""",
                    [(dcur.lastrowid, o.object_type, o.instance, o.name, o.text("description"),
                      o.text("present-value"), o.text("units"), _props_to_json(o.props))
                     for o in d.objects],
                )
        return scan.id

    def update_meta(self, scan_id: int, site: str | None = None, notes: str | None = None) -> None:
        with self.conn:
            if site is not None:
                self.conn.execute("UPDATE scan SET site = ? WHERE id = ?", (site, scan_id))
            if notes is not None:
                self.conn.execute("UPDATE scan SET notes = ? WHERE id = ?", (notes, scan_id))

    def delete(self, scan_id: int) -> bool:
        with self.conn:
            return self.conn.execute("DELETE FROM scan WHERE id = ?", (scan_id,)).rowcount > 0

    # -- read

    def list(self) -> list[ScanSummary]:
        rows = self.conn.execute(
            """SELECT s.*, (SELECT COUNT(*) FROM device d WHERE d.scan_id = s.id) AS n_dev,
                      (SELECT COUNT(*) FROM object o JOIN device d ON o.device_id = d.id
                        WHERE d.scan_id = s.id) AS n_obj
               FROM scan s ORDER BY s.started_at DESC, s.id DESC"""
        ).fetchall()
        return [ScanSummary(r["id"], r["started_at"], r["site"], r["status"], r["level"],
                            r["interface"], r["n_dev"], r["n_obj"], r["notes"]) for r in rows]

    def load(self, scan_id: int) -> Scan:
        r = self.conn.execute("SELECT * FROM scan WHERE id = ?", (scan_id,)).fetchone()
        if r is None:
            raise KeyError(f"scan {scan_id} not found")
        scan = Scan(
            id=r["id"], started_at=r["started_at"], finished_at=r["finished_at"], site=r["site"],
            notes=r["notes"], interface=r["interface"], local_address=r["local_address"],
            level=r["level"], status=r["status"], settings=json.loads(r["settings_json"]),
            tool_version=r["tool_version"],
            routers=[Router(**x) for x in json.loads(r["routers_json"])],
            network=json.loads(r["network_json"] or "{}"),
            hosts=[Host(ip=h["ip"], mac=h["mac"] or "", vendor=h["vendor"] or "", hostname=h["hostname"] or "",
                        bacnet_instance=h["bacnet_instance"], source=h["source"] or "", note=h["note"] or "")
                   for h in self.conn.execute("SELECT * FROM host WHERE scan_id = ? ORDER BY id", (scan_id,))],
        )
        for d in self.conn.execute("SELECT * FROM device WHERE scan_id = ? ORDER BY instance", (scan_id,)):
            dev = Device(
                instance=d["instance"], address=d["address"], network=d["network"], mac=d["mac"],
                router=d["router"], vendor_id=d["vendor_id"], max_apdu=d["max_apdu"],
                segmentation=d["segmentation"], first_seen=d["first_seen"], status=d["status"],
                props=_props_from_json(d["props_json"]), errors=json.loads(d["errors_json"]),
                eth_mac=d["eth_mac"], eth_vendor=d["eth_vendor"] or "", eth_mac_source=d["eth_mac_source"] or "",
            )
            for o in self.conn.execute(
                "SELECT * FROM object WHERE device_id = ? ORDER BY id", (d["id"],)
            ):
                dev.objects.append(BacnetObject(o["object_type"], o["instance"], _props_from_json(o["props_json"])))
            scan.devices.append(dev)
        return scan

    def latest_id(self) -> int | None:
        r = self.conn.execute("SELECT id FROM scan ORDER BY started_at DESC, id DESC LIMIT 1").fetchone()
        return r["id"] if r else None
