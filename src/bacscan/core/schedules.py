"""Readable view of Schedule objects (weekly / exception schedule, default, controlled properties)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import BacnetObject, Device, Scan

DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

Entry = tuple[str, str]  # (time "08:00", value "21.5")


@dataclass
class ExceptionView:
    period: str
    priority: int | None
    entries: list[Entry] = field(default_factory=list)


@dataclass
class ScheduleView:
    key: str
    name: str
    description: str = ""
    present_value: str = ""
    effective: str = ""
    default: str = ""
    priority_for_writing: str = ""
    days: list[list[Entry] | None] = field(default_factory=list)  # 7 days Mon..Sun; None = not readable
    exceptions: list[ExceptionView] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_weekly(self) -> bool:
        return any(d is not None for d in self.days)


def fmt_time(t: Any) -> str:
    s = str(t or "")
    head = s.split(".")[0]  # 08:00:00.00 -> 08:00:00
    parts = head.split(":")
    if len(parts) == 3 and parts[2] == "00":
        return ":".join(parts[:2])
    return head or "?"


def fmt_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "on" if v else "off"
    if isinstance(v, float):
        return f"{v:g}"
    return str(v)


def _entries(items: Any) -> list[Entry]:
    out: list[Entry] = []
    for e in items or []:
        if isinstance(e, dict):
            out.append((fmt_time(e.get("time")), fmt_value(e.get("value"))))
    return out


def _period(p: Any) -> str:
    if not isinstance(p, dict):
        return str(p or "")
    if "calendarReference" in p:
        return f"calendar {str(p['calendarReference']).split(',')[-1]}"
    entry = p.get("calendarEntry", p)
    if not isinstance(entry, dict):
        return str(entry)
    if "date" in entry:
        return str(entry["date"])
    if "dateRange" in entry:
        r = entry["dateRange"]
        return f"{r.get('startDate', '?')} – {r.get('endDate', '?')}" if isinstance(r, dict) else str(r)
    if "weekNDay" in entry:
        return f"week-and-day {entry['weekNDay']}"
    return ", ".join(f"{k}={v}" for k, v in entry.items())


def _prop(o: BacnetObject, name: str) -> Any:
    p = o.props.get(name)
    return p.value if p is not None and p.error is None else None


def parse_schedule(o: BacnetObject, device: Device | None = None) -> ScheduleView:
    names = {x.key: x.name for x in device.objects} if device else {}
    v = ScheduleView(key=o.key, name=o.name, description=o.text("description"),
                     present_value=o.text("present-value"), effective=o.text("effective-period"),
                     default=o.text("schedule-default"), priority_for_writing=o.text("priority-for-writing"))
    weekly = _prop(o, "weekly-schedule")
    if isinstance(weekly, list):
        for i in range(7):
            day = weekly[i] if i < len(weekly) else None
            v.days.append(_entries(day.get("daySchedule")) if isinstance(day, dict) else None)
    elif "weekly-schedule" in o.props and o.props["weekly-schedule"].error:
        v.errors.append(f"weekly-schedule: {o.props['weekly-schedule'].error}")
    exc = _prop(o, "exception-schedule")
    for e in exc if isinstance(exc, list) else []:
        if isinstance(e, dict):
            v.exceptions.append(ExceptionView(period=_period(e.get("period")), priority=e.get("eventPriority"),
                                              entries=_entries(e.get("listOfTimeValues"))))
    refs = _prop(o, "list-of-object-property-references")
    for r in refs if isinstance(refs, list) else []:
        if not isinstance(r, dict):
            continue
        oid = str(r.get("objectIdentifier", ""))
        text = f"{oid} {names[oid]}".strip() if oid in names else oid
        text += f" · {r['propertyIdentifier']}" if r.get("propertyIdentifier") else ""
        if r.get("deviceIdentifier"):
            text += f" @ {r['deviceIdentifier']}"
        v.controls.append(text)
    return v


def device_schedules(d: Device) -> list[ScheduleView]:
    return [parse_schedule(o, d) for o in d.objects if o.object_type == "schedule"]


def scan_schedules(scan: Scan) -> list[tuple[Device, ScheduleView]]:
    return [(d, s) for d in scan.devices for s in device_schedules(d)]
