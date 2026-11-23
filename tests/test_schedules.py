"""Schedule view: parsing, report section, dialog."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from bacpypes3.basetypes import CalendarEntry, DailySchedule, DateRange, DeviceObjectPropertyReference, SpecialEvent, TimeValue  # noqa: E402
from bacpypes3.constructeddata import AnyAtomic  # noqa: E402
from bacpypes3.primitivedata import Date, Null, Real, Time  # noqa: E402

from bacscan.core.models import BacnetObject, Device, PropValue, Scan  # noqa: E402
from bacscan.core.schedules import parse_schedule  # noqa: E402
from bacscan.core.scanner import weekly_text  # noqa: E402
from bacscan.core.values import to_json, to_text  # noqa: E402
from bacscan.storage import report  # noqa: E402


def _pv(v):
    return PropValue(value=to_json(v), text=to_text(v))


def make_device() -> Device:
    work = DailySchedule(daySchedule=[TimeValue(time=Time("07:30:00"), value=AnyAtomic(Real(21.5))),
                                      TimeValue(time=Time("18:00:00"), value=AnyAtomic(Null(())))])
    free = DailySchedule(daySchedule=[])
    exc = SpecialEvent(period=SpecialEvent._elements["period"](calendarEntry=CalendarEntry(date=Date("2026-12-24"))),
                       listOfTimeValues=[TimeValue(time=Time("00:00:00"), value=AnyAtomic(Real(16.0)))],
                       eventPriority=5)
    ref = DeviceObjectPropertyReference(objectIdentifier=("analog-value", 3), propertyIdentifier="present-value")
    props = {
        "object-name": PropValue(value="Office hours", text="Office hours"),
        "present-value": PropValue(value=21.5, text="21.5"),
        "schedule-default": PropValue(value=16.0, text="16"),
        "weekly-schedule": PropValue(value=[to_json(work)] * 5 + [to_json(free)] * 2, text=""),
        "exception-schedule": PropValue(value=[to_json(exc)], text=""),
        "list-of-object-property-references": PropValue(value=[to_json(ref)], text=""),
    }
    sched = BacnetObject("schedule", 1, props)
    av = BacnetObject("analog-value", 3, {"object-name": PropValue(value="Setpoint", text="Setpoint")})
    return Device(instance=1001, address="10.0.0.5", props={"object-name": PropValue(value="AHU", text="AHU")},
                  objects=[sched, av], status="done")


def test_parse_schedule():
    d = make_device()
    v = parse_schedule(d.objects[0], d)
    assert v.name == "Office hours" and v.default == "16"
    assert v.days[0] == [("07:30", "21.5"), ("18:00", "null")] and v.days[6] == []
    assert v.exceptions[0].period.startswith("2026-12-24") and v.exceptions[0].priority == 5
    assert v.exceptions[0].entries == [("00:00", "16")]
    assert v.controls == ["analog-value,3 Setpoint · present-value"]
    assert weekly_text(d.objects[0].props["weekly-schedule"].value[:1]) == "Mon: 07:30=21.5, 18:00=null"


def test_parse_schedule_unreadable():
    o = BacnetObject("schedule", 2, {"weekly-schedule": PropValue(error="abort: buffer-overflow")})
    v = parse_schedule(o)
    assert not v.has_weekly and v.errors


def test_report_has_schedules():
    scan = Scan(site="X", devices=[make_device()])
    html = report.build_html(scan)
    assert "<h2>Schedules</h2>" in html and "07:30 → 21.5" in html and "Setpoint" in html


def test_schedule_dialog():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841
    from bacscan.gui.schedule_dialog import ScheduleDialog
    d = make_device()
    dlg = ScheduleDialog(parse_schedule(d.objects[0], d), "device 1001 AHU")
    assert dlg.grid.item(0, 0).text() == "07:30  →  21.5"
    assert dlg.grid.item(0, 6).text() == "—"
    assert dlg.exceptions.topLevelItemCount() == 1 and dlg.controls.count() == 1
