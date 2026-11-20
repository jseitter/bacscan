"""Value rendering: AnyAtomic inside schedules is unwrapped."""
from bacpypes3.basetypes import DailySchedule, TimeValue
from bacpypes3.constructeddata import AnyAtomic
from bacpypes3.primitivedata import Null, Real, Time

from bacscan.core.values import to_json, to_text


def test_schedule_values_decoded():
    ds = DailySchedule(daySchedule=[
        TimeValue(time=Time("08:00:00"), value=AnyAtomic(Real(21.5))),
        TimeValue(time=Time("18:00:00"), value=AnyAtomic(Null(()))),
    ])
    j = to_json(ds)
    assert j["daySchedule"][0]["value"] == 21.5
    assert j["daySchedule"][1]["value"] is None
    t = to_text(ds)
    assert "AnyAtomic" not in t and "real" not in t and "21.5" in t


def test_weekly_schedule_read_per_day():
    import asyncio

    from bacscan.core.models import Device, PropValue
    from bacscan.core.scanner import DeviceReader, ScanConfig, weekly_text

    calls = []
    day = {"daySchedule": [{"time": "08:00:00.00", "value": 21.5}, {"time": "18:00:00.00", "value": None}]}

    class R(DeviceReader):
        def __init__(self):
            self.cfg = ScanConfig()
            self.device = Device(instance=1, address="x", segmentation="no-segmentation")

        async def rp(self, objid, prop, index=None):
            calls.append(index)
            if index == 0:
                return PropValue(value=7, text="7")
            if index == 3:
                return PropValue(error="abort: buffer-overflow")
            return PropValue(value=day, text="")

    pv = asyncio.run(R().read_array_prop(("schedule", 1), "weekly-schedule"))
    assert calls == [0, 1, 2, 3, 4, 5, 6, 7] and None not in calls
    assert pv.error is None and len(pv.value) == 7 and pv.value[2] is None
    assert "Mon: 08:00=21.5, 18:00=null" in pv.text and "Wed: ?" in pv.text and "unreadable: [3]" in pv.text
    assert weekly_text([day]) == "Mon: 08:00=21.5, 18:00=null"
