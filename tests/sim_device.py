"""Simulated BACnet/IP device for local testing.

Run:  uv run python tests/sim_device.py --address 127.0.0.1/8:47809 --instance 1001
"""
from __future__ import annotations

import argparse
import asyncio
import types

from bacpypes3.app import Application
from bacpypes3.local.analog import AnalogInputObject, AnalogValueObject
from bacpypes3.local.binary import BinaryValueObject
from bacpypes3.local.multistate import MultiStateValueObject
from bacpypes3.primitivedata import Real


def build_app(address: str, instance: int, n_analog: int = 5) -> Application:
    args = types.SimpleNamespace(
        name=f"SimDevice-{instance}",
        instance=instance,
        network=0,
        address=address,
        vendoridentifier=999,
        foreign=None,
        ttl=30,
        bbmd=None,
    )
    app = Application.from_args(args)
    dev = app.device_object
    dev.description = "bacscan test simulator"
    dev.location = "Lab rack 1"
    dev.modelName = "SIM-1000"
    dev.firmwareRevision = "1.2.3"
    dev.applicationSoftwareVersion = "4.5.6"
    dev.vendorName = "bacscan"

    for i in range(1, n_analog + 1):
        app.add_object(
            AnalogInputObject(
                objectIdentifier=("analog-input", i),
                objectName=f"Room{i:02d}.Temp",
                description=f"Room {i} temperature",
                presentValue=Real(20.0 + i / 2),
                units="degrees-celsius",
                statusFlags=[0, 0, 0, 0],
                eventState="normal",
                outOfService=False,
                reliability="no-fault-detected",
                covIncrement=0.1,
            )
        )
    app.add_object(
        AnalogValueObject(
            objectIdentifier=("analog-value", 1),
            objectName="Setpoint",
            presentValue=Real(21.5),
            units="degrees-celsius",
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            outOfService=False,
        )
    )
    app.add_object(
        BinaryValueObject(
            objectIdentifier=("binary-value", 1),
            objectName="Pump.Run",
            presentValue="active",
            activeText="Running",
            inactiveText="Stopped",
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            outOfService=False,
        )
    )
    app.add_object(
        MultiStateValueObject(
            objectIdentifier=("multi-state-value", 1),
            objectName="Mode",
            presentValue=2,
            numberOfStates=3,
            stateText=["Off", "Comfort", "Eco"],
            statusFlags=[0, 0, 0, 0],
            eventState="normal",
            outOfService=False,
        )
    )
    return app


async def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--address", default="127.0.0.1/8:47809")
    p.add_argument("--instance", type=int, default=1001)
    p.add_argument("--analog", type=int, default=5)
    a = p.parse_args()
    app = build_app(a.address, a.instance, a.analog)
    print(f"simulator device {a.instance} on {a.address} with {len(app.objectIdentifier)} objects", flush=True)
    try:
        await asyncio.Future()
    finally:
        app.close()


if __name__ == "__main__":
    asyncio.run(main())
