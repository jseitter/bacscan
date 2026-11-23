"""Plain-language descriptions of BACnet object types (ASHRAE 135).

name -> (title, what it is, typical use, properties worth looking at)
"""
from __future__ import annotations

OBJECT_TYPES: dict[str, tuple[str, str, str, tuple[str, ...]]] = {
    "device": (
        "Device",
        "The device itself. Every BACnet device has exactly one. It carries the identity (name, vendor, model, "
        "firmware), what the device can do (supported services and object types, max APDU, segmentation) and the "
        "list of all other objects.",
        "Inventory: who is this, which firmware, how big is it, what does it support.",
        ("object-name", "vendor-name", "model-name", "firmware-revision", "object-list", "max-apdu-length-accepted",
         "segmentation-supported", "protocol-services-supported"),
    ),
    "analog-input": (
        "Analog Input (AI)",
        "A measured analog value from a sensor, such as a temperature, pressure, humidity or CO2 reading. The "
        "present value is read-only: it comes from the hardware.",
        "Room, duct and outside temperatures, pressures, flow, energy meters read as numbers.",
        ("present-value", "units", "status-flags", "reliability", "out-of-service", "cov-increment"),
    ),
    "analog-output": (
        "Analog Output (AO)",
        "An analog signal the device sends out to an actuator, such as a valve or damper position or a fan speed. "
        "It is commandable: writers use priorities 1-16 and the highest priority wins (see priority-array).",
        "Valve, damper and variable speed drive commands.",
        ("present-value", "priority-array", "relinquish-default", "units", "status-flags"),
    ),
    "analog-value": (
        "Analog Value (AV)",
        "A number that lives in software and is not tied to a physical point: a setpoint, a calculated value, a "
        "parameter. Some are commandable (with priority array), others plain.",
        "Setpoints, limits, calculated temperatures, tuning parameters.",
        ("present-value", "units", "relinquish-default", "priority-array"),
    ),
    "binary-input": (
        "Binary Input (BI)",
        "A two-state signal from the field: on/off, open/closed, alarm/normal. Read-only. Polarity tells whether "
        "the physical signal is inverted.",
        "Status contacts, end switches, filter alarms, run feedback.",
        ("present-value", "active-text", "inactive-text", "polarity", "status-flags"),
    ),
    "binary-output": (
        "Binary Output (BO)",
        "A two-state signal sent to the field, such as starting a fan or opening a relay. Commandable with the "
        "16-level priority array.",
        "Start/stop commands, relays, enable signals.",
        ("present-value", "priority-array", "relinquish-default", "polarity", "active-text", "inactive-text"),
    ),
    "binary-value": (
        "Binary Value (BV)",
        "A two-state value in software: a mode flag, enable switch or status. May be commandable.",
        "Enable/disable flags, occupancy overrides, calculated alarms.",
        ("present-value", "active-text", "inactive-text", "relinquish-default"),
    ),
    "multi-state-input": (
        "Multi-state Input (MSI)",
        "A measured value with more than two states, numbered 1..n. The state-text property gives each number a "
        "name. Read-only.",
        "Operating mode feedback, fan speed stage, alarm levels.",
        ("present-value", "number-of-states", "state-text", "status-flags"),
    ),
    "multi-state-output": (
        "Multi-state Output (MSO)",
        "A command with 1..n states, for example off / low / high. Commandable with the priority array.",
        "Fan speed stages, operating mode commands.",
        ("present-value", "number-of-states", "state-text", "priority-array", "relinquish-default"),
    ),
    "multi-state-value": (
        "Multi-state Value (MSV)",
        "A software value with 1..n named states, such as an occupancy mode (occupied / unoccupied / standby). "
        "May be commandable.",
        "Modes, schedules' result values, status enumerations.",
        ("present-value", "number-of-states", "state-text", "relinquish-default"),
    ),
    "integer-value": (
        "Integer Value",
        "A signed whole number in software, without the floating point of an Analog Value.",
        "Counters, parameters, addresses.",
        ("present-value", "units"),
    ),
    "positive-integer-value": (
        "Positive Integer Value",
        "An unsigned whole number (0 and up) in software.",
        "Counters, runtime hours, parameters that cannot be negative.",
        ("present-value", "units"),
    ),
    "large-analog-value": (
        "Large Analog Value",
        "Like an Analog Value but with double precision (64 bit), for very large or very precise numbers.",
        "Energy totals, long counters.",
        ("present-value", "units"),
    ),
    "bitstring-value": (
        "BitString Value",
        "A row of named bits in software, for example a set of flags.",
        "Status words, flag sets.",
        ("present-value", "bit-text"),
    ),
    "characterstring-value": (
        "CharacterString Value",
        "A text value in software.",
        "Names, messages, text parameters.",
        ("present-value",),
    ),
    "octetstring-value": (
        "OctetString Value",
        "A string of raw bytes in software.",
        "Binary parameters, addresses, tokens.",
        ("present-value",),
    ),
    "date-value": ("Date Value", "A calendar date in software.", "Start dates, expiry dates.", ("present-value",)),
    "time-value": ("Time Value", "A time of day in software.", "Switch-on times, daily limits.", ("present-value",)),
    "datetime-value": (
        "DateTime Value", "A date and a time of day together, in software.", "Timestamps, last-change times.",
        ("present-value",)),
    "date-pattern-value": (
        "DatePattern Value",
        "A date with wildcards, e.g. 'every year on 24 Dec' or 'any Monday'.",
        "Holiday rules.",
        ("present-value",),
    ),
    "time-pattern-value": (
        "TimePattern Value", "A time of day with wildcards, e.g. 'every hour at :30'.", "Recurring time rules.",
        ("present-value",)),
    "datetime-pattern-value": (
        "DateTimePattern Value", "A date and time with wildcards.", "Recurring date-time rules.",
        ("present-value",)),
    "schedule": (
        "Schedule",
        "A time program. A weekly schedule gives, for each weekday, times and the value to apply from then on; an "
        "exception schedule overrides days (holidays, special days). The result is written to the properties "
        "listed in list-of-object-property-references. Outside any entry the schedule-default is used.",
        "Occupancy times, setback, lighting and ventilation programs. Double-click a schedule in bacscan for a "
        "weekly grid.",
        ("present-value", "weekly-schedule", "exception-schedule", "schedule-default", "effective-period",
         "list-of-object-property-references", "priority-for-writing"),
    ),
    "calendar": (
        "Calendar",
        "A list of dates, date ranges and week-and-day patterns. Its present value is true while today is in the "
        "list. Schedules refer to calendars in their exception schedule.",
        "Public holidays, shutdown days.",
        ("present-value", "date-list"),
    ),
    "command": (
        "Command",
        "Writes a whole set of values to other objects in one go, like a scene: writing the action number runs "
        "the matching list of writes.",
        "Scenes, emergency or mode switch-over for many points at once.",
        ("present-value", "action", "in-process", "all-writes-successful"),
    ),
    "event-enrollment": (
        "Event Enrollment",
        "Watches a property of another object with an alarm algorithm (out of range, change of state, ...) and "
        "raises an event when the rule is violated.",
        "Intrinsic alarm rules for objects that have none built in.",
        ("event-type", "event-state", "object-property-reference", "notification-class"),
    ),
    "notification-class": (
        "Notification Class",
        "Decides who is told about an alarm or event: recipients, priorities for to-offnormal / to-fault / "
        "to-normal, and whether acknowledgement is required. Other objects point to a class by its number.",
        "Alarm routing to head-ends and workstations.",
        ("notification-class", "priority", "ack-required", "recipient-list"),
    ),
    "notification-forwarder": (
        "Notification Forwarder",
        "Receives event notifications and forwards them to other recipients, optionally across networks.",
        "Passing alarms between networks or to systems that cannot subscribe themselves.",
        ("recipient-list", "subscribed-recipients"),
    ),
    "alert-enrollment": (
        "Alert Enrollment",
        "Like an Event Enrollment, but for alerts that need no acknowledgement or return-to-normal.",
        "Informational messages from devices.",
        ("event-state", "notification-class"),
    ),
    "event-log": (
        "Event Log",
        "A log of events and notifications the device has generated or received.",
        "Alarm history stored in the device.",
        ("log-buffer", "record-count", "enable"),
    ),
    "trend-log": (
        "Trend Log",
        "Records the value of one property over time: at fixed intervals, on change of value (COV) or when "
        "triggered. The log buffer can be read later in bulk.",
        "Temperature history, energy trends, commissioning data.",
        ("log-device-object-property", "log-interval", "logging-type", "enable", "record-count", "buffer-size"),
    ),
    "trend-log-multiple": (
        "Trend Log Multiple",
        "A trend log for several properties at once, each row sharing one timestamp.",
        "Logging a group of related points together.",
        ("log-device-object-property", "log-interval", "logging-type", "record-count", "buffer-size"),
    ),
    "loop": (
        "Loop",
        "A control loop (usually PID): it reads a controlled variable, compares it with a setpoint and writes "
        "an output. Gains and limits are properties.",
        "Temperature, pressure or flow control.",
        ("present-value", "controlled-variable-reference", "setpoint-reference", "manipulated-variable-reference",
         "proportional-constant", "integral-constant", "derivative-constant"),
    ),
    "program": (
        "Program",
        "An application program running in the device. BACnet only exposes its state and lets you start, stop "
        "or restart it; the code itself is vendor specific.",
        "Controller applications, custom sequences.",
        ("program-state", "program-change", "program-location", "description-of-halt"),
    ),
    "averaging": (
        "Averaging",
        "Keeps the minimum, maximum and average of a property over a time window.",
        "Smoothing, daily min/max of a temperature.",
        ("minimum-value", "average-value", "maximum-value", "object-property-reference"),
    ),
    "accumulator": (
        "Accumulator",
        "Counts pulses from a meter and holds the total, with scale and prescale to convert pulses to units.",
        "kWh, water and gas meters.",
        ("present-value", "scale", "prescale", "max-pres-value", "pulse-rate"),
    ),
    "pulse-converter": (
        "Pulse Converter",
        "Converts pulse counts (from an Accumulator) into engineering units and rates.",
        "Meter values as consumption or power.",
        ("present-value", "input-reference", "scale-factor", "adjust-value"),
    ),
    "file": (
        "File",
        "A file in the device, accessed with AtomicReadFile / AtomicWriteFile. Contents and use are vendor "
        "specific.",
        "Configuration backups, firmware images, logs.",
        ("file-type", "file-size", "modification-date", "archive"),
    ),
    "group": (
        "Group",
        "A named list of property references that can be read together with one request.",
        "Fast read of a set of points.",
        ("list-of-group-members", "present-value"),
    ),
    "global-group": (
        "Global Group",
        "A group that can span several devices and is updated by the device that owns it.",
        "Reading points from several devices as one set.",
        ("group-members", "present-value"),
    ),
    "structured-view": (
        "Structured View",
        "Describes how objects are organised into a tree (building, floor, equipment, point). It adds structure "
        "but no values.",
        "Navigation trees in tools.",
        ("node-type", "subordinate-list", "subordinate-annotations"),
    ),
    "network-port": (
        "Network Port",
        "Describes one network connection of the device: type (BACnet/IP, MS/TP, BACnet/SC, ...), network "
        "number, MAC address, IP address and mask, UDP port, BBMD and foreign device settings.",
        "Finding out how a device is wired and addressed. Changes here can cut the device off the network.",
        ("network-type", "network-number", "mac-address", "ip-address", "ip-subnet-mask", "bacnet-ip-udp-port",
         "bacnet-ip-mode"),
    ),
    "network-security": (
        "Network Security",
        "Holds the keys and security policy for secured BACnet networks (not used by BACnet/SC).",
        "Secure network configuration.",
        ("base-device-security-policy", "network-access-security-policies"),
    ),
    "life-safety-point": (
        "Life Safety Point",
        "A single fire or life-safety detector or device (smoke detector, pull station) with modes such as "
        "alarm, test and silenced.",
        "Fire alarm panels exposed to BACnet.",
        ("present-value", "mode", "silenced", "operation-expected"),
    ),
    "life-safety-zone": (
        "Life Safety Zone",
        "A group of life-safety points that are handled together.",
        "Fire zones.",
        ("present-value", "mode", "member-of"),
    ),
    "load-control": (
        "Load Control",
        "Asks a device to reduce its electrical load for a time (demand response) and reports whether it "
        "complied.",
        "Peak demand shedding.",
        ("present-value", "requested-shed-level", "actual-shed-level", "shed-duration"),
    ),
    "staging": (
        "Staging",
        "Controls equipment in stages, such as several chillers or pumps, and tracks which stage is active.",
        "Multi-stage plant.",
        ("present-value", "stages", "target-references"),
    ),
    "channel": (
        "Channel",
        "Writes one value to many objects at once, with channel numbers and priorities (often used for "
        "lighting groups).",
        "Lighting groups, broadcast setpoints.",
        ("present-value", "list-of-object-property-references", "channel-number"),
    ),
    "lighting-output": (
        "Lighting Output",
        "A dimmable light output with fade, ramp and step commands.",
        "Dimming, scenes, lighting control.",
        ("present-value", "lighting-command", "in-progress", "default-fade-time"),
    ),
    "binary-lighting-output": (
        "Binary Lighting Output",
        "An on/off light output with feedback and blink-warn support.",
        "Switched lighting.",
        ("present-value", "feedback-value", "blink-warn-enable"),
    ),
    "timer": (
        "Timer",
        "A timer that counts down or up and can write a value when it expires.",
        "Run-on timers, delayed switch-off.",
        ("present-value", "timer-state", "default-timeout", "initial-timeout"),
    ),
    "audit-log": (
        "Audit Log",
        "A log of who changed what in the device (writes and commands), with source and time.",
        "Change tracking.",
        ("log-buffer", "record-count", "enable"),
    ),
    "audit-reporter": (
        "Audit Reporter",
        "Selects which operations are audited and sends audit records to an audit log.",
        "Audit configuration.",
        ("audit-level", "auditable-operations"),
    ),
    "access-door": (
        "Access Door", "A controlled door: lock state, door state and commands such as unlock.",
        "Building access control.", ("present-value", "door-status", "lock-status")),
    "access-point": (
        "Access Point", "A reader or entry point that decides on access using credentials and rights.",
        "Building access control.", ("access-event", "access-doors", "authentication-policy-list")),
    "access-credential": (
        "Access Credential", "A card, code or token that identifies a person for access control.",
        "Building access control.", ("credential-status", "authorization-mode")),
    "access-rights": (
        "Access Rights", "A set of allowed locations and times.", "Building access control.",
        ("positive-access-rules", "negative-access-rules")),
    "access-user": (
        "Access User", "A person (or asset) that holds credentials.", "Building access control.",
        ("user-type", "credentials")),
    "access-zone": (
        "Access Zone", "An area, with occupancy counting and rules for entering.", "Building access control.",
        ("occupancy-state", "entry-points", "exit-points")),
    "credential-data-input": (
        "Credential Data Input", "The input side of a card reader or keypad: what was just presented.",
        "Building access control.", ("present-value", "supported-formats")),
    "elevator-group": (
        "Elevator Group", "A group of lifts that are dispatched together.", "Lift monitoring.",
        ("machine-room-id", "group-id")),
    "lift": ("Lift", "One elevator car with position, direction and door state.", "Lift monitoring.",
             ("car-position", "car-moving-direction", "car-door-status")),
    "escalator": ("Escalator", "An escalator or moving walkway with mode and direction.",
                  "Escalator monitoring.", ("escalator-mode", "operation-direction")),
}
