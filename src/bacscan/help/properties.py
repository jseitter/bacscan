"""One-line explanations of common BACnet properties."""
from __future__ import annotations

PROPERTIES: dict[str, str] = {
    # identity
    "object-identifier": "Object type and instance number together, e.g. analog-input,3. Unique within one device.",
    "object-name": "Name of the object. Must be unique within the device; this is what engineers usually search for.",
    "object-type": "The kind of object (analog-input, schedule, ...).",
    "description": "Free text describing the object, set by the engineer.",
    "location": "Free text: where the device or object is installed.",
    "profile-name": "Name of a vendor or standard profile the object follows.",
    # values and state
    "present-value": "The current value of the object. For outputs it is the result of the priority array; for inputs "
                     "it is the measurement (and can be overridden while out-of-service is true).",
    "status-flags": "Four flags: in-alarm, fault, overridden, out-of-service. All false means normal.",
    "event-state": "normal, fault, off-normal, high-limit, low-limit or life-safety-alarm: the alarm state of the object.",
    "reliability": "Why the value may not be trustworthy: no-fault-detected, no-sensor, over-range, under-range, "
                   "open-loop, shorted-loop, communication-failure, ...",
    "out-of-service": "True while the object is disconnected from the real hardware, so its value can be set by hand "
                      "for testing. Objects left out-of-service are a common commissioning leftover.",
    "units": "Engineering unit of the value, e.g. degrees-celsius, percent, kilowatt-hours.",
    "cov-increment": "Smallest change in present-value that triggers a change-of-value notification to subscribers.",
    "min-pres-value": "Lowest value the hardware can report or accept.",
    "max-pres-value": "Highest value the hardware can report or accept.",
    "resolution": "Smallest possible step of the value.",
    "device-type": "Free text naming the connected sensor or actuator type.",
    "event-enable": "Which transitions (to-offnormal, to-fault, to-normal) may raise notifications.",
    "notification-class": "Number of the Notification Class object that routes this object's alarms.",
    "priority": "Notification Class: three priorities (to-offnormal, to-fault, to-normal) that rank the "
                "notifications it sends; 0 is the most urgent.",
    "ack-required": "Notification Class: which transitions an operator has to acknowledge.",
    "recipient-list": "Notification Class: who receives the notifications, when and how.",
    "event-type": "Event Enrollment: the alarm algorithm used (change-of-state, out-of-range, ...).",
    "object-property-reference": "The property of another object that is watched or averaged.",
    "high-limit": "Upper alarm limit.",
    "low-limit": "Lower alarm limit.",
    "deadband": "Hysteresis around the limits before the alarm clears.",
    # commandable
    "priority-array": "16 slots (1 = highest priority, such as manual life-safety, to 16 = lowest). Present-value is the "
                      "value of the highest-priority slot that is not empty (null).",
    "relinquish-default": "Value used when every slot of the priority array is empty.",
    "priority-for-writing": "Priority (1-16) a schedule uses when it writes to other objects.",
    "current-command-priority": "Priority of the slot that currently decides the value.",
    # binary / multistate
    "polarity": "normal or reverse: whether the physical signal is inverted compared to present-value.",
    "active-text": "Label for the active (1) state, e.g. 'Running'.",
    "inactive-text": "Label for the inactive (0) state, e.g. 'Stopped'.",
    "number-of-states": "How many states a multi-state object has (1..n).",
    "state-text": "Names of the states 1..n, e.g. Off, Low, High.",
    # schedule / calendar
    "effective-period": "Range of dates in which the schedule is active.",
    "schedule-default": "Value used when no weekly or exception entry applies.",
    "weekly-schedule": "Seven day schedules (Monday to Sunday), each a list of time/value pairs.",
    "exception-schedule": "Special days that override the weekly schedule, with priorities.",
    "list-of-object-property-references": "The objects and properties this schedule or channel writes to.",
    "date-list": "The dates, date ranges and week-and-day patterns of a calendar.",
    # logging
    "log-device-object-property": "Which property a trend log records.",
    "log-interval": "Time between samples, in hundredths of a second (0 = not periodic).",
    "logging-type": "polled, cov or triggered: how the trend log collects samples.",
    "enable": "Whether logging is currently switched on.",
    "record-count": "Number of records currently in the log buffer.",
    "buffer-size": "Maximum number of records the log can hold before it overwrites old ones.",
    "log-buffer": "The recorded entries. Read in bulk with ReadRange.",
    # network port
    "network-type": "Type of this port: ipv4, ipv6, mstp, ptp, bacnet-sc, ...",
    "network-number": "BACnet network number of this port (1-65534). Must be unique across the internetwork.",
    "mac-address": "Data-link address. For BACnet/IP: 4 byte IP address plus 2 byte UDP port; for MS/TP: one byte.",
    "ip-address": "IPv4 address of the port.",
    "ip-subnet-mask": "IPv4 subnet mask of the port.",
    "ip-default-gateway": "IPv4 default gateway.",
    "ip-dns-server": "IPv4 DNS servers.",
    "bacnet-ip-udp-port": "UDP port, normally 47808 (0xBAC0).",
    "bacnet-ip-mode": "normal, foreign (registered with a BBMD) or bbmd.",
    "max-master": "MS/TP: highest MAC address that is polled for masters.",
    "max-info-frames": "MS/TP: how many frames this node may send per token.",
    # program
    "program-state": "idle, loading, running, waiting, halted or unloading.",
    "program-location": "Where the program is stored or loaded from.",
    "program-change": "Writable request to load, run, halt or restart the program.",
    # device
    "vendor-name": "Manufacturer of the device.",
    "vendor-identifier": "ASHRAE-assigned manufacturer number (0 = ASHRAE; 999 is used by bacscan itself).",
    "model-name": "Manufacturer's model name.",
    "firmware-revision": "Firmware version of the device.",
    "application-software-version": "Version of the application running on the device.",
    "serial-number": "Serial number of the device.",
    "protocol-version": "BACnet protocol version (always 1 so far).",
    "protocol-revision": "BACnet protocol revision the device implements, e.g. 14 or 22. Higher means newer features.",
    "protocol-services-supported": "Which BACnet services the device can answer, such as read-property-multiple.",
    "protocol-object-types-supported": "Which object types the device can contain.",
    "max-apdu-length-accepted": "Largest message (APDU) the device can receive in bytes: 50, 128, 206, 480, 1024 or 1476. "
                                "Small values force smaller requests.",
    "segmentation-supported": "Whether the device can split large messages into segments: segmented-both, "
                              "segmented-transmit, segmented-receive or no-segmentation.",
    "max-segments-accepted": "How many segments the device accepts for one message.",
    "system-status": "operational, operational-read-only, download-required, download-in-progress, "
                     "non-operational or backup-in-progress.",
    "database-revision": "Counter that increases when objects are added, removed or renamed; tools use it to detect "
                         "configuration changes.",
    "local-date": "Date according to the device's clock.",
    "local-time": "Time according to the device's clock.",
    "utc-offset": "Offset of the device's local time from UTC, in minutes.",
    "daylight-savings-status": "Whether daylight saving time is in effect.",
    "apdu-timeout": "How long the device waits for an answer before it retries, in milliseconds.",
    "number-of-apdu-retries": "How often the device repeats an unanswered request.",
    "apdu-segment-timeout": "Time the device waits between segments.",
    "last-restart-reason": "Why the device last restarted: coldstart, warmstart, power failure, watchdog, ...",
    "time-of-device-restart": "When the device last restarted.",
    "object-list": "Array of every object in the device. Can be long: read in one request only if the reply fits "
                   "the APDU or the device can segment.",
    "property-list": "Array of the properties an object supports (without the required object-name, object-type "
                     "and object-identifier).",
}
