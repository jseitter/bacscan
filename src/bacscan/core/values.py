"""Convert bacpypes3 values into JSON-serialisable data plus display text."""
from __future__ import annotations

from typing import Any

from bacpypes3.apdu import AbortPDU, ErrorPDU, ErrorRejectAbortNack, RejectPDU
from bacpypes3.basetypes import ErrorType
from bacpypes3.constructeddata import Any as BAny
from bacpypes3.constructeddata import Choice, Sequence
from bacpypes3.json.util import atomic_encode, sequence_to_json
from bacpypes3.primitivedata import (
    Atomic,
    BitString,
    Date,
    Enumerated,
    ObjectIdentifier,
    Real,
    Time,
)


def error_text(err: Any) -> str:
    """Readable text for an error/reject/abort response or ErrorType."""
    if isinstance(err, ErrorType) or hasattr(err, "errorCode"):
        cls = getattr(err, "errorClass", None)
        code = getattr(err, "errorCode", None)
        return f"{cls}: {code}" if cls is not None else str(code)
    if isinstance(err, RejectPDU):
        return f"reject: {err.apduAbortRejectReason}"
    if isinstance(err, AbortPDU):
        return f"abort: {err.apduAbortRejectReason}"
    if isinstance(err, (ErrorPDU, ErrorRejectAbortNack)):
        return str(err)
    if isinstance(err, TimeoutError):
        return "timeout"
    return f"{type(err).__name__}: {err}"


def is_unknown_property(err: Any) -> bool:
    """True for errors meaning 'object has no such property' (not worth storing)."""
    return str(getattr(err, "errorCode", "") or "") == "unknown-property"


def to_json(value: Any) -> Any:
    """Recursively convert a bacpypes3 value into plain JSON data."""
    if value is None:
        return None
    if isinstance(value, ObjectIdentifier):
        return f"{value[0]},{value[1]}"
    if isinstance(value, (Date, Time)):
        return str(value)
    if isinstance(value, Atomic):
        try:
            v = atomic_encode(value)
        except Exception:
            return str(value)
        if isinstance(value, Real):  # 32-bit float: drop widening noise (0.1 not 0.10000000149)
            f = float(value)
            return float(f"{f:.7g}") if f == f and f not in (float("inf"), float("-inf")) else str(f)
        return v
    if isinstance(value, (Sequence, Choice)):
        try:
            return sequence_to_json(value)
        except Exception:
            return str(value)
    if isinstance(value, BAny):
        return str(value)
    if isinstance(value, (list, tuple)):
        return [to_json(v) for v in value]
    if isinstance(value, (int, float, str, bool)):
        return value
    return str(value)


def to_text(value: Any) -> str:
    """Short human-readable rendering of a bacpypes3 value."""
    if value is None:
        return ""
    if isinstance(value, ObjectIdentifier):
        return f"{value[0]},{value[1]}"
    if isinstance(value, BitString):
        bits = to_json(value)
        return ", ".join(str(b) for b in bits) if isinstance(bits, list) else str(bits)
    if isinstance(value, Enumerated):
        return str(to_json(value))
    if isinstance(value, Real):
        return f"{float(value):.6g}"
    if isinstance(value, (Date, Time)):
        return str(value)
    if isinstance(value, Atomic):
        j = to_json(value)
        if isinstance(j, bool) or type(value).__name__ == "Boolean":
            return "true" if value else "false"
        return str(j)
    if isinstance(value, (list, tuple)) and not isinstance(value, ObjectIdentifier):
        parts = [to_text(v) for v in value]
        s = "; ".join(parts)
        return s if len(s) <= 500 else s[:497] + "..."
    j = to_json(value)
    if isinstance(j, dict):
        return ", ".join(f"{k}={v}" for k, v in j.items())
    return str(j)
