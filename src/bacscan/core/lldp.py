"""Switch port discovery (spec E10): passively capture one LLDP or CDP frame.

Uses tcpdump (needs capture rights: sudo, or Wireshark's ChmodBPF / 'access_bpf' group).
Nothing is sent. Switches announce LLDP about every 30 s and CDP every 60 s.
"""
from __future__ import annotations

import ipaddress
import os
import re
import select
import subprocess
import time
from typing import Any, Callable

from . import oui

CAPTURE_FILTER = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
DEFAULT_WAIT = 35.0

_LLDP_CAPS = ["other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station",
              "c-vlan", "s-vlan", "tpmr"]
_CDP_CAPS = ["router", "transparent-bridge", "source-route-bridge", "switch", "host", "igmp", "repeater",
             "phone", "remote-managed"]


# ---------------------------------------------------------------- capture


def parse_tcpdump_hex(text: str) -> list[bytes]:
    """Frames from `tcpdump -xx` output (a header line followed by '\\t0x0000:  aabb ...' lines)."""
    frames: list[bytes] = []
    current: list[str] | None = None
    for line in text.splitlines():
        m = re.match(r"^\s+0x[0-9a-f]+:\s+((?:[0-9a-f]{2,4}\s?)+)", line)
        if m:
            if current is None:
                current = []
            current.append(m.group(1).replace(" ", ""))
        else:
            if current:
                frames.append(bytes.fromhex("".join(current)))
            current = None
    if current:
        frames.append(bytes.fromhex("".join(current)))
    return frames


def capture(interface: str, wait: float = DEFAULT_WAIT, should_stop: Callable[[], bool] = lambda: False) -> dict:
    """Wait up to `wait` seconds for an LLDP/CDP frame on `interface`. Never raises."""
    cmd = ["tcpdump", "-i", interface, "-nn", "-xx", "-l", "-s", "1600", CAPTURE_FILTER]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    except OSError as e:
        return {"found": False, "error": f"tcpdump not available: {e}"}
    buf = ""
    deadline = time.monotonic() + wait
    result: dict[str, Any] = {"found": False, "waited_s": wait}
    fd = proc.stdout.fileno()
    try:
        while time.monotonic() < deadline and not should_stop():
            if proc.poll() is not None:
                break
            # unbuffered reads: select() must see everything tcpdump wrote
            ready, _, _ = select.select([fd], [], [], 0.25)
            if ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", "replace")
                continue
            if buf:  # output went quiet: the buffered frame(s) are complete
                for frame in parse_tcpdump_hex(buf):
                    info = parse_frame(frame)
                    if info:
                        info["found"] = True
                        info["waited_s"] = round(wait - (deadline - time.monotonic()), 1)
                        return info
                buf = ""
        for frame in parse_tcpdump_hex(buf):
            info = parse_frame(frame)
            if info:
                info["found"] = True
                return info
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(2)
            except subprocess.TimeoutExpired:
                proc.kill()
        err = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
    if "permission" in err.lower() or "Operation not permitted" in err:
        result["error"] = ("no permission to capture packets: run with sudo, or install Wireshark's "
                           "ChmodBPF so your user may capture")
    elif proc.returncode not in (None, 0, -15) and err.strip() and "listening on" not in err:
        result["error"] = err.strip().splitlines()[-1]
    return result


# ---------------------------------------------------------------- decoding


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _text(b: bytes) -> str:
    return b.decode("utf-8", "replace").strip("\x00").strip()


def _addr(family_subtype: int, b: bytes) -> str:
    if family_subtype == 1 and len(b) == 4:
        return str(ipaddress.IPv4Address(b))
    if family_subtype == 2 and len(b) == 16:
        return str(ipaddress.IPv6Address(b))
    return b.hex()


def parse_frame(frame: bytes) -> dict | None:
    if len(frame) < 18:
        return None
    dst, src = frame[0:6], frame[6:12]
    ethertype = int.from_bytes(frame[12:14], "big")
    offset = 14
    vlan_tag = None
    if ethertype == 0x8100:
        vlan_tag = int.from_bytes(frame[14:16], "big") & 0x0FFF
        ethertype = int.from_bytes(frame[16:18], "big")
        offset = 18
    if ethertype == 0x88CC:
        info = parse_lldp(frame[offset:])
    elif dst == bytes.fromhex("01000ccccccc") and frame[offset:offset + 8] == bytes.fromhex("aaaa0300000c2000"):
        info = parse_cdp(frame[offset + 8:])
    else:
        return None
    info["source_mac"] = _mac(src)
    info["source_vendor"] = oui.vendor(_mac(src))
    if vlan_tag is not None:
        info["frame_vlan"] = vlan_tag
    return info


def parse_lldp(data: bytes) -> dict:
    info: dict[str, Any] = {"protocol": "LLDP"}
    i = 0
    while i + 2 <= len(data):
        header = int.from_bytes(data[i:i + 2], "big")
        typ, length = header >> 9, header & 0x1FF
        value = data[i + 2:i + 2 + length]
        i += 2 + length
        if typ == 0:
            break
        if typ == 1 and value:  # chassis id
            sub = value[0]
            info["chassis_id"] = _mac(value[1:]) if sub == 4 and len(value) == 7 else (
                _addr(value[2], value[3:]) if sub == 5 and len(value) > 3 else _text(value[1:]))
        elif typ == 2 and value:  # port id
            sub = value[0]
            info["port_id"] = _mac(value[1:]) if sub == 3 and len(value) == 7 else _text(value[1:])
        elif typ == 3 and len(value) >= 2:
            info["ttl"] = int.from_bytes(value[:2], "big")
        elif typ == 4:
            info["port_description"] = _text(value)
        elif typ == 5:
            info["system_name"] = _text(value)
        elif typ == 6:
            info["system_description"] = _text(value)
        elif typ == 7 and len(value) >= 4:
            enabled = int.from_bytes(value[2:4], "big")
            info["capabilities"] = [n for b, n in enumerate(_LLDP_CAPS) if enabled & (1 << b)]
        elif typ == 8 and len(value) >= 2:
            alen = value[0]
            if alen >= 1:
                info.setdefault("management_addresses", []).append(_addr(value[1], value[2:1 + alen]))
        elif typ == 127 and len(value) >= 4:
            org, sub = value[:3], value[3]
            if org == b"\x00\x80\xc2" and sub == 1 and len(value) >= 6:  # IEEE 802.1 port VLAN id
                info["vlan"] = int.from_bytes(value[4:6], "big")
            elif org == b"\x00\x80\xc2" and sub == 3 and len(value) >= 7:  # VLAN name
                info.setdefault("vlan_names", []).append(_text(value[7:]))
            elif org == b"\x00\x12\x0f" and sub == 1 and len(value) >= 9:  # 802.3 MAC/PHY
                info["autoneg"] = bool(value[4] & 0x02)
    return info


def parse_cdp(data: bytes) -> dict:
    info: dict[str, Any] = {"protocol": "CDP"}
    if len(data) < 4:
        return info
    info["cdp_version"] = data[0]
    info["ttl"] = data[1]
    i = 4
    while i + 4 <= len(data):
        typ = int.from_bytes(data[i:i + 2], "big")
        length = int.from_bytes(data[i + 2:i + 4], "big")
        if length < 4:
            break
        value = data[i + 4:i + length]
        i += length
        if typ == 0x0001:
            info["system_name"] = _text(value)
        elif typ == 0x0003:
            info["port_id"] = _text(value)
        elif typ == 0x0004 and len(value) >= 4:
            caps = int.from_bytes(value[:4], "big")
            info["capabilities"] = [n for b, n in enumerate(_CDP_CAPS) if caps & (1 << b)]
        elif typ == 0x0005:
            info["system_description"] = _text(value)
        elif typ == 0x0006:
            info["platform"] = _text(value)
        elif typ == 0x000A and len(value) >= 2:
            info["vlan"] = int.from_bytes(value[:2], "big")
        elif typ == 0x000B and value:
            info["duplex"] = "full" if value[0] else "half"
        elif typ in (0x0002, 0x0016) and len(value) >= 4:
            n = int.from_bytes(value[:4], "big")
            j = 4
            for _ in range(n):
                if j + 2 > len(value):
                    break
                plen = value[j + 1]
                proto = value[j + 2:j + 2 + plen]
                j += 2 + plen
                alen = int.from_bytes(value[j:j + 2], "big")
                addr = value[j + 2:j + 2 + alen]
                j += 2 + alen
                if proto == b"\xcc" and alen == 4:
                    key = "management_addresses" if typ == 0x0016 else "addresses"
                    info.setdefault(key, []).append(str(ipaddress.IPv4Address(addr)))
    return info


def summarize(sw: dict) -> list[tuple[str, str]]:
    """Readable rows for CLI / GUI / Excel."""
    if not sw:
        return []
    if not sw.get("found"):
        msg = sw.get("error") or f"no LLDP/CDP frame received within {sw.get('waited_s', '?')} s"
        return [("Switch", msg)]
    rows = []

    def add(label: str, value: Any) -> None:
        if value not in (None, "", []):
            rows.append((label, ", ".join(map(str, value)) if isinstance(value, list) else str(value)))

    add("Switch", f"{sw.get('system_name') or sw.get('chassis_id', '?')} ({sw['protocol']})")
    add("Switch port", " - ".join(x for x in (sw.get("port_id"), sw.get("port_description")) if x))
    add("Switch VLAN", sw.get("vlan"))
    add("Switch VLAN names", sw.get("vlan_names"))
    add("Switch mgmt address", sw.get("management_addresses") or sw.get("addresses"))
    add("Switch platform", sw.get("platform"))
    desc = sw.get("system_description", "")
    add("Switch description", desc[:200] + ("…" if len(desc) > 200 else ""))
    add("Switch capabilities", sw.get("capabilities"))
    add("Switch MAC", f"{sw.get('source_mac')} {sw.get('source_vendor', '')}".strip())
    return rows
