"""Built-in help: guide topics, BACnet object types, properties and glossary.

Used by the GUI help window and by `bacscan help` / `bacscan explain`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape

from .content import GLOSSARY, GUIDE
from .objects import OBJECT_TYPES
from .properties import PROPERTIES

__all__ = ["Topic", "all_topics", "topic", "explain", "search", "render_html", "render_text", "object_topic_id",
           "property_topic_id"]


@dataclass
class Topic:
    id: str
    title: str
    group: str  # Guide | Object types | Properties | Glossary
    body: str  # light markup


def object_topic_id(object_type: str) -> str:
    return f"object:{object_type}"


def property_topic_id(prop: str) -> str:
    return f"property:{prop.split('[')[0]}"


def _object_body(name: str) -> str:
    title, what, use, props = OBJECT_TYPES[name]
    lines = [what, "", f"**Typically used for:** {use}"]
    if props:
        lines += ["", "**Properties to look at**"]
        lines += [f"- {p}: {PROPERTIES[p]}" if p in PROPERTIES else f"- {p}" for p in props]
    return "\n".join(lines)


def all_topics() -> list[Topic]:
    out = [Topic(i, t, "Guide", b) for i, t, b in GUIDE]
    out += [Topic(object_topic_id(n), f"{v[0]}  ({n})", "Object types", _object_body(n))
            for n, v in sorted(OBJECT_TYPES.items(), key=lambda kv: kv[1][0].lower())]
    out += [Topic(property_topic_id(p), p, "Properties", PROPERTIES[p]) for p in sorted(PROPERTIES)]
    out += [Topic(f"term:{k}", k, "Glossary", v) for k, v in sorted(GLOSSARY.items(), key=lambda kv: kv[0].lower())]
    return out


def topic(topic_id: str) -> Topic | None:
    return next((t for t in all_topics() if t.id == topic_id), None)


def explain(name: str) -> Topic | None:
    """Find the topic for an object type, property, glossary term or guide id (case-insensitive)."""
    key = name.strip().lower().replace("_", "-")
    for tid in (object_topic_id(key), property_topic_id(key), key):
        t = topic(tid)
        if t:
            return t
    for t in all_topics():
        if t.group == "Glossary" and t.title.lower() == name.strip().lower():
            return t
    if key.startswith("proprietary") or key.isdigit():
        return Topic("proprietary", "Proprietary object type", "Object types",
                     "Types from 128 upwards are defined by the manufacturer. The standard says nothing about them; "
                     "see the vendor's documentation.")
    return None


def search(query: str) -> list[Topic]:
    words = [w for w in re.split(r"\s+", query.lower().strip()) if w]
    if not words:
        return []
    hits = []
    for t in all_topics():
        title, text = t.title.lower(), t.body.lower()
        if all(w in title or w in text for w in words):
            hits.append((0 if all(w in title for w in words) else 1, t))
    return [t for _, t in sorted(hits, key=lambda x: x[0])]


# ---------------------------------------------------------------- rendering


def _inline_html(s: str) -> str:
    s = escape(s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    return re.sub(r"`(.+?)`", r"<code>\1</code>", s)


def render_html(t: Topic) -> str:
    out = [f"<h2>{escape(t.title)}</h2>", f'<p style="color:gray">{escape(t.group)}</p>']
    bullets: list[str] = []

    def flush() -> None:
        if bullets:
            out.append("<ul>" + "".join(f"<li>{b}</li>" for b in bullets) + "</ul>")
            bullets.clear()

    para: list[str] = []
    for line in t.body.strip().splitlines():
        if line.startswith("- "):
            if para:
                out.append(f"<p>{_inline_html(' '.join(para))}</p>")
                para.clear()
            bullets.append(_inline_html(line[2:]))
        elif not line.strip():
            flush()
            if para:
                out.append(f"<p>{_inline_html(' '.join(para))}</p>")
                para.clear()
        else:
            flush()
            para.append(line.strip())
    flush()
    if para:
        out.append(f"<p>{_inline_html(' '.join(para))}</p>")
    return "\n".join(out)


def render_text(t: Topic, width: int = 88) -> str:
    import textwrap
    out = [t.title, "=" * len(t.title), ""]
    para: list[str] = []

    def flush() -> None:
        if para:
            out.append(textwrap.fill(" ".join(para), width))
            out.append("")
            para.clear()

    for line in t.body.strip().splitlines():
        if line.startswith("- "):
            flush()
            out.append(textwrap.fill(line[2:].replace("**", "").replace("`", ""), width,
                                     initial_indent="  - ", subsequent_indent="    "))
        elif not line.strip():
            flush()
            if out and out[-1] != "":
                out.append("")
        else:
            para.append(line.strip().replace("**", "").replace("`", ""))
    flush()
    return "\n".join(out).rstrip() + "\n"
