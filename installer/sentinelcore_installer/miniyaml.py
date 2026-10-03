"""Minimal YAML for the install profile, so the installer needs no PyYAML.

Supports nested maps (2-space indent), block lists, "double" and 'single'
quoted strings, ints, true/false/null and # comments. Anything else
(flow maps, anchors, tabs, multi-line scalars) is rejected.
"""

from __future__ import annotations

import json

from .validators import ValidationError


def _scalar_out(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value))  # JSON strings are valid YAML double-quoted scalars


def dump(data: dict, indent: int = 0) -> str:
    pad = "  " * indent
    out: list[str] = []
    for key, val in data.items():
        if isinstance(val, dict):
            out.append(f"{pad}{key}:")
            out.append(dump(val, indent + 1).rstrip("\n"))
        elif isinstance(val, list):
            if not val:
                out.append(f"{pad}{key}: []")
            else:
                out.append(f"{pad}{key}:")
                out.extend(f"{pad}  - {_scalar_out(item)}" for item in val)
        else:
            out.append(f"{pad}{key}: {_scalar_out(val)}")
    return "\n".join(out) + "\n"


def _scalar_in(text: str):
    text = text.strip()
    if text.startswith('"'):
        end = text.rfind('"')
        try:
            return json.loads(text[: end + 1])
        except json.JSONDecodeError as exc:
            raise ValidationError(f"bad quoted string in profile: {text[:40]}") from exc
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    if text == "[]":
        return []
    if text[:1] in "[{&*!|>":
        raise ValidationError(f"unsupported YAML construct in profile: {text[:40]}")
    text = text.split(" #", 1)[0].strip()
    low = text.lower()
    if low in {"true", "false"}:
        return low == "true"
    if low in {"null", "~", ""}:
        return None
    if text.lstrip("-").isdigit():
        return int(text)
    return text


def load(text: str) -> dict:
    rows: list[tuple[int, str]] = []
    for raw in text.splitlines():
        lead = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in lead:
            raise ValidationError("tabs are not allowed in the profile")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        rows.append((len(lead), stripped))

    def block(i: int, indent: int):
        if rows[i][1].startswith("- "):
            items = []
            while i < len(rows) and rows[i][0] == indent and rows[i][1].startswith("- "):
                items.append(_scalar_in(rows[i][1][2:]))
                i += 1
            return items, i
        result: dict = {}
        while i < len(rows) and rows[i][0] == indent:
            line = rows[i][1]
            if ":" not in line or line.startswith("- "):
                raise ValidationError(f"cannot parse profile line: {line[:50]}")
            key, _, rest = line.partition(":")
            key = key.strip()
            i += 1
            if rest.strip():
                result[key] = _scalar_in(rest)
            elif i < len(rows) and rows[i][0] > indent:
                result[key], i = block(i, rows[i][0])
            else:
                result[key] = None
        return result, i

    if not rows:
        return {}
    data, end = block(0, rows[0][0])
    if end != len(rows):
        raise ValidationError("profile could not be fully parsed (check indentation)")
    return data
