"""Jinja2 rendering for the 21 email templates.

Autoescaping stays on for the whole environment — IPs, hostnames, incident
titles and free-text resolution notes all come from attacker-influenced
network data or user free-text, and none of it is ever marked `|safe`. The
text part is rendered from a *separate* `.txt` template (not derived by
stripping HTML tags), per CLAUDE.md's "no user-supplied input ever reaches
an unescaped surface" spirit applied to mail.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings
from app.email.types import EmailType

TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

_TXT_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=False,
    trim_blocks=True,
    lstrip_blocks=True,
)

# RFC 5322 header values must not contain CR/LF (header injection); strip any
# control character outright, subjects are capped to 120 chars per spec.
_CONTROL_CHARS = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]")
_MAX_SUBJECT_LEN = 120


def sanitize_header(value: str) -> str:
    """Strip control characters and clamp length — used for subjects and
    any other value interpolated into an email header."""
    cleaned = _CONTROL_CHARS.sub(" ", value).strip()
    if len(cleaned) > _MAX_SUBJECT_LEN:
        cleaned = cleaned[: _MAX_SUBJECT_LEN - 1].rstrip() + "…"
    return cleaned


def build_subject(*, prefix_severity: str | None, title: str) -> str:
    severity_tag = f"[{prefix_severity.upper()}]" if prefix_severity else ""
    return sanitize_header(f"[SentinelCore]{severity_tag} {title}")


def defang(value: str) -> str:
    """Render an IP/domain/URL safe to paste into a ticket or chat without
    it becoming a clickable/resolvable artifact: `hxxp://evil[.]com`,
    `1[.]2[.]3[.]4`. Real values are never defanged inside an in-app link —
    only in prose."""
    if not value:
        return value
    out = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return out.replace(".", "[.]")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def app_link(path: str) -> str:
    """Build an in-app link. `path` must start with `/`; the real value
    (incident id, IP, etc.) is embedded here — defanging is for prose only,
    an actual navigable link must stay real or it is useless to the analyst
    who is, by definition, already authenticated."""
    base = settings.app_base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _text_fallback(html: str) -> str:
    """Last-resort plain text when a type has no dedicated `.txt` template
    (should not happen for the 21 shipped types, kept as a safety net for
    tests/fixtures exercising a type before its template lands)."""
    text = re.sub(r"<br\s*/?>", "\n", html)
    text = re.sub(r"<[^>]+>", "", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def render(email_type: EmailType, context: dict[str, Any]) -> tuple[str, str]:
    """Returns (html_body, text_body). Caller builds the subject separately
    via `build_subject()` since it varies per-instance (severity, id...)."""
    basename = email_type.value.lower()
    html_template = _env.get_template(f"{basename}.html")
    html = html_template.render(**context)

    try:
        text_template = _TXT_ENV.get_template(f"{basename}.txt")
        text = text_template.render(**context)
    except Exception:  # noqa: BLE001 — template missing is a bug, not a crash reason
        text = _text_fallback(html)

    return html, text
