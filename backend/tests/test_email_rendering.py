"""U10 rendering tests: escaping, defanging, header-injection guard, and
"every EmailType has a template" coverage. No DB required."""

from __future__ import annotations

import pytest

from app.email import render
from app.email.types import EmailType

# One minimal, valid fixture context per type — mirrors what each real hook
# passes via `render_context` in `service.enqueue()`.
_FIXTURES: dict[str, dict] = {
    "E01": dict(incident_number=1, title="t", status="new", first_seen="x", last_seen="y",
                src_ip_defanged="1[.]2[.]3[.]4", target="host", event_count=3, rule_name="r", signatures=["sig"]),
    "E02": dict(incident_number=1, old_severity="high", new_severity="critical", what_changed="x", new_top_signatures=["s"]),
    "E03": dict(incident_number=1, title="t", severity="high", assigned_by="bob"),
    "E04": dict(incident_number=1, status="new", age_minutes=5, stage="breach"),
    "E05": dict(incident_number=1, final_status="resolved", acted_by="bob", resolution_note="n"),
    "E06": dict(ioc_type="ip", ioc_value_defanged="1[.]2[.]3[.]4", feed_name="f", confidence=80, first_seen="x", last_seen="y", asset="a"),
    "E07": dict(target="1.2.3.0/24", direction="inbound", protocol="tcp", port=22, ttl_seconds=600,
                expires_at_utc="x", expires_at_local="y", requester="bob", incident_number=1),
    "E08": dict(target="1.2.3.0/24", expires_at="x"),
    "E09": dict(target="1.2.3.0/24", reason="expired", revoked_by="bob", removal_failed=False),
    "E10": dict(requester="bob", target="1.2.3.0/24", reason="protected"),
    "E11": dict(report_type="incident_summary", window="7d", format="pdf", generated_at="x", attached=True),
    "E12": dict(),
    "E13": dict(report_type="x", window="7d", error_class="Timeout"),
    "E14": dict(period_start="a", period_end="b", new_incidents_by_severity={"high": 2},
                overdue_incidents=[{"number": 1, "severity": "high"}], containment_count=1, ioc_hit_count=2, queued_by_type={}),
    "E15": dict(since="x", last_event_at="y"),
    "E16": dict(backlog_size=5),
    "E17": dict(feed_name="f", last_success="x", error_class="Timeout"),
    "E18": dict(missing=["a"], extra=["b"]),
    "E19": dict(display_name="bob", purpose="reset", expiry_minutes=30),
    "E20": dict(what_changed="role changed", changed_by="admin", changed_at="x"),
    "E21": dict(time="x", ip_defanged="1[.]2[.]3[.]4", outcome="success"),
}

_BASE_CONTEXT = {
    "heading": "h", "severity": None, "button_label": "go", "button_url": "http://x",
    "why_you_got_this": None, "prefs_url": "http://p",
}


@pytest.mark.parametrize("email_type", list(EmailType))
def test_every_email_type_renders_html_and_text(email_type: EmailType):
    context = {**_BASE_CONTEXT, **_FIXTURES[email_type.value]}
    html, text = render.render(email_type, context)
    assert html.strip()
    assert text.strip()
    assert "SentinelCore" in html
    assert "SentinelCore" in text


def test_html_escapes_script_tags_and_quotes():
    context = {
        **_BASE_CONTEXT,
        **_FIXTURES["E01"],
        "title": "<script>alert(1)</script>",
        "target": '"onmouseover=alert(1)',
    }
    html, _ = render.render(EmailType.E01_NEW_INCIDENT, context)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert 'onmouseover=alert(1)' not in html or "&#34;onmouseover" in html


def test_text_part_is_a_separate_render_not_derived_from_html():
    context = {**_BASE_CONTEXT, **_FIXTURES["E01"], "title": "<b>bold</b>"}
    html, text = render.render(EmailType.E01_NEW_INCIDENT, context)
    # The HTML version escapes the tag; the text version — rendered from its
    # own .txt template with autoescape off — carries the literal characters.
    assert "&lt;b&gt;" in html
    assert "<b>bold</b>" in text


@pytest.mark.parametrize(
    "raw,expected_substring",
    [
        ("evil.com", "evil[.]com"),
        ("1.2.3.4", "1[.]2[.]3[.]4"),
        ("http://evil.com", "hxxp://evil[.]com"),
        ("https://evil.com", "hxxps://evil[.]com"),
    ],
)
def test_defang(raw: str, expected_substring: str):
    assert render.defang(raw) == expected_substring


def test_subject_strips_crlf_header_injection():
    subject = render.build_subject(prefix_severity="critical", title="Incident\r\nBcc: evil@example.com")
    assert "\r" not in subject
    assert "\n" not in subject


def test_subject_is_capped_at_120_chars():
    subject = render.build_subject(prefix_severity="high", title="x" * 300)
    assert len(subject) <= 120


def test_subject_includes_sentinelcore_prefix_and_severity():
    subject = render.build_subject(prefix_severity="critical", title="Incident #142")
    assert subject.startswith("[SentinelCore][CRITICAL]")
