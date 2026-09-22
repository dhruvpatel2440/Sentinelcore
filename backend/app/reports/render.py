"""M9 rendering: PDF via WeasyPrint over a Jinja2 template, CSV via the
stdlib, JSON as the raw (verifiable) ReportData.

Jinja2 autoescaping stays on for the whole environment — signatures,
hostnames and resolution notes come from untrusted network data and
free-text fields, and none of it is ever marked `|safe`.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from app.reports import charts

TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


def data_checksum(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _seconds_display(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    return f"{seconds / 3600:.1f}h"


def _extra_context(report_type: str, data: dict[str, Any]) -> dict[str, Any]:
    if report_type == "incident_summary":
        return {
            "mtta_display": _seconds_display(data["mtta_seconds"]),
            "mttr_display": _seconds_display(data["mttr_seconds"]),
            "severity_chart": charts.bar_chart(
                list(data["totals_by_severity"].keys()), list(data["totals_by_severity"].values()),
                title="Incidents by severity",
            ),
            "timeline_chart": charts.line_chart(
                data["opened_vs_closed"]["days"],
                {
                    "opened": [data["opened_vs_closed"]["opened"].get(d, 0) for d in data["opened_vs_closed"]["days"]],
                    "closed": [data["opened_vs_closed"]["closed"].get(d, 0) for d in data["opened_vs_closed"]["days"]],
                },
                title="Opened vs closed",
            ),
        }
    if report_type == "incident_detail":
        sev_counts: dict[str, int] = {}
        for e in data["events"]:
            sev_counts[e["severity"]] = sev_counts.get(e["severity"], 0) + 1
        return {"severity_chart": charts.bar_chart(list(sev_counts.keys()), list(sev_counts.values()), title="Linked events by severity")}
    if report_type == "asset_inventory":
        return {
            "posture_chart": charts.bar_chart(
                ["total", "stale", "high-risk"],
                [data["total_assets"], data["stale_count"], data["high_risk_count"]],
                title="Asset posture",
            )
        }
    if report_type == "event_statistics":
        days = sorted(data["volume_over_time"].keys())
        severities = sorted({sev for day in data["volume_over_time"].values() for sev in day})
        return {
            "severity_chart": charts.bar_chart(list(data["severity_counts"].keys()), list(data["severity_counts"].values()), title="Events by severity"),
            "volume_chart": charts.line_chart(
                days, {sev: [data["volume_over_time"][d].get(sev, 0) for d in days] for sev in severities}, title="Event volume over time"
            ),
        }
    return {}


def render_pdf(*, report_type: str, title: str, params: dict[str, Any], requested_by: str, data: dict[str, Any]) -> bytes:
    now = datetime.now(timezone.utc)
    checksum = data_checksum(data)

    template = _env.get_template(f"{report_type}.html")
    context = {
        "title": title,
        "report_type": report_type,
        "params": params,
        "requested_by": requested_by,
        "generated_at_utc": now.strftime("%Y-%m-%d %H:%M:%S"),
        "generated_at_local": now.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "data_checksum": checksum,
        "data": data,
        **_extra_context(report_type, data),
    }
    html = template.render(**context)
    return HTML(string=html, base_url=str(TEMPLATES_DIR)).write_pdf()


def render_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def render_csv(report_type: str, data: dict[str, Any]) -> bytes:
    buf = io.StringIO()

    if report_type == "incident_summary":
        rows = data["table"]
        fieldnames = ["number", "title", "severity", "status", "opened_at", "closed_at", "assignee"]
    elif report_type == "asset_inventory":
        rows = [
            {
                "ip_address": r["ip_address"], "hostname": r["hostname"], "mac_address": r["mac_address"],
                "vendor": r["vendor"], "os_guess": r["os_guess"], "is_active": r["is_active"],
                "last_seen": r["last_seen"], "is_stale": r["is_stale"], "incident_count": r["incident_count"],
                "high_risk_ports": ",".join(str(p) for p in r["high_risk_ports"]),
            }
            for r in data["table"]
        ]
        fieldnames = list(rows[0].keys()) if rows else [
            "ip_address", "hostname", "mac_address", "vendor", "os_guess", "is_active",
            "last_seen", "is_stale", "incident_count", "high_risk_ports",
        ]
    elif report_type == "event_statistics":
        rows = data["top_signatures"]
        fieldnames = ["signature", "count", "previous_count"]
    else:
        raise ValueError(f"CSV is not offered for {report_type!r}")

    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue().encode("utf-8")
