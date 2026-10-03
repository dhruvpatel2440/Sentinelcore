from __future__ import annotations

from app.models.report import ReportType

from . import asset_inventory, event_statistics, incident_detail, incident_summary

REGISTRY = {
    ReportType.INCIDENT_SUMMARY: incident_summary,
    ReportType.INCIDENT_DETAIL: incident_detail,
    ReportType.ASSET_INVENTORY: asset_inventory,
    ReportType.EVENT_STATISTICS: event_statistics,
}

__all__ = ["REGISTRY"]
