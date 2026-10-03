"""Aggregate router mounted at /api.

The `/api` prefix lives here rather than in nginx so that the paths the
backend serves are byte-identical to the paths the browser requests — which is
what makes the refresh cookie's `path=/api/auth` scoping work.
"""

from fastapi import APIRouter

from app.api.routes import (
    assets,
    audit,
    auth,
    correlation,
    email_admin,
    email_prefs,
    events,
    firewall,
    health,
    incidents,
    intel,
    pcap,
    password_reset,
    pipeline,
    reports,
    sensor,
    stats,
    users,
    webhooks,
)

api_router = APIRouter(prefix="/api")

api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(password_reset.router)
api_router.include_router(users.router)
api_router.include_router(audit.router)
api_router.include_router(assets.router)
api_router.include_router(sensor.router)
api_router.include_router(pipeline.router)
api_router.include_router(events.router)
api_router.include_router(stats.router)
api_router.include_router(correlation.router)
api_router.include_router(incidents.router)
api_router.include_router(reports.router)
api_router.include_router(firewall.router)
api_router.include_router(pcap.router)
api_router.include_router(intel.router)
api_router.include_router(email_admin.router)
api_router.include_router(email_prefs.router)
api_router.include_router(webhooks.router)
