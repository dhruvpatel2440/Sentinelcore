"""The 21 email types (U10) and their static routing metadata.

Nothing here talks to Brevo or the database — `service.enqueue()` and
`worker.py` read these tables to decide who can get a given type and how it
is throttled. Keeping the metadata in one place is what lets
`test_rendering.py` parametrise "every EmailType has a template" without a
hand-maintained list drifting from the real one.
"""

from __future__ import annotations

from app.models.email import EmailType  # noqa: F401 — re-exported for callers
from app.models.event import Severity

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_at_least(value: Severity, floor: Severity) -> bool:
    return _SEVERITY_RANK[value] >= _SEVERITY_RANK[floor]


# Incident-class mails are gated by the recipient's `min_severity` preference.
SEVERITY_GATED_TYPES: frozenset[EmailType] = frozenset(
    {
        EmailType.E01_NEW_INCIDENT,
        EmailType.E02_INCIDENT_ESCALATED,
    }
)

# Security/account + system-down mail: the user cannot opt out, and it is
# never folded into a digest. Can still be paused globally by an admin
# (E15 only — E19/E20/E21 are never disableable at all, see LOCKED_TYPES).
NEVER_DIGESTED_TYPES: frozenset[EmailType] = frozenset(
    {
        EmailType.E15_SENSOR_HEALTH,
        EmailType.E19_ACCOUNT_PASSWORD,
        EmailType.E20_ACCOUNT_CHANGED,
        EmailType.E21_SUSPICIOUS_LOGIN,
    }
)

# A user cannot disable these in their own preferences (`types_disabled`).
LOCKED_TYPES: frozenset[EmailType] = frozenset(
    {
        EmailType.E15_SENSOR_HEALTH,
        EmailType.E19_ACCOUNT_PASSWORD,
        EmailType.E20_ACCOUNT_CHANGED,
        EmailType.E21_SUSPICIOUS_LOGIN,
    }
)

# Eligible to be rolled into the E14 digest instead of sent instantly, when
# the recipient's `delivery_mode` is `digest`.
DIGEST_ELIGIBLE_TYPES: frozenset[EmailType] = frozenset(
    {
        EmailType.E01_NEW_INCIDENT,
        EmailType.E02_INCIDENT_ESCALATED,
        EmailType.E03_INCIDENT_ASSIGNED,
        EmailType.E06_THREAT_INTEL_MATCH,
        EmailType.E07_BLOCK_APPLIED,
        EmailType.E09_BLOCK_EXPIRED,
        EmailType.E10_BLOCK_REFUSED,
        EmailType.E16_PIPELINE_BACKLOG,
        EmailType.E17_FEED_FAILING,
        EmailType.E18_FIREWALL_DRIFT,
    }
)

# Admins-only destinations (system health class D, never routed to analysts).
ADMIN_ONLY_TYPES: frozenset[EmailType] = frozenset(
    {
        EmailType.E15_SENSOR_HEALTH,
        EmailType.E16_PIPELINE_BACKLOG,
        EmailType.E17_FEED_FAILING,
        EmailType.E18_FIREWALL_DRIFT,
    }
)

# Default on/off per type for `email_settings.types_enabled` (admin can flip
# any of these; LOCKED_TYPES ship enabled and an admin pause still applies).
DEFAULT_ENABLED: dict[EmailType, bool] = {t: True for t in EmailType}

# Subject prefix severity tag shown for incident/health mails. None means the
# type's subject carries no bracketed severity.
SEVERITY_IN_SUBJECT_TYPES: frozenset[EmailType] = frozenset(
    {
        EmailType.E01_NEW_INCIDENT,
        EmailType.E02_INCIDENT_ESCALATED,
        EmailType.E05_INCIDENT_RESOLVED,
        EmailType.E06_THREAT_INTEL_MATCH,
        EmailType.E09_BLOCK_EXPIRED,
        EmailType.E15_SENSOR_HEALTH,
        EmailType.E21_SUSPICIOUS_LOGIN,
    }
)

TEMPLATE_BASENAME: dict[EmailType, str] = {t: t.value.lower() for t in EmailType}
