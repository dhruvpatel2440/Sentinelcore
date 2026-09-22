"""Import every model so `Base.metadata` is complete for Alembic autogenerate.

Adding a model without importing it here means Alembic will silently generate a
migration that drops it. Add new model modules to this file.
"""

from app.db.base import Base  # noqa: F401
from app.models.asset import Asset, AssetPort  # noqa: F401
from app.models.audit_log import AuditLog  # noqa: F401
from app.models.correlation import CorrelationRule, IncidentCandidate, RuleRun  # noqa: F401
from app.models.event import Event  # noqa: F401
from app.models.incident import Incident, IncidentEvent, IncidentHistory  # noqa: F401
from app.models.report import Report, ReportSchedule  # noqa: F401
from app.models.saved_search import SavedSearch  # noqa: F401
from app.models.scan import Scan  # noqa: F401
from app.models.sensor import RuleOverride, RuleSource, SensorEvent  # noqa: F401
from app.models.user import User  # noqa: F401

__all__ = ["Base"]
