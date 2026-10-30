"""
Models package — import all models here so Alembic can discover them.
"""

from app.models.asset import Asset, AssetType, Service, ServiceProtocol, ServiceState
from app.models.audit import AuditLog
from app.models.authorization import (
    AuthorizedTarget,
    ScopeAuthorization,
    TargetType,
)
from app.models.base import Base, TimestampMixin, UTCDateTime, UUIDPrimaryKeyMixin
from app.models.finding import (
    Finding,
    FindingAssignment,
    FindingConfidence,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    RemediationNote,
    ScanFinding,
    ScanFindingSnapshot,
    finding_seen_in_scan,
)
from app.models.membership import OrganizationMembership, UserRole
from app.models.organization import Organization
from app.models.report import Report, ReportType
from app.models.scan import (
    ALLOWED_SCAN_TRANSITIONS,
    TERMINAL_SCAN_STATES,
    Scan,
    ScanEvent,
    ScanProfile,
    ScanStatus,
    ScanTarget,
)
from app.models.user import User

__all__ = [
    "Base",
    "TimestampMixin",
    "UTCDateTime",
    "UUIDPrimaryKeyMixin",
    "Organization",
    "User",
    "OrganizationMembership",
    "UserRole",
    "ScopeAuthorization",
    "AuthorizedTarget",
    "TargetType",
    "Scan",
    "ScanProfile",
    "ScanTarget",
    "ScanEvent",
    "ScanStatus",
    "ALLOWED_SCAN_TRANSITIONS",
    "TERMINAL_SCAN_STATES",
    "Asset",
    "Service",
    "AssetType",
    "ServiceState",
    "ServiceProtocol",
    "Finding",
    "FindingEvidence",
    "RemediationNote",
    "FindingAssignment",
    "FindingSeverity",
    "FindingStatus",
    "FindingConfidence",
    "ScanFinding",
    "ScanFindingSnapshot",
    "finding_seen_in_scan",
    "Report",
    "ReportType",
    "AuditLog",
]
