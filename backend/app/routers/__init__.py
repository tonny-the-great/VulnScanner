"""Routers package."""

from app.routers.assets import router as assets_router
from app.routers.audit import platform_router as platform_audit_router
from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.authorizations import router as authorizations_router
from app.routers.events import router as events_router
from app.routers.findings import router as findings_router
from app.routers.organizations import router as organizations_router
from app.routers.reports import router as reports_router
from app.routers.scans import router as scans_router
from app.routers.system import router as system_router

__all__ = [
    "auth_router",
    "organizations_router",
    "authorizations_router",
    "scans_router",
    "assets_router",
    "findings_router",
    "reports_router",
    "audit_router",
    "platform_audit_router",
    "events_router",
    "system_router",
]
