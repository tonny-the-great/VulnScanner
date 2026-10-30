"""FastAPI application factory and lifecycle."""

from __future__ import annotations

import copy
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.responses import Response
from starlette.types import Scope

from app.config import get_settings
from app.core.exceptions import AppError
from app.core.logging import configure_logging
from app.core.password_policy import validate_password_policy
from app.core.request_context import RequestContextMiddleware
from app.core.security import hash_password
from app.core.security_headers import SecurityHeadersMiddleware
from app.database import engine, get_db_context
from app.models import Base
from app.models.scan import ScanProfile
from app.models.user import User
from app.routers import (
    assets_router,
    audit_router,
    auth_router,
    authorizations_router,
    events_router,
    findings_router,
    organizations_router,
    platform_audit_router,
    reports_router,
    scans_router,
    system_router,
)
from app.scanning.profiles import DEFAULT_PROFILES
from app.services.scan_reaper import reap_stale_scans

configure_logging()
logger = logging.getLogger(__name__)

# Built-in profile fields kept in sync with DEFAULT_PROFILES. is_enabled is
# deliberately absent: an operator's decision to disable a profile is kept.
_SYNCED_PROFILE_FIELDS = (
    "display_name",
    "description",
    "requires_confirmation",
    "is_intrusive",
    "config_json",
)


def ensure_indexes() -> None:
    """Create indexes missing from an existing database.

    create_all() only creates missing tables, so indexes added to existing tables
    would otherwise never reach a database created by an earlier version.
    """
    for table in Base.metadata.sorted_tables:
        for index in table.indexes:
            try:
                index.create(bind=engine, checkfirst=True)
            except Exception:
                logger.warning(
                    "Could not create index %s on %s", index.name, table.name, exc_info=True
                )


def sync_system_profiles(db: Session) -> list[str]:
    """Insert or update the built-in (platform-wide) scan profiles; return changed names.

    Profiles not listed in DEFAULT_PROFILES are left untouched.
    """
    changed: list[str] = []
    for p_data in DEFAULT_PROFILES:
        stmt = select(ScanProfile).where(
            ScanProfile.name == p_data["name"],
            ScanProfile.organization_id.is_(None),
        )
        existing = db.scalars(stmt).first()
        if existing is None:
            db.add(ScanProfile(
                name=p_data["name"],
                organization_id=None,
                is_enabled=True,
                **{field: copy.deepcopy(p_data[field]) for field in _SYNCED_PROFILE_FIELDS},
            ))
            changed.append(p_data["name"])
            continue
        updated = False
        for field in _SYNCED_PROFILE_FIELDS:
            if getattr(existing, field) != p_data[field]:
                setattr(existing, field, copy.deepcopy(p_data[field]))
                updated = True
        if updated:
            changed.append(p_data["name"])
    db.commit()
    if changed:
        logger.info("Synchronized built-in scan profiles: %s", ", ".join(changed))
    return changed


def _bootstrap_superuser(db: Session) -> None:
    settings = get_settings()
    email = settings.FIRST_SUPERUSER_EMAIL.strip().lower()
    password = settings.FIRST_SUPERUSER_PASSWORD
    if not email or not password:
        return
    if db.scalars(select(User).where(User.email == email)).first():
        return
    try:
        validate_password_policy(password, email)
    except ValueError as exc:
        # The policy messages describe the problem without repeating the password.
        logger.error(
            "FIRST_SUPERUSER_PASSWORD does not meet the password policy (%s); "
            "the bootstrap superuser was not created",
            exc,
        )
        return
    logger.info("Seeding initial superuser: %s", email)
    db.add(User(
        email=email,
        password_hash=hash_password(password),
        full_name="Platform Administrator",
        is_active=True,
        is_superuser=True,
    ))
    db.commit()


def seed_database() -> None:
    """Initialize the DB schema, built-in scan profiles and the bootstrap superuser."""
    Base.metadata.create_all(bind=engine)
    ensure_indexes()
    with get_db_context() as db:
        sync_system_profiles(db)
        _bootstrap_superuser(db)


def log_configuration_warnings() -> list[str]:
    """Log (and return) warnings about risky but permitted configuration."""
    settings = get_settings()
    warnings: list[str] = []
    if settings.is_production:
        insecure = [o for o in settings.cors_origins_list if o.lower().startswith("http://")]
        if insecure:
            warnings.append(
                "CORS_ORIGINS lists plain-HTTP origins in production "
                f"({', '.join(insecure)}); secure session cookies require HTTPS"
            )
        if settings.SQL_ECHO:
            warnings.append(
                "SQL_ECHO is enabled in production; statement parameters, including "
                "credential rows, are written to the logs"
            )
        if settings.DATABASE_URL.startswith("sqlite"):
            warnings.append(
                "DATABASE_URL uses SQLite in production; use PostgreSQL for concurrent "
                "API and worker access"
            )
        if settings.ALLOW_SELF_REGISTRATION and settings.ORG_CREATION == "any_user":
            warnings.append(
                "Self-registration and organization creation are open: anyone who can "
                "reach the console can register, create an organization and launch scans. "
                "Set ALLOW_SELF_REGISTRATION=false or ORG_CREATION=superuser"
            )
    if not settings.RATE_LIMIT_ENABLED:
        warnings.append("RATE_LIMIT_ENABLED is false; login and registration are not rate limited")
    for message in warnings:
        logger.warning(message)
    return warnings


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Initializing VulnScanner platform...")
    seed_database()
    try:
        with get_db_context() as db:
            reap_stale_scans(db, api_startup=True)
    except Exception:
        logger.exception("Stale scan check failed at startup")
    log_configuration_warnings()
    yield
    logger.info("Shutting down VulnScanner platform.")


class ConsoleStaticFiles(StaticFiles):
    """Serves the console; the browser test harness and fixtures are never served."""

    async def get_response(self, path: str, scope: Scope) -> Response:
        # get_path() uses OS separators; Windows also ignores case and trailing dots.
        first = path.replace("\\", "/").strip("/").split("/", 1)[0]
        if first.rstrip(". ").lower() == "tests":
            return PlainTextResponse("Not Found", status_code=404)
        return await super().get_response(path, scope)


def create_app() -> FastAPI:
    settings = get_settings()
    docs_enabled = settings.api_docs_enabled
    app = FastAPI(
        title="VulnScanner API",
        description=(
            "Production-oriented vulnerability assessment and remediation management platform."
        ),
        version="0.1.0",
        lifespan=lifespan,
        # Disabled in production unless ENABLE_API_DOCS=true.
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    # Middleware added last runs first: security headers wrap every response,
    # including CORS preflights.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # ── Exception handlers ────────────────────────────────────────────────────
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        # Each domain exception carries its own HTTP status and optional error_type.
        content = {"detail": exc.message}
        if exc.error_type:
            content["error_type"] = exc.error_type
        return JSONResponse(status_code=exc.status_code, content=content, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError):
        # FastAPI's default 422 echoes each error's 'input' (and 'ctx'), which for
        # a model-level validator is the whole request body, passwords included.
        errors = [
            {key: value for key, value in error.items() if key not in {"input", "ctx", "url"}}
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(request: Request, exc: IntegrityError):
        # A concurrent duplicate that slipped past a service-level check. The
        # exception text holds SQL parameters (emails, names), so it is not logged.
        logger.warning(
            "Integrity constraint violation on %s %s (%s)",
            request.method, request.url.path, type(exc.orig).__name__,
        )
        return JSONResponse(
            status_code=409,
            content={
                "detail": "A record with these values already exists",
                "error_type": "conflict",
            },
        )

    # ── Mount Routers ─────────────────────────────────────────────────────────
    api_prefix = "/api/v1"
    app.include_router(system_router)
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(organizations_router, prefix=api_prefix)
    app.include_router(authorizations_router, prefix=api_prefix)
    app.include_router(scans_router, prefix=api_prefix)
    app.include_router(assets_router, prefix=api_prefix)
    app.include_router(findings_router, prefix=api_prefix)
    app.include_router(reports_router, prefix=api_prefix)
    app.include_router(audit_router, prefix=api_prefix)
    app.include_router(platform_audit_router, prefix=api_prefix)
    app.include_router(events_router, prefix=api_prefix)

    # ── Mount Frontend if present ─────────────────────────────────────────────
    frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
    if frontend_dir.exists():
        console = ConsoleStaticFiles(directory=str(frontend_dir), html=True)
        app.mount("/", console, name="frontend")

    return app


app = create_app()
