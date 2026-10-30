"""Remediation generation and caching service."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.core.audit import AuditAction, audit_log
from app.core.exceptions import NotFoundError
from app.core.rate_limit import enforce_rate_limit
from app.llm import describe_llm_provider, generate_remediation
from app.models.finding import Finding
from app.models.user import User
from app.schemas.remediation import RemediationSchema

logger = logging.getLogger(__name__)


class RemediationService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def get_or_generate_remediation(
        self,
        org_id: uuid.UUID,
        finding_id: uuid.UUID,
        actor: User,
        force_refresh: bool = False,
    ) -> RemediationSchema:
        """
        Return cached remediation guidance, or generate it with the configured LLM.

        Cached reads are not rate limited; generation is limited per user by
        LLM_RATE_LIMIT. A provider call can take up to LLM_TIMEOUT_SECONDS, so
        the values it needs are copied first and the read transaction is ended:
        no database connection is held while the provider runs.
        """
        stmt = (
            select(Finding)
            .options(joinedload(Finding.service), joinedload(Finding.asset))
            .where(
                Finding.id == finding_id,
                Finding.organization_id == org_id,
            )
        )
        finding = self.db.scalars(stmt).first()
        if not finding:
            raise NotFoundError(f"Finding {finding_id} not found")

        # Return cached remediation if present
        if finding.llm_remediation and not force_refresh:
            try:
                return RemediationSchema.model_validate(finding.llm_remediation)
            except PydanticValidationError:
                logger.warning(
                    "Cached remediation for finding %s is invalid; regenerating", finding_id
                )

        actor_id = actor.id
        actor_email = actor.email
        enforce_rate_limit("llm", str(actor_id), get_settings().LLM_RATE_LIMIT)

        # Copy everything the prompt needs; the ORM objects expire on rollback below.
        service = finding.service
        asset = finding.asset
        product_name = None
        if service and service.product:
            product_name = f"{service.product} {service.version or ''}".strip()
        known_identifiers: tuple[str, ...] = ()
        if asset is not None:
            known_identifiers = tuple(
                value for value in (asset.ip_address, asset.hostname, asset.domain) if value
            )
        prompt_values = {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "cve_ids": list(finding.cve_ids or []),
            "cwe_ids": list(finding.cwe_ids or []),
            "port": service.port if service else None,
            "protocol": service.protocol.value if service else None,
            "service_product": product_name,
            "source_tool": finding.source_tool,
            "scanner_reference": finding.scanner_reference,
            "known_identifiers": known_identifiers,
        }

        # End the read transaction and return the pooled connection before the slow call.
        self.db.rollback()

        try:
            schema = generate_remediation(**prompt_values)
        except Exception:
            logger.exception("Failed to generate remediation for finding %s", finding_id)
            self._mark_failed(finding_id)
            raise

        provider_name, model = describe_llm_provider()
        finding = self.db.get(Finding, finding_id)
        if finding is None:  # deleted while the provider was running
            raise NotFoundError(f"Finding {finding_id} not found")
        finding.llm_remediation = schema.model_dump()
        finding.llm_remediation_cached_at = datetime.now(UTC)
        finding.llm_remediation_failed = schema.source != "llm"

        audit_log(
            self.db,
            action=AuditAction.REMEDIATION_GENERATE,
            resource_type="finding",
            resource_id=str(finding_id),
            organization_id=org_id,
            actor_id=actor_id,
            actor_email=actor_email,
            metadata={"provider": provider_name, "model": model, "source": schema.source},
            commit=False,
        )
        self.db.commit()
        return schema

    def _mark_failed(self, finding_id: uuid.UUID) -> None:
        """Record a failed generation; never masks the original error."""
        try:
            finding = self.db.get(Finding, finding_id)
            if finding is not None:
                finding.llm_remediation_failed = True
                self.db.commit()
        except Exception:
            self.db.rollback()
            logger.exception("Could not record the remediation failure for finding %s", finding_id)
