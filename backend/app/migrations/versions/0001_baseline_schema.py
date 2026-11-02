"""Baseline schema.

Revision ID: 0001
Revises:
Create Date: 2026-11-02

The schema as it was when migrations were introduced. Databases created earlier by
create_all() already hold some or all of it, so every table, index and enum type is
created only when missing: this revision adopts those databases without touching data.
Later revisions are ordinary migrations.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Native enum types on PostgreSQL (created once, before the tables); VARCHAR elsewhere.
ENUMS = {
    "assettype": postgresql.ENUM(
        "ipv4", "ipv6", "hostname", "domain", "webapp", name="assettype", create_type=False
    ),
    "findingconfidence": postgresql.ENUM(
        "confirmed", "likely", "unverified", name="findingconfidence", create_type=False
    ),
    "findingseverity": postgresql.ENUM(
        "critical", "high", "medium", "low", "info", name="findingseverity", create_type=False
    ),
    "findingstatus": postgresql.ENUM(
        "open",
        "in_progress",
        "fixed",
        "accepted_risk",
        "false_positive",
        name="findingstatus",
        create_type=False,
    ),
    "reporttype": postgresql.ENUM("executive", "technical", name="reporttype", create_type=False),
    "scanstatus": postgresql.ENUM(
        "queued",
        "validating",
        "running",
        "parsing",
        "normalizing",
        "completed",
        "cancel_requested",
        "cancelled",
        "failed",
        "timed_out",
        name="scanstatus",
        create_type=False,
    ),
    "serviceprotocol": postgresql.ENUM("tcp", "udp", name="serviceprotocol", create_type=False),
    "servicestate": postgresql.ENUM(
        "open", "closed", "filtered", name="servicestate", create_type=False
    ),
    "targettype": postgresql.ENUM(
        "ipv4",
        "ipv4_cidr",
        "ipv6",
        "ipv6_cidr",
        "hostname",
        "domain",
        "url",
        name="targettype",
        create_type=False,
    ),
    "userrole": postgresql.ENUM("admin", "analyst", "viewer", name="userrole", create_type=False),
}


def _create_table(name: str, *elements: sa.SchemaItem) -> None:
    if not sa.inspect(op.get_bind()).has_table(name):
        op.create_table(name, *elements)


def _create_index(table: str, name: str, columns: list[str], *, unique: bool) -> None:
    existing = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes(table)}
    if name not in existing:
        op.create_index(name, table, columns, unique=unique)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for enum_type in ENUMS.values():
            enum_type.create(bind, checkfirst=True)

    _create_table(
        "organizations",
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("max_concurrent_scans", sa.Integer(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("organizations", "ix_organizations_id", ["id"], unique=False)
    _create_index("organizations", "ix_organizations_name", ["name"], unique=True)
    _create_index("organizations", "ix_organizations_slug", ["slug"], unique=True)

    _create_table(
        "users",
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("is_superuser", sa.Boolean(), nullable=False),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("users", "ix_users_email", ["email"], unique=True)
    _create_index("users", "ix_users_id", ["id"], unique=False)

    _create_table(
        "assets",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("asset_type", ENUMS["assettype"], nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("hostname", sa.String(length=512), nullable=True),
        sa.Column("domain", sa.String(length=512), nullable=True),
        sa.Column("os_name", sa.String(length=255), nullable=True),
        sa.Column("os_version", sa.String(length=255), nullable=True),
        sa.Column("os_confidence", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("discovery_source", sa.String(length=100), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("assets", "ix_assets_hostname", ["hostname"], unique=False)
    _create_index("assets", "ix_assets_id", ["id"], unique=False)
    _create_index("assets", "ix_assets_ip_address", ["ip_address"], unique=False)
    _create_index("assets", "ix_assets_organization_id", ["organization_id"], unique=False)

    _create_table(
        "audit_logs",
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("object_type", sa.String(length=100), nullable=False),
        sa.Column("object_id", sa.String(length=36), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("audit_logs", "ix_audit_logs_action", ["action"], unique=False)
    _create_index("audit_logs", "ix_audit_logs_actor_id", ["actor_id"], unique=False)
    _create_index("audit_logs", "ix_audit_logs_id", ["id"], unique=False)
    _create_index(
        "audit_logs", "ix_audit_logs_org_timestamp", ["organization_id", "timestamp"], unique=False
    )
    _create_index("audit_logs", "ix_audit_logs_organization_id", ["organization_id"], unique=False)
    _create_index("audit_logs", "ix_audit_logs_timestamp", ["timestamp"], unique=False)

    _create_table(
        "organization_memberships",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role", ENUMS["userrole"], nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("invited_by", sa.Uuid(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["invited_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_user"),
    )
    _create_index(
        "organization_memberships", "ix_organization_memberships_id", ["id"], unique=False
    )
    _create_index(
        "organization_memberships",
        "ix_organization_memberships_organization_id",
        ["organization_id"],
        unique=False,
    )
    _create_index(
        "organization_memberships", "ix_organization_memberships_user_id", ["user_id"], unique=False
    )

    _create_table(
        "scan_profiles",
        sa.Column("organization_id", sa.Uuid(), nullable=True),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("requires_confirmation", sa.Boolean(), nullable=False),
        sa.Column("is_intrusive", sa.Boolean(), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("scan_profiles", "ix_scan_profiles_id", ["id"], unique=False)
    _create_index(
        "scan_profiles", "ix_scan_profiles_organization_id", ["organization_id"], unique=False
    )

    _create_table(
        "scope_authorizations",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("signer_name", sa.String(length=255), nullable=False),
        sa.Column("signer_email", sa.String(length=320), nullable=False),
        sa.Column("authorization_date", sa.Date(), nullable=False),
        sa.Column("expiration_date", sa.Date(), nullable=True),
        sa.Column("document_path", sa.String(length=512), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("is_revoked", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.Uuid(), nullable=True),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["revoked_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("scope_authorizations", "ix_scope_authorizations_id", ["id"], unique=False)
    _create_index(
        "scope_authorizations",
        "ix_scope_authorizations_organization_id",
        ["organization_id"],
        unique=False,
    )

    _create_table(
        "authorized_targets",
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("target_type", ENUMS["targettype"], nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorization_id"], ["scope_authorizations.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index(
        "authorized_targets",
        "ix_authorized_targets_authorization_id",
        ["authorization_id"],
        unique=False,
    )
    _create_index("authorized_targets", "ix_authorized_targets_id", ["id"], unique=False)

    _create_table(
        "scans",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("authorization_id", sa.Uuid(), nullable=False),
        sa.Column("profile_id", sa.Uuid(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=False),
        sa.Column("status", ENUMS["scanstatus"], nullable=False),
        sa.Column("current_stage", sa.String(length=100), nullable=True),
        sa.Column("current_tool", sa.String(length=100), nullable=True),
        sa.Column("current_target", sa.String(length=512), nullable=True),
        sa.Column("progress_pct", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("rq_job_id", sa.String(length=255), nullable=True),
        sa.Column("raw_output_path", sa.String(length=512), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("timed_out_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorization_id"], ["scope_authorizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["profile_id"], ["scan_profiles.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("scans", "ix_scans_authorization_id", ["authorization_id"], unique=False)
    _create_index("scans", "ix_scans_id", ["id"], unique=False)
    _create_index("scans", "ix_scans_org_queued_at", ["organization_id", "queued_at"], unique=False)
    _create_index("scans", "ix_scans_organization_id", ["organization_id"], unique=False)
    _create_index("scans", "ix_scans_status", ["status"], unique=False)

    _create_table(
        "services",
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("protocol", ENUMS["serviceprotocol"], nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("service_name", sa.String(length=100), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=255), nullable=True),
        sa.Column("extra_info", sa.Text(), nullable=True),
        sa.Column("state", ENUMS["servicestate"], nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("services", "ix_services_asset_id", ["asset_id"], unique=False)
    _create_index("services", "ix_services_id", ["id"], unique=False)

    _create_table(
        "findings",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("service_id", sa.Uuid(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("source_tool", sa.String(length=100), nullable=False),
        sa.Column("scanner_reference", sa.String(length=512), nullable=True),
        sa.Column("confidence", ENUMS["findingconfidence"], nullable=False),
        sa.Column("cve_ids", sa.JSON(), nullable=False),
        sa.Column("cwe_ids", sa.JSON(), nullable=False),
        sa.Column("severity", ENUMS["findingseverity"], nullable=False),
        sa.Column("cvss_score", sa.Numeric(precision=4, scale=1), nullable=True),
        sa.Column("cvss_vector", sa.String(length=100), nullable=True),
        sa.Column("priority_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("status", ENUMS["findingstatus"], nullable=False),
        sa.Column("assigned_to", sa.Uuid(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_risk_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("accepted_risk_reason", sa.Text(), nullable=True),
        sa.Column("first_seen_scan_id", sa.Uuid(), nullable=True),
        sa.Column("last_seen_scan_id", sa.Uuid(), nullable=True),
        sa.Column("llm_remediation", sa.JSON(), nullable=True),
        sa.Column("llm_remediation_cached_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("llm_remediation_failed", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["first_seen_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["last_seen_scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("findings", "ix_findings_asset_id", ["asset_id"], unique=False)
    _create_index("findings", "ix_findings_fingerprint", ["fingerprint"], unique=False)
    _create_index(
        "findings", "ix_findings_first_seen_scan_id", ["first_seen_scan_id"], unique=False
    )
    _create_index("findings", "ix_findings_id", ["id"], unique=False)
    _create_index("findings", "ix_findings_last_seen_scan_id", ["last_seen_scan_id"], unique=False)
    _create_index(
        "findings", "ix_findings_org_priority", ["organization_id", "priority_score"], unique=False
    )
    _create_index("findings", "ix_findings_organization_id", ["organization_id"], unique=False)
    _create_index("findings", "ix_findings_severity", ["severity"], unique=False)
    _create_index("findings", "ix_findings_status", ["status"], unique=False)

    _create_table(
        "reports",
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=True),
        sa.Column("report_type", ENUMS["reporttype"], nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("generated_by", sa.Uuid(), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("html_path", sa.String(length=512), nullable=True),
        sa.Column("pdf_path", sa.String(length=512), nullable=True),
        sa.Column("access_token", sa.String(length=64), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["generated_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("access_token"),
    )
    _create_index("reports", "ix_reports_id", ["id"], unique=False)
    _create_index("reports", "ix_reports_organization_id", ["organization_id"], unique=False)
    _create_index("reports", "ix_reports_scan_id", ["scan_id"], unique=False)

    _create_table(
        "scan_events",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("scan_events", "ix_scan_events_id", ["id"], unique=False)
    _create_index("scan_events", "ix_scan_events_scan_id", ["scan_id"], unique=False)
    _create_index(
        "scan_events", "ix_scan_events_scan_id_created_at", ["scan_id", "created_at"], unique=False
    )

    _create_table(
        "scan_targets",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("target_value", sa.String(length=512), nullable=False),
        sa.Column("target_type", ENUMS["targettype"], nullable=False),
        sa.Column("scope_verified", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index("scan_targets", "ix_scan_targets_id", ["id"], unique=False)
    _create_index("scan_targets", "ix_scan_targets_scan_id", ["scan_id"], unique=False)

    _create_table(
        "finding_assignments",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("assigned_to", sa.Uuid(), nullable=False),
        sa.Column("assigned_by", sa.Uuid(), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["assigned_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index(
        "finding_assignments", "ix_finding_assignments_finding_id", ["finding_id"], unique=False
    )
    _create_index("finding_assignments", "ix_finding_assignments_id", ["id"], unique=False)
    _create_index(
        "finding_assignments", "ix_finding_assignments_is_current", ["is_current"], unique=False
    )

    _create_table(
        "finding_evidence",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("evidence_type", sa.String(length=100), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index(
        "finding_evidence", "ix_finding_evidence_finding_id", ["finding_id"], unique=False
    )
    _create_index("finding_evidence", "ix_finding_evidence_id", ["id"], unique=False)
    _create_index("finding_evidence", "ix_finding_evidence_scan_id", ["scan_id"], unique=False)

    _create_table(
        "remediation_notes",
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("status_at_time", ENUMS["findingstatus"], nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    _create_index(
        "remediation_notes", "ix_remediation_notes_finding_id", ["finding_id"], unique=False
    )
    _create_index("remediation_notes", "ix_remediation_notes_id", ["id"], unique=False)

    _create_table(
        "scan_finding_snapshots",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", ENUMS["findingseverity"], nullable=False),
        sa.Column("priority_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id", "finding_id"),
    )
    _create_table(
        "scan_findings",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id", "finding_id"),
    )
    _create_index("scan_findings", "ix_scan_findings_finding_id", ["finding_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_scan_findings_finding_id", table_name="scan_findings")

    op.drop_table("scan_findings")
    op.drop_table("scan_finding_snapshots")
    op.drop_index("ix_remediation_notes_id", table_name="remediation_notes")
    op.drop_index("ix_remediation_notes_finding_id", table_name="remediation_notes")

    op.drop_table("remediation_notes")
    op.drop_index("ix_finding_evidence_scan_id", table_name="finding_evidence")
    op.drop_index("ix_finding_evidence_id", table_name="finding_evidence")
    op.drop_index("ix_finding_evidence_finding_id", table_name="finding_evidence")

    op.drop_table("finding_evidence")
    op.drop_index("ix_finding_assignments_is_current", table_name="finding_assignments")
    op.drop_index("ix_finding_assignments_id", table_name="finding_assignments")
    op.drop_index("ix_finding_assignments_finding_id", table_name="finding_assignments")

    op.drop_table("finding_assignments")
    op.drop_index("ix_scan_targets_scan_id", table_name="scan_targets")
    op.drop_index("ix_scan_targets_id", table_name="scan_targets")

    op.drop_table("scan_targets")
    op.drop_index("ix_scan_events_scan_id_created_at", table_name="scan_events")
    op.drop_index("ix_scan_events_scan_id", table_name="scan_events")
    op.drop_index("ix_scan_events_id", table_name="scan_events")

    op.drop_table("scan_events")
    op.drop_index("ix_reports_scan_id", table_name="reports")
    op.drop_index("ix_reports_organization_id", table_name="reports")
    op.drop_index("ix_reports_id", table_name="reports")

    op.drop_table("reports")
    op.drop_index("ix_findings_status", table_name="findings")
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_organization_id", table_name="findings")
    op.drop_index("ix_findings_org_priority", table_name="findings")
    op.drop_index("ix_findings_last_seen_scan_id", table_name="findings")
    op.drop_index("ix_findings_id", table_name="findings")
    op.drop_index("ix_findings_first_seen_scan_id", table_name="findings")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")

    op.drop_table("findings")
    op.drop_index("ix_services_id", table_name="services")
    op.drop_index("ix_services_asset_id", table_name="services")

    op.drop_table("services")
    op.drop_index("ix_scans_status", table_name="scans")
    op.drop_index("ix_scans_organization_id", table_name="scans")
    op.drop_index("ix_scans_org_queued_at", table_name="scans")
    op.drop_index("ix_scans_id", table_name="scans")
    op.drop_index("ix_scans_authorization_id", table_name="scans")

    op.drop_table("scans")
    op.drop_index("ix_authorized_targets_id", table_name="authorized_targets")
    op.drop_index("ix_authorized_targets_authorization_id", table_name="authorized_targets")

    op.drop_table("authorized_targets")
    op.drop_index("ix_scope_authorizations_organization_id", table_name="scope_authorizations")
    op.drop_index("ix_scope_authorizations_id", table_name="scope_authorizations")

    op.drop_table("scope_authorizations")
    op.drop_index("ix_scan_profiles_organization_id", table_name="scan_profiles")
    op.drop_index("ix_scan_profiles_id", table_name="scan_profiles")

    op.drop_table("scan_profiles")
    op.drop_index("ix_organization_memberships_user_id", table_name="organization_memberships")
    op.drop_index(
        "ix_organization_memberships_organization_id", table_name="organization_memberships"
    )
    op.drop_index("ix_organization_memberships_id", table_name="organization_memberships")

    op.drop_table("organization_memberships")
    op.drop_index("ix_audit_logs_timestamp", table_name="audit_logs")
    op.drop_index("ix_audit_logs_organization_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_org_timestamp", table_name="audit_logs")
    op.drop_index("ix_audit_logs_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_actor_id", table_name="audit_logs")
    op.drop_index("ix_audit_logs_action", table_name="audit_logs")

    op.drop_table("audit_logs")
    op.drop_index("ix_assets_organization_id", table_name="assets")
    op.drop_index("ix_assets_ip_address", table_name="assets")
    op.drop_index("ix_assets_id", table_name="assets")
    op.drop_index("ix_assets_hostname", table_name="assets")

    op.drop_table("assets")
    op.drop_index("ix_users_id", table_name="users")
    op.drop_index("ix_users_email", table_name="users")

    op.drop_table("users")
    op.drop_index("ix_organizations_slug", table_name="organizations")
    op.drop_index("ix_organizations_name", table_name="organizations")
    op.drop_index("ix_organizations_id", table_name="organizations")

    op.drop_table("organizations")

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for enum_type in ENUMS.values():
            enum_type.drop(bind, checkfirst=True)
