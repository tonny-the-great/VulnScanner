"""Shared fixtures for API workflow tests.

Scanner stand-ins run local Python only; no network scan is performed.
"""

import sys
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.asset import AssetType, ServiceProtocol
from app.models.finding import FindingConfidence, FindingSeverity
from app.models.scan import ScanProfile
from app.scanning.adapters.base import (
    RawDiscoveredAsset,
    RawDiscoveredService,
    RawFinding,
    RawFindingEvidence,
    RawScannerResult,
)


class LocalScanner:
    name = "nmap"
    available = True
    command = "print('local fixture scanner')"
    exit_code = 0
    parser_error = None

    def is_available(self):
        return self.available

    def build_command(self, targets, config, output_file_base):
        return [sys.executable, "-c", self.command]

    def parse_output(self, file_base, exit_code, stdout, stderr, execution_time):
        return RawScannerResult(
            tool_name=self.name,
            exit_code=exit_code or self.exit_code,
            execution_time_seconds=execution_time,
            error_message=self.parser_error,
            assets=[
                RawDiscoveredAsset(
                    asset_type=AssetType.IPV4,
                    ip_address="192.168.10.10",
                    services=[
                        RawDiscoveredService(
                            protocol=ServiceProtocol.TCP, port=443, service_name="https"
                        ),
                    ],
                )
            ],
            findings=[
                RawFinding(
                    title="Local fixture vulnerability",
                    description="<script>untrusted</script>",
                    source_tool=self.name,
                    scanner_reference="fixture-001",
                    confidence=FindingConfidence.CONFIRMED,
                    cve_ids=[],
                    cwe_ids=[],
                    severity=FindingSeverity.HIGH,
                    port=443,
                    protocol="tcp",
                    target_address="192.168.10.10",
                    evidence=[
                        RawFindingEvidence(
                            evidence_type="fixture", content="<script>evidence</script>"
                        )
                    ],
                )
            ],
        )


@pytest.fixture
def workflow(monkeypatch, db):
    from app.scanning import orchestrator
    monkeypatch.setattr("app.services.scan_service.enqueue_job", lambda *args, **kwargs: "test-job")
    monkeypatch.setattr(
        "app.services.report_service.enqueue_job", lambda *args, **kwargs: "test-report-job"
    )
    scanner = LocalScanner()
    monkeypatch.setitem(orchestrator.ADAPTER_REGISTRY, "nmap", scanner)
    with TestClient(app) as client:
        tag = uuid.uuid4().hex
        email = f"workflow-{tag}@example.com"
        assert client.post("/api/v1/auth/register", json={
            "email": email, "password": "WorkflowPassword123!", "full_name": "Workflow Tester",
        }).status_code == 201
        assert (
            client.post(
                "/api/v1/auth/login", json={"email": email, "password": "WorkflowPassword123!"}
            ).status_code
            == 200
        )
        org_response = client.post(
            "/api/v1/organizations", json={"name": f"Test {tag}", "slug": f"test-{tag}"}
        )
        assert org_response.status_code == 201, org_response.text
        org_id = org_response.json()["id"]
        prefix = f"/api/v1/organizations/{org_id}"
        response = client.post(
            prefix + "/authorizations",
            json={
                "title": "Local test authorization",
                "signer_name": "Workflow Tester",
                "signer_email": email,
                "authorization_date": datetime.now(UTC).date().isoformat(),
                "targets": [{"value": "192.168.10.10"}],
            },
        )
        assert response.status_code == 201, response.text
        # Limit the fixture to one enabled tool, independent of seeded profile defaults.
        profile = ScanProfile(
            name=f"fixture-{tag}",
            display_name="Local fixture",
            config_json={"nmap": {"enabled": True}},
        )
        db.add(profile)
        db.commit()
        payload = {
            "authorization_id": response.json()["id"],
            "profile_id": str(profile.id),
            "targets": ["192.168.10.10"],
        }
        yield client, prefix, payload, scanner


@pytest.fixture
def launch_scan():
    """Return launch(workflow, **payload_overrides) -> scan id; asserts the scan was created."""

    def launch(workflow, **payload_overrides) -> uuid.UUID:
        client, prefix, payload, _scanner = workflow
        response = client.post(prefix + "/scans", json={**payload, **payload_overrides})
        assert response.status_code == 201, response.text
        return uuid.UUID(response.json()["id"])

    return launch
