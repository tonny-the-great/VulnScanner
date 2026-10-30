"""Check browser test fixtures and authored form values against API contracts."""

import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from app.models.finding import FindingSeverity, FindingStatus
from app.models.report import ReportType
from app.schemas.asset import AssetResponse
from app.schemas.auth import CurrentUserResponse
from app.schemas.authorization import ScopeAuthorizationResponse
from app.schemas.finding import FindingResponse
from app.schemas.organization import OrganizationResponse
from app.schemas.remediation import RemediationSchema
from app.schemas.report import ReportResponse
from app.schemas.scan import ScanProfileResponse, ScanResponse

FRONTEND = Path(__file__).resolve().parents[3] / "frontend"


class FormControls(HTMLParser):
    def __init__(self):
        super().__init__()
        self.fields = {}
        self.selects = {}
        self.active_select = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            self.fields[attributes["id"]] = (tag, attributes)
        if tag == "select":
            self.active_select = attributes.get("id")
            self.selects[self.active_select] = []
        elif tag == "option" and self.active_select:
            self.selects[self.active_select].append(attributes.get("value", ""))

    def handle_endtag(self, tag):
        if tag == "select":
            self.active_select = None


@pytest.mark.parametrize(
    ("fixture_name", "schema"),
    [
        ("organization", OrganizationResponse),
        ("user", CurrentUserResponse),
        ("profile", ScanProfileResponse),
        ("authorization", ScopeAuthorizationResponse),
        ("scan", ScanResponse),
        ("asset", AssetResponse),
        ("finding", FindingResponse),
        ("remediation", RemediationSchema),
        ("report", ReportResponse),
    ],
)
def test_frontend_behavior_fixture_matches_actual_api_schema(fixture_name, schema):
    fixtures = json.loads(
        (FRONTEND / "tests" / "fixtures" / "contracts.json").read_text(encoding="utf-8")
    )
    value = fixtures[fixture_name]
    # Prevent fixtures from inventing convenience fields absent from the API.
    assert not (value.keys() - schema.model_fields.keys())
    schema.model_validate(value)


def test_authorization_form_has_api_required_fields():
    controls = FormControls()
    controls.feed((FRONTEND / "index.html").read_text(encoding="utf-8"))
    assert "auth-title" in controls.fields or "auth-signer-title" in controls.fields
    for name in ("auth-signer-name", "auth-signer-email", "auth-date", "auth-targets"):
        assert name in controls.fields, f"Missing authorization control {name}"
        assert "required" in controls.fields[name][1], f"{name} should be required"
    assert controls.fields["auth-date"][1]["type"] == "date"


@pytest.mark.parametrize(
    ("select_id", "enum"),
    [
        ("findings-severity-filter", FindingSeverity),
        ("findings-status-filter", FindingStatus),
        ("update-finding-status-select", FindingStatus),
        ("report-type-select", ReportType),
    ],
)
def test_form_options_use_complete_actual_api_enums(select_id, enum):
    controls = FormControls()
    controls.feed((FRONTEND / "index.html").read_text(encoding="utf-8"))
    values = {value for value in controls.selects[select_id] if value}
    assert values == {item.value for item in enum}
