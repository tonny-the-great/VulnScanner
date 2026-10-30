"""Remediation generation: no transaction held during the LLM call, audit, limits, client reuse."""

import io
import json
import sys
import types
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.core import rate_limit
from app.core.audit import AuditAction
from app.core.exceptions import RateLimitExceededError
from app.llm import provider
from app.models.asset import Asset, AssetType, Service, ServiceProtocol
from app.models.audit import AuditLog
from app.models.finding import Finding, FindingConfidence, FindingSeverity
from app.models.organization import Organization
from app.models.user import User
from app.services import remediation_service
from app.services.remediation_service import RemediationService

COOKIE_VALUE = "s3cr3t-cookie-value"


class StubProvider(provider.LLMProvider):
    name = "stub-llm"
    model = "stub-model-1"

    def __init__(self, db):
        self.db = db
        self.in_transaction = []
        self.prompts = []

    def generate_completion(self, system_prompt, user_prompt):
        # Recorded rather than asserted: generate_remediation turns provider errors into fallbacks.
        self.in_transaction.append(self.db.in_transaction())
        self.prompts.append(user_prompt)
        return provider.MockLLMProvider().generate_completion("", "")


@pytest.fixture(autouse=True)
def local_rate_limits(monkeypatch):
    monkeypatch.setattr(rate_limit, "get_redis_safe", lambda: None)
    rate_limit.reset_rate_limits()
    yield
    rate_limit.reset_rate_limits()


@pytest.fixture
def stub(db, monkeypatch):
    instance = StubProvider(db)
    monkeypatch.setattr(provider, "get_llm_provider", lambda: instance)
    return instance


@pytest.fixture
def setup(db):
    tag = uuid.uuid4().hex[:12]
    # The account never logs in, so any placeholder hash will do.
    user = User(
        email=f"remediation-{tag}@example.com", display_name="Remediation",
        password_hash="unused-placeholder-hash",
    )
    org = Organization(name=f"Remediation {tag}", slug=f"remediation-{tag}")
    db.add_all([user, org])
    db.flush()
    asset = Asset(
        organization_id=org.id, asset_type=AssetType.HOSTNAME, ip_address="10.20.30.40",
        hostname="payroll.corp.example", discovery_source="test",
    )
    db.add(asset)
    db.flush()
    service = Service(
        asset_id=asset.id, protocol=ServiceProtocol.TCP, port=443,
        product="OpenSSL", version="1.0.2k",
    )
    db.add(service)
    db.flush()
    finding = Finding(
        organization_id=org.id, asset_id=asset.id, service_id=service.id,
        title="Heartbleed on payroll.corp.example",
        description=f"Host 10.20.30.40 leaks memory\nSet-Cookie: sid={COOKIE_VALUE}",
        source_tool="nmap", scanner_reference="ssl-heartbleed",
        confidence=FindingConfidence.CONFIRMED, severity=FindingSeverity.HIGH,
        cve_ids=["CVE-2014-0160"], cwe_ids=[], priority_score=8.0,
        fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
    )
    db.add(finding)
    db.commit()
    return SimpleNamespace(org_id=org.id, user_id=user.id, user=user, finding_id=finding.id)


def generate(db, setup, force_refresh=False):
    return RemediationService(db).get_or_generate_remediation(
        setup.org_id, setup.finding_id, setup.user, force_refresh=force_refresh,
    )


def remediation_audits(db, finding_id):
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(
        AuditLog.object_id == str(finding_id), AuditLog.action == AuditAction.REMEDIATION_GENERATE,
    )).all())


def test_provider_runs_without_open_transaction_and_is_audited(db, setup, stub):
    result = generate(db, setup)

    assert result.source == "llm"
    assert stub.in_transaction == [False]
    prompt = stub.prompts[0]
    for private in ("10.20.30.40", "payroll", COOKIE_VALUE):
        assert private not in prompt
    assert "CVE-2014-0160" in prompt and "OpenSSL 1.0.2k" in prompt

    db.expire_all()
    finding = db.get(Finding, setup.finding_id)
    assert finding.llm_remediation["summary"] == result.summary
    assert finding.llm_remediation_cached_at is not None
    assert finding.llm_remediation_failed is False

    (entry,) = remediation_audits(db, setup.finding_id)
    assert entry.actor_id == setup.user_id
    assert entry.organization_id == setup.org_id
    assert entry.metadata_["provider"] == "stub-llm"
    assert entry.metadata_["model"] == "stub-model-1"
    assert entry.metadata_["source"] == "llm"


def test_cached_guidance_skips_the_provider(db, setup, stub):
    first = generate(db, setup)
    cached = generate(db, setup)
    assert cached == first
    assert len(stub.prompts) == 1
    assert len(remediation_audits(db, setup.finding_id)) == 1

    generate(db, setup, force_refresh=True)
    assert len(stub.prompts) == 2
    assert len(remediation_audits(db, setup.finding_id)) == 2


def test_generation_is_rate_limited_but_cached_reads_are_not(db, setup, stub, monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LLM_RATE_LIMIT", "1/hour")

    generate(db, setup)
    with pytest.raises(RateLimitExceededError) as excinfo:
        generate(db, setup, force_refresh=True)
    assert excinfo.value.status_code == 429
    for _ in range(3):
        assert generate(db, setup).source == "llm"
    assert len(stub.prompts) == 1


def test_generation_error_marks_the_finding_failed(db, setup, monkeypatch):
    def broken(**kwargs):
        raise RuntimeError("prompt construction failed")

    monkeypatch.setattr(remediation_service, "generate_remediation", broken)
    with pytest.raises(RuntimeError):
        generate(db, setup)
    db.expire_all()
    assert db.get(Finding, setup.finding_id).llm_remediation_failed is True
    assert remediation_audits(db, setup.finding_id) == []


def test_unknown_finding_is_not_found(db, setup, stub):
    from app.core.exceptions import NotFoundError

    with pytest.raises(NotFoundError):
        RemediationService(db).get_or_generate_remediation(setup.org_id, uuid.uuid4(), setup.user)
    assert stub.prompts == []


@pytest.fixture
def clean_provider_cache():
    provider._build_provider.cache_clear()
    yield
    provider._build_provider.cache_clear()


def test_anthropic_client_is_created_once_with_timeout(monkeypatch, clean_provider_cache):
    created = []

    class FakeMessages:
        def create(self, **kwargs):
            return SimpleNamespace(content=[SimpleNamespace(text='{"ok": true}')])

    class FakeAnthropic:
        def __init__(self, **kwargs):
            created.append(kwargs)
            self.messages = FakeMessages()

    fake_module = types.ModuleType("anthropic")
    fake_module.Anthropic = FakeAnthropic
    monkeypatch.setitem(sys.modules, "anthropic", fake_module)
    settings = get_settings()
    monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(settings, "LLM_API_KEY", "test-key-not-real")

    llm = provider.get_llm_provider()
    assert llm is provider.get_llm_provider()
    assert isinstance(llm, provider.AnthropicProvider)
    assert created == []  # built lazily
    assert llm.generate_completion("system", "user") == '{"ok": true}'
    llm.generate_completion("system", "user")

    assert len(created) == 1
    assert created[0]["timeout"] == settings.LLM_TIMEOUT_SECONDS
    assert created[0]["max_retries"] == 1
    assert created[0]["api_key"] == "test-key-not-real"
    assert provider.describe_llm_provider() == ("anthropic", settings.LLM_MODEL)


def test_openai_client_is_created_once_with_timeout(monkeypatch, clean_provider_cache):
    created = []

    class FakeCompletions:
        def create(self, **kwargs):
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="{}"))])

    class FakeOpenAI:
        def __init__(self, **kwargs):
            created.append(kwargs)
            self.chat = SimpleNamespace(completions=FakeCompletions())

    fake_module = types.ModuleType("openai")
    fake_module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    settings = get_settings()
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(settings, "LLM_API_KEY", "test-key-not-real")
    monkeypatch.setattr(settings, "LLM_MODEL", "gpt-test")

    llm = provider.get_llm_provider()
    llm.generate_completion("system", "user")
    provider.get_llm_provider().generate_completion("system", "user")

    assert len(created) == 1
    assert created[0]["timeout"] == settings.LLM_TIMEOUT_SECONDS
    assert created[0]["max_retries"] == 1
    assert provider.describe_llm_provider() == ("openai", "gpt-test")


def test_ollama_uses_configured_timeout(monkeypatch, clean_provider_cache):
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(timeout)
        return io.BytesIO(json.dumps({"response": "{}"}).encode("utf-8"))

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    settings = get_settings()
    monkeypatch.setattr(settings, "LLM_PROVIDER", "ollama")
    monkeypatch.setattr(settings, "LLM_TIMEOUT_SECONDS", 12.5)

    assert provider.get_llm_provider().generate_completion("system", "user") == "{}"
    assert calls == [12.5]
    assert provider.describe_llm_provider()[0] == "ollama"


def test_unconfigured_provider_is_described_as_fallback(monkeypatch, clean_provider_cache):
    monkeypatch.setattr(get_settings(), "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(get_settings(), "LLM_API_KEY", "")
    assert isinstance(provider.get_llm_provider(), provider.MockLLMProvider)
    assert provider.describe_llm_provider()[0] == "fallback"
