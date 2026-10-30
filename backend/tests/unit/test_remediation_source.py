"""Provider failures remain distinguishable from generated guidance."""

from app.llm import provider


def generate():
    return provider.generate_remediation(
        title="Fixture", description="Fixture", severity="high", cve_ids=[], cwe_ids=[],
        port=443, protocol="tcp", service_product=None,
    )


def test_offline_guidance_is_labelled(monkeypatch):
    monkeypatch.setattr(provider, "get_llm_provider", lambda: provider.MockLLMProvider())
    result = generate()
    assert result.source == "fallback"
    assert result.fallback_reason


def test_provider_failure_is_labelled(monkeypatch):
    class FailingProvider:
        def generate_completion(self, *args):
            raise RuntimeError("Provider unavailable")

    monkeypatch.setattr(provider, "get_llm_provider", FailingProvider)
    result = generate()
    assert result.source == "fallback"
    assert "failed" in result.fallback_reason


def test_provider_cannot_spoof_guidance_source(monkeypatch):
    class FixtureProvider:
        def generate_completion(self, *args):
            return provider.MockLLMProvider().generate_completion("", "")

    monkeypatch.setattr(provider, "get_llm_provider", FixtureProvider)
    result = generate()
    assert result.source == "llm"
    assert result.fallback_reason is None


def test_transport_errors_are_not_retried_but_malformed_output_is(monkeypatch):
    calls = []

    class TimingOutProvider:
        def generate_completion(self, *args):
            calls.append("timeout")
            raise TimeoutError("read timed out")

    monkeypatch.setattr(provider, "get_llm_provider", TimingOutProvider)
    assert generate().source == "fallback"
    assert calls == ["timeout"]

    replies = ["not json", provider.MockLLMProvider().generate_completion("", "")]

    class MalformedOnceProvider:
        def generate_completion(self, *args):
            return replies.pop(0)

    monkeypatch.setattr(provider, "get_llm_provider", MalformedOnceProvider)
    assert generate().source == "llm"
    assert replies == []
