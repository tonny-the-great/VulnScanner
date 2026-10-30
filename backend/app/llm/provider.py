"""
LLM provider abstraction and implementations.

Providers are cached per configuration (see get_llm_provider), and each one
builds its SDK client once, so HTTP connections are reused across requests.
Every call is bounded by LLM_TIMEOUT_SECONDS with at most one SDK retry.
"""

from __future__ import annotations

import abc
import json
import logging
import threading
from collections.abc import Iterable
from functools import lru_cache
from typing import Any

from app.config import get_settings
from app.llm.prompts import SYSTEM_PROMPT, build_remediation_prompt
from app.schemas.remediation import RemediationSchema

logger = logging.getLogger(__name__)

# SDK-level retries per request (the SDK defaults retry twice). generate_remediation
# adds one more attempt for malformed output.
_SDK_MAX_RETRIES = 1


class LLMProvider(abc.ABC):
    """Abstract interface for LLM providers."""

    # Provider name recorded in audit entries
    name: str = "unknown"
    model: str = ""

    @abc.abstractmethod
    def generate_completion(self, system_prompt: str, user_prompt: str) -> str:
        """Execute prompt against provider and return raw text response."""
        ...


class _SDKProvider(LLMProvider):
    """A provider backed by a vendor SDK client that is built lazily, once per instance."""

    def __init__(self, api_key: str, model: str, timeout: float | None = None) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout if timeout is not None else get_settings().LLM_TIMEOUT_SECONDS
        self._client: Any = None
        self._client_lock = threading.Lock()

    @abc.abstractmethod
    def _create_client(self) -> Any:
        """Construct the SDK client (imports the SDK on first use)."""
        ...

    def _get_client(self) -> Any:
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    self._client = self._create_client()
        return self._client


class AnthropicProvider(_SDKProvider):
    name = "anthropic"

    def _create_client(self) -> Any:
        import anthropic

        return anthropic.Anthropic(
            api_key=self.api_key,
            timeout=self.timeout,
            max_retries=_SDK_MAX_RETRIES,
        )

    def generate_completion(self, system_prompt: str, user_prompt: str) -> str:
        response = self._get_client().messages.create(
            model=self.model,
            max_tokens=2048,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(getattr(block, "text", "") or "" for block in response.content)


class OpenAIProvider(_SDKProvider):
    name = "openai"

    def _create_client(self) -> Any:
        from openai import OpenAI

        return OpenAI(
            api_key=self.api_key,
            timeout=self.timeout,
            max_retries=_SDK_MAX_RETRIES,
        )

    def generate_completion(self, system_prompt: str, user_prompt: str) -> str:
        response = self._get_client().chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
        )
        return response.choices[0].message.content or ""


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, base_url: str, model: str, timeout: float | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout if timeout is not None else get_settings().LLM_TIMEOUT_SECONDS

    def generate_completion(self, system_prompt: str, user_prompt: str) -> str:
        import urllib.request
        # urllib also opens file: and ftp: URLs; only an HTTP(S) Ollama endpoint is valid.
        if not self.base_url.lower().startswith(("http://", "https://")):
            raise ValueError("OLLAMA_BASE_URL must be an http:// or https:// URL")
        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
        }
        req = urllib.request.Request(  # noqa: S310 - scheme checked above
            f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "")


class MockLLMProvider(LLMProvider):
    """Deterministic offline fallback provider when no API keys are configured."""

    name = "fallback"
    model = "none"

    def generate_completion(self, system_prompt: str, user_prompt: str) -> str:
        # Generate clean structured guidance based on prompt content
        guidance = {
            "source": "fallback",
            "fallback_reason": "No AI provider is configured; this is generic guidance",
            "summary": (
                "This vulnerability indicates an unpatched or misconfigured component "
                "exposed on the network."
            ),
            "root_cause": (
                "The service version running contains known security flaws "
                "or default configuration settings allowing potential unauthorized interaction."
            ),
            "business_impact": (
                "Exposure may allow attackers to perform service reconnaissance, "
                "unauthorized access, or disrupt system availability."
            ),
            "prerequisites": [
                "Take a system snapshot or backup before making configuration changes",
                "Ensure maintenance window or staging test environment is available",
            ],
            "remediation_steps": [
                {
                    "step_number": 1,
                    "title": "Upgrade Package / Component",
                    "description": (
                        "Update the affected package to the latest supported security release "
                        "through your package manager."
                    ),
                    "commands_or_code": (
                        "sudo apt-get update "
                        "&& sudo apt-get --only-upgrade install <package-name>"
                    ),
                    "verification": (
                        "Run package version check "
                        "to confirm upgraded version is active"
                    ),
                },
                {
                    "step_number": 2,
                    "title": "Harden Configuration",
                    "description": (
                        "Disable unnecessary features, ensure secure cipher suites, "
                        "and restrict network access via firewall rules."
                    ),
                    "commands_or_code": "sudo ufw allow from <trusted-ip> to any port <port>",
                    "verification": (
                        "Test access from non-whitelisted IP "
                        "to confirm connection is refused"
                    ),
                },
            ],
            "verification_steps": [
                "Trigger a verification scan to confirm the finding is marked resolved",
                "Review service logs for normal operational status post-upgrade",
            ],
            "references": [
                "https://cve.mitre.org",
                "https://owasp.org/www-project-top-ten/",
            ],
        }
        return json.dumps(guidance)


@lru_cache(maxsize=8)
def _build_provider(
    provider_name: str,
    model: str,
    api_key: str,
    base_url: str,
    timeout: float,
) -> LLMProvider:
    """One provider (and so one SDK client) per distinct configuration."""
    if provider_name == "anthropic" and api_key:
        return AnthropicProvider(api_key, model, timeout=timeout)
    if provider_name == "openai" and api_key:
        return OpenAIProvider(api_key, model, timeout=timeout)
    if provider_name == "ollama":
        return OllamaProvider(base_url, model, timeout=timeout)
    return MockLLMProvider()


def get_llm_provider() -> LLMProvider:
    """Factory for selecting LLM provider based on application configuration (cached)."""
    settings = get_settings()
    provider_name = (settings.llm_provider or "").lower()
    api_key = ""
    base_url = ""
    if provider_name == "anthropic":
        api_key = settings.anthropic_api_key
    elif provider_name == "openai":
        api_key = settings.openai_api_key
    elif provider_name == "ollama":
        base_url = settings.ollama_base_url
    return _build_provider(
        provider_name,
        settings.llm_model,
        api_key,
        base_url,
        float(settings.LLM_TIMEOUT_SECONDS),
    )


def describe_llm_provider() -> tuple[str, str]:
    """
    (provider name, model) of the provider generate_remediation uses.

    The name is 'fallback' when no provider is configured (offline guidance).
    """
    provider = get_llm_provider()
    if isinstance(provider, MockLLMProvider):
        return "fallback", provider.model
    name = getattr(provider, "name", None) or "fallback"
    model = getattr(provider, "model", None) or "unknown"
    return str(name), str(model)


def generate_remediation(
    title: str,
    description: str | None,
    severity: str,
    cve_ids: list[str],
    cwe_ids: list[str],
    port: int | None,
    protocol: str | None,
    service_product: str | None,
    source_tool: str | None = None,
    scanner_reference: str | None = None,
    known_identifiers: Iterable[str | None] = (),
) -> RemediationSchema:
    """
    Generate validated RemediationSchema using configured LLM provider.
    Retries once when the response is malformed JSON or fails validation;
    provider errors (timeouts, connection failures) fall back immediately.

    The prompt is redacted by build_remediation_prompt(); known_identifiers are
    the affected asset's IP address, hostname and domain.
    """
    # Looked up at call time so tests can replace get_llm_provider.
    provider = get_llm_provider()
    user_prompt = build_remediation_prompt(
        title=title,
        description=description,
        severity=severity,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        port=port,
        protocol=protocol,
        service_product=service_product,
        source_tool=source_tool,
        scanner_reference=scanner_reference,
        known_identifiers=known_identifiers,
    )

    for attempt in range(2):
        try:
            raw_text = provider.generate_completion(SYSTEM_PROMPT, user_prompt)
            # Strip markdown fences if any
            clean_text = raw_text.strip()
            if clean_text.startswith("```json"):
                clean_text = clean_text[7:]
            elif clean_text.startswith("```"):
                clean_text = clean_text[3:]
            if clean_text.endswith("```"):
                clean_text = clean_text[:-3]

            parsed = json.loads(clean_text.strip())
            schema = RemediationSchema.model_validate(parsed)
            schema.source = "fallback" if isinstance(provider, MockLLMProvider) else "llm"
            if schema.source == "llm":
                schema.fallback_reason = None
            return schema
        except Exception as e:
            logger.warning(
                "LLM remediation generation attempt %s failed: %s: %s",
                attempt + 1,
                type(e).__name__,
                str(e)[:200],
            )
            # Only malformed output (JSON or schema errors, both ValueErrors) is
            # retried. A timeout or connection error already used the SDK's own
            # retry; trying again would roughly double the wait, past the
            # console's request timeout.
            if attempt == 1 or not isinstance(e, ValueError):
                # Return graceful fallback schema
                fallback = MockLLMProvider().generate_completion("", "")
                schema = RemediationSchema.model_validate(json.loads(fallback))
                schema.fallback_reason = "AI generation failed; this is generic guidance"
                return schema

    raise RuntimeError("Remediation generation failed")
