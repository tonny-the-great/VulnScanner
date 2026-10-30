"""
Application configuration — all values sourced from environment variables.

NEVER hard-code secrets. Generate SESSION_SECRET with:
    python -c "import secrets; print(secrets.token_hex(32))"

ENVIRONMENT defaults to "production" so a missing value fails safe (secure
cookies, no development thread fallback, API docs off). Local runs set
ENVIRONMENT=development explicitly, as both .env examples do.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# '<count>/<unit>' such as "10/minute" or "5/hours". Mirrors app.core.rate_limit.parse_rate,
# which cannot be imported here without a circular import.
_RATE_LIMIT_PATTERN = re.compile(r"[1-9][0-9]*/(second|minute|hour|day)s?", re.IGNORECASE)
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _split_networks(value: str) -> list[str]:
    return [token for token in re.split(r"[\s,]+", value.strip()) if token]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # "ENABLE_API_DOCS=" in a .env file or Compose means "unset", not an invalid value.
        env_ignore_empty=True,
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    ENVIRONMENT: Literal["development", "production", "testing"] = "production"

    # ── Security ──────────────────────────────────────────────────────────────
    # Required — no default so the app refuses to start without it
    SESSION_SECRET: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(60, ge=1)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, ge=1)
    # Argon2id uses 64 MiB per hash; this bounds concurrent hashing per API process.
    PASSWORD_HASH_CONCURRENCY: int = Field(4, ge=1, le=64)
    # Number of reverse proxies in front of the API whose X-Forwarded-For entries are
    # trusted. 0 ignores the header; Compose sets 1 for its nginx container.
    TRUSTED_PROXY_HOPS: int = Field(0, ge=0, le=5)

    # ── Accounts and tenancy ──────────────────────────────────────────────────
    ALLOW_SELF_REGISTRATION: bool = True
    ORG_CREATION: Literal["any_user", "superuser"] = "any_user"

    # ── API documentation ─────────────────────────────────────────────────────
    # None (unset) enables /docs, /redoc and /openapi.json outside production.
    ENABLE_API_DOCS: bool | None = None

    # ── Logging ───────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: Literal["console", "json"] = "console"

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite:///./vulnscanner.db"
    # Logs every SQL statement with its parameters (including credential and token rows).
    SQL_ECHO: bool = False
    # Connection pool sizing (ignored for SQLite)
    DB_POOL_SIZE: int = Field(10, ge=1)
    DB_MAX_OVERFLOW: int = Field(20, ge=0)
    DB_POOL_TIMEOUT: int = Field(30, ge=1)

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── LLM ───────────────────────────────────────────────────────────────────
    LLM_PROVIDER: Literal["anthropic", "openai", "ollama"] = "anthropic"
    LLM_MODEL: str = "claude-opus-4-5"
    LLM_API_KEY: str = ""
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    LLM_TIMEOUT_SECONDS: float = Field(60.0, gt=0, le=600)

    # ── Scanning ──────────────────────────────────────────────────────────────
    SCAN_TIMEOUT: int = Field(3600, ge=60)  # seconds
    MAX_TARGETS_PER_SCAN: int = Field(50, ge=1, le=1000)
    # Run Nmap with --privileged (raw sockets, OS detection) when the worker is not root
    # but has CAP_NET_RAW. Off and not root: OS detection is skipped with a scan warning.
    # A worker running as root (as in the Docker image) always gets OS detection.
    NMAP_PRIVILEGED: bool = False
    # Networks that are never scanned, even when authorized, checked against resolved
    # addresses at scan time. Whitespace- or comma-separated; an empty value is allowed.
    SCAN_BLOCKED_NETWORKS: str = "127.0.0.0/8 ::1/128 0.0.0.0/8 ::/128"
    SCAN_DNS_TIMEOUT_SECONDS: float = Field(5.0, gt=0, le=60)
    # Extra time beyond SCAN_TIMEOUT before an active scan is considered abandoned.
    SCAN_STALE_GRACE_SECONDS: int = Field(900, ge=60)
    REPORT_JOB_TIMEOUT: int = Field(900, ge=60)  # seconds

    # ── File uploads ──────────────────────────────────────────────────────────
    UPLOAD_DIR: str = "./uploads"

    # ── Bootstrap superuser ───────────────────────────────────────────────────
    FIRST_SUPERUSER_EMAIL: str = ""
    FIRST_SUPERUSER_PASSWORD: str = ""

    # ── CORS ──────────────────────────────────────────────────────────────────
    CORS_ORIGINS: str = "http://localhost:5173 http://localhost:3000"

    # ── Rate limiting ─────────────────────────────────────────────────────────
    # Fixed windows shared through Redis; per API process when Redis is unavailable.
    RATE_LIMIT_ENABLED: bool = True
    LOGIN_RATE_LIMIT: str = "10/minute"
    REGISTER_RATE_LIMIT: str = "10/hour"
    REFRESH_RATE_LIMIT: str = "30/minute"
    PASSWORD_CHANGE_RATE_LIMIT: str = "5/minute"
    LLM_RATE_LIMIT: str = "30/hour"
    REPORT_DOWNLOAD_RATE_LIMIT: str = "60/minute"

    @field_validator("SESSION_SECRET")
    @classmethod
    def session_secret_must_be_long_enough(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError(
                "SESSION_SECRET must be at least 32 characters. "
                "Generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        allowed_prefixes = ("sqlite", "postgresql", "postgresql+psycopg2", "postgresql+asyncpg")
        if not any(v.startswith(p) for p in allowed_prefixes):
            raise ValueError(f"DATABASE_URL must start with one of: {allowed_prefixes}")
        return v

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        level = v.strip().upper()
        if level not in _LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of: {', '.join(sorted(_LOG_LEVELS))}")
        return level

    @field_validator(
        "LOGIN_RATE_LIMIT",
        "REGISTER_RATE_LIMIT",
        "REFRESH_RATE_LIMIT",
        "PASSWORD_CHANGE_RATE_LIMIT",
        "LLM_RATE_LIMIT",
        "REPORT_DOWNLOAD_RATE_LIMIT",
    )
    @classmethod
    def validate_rate_limit(cls, v: str) -> str:
        value = v.strip()
        if not _RATE_LIMIT_PATTERN.fullmatch(value):
            raise ValueError(
                "Rate limits must look like '<count>/<second|minute|hour|day>', e.g. '10/minute'"
            )
        return value

    @field_validator("SCAN_BLOCKED_NETWORKS")
    @classmethod
    def validate_blocked_networks(cls, v: str) -> str:
        for token in _split_networks(v):
            try:
                ipaddress.ip_network(token, strict=False)
            except ValueError:
                raise ValueError(
                    f"SCAN_BLOCKED_NETWORKS contains an invalid network: {token!r}"
                ) from None
        return v

    @model_validator(mode="after")
    def validate_combinations(self) -> Settings:
        if "*" in self.cors_origins_list:
            # Session cookies are sent with credentials, so origins must be listed exactly.
            raise ValueError("CORS_ORIGINS cannot contain '*'; list each allowed origin")
        has_email = bool(self.FIRST_SUPERUSER_EMAIL.strip())
        has_password = bool(self.FIRST_SUPERUSER_PASSWORD.strip())
        if has_email != has_password:
            raise ValueError(
                "Set both FIRST_SUPERUSER_EMAIL and FIRST_SUPERUSER_PASSWORD, or neither"
            )
        return self

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split() if o.strip()]

    @property
    def cors_origins(self) -> list[str]:
        return self.cors_origins_list

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"

    @property
    def is_testing(self) -> bool:
        return self.ENVIRONMENT == "testing"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def api_docs_enabled(self) -> bool:
        if self.ENABLE_API_DOCS is not None:
            return self.ENABLE_API_DOCS
        return not self.is_production

    @property
    def scan_blocked_networks(
        self,
    ) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(
            ipaddress.ip_network(token, strict=False)
            for token in _split_networks(self.SCAN_BLOCKED_NETWORKS)
        )

    @property
    def upload_dir(self) -> str:
        return self.UPLOAD_DIR

    @property
    def upload_dir_path(self) -> str:
        return self.UPLOAD_DIR

    @property
    def redis_url(self) -> str:
        return self.REDIS_URL

    @property
    def scan_timeout_seconds(self) -> int:
        return self.SCAN_TIMEOUT

    @property
    def first_superuser_email(self) -> str:
        return self.FIRST_SUPERUSER_EMAIL

    @property
    def first_superuser_password(self) -> str:
        return self.FIRST_SUPERUSER_PASSWORD

    @property
    def llm_provider(self) -> str:
        return self.LLM_PROVIDER

    @property
    def llm_model(self) -> str:
        return self.LLM_MODEL

    @property
    def anthropic_api_key(self) -> str:
        return self.LLM_API_KEY if self.LLM_PROVIDER == "anthropic" else ""

    @property
    def openai_api_key(self) -> str:
        return self.LLM_API_KEY if self.LLM_PROVIDER == "openai" else ""

    @property
    def ollama_base_url(self) -> str:
        return self.OLLAMA_BASE_URL


@lru_cache
def get_settings() -> Settings:
    return Settings()
