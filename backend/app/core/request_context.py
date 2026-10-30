"""
Per-request network context (client IP and user agent).

RequestContextMiddleware records the context for every HTTP/WebSocket request in a
ContextVar, so services can attribute audit entries without threading the Request
object through every call. Sync endpoints run in a threadpool that copies the
context, so the value is visible there too.

Client IP resolution trusts X-Forwarded-For only for the configured number of
proxy hops (TRUSTED_PROXY_HOPS). Entries further left are client-controlled and
are ignored, so a spoofed header cannot change the recorded or rate-limited IP.
"""

from __future__ import annotations

import ipaddress
from contextvars import ContextVar
from dataclasses import dataclass

from starlette.requests import HTTPConnection
from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings

_MAX_IP_LENGTH = 45  # AuditLog.ip_address column size
_MAX_USER_AGENT_LENGTH = 512


@dataclass(frozen=True)
class RequestContext:
    ip_address: str | None
    user_agent: str | None


request_context_var: ContextVar[RequestContext | None] = ContextVar(
    "vulnscanner_request_context", default=None
)


def current_request_context() -> RequestContext | None:
    """Return the context of the request being handled, or None outside a request."""
    return request_context_var.get()


def _header_values(scope: Scope, name: bytes) -> list[str]:
    return [
        value.decode("latin-1")
        for key, value in scope.get("headers") or ()
        if key.lower() == name
    ]


def _normalize_ip(value: str) -> str | None:
    candidate = value.strip()
    if candidate.startswith("["):
        # "[2001:db8::1]" or "[2001:db8::1]:443"
        end = candidate.find("]")
        candidate = candidate[1:end] if end > 0 else ""
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def client_ip_from_scope(scope: Scope) -> str | None:
    """Resolve the client IP for an ASGI scope, honouring TRUSTED_PROXY_HOPS."""
    client = scope.get("client")
    peer: str | None = client[0] if client else None
    hops = get_settings().TRUSTED_PROXY_HOPS
    if hops == 0 or peer is None:
        return peer[:_MAX_IP_LENGTH] if peer else peer

    # Each trusted proxy appends the address it received the request from, so the
    # entry 'hops' places left of the direct peer is the last one a trusted proxy saw.
    chain = [
        part.strip()
        for header in _header_values(scope, b"x-forwarded-for")
        for part in header.split(",")
        if part.strip()
    ]
    chain.append(peer)
    if len(chain) < hops + 1:
        # Fewer entries than trusted proxies: the request did not pass through them all.
        return peer[:_MAX_IP_LENGTH]
    # Malformed or overlong entries fall back to the direct peer.
    return (_normalize_ip(chain[-(hops + 1)]) or peer)[:_MAX_IP_LENGTH]


def get_client_ip(request: HTTPConnection) -> str | None:
    """Client IP for a FastAPI/Starlette request (see client_ip_from_scope)."""
    return client_ip_from_scope(request.scope)


def _user_agent_from_scope(scope: Scope) -> str | None:
    values = _header_values(scope, b"user-agent")
    if not values or not values[0]:
        return None
    return values[0][:_MAX_USER_AGENT_LENGTH]


class RequestContextMiddleware:
    """Pure ASGI middleware that publishes RequestContext for the current request."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        context = RequestContext(
            ip_address=client_ip_from_scope(scope),
            user_agent=_user_agent_from_scope(scope),
        )
        token = request_context_var.set(context)
        try:
            await self.app(scope, receive, send)
        finally:
            request_context_var.reset(token)
