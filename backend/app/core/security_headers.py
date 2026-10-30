"""
Baseline security headers for every HTTP response served by the API process.

nginx sets the same headers in the Compose stack; this middleware covers direct
uvicorn deployments and the locally served console. A header already set by a
route (for example a report's own Content-Security-Policy) is never overwritten.
"""

from __future__ import annotations

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config import get_settings

# The console loads only same-origin scripts, styles and fonts: no inline code.
CONSOLE_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'"
)
# Generated reports embed their stylesheet and contain no scripts.
REPORT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

# Swagger UI and ReDoc load their assets from a CDN, so the console CSP would break them.
_DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc"})
_HSTS = "max-age=31536000"


class SecurityHeadersMiddleware:
    """Pure ASGI middleware adding default security headers when absent."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        hsts = get_settings().is_production

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
                headers.setdefault("X-Frame-Options", "DENY")
                headers.setdefault("Referrer-Policy", "same-origin")
                if hsts:
                    headers.setdefault("Strict-Transport-Security", _HSTS)
                if path.startswith("/api/"):
                    # Authenticated JSON, event streams and report downloads.
                    headers.setdefault("Cache-Control", "no-store")
                content_type = headers.get("content-type", "").lower()
                if (
                    content_type.startswith("text/html")
                    and path not in _DOCS_PATHS
                    and "content-security-policy" not in headers
                ):
                    headers["Content-Security-Policy"] = CONSOLE_CSP
            await send(message)

        await self.app(scope, receive, send_with_headers)
