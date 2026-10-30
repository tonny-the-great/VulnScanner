"""
Domain exception classes.

These are raised in the service layer and translated to HTTP responses
by FastAPI exception handlers in main.py.

Users never see Python tracebacks or internal error details.
"""

from __future__ import annotations


class VulnScannerError(Exception):
    """Base class for all application exceptions."""
    status_code: int = 500
    error_type: str | None = None
    detail: str = "An unexpected error occurred."
    # Extra response headers (e.g. Retry-After); passed through by the handler in main.py.
    headers: dict[str, str] | None = None

    def __init__(self, detail: str = "An unexpected error occurred."):
        self.detail = detail
        self.message = detail
        super().__init__(detail)


# Aliases
AppError = VulnScannerError


class NotFoundError(VulnScannerError):
    status_code = 404

    def __init__(self, detail: str, resource_id: str | None = None):
        # Callers pass a complete message ("Scan 123 not found"); a bare resource
        # name plus an id is formatted as "<resource> not found: <id>".
        self.resource_id = resource_id
        super().__init__(f"{detail} not found: {resource_id}" if resource_id else detail)


class ForbiddenError(VulnScannerError):
    status_code = 403

    def __init__(self, detail: str = "You do not have permission to perform this action."):
        super().__init__(detail)


PermissionDeniedError = ForbiddenError


class AuthenticationError(VulnScannerError):
    status_code = 401

    def __init__(self, detail: str = "Authentication failed."):
        super().__init__(detail)


class ConflictError(VulnScannerError):
    status_code = 409

    def __init__(self, detail: str):
        super().__init__(detail)


class ValidationError(VulnScannerError):
    status_code = 422  # Unprocessable Content

    def __init__(self, detail: str):
        super().__init__(detail)


class ScopeViolationError(ForbiddenError):
    """Raised when a scan target is outside the authorized scope."""
    status_code = 400
    error_type = "scope_violation"

    def __init__(self, message: str):
        super().__init__(detail=message)


class ScanStateError(VulnScannerError):
    """Raised when an illegal scan state transition is attempted."""
    status_code = 409
    error_type = "invalid_scan_state"

    def __init__(self, message: str):
        super().__init__(message)


class RateLimitExceededError(VulnScannerError):
    """Raised when a client exceeds a configured request rate."""
    status_code = 429
    error_type = "rate_limited"

    def __init__(self, retry_after: int):
        self.retry_after = max(1, int(retry_after))
        super().__init__(f"Too many requests. Try again in {self.retry_after} seconds.")
        self.headers = {"Retry-After": str(self.retry_after)}
