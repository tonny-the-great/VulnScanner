"""
Logging configuration shared by the API and RQ workers.

Both stdlib and structlog loggers render through one stdout handler, as
human-readable lines (LOG_FORMAT=console) or one JSON object per line
(LOG_FORMAT=json) for log collectors.
"""

from __future__ import annotations

import logging
import sys

import structlog

from app.config import get_settings

_HANDLER_MARKER = "_vulnscanner_handler"
_configured = False


def configure_logging() -> None:
    """Configure stdlib logging and structlog once per process."""
    global _configured
    if _configured:
        return
    settings = get_settings()

    timestamper = structlog.processors.TimeStamper(fmt="iso", utc=True)
    final_processors: list = [structlog.stdlib.ProcessorFormatter.remove_processors_meta]
    if settings.LOG_FORMAT == "json":
        # Render tracebacks of stdlib records as a string field instead of a tuple repr.
        final_processors += [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        final_processors.append(structlog.dev.ConsoleRenderer(colors=False))

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            timestamper,
        ],
        processors=final_processors,
    )

    root = logging.getLogger()
    root.setLevel(settings.LOG_LEVEL)
    # Handlers installed by others (pytest, uvicorn) are left alone.
    if not any(getattr(handler, _HANDLER_MARKER, False) for handler in root.handlers):
        handler = logging.StreamHandler(sys.stdout)
        setattr(handler, _HANDLER_MARKER, True)
        handler.setFormatter(formatter)
        root.addHandler(handler)

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    _configured = True
