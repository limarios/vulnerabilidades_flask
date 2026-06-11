"""Structured (JSON) logging for the Blue Team / SOC view.

Every inspected request and every detected attack is emitted as a single JSON line,
which is exactly what you would ship to a SIEM. This is the project's answer to OWASP
A09 (Security Logging and Monitoring Failures): the defense here *is* observability.
"""

from __future__ import annotations

import logging
import sys

import structlog

_configured = False


def configure_logging(level: int = logging.INFO) -> None:
    """Configure structlog to emit JSON lines. Idempotent."""
    global _configured
    if _configured:
        return

    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger("blue_team")
