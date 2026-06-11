"""Signature-based attack detection.

This is intentionally a *naive* detector: regular expressions over the request
surface. Real WAFs are far more sophisticated, but signatures are enough to teach the
core idea -- that the same payloads an attacker sends leave recognizable fingerprints
a defender can match on. The deliberate weakness (signatures are bypassable) is itself
a lesson, documented in docs/vulnerabilities.
"""

from __future__ import annotations

import contextlib
import re
from urllib.parse import unquote, unquote_plus

from werkzeug.wrappers import Request

# category -> compiled signatures. Kept readable on purpose.
_SIGNATURES: dict[str, list[re.Pattern[str]]] = {
    "sql_injection": [
        re.compile(r"\bunion\b.+\bselect\b", re.I),
        re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.I),
        re.compile(r"(--|#|/\*)", re.I),
        re.compile(r"\b(sqlite_master|information_schema)\b", re.I),
    ],
    "xss": [
        re.compile(r"<\s*script", re.I),
        re.compile(r"on(error|load|click|mouseover)\s*=", re.I),
        re.compile(r"javascript:", re.I),
    ],
    "path_traversal": [
        re.compile(r"\.\.[/\\]"),
        re.compile(r"(/etc/passwd|boot\.ini|win\.ini)", re.I),
    ],
    "command_injection": [
        re.compile(r"[;&|`]"),
        re.compile(r"\$\("),
        re.compile(r"\b(whoami|cat\s|/bin/sh|nc\s|curl\s|wget\s)", re.I),
    ],
    "ssti": [
        re.compile(r"\{\{.*\}\}"),
        re.compile(r"\{%.*%\}"),
        re.compile(r"__class__|__mro__|__subclasses__|__globals__"),
    ],
    "ssrf": [
        re.compile(r"(169\.254\.169\.254|metadata\.google|127\.0\.0\.1|localhost)", re.I),
        re.compile(r"\bfile://", re.I),
    ],
}


def scan_value(value: str) -> set[str]:
    """Return the set of attack categories matching a single string value.

    Each value is checked raw and URL-decoded (both ``%xx`` and ``+`` forms), so
    encoded payloads do not slip past the signatures.
    """
    variants = {value, unquote(value), unquote_plus(value)}
    hits: set[str] = set()
    for category, patterns in _SIGNATURES.items():
        if any(p.search(v) for v in variants for p in patterns):
            hits.add(category)
    return hits


def scan_request(request: Request) -> set[str]:
    """Scan the path, query string and form body of a request for signatures."""
    surfaces: list[str] = [unquote(request.path), request.query_string.decode("utf-8", "replace")]
    # Inspecting the body must never be able to break the request itself.
    with contextlib.suppress(Exception):
        surfaces.extend(f"{k}={v}" for k, v in request.form.items(multi=True))

    detected: set[str] = set()
    for surface in surfaces:
        detected |= scan_value(surface)
    return detected
