"""Security response headers (defense in depth).

These do not fix the underlying bugs, but they meaningfully reduce blast radius: a
strict CSP neuters most reflected XSS, frame-ancestors stops clickjacking, and
nosniff/Referrer-Policy close common side channels.
"""

from __future__ import annotations

from flask import Response

_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    # HSTS only matters over HTTPS; harmless on localhost and documents intent.
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
}


def apply_security_headers(response: Response) -> Response:
    for header, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response
