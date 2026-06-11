"""Blue Team layer: cross-cutting defenses wired in through request hooks.

When ``BLUE_TEAM_ENABLED`` is false, ``init_app`` installs nothing and the app runs
exactly like the naive original. When true:

* every request is inspected and attacks are logged (SOC visibility), including those
  aimed at the still-exploitable ``/vulnerable`` routes;
* the mini-WAF blocks matched requests, but only on ``/secure`` routes, so the
  vulnerable twins stay learnable;
* security headers are added to every response.
"""

from __future__ import annotations

from flask import Flask, Response, jsonify, request

from .detection import scan_request
from .headers import apply_security_headers
from .logging import configure_logging, get_logger

__all__ = ["init_app"]


def init_app(app: Flask) -> None:
    configure_logging()

    if not app.config.get("BLUE_TEAM_ENABLED"):
        return

    log = get_logger()
    waf_enabled = app.config.get("WAF_ENABLED", True)

    @app.before_request
    def _inspect_request() -> Response | None:
        detected = scan_request(request)
        if not detected:
            return None

        log.warning(
            "attack_detected",
            categories=sorted(detected),
            method=request.method,
            path=request.path,
            query=request.query_string.decode("utf-8", "replace"),
            remote_addr=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            blocked=waf_enabled and request.path.startswith("/secure"),
        )

        # WAF blocks on the hardened routes only; vulnerable routes stay exploitable.
        if waf_enabled and request.path.startswith("/secure"):
            response = jsonify(
                error="Request blocked by WAF",
                categories=sorted(detected),
                hint=(
                    "The mini-WAF matched an attack signature. "
                    "Try /vulnerable to see the unprotected behavior."
                ),
            )
            response.status_code = 403
            return response
        return None

    @app.after_request
    def _harden_response(response: Response) -> Response:
        return apply_security_headers(response)
