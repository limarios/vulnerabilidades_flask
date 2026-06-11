"""A03:2021 Injection - Reflected XSS, hardened twin of vulnerable/xss.py.

The fix is to never build HTML by string concatenation. ``markupsafe.escape`` turns
input into inert text; in a full app this is what Jinja2 autoescaping does for you on
every ``{{ variable }}``. Security headers (a strict CSP) add defense in depth.
"""

from __future__ import annotations

from flask import Blueprint, request
from markupsafe import escape

bp = Blueprint("secure_xss", __name__)


@bp.route("/xss")
def xss():
    name = request.args.get("name", "guest")
    # escape() neutralizes <, >, &, " and ' so the payload renders as text.
    return f"<h1>Welcome, {escape(name)}!</h1>"
