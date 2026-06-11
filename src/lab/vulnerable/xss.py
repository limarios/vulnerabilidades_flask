"""A03:2021 Injection - Reflected XSS (CWE-79).

VULNERABLE BY DESIGN. User input is concatenated into raw HTML and returned, so a
``<script>`` payload executes in the victim's browser.

Attack:  /vulnerable/xss?name=<script>alert(document.domain)</script>
Fix:     see lab/secure/xss.py
"""

from __future__ import annotations

from flask import Blueprint, request

bp = Blueprint("vuln_xss", __name__)


@bp.route("/xss")
def xss():
    name = request.args.get("name", "guest")
    # VULNERABLE: input is dropped into HTML with no escaping.
    return f"<h1>Welcome, {name}!</h1>"
