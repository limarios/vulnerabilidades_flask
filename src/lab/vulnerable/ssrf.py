"""A10:2021 Server-Side Request Forgery (CWE-918).

VULNERABLE BY DESIGN. The server fetches whatever URL the user supplies, so an
attacker can pivot through the server to reach internal-only resources: cloud
metadata endpoints, localhost admin ports, or the filesystem via ``file://``.

Attack:  /vulnerable/fetch?url=http://169.254.169.254/latest/meta-data/
         /vulnerable/fetch?url=http://127.0.0.1:5000/secure/account/1
Fix:     see lab/secure/ssrf.py
"""

from __future__ import annotations

import requests
from flask import Blueprint, jsonify, request

bp = Blueprint("vuln_ssrf", __name__)


@bp.route("/fetch")
def fetch():
    url = request.args.get("url", "http://example.com")
    try:
        # VULNERABLE: no scheme allowlist, no IP filtering. Fetches anything.
        resp = requests.get(url, timeout=3)
        return jsonify(url=url, status=resp.status_code, body=resp.text[:2000])
    except requests.RequestException as exc:
        return jsonify(url=url, error=str(exc)), 502
