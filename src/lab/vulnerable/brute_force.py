"""A07:2021 Identification and Authentication Failures (CWE-307, CWE-256).

VULNERABLE BY DESIGN. Multiple failures stacked together:
* no rate limiting -> unlimited password guesses;
* credentials compared in plaintext;
* login over GET -> the password lands in URLs, logs and history;
* error message does not distinguish the failures, but there is nothing slowing an
  attacker down.

Attack:  loop GET /vulnerable/login?username=admin&password=<from wordlist>
Fix:     see lab/secure/brute_force.py
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..db import get_db

bp = Blueprint("vuln_login", __name__)


@bp.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT username, password, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    # VULNERABLE: plaintext comparison, no rate limit, password came via GET.
    if row and row["password"] == password:
        return jsonify(status="ok", message=f"Welcome {username} ({row['role']})")
    return jsonify(status="error", message="Invalid credentials"), 401
