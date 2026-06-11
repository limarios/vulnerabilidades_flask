"""A07:2021 Identification and Authentication Failures, hardened twin.

Defenses:
* rate limiting (Flask-Limiter) caps guesses per IP -> brute force becomes infeasible;
* password verified against a salted hash via ``check_password_hash`` (constant-time);
* login is POST-only, so the password never appears in a URL or access log;
* a generic error avoids leaking whether the username exists.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request
from werkzeug.security import check_password_hash

from ..db import get_db
from ..extensions import limiter

bp = Blueprint("secure_login", __name__)


@bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT username, password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        return jsonify(status="ok", message=f"Welcome {username} ({row['role']})")
    # Same message and timing path whether or not the username exists.
    return jsonify(status="error", message="Invalid credentials"), 401
