"""A01:2021 Broken Access Control - IDOR, hardened twin.

The fix is an authorization check: the resource is only returned if the authenticated
caller owns it (or is an admin). The caller's identity here comes from the
``X-User-Id`` header, standing in for a real session/JWT principal so the lab stays
free of session plumbing. The lesson is the *check*, not the transport.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..db import get_db

bp = Blueprint("secure_idor", __name__)


def _current_principal(db):
    """Resolve the 'logged in' user from the stand-in session header."""
    raw = request.headers.get("X-User-Id")
    if raw is None or not raw.isdigit():
        return None
    return db.execute("SELECT id, role FROM users WHERE id = ?", (int(raw),)).fetchone()


@bp.route("/account/<int:user_id>")
def account(user_id: int):
    db = get_db()
    principal = _current_principal(db)
    if principal is None:
        return jsonify(error="Authentication required"), 401

    # Authorization: you may only read your own record, unless you are an admin.
    if principal["id"] != user_id and principal["role"] != "admin":
        return jsonify(error="Forbidden"), 403

    row = db.execute(
        "SELECT id, username, private_note FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="Not found"), 404
    return jsonify(dict(row))
