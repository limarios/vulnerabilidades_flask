"""A01:2021 Broken Access Control - IDOR (CWE-639).

VULNERABLE BY DESIGN. The endpoint returns any user's private note based purely on the
id in the URL. There is no check that the caller is allowed to see that record, so
incrementing the id walks the whole table (a classic Insecure Direct Object Reference).

Attack:  /vulnerable/account/1   (read admin's private note while logged in as bob)
Fix:     see lab/secure/idor.py
"""

from __future__ import annotations

from flask import Blueprint, jsonify

from ..db import get_db

bp = Blueprint("vuln_idor", __name__)


@bp.route("/account/<int:user_id>")
def account(user_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, username, private_note FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="Not found"), 404
    # VULNERABLE: no ownership check - anyone can read anyone's note.
    return jsonify(dict(row))
