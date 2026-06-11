"""A03:2021 Injection - SQL Injection, hardened twin of vulnerable/sql_injection.py.

Two layers of defense:
1. Input validation: the id is expected to be an integer, so reject anything else.
2. Parameterized query: the value is bound, never concatenated, so the database
   driver treats it strictly as data.
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..db import get_db

bp = Blueprint("secure_sql", __name__)


@bp.route("/sql")
def sql_injection():
    raw_id = request.args.get("id", "1")
    try:
        user_id = int(raw_id)  # layer 1: validate the expected type
    except ValueError:
        return jsonify(error="Parameter 'id' must be an integer"), 400

    db = get_db()
    # layer 2: parameter binding - the '?' is data, never code
    rows = [
        dict(r)
        for r in db.execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchall()
    ]
    return jsonify(results=rows)
