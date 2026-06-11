"""A03:2021 Injection - SQL Injection (CWE-89).

VULNERABLE BY DESIGN. The user-controlled ``id`` is concatenated straight into the
SQL string, so the parameter is parsed as code.

Attack:  /vulnerable/sql?id=1 OR 1=1
         /vulnerable/sql?id=0 UNION SELECT username, password, 1, 1, 1, 1 FROM users
Fix:     see lab/secure/sql_injection.py
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request

from ..db import get_db

bp = Blueprint("vuln_sql", __name__)


@bp.route("/sql")
def sql_injection():
    user_id = request.args.get("id", "1")
    db = get_db()
    # VULNERABLE: f-string interpolation places attacker input into the query body.
    query = f"SELECT id, username, role FROM users WHERE id = {user_id}"  # noqa: S608
    try:
        rows = [dict(r) for r in db.execute(query).fetchall()]
        return jsonify(query=query, results=rows)
    except Exception as exc:  # noqa: BLE001 - leaking the error is part of the lesson
        return jsonify(query=query, error=str(exc)), 400
