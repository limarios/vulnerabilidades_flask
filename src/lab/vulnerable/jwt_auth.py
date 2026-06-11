"""A02:2021 Cryptographic Failures / A07 Auth - JWT signature not verified (CWE-347).

VULNERABLE BY DESIGN. The token is decoded with signature verification turned off, so
the server trusts whatever claims the client sends. An attacker simply edits the
payload to ``{"role": "admin"}`` and gains admin access -- no key required. The same
class of bug includes accepting the ``alg: none`` token.

Attack:  forge a token with role=admin (no signature) and call
         /vulnerable/jwt/admin?token=<forged>   (see red_team/attacks/jwt_forge.py)
Fix:     see lab/secure/jwt_auth.py
"""

from __future__ import annotations

import jwt
from flask import Blueprint, jsonify, request

bp = Blueprint("vuln_jwt", __name__)


@bp.route("/jwt/admin")
def admin():
    token = request.args.get("token", "")
    try:
        # VULNERABLE: signature verification disabled -> claims are attacker-controlled.
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        return jsonify(error=str(exc)), 401

    if claims.get("role") == "admin":
        return jsonify(status="ok", message="Welcome to the admin area", claims=claims)
    return jsonify(status="denied", message="Admin role required"), 403
