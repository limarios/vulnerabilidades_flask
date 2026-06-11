"""A02:2021 Cryptographic Failures / A07 Auth - JWT verified, hardened twin.

The token is decoded with the server secret and a pinned algorithm allowlist, so a
tampered payload fails signature verification and ``alg: none`` is rejected outright.
A ``/jwt/token`` helper issues a correctly signed token so the flow is demonstrable
end to end.
"""

from __future__ import annotations

import jwt
from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("secure_jwt", __name__)

_ALGORITHM = "HS256"


@bp.route("/jwt/token")
def issue_token():
    """Demo helper: issue a signed token for ?role=user|admin."""
    role = request.args.get("role", "user")
    token = jwt.encode({"role": role}, current_app.config["SECRET_KEY"], algorithm=_ALGORITHM)
    return jsonify(token=token)


@bp.route("/jwt/admin")
def admin():
    token = request.args.get("token", "")
    try:
        # Verify signature with the server secret and pin the algorithm: a tampered
        # payload or an 'alg: none' token raises here.
        claims = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        return jsonify(error="Invalid token"), 401

    if claims.get("role") == "admin":
        return jsonify(status="ok", message="Welcome to the admin area")
    return jsonify(status="denied", message="Admin role required"), 403
