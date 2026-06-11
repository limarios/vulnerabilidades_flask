"""A08:2021 Software and Data Integrity Failures - hardened twin.

The fix is to never deserialize untrusted data into live objects. Use a data-only
format (JSON) that cannot describe code or object construction. If a richer format is
truly required, it must be signed (e.g. with itsdangerous) and verified before
parsing -- but for transporting user data, JSON is the right tool.
"""

from __future__ import annotations

import base64
import binascii
import json

from flask import Blueprint, jsonify, request

bp = Blueprint("secure_deserialize", __name__)


@bp.route("/deserialize")
def deserialize():
    data = request.args.get("data", "")
    try:
        raw = base64.b64decode(data, validate=True)
        # JSON describes data only - no object construction, no code execution.
        obj = json.loads(raw)
    except (binascii.Error, ValueError):
        return jsonify(error="Expected base64-encoded JSON"), 400
    return jsonify(type=type(obj).__name__, value=obj)
