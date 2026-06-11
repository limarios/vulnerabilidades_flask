"""A08:2021 Software and Data Integrity Failures - Insecure Deserialization (CWE-502).

VULNERABLE BY DESIGN. The endpoint base64-decodes a parameter and feeds it to
``pickle.loads``. Pickle can reconstruct arbitrary objects and invoke ``__reduce__``,
so a crafted payload runs arbitrary code on the server.

Attack:  craft a pickle whose __reduce__ runs os.system(...), base64 it, then
         /vulnerable/deserialize?data=<base64>   (see red_team/attacks/deserialization.py)
Fix:     see lab/secure/deserialization.py
"""

from __future__ import annotations

import base64
import pickle  # noqa: S403 - the whole point of this module

from flask import Blueprint, jsonify, request

bp = Blueprint("vuln_deserialize", __name__)


@bp.route("/deserialize")
def deserialize():
    data = request.args.get("data", "")
    try:
        raw = base64.b64decode(data)
        # VULNERABLE: pickle.loads on untrusted input is remote code execution.
        obj = pickle.loads(raw)  # noqa: S301
        return jsonify(type=type(obj).__name__, value=str(obj))
    except Exception as exc:  # noqa: BLE001
        return jsonify(error=str(exc)), 400
