"""A01:2021 Broken Access Control - Path Traversal (CWE-22).

VULNERABLE BY DESIGN. The filename is joined to a base directory with no validation,
so ``../`` sequences escape the sandbox and read arbitrary files.

Attack:  /vulnerable/file?name=../../../../etc/passwd
         /vulnerable/file?name=../config.py
Fix:     see lab/secure/path_traversal.py
"""

from __future__ import annotations

import os

from flask import Blueprint, current_app, jsonify, request

bp = Blueprint("vuln_file", __name__)


@bp.route("/file")
def read_file():
    name = request.args.get("name", "welcome.txt")
    base = current_app.config["FILES_DIR"]
    # VULNERABLE: os.path.join with attacker input does not contain traversal.
    path = os.path.join(base, name)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return jsonify(path=path, content=fh.read())
    except OSError as exc:
        return jsonify(path=path, error=str(exc)), 404
