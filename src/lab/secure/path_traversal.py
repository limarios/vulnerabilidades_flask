"""A01:2021 Broken Access Control - Path Traversal, hardened twin.

``werkzeug.utils.safe_join`` resolves the path and returns ``None`` if the result
would escape the base directory, which collapses ``../`` and absolute-path tricks.
A realpath containment check is added as belt-and-suspenders.
"""

from __future__ import annotations

import os

from flask import Blueprint, current_app, jsonify, request
from werkzeug.utils import safe_join

bp = Blueprint("secure_file", __name__)


@bp.route("/file")
def read_file():
    name = request.args.get("name", "welcome.txt")
    base = current_app.config["FILES_DIR"]

    safe_path = safe_join(base, name)
    if safe_path is None:
        return jsonify(error="Path traversal attempt blocked"), 400

    # Defense in depth: confirm the resolved path is still inside the sandbox.
    if os.path.commonpath(
        [os.path.realpath(safe_path), os.path.realpath(base)]
    ) != os.path.realpath(base):
        return jsonify(error="Path traversal attempt blocked"), 400

    try:
        with open(safe_path, encoding="utf-8", errors="replace") as fh:
            return jsonify(content=fh.read())
    except OSError:
        return jsonify(error="File not found"), 404
