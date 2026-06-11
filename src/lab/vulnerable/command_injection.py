"""A03:2021 Injection - OS Command Injection / RCE (CWE-78).

VULNERABLE BY DESIGN. The host is interpolated into a string handed to the shell, so
metacharacters like ``;`` and ``&&`` let the attacker run arbitrary commands.

Attack:  /vulnerable/ping?host=127.0.0.1; whoami
         /vulnerable/ping?host=127.0.0.1 && dir   (Windows)
Fix:     see lab/secure/command_injection.py
"""

from __future__ import annotations

import os

from flask import Blueprint, jsonify, request

bp = Blueprint("vuln_ping", __name__)

_COUNT_FLAG = "-n" if os.name == "nt" else "-c"


@bp.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: the shell parses the whole string, including injected commands.
    command = f"ping {_COUNT_FLAG} 1 {host}"
    output = os.popen(command).read()  # noqa: S605
    return jsonify(command=command, output=output)
