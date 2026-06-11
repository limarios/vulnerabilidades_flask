"""A03:2021 Injection - OS Command Injection, hardened twin.

Two defenses:
1. Validate the input as a real IP address or hostname (allowlist of shape).
2. Run the command as an argument vector with ``shell=False``, so the OS never
   interprets the input as shell syntax. The two together make injection impossible.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess

from flask import Blueprint, jsonify, request

bp = Blueprint("secure_ping", __name__)

_COUNT_FLAG = "-n" if os.name == "nt" else "-c"
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$")


def _is_valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))


@bp.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not _is_valid_host(host):
        return jsonify(error="Invalid host"), 400

    # Argument vector + shell=False: 'host' can never be parsed as a command. The
    # executable is the fixed literal "ping" (S607) and the only dynamic element is
    # the already-validated host (S603), so these bandit lints are intentionally
    # acknowledged rather than a finding.
    result = subprocess.run(  # noqa: S603
        ["ping", _COUNT_FLAG, "1", host],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,
    )
    return jsonify(output=result.stdout, returncode=result.returncode)
