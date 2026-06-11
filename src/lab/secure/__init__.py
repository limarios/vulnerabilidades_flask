"""Blue zone: hardened blueprints, mounted under /secure.

Each module is the fixed twin of its lab/vulnerable counterpart, same route shape,
safe behavior.
"""

from __future__ import annotations

from flask import Blueprint

from .brute_force import bp as brute_force_bp
from .command_injection import bp as command_injection_bp
from .deserialization import bp as deserialization_bp
from .idor import bp as idor_bp
from .jwt_auth import bp as jwt_bp
from .path_traversal import bp as path_traversal_bp
from .sql_injection import bp as sql_bp
from .ssrf import bp as ssrf_bp
from .ssti import bp as ssti_bp
from .xss import bp as xss_bp

secure_blueprints: list[Blueprint] = [
    sql_bp,
    xss_bp,
    brute_force_bp,
    path_traversal_bp,
    command_injection_bp,
    ssti_bp,
    idor_bp,
    ssrf_bp,
    deserialization_bp,
    jwt_bp,
]
