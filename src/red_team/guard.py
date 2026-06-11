"""Safety guard rails for the offensive tooling.

These attack helpers exist to exercise the *local* lab and nothing else. The guard
enforces that at runtime: any target that is not loopback is refused before a single
packet is sent. This is what makes the offensive code in this repo defensible to ship.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_LOOPBACK_NAMES = {"localhost", "ip6-localhost"}


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(info[4][0]).is_loopback for info in infos)


def assert_loopback(target: str) -> str:
    """Return the target if it points at loopback, otherwise abort hard.

    The whole offensive suite routes through here, so there is no code path that
    can fire at an external host.
    """
    host = urlparse(target).hostname
    if host is None or not _is_loopback(host):
        raise SystemExit(
            f"Refusing to target '{target}'. The red_team tooling is loopback-only "
            f"(127.0.0.1 / localhost / ::1) by design. Point it at your local lab."
        )
    return target
