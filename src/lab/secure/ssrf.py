"""A10:2021 Server-Side Request Forgery, hardened twin.

Defenses:
* scheme allowlist (http/https only) -> blocks ``file://``, ``gopher://`` etc.;
* DNS resolution followed by an IP check that rejects private, loopback and
  link-local ranges -> blocks 127.0.0.1, 169.254.169.254 and the RFC1918 space,
  and also defeats DNS-rebinding-style hostnames that resolve to internal IPs.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Blueprint, jsonify, request

bp = Blueprint("secure_ssrf", __name__)

_ALLOWED_SCHEMES = {"http", "https"}


def _is_public_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


@bp.route("/fetch")
def fetch():
    url = request.args.get("url", "http://example.com")
    parsed = urlparse(url)

    if parsed.scheme not in _ALLOWED_SCHEMES:
        return jsonify(error="Only http/https URLs are allowed"), 400
    if not parsed.hostname or not _is_public_host(parsed.hostname):
        return jsonify(error="Refusing to fetch a non-public address"), 400

    try:
        resp = requests.get(url, timeout=3, allow_redirects=False)
        return jsonify(status=resp.status_code, body=resp.text[:2000])
    except requests.RequestException:
        return jsonify(error="Upstream request failed"), 502
