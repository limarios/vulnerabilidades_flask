"""Proof-of-defense tests against the hardened ``/secure`` routes.

The same payloads that succeed in ``test_vulnerable.py`` are fired here and must be
neutralized by the route's own logic. We use ``naive_client`` (Blue Team off) on
purpose: with the WAF disabled, nothing upstream blocks the request, so a passing
test proves the *route itself* defends -- not the perimeter. The WAF is covered
separately in ``test_blue_team.py``.

The exception is brute force, which needs the rate limiter wired in
(``ratelimited_client``).
"""

from __future__ import annotations

import base64
import os
import pickle  # noqa: S403 - reusing the same exploit payload as the vulnerable test
import tempfile

import jwt
import pytest

pytestmark = pytest.mark.secure


def test_sql_injection_rejected(naive_client):
    resp = naive_client.get("/secure/sql", query_string={"id": "1 OR 1=1"})
    # Layer 1 (int validation) rejects the injection payload before any query runs.
    assert resp.status_code == 400


def test_xss_is_escaped(naive_client):
    resp = naive_client.get("/secure/xss", query_string={"name": "<script>alert(1)</script>"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "<script>" not in body  # the raw tag never reaches the browser
    assert "&lt;script&gt;" in body  # it is rendered as inert, escaped text


def test_path_traversal_blocked(naive_client):
    resp = naive_client.get("/secure/file", query_string={"name": "../../config.py"})
    # safe_join + realpath containment collapse the '../' escape attempt.
    assert resp.status_code == 400


def test_command_injection_blocked(naive_client):
    resp = naive_client.get("/secure/ping", query_string={"host": "127.0.0.1; whoami"})
    # The host fails IP/hostname validation, so it never reaches a subprocess.
    assert resp.status_code == 400


def test_ssti_not_evaluated(naive_client):
    resp = naive_client.get("/secure/ssti", query_string={"name": "{{7*7}}"})
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "49" not in body  # the expression was never evaluated as template code
    # Passed as a value into a fixed template -> the payload is echoed literally.
    assert "{{7*7}}" in body


def test_idor_requires_auth(naive_client):
    # No identity header at all -> 401.
    assert naive_client.get("/secure/account/1").status_code == 401


def test_idor_forbids_other_users_record(naive_client):
    # bob (id=3, role=user) tries to read admin's (id=1) note -> 403.
    resp = naive_client.get("/secure/account/1", headers={"X-User-Id": "3"})
    assert resp.status_code == 403


def test_idor_allows_admin(naive_client):
    # admin (id=1) may read any record, including alice's (id=2) -> 200.
    resp = naive_client.get("/secure/account/2", headers={"X-User-Id": "1"})
    assert resp.status_code == 200


def test_ssrf_blocks_metadata_endpoint(naive_client):
    resp = naive_client.get("/secure/fetch", query_string={"url": "http://169.254.169.254/"})
    assert resp.status_code == 400  # link-local cloud metadata address refused


def test_ssrf_blocks_file_scheme(naive_client):
    resp = naive_client.get("/secure/fetch", query_string={"url": "file:///etc/passwd"})
    assert resp.status_code == 400  # scheme not in the http/https allowlist


def test_ssrf_blocks_localhost(naive_client):
    resp = naive_client.get("/secure/fetch", query_string={"url": "http://localhost/"})
    assert resp.status_code == 400  # resolves to loopback -> refused


def test_deserialization_rejects_pickle(naive_client):
    marker_dir = os.path.join(tempfile.gettempdir(), "lab_pickle_rce_marker_secure")
    if os.path.isdir(marker_dir):
        os.rmdir(marker_dir)

    class _Exploit:
        def __reduce__(self):
            return (os.makedirs, (marker_dir,))

    # Same pickle payload that pops a directory on the vulnerable route.
    payload = base64.b64encode(pickle.dumps(_Exploit())).decode("ascii")
    try:
        resp = naive_client.get("/secure/deserialize", query_string={"data": payload})
        # The secure route expects base64 JSON; a pickle blob fails to parse as JSON.
        assert resp.status_code == 400
        # Crucially, no code ran: the marker directory was never created.
        assert not os.path.isdir(marker_dir)
    finally:
        if os.path.isdir(marker_dir):
            os.rmdir(marker_dir)


def test_jwt_rejects_forged_token(naive_client):
    forged = jwt.encode({"role": "admin"}, "wrong-key", algorithm="HS256")
    resp = naive_client.get("/secure/jwt/admin", query_string={"token": forged})
    # Signature verified against the server secret -> the wrong-key token is rejected.
    assert resp.status_code == 401


def test_jwt_accepts_properly_signed_token(naive_client):
    # Obtain a legitimately signed admin token from the issuing helper.
    issued = naive_client.get("/secure/jwt/token", query_string={"role": "admin"})
    token = issued.get_json()["token"]
    resp = naive_client.get("/secure/jwt/admin", query_string={"token": token})
    assert resp.status_code == 200  # valid signature + admin claim -> granted


def test_brute_force_is_rate_limited(ratelimited_client):
    # The correct credentials over POST succeed (and consume one attempt).
    ok = ratelimited_client.post(
        "/secure/login", data={"username": "admin", "password": "admin123"}
    )
    assert ok.status_code == 200

    # Hammer with wrong passwords; the 5-per-minute limit kicks in and returns 429.
    statuses = [ok.status_code]
    for _ in range(10):
        resp = ratelimited_client.post(
            "/secure/login", data={"username": "admin", "password": "errado"}
        )
        statuses.append(resp.status_code)

    assert 429 in statuses  # the attacker is eventually throttled
