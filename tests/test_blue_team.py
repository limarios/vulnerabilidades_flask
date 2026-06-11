"""Tests for the Blue Team layer: WAF blocking, security headers, and detection.

These prove the cross-cutting defenses behave as designed -- including the deliberate
design choice that the WAF blocks ``/secure`` but leaves ``/vulnerable`` exploitable
so the contrast stays demonstrable.
"""

from __future__ import annotations

import pytest

from lab.blue_team.detection import scan_value

pytestmark = pytest.mark.blue_team


def test_waf_blocks_secure_route(defended_client):
    resp = defended_client.get("/secure/sql", query_string={"id": "1 OR 1=1"})
    # The WAF matches the signature and blocks before the route runs.
    assert resp.status_code == 403
    assert "categories" in resp.get_json()


def test_waf_leaves_vulnerable_route_exploitable(defended_client):
    # Same defenses on, but the WAF intentionally does NOT block /vulnerable, so the
    # teaching exploit still works.
    resp = defended_client.get(
        "/vulnerable/xss", query_string={"name": "<script>alert(1)</script>"}
    )
    assert resp.status_code == 200
    assert "<script>" in resp.get_data(as_text=True)


def test_security_headers_present_when_defended(defended_client):
    resp = defended_client.get("/")
    assert "Content-Security-Policy" in resp.headers
    assert "X-Frame-Options" in resp.headers


def test_security_headers_absent_when_naive(naive_client):
    resp = naive_client.get("/")
    # Blue Team off -> the after_request hook is never installed.
    assert "Content-Security-Policy" not in resp.headers


def test_detection_categorizes_payloads():
    assert "sql_injection" in scan_value("1 OR 1=1")
    assert "xss" in scan_value("<script>")
    assert "path_traversal" in scan_value("../")
