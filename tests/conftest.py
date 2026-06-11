"""Shared pytest fixtures for the Flask Security Lab suite.

The whole suite is built around one idea: the *same* attack is fired at the naive
route (where it must succeed) and at the hardened twin / Blue Team layer (where it
must be blocked). The fixtures here give each test the right app wiring for that
contrast:

* ``naive_client``       -> Blue Team off: no WAF, no headers, no rate limit. This is
  what lets us both prove the ``/vulnerable`` exploits AND test the *route-level*
  defenses on ``/secure`` in isolation (the WAF is not in the way).
* ``defended_client``    -> Blue Team + WAF on: proves the WAF blocks ``/secure`` and
  that security headers are present.
* ``ratelimited_client`` -> Blue Team on but WAF off, rate limit on: isolates the
  ``/secure/login`` rate limit so the WAF does not short-circuit the request first.
"""

from __future__ import annotations

import pytest

from lab import create_app
from lab.extensions import limiter


def _make_client(overrides: dict[str, object]):
    """Build a test app with the given config overrides and return its test client."""
    app = create_app("test", overrides=overrides)
    return app.test_client()


@pytest.fixture
def naive_client():
    """Naive behavior: defenses fully off (no WAF, no headers, no rate limit)."""
    return _make_client({"BLUE_TEAM_ENABLED": False})


@pytest.fixture
def defended_client():
    """Full Blue Team: detection + WAF blocking on /secure + security headers."""
    return _make_client({"BLUE_TEAM_ENABLED": True, "WAF_ENABLED": True})


@pytest.fixture
def ratelimited_client():
    """Rate limit on, WAF off: the limiter is tested without the WAF interfering.

    The ``limiter`` is a module-level singleton (see lab/extensions.py) whose
    in-memory counters survive across app instances and tests. We reset it here so
    the rate-limit test starts from a clean window and stays deterministic.
    """
    overrides = {
        "BLUE_TEAM_ENABLED": True,
        "WAF_ENABLED": False,
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_STORAGE_URI": "memory://",
    }
    app = create_app("test", overrides=overrides)
    with app.app_context():
        limiter.reset()
    return app.test_client()
