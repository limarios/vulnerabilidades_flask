"""Environment-aware configuration.

The single most important switch in this lab is ``BLUE_TEAM_ENABLED``. When it is
off, the application behaves like naive, unprotected code: no security headers, no
WAF, no request-level detection. When it is on, the Blue Team defenses are wired in
through request hooks. This is what powers the "before / after" demo without having
to maintain two separate applications.
"""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
# Sandbox that the (vulnerable and secure) file routes are allowed to read from.
FILES_DIR = BASE_DIR / "data" / "files"


def _as_bool(value: str | None, *, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class BaseConfig:
    """Defaults shared by every environment."""

    # In a real app this would come from a secret manager. The lab ships an
    # obviously-fake default and reads the real value from the environment.
    SECRET_KEY = os.environ.get("SECRET_KEY", "lab-insecure-development-key-change-me-please")

    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "data" / "lab.db"))
    FILES_DIR = str(FILES_DIR)

    # Master switch for the Blue Team layer (headers, WAF, detection, rate limit).
    BLUE_TEAM_ENABLED = _as_bool(os.environ.get("BLUE_TEAM_ENABLED"), default=True)

    # The mini-WAF only blocks requests; detection/logging runs regardless so you
    # can observe attacks even while the WAF is disabled.
    WAF_ENABLED = _as_bool(os.environ.get("WAF_ENABLED"), default=True)

    # Rate limiting (Flask-Limiter). Disabled storage warning in dev via memory://.
    RATELIMIT_ENABLED = _as_bool(os.environ.get("RATELIMIT_ENABLED"), default=True)
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    JSON_SORT_KEYS = False


class DevConfig(BaseConfig):
    DEBUG = True


class LabConfig(BaseConfig):
    """How the lab is meant to be run: defenses on, debug off."""

    DEBUG = False


class TestConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    # Tests flip BLUE_TEAM_ENABLED per-case, so the default here is irrelevant,
    # but rate limiting is off by default to keep unrelated tests deterministic.
    RATELIMIT_ENABLED = False
    DATABASE_PATH = ":memory:"


_CONFIGS: dict[str, type[BaseConfig]] = {
    "dev": DevConfig,
    "development": DevConfig,
    "lab": LabConfig,
    "production": LabConfig,
    "test": TestConfig,
    "testing": TestConfig,
}


def resolve_config(name: str | None) -> type[BaseConfig]:
    """Map an environment name to a config class, defaulting to dev."""
    key = (name or os.environ.get("FLASK_ENV") or "dev").lower()
    return _CONFIGS.get(key, DevConfig)
