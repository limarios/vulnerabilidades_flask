"""Application factory for the Flask Security Lab.

The factory wires three layers together:

* ``vulnerable`` blueprints  -> naive code, mounted under ``/vulnerable``
* ``secure`` blueprints      -> hardened twins, mounted under ``/secure``
* ``blue_team`` hooks        -> cross-cutting defenses, active only when
  ``BLUE_TEAM_ENABLED`` is true

Keeping all three in one app is what makes the "attack the same endpoint, then see
it defended" demo possible.
"""

from __future__ import annotations

from flask import Flask

from . import blue_team, db
from .config import BaseConfig, resolve_config
from .extensions import limiter

__all__ = ["create_app"]


def create_app(config_name: str | None = None, overrides: dict[str, object] | None = None) -> Flask:
    app = Flask(__name__)

    config: type[BaseConfig] = resolve_config(config_name)
    app.config.from_object(config)
    if overrides:
        # Mainly for tests, which flip BLUE_TEAM_ENABLED / WAF_ENABLED per case.
        app.config.update(overrides)

    db.init_app(app)
    if app.config["RATELIMIT_ENABLED"]:
        limiter.init_app(app)
        app.config["RATELIMIT_STORAGE_URI"] = config.RATELIMIT_STORAGE_URI

    _register_blueprints(app)

    # The Blue Team layer reads its own config flags and becomes a no-op when the
    # defenses are switched off, so the call is always safe to make.
    blue_team.init_app(app)

    return app


def _register_blueprints(app: Flask) -> None:
    from .main import main_bp
    from .secure import secure_blueprints
    from .vulnerable import vulnerable_blueprints

    app.register_blueprint(main_bp)
    for bp in vulnerable_blueprints:
        app.register_blueprint(bp, url_prefix="/vulnerable")
    for bp in secure_blueprints:
        app.register_blueprint(bp, url_prefix="/secure")
