"""Landing page and health check."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template

from .catalog import CATALOG

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template(
        "index.html",
        catalog=CATALOG,
        blue_team_enabled=current_app.config["BLUE_TEAM_ENABLED"],
        waf_enabled=current_app.config["WAF_ENABLED"],
    )


@main_bp.route("/health")
def health():
    return jsonify(status="ok", blue_team_enabled=current_app.config["BLUE_TEAM_ENABLED"])
