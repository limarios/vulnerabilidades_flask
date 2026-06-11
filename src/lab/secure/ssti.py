"""A03:2021 Injection - Server-Side Template Injection, hardened twin.

The fix is conceptual: user input must be *data passed to* a fixed template, never
part of the template source. Here ``name`` is bound as a variable, so Jinja2 treats
it as an inert value and autoescaping handles any HTML inside it.
"""

from __future__ import annotations

from flask import Blueprint, render_template_string, request

bp = Blueprint("secure_ssti", __name__)


@bp.route("/ssti")
def ssti():
    name = request.args.get("name", "guest")
    # The template is a constant; input is passed as the 'name' variable.
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)
