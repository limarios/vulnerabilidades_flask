"""A03:2021 Injection - Server-Side Template Injection (CWE-1336 / CWE-94).

VULNERABLE BY DESIGN. User input is concatenated into the *template source* that
Jinja2 then compiles, so the input is evaluated as template code -- which in Jinja2
escalates all the way to RCE through Python introspection.

Attack:  /vulnerable/ssti?name={{7*7}}                      -> renders 49
         /vulnerable/ssti?name={{config}}                   -> leaks Flask config
         /vulnerable/ssti?name={{ ''.__class__.__mro__ }}   -> path to RCE gadgets
Fix:     see lab/secure/ssti.py
"""

from __future__ import annotations

from flask import Blueprint, render_template_string, request

bp = Blueprint("vuln_ssti", __name__)


@bp.route("/ssti")
def ssti():
    name = request.args.get("name", "guest")
    # VULNERABLE: input becomes part of the template, not a value passed to it.
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
