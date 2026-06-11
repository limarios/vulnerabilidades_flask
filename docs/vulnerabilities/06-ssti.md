# 06 — Server-Side Template Injection (SSTI)

## Overview

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | [CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine](https://cwe.mitre.org/data/definitions/1336.html) (also CWE-94) |
| **Red Team slug** | `ssti` |
| **Vulnerable route** | `GET /vulnerable/ssti?name=guest` |
| **Secure route** | `GET /secure/ssti?name=guest` |

SSTI happens when user input becomes part of the *template source* that the engine compiles, rather than a value passed *into* the template. In Jinja2, attacker-controlled template code can walk Python's object model and escalate all the way to remote code execution.

## The Vulnerability

`src/lab/vulnerable/ssti.py` concatenates input into the template string, then compiles it:

```python
@bp.route("/ssti")
def ssti():
    name = request.args.get("name", "guest")
    # VULNERABLE: input becomes part of the template, not a value passed to it.
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)
```

`render_template_string` treats its argument as Jinja2 source. Anything the user puts in `name` — including `{{ ... }}` expressions — is compiled and evaluated server-side.

## Exploit (Red Team)

The classic probe is an arithmetic expression; if it evaluates, the engine is injectable:

```
/vulnerable/ssti?name={{7*7}}                     -> renders "Hello, 49!"
/vulnerable/ssti?name={{config}}                  -> leaks Flask config (incl. SECRET_KEY)
/vulnerable/ssti?name={{ ''.__class__.__mro__ }}  -> path to RCE gadgets
```

```bash
curl "http://127.0.0.1:5000/vulnerable/ssti?name=%7B%7B7*7%7D%7D"
```

CLI (`src/red_team/attacks.py::ssti`):

```bash
python -m red_team ssti --target http://127.0.0.1:5000
```

The attack sends `name={{7*7}}` and confirms injection by checking that `49` appears in the response — the server evaluated the expression. From `{{config}}` and `__class__.__mro__.__subclasses__()` an attacker reaches `os.popen`/`subprocess` and achieves RCE.

## The Fix (Blue Team)

`src/lab/secure/ssti.py` keeps the template a constant and passes input as a bound variable:

```python
@bp.route("/ssti")
def ssti():
    name = request.args.get("name", "guest")
    # The template is a constant; input is passed as the 'name' variable.
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)
```

**Why it works:** the template source is now a fixed literal that the developer controls completely. The user input arrives as the `name=name` keyword argument — Jinja2 substitutes it as an inert *value* into the already-compiled template and never compiles the user input itself. `{{7*7}}` in `name` renders as the literal text `{{7*7}}`, and autoescaping additionally neutralizes any HTML inside it. The rule is absolute: **input is data passed to a template, never the source of one.**

## Detection (Blue Team)

`src/lab/blue_team/detection.py` `ssti` signatures:

```python
"ssti": [
    re.compile(r"\{\{.*\}\}"),
    re.compile(r"\{%.*%\}"),
    re.compile(r"__class__|__mro__|__subclasses__|__globals__"),
],
```

`{{7*7}}` matches the expression-delimiter pattern; `{% ... %}` statement blocks match the second; introspection gadget names (`__class__`, `__mro__`, ...) match the third — these dunder chains are the hallmark of an SSTI-to-RCE escalation.

## References

- [OWASP A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)
- [OWASP Testing for SSTI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection)
- [PortSwigger: Server-Side Template Injection](https://portswigger.net/web-security/server-side-template-injection)
