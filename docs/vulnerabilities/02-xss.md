# 02 — Reflected Cross-Site Scripting (XSS)

## Overview

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html) |
| **Red Team slug** | `xss` |
| **Vulnerable route** | `GET /vulnerable/xss?name=guest` |
| **Secure route** | `GET /secure/xss?name=guest` |

Reflected XSS occurs when user input is placed into an HTML response without encoding, so the browser parses attacker-supplied markup as part of the page. The injected script runs in the victim's session, allowing cookie theft, account takeover, and UI manipulation.

## The Vulnerability

`src/lab/vulnerable/xss.py` drops the `name` parameter straight into HTML:

```python
@bp.route("/xss")
def xss():
    name = request.args.get("name", "guest")
    # VULNERABLE: input is dropped into HTML with no escaping.
    return f"<h1>Welcome, {name}!</h1>"
```

Because there is no output encoding, a `<script>` tag in `name` becomes a live `<script>` element in the document.

## Exploit (Red Team)

```
/vulnerable/xss?name=<script>alert(document.domain)</script>
```

```bash
curl "http://127.0.0.1:5000/vulnerable/xss?name=<script>alert(document.domain)</script>"
```

CLI (`src/red_team/attacks.py::xss`):

```bash
python -m red_team xss --target http://127.0.0.1:5000
```

The attack sends `name=<script>alert(document.domain)</script>` and confirms the literal `<script>` survives unescaped in the `/vulnerable` response while being neutralized on `/secure`.

## The Fix (Blue Team)

`src/lab/secure/xss.py` escapes the value with `markupsafe.escape` before it touches the HTML:

```python
from markupsafe import escape

@bp.route("/xss")
def xss():
    name = request.args.get("name", "guest")
    # escape() neutralizes <, >, &, " and ' so the payload renders as text.
    return f"<h1>Welcome, {escape(name)}!</h1>"
```

**Why it works:** `escape()` converts `<`, `>`, `&`, `"` and `'` into HTML entities (`&lt;`, `&gt;`, ...), so the browser renders the payload as visible text instead of executing it. In a real template this is exactly what Jinja2 autoescaping does for every `{{ variable }}`. As defense in depth, `src/lab/blue_team/headers.py` sets a strict Content-Security-Policy (`script-src 'self'`) that blocks inline script execution even if an escaping bug slips through.

## Detection (Blue Team)

`src/lab/blue_team/detection.py` `xss` signatures:

```python
"xss": [
    re.compile(r"<\s*script", re.I),
    re.compile(r"on(error|load|click|mouseover)\s*=", re.I),
    re.compile(r"javascript:", re.I),
],
```

The `<script>` payload matches the first pattern; event-handler payloads (`<img onerror=...>`) and `javascript:` URIs match the others. URL-encoded variants are caught because the scanner also inspects the decoded value.

## References

- [OWASP A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
