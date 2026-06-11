# 03 — Brute Force / Broken Authentication

## Overview

| | |
|---|---|
| **OWASP** | A07:2021 — Identification and Authentication Failures |
| **CWE** | [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) (also CWE-256, CWE-598) |
| **Red Team slug** | `brute-force` |
| **Vulnerable route** | `GET /vulnerable/login?username=admin&password=...` |
| **Secure route** | `POST /secure/login` |

The vulnerable login stacks several authentication failures: no rate limiting, plaintext password comparison, and credentials carried over `GET`. Together they let an attacker guess passwords at unlimited speed while the credentials leak into URLs, logs, and browser history.

## The Vulnerability

`src/lab/vulnerable/brute_force.py`:

```python
@bp.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT username, password, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    # VULNERABLE: plaintext comparison, no rate limit, password came via GET.
    if row and row["password"] == password:
        return jsonify(status="ok", message=f"Welcome {username} ({row['role']})")
    return jsonify(status="error", message="Invalid credentials"), 401
```

Three distinct problems: (1) no throttling means thousands of guesses per second; (2) `row["password"] == password` compares plaintext, so a database leak hands over every password directly; (3) `GET` puts the secret in the request line.

## Exploit (Red Team)

Loop a wordlist against the endpoint:

```bash
curl "http://127.0.0.1:5000/vulnerable/login?username=admin&password=admin123"
```

CLI (`src/red_team/attacks.py::brute_force`), which iterates `src/red_team/wordlists/common-passwords.txt`:

```bash
python -m red_team brute-force --target http://127.0.0.1:5000
```

The attack tries each candidate against `/vulnerable/login` until it gets `status: ok`, then fires 8 rapid `POST`s at `/secure/login` to show the rate limiter returning HTTP 429.

## The Fix (Blue Team)

`src/lab/secure/brute_force.py`:

```python
from werkzeug.security import check_password_hash
from ..extensions import limiter

@bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()
    row = db.execute(
        "SELECT username, password_hash, role FROM users WHERE username = ?", (username,)
    ).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        return jsonify(status="ok", message=f"Welcome {username} ({row['role']})")
    # Same message and timing path whether or not the username exists.
    return jsonify(status="error", message="Invalid credentials"), 401
```

**Why it works:**
- `@limiter.limit("5 per minute")` (Flask-Limiter) caps guesses per client to 5/min; a wordlist attack that needs thousands of tries becomes infeasible and noisy.
- `check_password_hash` verifies against a salted hash in constant time, so a stolen database does not expose usable passwords and timing does not reveal partial matches.
- `methods=["POST"]` with `request.form` keeps the password out of the URL, access logs, and history.
- The identical error message for "no such user" and "wrong password" avoids username enumeration.

## Detection (Blue Team)

Brute force is a *behavioral* attack rather than a payload, so it has no regex signature in `src/lab/blue_team/detection.py`. It is detected by volume: many failed authentication attempts from one source in a short window. The rate limiter itself is both the mitigation and the detection signal — a burst of HTTP 429 responses on `/secure/login` is the fingerprint a defender alerts on (see the request-logging hook in `src/lab/blue_team/logging.py`).

## References

- [OWASP A07:2021 — Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [CWE-307](https://cwe.mitre.org/data/definitions/307.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Flask-Limiter documentation](https://flask-limiter.readthedocs.io/)
