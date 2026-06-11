# 07 — Insecure Direct Object Reference (IDOR)

## Overview

| | |
|---|---|
| **OWASP** | A01:2021 — Broken Access Control |
| **CWE** | [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) |
| **Red Team slug** | `idor` |
| **Vulnerable route** | `GET /vulnerable/account/<user_id>` |
| **Secure route** | `GET /secure/account/<user_id>` |

IDOR is a *missing authorization check*. The endpoint returns a record based purely on an identifier in the URL, without verifying that the caller is allowed to see that specific record. Incrementing the id walks the entire table.

## The Vulnerability

`src/lab/vulnerable/idor.py`:

```python
@bp.route("/account/<int:user_id>")
def account(user_id: int):
    db = get_db()
    row = db.execute(
        "SELECT id, username, private_note FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="Not found"), 404
    # VULNERABLE: no ownership check - anyone can read anyone's note.
    return jsonify(dict(row))
```

The query is parameterized (so this is *not* SQL injection), but there is no check tying `user_id` to the authenticated caller. Any id resolves to that user's private note.

## Exploit (Red Team)

Logged in as one user, request another user's id:

```
/vulnerable/account/1     (read the admin's private note)
```

```bash
curl "http://127.0.0.1:5000/vulnerable/account/1"
```

CLI (`src/red_team/attacks.py::idor`):

```bash
python -m red_team idor --target http://127.0.0.1:5000
```

The attack, acting as user *bob* (id 3), reads admin's (id 1) record on `/vulnerable/account/1` and confirms the `private_note` field leaked. The same request against `/secure/account/1` with `X-User-Id: 3` is denied.

## The Fix (Blue Team)

`src/lab/secure/idor.py` resolves the caller's identity and enforces ownership:

```python
def _current_principal(db):
    """Resolve the 'logged in' user from the stand-in session header."""
    raw = request.headers.get("X-User-Id")
    if raw is None or not raw.isdigit():
        return None
    return db.execute("SELECT id, role FROM users WHERE id = ?", (int(raw),)).fetchone()

@bp.route("/account/<int:user_id>")
def account(user_id: int):
    db = get_db()
    principal = _current_principal(db)
    if principal is None:
        return jsonify(error="Authentication required"), 401

    # Authorization: you may only read your own record, unless you are an admin.
    if principal["id"] != user_id and principal["role"] != "admin":
        return jsonify(error="Forbidden"), 403

    row = db.execute(
        "SELECT id, username, private_note FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify(error="Not found"), 404
    return jsonify(dict(row))
```

**Why it works:** the request is authenticated first (no principal → `401`), then authorized — the requested `user_id` must equal the caller's own id, with an explicit admin exception, otherwise `403`. The identity comes from the `X-User-Id` header purely as a *stand-in for a real session or JWT principal*, so the lab stays free of session plumbing; in production this value must come from a server-validated session/token, never a client-supplied header. The lesson is the *check*, not the transport.

## Detection (Blue Team)

IDOR has no payload signature in `src/lab/blue_team/detection.py` — the malicious request looks identical to a legitimate one; only the *identity-to-resource relationship* is wrong. It is detected behaviorally: one principal accessing many sequential object ids, or accessing ids they do not own, surfaces in access logs (`src/lab/blue_team/logging.py`). Prevention via the authorization check is the only reliable control; regex matching cannot see authorization context.

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-639](https://cwe.mitre.org/data/definitions/639.html)
- [OWASP IDOR Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html)
