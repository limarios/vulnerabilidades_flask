# 10 — JWT Signature Bypass

## Overview

| | |
|---|---|
| **OWASP** | A02:2021 — Cryptographic Failures (also A07 — Auth Failures) |
| **CWE** | [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) |
| **Red Team slug** | `jwt-forge` |
| **Vulnerable route** | `GET /vulnerable/jwt/admin?token=<jwt>` |
| **Secure route** | `GET /secure/jwt/admin?token=<jwt>` (issue one via `GET /secure/jwt/token?role=...`) |

A JSON Web Token carries claims (e.g. `{"role": "admin"}`) that the server trusts — but *only* if it verifies the token's signature with its secret key. If verification is skipped, the claims are entirely attacker-controlled and authorization collapses.

## The Vulnerability

`src/lab/vulnerable/jwt_auth.py` decodes the token with verification turned off:

```python
@bp.route("/jwt/admin")
def admin():
    token = request.args.get("token", "")
    # VULNERABLE: signature verification disabled -> claims are attacker-controlled.
    claims = jwt.decode(token, options={"verify_signature": False})
    if claims.get("role") == "admin":
        return jsonify(status="ok", message="Welcome to the admin area", claims=claims)
    return jsonify(status="denied", message="Admin role required"), 403
```

With `verify_signature: False`, the server reads whatever the client put in the payload. The attacker does not need the secret key — they just write `"role": "admin"`. The same bug class includes accepting `alg: none` tokens (a token that declares it has no signature).

## Exploit (Red Team)

Forge a token claiming `role: admin`, signed with a key the attacker invents (the signature is never checked, so the key is irrelevant). From `src/red_team/attacks.py::jwt_forge`:

```python
forged = jwt.encode({"role": "admin"}, "attacker-does-not-know-the-key", algorithm="HS256")
```

```bash
python -m red_team jwt-forge --target http://127.0.0.1:5000
```

The forged token is accepted by `/vulnerable/jwt/admin` (HTTP 200 — admin access granted) and rejected by `/secure/jwt/admin` (HTTP 401). An `alg: none` token with no signature segment would equally pass the vulnerable endpoint.

## The Fix (Blue Team)

`src/lab/secure/jwt_auth.py` verifies the signature against the server secret and pins the algorithm:

```python
_ALGORITHM = "HS256"

@bp.route("/jwt/admin")
def admin():
    token = request.args.get("token", "")
    try:
        # Verify signature with the server secret and pin the algorithm: a tampered
        # payload or an 'alg: none' token raises here.
        claims = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        return jsonify(error="Invalid token"), 401

    if claims.get("role") == "admin":
        return jsonify(status="ok", message="Welcome to the admin area")
    return jsonify(status="denied", message="Admin role required"), 403
```

**Why it works:**
- Passing `current_app.config["SECRET_KEY"]` forces `jwt.decode` to recompute the HMAC over the header and payload and compare it to the token's signature. The attacker's forged token was signed with a different key, so the signatures do not match and `PyJWTError` is raised — `401`. Any tampering with the payload invalidates the signature.
- `algorithms=["HS256"]` is an explicit allowlist. It rejects `alg: none` outright (the dangerous "unsigned token" trick) and also blocks algorithm-confusion attacks where an attacker swaps the algorithm header.

## Detection (Blue Team)

There is no JWT signature in `src/lab/blue_team/detection.py` — a forged token is well-formed base64 and indistinguishable on the wire from a legitimate one; only signature verification can tell them apart. Detection therefore relies on the application rejecting invalid tokens (the `401` responses are the signal to log and alert on) and on monitoring for tokens with `alg: none` or unexpected algorithm headers. Correct verification is the control.

## References

- [OWASP A02:2021 — Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
- [OWASP JWT for Java Cheat Sheet (concepts apply broadly)](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [RFC 8725 — JWT Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
