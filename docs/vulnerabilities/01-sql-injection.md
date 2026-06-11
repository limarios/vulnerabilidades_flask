# 01 — SQL Injection

## Overview

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html) |
| **Red Team slug** | `sqli` |
| **Vulnerable route** | `GET /vulnerable/sql?id=1` |
| **Secure route** | `GET /secure/sql?id=1` |

SQL injection happens when user input is treated as part of a SQL command instead of as data. The attacker controls the structure of the query and can read, modify, or destroy data they were never authorized to touch.

## The Vulnerability

`src/lab/vulnerable/sql_injection.py` builds the query with an f-string, so the `id` parameter is interpolated directly into the SQL text:

```python
@bp.route("/sql")
def sql_injection():
    user_id = request.args.get("id", "1")
    db = get_db()
    # VULNERABLE: f-string interpolation places attacker input into the query body.
    query = f"SELECT id, username, role FROM users WHERE id = {user_id}"  # noqa: S608
    rows = [dict(r) for r in db.execute(query).fetchall()]
    return jsonify(query=query, results=rows)
```

The database parser cannot tell the difference between the developer's intended `WHERE id = 1` and the attacker's appended `UNION SELECT`. Everything is one string.

## Exploit (Red Team)

A `UNION`-based payload pivots the query to dump the credentials table:

```
/vulnerable/sql?id=0 UNION SELECT username, password, role FROM users
```

```bash
curl "http://127.0.0.1:5000/vulnerable/sql?id=0%20UNION%20SELECT%20username,%20password,%20role%20FROM%20users"
```

CLI (`src/red_team/attacks.py::sqli`):

```bash
python -m red_team sqli --target http://127.0.0.1:5000
```

The attack uses `id = "0 UNION SELECT username, password, role FROM users"`. `id = 0` matches no real row, so every output row is attacker-chosen — the password column is leaked verbatim.

## The Fix (Blue Team)

`src/lab/secure/sql_injection.py` applies two layers:

```python
@bp.route("/sql")
def sql_injection():
    raw_id = request.args.get("id", "1")
    try:
        user_id = int(raw_id)  # layer 1: validate the expected type
    except ValueError:
        return jsonify(error="Parameter 'id' must be an integer"), 400

    db = get_db()
    # layer 2: parameter binding - the '?' is data, never code
    rows = [
        dict(r)
        for r in db.execute(
            "SELECT id, username, role FROM users WHERE id = ?", (user_id,)
        ).fetchall()
    ]
    return jsonify(results=rows)
```

**Why it works:** `int(raw_id)` rejects anything that is not a whole number, so the `UNION SELECT` string never reaches the database. Even if it did, the `?` placeholder makes the driver send the SQL text and the parameter value on separate channels — the value is bound as a literal and can never be reparsed as SQL. Parameterized queries are the primary defense; input validation is defense in depth.

## Detection (Blue Team)

`src/lab/blue_team/detection.py` matches the `sql_injection` signature family on the request surface (path, query string, form body), both raw and URL-decoded:

```python
"sql_injection": [
    re.compile(r"\bunion\b.+\bselect\b", re.I),
    re.compile(r"\bor\b\s+\d+\s*=\s*\d+", re.I),
    re.compile(r"(--|#|/\*)", re.I),
    re.compile(r"\b(sqlite_master|information_schema)\b", re.I),
],
```

The `UNION SELECT` payload above trips the first pattern; a `' OR 1=1 --` payload trips the second and third. Note: signatures are bypassable (e.g. inline comments, casing tricks) — they are a tripwire, not a fix.

## References

- [OWASP A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
