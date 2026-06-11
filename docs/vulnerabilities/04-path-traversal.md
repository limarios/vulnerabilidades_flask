# 04 — Path Traversal

## Overview

| | |
|---|---|
| **OWASP** | A01:2021 — Broken Access Control |
| **CWE** | [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html) |
| **Red Team slug** | `traversal` |
| **Vulnerable route** | `GET /vulnerable/file?name=welcome.txt` |
| **Secure route** | `GET /secure/file?name=welcome.txt` |

Path traversal lets an attacker supply `../` sequences in a filename to escape the intended directory and read (or write) arbitrary files on the server — source code, configuration, secrets, or system files like `/etc/passwd`.

## The Vulnerability

`src/lab/vulnerable/path_traversal.py` joins user input to the base directory with no containment check:

```python
@bp.route("/file")
def read_file():
    name = request.args.get("name", "welcome.txt")
    base = current_app.config["FILES_DIR"]
    # VULNERABLE: os.path.join with attacker input does not contain traversal.
    path = os.path.join(base, name)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return jsonify(path=path, content=fh.read())
```

`os.path.join(base, "../../config.py")` happily resolves *above* `base`. `os.path.join` does not constrain the result to the sandbox — that is a common and dangerous misconception.

## Exploit (Red Team)

```
/vulnerable/file?name=../../config.py
```

```bash
curl "http://127.0.0.1:5000/vulnerable/file?name=../../config.py"
curl "http://127.0.0.1:5000/vulnerable/file?name=../../../../etc/passwd"
```

CLI (`src/red_team/attacks.py::path_traversal`):

```bash
python -m red_team traversal --target http://127.0.0.1:5000
```

The attack requests `name=../../config.py` and confirms success by checking that `SECRET_KEY` appears in the returned content — proof the response escaped the sandbox into application source.

## The Fix (Blue Team)

`src/lab/secure/path_traversal.py` uses `werkzeug.utils.safe_join` plus a realpath containment check:

```python
from werkzeug.utils import safe_join

@bp.route("/file")
def read_file():
    name = request.args.get("name", "welcome.txt")
    base = current_app.config["FILES_DIR"]

    safe_path = safe_join(base, name)
    if safe_path is None:
        return jsonify(error="Path traversal attempt blocked"), 400

    # Defense in depth: confirm the resolved path is still inside the sandbox.
    if os.path.commonpath(
        [os.path.realpath(safe_path), os.path.realpath(base)]
    ) != os.path.realpath(base):
        return jsonify(error="Path traversal attempt blocked"), 400

    with open(safe_path, encoding="utf-8", errors="replace") as fh:
        return jsonify(content=fh.read())
```

**Why it works:** `safe_join` rejects absolute paths and any input whose normalized form would leave the base directory, returning `None`. The second layer resolves symlinks with `os.path.realpath` and uses `os.path.commonpath` to assert the final path is still rooted under `base` — this defeats symlink tricks and edge cases `safe_join` might not catch. The two checks together guarantee containment.

## Detection (Blue Team)

`src/lab/blue_team/detection.py` `path_traversal` signatures:

```python
"path_traversal": [
    re.compile(r"\.\.[/\\]"),
    re.compile(r"(/etc/passwd|boot\.ini|win\.ini)", re.I),
],
```

The `../` payload matches the first pattern (covering both `/` and `\` separators); requests for well-known sensitive files match the second. The scanner inspects the URL-decoded value too, so `%2e%2e%2f` is also caught.

## References

- [OWASP A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [Werkzeug `safe_join`](https://werkzeug.palletsprojects.com/en/latest/utils/#werkzeug.utils.safe_join)
