# 09 — Insecure Deserialization

## Overview

| | |
|---|---|
| **OWASP** | A08:2021 — Software and Data Integrity Failures |
| **CWE** | [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html) |
| **Red Team slug** | `deserialize` |
| **Vulnerable route** | `GET /vulnerable/deserialize?data=<base64>` |
| **Secure route** | `GET /secure/deserialize?data=<base64>` |

Deserializing untrusted data into live objects is dangerous when the format can describe *object construction* rather than just data. Python's `pickle` can, and reconstructing a pickled object invokes the object's `__reduce__` method — which an attacker controls — leading directly to remote code execution.

## The Vulnerability

`src/lab/vulnerable/deserialization.py` base64-decodes a parameter and feeds it to `pickle.loads`:

```python
import base64
import pickle  # noqa: S403 - the whole point of this module

@bp.route("/deserialize")
def deserialize():
    data = request.args.get("data", "")
    raw = base64.b64decode(data)
    # VULNERABLE: pickle.loads on untrusted input is remote code execution.
    obj = pickle.loads(raw)  # noqa: S301
    return jsonify(type=type(obj).__name__, value=str(obj))
```

### Why `__reduce__` means RCE

When `pickle` serializes an object, it can store a callable plus its arguments via the object's `__reduce__` method; on `loads`, pickle *calls* that callable to rebuild the object. An attacker defines a class whose `__reduce__` returns `(os.system, ("malicious command",))`. The moment the server unpickles it, `os.system(...)` runs — no further interaction needed. The request body *is* the exploit.

## Exploit (Red Team)

Craft a malicious pickle, base64-encode it, and send it as `data`. From `src/red_team/attacks.py::deserialization`:

```python
class _Exploit:
    def __reduce__(self):
        return (os.makedirs, (str(marker), 0o777, True))

data = base64.b64encode(pickle.dumps(_Exploit())).decode()
```

```bash
python -m red_team deserialize --target http://127.0.0.1:5000
```

The attack's `__reduce__` returns `os.makedirs(...)` (a harmless, local, auto-cleaned proof of execution standing in for `os.system`). Sending the payload to `/vulnerable/deserialize` creates the directory on the server, proving arbitrary code ran during unpickling. The same payload against `/secure/deserialize` is rejected.

## The Fix (Blue Team)

`src/lab/secure/deserialization.py` parses the input as JSON instead of pickle:

```python
import base64
import binascii
import json

@bp.route("/deserialize")
def deserialize():
    data = request.args.get("data", "")
    try:
        raw = base64.b64decode(data, validate=True)
        # JSON describes data only - no object construction, no code execution.
        obj = json.loads(raw)
    except (binascii.Error, ValueError):
        return jsonify(error="Expected base64-encoded JSON"), 400
    return jsonify(type=type(obj).__name__, value=obj)
```

**Why it works:** JSON is a *data-only* format. It can represent strings, numbers, booleans, lists and objects — but it has no concept of arbitrary object construction or callables, so there is no `__reduce__` equivalent and no code path to execution. A pickle payload is not valid JSON, so it fails parsing with a clean `400`. The rule: **never deserialize untrusted input into live objects.** If a richer format is genuinely required, the payload must be cryptographically signed (e.g. with `itsdangerous`) and the signature verified *before* parsing.

## Detection (Blue Team)

There is no dedicated `pickle` signature in `src/lab/blue_team/detection.py` — the payload is opaque base64, so a content signature is ineffective. Detection relies on the *behavior* the deserialization triggers (a web process spawning a child process, writing files, or making network connections) observed via host/EDR monitoring, plus alerting on any endpoint that accepts serialized blobs. The structural fix (JSON-only) is the control that matters.

## References

- [OWASP A08:2021 — Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [CWE-502](https://cwe.mitre.org/data/definitions/502.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [Python `pickle` security warning](https://docs.python.org/3/library/pickle.html#module-pickle)
