# 05 — OS Command Injection (RCE)

## Overview

| | |
|---|---|
| **OWASP** | A03:2021 — Injection |
| **CWE** | [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html) |
| **Red Team slug** | `cmdi` |
| **Vulnerable route** | `GET /vulnerable/ping?host=127.0.0.1` |
| **Secure route** | `GET /secure/ping?host=127.0.0.1` |

Command injection occurs when user input is passed to a system shell. Shell metacharacters (`;`, `&&`, `|`, backticks, `$()`) let the attacker chain their own commands onto the intended one, resulting in full remote code execution with the privileges of the web process.

## The Vulnerability

`src/lab/vulnerable/command_injection.py` interpolates the host into a string handed to the shell via `os.popen`:

```python
@bp.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: the shell parses the whole string, including injected commands.
    command = f"ping {_COUNT_FLAG} 1 {host}"
    output = os.popen(command).read()  # noqa: S605
    return jsonify(command=command, output=output)
```

`os.popen` runs the string through `/bin/sh` (or `cmd.exe`), which interprets `;` and `&&` as command separators. The `host` value is parsed as shell syntax, not as a single argument.

## Exploit (Red Team)

```
/vulnerable/ping?host=127.0.0.1; whoami         (Linux/macOS)
/vulnerable/ping?host=127.0.0.1 && dir          (Windows)
```

```bash
curl "http://127.0.0.1:5000/vulnerable/ping?host=127.0.0.1;%20whoami"
```

CLI (`src/red_team/attacks.py::command_injection`), which picks the OS-appropriate separator (`&` on Windows, `;` elsewhere):

```bash
python -m red_team cmdi --target http://127.0.0.1:5000
```

The attack sends `host=127.0.0.1; echo INJECTED` and confirms RCE by checking that `INJECTED` appears in the command output — that string only exists if the injected command ran.

## The Fix (Blue Team)

`src/lab/secure/command_injection.py` validates the host *and* removes the shell entirely:

```python
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$")

def _is_valid_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.match(host))

@bp.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not _is_valid_host(host):
        return jsonify(error="Invalid host"), 400

    result = subprocess.run(  # noqa: S603
        ["ping", _COUNT_FLAG, "1", host],  # noqa: S607
        capture_output=True, text=True, timeout=5, shell=False,
    )
    return jsonify(output=result.stdout, returncode=result.returncode)
```

**Why it works:**
- `_is_valid_host` is an allowlist of *shape*: the value must be a valid IP address or a valid DNS hostname. `127.0.0.1; whoami` contains a space and `;`, so it fails validation and never executes.
- `subprocess.run([...], shell=False)` passes an argument vector directly to the `execve` family. No shell is invoked, so there is nothing to interpret metacharacters — even a malicious `host` is handed to `ping` as a single, literal argument.

Either layer alone blocks the attack; together they are belt-and-suspenders. Avoiding the shell (`shell=False` + argument list) is the structural fix.

## Detection (Blue Team)

`src/lab/blue_team/detection.py` `command_injection` signatures:

```python
"command_injection": [
    re.compile(r"[;&|`]"),
    re.compile(r"\$\("),
    re.compile(r"\b(whoami|cat\s|/bin/sh|nc\s|curl\s|wget\s)", re.I),
],
```

The `; whoami` payload matches both the metacharacter pattern and the command-keyword pattern. `$(...)` command substitution matches the second pattern.

## References

- [OWASP A03:2021 — Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [Python `subprocess` security](https://docs.python.org/3/library/subprocess.html#security-considerations)
