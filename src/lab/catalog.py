"""Single source of truth for the vulnerability catalog.

Drives the index page and is handy for docs/tests. Each entry pairs a vulnerable
route with its hardened twin so the UI can render them side by side.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Vulnerability:
    slug: str
    name: str
    owasp: str
    cwe: str
    vulnerable_path: str
    secure_path: str
    attack_example: str
    summary: str


CATALOG: list[Vulnerability] = [
    Vulnerability(
        slug="sql-injection",
        name="SQL Injection",
        owasp="A03:2021 Injection",
        cwe="CWE-89",
        vulnerable_path="/vulnerable/sql?id=1",
        secure_path="/secure/sql?id=1",
        attack_example="/vulnerable/sql?id=0 UNION SELECT username, password, 1 FROM users",
        summary="User input concatenated into a SQL string is parsed as code.",
    ),
    Vulnerability(
        slug="xss",
        name="Reflected XSS",
        owasp="A03:2021 Injection",
        cwe="CWE-79",
        vulnerable_path="/vulnerable/xss?name=guest",
        secure_path="/secure/xss?name=guest",
        attack_example="/vulnerable/xss?name=<script>alert(document.domain)</script>",
        summary="Unescaped input reflected into HTML runs in the victim's browser.",
    ),
    Vulnerability(
        slug="brute-force",
        name="Brute Force / Broken Auth",
        owasp="A07:2021 Auth Failures",
        cwe="CWE-307",
        vulnerable_path="/vulnerable/login?username=admin&password=admin123",
        secure_path="/secure/login",
        attack_example="loop GET /vulnerable/login?username=admin&password=<wordlist>",
        summary="No rate limit, plaintext passwords, credentials over GET.",
    ),
    Vulnerability(
        slug="path-traversal",
        name="Path Traversal",
        owasp="A01:2021 Broken Access Control",
        cwe="CWE-22",
        vulnerable_path="/vulnerable/file?name=welcome.txt",
        secure_path="/secure/file?name=welcome.txt",
        attack_example="/vulnerable/file?name=../../config.py",
        summary="Unvalidated filename lets '../' escape the sandbox directory.",
    ),
    Vulnerability(
        slug="command-injection",
        name="Command Injection (RCE)",
        owasp="A03:2021 Injection",
        cwe="CWE-78",
        vulnerable_path="/vulnerable/ping?host=127.0.0.1",
        secure_path="/secure/ping?host=127.0.0.1",
        attack_example="/vulnerable/ping?host=127.0.0.1; whoami",
        summary="Input passed to a shell lets metacharacters run arbitrary commands.",
    ),
    Vulnerability(
        slug="ssti",
        name="Server-Side Template Injection",
        owasp="A03:2021 Injection",
        cwe="CWE-1336",
        vulnerable_path="/vulnerable/ssti?name=guest",
        secure_path="/secure/ssti?name=guest",
        attack_example="/vulnerable/ssti?name={{7*7}}",
        summary="Input compiled as template source escalates to RCE via Jinja2.",
    ),
    Vulnerability(
        slug="idor",
        name="IDOR",
        owasp="A01:2021 Broken Access Control",
        cwe="CWE-639",
        vulnerable_path="/vulnerable/account/2",
        secure_path="/secure/account/2",
        attack_example="/vulnerable/account/1  (read another user's private note)",
        summary="No ownership check: incrementing the id walks the whole table.",
    ),
    Vulnerability(
        slug="ssrf",
        name="SSRF",
        owasp="A10:2021 SSRF",
        cwe="CWE-918",
        vulnerable_path="/vulnerable/fetch?url=http://example.com",
        secure_path="/secure/fetch?url=http://example.com",
        attack_example="/vulnerable/fetch?url=http://169.254.169.254/latest/meta-data/",
        summary="Server fetches any URL, pivoting to internal-only resources.",
    ),
    Vulnerability(
        slug="deserialization",
        name="Insecure Deserialization",
        owasp="A08:2021 Integrity Failures",
        cwe="CWE-502",
        vulnerable_path="/vulnerable/deserialize?data=",
        secure_path="/secure/deserialize?data=",
        attack_example="pickle payload whose __reduce__ runs a command, base64-encoded",
        summary="pickle.loads on untrusted input is remote code execution.",
    ),
    Vulnerability(
        slug="jwt",
        name="JWT Signature Bypass",
        owasp="A02:2021 Cryptographic Failures",
        cwe="CWE-347",
        vulnerable_path="/vulnerable/jwt/admin?token=",
        secure_path="/secure/jwt/admin?token=",
        attack_example='forge {"role":"admin"} with no signature, pass as ?token=',
        summary="Token decoded without verifying the signature; claims are forgeable.",
    ),
]
