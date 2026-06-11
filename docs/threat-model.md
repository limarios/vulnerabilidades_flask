# Threat Model

Flask Security Lab implements ten classic web vulnerabilities, each as a twin
pair of routes: an exploitable `/vulnerable/*` route and a hardened `/secure/*`
counterpart. This document maps every vulnerability to its
[OWASP Top 10 (2021)](https://owasp.org/Top10/) category and
[CWE](https://cwe.mitre.org/), and names the key defense applied in the secure
twin.

---

## Vulnerability matrix

| # | Vulnerability | OWASP 2021 | CWE | Vulnerable route | Key defense (secure twin) |
|---|---------------|------------|-----|------------------|---------------------------|
| 1 | SQL Injection | A03: Injection | CWE-89 | `/vulnerable/sql` | Parameterized query |
| 2 | Reflected XSS | A03: Injection | CWE-79 | `/vulnerable/xss` | `markupsafe.escape` + CSP |
| 3 | Brute Force / Broken Auth | A07: Identification & Authentication Failures | CWE-307 | `/vulnerable/login` | Flask-Limiter + password hash + POST-only |
| 4 | Path Traversal | A01: Broken Access Control | CWE-22 | `/vulnerable/file` | `werkzeug.safe_join` + `realpath` containment check |
| 5 | Command Injection | A03: Injection | CWE-78 | `/vulnerable/ping` | `subprocess` with `shell=False` + host validation |
| 6 | Server-Side Template Injection (SSTI) | A03: Injection | CWE-1336 | `/vulnerable/ssti` | Treat input as data, never as template source |
| 7 | IDOR | A01: Broken Access Control | CWE-639 | `/vulnerable/account/<id>` | Ownership / authorization check |
| 8 | SSRF | A10: Server-Side Request Forgery | CWE-918 | `/vulnerable/fetch` | URL scheme allowlist + private-IP block |
| 9 | Insecure Deserialization | A08: Software & Data Integrity Failures | CWE-502 | `/vulnerable/deserialize` | JSON only — no `pickle` |
| 10 | JWT Signature Bypass | A02: Cryptographic Failures | CWE-347 | `/vulnerable/jwt/admin` | Verify signature + pin algorithm |

---

## OWASP Top 10 coverage

The lab covers **7 of the 10** OWASP 2021 categories as directly exploitable
vulnerabilities, plus an eighth realized as the Blue Team's own logging layer.

### Covered as exploitable vulnerabilities (6 categories)

| Category | Realized by |
|----------|-------------|
| **A01 — Broken Access Control** | Path Traversal, IDOR |
| **A02 — Cryptographic Failures** | JWT Signature Bypass |
| **A03 — Injection** | SQL Injection, Reflected XSS, Command Injection, SSTI |
| **A07 — Identification & Authentication Failures** | Brute Force / Broken Auth |
| **A08 — Software & Data Integrity Failures** | Insecure Deserialization |
| **A10 — Server-Side Request Forgery** | SSRF |

### Covered as a platform capability

- **A09 — Security Logging & Monitoring Failures** is addressed *positively* by
  the Blue Team layer itself. `blue_team/detection.py` performs signature-based
  request inspection and emits structured JSON attack logs via `structlog`
  (`blue_team/logging.py`). The naive mode (`BLUE_TEAM_ENABLED=False`) is the
  living demonstration of A09 — the same attacks generate **no** telemetry at
  all. The contrast between the two modes is the lesson.

### Narrative notes — not implemented as routes

The remaining three categories are discussed in-repo rather than shipped as
exploitable endpoints, because they are architectural/operational rather than
per-request:

- **A04 — Insecure Design.** The `/vulnerable` vs `/secure` split is itself a
  design-level statement: insecurity is a property of the *design choice* (e.g.
  storing `password` in plaintext, trusting client-supplied IDs), not just of a
  single bad line. The mirrored modules make the design contrast explicit.
- **A05 — Security Misconfiguration.** Demonstrated by the
  `BLUE_TEAM_ENABLED=False` configuration: missing security headers, no WAF,
  debug-friendly defaults. Flipping the flag is flipping a misconfiguration.
- **A06 — Vulnerable & Outdated Components.** Acknowledged operationally: the
  project pins dependencies in `requirements.txt` and the CI/Make tooling can be
  extended with `pip-audit` to flag known-vulnerable or outdated packages. The
  lesson is process, not a route.

---

## Defense-in-depth across the request

No single control is trusted in isolation. For a request hitting a `/secure`
route with the Blue Team enabled, multiple layers apply in sequence:

```
request → detection (log)  → mini-WAF (403 on /secure)
        → secure handler (per-vuln defense, e.g. parameterized query)
        → response → security headers (CSP, X-Frame-Options, …)
```

The per-vulnerability defense in the table above is the **primary** control; the
WAF, detection logging, and security headers are **secondary**, defense-in-depth
layers that apply uniformly across all `/secure` routes.
