# Flask Security Lab — Red Team ⚔ Blue Team

> A hands-on Flask application where **every vulnerability ships with its attack, its fix, and its detection.** Built to be studied, attacked, and defended.

[![CI](https://github.com/limarios/flask-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/limarios/flask-security-lab/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP%20Top%2010-7%2F10%20covered-orange.svg)](docs/threat-model.md)

🇧🇷 **[Leia em português](README.pt-BR.md)**

---

> ### ⚠️ Educational use only
> This project contains **intentional vulnerabilities**. It must **never** be deployed to production or exposed beyond your local machine. The offensive tooling is **loopback-only by design**. Attacking systems you do not own or have written authorization to test is a crime (Brazil: Law 12.737/2012 & 14.155/2021; US: CFAA; UK: Computer Misuse Act). See [SECURITY.md](SECURITY.md).

---

## Why this exists

Most "vulnerable app" projects only show you the broken code. This one is built around a single idea: **for every weakness, you should be able to see all three sides of it.**

- 🔴 **Red Team** — the attack that breaks the naive endpoint (`/vulnerable/*`)
- 🔵 **Blue Team** — the hardened twin that defeats the same attack (`/secure/*`)
- 🛰️ **Detection** — the request-time signature logging that spots the attack as it happens

The two sides live in **mirrored modules** (`src/lab/vulnerable/sql_injection.py` ↔ `src/lab/secure/sql_injection.py`), so the diff between *wrong* and *right* is structural, not buried in prose. And it is **verifiable**: the test suite proves each attack succeeds against the naive code and fails against the fix.

## The demo, in one command

Spin up the lab, then run the whole attack catalog against it:

```console
$ python -m red_team all --target http://127.0.0.1:5000

Target: http://127.0.0.1:5000  (loopback verified)

=== SQL Injection ===
  Red  (/vulnerable): leaked 3 row(s) incl. credentials: [{'username': 'admin123', ...}]
  Blue (/secure)    : HTTP 403 (input rejected / parameterized)

=== Reflected XSS ===
  Red  (/vulnerable): payload reflected unescaped
  Blue (/secure)    : payload escaped

=== Brute Force ===
  Red  (/vulnerable): password cracked: 'admin123'
  Blue (/secure)    : 3/8 attempts rate-limited (HTTP 429)

=== Command Injection ===
  Red  (/vulnerable): injected command executed
  Blue (/secure)    : HTTP 403 (host validation rejected input)

=== IDOR ===
  Red  (/vulnerable): read another user's note: 'Master recovery code: 8F3K-9920-ZZ'
  Blue (/secure)    : HTTP 403 (ownership check denied access)

   ... and SSTI, Path Traversal, SSRF, Insecure Deserialization, JWT bypass, L7 load test
```

Every line is the real output of a real request. The attacker wins on the left; the defender wins on the right.

## Vulnerability matrix

Ten vulnerabilities covering **7 of the OWASP Top 10 (2021)** categories. Each links to a focused write-up.

| # | Vulnerability | OWASP | CWE | Key defense | Docs |
|---|---|---|---|---|---|
| 1 | SQL Injection | A03 Injection | CWE-89 | Parameterized query | [↗](docs/vulnerabilities/01-sql-injection.md) |
| 2 | Reflected XSS | A03 Injection | CWE-79 | Output escaping + CSP | [↗](docs/vulnerabilities/02-xss.md) |
| 3 | Brute Force / Broken Auth | A07 Auth Failures | CWE-307 | Rate limit + password hashing | [↗](docs/vulnerabilities/03-brute-force.md) |
| 4 | Path Traversal | A01 Broken Access Control | CWE-22 | `safe_join` + realpath check | [↗](docs/vulnerabilities/04-path-traversal.md) |
| 5 | Command Injection (RCE) | A03 Injection | CWE-78 | `subprocess` w/o shell + validation | [↗](docs/vulnerabilities/05-command-injection.md) |
| 6 | Server-Side Template Injection | A03 Injection | CWE-1336 | Input as data, not template source | [↗](docs/vulnerabilities/06-ssti.md) |
| 7 | IDOR | A01 Broken Access Control | CWE-639 | Ownership / authorization check | [↗](docs/vulnerabilities/07-idor.md) |
| 8 | SSRF | A10 SSRF | CWE-918 | Scheme allowlist + private-IP block | [↗](docs/vulnerabilities/08-ssrf.md) |
| 9 | Insecure Deserialization | A08 Integrity Failures | CWE-502 | JSON instead of pickle | [↗](docs/vulnerabilities/09-insecure-deserialization.md) |
| 10 | JWT Signature Bypass | A02 Cryptographic Failures | CWE-347 | Verify signature + pin algorithm | [↗](docs/vulnerabilities/10-jwt-signature-bypass.md) |

A09 (Logging & Monitoring) is covered by the Blue Team layer itself. See the full mapping in the **[threat model](docs/threat-model.md)**.

## The `BLUE_TEAM_ENABLED` switch

The same app runs in two modes, controlled by one flag — this is what makes the "before / after" story possible without maintaining two codebases:

| Mode | Behaviour |
|---|---|
| `BLUE_TEAM_ENABLED=false` | Naive app: no security headers, no detection, no WAF. Attacks just work. |
| `BLUE_TEAM_ENABLED=true` | Defenses wired in via request hooks: **structured JSON attack logging**, a **signature-based mini-WAF** (blocks `/secure/*`, leaves `/vulnerable/*` exploitable on purpose), **security headers** (CSP, `X-Frame-Options`, …), and **rate limiting**. |

When the WAF spots an attack, it emits a SOC-style log line — this is OWASP A09 done right:

```json
{"event": "attack_detected", "categories": ["sql_injection"], "path": "/secure/sql",
 "remote_addr": "127.0.0.1", "blocked": true, "level": "warning", "timestamp": "..."}
```

## Quickstart

### Local (Python 3.10+)

```bash
git clone https://github.com/limarios/flask-security-lab.git
cd flask-security-lab

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

python wsgi.py                       # defended lab on http://127.0.0.1:5000
```

Open `http://127.0.0.1:5000` for the dashboard, then attack it:

```bash
python -m red_team sqli              # one attack
python -m red_team all               # the whole catalog
```

### Docker

Brings up both modes side by side — defended on `:5000`, naive on `:5001` (published on loopback only):

```bash
docker compose up
```

### Make targets

```bash
make install     # venv deps + pre-commit hooks
make run         # run the defended lab
make run-naive   # run with the Blue Team disabled
make test        # pytest (proves attack + defense)
make lint        # ruff + black --check
make demo        # run the full red_team catalog
```

## How it's built

```
src/
├── lab/
│   ├── __init__.py        # Application Factory: create_app()
│   ├── config.py          # Dev / Lab / Test configs + the BLUE_TEAM_ENABLED flag
│   ├── db.py              # thin SQLite layer (parameterized vs raw)
│   ├── catalog.py         # single source of truth for the vulnerability list
│   ├── vulnerable/        # 🔴 naive blueprints  -> /vulnerable/*
│   ├── secure/            # 🔵 hardened twins     -> /secure/*
│   ├── blue_team/         # detection, mini-WAF, security headers, JSON logging
│   ├── templates/ static/ # the SOC-themed dashboard
├── red_team/              # loopback-only attack CLI (guard.py enforces 127.0.0.1)
tests/                     # test_vulnerable (attack works) + test_secure (fix holds) + test_blue_team
docs/                      # architecture, threat model, ADRs, per-vulnerability write-ups
```

Architecture decisions are recorded as **[ADRs](docs/adr/)**; the design is explained in **[docs/architecture.md](docs/architecture.md)**.

## Testing

The suite encodes the project's thesis — each vulnerability has a test that **proves the attack lands** and one that **proves the fix holds**:

```bash
pytest                       # all
pytest -m vulnerable         # only the attacks-succeed tests
pytest -m secure             # only the defense-holds tests
pytest -m blue_team          # WAF / detection / headers
```

## Documentation

- **[Architecture](docs/architecture.md)** — factory, layers, request flow
- **[Threat model](docs/threat-model.md)** — full OWASP Top 10 mapping
- **[Vulnerability write-ups](docs/vulnerabilities/)** — one per vulnerability: theory, exploit, fix, detection
- **[ADRs](docs/adr/)** — why the project is shaped the way it is

## Contributing & security

Contributions welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)** for the dev setup and the pattern for adding a new vulnerability. Please read **[SECURITY.md](SECURITY.md)** first: the vulnerabilities here are intentional and must not be reported as bugs.

## License

MIT © Matheus Lima — see [LICENSE](LICENSE).
