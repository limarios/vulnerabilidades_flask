# Architecture

Flask Security Lab is a Red Team vs Blue Team teaching laboratory. Every
vulnerability ships as a **pair of twin routes**: a deliberately insecure one
under `/vulnerable/*` and its hardened counterpart under `/secure/*`. A single
runtime flag, `BLUE_TEAM_ENABLED`, toggles the application between behaving like
naive legacy code and behaving like a defended production service.

This document describes the request lifecycle, the application-factory pattern,
the layering, the Blue Team flag, the directory layout, and the testing
strategy.

---

## Request flow

```
                         ┌──────────────────────────────────────────┐
   HTTP request          │            create_app(config)            │
       │                 │  - load Config (Dev|Lab|Test)            │
       ▼                 │  - init extensions (Limiter)             │
 ┌───────────┐           │  - register blueprints                   │
 │  Werkzeug │           │  - if BLUE_TEAM_ENABLED: register hooks  │
 │   /WSGI   │           └──────────────────────────────────────────┘
 └─────┬─────┘
       │
       ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  before_request  (Blue Team — only if BLUE_TEAM_ENABLED)          │
 │    1. detection.py  → signature match → structured JSON log       │
 │    2. mini-WAF      → 403 ONLY on /secure/* ; /vulnerable stays   │
 │                       explorable (WAF_ENABLED gate)               │
 └────────────────────────────┬─────────────────────────────────────┘
                              │
        ┌─────────────────────┴─────────────────────┐
        ▼                                            ▼
 ┌───────────────┐                          ┌───────────────┐
 │  vulnerable/  │   blueprint              │   secure/     │   blueprint
 │  (naive impl) │                          │ (hardened)    │
 └───────┬───────┘                          └───────┬───────┘
         │            both hit data layer           │
         └─────────────────┬────────────────────────┘
                           ▼
                    ┌──────────────┐
                    │   db.py      │  raw SQLite, table `users`
                    └──────┬───────┘
                           │
                           ▼
 ┌──────────────────────────────────────────────────────────────────┐
 │  after_request  (Blue Team — only if BLUE_TEAM_ENABLED)           │
 │    headers.py → CSP, X-Frame-Options, X-Content-Type-Options, …   │
 └────────────────────────────┬─────────────────────────────────────┘
                              ▼
                         HTTP response
```

When `BLUE_TEAM_ENABLED` is **off**, the `before_request` / `after_request`
hooks are never registered. The app then responds exactly like uninstrumented
naive code: no detection, no WAF, no security headers. This is the single
switch that flips the lab between "attacker's playground" and "defended
service".

---

## Application Factory

The app is built by `create_app(config_name=None, overrides=None)` in
`src/lab/__init__.py`.

```python
def create_app(config_name=None, overrides=None):
    app = Flask(__name__)
    app.config.from_object(resolve_config(config_name))   # Dev|Lab|Test
    if overrides:
        app.config.update(overrides)                      # per-test tuning
    init_extensions(app)                                  # Flask-Limiter
    register_blueprints(app)                              # vulnerable, secure, main
    if app.config["BLUE_TEAM_ENABLED"]:
        register_blue_team(app)                           # before/after hooks
    return app
```

Why a factory (see ADR-0001):

- **Per-config instances.** Dev, Lab, and Test configs each produce a fresh
  app. Tests build dozens of apps with different `overrides` (e.g.
  `BLUE_TEAM_ENABLED=False`, `RATELIMIT_ENABLED=False`) without polluting global
  state.
- **No import-time side effects.** Nothing binds a socket or opens a database
  at import time, so the package is safe to import from tests, the Red Team CLI,
  and `wsgi.py` alike.
- **Composability.** The Blue Team layer is wired in conditionally, expressing
  the central design idea as a single `if` in the factory.

Configuration lives in `src/lab/config.py`:

| Config       | Purpose                              | `BLUE_TEAM_ENABLED` |
|--------------|--------------------------------------|---------------------|
| `DevConfig`  | Local development, debug on          | `True`              |
| `LabConfig`  | The defended demo (docker `lab-defended`) | `True`         |
| `TestConfig` | pytest; deterministic, ephemeral DB  | overridable         |

The naive `lab-naive` service is just `LabConfig` with `BLUE_TEAM_ENABLED=False`
supplied via environment override — no separate codebase.

---

## Layers

```
src/lab/
├── __init__.py      Application Factory: create_app, blueprint + hook wiring
├── config.py        DevConfig / LabConfig / TestConfig + feature flags
├── catalog.py       Single source of truth for the 10 vulnerabilities
│                    (id, title, OWASP, CWE, vulnerable route, secure route)
├── extensions.py    Flask-Limiter instance (RATELIMIT_ENABLED gate)
├── db.py            Raw SQLite access; `users` table; no ORM (ADR-0004)
├── main.py          Index page + /health
├── vulnerable/      One naive module per vulnerability
├── secure/          One hardened module per vulnerability (mirror of above)
├── blue_team/       Detection, WAF, logging, security headers
├── templates/       Jinja2 templates
└── static/          CSS/JS assets
```

- **`vulnerable/` and `secure/` are mirrored file-for-file** (see ADR-0002):
  `vulnerable/sql_injection.py` ↔ `secure/sql_injection.py`, and so on. The
  diff between the two files *is* the lesson.
- **`catalog.py` is the single source of truth.** The index page, the docs
  table, and tests all read vulnerability metadata from here, so routes and
  classifications never drift.
- **`blue_team/` is the defensive layer**, split into:
  - `detection.py` — request signature matching; emits structured JSON attack
    logs via `structlog`.
  - `headers.py` — security response headers (CSP, `X-Frame-Options`,
    `X-Content-Type-Options`, etc.).
  - `logging.py` — `structlog` configuration.
- **`db.py`** wraps raw SQLite. The `users` table is intentionally shaped to
  enable the demos:

  | Column          | Purpose                                          |
  |-----------------|--------------------------------------------------|
  | `id`            | primary key                                      |
  | `username`      | login identifier                                 |
  | `password`      | plaintext — drives the *naive* login demo        |
  | `password_hash` | Werkzeug hash — drives the *secure* login        |
  | `role`          | authorization (admin vs user)                    |
  | `private_note`  | per-user secret — the IDOR target                |

- **`src/red_team/`** is a separate package: a loopback-only attack CLI.
  `guard.py` enforces that every target resolves to `127.0.0.1`, so the tooling
  can never be pointed at a third party.

---

## Feature flags

All flags resolve from config / environment and gate the Blue Team layer
independently:

| Flag                 | Effect                                                        |
|----------------------|---------------------------------------------------------------|
| `BLUE_TEAM_ENABLED`  | Master switch. Off ⇒ no hooks, naive behavior.                |
| `WAF_ENABLED`        | Enables the mini-WAF inside `before_request`.                 |
| `RATELIMIT_ENABLED`  | Enables Flask-Limiter (brute-force defense on `/secure`).     |

**Key invariant:** the mini-WAF returns `403` **only on `/secure/*`**. The
`/vulnerable/*` routes always remain exploitable so the attack half of each
lesson keeps working even while the defended half is hardened.

---

## Testing strategy

Tests (pytest, ~30 cases) follow a "**prove the attack AND prove the
defense**" philosophy, split three ways:

| Suite              | Asserts                                                       |
|--------------------|---------------------------------------------------------------|
| `test_vulnerable`  | The exploit actually works against `/vulnerable/*`.           |
| `test_secure`      | The same exploit fails against `/secure/*`.                   |
| `test_blue_team`   | Detection logs fire, the WAF blocks `/secure`, headers exist. |

Each test builds its own app via `create_app(..., overrides=...)`, toggling
flags as needed (e.g. disabling rate limiting to test the underlying logic in
isolation). Because the factory guarantees fresh, side-effect-free instances,
suites stay independent and deterministic.

CI (GitHub Actions) runs the suite across a Python 3.10–3.12 matrix, plus Ruff,
Black, and mypy gates enforced locally via pre-commit.
