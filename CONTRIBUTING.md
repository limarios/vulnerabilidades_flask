# Contributing to Flask Security Lab

Thank you for your interest in improving Flask Security Lab. This is an
educational Red Team vs. Blue Team security lab built on Flask. Contributions
that sharpen the teaching value, harden the scaffolding, or add well-modeled
vulnerabilities are very welcome.

> **Ethics first.** This project ships intentional vulnerabilities for
> learning. Every contribution must preserve the project's ethical,
> **loopback-only** stance. The `red_team` attack CLI must never be made to
> target hosts other than `127.0.0.1`/`localhost`. Do not weaken the safety
> guard, and do not add functionality designed to be pointed at third-party
> systems. See `SECURITY.md` for the full policy.

---

## Development environment

Requires Python 3.11+.

```bash
# 1. Clone and enter the repo
git clone https://github.com/limarios/flask-security-lab.git
cd flask-security-lab

# 2. Create and activate a virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# 3. Install the package in editable mode with dev extras
pip install -e ".[dev]"

# 4. Install the git hooks
pre-commit install
```

Run the app locally:

```bash
python wsgi.py
# or with Docker:
docker compose up
```

---

## Project layout

This project uses a `src/` layout.

```
src/
  lab/                 # The Flask application (application factory)
    main.py            # create_app() factory + blueprint registration
    config.py          # Config objects (incl. BLUE_TEAM_ENABLED)
    catalog.py         # Central catalog of vulnerabilities
    extensions.py      # Shared Flask extensions
    db.py              # Database setup / seed data
    vulnerable/        # Intentionally vulnerable implementations
    secure/            # Mirrored, hardened implementations
    blue_team/         # Defensive layer (logging, detection, headers)
    templates/  static/  data/
  red_team/            # Loopback-only attack CLI
    cli.py  attacks.py  guard.py  wordlists/
tests/                 # pytest suite (attack + defense)
```

The `vulnerable/` and `secure/` packages mirror each other module-for-module
(e.g. `vulnerable/sql_injection.py` <-> `secure/sql_injection.py`). The
`blue_team/` layer (structured JSON logging, signature detection, mini-WAF,
security headers, rate limiting) is toggled by the `BLUE_TEAM_ENABLED`
configuration flag.

---

## Coding standards

All of the following must pass before a PR is merged (they run in CI and via
pre-commit):

```bash
ruff check .          # linting
black --check .       # formatting
mypy                  # static typing
pytest                # tests
```

To auto-fix formatting and lint issues locally:

```bash
ruff check --fix .
black .
```

- Type-annotate new code; `mypy` must be clean.
- Keep modules small and mirror the existing structure.
- **Conventional Commits** are encouraged, e.g.
  `feat(vuln): add open-redirect module`, `fix(blue): correct WAF regex`,
  `docs: clarify SSRF walkthrough`, `test: cover IDOR fix`.

---

## Testing philosophy

Security claims are only credible if they are proven by tests. Therefore:

> **Every vulnerability needs a test that proves the attack succeeds against
> the `vulnerable/` implementation, AND a test that proves the attack fails
> (is mitigated) against the `secure/` implementation.**

When the Blue Team layer is relevant, also add a test (in
`tests/test_blue_team.py`) proving the defensive control detects or blocks the
attack when `BLUE_TEAM_ENABLED` is on.

The suite is organized as:

- `tests/test_vulnerable.py` — attack succeeds against vulnerable code.
- `tests/test_secure.py` — attack is mitigated by the secure code.
- `tests/test_blue_team.py` — defensive controls behave correctly.
- `tests/conftest.py` — shared fixtures (app factory, clients).

---

## Adding a NEW vulnerability

Follow the mirrored module pattern end to end:

1. **Vulnerable module** — create `src/lab/vulnerable/<name>.py` with the
   intentionally insecure implementation and its blueprint/route(s).
2. **Secure module** — create the mirror at `src/lab/secure/<name>.py` with the
   hardened implementation exposing the equivalent route(s).
3. **Register** both blueprints in the application factory
   (`src/lab/main.py`).
4. **Catalog entry** — add the vulnerability to `src/lab/catalog.py` (name,
   OWASP category, description, route mapping) so it appears in the lab index.
5. **Docs entry** — add a bilingual walkthrough under `docs/vulnerabilities/`
   explaining the flaw, the exploit, and the fix.
6. **Tests** — add the attack test (`tests/test_vulnerable.py`), the fix test
   (`tests/test_secure.py`), and, if it interacts with the defensive layer, a
   Blue Team test (`tests/test_blue_team.py`).
7. **Red Team support (optional)** — if the vulnerability warrants an automated
   exploit, add it to `src/red_team/attacks.py` and wire it into the CLI. It
   **must** route through the loopback guard in `src/red_team/guard.py`.

Keep the vulnerable and secure modules symmetric so learners can diff them.

---

## Pull request process

1. Branch from `master` (e.g. `feat/open-redirect`).
2. Make focused commits (Conventional Commits encouraged).
3. Ensure the full quality gate passes locally:
   `ruff check . && black --check . && mypy && pytest`.
4. Update docs and `CHANGELOG.md` (`[Unreleased]` section) as needed.
5. Open a PR against `master` and fill out the PR template checklist.
6. CI (GitHub Actions) runs on every push and PR to `master` and must be green.
7. A maintainer reviews; address feedback and keep the branch up to date.

By contributing you agree that your work is licensed under the project's MIT
License, and that it upholds the ethical, loopback-only stance described above.
