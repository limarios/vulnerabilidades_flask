# ADR-0001: Application Factory with Blueprints

## Status

Accepted

## Context

Flask Security Lab needs to instantiate the application in several distinct
shapes:

- Three environment configurations (`DevConfig`, `LabConfig`, `TestConfig`).
- A defended demo and a naive demo that differ only by the `BLUE_TEAM_ENABLED`
  flag.
- A test suite (~30 cases) that builds many app instances with per-test flag
  overrides and an ephemeral database.

The naive alternative — a single module that creates a module-level `app = Flask(__name__)`
and registers routes at import time — would force global, import-time
configuration. That makes per-test configuration awkward, introduces shared
mutable state between tests, and triggers side effects (config reads, extension
setup) merely by importing the package.

We also have twenty route modules (ten vulnerable, ten secure) plus an index and
the Blue Team layer. They need to be grouped and namespaced cleanly.

## Decision

Use the **Application Factory** pattern. `create_app(config_name=None, overrides=None)`
in `src/lab/__init__.py`:

1. Creates a fresh `Flask` instance.
2. Loads the resolved config object, then applies optional `overrides`.
3. Initializes extensions (Flask-Limiter).
4. Registers the `vulnerable`, `secure`, and `main` **Blueprints**.
5. Conditionally wires the Blue Team `before_request` / `after_request` hooks
   when `BLUE_TEAM_ENABLED` is true.

Routes are organized as Blueprints, giving each group its own URL prefix
(`/vulnerable`, `/secure`) and import namespace.

## Consequences

**Positive**

- Every config / flag combination produces an isolated app; tests pass
  `overrides` (e.g. `RATELIMIT_ENABLED=False`) without global state.
- No import-time side effects: the package is safe to import from tests, the
  Red Team CLI, and `wsgi.py`.
- The conditional Blue Team wiring expresses the lab's core idea as one `if` in
  the factory.
- Blueprints keep the twenty route modules namespaced and prefixed cleanly.

**Negative / trade-offs**

- One layer of indirection versus a flat single-file app; contributors must know
  to construct the app via `create_app` rather than import a global `app`.
- Slightly more boilerplate (the factory, the registration helpers).

These costs are acceptable and standard for any non-trivial Flask application.
