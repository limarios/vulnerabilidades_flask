# ADR-0003: Single App with a `BLUE_TEAM_ENABLED` Flag

## Status

Accepted

## Context

The lab must demonstrate the same application in two postures:

- **Naive** — no security headers, no WAF, no attack detection or logging. This
  is what legacy/uninstrumented code looks like.
- **Defended** — Blue Team layer active: signature detection with structured
  logging, a mini-WAF, and security response headers.

Two ways to deliver this:

1. **Two separate applications / codebases**, one naive and one defended.
2. **One application** whose defensive behavior is gated by a runtime flag.

Option 1 doubles the code, invites drift between the two versions, and obscures
the central teaching point: that the *only* difference between insecure-by-default
and defended is whether a defensive layer is wired in. It also complicates
testing — every test would need to know which app it is exercising.

## Decision

Ship **one application** with a master runtime flag, `BLUE_TEAM_ENABLED`, read
from config/environment in the factory:

```python
if app.config["BLUE_TEAM_ENABLED"]:
    register_blue_team(app)   # before_request + after_request hooks
```

When the flag is off, the Blue Team hooks are **never registered**, and the app
behaves as naive code. Two finer-grained flags, `WAF_ENABLED` and
`RATELIMIT_ENABLED`, gate sub-components for focused demos and tests.

The two Docker services run the *same image*: `lab-defended` (port 5000) with the
flag on, `lab-naive` (port 5001) with it off via environment override. Both bind
to loopback only.

## Consequences

**Positive**

- One codebase, zero drift between the two postures.
- The teaching point is literally one `if` in the factory.
- Tests flip `BLUE_TEAM_ENABLED` (and the sub-flags) per case via `overrides`,
  proving both "the attack succeeds with defenses off" and "the defense holds
  with them on" against identical handlers.
- Operationally mirrors reality: enabling monitoring/WAF/headers in production is
  a configuration change, not a rewrite.

**Negative / trade-offs**

- A misconfigured flag could ship the naive posture unintentionally; mitigated by
  defended defaults in `LabConfig`/`DevConfig` and explicit overrides for the
  naive service.
- Conditional wiring means a reader must consult the factory to know which hooks
  are active for a given config — documented here and in `architecture.md`.
