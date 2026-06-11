# ADR-0002: Mirrored `vulnerable/` and `secure/` Blueprints

## Status

Accepted

## Context

The lab's pedagogical goal is to make the difference between insecure and secure
code **obvious and reviewable**. For each of the ten vulnerabilities we need to
present both the flawed implementation and its fix in a way that:

- lets a reader diff one against the other and see exactly what changed,
- keeps the attack half explorable independently of the defended half,
- avoids hiding the contrast behind conditionals inside a single handler.

Possible layouts considered:

1. **One handler per vuln, branching on a flag** inside the function. Rejected:
   the insecure and secure paths get tangled in `if secure:` branches, the diff
   is invisible, and a reader cannot point to "the vulnerable file".
2. **Secure code only, with the vulnerability described in comments.** Rejected:
   the lab must *prove the attack works*, not just describe it.
3. **Two mirrored module trees**, one Blueprint each.

## Decision

Maintain two parallel packages, **`src/lab/vulnerable/` and `src/lab/secure/`,
mirrored file-for-file**:

```
vulnerable/sql_injection.py   ↔   secure/sql_injection.py
vulnerable/xss.py             ↔   secure/xss.py
vulnerable/idor.py            ↔   secure/idor.py
…ten pairs…
```

Each tree is registered as its own Blueprint (`/vulnerable/*`, `/secure/*`). The
two files for a given vulnerability share structure and intent; the *only*
meaningful difference is the defense. That diff is the lesson.

Vulnerability metadata (routes, OWASP/CWE classification) lives once in
`catalog.py`, which both trees and the docs reference.

## Consequences

**Positive**

- `diff vulnerable/sql_injection.py secure/sql_injection.py` is a teaching
  artifact on its own.
- Insecure and secure logic never interleave; no flag-branching inside handlers.
- The `/vulnerable/*` routes stay independently exploitable (the WAF blocks only
  `/secure/*`), so the attack half always works.
- Reviewers can audit the `secure/` tree as a self-contained "here's how to do
  it right" reference.

**Negative / trade-offs**

- Some boilerplate is duplicated across the twin files (imports, route scaffolding).
- A genuinely shared helper must be lifted to a common module rather than copied;
  contributors must resist copy-paste drift. `catalog.py` centralizes the
  metadata that would otherwise be the worst offender.

The duplication is intentional and bounded — it is the medium of instruction.
