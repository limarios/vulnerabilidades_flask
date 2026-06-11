# Pull Request

## Summary

Briefly describe what this PR changes and why.

## Type of change

- [ ] New vulnerability module (mirrored `vulnerable/` + `secure/`)
- [ ] Bug fix in scaffolding
- [ ] Blue Team / defensive improvement
- [ ] Red Team CLI change
- [ ] Documentation
- [ ] Tooling / CI / Docker

## Checklist

- [ ] **Tests added** — proves the attack (vulnerable) **and** proves the fix
      (secure); Blue Team test added if a defensive control is involved.
- [ ] `ruff check .` passes.
- [ ] `black --check .` passes.
- [ ] `mypy` passes.
- [ ] `pytest` passes locally and CI is green.
- [ ] **Docs updated** (`docs/vulnerabilities/`, README, etc.) where relevant.
- [ ] **Catalog updated** (`src/lab/catalog.py`) if a new vulnerability was
      added.
- [ ] `CHANGELOG.md` `[Unreleased]` section updated.
- [ ] **Ethical / loopback-only stance preserved** — no functionality intended
      to target third-party systems; the Red Team safety guard is intact.

## Related issues

Closes #
