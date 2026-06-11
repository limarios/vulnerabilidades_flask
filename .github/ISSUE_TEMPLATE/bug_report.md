---
name: Bug report
about: Report a bug in the lab scaffolding (NOT an intentional vulnerability)
title: "[BUG] "
labels: ["bug", "triage"]
assignees: []
---

> ⚠️ **Do NOT report the intentional vulnerabilities — they are by design.**
> SQL injection, XSS, SSTI, command injection, IDOR, SSRF, insecure
> deserialization, JWT flaws, path traversal, and brute force are all
> deliberate teaching material. See `SECURITY.md`. This template is only for
> bugs in the **scaffolding** (the app factory, catalog, Blue Team layer,
> Red Team CLI, tests, Docker, CI, docs, etc.).

## Describe the bug

A clear and concise description of what the bug is.

## To reproduce

Steps to reproduce the behavior:

1. ...
2. ...
3. ...

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened (include error output / tracebacks).

## Environment

- OS:
- Python version:
- Install method: [ ] `pip install -e ".[dev]"`  [ ] Docker (`docker compose up`)
- `BLUE_TEAM_ENABLED`: [ ] true  [ ] false
- Commit / version:

## Additional context

Logs, screenshots, or anything else that helps.

## Confirmation

- [ ] This is **not** one of the intentional vulnerabilities.
- [ ] I searched existing issues and this is not a duplicate.
