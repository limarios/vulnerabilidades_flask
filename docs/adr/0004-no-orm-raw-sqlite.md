# ADR-0004: No ORM — Raw SQLite

## Status

Accepted

## Context

The lab needs a data layer for the login, IDOR, and SQL Injection demos. An ORM
(e.g. SQLAlchemy) would be the conventional production choice, and it would make
SQL injection nearly impossible to demonstrate — which is precisely the problem
for a teaching lab.

The whole point of the SQL Injection module is to show, in plain sight, the
difference between a string-built query and a parameterized one. An ORM hides
both behind its query API, so the lesson would have to be faked rather than
shown.

## Decision

Use **raw SQLite with no ORM**, accessed through a thin `src/lab/db.py` wrapper.
A single `users` table backs the demos:

| Column          | Purpose                                              |
|-----------------|------------------------------------------------------|
| `id`            | primary key                                          |
| `username`      | login identifier                                     |
| `password`      | plaintext — drives the *naive* login demo            |
| `password_hash` | Werkzeug hash — drives the *secure* login            |
| `role`          | authorization (admin vs user)                        |
| `private_note`  | per-user secret — the IDOR target                    |

The `vulnerable/` modules build queries with string interpolation (exploitable);
the `secure/` modules use parameterized queries against the same wrapper. Storing
both `password` and `password_hash` lets the naive and secure logins coexist on
one table.

## Consequences

**Positive**

- SQL Injection is demonstrable and fixable *in the same file pair*: interpolated
  query vs parameterized query, side by side.
- No ORM magic between the reader and the SQL — the security-relevant code is
  literal and reviewable.
- Zero external database dependency; SQLite is file-based and ephemeral, ideal
  for tests and Docker.

**Negative / trade-offs**

- Hand-written SQL is more verbose and less safe than an ORM in a real product;
  acceptable here because demonstrating that danger is the goal.
- The plaintext `password` column is deliberately insecure and exists **only**
  for the demo; it must never be copied into real systems. This is called out in
  the code and docs.
- No migrations framework; the schema is small and created on init, so this is a
  non-issue at lab scale.
