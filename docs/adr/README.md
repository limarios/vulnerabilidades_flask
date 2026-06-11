# Architecture Decision Records

Short, dated records of the significant design decisions behind this project. Each
follows the standard format: **Status · Context · Decision · Consequences.**

| ADR | Decision |
|-----|----------|
| [0001](0001-application-factory.md) | Use the Application Factory pattern with blueprints |
| [0002](0002-vulnerable-vs-secure-blueprints.md) | Mirror each vulnerability as twin `vulnerable/` and `secure/` modules |
| [0003](0003-single-app-with-blue-team-flag.md) | One app with a `BLUE_TEAM_ENABLED` flag instead of two apps |
| [0004](0004-no-orm-raw-sqlite.md) | Use raw SQLite instead of an ORM |
