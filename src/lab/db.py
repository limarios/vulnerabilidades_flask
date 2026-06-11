"""SQLite access layer.

Deliberately thin: no ORM. A single ``users`` table is enough to demonstrate SQL
injection, broken authentication and IDOR. The layer exposes both a parameterized
helper (used by the secure routes) and a raw connection (used by the vulnerable
routes, on purpose).

Each row carries both a plaintext ``password`` (so the naive ``/vulnerable/login``
can compare strings, as legacy code often does) and a ``password_hash`` (used by the
hardened ``/secure/login``). That mirror is itself a teaching point.
"""

from __future__ import annotations

import sqlite3

from flask import Flask, current_app, g
from werkzeug.security import generate_password_hash

# (id, username, plaintext password, role, private note for the IDOR demo)
_SEED_USERS = [
    (1, "admin", "admin123", "admin", "Master recovery code: 8F3K-9920-ZZ"),
    (2, "alice", "correct horse battery staple", "user", "Alice's diary: bought a cat."),
    (3, "bob", "hunter2", "user", "Bob's notes: passport in the drawer."),
]


def _connect(database_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_db() -> sqlite3.Connection:
    """Return a request-scoped connection, creating and seeding it on first use."""
    if "db" not in g:
        database_path = current_app.config["DATABASE_PATH"]
        g.db = _connect(database_path)
        _ensure_schema(g.db)
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            username      TEXT NOT NULL UNIQUE,
            password      TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'user',
            private_note  TEXT NOT NULL DEFAULT ''
        )
        """)
    already_seeded = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if not already_seeded:
        conn.executemany(
            "INSERT INTO users (id, username, password, password_hash, role, private_note) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [
                (uid, name, pwd, generate_password_hash(pwd), role, note)
                for uid, name, pwd, role, note in _SEED_USERS
            ],
        )
        conn.commit()


def init_app(app: Flask) -> None:
    """Register the connection teardown so each request cleans up after itself."""
    app.teardown_appcontext(close_db)
