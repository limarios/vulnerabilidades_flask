"""WSGI entrypoint. Run with `python wsgi.py` or `flask --app wsgi run`."""

from __future__ import annotations

import os

from lab import create_app

app = create_app()

if __name__ == "__main__":
    # Defaults to loopback on purpose: this app is intentionally vulnerable and must
    # never be exposed beyond the local machine. Inside a container HOST=0.0.0.0 is
    # used, but docker-compose only publishes the port on the host's 127.0.0.1.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    app.run(host=host, port=port)
