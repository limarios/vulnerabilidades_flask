# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Flask Security Lab - multi-stage image
# ---------------------------------------------------------------------------
# This app is intentionally vulnerable for educational purposes. It MUST NOT be
# exposed to a network. The container listens on 0.0.0.0 so docker-compose can
# reach it, but compose only publishes the port on the host's loopback
# (127.0.0.1) -- see docker-compose.yml.
# ---------------------------------------------------------------------------

# --- Stage 1: builder -------------------------------------------------------
# Build a wheel for the project so the runtime image stays lean and free of
# build tooling.
FROM python:3.12-slim AS builder

WORKDIR /build

# Faster, cleaner pip behaviour during build.
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# Only the metadata + sources needed to build the wheel.
COPY pyproject.toml README.md ./
COPY src ./src
COPY wsgi.py ./

# Build a wheel of the project (runtime deps only, no [dev] extras).
RUN python -m pip install --upgrade pip build \
    && python -m build --wheel --outdir /dist

# --- Stage 2: runtime -------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Inside the container we bind to all interfaces; compose restricts the
    # published port to the host loopback only.
    HOST=0.0.0.0 \
    PORT=5000 \
    FLASK_ENV=lab

WORKDIR /app

# Install the project from the wheel built in stage 1.
COPY --from=builder /dist/*.whl /tmp/
RUN python -m pip install /tmp/*.whl \
    && rm -f /tmp/*.whl

# The WSGI entrypoint lives at the project root and is not part of the wheel.
COPY wsgi.py ./

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 labuser
USER labuser

EXPOSE 5000

# Lightweight healthcheck against the app's /health endpoint. Uses urllib so we
# don't need curl/wget in the slim image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=3).status == 200 else 1)"]

# Educational app: a plain dev server is exactly what we want so the
# vulnerable/secure contrast is observable. Run via the WSGI entrypoint.
CMD ["python", "wsgi.py"]
