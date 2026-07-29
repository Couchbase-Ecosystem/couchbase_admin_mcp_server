# syntax=docker/dockerfile:1.6
#
# Couchbase Admin MCP Server — container image
#
# Build:
#   docker build -t couchbase-ecosystem/couchbase-admin-mcp:0.1.0 -t couchbase-ecosystem/couchbase-admin-mcp:latest .
#
# Run (stdio — for use behind a process supervisor):
#   docker run -i --rm \
#     -e CB_CONNECTION_STRING="couchbases://cluster.example" \
#     -e CB_USERNAME="user" \
#     -e CB_PASSWORD="pass" \
#     -e CB_BUCKET="travel-sample" \
#     couchbase-ecosystem/couchbase-admin-mcp:latest
#
# Run (HTTP transport — for networked deployment):
#   docker run -d --rm --name couchbase-mcp \
#     -p 8000:8000 \
#     -e CB_ADMIN_TRANSPORT=http \
#     -e CB_ADMIN_HOST=0.0.0.0 \
#     -e CB_CONNECTION_STRING="couchbases://cluster.example" \
#     -e CB_USERNAME="user" -e CB_PASSWORD="pass" \
#     -e CB_BUCKET="travel-sample" \
#     couchbase-ecosystem/couchbase-admin-mcp:latest

# ── Stage 1: build dependencies ───────────────────────────────────────────────
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Build deps for couchbase SDK C extension
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./

# Install runtime deps + the HTTP transport extras
RUN pip install --prefix=/install \
    "mcp>=1.0.0" \
    "couchbase>=4.4.0,<5.0.0" \
    "uvicorn>=0.27" \
    "starlette>=0.35" \
    "PyJWT[crypto]>=2.8.0" \
    "cryptography>=42.0" \
    "requests>=2.31"

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

# Runtime-only OS dependencies (TLS, libc) — no compilers
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for security
RUN groupadd --system --gid 1000 mcp \
    && useradd --system --uid 1000 --gid mcp --home /app --shell /sbin/nologin mcp

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=mcp:mcp server.py /app/server.py
COPY --chown=mcp:mcp logging_config.py /app/logging_config.py
COPY --chown=mcp:mcp handlers /app/handlers
COPY --chown=mcp:mcp auth /app/auth

USER mcp

# Read-only mode is ON by default — operators must explicitly opt out
ENV CB_ADMIN_READ_ONLY_MODE=true \
    CB_ADMIN_TRANSPORT=stdio \
    CB_ADMIN_HOST=127.0.0.1 \
    CB_ADMIN_PORT=8000

# Document the HTTP transport port (no-op for stdio mode)
EXPOSE 8000

# Healthcheck — only meaningful in HTTP transport mode. When CB_ADMIN_TRANSPORT
# is anything other than 'http', the check exits 0 (skip), since stdio mode
# has no HTTP listener to probe.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import os, sys; \
        sys.exit(0) if os.environ.get('CB_ADMIN_TRANSPORT', 'stdio').lower() != 'http' else None; \
        import urllib.request; \
        host = os.environ.get('CB_ADMIN_HOST', '127.0.0.1'); \
        port = os.environ.get('CB_ADMIN_PORT', '8000'); \
        urllib.request.urlopen(f'http://{host}:{port}/mcp', timeout=5)" || exit 1

ENTRYPOINT ["python", "/app/server.py"]
