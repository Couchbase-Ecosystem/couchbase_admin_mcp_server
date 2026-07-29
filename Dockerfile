# syntax=docker/dockerfile:1.6
#
# Couchbase Admin MCP Server — container image
#
# Build:
#   docker build -t couchbase-ecosystem/couchbase-admin-mcp:0.1.0 -t couchbase-ecosystem/couchbase-admin-mcp:latest .
#
# Run (default: stdio — for Claude Desktop and local MCP clients that launch the
# container per session and speak over stdin/stdout):
#   docker run -i --rm \
#     --network your_docker_network \
#     -e CB_CONNECTION_STRING="couchbase://couchbase-server" \
#     -e CB_USERNAME="user" -e CB_PASSWORD="pass" \
#     couchbase-ecosystem/couchbase-admin-mcp:latest
#   # (--network lets the container resolve the couchbase service name)
#
# Run (HTTP transport — opt in for a long-running networked service that other
# containers / agents connect to; stdio cannot cross a container boundary):
#   docker run -d --rm --name couchbase-admin-mcp \
#     -p 8000:8000 \
#     -e CB_ADMIN_TRANSPORT=http \
#     -e CB_ADMIN_HOST=0.0.0.0 \
#     -e CB_CONNECTION_STRING="couchbase://couchbase-server" \
#     -e CB_USERNAME="user" -e CB_PASSWORD="pass" \
#     couchbase-ecosystem/couchbase-admin-mcp:latest
#   # MCP client connects to http://<host>:8000/mcp
#
# Connecting to a Couchbase cluster in ANOTHER container: put both on the same
# Docker network and point CB_CONNECTION_STRING at the cluster's service name,
# e.g. CB_CONNECTION_STRING="couchbase://couchbase-server". See README
# ("Connecting from Claude Desktop" and "Running in Docker").
#
# Note: CB_BUCKET is optional for the admin server — admin operations act at the
# cluster level. It only affects the SDK warm-up used by a few diagnostics tools.

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

# Install runtime deps + the HTTP transport extras.
# NOTE: the HTTP transport uses StreamableHTTPServerTransport, whose API has
# varied across mcp releases. This code was validated against mcp 1.28.1. If the
# HTTP transport fails to start after a rebuild, pin mcp to a known-good version
# here (e.g. "mcp==1.28.1") rather than the open ">=1.0.0" range.
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

# Container defaults:
#   * Transport defaults to STDIO — the frictionless path for Claude Desktop and
#     other local MCP clients, which launch the server with `docker run -i` and
#     speak over stdin/stdout. stdio cannot cross a container boundary, so for a
#     long-running networked service that other containers/agents connect to,
#     opt in with -e CB_ADMIN_TRANSPORT=http (and CB_ADMIN_HOST=0.0.0.0).
#   * Host defaults to 127.0.0.1 (only relevant once http is enabled). Set
#     CB_ADMIN_HOST=0.0.0.0 to accept connections from other containers/the host.
#     HTTP without OAuth performs no request auth — keep it on a trusted network,
#     publish the port only when you mean to, and enable OAuth (OAUTH_ISSUER +
#     CB_ADMIN_HTTP_REQUIRE_AUTH=true) for authenticated scope enforcement.
# Read-only is ON by default in every mode — writes require CB_ADMIN_READ_ONLY_MODE=false.
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
