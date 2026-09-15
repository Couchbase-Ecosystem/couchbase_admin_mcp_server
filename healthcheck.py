"""Container health probe for the HTTP transport.

ONE DEFINITION, THREE CALLERS: the image's HEALTHCHECK and both Kubernetes
manifests run this file. It used to be an inline one-liner in the Dockerfile and
a `httpGet: /healthz` in the manifests, and those two disagreed with each other
and with the server -- see below.

WHY A 401 IS HEALTHY
====================
The probe answers one question: is this process serving HTTP? A 401 answers it
YES and additionally proves the authorization layer is engaged. Treating it as a
failure means the container can never report healthy in the only profile the
shipped deployment artifacts support.

MEASURED 2026-09-15, the first time the image was ever run over HTTP. The
Dockerfile's probe was

    urllib.request.urlopen(f'http://{host}:{port}/mcp', timeout=5)

with no Authorization header. `CB_ADMIN_HTTP_REQUIRE_AUTH=true` is MANDATORY in
the enterprise profile, so the server answered 401, urlopen raised, and the
container sat at `health: starting` forever:

    GET /mcp HTTP/1.1" 401 Unauthorized      <- every 30 seconds, by design

Anything keyed on that health state -- `depends_on: service_healthy`, an
orchestrator's restart policy -- is broken by it, in the deployment shape this
repository ships for.

The Kubernetes manifests were worse: `httpGet: { path: /healthz, port: 8000 }`
against a server that has no /healthz and no health route of any kind. The only
occurrence of that string in the tree was the manifests themselves. A pod would
never become ready and the Service would never route to it. Neither manifest had
ever been applied.

AND WHY NOT A /healthz ENDPOINT
==============================
Considered and rejected, deliberately: an unauthenticated route on a server that
administers clusters is a new public surface, and a public surface on an admin
service is an attack surface. Tolerating the refusal costs nothing and adds
nothing reachable.

WHAT COUNTS AS HEALTHY
======================
Any HTTP response the application itself produced, including 4xx. The process is
up, the ASGI stack is routing, and -- for a 401 -- the auth layer is enforcing.

WHAT COUNTS AS UNHEALTHY
========================
A connection error, a timeout, or a 5xx. Nothing answered, or what answered is
broken rather than refusing.

A 5xx is deliberately NOT tolerated. 401 is the server working; 500 is not, and a
probe that cannot tell them apart reports a wedged process as healthy, which is
the failure mode this file exists to remove rather than relocate.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request

#: Statuses that prove the application answered. 4xx is the application refusing,
#: which is the application working.
_ANSWERED_FLOOR = 200
_ANSWERED_CEILING = 499


def _endpoint() -> str:
    host = os.environ.get("CB_ADMIN_HOST", "127.0.0.1").strip() or "127.0.0.1"
    # 0.0.0.0 is a bind address, not a destination. Probing it works on Linux and
    # is meaningless as an address; loopback is what a probe inside the container
    # should dial.
    if host in ("0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
    port = os.environ.get("CB_ADMIN_PORT", "8000").strip() or "8000"
    return f"http://{host}:{port}/mcp"


def check(url: str | None = None, timeout: float = 5.0) -> tuple[int, str]:
    """(exit_code, reason). 0 is healthy."""
    if os.environ.get("CB_ADMIN_TRANSPORT", "stdio").strip().lower() != "http":
        return 0, "transport is not http; nothing to probe"

    target = url or _endpoint()
    try:
        with urllib.request.urlopen(target, timeout=timeout) as response:
            return 0, f"answered {response.status}"
    except urllib.error.HTTPError as exc:
        if _ANSWERED_FLOOR <= exc.code <= _ANSWERED_CEILING:
            return 0, f"answered {exc.code} (the application refused, so it is up)"
        return 1, f"answered {exc.code}"
    except Exception as exc:  # URLError, socket timeout, anything else
        return 1, f"no answer from {target}: {exc}"


def main() -> int:
    code, reason = check()
    print(reason, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
