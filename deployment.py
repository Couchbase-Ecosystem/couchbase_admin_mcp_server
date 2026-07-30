"""
deployment.py — deployment-mode detection and capability gating.

WHY THIS MODULE EXISTS
======================
This server was built for self-managed Couchbase Enterprise Server. Nearly
every `admin_*` tool routes through ``handlers.shared.admin_request()``, which
talks to the ns_server Management REST API on port 8091/18091 with Basic auth:

    GET https://cluster:18091/pools/default/buckets
    Authorization: Basic <Administrator:password>

Couchbase Capella does **not** expose that surface to tenants. A Capella
*database credential* carries bucket-scoped data roles only — never Full Admin
— so the ns_server admin endpoints answer 401 (or the port is simply not
reachable for the endpoints in question). The result is that pointing this
server at a Capella connection string produces a tool list that is ~90%
non-functional, failing one call at a time with opaque HTTP errors.

Capella's equivalents live on three *different* planes:

  1. CONTROL PLANE — the Capella Management API v4 at
     ``https://cloudapi.cloud.couchbase.com/v4/...``, authenticated with an
     organization API key secret as a Bearer token. This is where buckets,
     scopes/collections, backups, replications, eventing, query indexes,
     audit logs, allowlists, credentials, CMEK, peering and org users live.
     Covered by ``handlers.capella``.

  2. PROMETHEUS SCRAPE — each Capella cluster exposes a native Prometheus
     target on ``https://cb.<id>.cloud.couchbase.com:18091/metrics`` plus
     ``/prometheus_sd_config``, authenticated with a *database* credential
     that has read access to all buckets. This is the supported route to the
     per-cluster/per-node statistics that ``admin_stats_*`` reads on
     self-managed. Covered by ``handlers.capella.metrics``.

  3. SQL++ / SDK DATA PLANE — ``couchbases://`` to the cluster. Schema
     inference, ``system:indexes``, ``EXPLAIN``, ``ADVISE`` and the
     completed-requests performance advisors need no admin REST at all, so the
     ``cb_*`` diagnostics tools work unchanged against Capella.

This module decides which deployment it is talking to, and the server uses that
to load only the tools that can actually succeed. A tool that cannot work is
better absent than present-and-broken: an agent cannot misroute to a tool it
never sees.

CONFIGURATION
=============
  CB_DEPLOYMENT           auto (default) | capella | self_managed | both
                          `auto`  — infer, see detect_mode() below
                          `both`  — load everything, gate nothing. Use for a
                                    hybrid session that administers a
                                    self-managed cluster AND a Capella org from
                                    one server. You accept that some tools will
                                    fail against whichever side lacks them.
  CB_DEPLOYMENT_GATE      true (default). Set false to keep every tool loaded
                          regardless of detected mode (escape hatch — prefer
                          CB_DEPLOYMENT=both, which is the explicit spelling).
"""

from __future__ import annotations

import os

from logging_config import get_logger

_log = get_logger("deployment")

# ── Modes ────────────────────────────────────────────────────────────────────

CAPELLA = "capella"
SELF_MANAGED = "self_managed"
BOTH = "both"

_VALID_MODES = (CAPELLA, SELF_MANAGED, BOTH)

# Hostname fragments that identify a Capella-hosted data plane. Capella data
# nodes are always addressed as cb.<cluster-id>.cloud.couchbase.com; the
# .digital.couchbase.com suffix appears on some internal/preview environments.
_CAPELLA_HOST_MARKERS = (
    "cloud.couchbase.com",
    "digital.couchbase.com",
)


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or "").strip()


def _env_bool(key: str, default: bool) -> bool:
    raw = _env(key)
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def looks_like_capella_host(connection_string: str) -> bool:
    """True if a connection string points at a Capella-hosted cluster."""
    host = (connection_string or "").lower()
    return any(marker in host for marker in _CAPELLA_HOST_MARKERS)


def detect_mode() -> str:
    """Resolve the deployment mode.

    Explicit CB_DEPLOYMENT always wins. Otherwise infer:

      * Capella host in CB_CONNECTION_STRING            -> capella
      * CAPELLA_API_KEY_SECRET set, no connection string -> capella
      * CAPELLA_API_KEY_SECRET set AND a non-Capella
        connection string set                           -> both
      * anything else                                   -> self_managed

    The last inference matters: an operator who configures both a self-managed
    cluster and a Capella API key plainly intends to drive both, and silently
    unloading one half would be wrong.
    """
    explicit = _env("CB_DEPLOYMENT").lower()
    if explicit in _VALID_MODES:
        return explicit
    if explicit and explicit != "auto":
        _log.warning(
            "CB_DEPLOYMENT=%r is not one of %s or 'auto'; falling back to auto-detection",
            explicit,
            list(_VALID_MODES),
        )

    conn = _env("CB_CONNECTION_STRING")
    has_key = bool(_env("CAPELLA_API_KEY_SECRET"))

    if looks_like_capella_host(conn):
        return CAPELLA
    if has_key and not conn:
        return CAPELLA
    if has_key and conn:
        return BOTH
    return SELF_MANAGED


# ── Capability matrix ────────────────────────────────────────────────────────
#
# On Capella, an `admin_*` tool is unloaded unless it appears here. The rule is
# deliberately deny-by-default: the ns_server admin surface is broad and mostly
# unavailable, so an allowlist of the few reachable endpoints is safer to
# maintain than a denylist of everything else.
#
# Entries and why they survive:
#   admin_prometheus_targets — GET /prometheus_sd_config on 18091. Capella
#       documents this endpoint for Prometheus HTTP service discovery and
#       authorizes it with a database credential that has read access to all
#       buckets. It is genuinely reachable.
#
# Everything else under admin_* (buckets, collections, security, cluster,
# xdcr, indexes, fts, eventing, backup, encryption, stats-range, events,
# internal settings, query settings, node self) requires cluster-admin roles on
# ns_server and has a Capella v4 or Prometheus equivalent instead.
CAPELLA_REACHABLE_ADMIN_TOOLS: frozenset[str] = frozenset(
    {
        "admin_prometheus_targets",
    }
)

# Tool-name prefixes that never depend on the ns_server admin REST API.
#   cb_*      — SDK / SQL++ diagnostics and the server's own status tools
#   capella_* — Capella v4 control plane and Prometheus scrape
_DEPLOYMENT_NEUTRAL_PREFIXES = ("cb_", "capella_")

# Capella-only tools. Loading these against a self-managed cluster would be
# noise at best: there is no organization, no project, and no cloudapi to call.
_CAPELLA_ONLY_PREFIX = "capella_"


def tool_is_available(tool_name: str, mode: str) -> bool:
    """Whether ``tool_name`` can work in the given deployment mode."""
    if mode == BOTH:
        return True

    if tool_name.startswith(_CAPELLA_ONLY_PREFIX):
        return mode == CAPELLA

    if mode == CAPELLA:
        if tool_name.startswith(_DEPLOYMENT_NEUTRAL_PREFIXES):
            return True
        return tool_name in CAPELLA_REACHABLE_ADMIN_TOOLS

    # self-managed: everything except the capella_* family
    return True


def gating_enabled() -> bool:
    return _env_bool("CB_DEPLOYMENT_GATE", True)


def unavailable_reason(tool_name: str, mode: str) -> str:
    """Human-readable explanation for a tool that was gated out.

    Surfaced in the dispatch error path so an agent that has a stale tool list
    gets a directive answer instead of an HTTP 401 it cannot interpret.
    """
    if tool_name.startswith(_CAPELLA_ONLY_PREFIX):
        return (
            f"`{tool_name}` is a Capella control-plane tool and this server is "
            f"running in {mode!r} mode. Set CAPELLA_API_KEY_SECRET and "
            "CB_DEPLOYMENT=capella (or both) to enable it."
        )
    return (
        f"`{tool_name}` uses the self-managed Couchbase Management REST API on "
        "port 8091/18091, which Capella does not expose to tenants — a Capella "
        "database credential has bucket-scoped data roles, never Full Admin. "
        "Use the Capella v4 equivalent (a capella_* tool) instead, or the "
        "Prometheus scrape (capella_metrics_query) for statistics. If you really "
        "are pointing at a self-managed cluster, set CB_DEPLOYMENT=self_managed."
    )


# ── Startup summary ──────────────────────────────────────────────────────────


def describe(mode: str) -> str:
    """One-line description for the startup banner."""
    if mode == CAPELLA:
        return (
            "capella (control plane: cloudapi v4; statistics: Prometheus scrape; "
            "ns_server admin tools unloaded)"
        )
    if mode == BOTH:
        return "both (no capability gating — every tool loaded)"
    return "self_managed (ns_server Management REST on 8091/18091)"
