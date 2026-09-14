"""
handlers/capella/client.py — HTTP client for the Capella Management API v4.

DIFFERENT FROM ``handlers.shared.admin_request``
===============================================
    shared.admin_request  ->  https://<node>:18091/pools/...             Basic
    capella_request       ->  https://cloudapi.cloud.couchbase.com/v4/... Bearer

They are separate on purpose: different base URL, different auth scheme,
different TLS story (Capella terminates on a publicly-trusted certificate, so
none of the CB_CA_CERT_PATH / mTLS plumbing applies), and different pagination
(v4 returns a ``{"data": [...], "cursor": {...}}`` envelope; ns_server does not).

AUTH
====
Every v4 call carries the API key **secret** as a Bearer token::

    Authorization: Bearer <CAPELLA_API_KEY_SECRET>

The secret is shown once, at key creation, in Capella under
Settings -> API Keys. It cannot be retrieved afterwards. The key's organization
role and per-project roles determine what these tools can do — an API key with
only ``projectViewer`` will read but never write, no matter what this server's
read-only mode says. Both gates apply; the stricter one wins.

ENV VARS
========
  CAPELLA_API_KEY_SECRET   Required. Bearer token (the API key secret).
  CAPELLA_BASE_URL         Optional. Default https://cloudapi.cloud.couchbase.com
  CAPELLA_HTTP_TIMEOUT     Optional, seconds. Default 30.
  CAPELLA_HTTP_RETRIES     Optional. Default 3 attempts.
  CAPELLA_PAGE_SIZE        Optional. perPage for list calls. Default 100 (v4 max).
  CAPELLA_MAX_ITEMS        Optional. Cap on auto-paginated results. Default 1000 —
                           a guard against handing an LLM a 50,000-row audit dump.
"""

from __future__ import annotations

import http.client
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from handlers.shared import get_env, get_env_int, redact
from logging_config import get_logger

_log = get_logger("handlers.capella.client")

_DEFAULT_BASE = "https://cloudapi.cloud.couchbase.com"

# v4 caps perPage at 100 on the list endpoints.
_MAX_PER_PAGE = 100


def base_url() -> str:
    return (os.environ.get("CAPELLA_BASE_URL") or _DEFAULT_BASE).rstrip("/")


def _secret() -> str:
    """The API key secret, or a fail-loud error naming the fix.

    Deliberately not defaulted: a silently unauthenticated control-plane client
    produces 401s that look like a permissions problem rather than a
    configuration problem.
    """
    return get_env("CAPELLA_API_KEY_SECRET")


#: Statuses that mean "the request was definitely NOT processed" — the server
#: rejected or never began it. Safe to retry for any method, including POST.
_REJECTED_UNPROCESSED = frozenset({408, 425, 429})

#: Statuses that mean "something went wrong server-side, outcome unknown". The
#: request may have been partially or fully applied before the error.
_SERVER_ERROR = frozenset({500, 502, 503, 504})

#: Methods that are safe to repeat: repeating them cannot create a second
#: resource. DELETE and PUT on a specific resource are idempotent by definition;
#: GET is a read. POST is the exception — it creates.
_IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE"})


def _retryable(status: int, method: str) -> bool:
    """Whether to retry, accounting for whether the method is safe to repeat.

    The subtlety that matters: a POST that creates a cluster may SUCCEED and then
    have its response lost to a 502 from an intermediary or a dropped connection.
    Blindly retrying that POST creates a SECOND cluster — a real duplicate, billed
    — and the caller never learns it happened. So POST is retried only on statuses
    that prove the request was never processed (429 rate-limit, 408/425), never on
    5xx where the outcome is genuinely unknown.

    The cost of not retrying is one failed create that the caller must repeat.
    Because the environment orchestrator is a reconciler, its next pass lists what
    exists and adopts anything that did land — so the conservative choice is also
    the recoverable one.
    """
    if status in _REJECTED_UNPROCESSED:
        return True
    if status in _SERVER_ERROR:
        return method.upper() in _IDEMPOTENT_METHODS
    return False


class CapellaError(RuntimeError):
    """A v4 call that failed permanently. Carries an actionable hint."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        hint: str = "",
        code: int | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.hint = hint
        #: The Capella DOMAIN code (7011 "already off", 5026 "source must match"), as
        #: distinct from the HTTP status. Carried as an attribute because recovering it
        #: from the message text proved unreliable -- see capella_error_code.
        self.code = code


def _domain_code_of(detail: Any) -> int | None:
    """The Capella domain ``code`` from a PARSED error body."""
    if not isinstance(detail, dict):
        return None
    code = detail.get("code")
    if isinstance(code, bool):
        return None
    if isinstance(code, int):
        return code
    if isinstance(code, str) and code.strip().isdigit():
        return int(code.strip())
    return None


def capella_error_code(exc: BaseException) -> int | None:
    """The Capella domain ``code`` from an error, or None.

    Callers need to recognise specific outcomes -- 7011 "cluster already off", 7010
    "already on", 5026 "source cluster must match" -- and the obvious way to do that
    was `if "7011" in str(exc)`. That is wrong in a way that costs money. The
    rendered message is ``HTTP <status> on <METHOD> <path>: <body>``, so the digits
    are matched against the STATUS, the PATH (which contains cluster and project
    UUIDs) and the request id, not just the code. A cluster whose UUID happens to
    contain 7011 turned every failed turn-off -- including a 500 and a 503 -- into
    ``{"state": "already_off", "billing": "stopped"}`` while the cluster kept
    running and billing.

    So the code is parsed out of the JSON body proper. Returns None when there is no
    parseable code, and every caller must treat None as "not the outcome I was
    hoping for" and re-raise.
    """
    # The ATTRIBUTE first. Parsing it back out of the rendered message was fragile in
    # exactly the way that matters: the message carried a Python repr rather than JSON,
    # so the string path never matched and the callers silently took the re-raise
    # branch. The attribute is set where the body is parsed, so no round-trip is needed.
    # Typed, because `.code` means something DIFFERENT on urllib.error.HTTPError: there
    # it is the HTTP status. Reading it off an arbitrary exception would report a 404 as
    # Capella domain code 404. Not currently reachable -- both call sites catch only
    # CapellaError -- but the next caller that passes an HTTPError would be wrong in a
    # way that silently changes a park/resume decision.
    if isinstance(exc, CapellaError):
        attached = getattr(exc, "code", None)
        if isinstance(attached, int) and not isinstance(attached, bool):
            return attached
    text = str(exc)
    start = text.find("{")
    while start != -1:
        try:
            body = json.loads(text[start:])
        except json.JSONDecodeError:
            start = text.find("{", start + 1)
            continue
        if isinstance(body, dict):
            code = body.get("code")
            if isinstance(code, bool):
                return None
            if isinstance(code, int):
                return code
            if isinstance(code, str) and code.strip().isdigit():
                return int(code.strip())
        return None
    return None


#: Capella 404 messages that explain themselves. When the body says WHY, the
#: generic "your ids are probably wrong" hint is not merely redundant, it is a
#: wrong answer printed with authority.
#:
#: MEASURED 2026-09-13. capella_cluster_audit_log_export_get answered:
#:
#:   404 {"message": "No audit log files exist within the requested time frame."}
#:
#: The export EXISTS -- it is in capella_cluster_audit_log_exports_list, with
#: that same sentence as its `status` -- and the path, the project and the
#: auditLogExportId were all correct. Capella uses 404 for "this job produced no
#: content", not only for "no such object". The generic hint sent the reader to
#: re-resolve ids that were already right, which cost an investigation.
_SELF_EXPLAINING_404 = (
    "no audit log files exist",
    "within the requested time frame",
)


def _message_of(detail: Any) -> str:
    if isinstance(detail, dict):
        return str(detail.get("message") or "")
    return str(detail or "")


def _hint_for_status(status: int, detail: Any = None) -> str:
    """The hint for a status, SILENCED when the server already gave a reason.

    `detail` is optional so every existing caller keeps working; passing it is
    what lets a self-explaining error speak for itself.
    """
    if status == 404:
        message = _message_of(detail).lower()
        if any(phrase in message for phrase in _SELF_EXPLAINING_404):
            # Do not restate, and do not contradict. Point at the ONE thing that
            # changes the outcome.
            return (
                "Capella answered 404 with a reason of its own, quoted above — the "
                "object exists and the request was well formed. For an audit-log "
                "export this means the window held no audit records: enable audit "
                "logging with capella_cluster_audit_log_config_set, let the cluster "
                "record some activity, then export a window that contains it."
            )
    return _hint_body(status)


def _hint_body(status: int) -> str:
    if status == 401:
        return (
            "Capella rejected the credential. CAPELLA_API_KEY_SECRET must be the "
            "API key SECRET — the value shown once at creation under Settings -> "
            "API Keys — not the key's id or name. If the key was rotated, the old "
            "secret is dead; update the env var."
        )
    if status == 403:
        return (
            "Authenticated but not authorized. The API key's organization role and "
            "its per-project roles govern this call: reads need at least "
            "projectViewer on the target project, writes need projectManager or "
            "organizationOwner. Widen the key's roles in Capella or use a "
            "different key — this server cannot escalate."
        )
    if status == 404:
        return (
            "Resource not found. In v4 every id is a UUID and the hierarchy is "
            "strict: organization -> project -> cluster -> bucket/scope/collection. "
            "A valid cluster UUID under the WRONG project id returns 404, not 403. "
            "Resolve ids with capella_resolve or the *_list tools instead of "
            "assuming them."
        )
    if status == 409:
        return (
            "Conflict — the resource already exists, or the cluster is mid-operation "
            "(deploying, scaling, rebalancing, turning on/off). Poll "
            "capella_cluster_get until currentState is 'healthy', then retry."
        )
    if status == 422:
        return (
            "Well-formed JSON but semantically invalid for v4 — commonly a service "
            "group whose compute/storage combination the cloud provider does not "
            "offer, or a bucket memory allocation exceeding the cluster's free "
            "quota. The error detail names the offending field."
        )
    if status == 429:
        return (
            "Organization rate limit; retries with backoff were exhausted. Slow down."
        )
    return ""


def _ssl_context() -> ssl.SSLContext:
    # cloudapi presents a publicly-trusted certificate. There is intentionally no
    # insecure escape hatch here: CB_ADMIN_TLS_INSECURE exists for self-signed
    # self-managed clusters and must not be able to weaken the control plane.
    return ssl.create_default_context()


def _encode_params(params: dict | None) -> str:
    if not params:
        return ""
    cleaned: dict[str, Any] = {}
    for k, v in params.items():
        if v is None:
            continue
        if isinstance(v, bool):
            cleaned[k] = "true" if v else "false"
        elif isinstance(v, (list, tuple)):
            cleaned[k] = list(v)  # v4 repeats the key for multi-valued params
        else:
            cleaned[k] = v
    if not cleaned:
        return ""
    return "?" + urllib.parse.urlencode(cleaned, doseq=True)


def quote_segment(segment: Any) -> str:
    """URL-encode one path segment, escaping '/' too.

    Applied to every caller-supplied id so a value containing a slash, a space or
    '..' cannot escape its segment and address a different resource.
    """
    return urllib.parse.quote(str(segment or ""), safe="")


def extract_placeholders(template: str) -> list[str]:
    """Placeholder names in a ``/v4/...{name}...`` template, in order."""
    names: list[str] = []
    start = -1
    for i, ch in enumerate(template):
        if ch == "{":
            start = i
        elif ch == "}" and start >= 0:
            names.append(template[start + 1 : i])
            start = -1
    return names


def build_path(template: str, args: dict) -> str:
    """Render a path template from tool arguments, encoding each segment.

    A missing placeholder is an error rather than an empty segment: silently
    collapsing ``/clusters//buckets`` would address a different resource.
    """
    out = template
    for placeholder in extract_placeholders(template):
        value = args.get(placeholder)
        if value is None or value == "":
            raise CapellaError(
                f"Missing required argument '{placeholder}' for path {template}",
                hint=(
                    "Every v4 path segment is a UUID (or, for scopes and "
                    "collections, a name). Obtain it from the corresponding "
                    "*_list tool or from capella_resolve."
                ),
            )
        out = out.replace("{" + placeholder + "}", quote_segment(value))
    return out


def capella_request(
    method: str,
    path: str,
    *,
    params: dict | None = None,
    body: Any | None = None,
) -> Any:
    """Execute one Capella v4 call.

    ``path`` must already be per-segment encoded (see ``build_path``). Retries
    transient failures with exponential backoff. Returns parsed JSON, or
    ``{"status": "ok"}`` for an empty 2xx body (v4 DELETEs answer 204).
    """
    secret = _secret()
    url = base_url() + (path if path.startswith("/") else "/" + path)
    url += _encode_params(params)

    headers = {
        "Authorization": f"Bearer {secret}",
        "Accept": "application/json",
    }
    payload: bytes | None = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        payload = json.dumps(body).encode()

    timeout = get_env_int("CAPELLA_HTTP_TIMEOUT", 30)
    max_attempts = max(1, get_env_int("CAPELLA_HTTP_RETRIES", 3))
    backoff = 0.5
    context = _ssl_context()

    last: CapellaError | None = None
    for attempt in range(1, max_attempts + 1):
        req = urllib.request.Request(url, data=payload, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                raw = resp.read()
                if not raw:
                    return {"status": "ok", "http_status": resp.status}
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return {"status": "ok", "body": raw.decode(errors="replace")}
        except urllib.error.HTTPError as exc:
            raw = exc.read() if hasattr(exc, "read") else b""
            try:
                detail: Any = json.loads(raw)
            except Exception:
                detail = raw.decode(errors="replace")
            hint = _hint_for_status(exc.code, detail)
            if exc.code in _SERVER_ERROR and method.upper() not in _IDEMPOTENT_METHODS:
                hint = (
                    "Capella returned a server error on a CREATE request. This was "
                    "deliberately NOT retried: the request may have succeeded before "
                    "the error, and repeating it could create a duplicate resource. "
                    "Check whether the resource exists (the *_list tools, or "
                    "capella_env_status) before retrying. If you are using "
                    "capella_env_ensure, simply call it again — it adopts anything "
                    "that did get created."
                ) + (f" {hint}" if hint else "")
            # json.dumps the detail, and carry the domain code on the exception.
            #
            # `f"...: {detail}"` interpolated the already-parsed DICT, so the message
            # held a single-quoted Python repr -- {'code': 7011} -- which is not JSON.
            # capella_error_code therefore never matched, and the park/resume
            # "already off"/"already on" recognition it was written for silently never
            # fired. Carrying the code as an ATTRIBUTE removes the string round-trip
            # from the decision entirely; the JSON body stays in the message for humans.
            domain_code = _domain_code_of(detail)
            last = CapellaError(
                f"HTTP {exc.code} on {method} {path}: "
                f"{json.dumps(detail, default=str) if isinstance(detail, (dict, list)) else detail}",
                status=exc.code,
                hint=hint,
            )
            last.code = domain_code
            if _retryable(exc.code, method) and attempt < max_attempts:
                _log.debug(
                    "capella %s %s -> %s, retry %d/%d",
                    method,
                    path,
                    exc.code,
                    attempt,
                    max_attempts,
                )
                time.sleep(backoff * (2 ** (attempt - 1)))
                continue
            raise last from exc
        except (
            urllib.error.URLError,
            TimeoutError,
            ssl.SSLError,
            http.client.HTTPException,
        ) as exc:
            # TimeoutError, ssl.SSLError and HTTPException alongside URLError. A read
            # timeout raises bare TimeoutError -- an OSError, NOT a URLError subclass --
            # so the only timeout this client can actually see escaped uncaught: no
            # retry for an idempotent GET, no CapellaError, and none of the "this
            # CREATE may have been applied, verify before retrying" guidance below.
            safe_to_repeat = method.upper() in _IDEMPOTENT_METHODS
            network_hint = (
                "Could not reach the Capella control plane. Check outbound HTTPS "
                f"to {base_url()} — a different destination from your cluster's "
                "data-plane hostname, and one that egress allowlists and proxies "
                "commonly miss."
            )
            if not safe_to_repeat:
                # A dropped connection on a POST is indistinguishable from "the
                # request arrived, was applied, and the reply was lost". Retrying
                # risks a duplicate resource, so it is left to the caller.
                network_hint += (
                    " This CREATE request was not retried, because a dropped "
                    "connection cannot be distinguished from a request that was "
                    "applied before the reply was lost. Verify current state "
                    "before retrying."
                )
            # getattr, because `reason` exists only on URLError. Widening this except
            # tuple to cover the bare TimeoutError a read timeout actually raises made
            # `exc.reason` an AttributeError -- so the timeout escaped as
            # AttributeError instead of CapellaError, and every `except CapellaError`
            # recovery downstream (env_status' detail_unavailable, _fetch_cluster_by_id's
            # 404 -> None, the contextlib.suppress(CapellaError) sites) was bypassed.
            reason = getattr(exc, "reason", None) or exc
            last = CapellaError(
                f"Network error on {method} {path}: {reason}",
                hint=network_hint,
            )
            if safe_to_repeat and attempt < max_attempts:
                time.sleep(backoff * (2 ** (attempt - 1)))
                continue
            raise last from exc

    raise last or CapellaError("Unknown error after retries")


# ── Pagination ───────────────────────────────────────────────────────────────
#
# v4 list endpoints answer:
#
#   {"data": [ ... ], "cursor": {"pages": {"page": 1, "perPage": 100,
#                                          "totalItems": 431, "last": 5}}}
#
# Handing an agent only page 1 of 5 is a correctness bug, not a UX wrinkle — it
# will confidently report 100 clusters when there are 431. List calls therefore
# auto-paginate to completion, bounded by CAPELLA_MAX_ITEMS.


def _pages_meta(envelope: Any) -> dict:
    if not isinstance(envelope, dict):
        return {}
    cursor = envelope.get("cursor")
    if not isinstance(cursor, dict):
        return {}
    pages = cursor.get("pages")
    return pages if isinstance(pages, dict) else {}


def capella_list(
    path: str,
    *,
    params: dict | None = None,
    page_size: int | None = None,
    max_items: int | None = None,
) -> Any:
    """GET a v4 list endpoint, following the cursor to the last page.

    Returns a normalized envelope::

        {"data": [...], "itemCount": n, "totalItems": n,
         "pagesFetched": k, "truncated": bool}

    ``truncated`` is set when the cap stopped collection early, so the caller is
    told rather than handed a silently short list. Endpoints that answer a bare
    array or a single object are passed through untouched.
    """
    per_page = page_size or get_env_int("CAPELLA_PAGE_SIZE", _MAX_PER_PAGE)
    per_page = max(1, min(per_page, _MAX_PER_PAGE))
    # `is not None`, not `or`: max_items=0 fell through to the default instead of
    # reaching the non-positive refusal below, so the one value most likely to be
    # passed by mistake was silently ignored.
    cap = max_items if max_items is not None else get_env_int("CAPELLA_MAX_ITEMS", 1000)
    # A non-positive cap silently dropped records off the end -- max_items=-1 returned
    # 99 of 100 -- so an internal lookup could answer "this resource does not exist"
    # for one that does, which is how a duplicate cluster gets created.
    if cap <= 0:
        raise CapellaError(
            f"max_items={cap} is not a positive integer.",
            hint=(
                "A non-positive cap would silently truncate the list, and these "
                "listings decide whether a resource already exists. Omit it or pass a "
                "positive value."
            ),
        )

    collected: list[Any] = []
    page = 1
    pages_fetched = 0
    total_items: int | None = None
    truncated = False

    while True:
        merged = dict(params or {})
        merged.setdefault("perPage", per_page)
        merged["page"] = page
        envelope = capella_request("GET", path, params=merged)
        pages_fetched += 1

        if isinstance(envelope, list):
            return {
                "data": envelope,
                "itemCount": len(envelope),
                "totalItems": len(envelope),
                "pagesFetched": 1,
                "truncated": False,
            }
        if not isinstance(envelope, dict) or "data" not in envelope:
            return envelope

        chunk = envelope.get("data") or []
        if not isinstance(chunk, list):
            return envelope
        collected.extend(chunk)

        meta = _pages_meta(envelope)
        if total_items is None and isinstance(meta.get("totalItems"), int):
            total_items = meta["totalItems"]

        if len(collected) >= cap:
            collected = collected[:cap]
            # Only TRUNCATED if records actually remain. `>= cap` fired on an
            # exactly-full but COMPLETE list, so a 100-item result under
            # CAPELLA_MAX_ITEMS=100 reported truncated:true and told the agent to
            # narrow a query that had already returned everything.
            if total_items is None or total_items > len(collected):
                truncated = True
            break

        last_page = meta.get("last")
        # Keep paging while totalItems says records remain, even when `last` is
        # absent or non-int. Stopping after page 1 on a missing `last` reported
        # truncated:false while leaving records behind -- count_managed_environments
        # saw 100 of 431 clusters, which under-reads the spend ceiling and can make
        # the reconciler create a duplicate instead of adopting the real one.
        more_by_total = (
            isinstance(total_items, int) and len(collected) < total_items and chunk
        )
        if isinstance(last_page, int):
            if page >= last_page or not chunk:
                break
        elif not more_by_total:
            break
        page += 1

    result: dict[str, Any] = {
        "data": collected,
        "itemCount": len(collected),
        "totalItems": total_items if total_items is not None else len(collected),
        "pagesFetched": pages_fetched,
        "truncated": truncated,
    }
    if truncated:
        result["note"] = (
            f"Result capped at CAPELLA_MAX_ITEMS={cap}. Narrow the query with "
            "sortBy/sortDirection or a more specific parent id, or raise the cap."
        )
    return result


def redact_response(data: Any) -> Any:
    """Mask credential material in a v4 response.

    Applied only to operations whose *response* carries a secret — API key
    create/rotate returns the new token, database-credential create echoes the
    password. Those values must not enter an LLM context window or the server
    log. Everything else passes through unredacted so ordinary fields are not
    needlessly masked.
    """
    return redact(data)
