"""
audit.py — the accountability record for an autonomous administration chain.

WHAT THIS HAS TO ANSWER
=======================
In the intended deployment there is deliberately no human at the moment of
action. A person pushes code; a workflow-manager agent notices the push and
instructs a child agent; the child creates a bucket, a collection, an XDCR
replication. Nobody clicks "OK", and nobody should have to — the authorization
happened when the IdP issued that service principal a token carrying the
automation scope.

That model is sound, but it moves the entire weight of accountability onto the
record. Three questions must be answerable afterwards, and the previous log line
answered none of them:

    _log.info("tool call: %s args=%s", name, redact(arguments))

  WHO      Which principal? For an unattended workflow the service principal is
           the ONLY identity that exists. Taken from the validated token, never
           from anything the caller can set beside the tool arguments.

  WHY      Was this run unattended, and on what authority? The record states
           whether automation mode applied and which scopes the token carried, so
           "this write executed with no per-call confirmation" is a fact in the
           log rather than an inference.

  TRACING BACK TO A HUMAN
           A principal id stops at "service principal X created a bucket". It
           does not reach the person who pushed the code. So the caller may pass
           a CORRELATION ID — a git SHA, a workflow run URL — which is recorded
           and, critically, has NO effect on authorization. That is the field
           that joins cluster change -> child agent -> workflow run -> the human's
           push into one chain.

DESIGN RULES
============
  * The correlation id is log-only. It is caller-supplied, therefore untrusted,
    therefore it must never influence a decision. Length-capped and newline-
    stripped so it cannot be used to forge log structure.
  * Records are emitted for DENIALS as well as successes. A refused call is the
    more interesting half of an audit trail, and authentication failures
    previously left no trace at all.
  * One record per decision, structured, so it can be shipped to a SIEM without
    re-parsing prose.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import time
from typing import Any

from logging_config import get_logger

_log = get_logger("audit")

# The audit trail must not be subject to the operator's verbosity knob.
#
# Records were emitted at INFO on a logger whose effective level is inherited from
# the `couchbase-admin` tree, which configure_logging sets from CB_ADMIN_LOG_LEVEL.
# So CB_ADMIN_LOG_LEVEL=WARNING (or ERROR) silently discarded EVERY audit record --
# and profile_config.validate() explicitly blesses `CB_ADMIN_LOG_SINKS=stderr,file`
# with no CB_ADMIN_AUDIT_FILE as a durable sink, so the enterprise profile could pass
# validation and then keep no accountability at all. In an unattended deployment the
# audit trail is the only record that an action happened.
#
# Pinning the level here is deliberate and one-directional: a operator may make the
# rest of the server quieter, and the audit trail stays. The dedicated file sink was
# already pinned to INFO with propagate=False, which is why the defect only showed on
# the shared-tree path.
_log.setLevel(logging.INFO)


# ── The dedicated audit sink ─────────────────────────────────────────────────
#
# CB_ADMIN_AUDIT_FILE was a phantom variable, and that made it worse than merely
# missing: the enterprise profile SET it, and profile_config.validate() accepted it
# as proof of "a durable audit sink". So an operator who followed the recommendation
# — set CB_ADMIN_AUDIT_FILE, leave CB_ADMIN_LOG_SINKS alone — passed validation and
# got no durable audit trail whatsoever, in the one deployment shape where the log is
# the only accountability that exists. A control that reports success while doing
# nothing is worse than an absent one.
#
# Records still go to the ordinary logger as well. This is an ADDITIONAL sink whose
# contents are only audit records, because that is the file you hand to an auditor,
# and mixing it with SDK debug output makes it useless for that purpose.
_AUDIT_FILE_HANDLER: Any = None
_AUDIT_SINK_READY = False


class AuditSinkUnavailableError(RuntimeError):
    """The configured durable audit sink could not be opened."""


def audit_sink_error() -> str | None:
    """Why the dedicated sink is unavailable, or None if it is fine / not requested.

    Called from the startup path so an unwritable audit file is FATAL rather than a
    log line nobody reads. profile_config.validate() accepts the mere presence of
    CB_ADMIN_AUDIT_FILE as proof of a durable sink, and the enterprise default points
    at /var/log/couchbase-admin-mcp/ — a directory the container did not create. So
    the common case was: validation passes, the sink silently fails, and the one
    accountability record an unattended chain has goes only to a log the operator was
    told they did not need to configure.
    """
    path = (os.environ.get("CB_ADMIN_AUDIT_FILE") or "").strip()
    if not path:
        return None
    if _audit_file_logger() is not None:
        return None
    return (
        f"CB_ADMIN_AUDIT_FILE={path} cannot be used: the path could not be prepared "
        "(a symlink, a missing directory, or not writable by this user). This is the "
        "durable audit sink, and in an unattended deployment it is the only record "
        "that an operation happened at all — so refusing to start is the correct "
        "response. Create the directory and make it writable by the runtime user, or "
        "unset CB_ADMIN_AUDIT_FILE and configure 'file' in CB_ADMIN_LOG_SINKS instead."
    )


def _audit_file_logger():
    """Lazily attach a private, rotating, audit-only file handler.

    Built on the same primitives as the main log: 0600 creation preserved across
    rotation, and a refusal to write through a symlink — the audit file is the single
    most attractive target for `ln -sf /dev/null`.
    """
    global _AUDIT_FILE_HANDLER, _AUDIT_SINK_READY
    if _AUDIT_SINK_READY:
        return _AUDIT_FILE_HANDLER

    _AUDIT_SINK_READY = True
    path = (os.environ.get("CB_ADMIN_AUDIT_FILE") or "").strip()
    if not path:
        return None

    try:
        import logging

        from logging_config import (
            DEFAULT_LOG_DATEFMT,
            PrivateRotatingFileHandler,
            SafeRecordFilter,
            _ensure_private_logfile,
            _int_env_value,
        )

        if not _ensure_private_logfile(path):
            _log.error(
                "CB_ADMIN_AUDIT_FILE=%s could not be prepared safely (symlink, or "
                "not writable). The dedicated audit sink is NOT active; records are "
                "going only to the ordinary log.",
                path,
            )
            return None

        handler = PrivateRotatingFileHandler(
            path,
            maxBytes=_int_env_value("CB_ADMIN_AUDIT_MAX_BYTES", 32 * 1024 * 1024),
            backupCount=_int_env_value("CB_ADMIN_AUDIT_BACKUP_COUNT", 10),
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(message)s", DEFAULT_LOG_DATEFMT)
        )
        handler.addFilter(SafeRecordFilter())

        sink = logging.getLogger("couchbase-admin.audit.file")
        sink.setLevel(logging.INFO)
        sink.propagate = False  # already emitted on the main tree; do not duplicate
        sink.handlers = [handler]
        _AUDIT_FILE_HANDLER = sink
        return sink
    except Exception as exc:  # never let sink setup break the call it records
        _log.error("Could not open CB_ADMIN_AUDIT_FILE=%s: %s", path, exc)
        return None


def reset_audit_sink() -> None:
    """Drop the memoised sink so a test (or a reconfigure) re-reads the env."""
    global _AUDIT_FILE_HANDLER, _AUDIT_SINK_READY
    if _AUDIT_FILE_HANDLER is not None:
        for handler in list(_AUDIT_FILE_HANDLER.handlers):
            with contextlib.suppress(Exception):
                handler.close()
        _AUDIT_FILE_HANDLER.handlers = []
    _AUDIT_FILE_HANDLER = None
    _AUDIT_SINK_READY = False


#: Cap on the caller-supplied correlation id. It is untrusted text that lands in
#: a log line; unbounded input there is a log-flooding and log-forgery vector.
_MAX_CORRELATION_LEN = 200

#: Argument key through which a workflow passes its provenance. Stripped from the
#: arguments before they reach any REST call, exactly like `confirm`.
CORRELATION_ARG = "correlation_id"


def _redact(value: Any) -> Any:
    """Mask credential-looking fields.

    Imported lazily on purpose. A module-level `from handlers.shared import redact`
    pulled handlers.shared in at audit's import time — and because isort sorts
    `import audit` before `import profile_config`, that happened BEFORE the profile
    applied its env defaults, so handlers.shared snapshotted CB_ADMIN_READ_ONLY_MODE
    from the wrong values. The startup banner showed read_only=True under a
    workstation profile that had set it false. Deferring the import keeps audit free
    of import-time side effects on configuration.
    """
    from handlers.shared import redact as _impl

    return _impl(value)


def sanitize_correlation(value: Any) -> str | None:
    """Make a caller-supplied correlation id safe to write to a log.

    Newlines and carriage returns are removed rather than escaped: this value is
    attacker-influenceable in the sense that whatever drives the agent controls
    it, and CR/LF in a log line lets an attacker fabricate entire records to hide
    a real operation.
    """
    if value is None:
        return None
    text = str(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    text = " ".join(text.split())
    if not text:
        return None
    if len(text) > _MAX_CORRELATION_LEN:
        text = text[:_MAX_CORRELATION_LEN] + "...(truncated)"
    return text


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


def build_record(
    *,
    tool: str,
    arguments: dict,
    decision: str,
    principal: dict | None = None,
    reason: str = "",
    duration_ms: float | None = None,
    source: str = "",
    correlation_id: str | None = None,
) -> dict:
    """Assemble one audit record.

    ``decision`` is one of: allowed, denied_scope, denied_read_only,
    denied_confirmation, denied_hard_ceiling, denied_guardrail, denied_egress,
    dry_run, error. The vocabulary is closed so a SIEM rule can match on it.

    ``dry_run`` is not a refusal and not an execution: the call was authorized and then
    deliberately not performed. It has its own value rather than being folded into
    ``allowed`` because a SIEM rule counting privileged writes must not count previews,
    and an operator asking "did that actually happen?" needs the record to answer.
    """
    args = dict(arguments or {})
    # Accept it explicitly as well as from the arguments. server.py strips
    # CORRELATION_ARG before invoking the handler, and the audit closure reads the
    # same dict — so by the time the "allowed" record was built the field was gone,
    # and the one value whose whole purpose is reaching back to the human who pushed
    # the code was present only on records for calls that never ran.
    correlation = sanitize_correlation(
        correlation_id
        if correlation_id is not None
        else args.pop(CORRELATION_ARG, None)
    )
    args.pop(CORRELATION_ARG, None)

    record: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": "tool_call",
        "tool": tool,
        "decision": decision,
        # redact() masks credential-looking keys, including nested bodies.
        "args": _redact(args),
    }

    if principal:
        # The primary WHO field must never be null when SOME identity is known.
        # On a workstation there is no token and therefore no `principal` key, so
        # this field read null while os_user/host sat right beside it — and
        # "principal" is the field an auditor greps first.
        who = principal.get("principal")
        if not who:
            os_user = principal.get("os_user")
            host = principal.get("host")
            if os_user:
                who = f"{os_user}@{host}" if host else str(os_user)
        record.update(
            {
                "principal": who,
                "client_id": principal.get("client_id"),
                "issuer": principal.get("issuer"),
                "scopes": principal.get("scopes"),
                # The fact that matters most for an unattended write: it ran
                # without per-call confirmation because the token said it could.
                "automation": principal.get("automation", False),
                "auth": principal.get("auth", "none"),
            }
        )
        # Carry through anything else the principal supplied — notably the
        # workstation profile's os_user/host, which were computed and then silently
        # discarded, leaving the laptop record with every WHO field null.
        for key, value in principal.items():
            if key not in record:
                record[key] = value
    else:
        record["auth"] = "none"

    if correlation:
        # Provenance from the workflow manager: the git SHA or run URL that ties
        # this change back to a human decision. Log-only, never authorizing.
        record["correlation_id"] = correlation
    if reason:
        record["reason"] = reason
    if duration_ms is not None:
        record["duration_ms"] = round(duration_ms, 1)
    if source:
        record["source"] = source
    return record


def emit(record: dict) -> None:
    """Write one audit record. Never raises.

    Emitted as a single JSON object per line: forgery of a structured record is
    detectable in a way that forgery of a prose line is not, and a SIEM can ingest it
    without a custom grok pattern.

    The fallback matters more than it looks. A caller-supplied argument nested a few
    hundred levels deep used to raise RecursionError inside record construction —
    which happens AFTER the handler has run — so the operation completed and the
    audit trail contained nothing at all. That is the precise reverse of the intent,
    and it was reachable with one junk argument the handler ignores. Losing detail
    from a record is acceptable; losing the record is not.
    """
    try:
        line = json.dumps(record, sort_keys=True, default=str)
        # PRE-FORMATTED, with no %-args, and that is deliberate.
        #
        # logging_config's SafeRecordFilter applies handlers.shared.redact to
        # `record.args` -- correct for an ordinary log call, where the args are raw
        # values a handler forgot to mask. But this record's fields were ALREADY
        # redacted individually by _redact() at build time, and `line` is the serialized
        # JSON. Passing it as an arg meant the filter ran content redaction over the
        # serialized form, rewriting `"auth": "none"` to `"auth": ***REDACTED***` --
        # unquoted -- so the audit line stopped being parseable JSON. An audit trail a
        # SIEM cannot parse is worse than a slightly less redacted one, and re-redacting
        # an already-redacted record can only ever corrupt it.
        _log.info("AUDIT " + line)
        sink = _audit_file_logger()
        if sink is not None:
            sink.info("AUDIT " + line)  # pre-formatted; see the note above
    except BaseException:
        try:
            _log.info(
                "AUDIT %s",
                json.dumps(
                    {
                        "ts": record.get("ts"),
                        "event": record.get("event", "tool_call"),
                        "tool": record.get("tool"),
                        "decision": record.get("decision"),
                        "principal": record.get("principal"),
                        "automation": record.get("automation"),
                        "record_error": "record could not be serialised in full",
                    },
                    sort_keys=True,
                    default=str,
                ),
            )
        except BaseException:
            # Last resort: a bare line is still evidence that something happened.
            with contextlib.suppress(BaseException):
                _log.error(
                    "AUDIT record emission failed for tool=%s", record.get("tool")
                )


def emit_tool_call(
    *,
    tool: str,
    arguments: dict,
    decision: str,
    principal: dict | None = None,
    reason: str = "",
    duration_ms: float | None = None,
    source: str = "",
    correlation_id: str | None = None,
) -> None:
    emit(
        build_record(
            tool=tool,
            arguments=arguments,
            decision=decision,
            principal=principal,
            reason=reason,
            duration_ms=duration_ms,
            source=source,
            correlation_id=correlation_id,
        )
    )


def classify_result(result: object, error_marker: str) -> tuple[str, str]:
    """Decide whether a handler's return value is a success or a refusal, and which.

    Lives here rather than in server.py because BOTH dispatchers need it and only one
    had it: the console collapsed every refusal to ``denied_handler``, so a blocked
    log-bundle exfiltration (``denied_egress``) or a Capella guardrail refusal
    performed through the console was recorded under the wrong label and a SIEM rule
    matching the documented vocabulary never fired for console-originated attacks.

    Keyed on the marker ``err()`` stamps, NOT on the presence of an "error" key.
    Key-presence misclassified successes: capella_env_ensure's phase results and
    capella_env_reap's per-item failures both carry a top-level "error" inside an
    otherwise successful response, so ordinary provisioning progress was audited as a
    denial. An audit trail that cries wolf on every poll is one an operator ignores.
    """
    try:
        first = result[0] if isinstance(result, list) and result else None
        text = getattr(first, "text", None)
        if not isinstance(text, str):
            return "allowed", ""
        payload = json.loads(text)
        if isinstance(payload, dict) and payload.get(error_marker) is True:
            reason = str(payload.get("error"))[:400]
            if payload.get("guardrail"):
                return "denied_guardrail", reason
            if "EgressDenied" in reason or "EGRESS_ALLOWED_HOSTS" in reason:
                return "denied_egress", reason
            return "denied_handler", reason
    except Exception:
        # Not JSON, or an unexpected shape. Treat as success rather than inventing a
        # denial; the handler returned normally.
        return "allowed", ""
    return "allowed", ""


def emit_auth_failure(*, reason: str, source: str = "") -> None:
    """Record a rejected credential.

    Authentication failures previously produced no log record at all, so somebody
    probing the endpoint left no trace. An audit trail that only contains
    successful calls cannot show an attempted intrusion.
    """
    emit(
        {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": "auth_failure",
            "decision": "denied_authentication",
            "reason": reason,
            "source": source,
        }
    )
