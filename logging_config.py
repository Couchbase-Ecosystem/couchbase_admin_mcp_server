"""Logging configuration for the Couchbase Admin MCP Server.

Mirrors the logging model of the official couchbase/mcp-server-couchbase so an
operator (or Couchbase support) gets the same shape of diagnostics from this
server as from the product one:

  * All modules log under the ``CB_ADMIN_SERVER_NAME`` ("couchbase-admin")
    logger hierarchy — e.g. ``couchbase-admin.handlers.cluster``.
  * Sinks are configurable via ``CB_ADMIN_LOG_SINKS`` (stderr and/or file).
  * The file sink writes **one rotating file per level** (info/warning/error/
    debug) so support can ask a customer for just the error log.
  * A queryable snapshot (:class:`ResolvedLoggingConfig`) lets an MCP status
    tool report exactly what logging is active.

This server talks to the cluster mostly over REST (``admin_request``), so
unlike the product server there is no unconditional Couchbase SDK log routing;
the SDK is only pulled in by the index-advisor and diagnostics handlers. When
the SDK is present we still route its logs into this tree so those handlers'
SDK-level records land in the same files.
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import Any

# ── Configuration constants (mirrors the product server's constants.py) ───────

CB_ADMIN_SERVER_NAME = "couchbase-admin"

DEFAULT_LOG_LEVEL = "INFO"
# 32 MB x 10 per level. The previous 1 MB x 1 (~2 MB total per level) meant a few
# thousand noisy read calls could rotate the record of a destructive one out of
# existence — trivial anti-forensics, and reachable by accident on a busy cluster.
# Both are now overridable via CB_ADMIN_LOG_MAX_BYTES / CB_ADMIN_LOG_BACKUP_COUNT;
# forward to a SIEM for anything that must be retained beyond that.
DEFAULT_LOG_MAX_BYTES = 32 * 1024 * 1024
DEFAULT_LOG_BACKUP_COUNT = 10
ALLOWED_LOG_LEVELS = ("OFF", "DEBUG", "INFO", "WARNING", "ERROR")
DEFAULT_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
# ISO 8601 local time with UTC offset, e.g. 2026-07-28T18:08:49+0000.
DEFAULT_LOG_DATEFMT = "%Y-%m-%dT%H:%M:%S%z"
ALLOWED_LOG_SINKS = ("stderr", "file")
DEFAULT_LOG_SINKS = "stderr"
DEFAULT_LOG_FILE = "cb_admin_mcp.log"

# One rotating file per level so operators can isolate, e.g., just the errors.
_PER_LEVEL_FILE_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

# Sentinel above CRITICAL used to disable the logger when level=OFF.
LEVEL_OFF = logging.CRITICAL + 1


@dataclass(frozen=True)
class ResolvedLoggingConfig:
    """Snapshot of the active logging configuration after configure_logging()."""

    level: str
    sinks: tuple[str, ...]
    log_files: dict[str, str] | None
    log_max_bytes: int
    log_backup_count: int
    #: Sink-level problems an operator must see: a level whose handler could NOT be
    #: attached is a level that is NOT being persisted, and silence there is exactly
    #: how a missing audit trail goes unnoticed.
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "sinks": list(self.sinks),
            "log_files": dict(self.log_files) if self.log_files else None,
            "max_bytes": self.log_max_bytes,
            "errors": list(self.errors),
        }


_resolved_config: ResolvedLoggingConfig | None = None


def get_resolved_logging_config() -> ResolvedLoggingConfig | None:
    """Return the snapshot recorded by the last configure_logging() call."""
    return _resolved_config


def _exact_level_filter(levelno: int):
    """Return a filter that keeps only records whose level is exactly ``levelno``."""

    def _filter(record: logging.LogRecord) -> bool:
        return record.levelno == levelno

    return _filter


class SafeRecordFilter(logging.Filter):
    """Sink-level scrubbing: credential masking and log-forgery prevention.

    MUST BE ATTACHED TO HANDLERS, NOT TO A LOGGER. Python applies logger-level
    filters only to records that ORIGINATE on that logger; propagation to ancestors
    runs ``callHandlers``, which consults handler filters only. Every record here is
    created on a child (``get_logger()`` -> ``couchbase-admin.handlers.cluster``,
    ``couchbase-admin.audit``, the SDK tree), so attaching this to the parent
    ``couchbase-admin`` logger meant it never ran on a single real record and both
    transformations below were dead code.

    Two transformations:

      REDACT   ``record.args`` pass through ``handlers.shared.redact``, so a
               credential in a %-format argument is masked even where the call site
               forgot — SDK DEBUG records (connection strings, auth negotiation),
               REST exception bodies, any handler that omitted redact().

      FLATTEN  CR/LF are escaped in the FORMATTED message. Escaping ``record.msg``
               was useless: that is the developer-written format string, while
               attacker-influenced text always arrives in ``record.args``. A bucket
               name or a REST error body containing a newline could therefore inject
               a complete, well-formed fake log line — including a forged AUDIT
               record — and bury the real operation.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            from handlers.shared import redact as _redact

            if record.args:
                if isinstance(record.args, dict):
                    record.args = _redact(record.args)
                elif isinstance(record.args, tuple):
                    record.args = tuple(_redact(a) for a in record.args)
        except Exception:
            # Logging must never break a request. An unscrubbed record is still
            # better emitted than dropped, and the flattening below still applies.
            pass

        try:
            # Interpolate here, then flatten, then blank the args so the formatter
            # does not re-interpolate. This is the only point at which the
            # caller-supplied text and the template are combined.
            message = record.getMessage()
        except Exception:
            return True
        if "\r" in message or "\n" in message:
            record.msg = message.replace("\r", "\\r").replace("\n", "\\n")
            record.args = ()
        return True


class PrivateRotatingFileHandler(RotatingFileHandler):
    """RotatingFileHandler that keeps every generation 0600.

    ``_ensure_private_logfile`` only fixes the file that exists at construction.
    ``doRollover()`` calls ``_open()`` again, which uses plain ``open()`` ->
    ``0666 & ~umask`` -> typically 0644. So the current log became world-readable at
    the first rotation and every archived generation stayed that way permanently —
    the 0600 guarantee held only until the first rollover.
    """

    def _open(self):
        previous = os.umask(0o077)
        try:
            return super()._open()
        finally:
            os.umask(previous)

    # `_opener` was DELETED, not fixed.
    #
    # It existed behind `# pragma: no cover - used via delay/rotation`, and that stated
    # reason was false: logging.FileHandler._open never passes an `opener`, and the only
    # occurrence of the name in the whole repo was its own definition. Mutating its
    # 0o600 to 0o644 survived the suite -- because the mode is actually delivered by the
    # umask(0o077) in _open above, whose equivalent mutation IS killed. Dead code
    # carrying a security-looking constant is worse than no code: it reads as the
    # control and is not.


def _ensure_private_logfile(path: str) -> bool:
    """Guarantee a log file is 0600 before anything is written to it.

    RotatingFileHandler creates files with ``0666 & ~umask`` — typically 0644 — so
    cluster topology, usernames and anything that slipped past redaction were
    readable by every local user on a shared host or in a container with more than
    one account.

    Implemented by pre-creating the file with the right mode rather than via
    FileHandler's ``opener``: logging.FileHandler does not accept an ``opener``
    argument (unlike ``open()``), so passing one raises TypeError on 3.10-3.13.
    Creating it first leaves no window in which the file exists world-readable;
    the chmod covers a file that already existed from an earlier run.
    """
    try:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)

        # Refuse to touch a symlink. os.chmod and os.open both FOLLOW links, so a
        # local user who can write the log directory could previously (a) chmod an
        # arbitrary reachable file to 0600 — as root, `ln -s /etc/passwd` bricks the
        # host — or (b) `ln -sf /dev/null <log>` and send the entire audit trail to
        # the void, silently, because the OSError handler swallowed everything.
        if os.path.islink(path):
            print(
                f"[couchbase-admin-mcp] REFUSING to log to {path!r}: it is a "
                "symlink. Following it would allow an arbitrary file to be "
                "modified, or the audit trail to be discarded.",
                file=sys.stderr,
                flush=True,
            )
            return False

        if not os.path.exists(path):
            # O_NOFOLLOW closes the race between the islink check and the open.
            flags = (
                os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            fd = os.open(path, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        else:
            info = os.lstat(path)
            if info.st_nlink > 1:
                print(
                    f"[couchbase-admin-mcp] WARNING: {path!r} has "
                    f"{info.st_nlink} hard links; another name for this file will "
                    "also receive the log.",
                    file=sys.stderr,
                    flush=True,
                )
            # fchmod on an fd we opened without following links, not chmod on a path.
            fd = os.open(path, os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
        return True
    except OSError:
        # A path we cannot prepare is reported to the caller, which SKIPS the
        # handler. Previously this swallowed the symlink refusal raised above, so
        # the warning printed and the handler was attached anyway — plain open()
        # then followed the link and the entire audit trail could be routed to
        # /dev/null by any user who could write the log directory.
        return False


def _int_env_value(key: str, default: int) -> int:
    """Read a positive integer from the environment, falling back on anything odd.

    Module scope so the audit sink in audit.py can share it; it was nested inside
    configure_from_env and therefore unavailable to any other caller.
    """
    raw = (os.environ.get(key) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _per_level_path(base_path: str, level_name: str) -> str:
    """``cb_admin_mcp.log`` + ``INFO`` -> ``cb_admin_mcp.info.log``."""
    root, ext = os.path.splitext(base_path)
    return f"{root}.{level_name.lower()}{ext}"


def _attach_per_level_file_handlers(
    logger: logging.Logger,
    formatter: logging.Formatter,
    log_file: str,
    log_max_bytes: int,
    log_backup_count: int,
) -> tuple[dict[str, str], list[str]]:
    """Attach one rotating file handler per active level. Returns (attached, errors)."""
    errors: list[str] = []
    if not log_file:
        errors.append(
            "File logging enabled but no CB_ADMIN_LOG_FILE configured; "
            f"falling back to default '{DEFAULT_LOG_FILE}'."
        )
        log_file = DEFAULT_LOG_FILE

    attached: dict[str, str] = {}
    for lvl_name in _PER_LEVEL_FILE_LEVELS:
        lvl_no = logging.getLevelName(lvl_name)
        # INFO is attached REGARDLESS of the configured level, because audit records
        # are emitted at INFO and audit.py pins that logger's level so a raised
        # verbosity cannot suppress them. Skipping the handler here defeated that from
        # the other end: with CB_ADMIN_LOG_LEVEL=WARNING and `file` as the only sink,
        # emit_tool_call for a bucket delete landed in no file at all. The audit trail
        # must not be a function of how chatty the operator wants the server to be.
        if lvl_no < logger.level and lvl_name != "INFO":
            continue
        path = _per_level_path(log_file, lvl_name)
        if not _ensure_private_logfile(path):
            errors.append(
                f"Refusing to attach a {lvl_name} handler to '{path}': the path "
                "could not be prepared safely (symlink, or unwritable). Records for "
                "this level are NOT being persisted."
            )
            continue
        try:
            handler = PrivateRotatingFileHandler(
                path,
                maxBytes=log_max_bytes,
                backupCount=log_backup_count,
                encoding="utf-8",
            )
        except OSError as e:
            errors.append(f"Cannot write {lvl_name} log file '{path}': {e}")
            continue
        handler.setFormatter(formatter)
        # Handler-level, not logger-level: see SafeRecordFilter's docstring.
        handler.addFilter(SafeRecordFilter())
        if lvl_name == "ERROR":
            # ERROR file is the catch-all for ERROR and above (incl. CRITICAL).
            handler.setLevel(logging.ERROR)
        else:
            handler.addFilter(_exact_level_filter(lvl_no))
        logger.addHandler(handler)
        attached[lvl_name] = path
    return attached, errors


def parse_log_level(value: str) -> tuple[str, str | None]:
    """Parse a log level, falling back to the default for invalid input."""
    token = value.strip().upper()
    if token in ALLOWED_LOG_LEVELS:
        return token, None
    return DEFAULT_LOG_LEVEL, value


def parse_log_sinks(value: str) -> tuple[set[str], list[str]]:
    """Parse a comma-separated CB_ADMIN_LOG_SINKS value."""
    sinks: set[str] = set()
    invalid: list[str] = []
    for part in value.split(","):
        token = part.strip()
        if token:
            normalised = token.lower()
            if normalised in ALLOWED_LOG_SINKS:
                sinks.add(normalised)
            else:
                invalid.append(token)
    if not sinks:
        sinks.add(DEFAULT_LOG_SINKS)
    return sinks, invalid


def _route_sdk_logs(level: int) -> None:
    """Route Couchbase SDK logs into this tree, if the SDK is importable.

    Only the index-advisor and diagnostics handlers use the SDK, so it may not
    even be installed in a minimal deployment. Import defensively.
    """
    try:
        import couchbase

        couchbase.configure_logging(CB_ADMIN_SERVER_NAME, level)
    except Exception:
        pass


def configure_logging(
    level: str,
    sinks: set[str],
    log_file: str,
    log_max_bytes: int = DEFAULT_LOG_MAX_BYTES,
    log_backup_count: int = DEFAULT_LOG_BACKUP_COUNT,
    invalid_sinks: list[str] | None = None,
    invalid_level: str | None = None,
) -> None:
    """Configure the root admin-MCP logger (and SDK logs when the SDK is present).

    ``sinks`` is authoritative: ``"stderr"`` attaches a stderr handler; ``"file"``
    attaches one rotating file handler per active level, derived from ``log_file``
    by inserting the level name. ``level="OFF"`` suppresses all output.
    """
    global _resolved_config

    level_name = level.upper()
    if level_name not in ALLOWED_LOG_LEVELS:
        invalid_level = level
        level_name = DEFAULT_LOG_LEVEL.upper()

    logger = logging.getLogger(CB_ADMIN_SERVER_NAME)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()  # release FDs on reconfigure (tests, reloads).
    logger.propagate = False

    if level_name == "OFF":
        logger.setLevel(LEVEL_OFF)
        _route_sdk_logs(LEVEL_OFF)
        _resolved_config = ResolvedLoggingConfig(
            level=level_name,
            sinks=(),
            log_files=None,
            log_max_bytes=log_max_bytes,
            log_backup_count=log_backup_count,
        )
        return

    logger.setLevel(level_name)
    formatter = logging.Formatter(DEFAULT_LOG_FORMAT, datefmt=DEFAULT_LOG_DATEFMT)

    effective_sinks = set(sinks)
    file_sink_active = "file" in effective_sinks

    if "stderr" in effective_sinks:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setFormatter(formatter)
        stderr_handler.addFilter(SafeRecordFilter())
        logger.addHandler(stderr_handler)

    file_warnings: list[str] = []
    file_errors: list[str] = []
    attached_files: dict[str, str] = {}

    if file_sink_active:
        attached_files, file_errors = _attach_per_level_file_handlers(
            logger, formatter, log_file, log_max_bytes, log_backup_count
        )
        no_error_handler = "ERROR" not in attached_files
        if file_errors and no_error_handler and "stderr" not in effective_sinks:
            fallback_handler = logging.StreamHandler(sys.stderr)
            fallback_handler.setFormatter(formatter)
            fallback_handler.addFilter(SafeRecordFilter())
            logger.addHandler(fallback_handler)
    else:
        file_warnings.append(
            "WARNING: File logging is disabled. Log files for support are not "
            "being generated."
        )

    _route_sdk_logs(logger.level)

    if invalid_level:
        logger.error(
            "Ignored invalid log level %r in CB_ADMIN_LOG_LEVEL; allowed values "
            "are %s. Continuing with level=%s.",
            invalid_level,
            list(ALLOWED_LOG_LEVELS),
            level_name,
        )
    if invalid_sinks:
        logger.error(
            "Ignored invalid log sink value(s) %s in CB_ADMIN_LOG_SINKS; allowed "
            "values are %s. Continuing with sinks=%s.",
            invalid_sinks,
            list(ALLOWED_LOG_SINKS),
            ",".join(sorted(effective_sinks)),
        )
    for message in file_errors:
        logger.error(message)
    for message in file_warnings:
        logger.warning(message)

    logger.info(
        "Logging configured: level=%s, sinks=%s, log_files=%s, max_bytes=%d",
        level_name,
        ",".join(sorted(effective_sinks)),
        attached_files if file_sink_active else "-",
        log_max_bytes,
    )

    _resolved_config = ResolvedLoggingConfig(
        level=level_name,
        sinks=tuple(sorted(effective_sinks)),
        log_files=dict(attached_files)
        if (file_sink_active and attached_files)
        else None,
        log_max_bytes=log_max_bytes,
        log_backup_count=log_backup_count,
        errors=tuple(file_errors),
    )


def configure_from_env() -> None:
    """Convenience entrypoint — read CB_ADMIN_LOG_* env vars and configure.

    Called once by the server entrypoint. Kept separate from configure_logging
    so tests can drive the latter directly with explicit arguments.
    """
    level, invalid_level = parse_log_level(
        os.environ.get("CB_ADMIN_LOG_LEVEL", DEFAULT_LOG_LEVEL)
    )
    sinks, invalid_sinks = parse_log_sinks(
        os.environ.get("CB_ADMIN_LOG_SINKS", DEFAULT_LOG_SINKS)
    )
    log_file = os.environ.get("CB_ADMIN_LOG_FILE", DEFAULT_LOG_FILE)

    # Previously hard-coded: the parameters existed but were never wired to env,
    # so an operator could not raise retention without editing the source.
    log_max_bytes = _int_env_value("CB_ADMIN_LOG_MAX_BYTES", DEFAULT_LOG_MAX_BYTES)
    log_backup_count = _int_env_value(
        "CB_ADMIN_LOG_BACKUP_COUNT", DEFAULT_LOG_BACKUP_COUNT
    )
    configure_logging(
        level=level,
        sinks=sinks,
        log_file=log_file,
        log_max_bytes=log_max_bytes,
        log_backup_count=log_backup_count,
        invalid_sinks=invalid_sinks,
        invalid_level=invalid_level,
    )


def get_logger(module: str) -> logging.Logger:
    """Return a child logger under the admin-MCP tree.

    ``get_logger("handlers.cluster")`` -> ``couchbase-admin.handlers.cluster``.
    """
    return logging.getLogger(f"{CB_ADMIN_SERVER_NAME}.{module}")
