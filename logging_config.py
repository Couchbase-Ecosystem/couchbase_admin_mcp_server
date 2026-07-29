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
DEFAULT_LOG_MAX_BYTES = 1 * 1024 * 1024  # 1 MB
DEFAULT_LOG_BACKUP_COUNT = 1
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "sinks": list(self.sinks),
            "log_files": dict(self.log_files) if self.log_files else None,
            "max_bytes": self.log_max_bytes,
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
        if lvl_no < logger.level:
            continue
        path = _per_level_path(log_file, lvl_name)
        try:
            handler = RotatingFileHandler(
                path,
                maxBytes=log_max_bytes,
                backupCount=log_backup_count,
                encoding="utf-8",
            )
        except OSError as e:
            errors.append(f"Cannot write {lvl_name} log file '{path}': {e}")
            continue
        handler.setFormatter(formatter)
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
        log_files=dict(attached_files) if (file_sink_active and attached_files) else None,
        log_max_bytes=log_max_bytes,
        log_backup_count=log_backup_count,
    )


def configure_from_env() -> None:
    """Convenience entrypoint — read CB_ADMIN_LOG_* env vars and configure.

    Called once by the server entrypoint. Kept separate from configure_logging
    so tests can drive the latter directly with explicit arguments.
    """
    level, invalid_level = parse_log_level(os.environ.get("CB_ADMIN_LOG_LEVEL", DEFAULT_LOG_LEVEL))
    sinks, invalid_sinks = parse_log_sinks(
        os.environ.get("CB_ADMIN_LOG_SINKS", DEFAULT_LOG_SINKS)
    )
    log_file = os.environ.get("CB_ADMIN_LOG_FILE", DEFAULT_LOG_FILE)
    configure_logging(
        level=level,
        sinks=sinks,
        log_file=log_file,
        invalid_sinks=invalid_sinks,
        invalid_level=invalid_level,
    )


def get_logger(module: str) -> logging.Logger:
    """Return a child logger under the admin-MCP tree.

    ``get_logger("handlers.cluster")`` -> ``couchbase-admin.handlers.cluster``.
    """
    return logging.getLogger(f"{CB_ADMIN_SERVER_NAME}.{module}")
