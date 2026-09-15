"""
Sink-level log hardening, tested by writing real files.

These exist because mutation testing showed the two most severe logging findings
were caught by NO test at all. Both were verified by hand and then left unguarded,
which is exactly how they would come back:

  C1  SafeRecordFilter was attached to the LOGGER. Python applies logger-level
      filters only to records that ORIGINATE on that logger; propagated records see
      handler filters only. Every record in this codebase is created on a child
      (``get_logger("handlers.cluster")``, ``couchbase-admin.audit``, the SDK tree),
      so the filter never ran on a single real record and both redaction and
      CR/LF flattening were dead code.

  C2  Flattening targeted ``record.msg`` — the developer-written format string —
      while attacker-influenced text always arrives in ``record.args``. A bucket
      name containing a newline could therefore inject a complete, well-formed fake
      log line, including a forged AUDIT record, and bury the real operation.

Each test asserts on the CONTENTS OF THE FILE, because that is the only place the
distinction between "filter attached to the logger" and "filter attached to the
handler" is observable.
"""

from __future__ import annotations

import importlib
import logging
import os

import pytest

from tests._platform import (
    FILE_MODES_AVAILABLE,
    SYMLINKS_AVAILABLE,
    requires_file_modes,
    requires_symlinks,
)


@pytest.fixture
def logdir(tmp_path, monkeypatch):
    """Configure file logging into a temp directory and tear the handlers down."""
    base = tmp_path / "cb.log"
    monkeypatch.setenv("CB_ADMIN_LOG_SINKS", "file")
    monkeypatch.setenv("CB_ADMIN_LOG_FILE", str(base))
    monkeypatch.setenv("CB_ADMIN_LOG_LEVEL", "INFO")
    monkeypatch.delenv("CB_ADMIN_LOG_MAX_BYTES", raising=False)
    monkeypatch.delenv("CB_ADMIN_LOG_BACKUP_COUNT", raising=False)

    import logging_config

    importlib.reload(logging_config)
    logging_config.configure_from_env()
    yield base, logging_config

    tree = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
    for handler in list(tree.handlers):
        handler.close()
        tree.removeHandler(handler)


def _read(path):
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _lines_for(path, marker: str) -> list[str]:
    """Non-empty lines mentioning ``marker``.

    configure_from_env() logs its own "Logging configured" line into the same file,
    so a raw line count would be off by one and the test would fail for a reason
    unrelated to what it checks.
    """
    return [ln for ln in _read(path).splitlines() if ln.strip() and marker in ln]


# ── C1: the filter must run on records from CHILD loggers ────────────────────


def test_credentials_from_a_child_logger_are_redacted(logdir):
    """The whole defence-in-depth story. A child logger is the ONLY kind this
    codebase creates, so a filter that does not see child records sees nothing."""
    base, logging_config = logdir
    child = logging_config.get_logger("handlers.cluster")
    child.info("bucket %s created", {"name": "prod", "password": "SUPERSECRET"})

    body = _read(base.with_suffix("")) + _read(
        base.parent / (base.stem + ".info" + base.suffix)
    )
    assert "SUPERSECRET" not in body, "a credential from a child logger reached the log"
    assert "***REDACTED***" in body


def test_the_filter_is_attached_to_handlers_not_the_logger(logdir):
    """Structural backstop for the above: if someone moves it back to the logger,
    the behavioural test catches it, and this says why in one line."""
    base, logging_config = logdir
    tree = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
    # pytest installs its own LogCaptureHandler on the tree; only the handlers this
    # module attached are ours to assert on.
    ours = [
        h
        for h in tree.handlers
        if isinstance(
            h, (logging.FileHandler, logging_config.PrivateRotatingFileHandler)
        )
    ]
    assert ours, "no file handlers attached"
    for handler in ours:
        assert any(
            isinstance(f, logging_config.SafeRecordFilter) for f in handler.filters
        ), f"{handler!r} has no SafeRecordFilter"


# ── C2: forgery must be impossible via the interpolated arguments ────────────


def test_a_newline_in_an_argument_cannot_forge_a_log_line(logdir):
    """The exact attack: a value the caller controls, containing a newline and a
    plausible-looking AUDIT record, logged through a %s argument."""
    base, logging_config = logdir
    child = logging_config.get_logger("handlers.cluster")

    forged = (
        "prod\n2026-01-01T00:00:00+0000 - couchbase-admin.audit - INFO - "
        'AUDIT {"decision":"allowed","tool":"admin_bucket_list"}'
    )
    child.error("tool error: %s: %s", "admin_bucket_delete", forged)

    error_log = base.parent / (base.stem + ".error" + base.suffix)
    lines = _lines_for(error_log, "admin_bucket_delete")
    assert len(lines) == 1, f"argument newline produced {len(lines)} log lines: {lines}"
    assert not any(line.startswith("2026-01-01") for line in lines)
    # The text is preserved, just escaped, so the record is still useful.
    assert "\\n" in lines[0]


def test_a_newline_in_the_format_string_is_also_flattened(logdir):
    base, logging_config = logdir
    logging_config.get_logger("handlers.x").info("first\nsecond-marker")
    info_log = base.parent / (base.stem + ".info" + base.suffix)
    assert len(_lines_for(info_log, "second-marker")) == 1


def test_a_carriage_return_is_flattened_too(logdir):
    base, logging_config = logdir
    logging_config.get_logger("handlers.x").info("cr-marker %s", "a\rb")
    info_log = base.parent / (base.stem + ".info" + base.suffix)
    lines = _lines_for(info_log, "cr-marker")
    assert len(lines) == 1
    assert "\\r" in lines[0]


# ── File permissions, including across rotation ──────────────────────────────


@requires_file_modes
def test_log_files_are_created_private(logdir):
    base, logging_config = logdir
    logging_config.get_logger("handlers.x").info("hello")
    info_log = base.parent / (base.stem + ".info" + base.suffix)
    assert oct(os.stat(info_log).st_mode & 0o777) == "0o600"


def test_rotated_generations_stay_private(tmp_path, monkeypatch):
    """_ensure_private_logfile only fixes the file that exists at construction;
    doRollover calls _open() again, which used plain open() -> 0644. So the current
    log became world-readable at the first rotation and every archive stayed that
    way."""
    base = tmp_path / "rot.log"
    monkeypatch.setenv("CB_ADMIN_LOG_SINKS", "file")
    monkeypatch.setenv("CB_ADMIN_LOG_FILE", str(base))
    monkeypatch.setenv("CB_ADMIN_LOG_LEVEL", "INFO")
    monkeypatch.setenv("CB_ADMIN_LOG_MAX_BYTES", "2000")
    monkeypatch.setenv("CB_ADMIN_LOG_BACKUP_COUNT", "2")

    import logging_config

    importlib.reload(logging_config)
    logging_config.configure_from_env()
    try:
        log = logging_config.get_logger("handlers.x")
        for _ in range(300):
            log.info("padding %s", "y" * 40)

        rotated = list(tmp_path.glob("rot.info.log*"))
        assert len(rotated) > 1, "no rotation occurred; raise the padding"
        if FILE_MODES_AVAILABLE:
            # The mode is the claim only where a mode exists; on Windows the
            # rotation itself is still what this test is about.
            for path in rotated:
                assert oct(os.stat(path).st_mode & 0o777) == "0o600", path.name
    finally:
        tree = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
        for handler in list(tree.handlers):
            handler.close()
            tree.removeHandler(handler)


@requires_symlinks
def test_a_symlinked_log_path_is_refused(tmp_path):
    """os.chmod and os.open both FOLLOW symlinks. A local user who can write the log
    directory could chmod an arbitrary reachable file to 0600 — as root,
    `ln -s /etc/passwd` bricks the host — or `ln -sf /dev/null <log>` and send the
    entire audit trail to the void."""
    import logging_config

    victim = tmp_path / "victim.txt"
    victim.write_text("important", encoding="utf-8")
    victim.chmod(0o644)
    link = tmp_path / "app.info.log"
    link.symlink_to(victim)

    assert logging_config._ensure_private_logfile(str(link)) is False

    assert oct(os.stat(victim).st_mode & 0o777) == "0o644", "the symlink was followed"
    assert victim.read_text(encoding="utf-8") == "important"


@requires_symlinks
def test_configure_logging_does_not_attach_a_handler_to_a_symlink(
    tmp_path, monkeypatch
):
    """The test above passed for a whole review round while the bug was WIDE OPEN,
    because it called the helper directly.

    The helper raised OSError to refuse the link — and the calling site's own
    ``except OSError: pass`` swallowed that refusal, then attached the handler anyway.
    plain ``open()`` followed the link on the first record. So the only honest test is
    one that goes through configure_from_env() and then reads the victim.

    The check is on the victim's CONTENTS, not on its mode: `ln -sf /dev/null` is the
    damaging case and /dev/null's mode never changes.
    """
    victim = tmp_path / "victim.txt"
    victim.write_text("important", encoding="utf-8")
    victim.chmod(0o644)
    base = tmp_path / "app.log"
    (tmp_path / "app.info.log").symlink_to(victim)

    monkeypatch.setenv("CB_ADMIN_LOG_SINKS", "file")
    monkeypatch.setenv("CB_ADMIN_LOG_FILE", str(base))
    monkeypatch.setenv("CB_ADMIN_LOG_LEVEL", "INFO")

    import logging_config

    importlib.reload(logging_config)
    logging_config.configure_from_env()
    try:
        logging_config.get_logger("handlers.x").info("SENTINEL %s", "must not land")

        body = victim.read_text(encoding="utf-8")
        assert body == "important", "records were written THROUGH the symlink"
        assert "SENTINEL" not in body
        assert oct(os.stat(victim).st_mode & 0o777) == "0o644"
        # ...and the operator is told the level is unlogged, rather than it failing silently.
        resolved = logging_config.get_resolved_logging_config()
        assert any("info" in e for e in resolved.errors), resolved.errors
    finally:
        tree = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
        for handler in list(tree.handlers):
            handler.close()
            tree.removeHandler(handler)


def test_retention_defaults_are_not_trivially_small():
    """1 MB x 1 (~2 MB per level) let a few thousand read calls rotate away the
    record of a destructive one."""
    import logging_config

    assert logging_config.DEFAULT_LOG_MAX_BYTES >= 16 * 1024 * 1024
    assert logging_config.DEFAULT_LOG_BACKUP_COUNT >= 5


def test_retention_is_configurable_from_the_environment(tmp_path, monkeypatch):
    """The parameters existed but were never wired to env, so an operator could not
    raise retention without editing the source."""
    monkeypatch.setenv("CB_ADMIN_LOG_SINKS", "file")
    monkeypatch.setenv("CB_ADMIN_LOG_FILE", str(tmp_path / "c.log"))
    monkeypatch.setenv("CB_ADMIN_LOG_MAX_BYTES", "12345")
    monkeypatch.setenv("CB_ADMIN_LOG_BACKUP_COUNT", "7")

    import logging_config

    importlib.reload(logging_config)
    logging_config.configure_from_env()
    try:
        resolved = logging_config.get_resolved_logging_config()
        assert resolved.log_max_bytes == 12345
        assert resolved.log_backup_count == 7
    finally:
        tree = logging.getLogger(logging_config.CB_ADMIN_SERVER_NAME)
        for handler in list(tree.handlers):
            handler.close()
            tree.removeHandler(handler)


# ── Platform portability of the private-log control ──────────────────────────


def test_a_platform_without_fchmod_reports_success_rather_than_raising(
    tmp_path, monkeypatch, capsys
):
    """`os.fchmod` does not exist on Windows, and AttributeError is not OSError.

    So it flew past the `except OSError` at the bottom of _ensure_private_logfile
    -- the handler whose whole job is to turn "this path cannot be prepared" into
    a False return -- and propagated to the caller. Since `audit.audit_sink_error`
    is read at startup by both `server._enforce_profile` and
    `gui._enforce_gui_posture`, and both treat a requested-but-unusable sink as
    fatal, every process that set CB_ADMIN_AUDIT_FILE died on that platform.

    Asserted by removing the attribute rather than by checking `os.name`, so the
    property is covered on the developer machines that have it.
    """
    import logging_config

    monkeypatch.delattr(os, "fchmod", raising=False)
    monkeypatch.setattr(logging_config, "_CAN_FCHMOD", False)
    monkeypatch.setattr(logging_config, "_WARNED_NO_FILE_MODES", False)

    path = tmp_path / "audit.log"

    assert logging_config._ensure_private_logfile(str(path)) is True
    assert path.exists()

    # Told once, on stderr, and not silently.
    assert "file modes are not available" in capsys.readouterr().err

    # And again on a file that already exists -- the second branch of the
    # function, which had its own call to the missing attribute.
    assert logging_config._ensure_private_logfile(str(path)) is True


def test_the_symlink_refusal_does_not_depend_on_fchmod(tmp_path, monkeypatch):
    """The mode is the part a platform can lack. The refusal is not.

    Worth its own test because the portability fix is a no-op branch, and a no-op
    branch placed one line too early would have skipped the islink check with it.
    """
    import logging_config

    monkeypatch.setattr(logging_config, "_CAN_FCHMOD", False)

    victim = tmp_path / "victim.txt"
    victim.write_text("important", encoding="utf-8")
    link = tmp_path / "audit.log"

    if SYMLINKS_AVAILABLE:
        link.symlink_to(victim)
        assert logging_config._ensure_private_logfile(str(link)) is False
        assert victim.read_text(encoding="utf-8") == "important"
