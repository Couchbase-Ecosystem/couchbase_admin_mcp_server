"""Re-check the mutations that SURVIVED, plus the round-3 fixes.

Targeted test files and a short per-run timeout, so this finishes in minutes rather
than stalling on a full-suite run per mutation.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile


class MutationTimeoutError(RuntimeError):
    """A mutation run that neither passed nor failed. Never counted as caught."""


# The repository root, derived from this file's location rather than hard-coded, so the
# harness works from a checkout anywhere.
ROOT = pathlib.Path(__file__).resolve().parent.parent
T3 = "tests/test_round3_hardening.py"

MUTATIONS = [
    (
        "JWKS: drop the cached-key check (throttle legitimate tokens again)",
        "auth/oidc.py",
        """    if not _kid_is_known(jwks_client, kid):
        _refuse_if_recently_missed(jwks_uri, kid or "<no-kid>")""",
        """    if False:
        _refuse_if_recently_missed(jwks_uri, kid or "<no-kid>")""",
        T3,
    ),
    (
        "JWKS: remove the global refresh budget (amplification returns)",
        "auth/oidc.py",
        """        if not _refresh_budget_available(now):""",
        """        if False:""",
        T3,
    ),
    (
        "JWKS: drop the lock AND the snapshot (concurrency race returns)",
        "auth/oidc.py",
        """    with _throttle_lock:
        for stale in [
            k
            for k, seen in list(_unknown_kids.items())""",
        """    if True:
        for stale in [
            k
            for k, seen in _unknown_kids.items()""",
        T3,
    ),
    (
        # Anchor RETARGETED: this logic moved from server.py into
        # audit.classify_result so BOTH dispatch paths share it -- the console was
        # collapsing every refusal to `denied_handler`. When the code moved, this
        # mutation's anchor stopped matching and the harness reported ANCHOR-GONE,
        # which is the harness working: a control that silently stops being
        # mutation-tested is the failure it exists to catch.
        "classify: key presence instead of the err() marker",
        "audit.py",
        """        if isinstance(payload, dict) and payload.get(error_marker) is True:""",
        """        if isinstance(payload, dict) and "error" in payload:""",
        T3,
    ),
    (
        "correlation_id: drop the capture again",
        "server.py",
        """    _correlation = audit.sanitize_correlation(arguments.get(audit.CORRELATION_ARG))""",
        """    _correlation = None""",
        T3,
    ),
    (
        "correlation_id: stop passing it to the audit record",
        "server.py",
        """            correlation_id=_correlation,""",
        """            correlation_id=None,""",
        T3,
    ),
    (
        "workstation escape hatch: skip the locality check",
        "profile_config.py",
        """    if name == WORKSTATION:
        errors.extend(_validate_workstation_is_actually_local())""",
        """    if name == WORKSTATION:
        pass""",
        T3,
    ),
    (
        "ceiling: nest it under automation again",
        "authz.py",
        """    if tool_name in hard_ceiling_tools():
        if not human_present:""",
        """    if tool_name in hard_ceiling_tools() and has_automation_scope:
        if not human_present:""",
        T3,
    ),
    (
        "human_is_present: trust the profile label alone",
        "authz.py",
        '''    transport = (os.environ.get("CB_ADMIN_TRANSPORT") or "stdio").strip().lower()
    return transport == "stdio"''',
        """    return True""",
        T3,
    ),
    (
        "audit sink: make CB_ADMIN_AUDIT_FILE a phantom again",
        "audit.py",
        # Anchor updated: the call is now PRE-FORMATTED ("AUDIT " + line) rather than
        # %-formatted. logging_config's filter redacts record.args, and passing the
        # already-serialized, already-redacted JSON as an arg made it rewrite
        # `"auth": "none"` to unquoted ***REDACTED***, so the audit line stopped being
        # parseable JSON.
        """        sink = _audit_file_logger()
        if sink is not None:
            sink.info("AUDIT " + line)  # pre-formatted; see the note above""",
        """        pass""",
        T3,
    ),
    (
        "audit sink: degrade silently instead of refusing to start",
        "audit.py",
        """    if _audit_file_logger() is not None:
        return None""",
        """    if True:
        return None""",
        T3,
    ),
    (
        "err(): stop redacting the message",
        "handlers/shared.py",
        """    payload = {"error": redact_text(msg)}""",
        """    payload = {"error": msg}""",
        T3,
    ),
    (
        "mass assignment: silently ignore unknown keys instead of refusing",
        "handlers/indexes.py",
        """            refusal = refuse_undeclared(args, name, TOOLS, endpoint="/settings/indexes")
            if refusal is not None:
                return refusal""",
        """            refusal = None""",
        # The handler-level test lives with the other guard tests, not in T3.
        "tests/test_egress_and_statement_guards.py",
    ),
    (
        # Anchor RETARGETED for the same reason: `_with_correlation_id` became
        # `_with_control_fields`, which now delegates to
        # mcp_compat.with_control_fields so the console advertises the same fields as
        # the transport (it was serving raw schemas with neither dry_run nor
        # correlation_id on them).
        "correlation_id: stop declaring it on tool schemas",
        "server.py",
        """        filtered.append(_with_control_fields(t))""",
        """        filtered.append(t)""",
        T3,
    ),
    (
        "composite: let a disabled primitive through",
        "handlers/capella/environment.py",
        """    if op_name in DISABLED_TOOLS:""",
        """    if False:""",
        T3,
    ),
    (
        "composite: let a ceiling primitive through unattended",
        "handlers/capella/environment.py",
        """    if op_name in authz.hard_ceiling_tools() and not authz.human_is_present():""",
        """    if False:""",
        T3,
    ),
    (
        "GUI CSRF: stop validating Origin",
        "gui/gui_server.py",
        """    if origin and not _origin_is_allowed(origin):""",
        """    if False:""",
        "tests/test_gui_csrf.py",
    ),
    (
        "GUI CSRF: stop requiring application/json",
        "gui/gui_server.py",
        """        if content_type != "application/json":""",
        """        if False:""",
        "tests/test_gui_csrf.py",
    ),
    (
        "GUI: parse any body AND drop the content-type check",
        "gui/gui_server.py",
        """        if content_type != "application/json":
            return (
                jsonify(""",
        """        if False:
            return (
                jsonify(""",
        "tests/test_gui_csrf.py",
    ),
    (
        "GUI: trust a forwarding header again",
        "gui/gui_server.py",
        """        "X-Forwarded-For",""",
        """        "X-Ignored-Header-Name",""",
        "tests/test_gui_csrf.py",
    ),
    (
        "egress: drop the list-of-scalars handling (M7 bypass returns)",
        "handlers/egress.py",
        """                _check_leaf(enclosing, item, child, force=_depth == 0)""",
        """                pass""",
        "tests/test_egress_and_statement_guards.py",
    ),
    (
        "egress: remove the leaf budget",
        "handlers/egress.py",
        """        _budget[0] -= 1
        if _budget[0] < 0:""",
        """        _budget[0] -= 1
        if False:""",
        "tests/test_egress_and_statement_guards.py",
    ),
    (
        "packaging: drop audit.py from the Dockerfile",
        "Dockerfile",
        """COPY --chown=mcp:mcp audit.py /app/audit.py\n""",
        "",
        "tests/test_packaging.py",
    ),
    (
        "packaging: drop authz.py from the wheel",
        "pyproject.toml",
        """"authz.py" = "authz.py"\n""",
        "",
        "tests/test_packaging.py",
    ),
    (
        "list_tools: stop requiring a token",
        "server.py",
        """    if _auth_required_for_listing():""",
        """    if False:""",
        "tests/test_http_authorization.py",
    ),
]


def run(target: str, cwd: pathlib.Path) -> bool:
    """True if the suite PASSES, i.e. the mutation was NOT caught."""
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-x",
                "-q",
                "-p",
                "no:randomly",
                "-m",
                "not live",
                *target.split(),
            ],
            check=False,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=150,
        )
    except subprocess.TimeoutExpired:
        # A TIMEOUT IS NOT A KILL. This returned "caught", so any mutation that made the
        # target slow enough to exceed the timeout was reported as covered by a test --
        # with no assertion having failed anywhere. That is the harness telling the
        # comfortable story rather than the true one, in the one tool whose entire job is
        # to say which controls are untested.
        print(
            "    INDETERMINATE: the run timed out, so this mutation is NOT proven "
            "caught. Re-run with a longer timeout before trusting this result.",
            file=sys.stderr,
        )
        raise MutationTimeoutError("the pytest run timed out") from None
    return result.returncode == 0


def main() -> int:
    survivors = []
    for label, relpath, old, new, target in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp) / "cb"
            shutil.copytree(
                ROOT,
                work,
                ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".git"),
            )
            path = work / relpath
            text = path.read_text()
            if old not in text:
                print(f"  ANCHOR-GONE  {label} ({relpath})", flush=True)
                survivors.append((label, "anchor not found"))
                continue
            path.write_text(text.replace(old, new, 1))
            if run(target, work):
                print(f"  SURVIVED     {label}", flush=True)
                survivors.append((label, "no test caught it"))
            else:
                print(f"  caught       {label}", flush=True)

    print(flush=True)
    if survivors:
        print(f"{len(survivors)} of {len(MUTATIONS)} NOT CAUGHT:")
        for label, why in survivors:
            print(f"  - {label}  [{why}]")
        return 1
    print(f"All {len(MUTATIONS)} mutations caught.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
