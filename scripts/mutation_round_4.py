"""Mutation-check the round-4 fixes and the test-quality gaps independent
verification found (controls that could be deleted with all 504 tests green)."""

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
    # ── The HIGH bypass in my own JWKS fix ──────────────────────────────────
    (
        "JWKS: kid-less token skips the gate (the 101-fetch bypass)",
        "auth/oidc.py",
        """    if not _kid_is_known(jwks_client, kid):
        _refuse_if_recently_missed(jwks_uri, kid or "<no-kid>")""",
        """    if kid and not _kid_is_known(jwks_client, kid):
        _refuse_if_recently_missed(jwks_uri, kid)""",
        T3,
    ),
    (
        "JWKS: an empty kid is treated as known",
        "auth/oidc.py",
        """    if not kid:
        return False""",
        """    if not kid:
        return True""",
        T3,
    ),
    (
        "JWKS: forgetting one kid clears the whole budget",
        "auth/oidc.py",
        """        with _throttle_lock:
            _unknown_kids.pop(f"{jwks_uri}|{kid}", None)""",
        """        with _throttle_lock:
            _unknown_kids.clear()
            _refresh_times.clear()""",
        T3,
    ),
    (
        "JWKS: default refresh budget raised to a billion",
        "auth/oidc.py",
        """_REFRESH_BUDGET = _int_env("CB_ADMIN_JWKS_REFRESH_BUDGET", 10)""",
        """_REFRESH_BUDGET = _int_env("CB_ADMIN_JWKS_REFRESH_BUDGET", 1000000000)""",
        T3,
    ),
    # ── The MEDIUM scalar-root egress bypass ────────────────────────────────
    (
        "egress: scalar root returns silently again",
        "handlers/egress.py",
        """    if not isinstance(obj, (dict, list, tuple, set)):""",
        """    if False:""",
        T3,
    ),
    (
        "egress: root-level list items no longer forced",
        "handlers/egress.py",
        """                _check_leaf(enclosing, item, child, force=_depth == 0)""",
        """                _check_leaf(enclosing, item, child, force=False)""",
        T3,
    ),
    # ── Scope extraction across IdP claim shapes ────────────────────────────
    (
        "scope gate: stop reading Keycloak's nested realm roles",
        "auth/scope_gate.py",
        """    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        granted |= _flatten_grant(realm_access.get("roles"))""",
        """    realm_access = None""",
        "tests/test_scope_claim_shapes.py",
    ),
    (
        "scope gate: stop reading Keycloak's nested client roles",
        "auth/scope_gate.py",
        """    resource_access = claims.get("resource_access")
    if isinstance(resource_access, dict):
        for per_client in resource_access.values():
            if isinstance(per_client, dict):
                granted |= _flatten_grant(per_client.get("roles"))""",
        """    resource_access = None""",
        "tests/test_scope_claim_shapes.py",
    ),
    (
        "scope gate: scrape EVERY claim instead of the known grant claims",
        "auth/scope_gate.py",
        """    for claim in _SCOPE_CLAIMS:
        granted |= _flatten_grant(claims.get(claim))""",
        """    for claim in claims:
        granted |= _flatten_grant(claims.get(claim))""",
        "tests/test_scope_claim_shapes.py",
    ),
    # ── Audit sink is fatal at startup ──────────────────────────────────────
    (
        "audit sink: server no longer refuses to start",
        "server.py",
        """    sink_problem = audit.audit_sink_error()""",
        """    sink_problem = None""",
        T3,
    ),
    (
        "audit sink: GUI no longer refuses to start",
        "gui/gui_server.py",
        """    _sink_problem = _audit_mod.audit_sink_error()""",
        """    _sink_problem = None""",
        T3,
    ),
    # ── GUI logging / gating / CSRF breadth ─────────────────────────────────
    (
        "GUI: stop configuring logging (audit records silently dropped)",
        "gui/gui_server.py",
        """observes the logger CALL, which happens either way.
configure_from_env()""",
        """observes the logger CALL, which happens either way.
pass""",
        T3,
    ),
    (
        "GUI: drop deployment gating from the listing",
        "gui/gui_server.py",
        """        if not _tool_is_deployable(t.name):
            continue""",
        """        if False:
            continue""",
        T3,
    ),
    (
        "GUI: drop deployment gating from the execution path",
        "gui/gui_server.py",
        """    if not _tool_is_deployable(tool_name):""",
        """    if False:""",
        T3,
    ),
    (
        "GUI CSRF: narrow the guard to /api/call only",
        "gui/gui_server.py",
        """    if not request.path.startswith("/api/") and not request.path.startswith("/auth/"):
        return None""",
        """    if request.path != "/api/call":
        return None""",
        T3,
    ),
    # ── Required claims ─────────────────────────────────────────────────────
    (
        "oidc: drop the sub requirement",
        "auth/oidc.py",
        """REQUIRED_CLAIM_NAMES: tuple[str, ...] = ("exp", "iss", "sub")""",
        """REQUIRED_CLAIM_NAMES: tuple[str, ...] = ("exp", "iss")""",
        T3,
    ),
    # ── redact_text balance ─────────────────────────────────────────────────
    (
        "redact_text: revert to substring matching (masks diagnostics)",
        "handlers/shared.py",
        """    if any(fragment in bare for fragment in _SENSITIVE_KEY_PARTS):
        return not bare.endswith(_NON_SECRET_ENDINGS)""",
        """    if any(fragment in bare for fragment in _SENSITIVE_KEY_PARTS):
        return True""",
        T3,
    ),
    (
        "redact_text: treat every value as prose (secrets escape)",
        "handlers/shared.py",
        """    return len(inner.split()) >= 3""",
        """    return True""",
        T3,
    ),
    (
        "redact_text: drop the Bearer/Basic scheme handling",
        "handlers/shared.py",
        """        r"(?P<val>(?:Bearer|Basic|Digest)\\s+[A-Za-z0-9._~+/=-]+\"""",
        """        r"(?P<val>(?!x)x\"""",
        T3,
    ),
    # ── Packaging ───────────────────────────────────────────────────────────
    (
        "packaging: drop flask from the image",
        "Dockerfile",
        """    "flask>=3.0" \\\n""",
        "",
        "tests/test_packaging.py",
    ),
    (
        "packaging: drop gui from the wheel",
        "pyproject.toml",
        """packages = ["handlers", "auth", "gui"]""",
        """packages = ["handlers", "auth"]""",
        "tests/test_packaging.py",
    ),
    # ── GUI hardening details ───────────────────────────────────────────────
    (
        "GUI: leave exception text unredacted",
        "gui/gui_server.py",
        """        return jsonify({"ok": False, "error": shared.redact_text(str(exc))}), 200""",
        """        return jsonify({"ok": False, "error": str(exc)}), 200""",
        "tests/test_gui_csrf.py",
    ),
    (
        "GUI: stop covering /auth/logout",
        "gui/gui_server.py",
        """    if request.method in ("GET", "HEAD", "OPTIONS") and request.path != "/auth/logout":""",
        """    if request.method in ("GET", "HEAD", "OPTIONS"):""",
        "tests/test_gui_csrf.py",
    ),
]


def run(target: str, cwd: pathlib.Path) -> bool:
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
        # A TIMEOUT IS NOT A KILL. `return False` here means "tests failed", which this
        # harness reports as the mutation being CAUGHT -- with no assertion having failed
        # anywhere. So any mutation that merely made the target slow enough to exceed the
        # timeout was recorded as covered by a test. That is the harness telling the
        # comfortable story, in the one tool whose entire job is to say which controls
        # are untested. Raised so the run fails loudly instead.
        raise MutationTimeoutError(
            f"pytest timed out on {target}; this mutation is NOT proven caught. "
            "Re-run with a longer timeout before trusting the result."
        ) from None
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
