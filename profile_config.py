"""
profile_config.py — the two deployments this server actually has, made explicit.

WHY A PROFILE AND NOT EIGHT ENV VARS
====================================
There are two ways this runs, and they have genuinely different trust models:

  WORKSTATION   A developer's laptop. Docker container or a local process, driven
                by Claude Desktop (or similar) over stdio. There is no IdP and no
                token. A HUMAN IS PRESENT: the MCP client surfaces each tool call,
                and `confirm: true` is a real second look by a real person.
                Identity is the OS user. Nothing is network-exposed.

  ENTERPRISE    A human pushes code; a workflow-manager agent notices and
                instructs a child agent; the child performs an admin task and
                nobody says "OK" at the moment of action — correctly, because the
                authorization happened when the IdP issued that child's service
                principal a token carrying the automation scope. NO HUMAN IS
                PRESENT BY DESIGN. `confirm: true` means nothing here: the model
                supplies it. The controls that matter are the token's scopes, the
                allowlists, and the audit record.

Those two want opposite defaults, and previously they were expressed as ~10
independent environment variables with no coherence check between them. That is
how you end up with the combinations that caused the real findings: fail-closed
authorization that blocks a laptop, an unauthenticated console that is fine on
loopback and catastrophic in a data centre, `confirm: true` treated as human
approval in a context with no human.

So the deployment states which shape it is, once, and this module derives the
posture and refuses incoherent combinations at startup rather than at 3am.

  CB_ADMIN_PROFILE = workstation | enterprise      (no default — must be stated)

Explicit env vars always win over a profile default; the profile only supplies
values the operator did not set. What the profile will NOT do is let an
incoherent pair through silently — see validate().
"""

from __future__ import annotations

import getpass
import os
import socket
from dataclasses import dataclass, field

WORKSTATION = "workstation"
ENTERPRISE = "enterprise"
_VALID = (WORKSTATION, ENTERPRISE)


def _env(key: str, default: str = "") -> str:
    return (os.environ.get(key) or default).strip()


def _is_set(key: str) -> bool:
    return bool((os.environ.get(key) or "").strip())


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Profile:
    name: str
    #: Defaults the profile supplies for env vars the operator left unset.
    defaults: dict[str, str] = field(default_factory=dict)


#: Workstation: a human is present, nothing is exposed, friction should be low but
#: the destructive edges still guarded.
_WORKSTATION_DEFAULTS = {
    # A person is watching; the confirm gate is a genuine second look.
    "CB_ADMIN_READ_ONLY_MODE": "false",
    "CB_ADMIN_TRANSPORT": "stdio",
    "CB_ADMIN_HOST": "127.0.0.1",
    # No IdP on a laptop, so demanding auth would only fail closed pointlessly.
    "CB_ADMIN_HTTP_REQUIRE_AUTH": "false",
    # A dev cluster's backup/SMTP targets are usually local; still requires the
    # operator to name them, but the metadata denial is what actually matters here.
    "CB_ADMIN_EGRESS_ALLOW_ANY": "false",
    # The console is loopback-only and driven by the same person. Enforced at
    # request time by the peer-address check in gui_server, not just at startup.
    "CB_GUI_INSECURE_NO_AUTH": "1",
}

#: Enterprise: no human at the moment of action, so every control has to be
#: something a credential or a config can prove — not something a model asserts.
_ENTERPRISE_DEFAULTS = {
    # Writes are the point of the workflow, so read-only mode is off — but the
    # authorization comes from the token, and auth is mandatory.
    "CB_ADMIN_READ_ONLY_MODE": "false",
    "CB_ADMIN_HTTP_REQUIRE_AUTH": "true",
    # The console must be behind SSO; the insecure acknowledgement is unavailable.
    "OAUTH_ENABLED": "true",
    "CB_GUI_INSECURE_NO_AUTH": "0",
    # Egress fails closed: the operator states where the cluster may be pointed.
    "CB_ADMIN_EGRESS_ALLOW_ANY": "false",
    # Retention worth having when the log is the only record of an unattended act.
    "CB_ADMIN_LOG_SINKS": "stderr,file",
    # An absolute path: the previous relative default landed in whatever CWD the
    # process happened to have, which for the container entrypoint is the writable
    # layer and is lost on restart.
    "CB_ADMIN_AUDIT_FILE": "/var/log/couchbase-admin-mcp/audit.log",
}


def profile_name() -> str | None:
    raw = _env("CB_ADMIN_PROFILE").lower()
    return raw if raw in _VALID else None


def apply_profile() -> tuple[str | None, list[str]]:
    """Fill in unset env vars from the selected profile.

    Returns (profile_name, notes). Explicitly-set variables are never overwritten
    — an operator who has made a decision keeps it — so this only closes the gap
    between "didn't think about it" and a coherent posture.
    """
    name = profile_name()
    notes: list[str] = []
    if name is None:
        return None, [
            "CB_ADMIN_PROFILE is not set. Set it to 'workstation' (developer "
            "laptop, human present, stdio) or 'enterprise' (unattended "
            "workflow-agent chain, OAuth-authenticated) so the security posture is "
            "a single stated decision rather than the accidental sum of individual "
            "variables."
        ]

    defaults = _WORKSTATION_DEFAULTS if name == WORKSTATION else _ENTERPRISE_DEFAULTS
    for key, value in defaults.items():
        if not _is_set(key):
            os.environ[key] = value
            notes.append(f"{key}={value} (from profile {name})")
    return name, notes


#: Explicit acknowledgement that a non-loopback bind under the workstation profile
#: is the CONTAINER case: inside a container the process must bind 0.0.0.0, and the
#: isolation comes from publishing the port to 127.0.0.1 on the host
#: (`-p 127.0.0.1:8080:8080`), not from the bind address.
CONTAINER_BIND_ACK = "CB_ADMIN_WORKSTATION_CONTAINER_BIND"


def _is_loopback_host(host: str) -> bool:
    """Whether a bind address reaches only this machine.

    An empty host means "all interfaces" for every server in this codebase, so it is
    NOT loopback. A hostname that is not a literal address cannot be judged here
    without resolving it, and resolution at validation time is both unreliable and a
    DNS dependency in the startup path — so a non-literal is treated as exposed,
    which is the safe direction.
    """
    import ipaddress

    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_workstation_is_actually_local() -> list[str]:
    """Enforce the premise the workstation relaxations REST on.

    Everything the workstation profile loosens is justified by one claim: a human is
    sitting at the client and nothing is network-exposed. On that basis it disables
    HTTP authentication, permits the unauthenticated admin console, and — most
    significantly — treats `confirm: true` as a genuine second look by a person,
    which is what lets a hard-ceiling tool (bucket delete, cluster teardown) execute
    at all.

    None of that was checked. `CB_ADMIN_PROFILE=workstation` with
    CB_ADMIN_TRANSPORT=http and CB_ADMIN_HOST=0.0.0.0 produced an unauthenticated
    admin server, reachable from the network, on which every destructive tool could
    be driven to completion by any caller willing to send `confirm: true` — the
    single most privileged configuration in the codebase, reachable by setting the
    profile that sounds like the SAFE one.

    The realistic path to it is not an attacker choosing these values; it is an
    operator copying a dev compose file into a data centre. So it fails at startup.

    The container shape Chris described (Docker on a laptop, Claude Desktop talking
    to the container) genuinely needs a 0.0.0.0 bind, so it is permitted behind an
    explicit acknowledgement. Nobody sets an acknowledgement variable they have not
    read, which is exactly the property that makes the misdeploy loud and the
    supported case quiet.
    """
    errors: list[str] = []
    transport = _env("CB_ADMIN_TRANSPORT", "stdio").lower()
    if transport == "stdio":
        # No socket exists; the premise holds by construction.
        return errors

    host = _env("CB_ADMIN_HOST", "127.0.0.1")
    if _is_loopback_host(host) or _truthy(_env(CONTAINER_BIND_ACK)):
        return errors

    errors.append(
        f"CB_ADMIN_PROFILE=workstation with CB_ADMIN_TRANSPORT={transport} bound to "
        f"CB_ADMIN_HOST={host or '(empty = all interfaces)'}. The workstation "
        "profile's relaxations — HTTP auth off, unauthenticated console, and "
        "`confirm: true` accepted as human approval for hard-ceiling tools such as "
        "bucket and cluster deletion — are all justified by the claim that a human "
        "is at the client and the port is not reachable from the network. A "
        "non-loopback bind contradicts that, and makes this the most privileged "
        "configuration available: destructive admin, unauthenticated, over the "
        "network. Either bind CB_ADMIN_HOST=127.0.0.1, or switch to "
        "CB_ADMIN_PROFILE=enterprise (which requires OAuth and refuses ceiling tools "
        f"outright). If this is a container whose port is published to loopback on "
        f"the host (-p 127.0.0.1:PORT:PORT), set {CONTAINER_BIND_ACK}=1 to say so."
    )
    return errors


def validate(name: str | None) -> list[str]:
    """Refuse combinations that cannot be secure in the stated profile.

    Returned strings are fatal: the caller should refuse to start. These are the
    pairs that produced real findings, so they are checked rather than documented.
    """
    errors: list[str] = []

    # An unstated profile received ZERO validation, so a server could start with no
    # posture at all — the docstring says the profile "must be stated" and nothing
    # enforced it.
    if name is None:
        errors.append(
            "CB_ADMIN_PROFILE is not set. Set it to 'workstation' or 'enterprise'. "
            "Without it the security posture is the accidental sum of individual "
            "variables and none of the coherence checks below can run."
        )
        return errors

    # OAUTH_SKIP_VERIFY must be fatal in EVERY profile, not only enterprise. It
    # returns claims for an UNSIGNED token, and those claims can name the automation
    # scope — which skips the confirmation gate entirely. A workstation on loopback
    # is still a machine an attacker may already be on.
    if _truthy(_env("OAUTH_SKIP_VERIFY")):
        errors.append(
            "OAUTH_SKIP_VERIFY is enabled. JWT signature, issuer, audience and "
            "expiry all go unverified, so any token — including an unsigned one "
            "naming the automation scope — is accepted. Never set this."
        )

    if name == WORKSTATION:
        errors.extend(_validate_workstation_is_actually_local())

    if name != ENTERPRISE:
        return errors

    # The variable the whole enterprise model rests on was never checked. It is set
    # by the profile only when UNSET, so an explicit `false` (a debugging change, a
    # stale Helm value) passed validation and produced full unauthenticated admin on
    # a loopback bind, which the non-loopback guard does not cover.
    if not _truthy(_env("CB_ADMIN_HTTP_REQUIRE_AUTH")):
        errors.append(
            "CB_ADMIN_HTTP_REQUIRE_AUTH must be true in the enterprise profile. "
            "With it false, requests arrive with no token, no scope separation "
            "applies, the automation ceiling never engages, and the audit record "
            "carries no principal."
        )

    # The audit trail is the ONLY accountability in an unattended deployment, and by
    # default it goes to stderr, which a spawned server discards.
    if not _env("CB_ADMIN_AUDIT_FILE") and "file" not in _env("CB_ADMIN_LOG_SINKS"):
        errors.append(
            "No durable audit sink in the enterprise profile: set "
            "CB_ADMIN_AUDIT_FILE (recommended) or include 'file' in "
            "CB_ADMIN_LOG_SINKS. Unattended writes would otherwise leave no record "
            "that survives the process."
        )

    if _truthy(_env("OAUTH_SKIP_VERIFY")):
        errors.append(
            "OAUTH_SKIP_VERIFY is enabled in the enterprise profile. Signature, "
            "issuer, audience and expiry would all go unverified, so any token — "
            "including an unsigned one — would be accepted as an authorized "
            "service principal. This is the one control the unattended model rests "
            "on entirely."
        )

    if _truthy(_env("CB_GUI_INSECURE_NO_AUTH")):
        errors.append(
            "CB_GUI_INSECURE_NO_AUTH is enabled in the enterprise profile. The "
            "admin console would serve the full tool surface, including destructive "
            "tools, to any client that can reach the port."
        )

    if not _env("OAUTH_ISSUER"):
        errors.append(
            "OAUTH_ISSUER is unset in the enterprise profile. The unattended model "
            "authorizes a child agent by the scopes in its IdP-issued token; with "
            "no issuer there is no token to authorize, and no principal to record "
            "in the audit trail."
        )

    if not _env("OAUTH_AUDIENCE"):
        errors.append(
            "OAUTH_AUDIENCE is unset in the enterprise profile. Without it, any "
            "validly-signed token from the tenant is accepted — including one "
            "minted for an unrelated application."
        )

    if _truthy(_env("CB_ADMIN_EGRESS_ALLOW_ANY")):
        errors.append(
            "CB_ADMIN_EGRESS_ALLOW_ANY is enabled in the enterprise profile. The "
            "cluster could be pointed at any public host — including as the "
            "destination for a full diagnostic log bundle."
        )

    if _truthy(_env("CB_ADMIN_TLS_INSECURE")):
        errors.append(
            "CB_ADMIN_TLS_INSECURE is enabled in the enterprise profile. "
            "Certificate and hostname verification against the cluster would be "
            "disabled, so the administrator credentials this server sends on every "
            "call are MITM-able."
        )

    return errors


def local_identity() -> dict[str, str]:
    """Identity for the audit record when there is no token.

    On a workstation there is no IdP, but "who did what" must still be answerable,
    so the record carries the OS user and host. This is attribution, not
    authentication — it is trivially spoofable by whoever controls the process, and
    is recorded on that understanding.
    """
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    return {"os_user": user, "host": host}


def describe(name: str | None) -> str:
    if name == WORKSTATION:
        return (
            "workstation (human present at the client; stdio; loopback only; "
            "confirm:true is a real second look)"
        )
    if name == ENTERPRISE:
        return (
            "enterprise (unattended agent chain; OAuth-authenticated; authorization "
            "is the token's scopes, not a per-call confirmation)"
        )
    return "UNSET — no profile stated; posture is the accidental sum of individual variables"


# ── Import-time application ──────────────────────────────────────────────────
#
# Applied on import rather than from an explicit call in server.py. The profile
# supplies env vars, and `handlers.shared` snapshots CB_ADMIN_READ_ONLY_MODE at
# ITS import time — so the profile has to win that race. Doing it here means the
# ordinary "import profile_config before the handlers" ordering is sufficient,
# rather than requiring a call wedged between import statements (which is both
# fragile and unsortable by any formatter).
#
# The results are module attributes so server.py can report and enforce them.
PROFILE_NAME, PROFILE_NOTES = apply_profile()
PROFILE_ERRORS = validate(PROFILE_NAME)
