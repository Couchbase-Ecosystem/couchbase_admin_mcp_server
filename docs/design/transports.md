# The transports: stdio, streamable HTTP and TLS

**Source:** `server.py` (`_main_stdio`, `_main_http`, `_ScopeAuthMiddleware`, `_allowed_origins`,
`_allowed_hosts`, `_enforce_profile`), `auth/request_auth.py` (who is calling),
`tls_config.py` (transport encryption), `profile_config.py` (what each profile requires).
**Spec:** `docs/spec.md` S5 (profiles) and S6 (transports).
**Related:** `docs/design/authorization.md` (what is done with the caller once it is known).
`gui/gui_server.py` is a separate entry point with its own HTTP listener; it shares `authz.py`
and `tls_config.py` and is covered in the authorization note.

## What it decides

How a client reaches the server, how the caller is identified on that path, and whether the server
is allowed to start in the posture it was given.

- **stdio (the default).** No token. A person at the client started the process and sees the
  calls. This is the only transport on which "a human is present" can be true
  (`docs/design/authorization.md`).
- **Streamable HTTP** (`CB_ADMIN_TRANSPORT=http`). One session per client. The caller's token is
  checked at the edge and then resolved again, from the request itself, inside the task that
  dispatches the tool call.
- **Start-up.** `_enforce_profile` refuses to start, with exit code 2 and every problem listed,
  when the posture cannot be secure in the stated profile. It gathers four kinds of problem:
  incoherent profile settings (`profile_config.PROFILE_ERRORS`), an audit sink that was asked for
  and cannot be opened, a declared deployment mode that does not match the configuration
  (`deployment.declared_mode_error`), and transport encryption (`tls_config.validate`).
  `_main_http` adds two refusals of its own, below.

## Why it is built this way

**The caller is resolved inside the dispatch task, not in the middleware.** The first design
validated the token in middleware and stored the claims in a context variable. Context variables
are copied when a task is created, and the SDK's dispatch task is a sibling that was created when
the session started, before any request existed. So `check_scope()` always saw no claims and
returned "allowed", read and write separation did nothing on HTTP, and the automation scope was
never seen. All of it failed silently. `auth/request_auth.py` now reads the claims from the
request during dispatch and caches them. The middleware's token check is only an edge filter.

**One session per client.** The first HTTP transport used one shared transport with no session id,
so every client landed in the same session and nothing bound a tool call to its authenticated
request. `StreamableHTTPSessionManager` gives each client its own session and id.

**A bad token is a rejection, never a downgrade.** With `CB_ADMIN_HTTP_REQUIRE_AUTH` unset, a
forged or expired token used to be discarded and the request went on as anonymous, which meant a
bad credential switched enforcement off. Now a token that is presented and fails is always a 401.
A missing token is refused only when auth is required. `env_truthy` decides what counts as on, so
`on` does not mean something different at the edge than it does in the deeper checks. A single
local list of accepted spellings once let `=on` disable the edge 401 while `list_tools`, which has
no check of its own, served the whole admin surface unauthenticated.

**Token validation runs off the event loop.** `validate_token` makes a blocking key fetch on a
cache miss, and the library re-fetches for an unknown key id, which the caller chooses. Done inline,
one request a second with random key ids stalled the single event loop for up to 30 seconds each
and hammered the customer's identity provider from a trusted address. It runs in a thread.

**The token never reaches a log or a response.** Only the exception type is recorded. The 401 body
is built with `json.dumps`, so exception text containing quotes or a token fragment cannot break
the JSON or leak.

**A non-loopback bind needs authentication, and then needs encryption.** `_main_http` exits if the
host is not loopback and `CB_ADMIN_HTTP_REQUIRE_AUTH` is off. `tls_config.validate` exits on a
non-loopback bind with neither a certificate pair nor `CB_ADMIN_TLS_TERMINATED_EXTERNALLY`. The
acknowledgement is mandatory because "an ingress terminates TLS" and "nobody configured TLS" give a
byte-identical process, and the only difference is whether a human decided. Cleartext bearer
tokens defeat every other control at once, because every other control is downstream of "the
caller holds a legitimate token". Loopback is exempt. A half-configured certificate pair is fatal
even there. Mutual TLS is optional (`CB_ADMIN_TLS_CLIENT_CA_FILE`), so a stolen token alone is not
enough.

**Origin and Host are validated, and the operator states the names.** Without an allowlist, a web
page on the operator's machine can drive a loopback-bound server through DNS rebinding.
`_main_http` builds `TransportSecuritySettings` with protection on, the origins from
`CB_ADMIN_ALLOWED_ORIGINS`, and the hosts from the bind address, `localhost`, `127.0.0.1` and
`CB_ADMIN_ALLOWED_HOSTS` (each name is allowed with and without the port). Behind an ingress the
bind is `0.0.0.0` and the Host header is a service name, so the derived list alone answered 421 to
every request. Widening it silently would have discarded the protection, so the external names are
an explicit statement, and a wildcard bind with none prints why requests will fail.

**Both `/mcp` and `/mcp/` work.** Starlette answered a POST to `/mcp` with a 307 to `/mcp/`, which
MCP clients do not follow. With redirects off, `/mcp` was a 404. `_mcp_endpoint` normalizes the
path itself. This was verified against a real client handshake.

## What went wrong before

- **The scope model was inoperative over HTTP,** for the reason in the first paragraph above.
- **One shared session for every client,** and **a forged token treated as anonymous**, above.
- **Origin protection was silently off on every default deployment.** `allowed_origins` is a list
  with default `[]`, and passing `None` raised a validation error that a bare `except Exception`
  swallowed, leaving `security_settings` as `None` while telling the operator to upgrade `mcp`.
  The code now passes a list and catches only `ImportError`.
- **The HTTP server could be bound to a network interface with no authentication,** while the
  README and the Dockerfile told operators to set `CB_ADMIN_HOST=0.0.0.0`. The console already had
  the guard and the MCP server did not.
- **The HTTP transport served cleartext,** so the automation-scope token, the most privileged
  credential in the design, crossed the network in the open in the enterprise profile.

## Where it is tested

| Property | Test |
| --- | --- |
| A presented bad token is a 401 even when auth is not required; a missing one only when it is | `tests/test_transport_edge.py` (`test_an_invalid_token_is_rejected_even_when_auth_is_not_required`, `test_a_missing_token_is_refused_when_auth_is_required`) |
| Validation off the event loop; the token is never in the response; a hostile exception message gives valid JSON | same file |
| Banner warnings that a control is inert | same file (`test_an_issuer_without_enforcement_is_warned_about`, `test_skip_verify_is_announced_loudly`) |
| A real HTTP server: forged token, scopes, a session per client, a call with no session id, trailing slash | `tests/test_http_transport_live.py` |
| Scope and automation over HTTP | `tests/test_http_authorization.py` |
| Host allowlist: a configured name with and without its port, several names, a wildcard bind warning, a hostile host | `tests/test_server_dispatch.py` (`test_a_configured_hostname_is_allowed_with_and_without_its_port` and the four after it) |
| TLS: loopback exempt, exposed bind fatal, acknowledgement and certificate accepted, half pair fatal, mutual TLS, a real handshake | `tests/test_tls.py` |
| A declared deployment mode that does not match refuses to start | `tests/test_one_container_one_surface.py` |
| A workstation profile with a network bind refuses to start | `tests/test_round3_hardening.py::test_workstation_with_a_network_bind_refuses_to_start` |

## Before you change it

- Never carry a caller's identity in a context variable set outside the dispatch task. Resolve it
  from the request in `auth/request_auth.py`.
- Never turn a failed credential into an anonymous request. Use `env_truthy` for every on/off
  setting, not a local list.
- A new start-up refusal belongs in `_enforce_profile` so every problem is listed at once, and
  needs a test that starts the server in that posture.
- Do not widen the Host or Origin lists to make a deployment work. Ask the operator for the names.
- GAP: no test calls `_main_http` with a non-loopback bind and authentication off, and none
  asserts that `TransportSecuritySettings` is constructed with protection on (searched the tests
  on 2026-11-09). `tests/test_http_transport_live.py` starts a real server but does not check
  either. A keyword search of the mutation labels (`scripts/mutation_*.py --list`) finds one
  transport mutation, on the Host allowlist.
- Chris Ahrendt decides the defaults. Record a change in `docs/design-decisions.md`.
