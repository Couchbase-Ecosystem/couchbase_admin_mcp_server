# auth/

Authentication and authorization for the HTTP transport and the operator console.
Read `docs/spec.md` S3 and S5 first, then `docs/THREADING_MODEL.md` (token validation runs on
worker threads).

| File | What it does |
| --- | --- |
| `oidc.py` | OIDC and OAuth 2.0 provider abstraction: discovery, token validation, JWKS handling, and the throttle that stops a caller from forcing a flood of key fetches |
| `request_auth.py` | Resolves the calling principal from the request inside the dispatch task |
| `scope_gate.py` | Per-tool scope enforcement. A token's scopes must satisfy the tool's read or write class |
| `session.py` | Server-side sessions for the console login (opaque session id in a Secure, HttpOnly cookie) |

The confirmation and hard-ceiling decision is **not** here. It is `authz.py` at the repository
root, because both the MCP server and the console use it.

Tests: `tests/test_token_validation.py`, `tests/test_scope_claim_shapes.py`,
`tests/test_http_authorization.py`, `tests/test_session.py` and the identity-provider lab
(`docs/OKTA_LAB.md`, `deploy/keycloak/`).
