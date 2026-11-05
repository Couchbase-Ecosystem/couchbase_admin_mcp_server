"""Authentication and authorization helpers: OIDC token validation, the per-tool scope gate,
request-level principal resolution and console sessions. See auth/README.md.

Component: the package of the modules that decide who is calling and what they may do.
Spec: docs/spec.md S3 step 3 (scope), S5 (profiles), S6 (transports).
Main items: none here; see `oidc`, `request_auth`, `scope_gate` and `session`.
Callers: `auth/request_auth.py`, `gui/gui_server.py`, `server.py`; each imports modules from this package.
Callees: none
"""
