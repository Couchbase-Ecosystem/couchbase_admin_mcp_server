# Security & Bug Scan — Couchbase Admin MCP Server

**Target:** cb-admin-mcp (this repo) — the admin server split from MCP-Couchbase
**Scope:** all of `handlers/`, `auth/`, `server.py`, `logging_config.py`
**Date:** 2026-07-28
**Method:** ruff + full bandit (`S`) ruleset; manual review of query construction,
TLS, auth, credential handling, and every silent exception; runtime verification
of the injection-relevant paths.

---

## Verdict

**No vulnerabilities.** Full bandit ruleset raised 34 findings; every one is a
false positive or an intentional, now-logged, graceful-degradation path. Fixed
the handful worth hardening. The code is clean.

The headline: the SQL++ identifier injection that exists in the **official**
server (`get_schema_for_collection`, unescaped `INFER \`{name}\``) does **not**
exist here — this server's equivalent path escapes identifiers correctly.

---

## Findings and dispositions

### S608 ×2 — "possible SQL injection" — FALSE POSITIVE (verified)

`handlers/diagnostics.py:416` and `handlers/eight_x.py:477` build SQL++ with an
interpolated `keyspace`. Both route every identifier through `_safe_ident`:

```python
def _safe_ident(s: str) -> str:
    return "`" + (s or "").replace("`", "``") + "`"
```

That is exactly the backtick-doubling escape the official server is **missing**.
Verified at runtime: a `collection_name` of `` x`; DROP … `` becomes
`` `x``; DROP …` `` — the injected backtick is doubled and stays *inside* the
quoted identifier, so it cannot break out to a second statement. All `LIMIT`/
`sample` values use named parameters (`$lim`, `$sample`), never interpolation.

Not exploitable. Ruff flags the f-string shape structurally and cannot see that
`_safe_ident` neutralizes it.

### S310 ×4 — "URL open for permitted schemes" — NOT APPLICABLE

`handlers/shared.py` and `handlers/capella.py` open URLs built internally from
the configured connection string + a fixed REST path. The scheme is not
user-controlled (it is derived from `couchbase(s)://` config), so the `file:`/
custom-scheme concern the rule warns about does not arise.

### S110 / S112 ×3 — "silent try/except" — HARDENED

Three graceful-degradation paths swallowed exceptions:
- `handlers/shared.py` cluster-version detection (best-effort).
- `handlers/diagnostics.py` two EXPLAIN advisors that skip un-explainable
  statements (DDL etc.) while scanning `system:completed_requests`.

All three are *correct* to continue rather than abort — but they were fully
silent. Now that the server has logging, each logs at `debug` before continuing,
so a diagnostician isn't blind. Behaviour unchanged; visibility added.

### TLS — REVIEWED, CORRECT

`_build_ssl_context` verifies by default (`ssl.create_default_context()`),
honours a custom CA and mutual-TLS client certs, and disables verification
**only** when `CB_ADMIN_TLS_INSECURE=true` is explicitly set (documented as an
opt-in footgun). `CERT_NONE` never fires by default.

### `__import__("base64")` — cosmetic

`auth/oidc.py:88` uses an inline `__import__` for base64 (stdlib). Harmless;
left as-is to avoid touching working OAuth code.

---

## What was verified clean by manual review

- No `eval`, `exec`, `pickle`, `os.system`, `subprocess`, or `shell=True`.
- No hardcoded secrets/tokens/passwords — all credentials come from env.
- No `verify=False` in any HTTP path; TLS off only via explicit opt-in.
- Credential **redaction** covers logs and error responses; the password-echo
  leak (a failed `admin_user_create` returning the plaintext via `err(args=…)`)
  is closed and tested.
- Identifier escaping (`_safe_ident`) applied consistently across the query-
  building handlers (diagnostics, eight_x vector index DDL).
- Confirmation gate is enforced at dispatch by tool annotation, not by client
  elicitation capability — so it cannot be bypassed by a client that omits the
  capability (the failure mode present in the official server).

---

## Post-scan state

- ruff: clean (full ruleset).
- tests: 14 passed (8 automation-model, 6 redaction).
- Hardening applied: 3 silent excepts now debug-logged.
