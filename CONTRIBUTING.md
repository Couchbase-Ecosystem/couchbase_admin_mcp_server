# Contributing to the Couchbase Admin MCP Server

Thanks for your interest in contributing. This guide covers the development setup and,
more importantly, the handful of conventions in this repository that are **load-bearing
for safety** — the ones where doing the obvious thing quietly removes a control.

This server administers clusters. It creates and deletes buckets, manages users, triggers
failovers, and stands up and tears down Capella infrastructure, and in its intended
deployment it does so **unattended**, driven by an agent with no human at the moment of
action. That shapes every convention below.

---

## 🚀 Development setup

### Prerequisites

- **Python 3.10+**
- **[uv](https://docs.astral.sh/uv/)** — used by the rest of the Couchbase MCP projects
- **Git**
- **Node** (optional) — only for the admin console's frontend tests, which skip without it

### Clone and install

```bash
git clone https://github.com/Couchbase-Ecosystem/couchbase-admin-mcp-server.git
cd couchbase-admin-mcp-server
uv sync --extra dev
```

External contributors do not have commit access. [Fork the
repository](https://github.com/Couchbase-Ecosystem/couchbase-admin-mcp-server/fork) and
clone your fork.

The `dev` extra deliberately includes Flask and uvicorn even though they are optional at
runtime. Without them the console and HTTP-transport tests **skip silently**, which is how
`POST /api/call` drifted away from the MCP dispatch twice without anyone noticing.

```bash
uv run pre-commit install
uv run pre-commit run --all-files
```

### The first thing that will trip you up

```bash
uv run python server.py
# [couchbase-admin-mcp] REFUSING TO START: CB_ADMIN_PROFILE is not set...
```

That is not a bug. **`CB_ADMIN_PROFILE` has no default**, because the two deployments this
server supports have opposite security postures and guessing between them is how you get an
unauthenticated admin API on a network interface. For local work:

```bash
export CB_ADMIN_PROFILE=workstation
export CB_CONNECTION_STRING=couchbase://localhost
export CB_USERNAME=Administrator
export CB_PASSWORD=password
```

See `.env.example`, which is long on purpose — it documents *why* each variable exists, not
just its name.

---

## 🧹 Linting

```bash
uv run ruff check .          # check
uv run ruff check . --fix    # fix
uv run ruff format .         # format
```

Both must be clean before a PR. Pre-commit runs them on every commit with the same pinned
ruff version as CI, so the two cannot disagree.

---

## 🧪 Testing

```bash
uv run pytest                        # everything (~40s)
uv run pytest -m "not live"          # skip the 9 tests that bind a local port (~20s)
uv run pytest -m live                # only those
uv run pytest tests/test_capella.py  # one file
```

The suite runs **in randomised order** by default (`pytest-randomly`). That is deliberate:
several modules read environment variables at import time, and order-dependent tests here
have hidden real bugs before. If a test passes in file order and fails randomised, the test
is wrong, not the runner.

### Tests must fail when the control is removed

This is the one testing rule that matters most here, and it is not negotiable for
security-relevant code.

Two mutation harnesses re-introduce specific bugs and assert the suite catches them:

```bash
uv run python scripts/mutation_rounds_1_3.py   # 25 mutations
uv run python scripts/mutation_round_4.py      # 20 mutations
```

Both must report **all mutations caught**. They exist because a green suite proved nothing
on several occasions during this project's security review:

- Five tests asserted on a *helper* while the composition that actually enforces the
  control went uncovered. Deleting the enforcement left the suite green.
- One test passed only because it exercised a *fallback* path rather than the fix.
- A logging control was tested by calling the helper directly; the calling site swallowed
  the helper's refusal and attached the handler anyway. The suite was green while
  `ln -sf /dev/null <logfile>` discarded the audit trail.

If you add a guard, add a mutation entry for it. If your test still passes with the guard
deleted, it is not testing the guard.

---

## 🔒 The conventions that are load-bearing

Please read this section before adding a tool. Each item is here because breaking it caused
a real finding.

### 1. Annotations drive behaviour, not documentation

`readOnlyHint` / `destructiveHint` / `idempotentHint` decide whether a tool is loaded in
read-only mode, whether the confirmation gate applies, and whether the hard ceiling
refuses it. A write tool annotated `readOnlyHint=True` is a silent authorization bypass.

### 2. Never forward caller-supplied keys wholesale

```python
data = form_data(args)                        # NO — mass assignment
```

Couchbase settings endpoints accept far more fields than any tool exposes, so an invented
or hostile key becomes a real configuration change. Use the schema-derived allow-list:

```python
refusal = refuse_undeclared(args, name, TOOLS, endpoint="/settings/indexes")
if refusal is not None:
    return refusal
data = form_data_declared(args, name, TOOLS)
```

It refuses rather than dropping, because a silently dropped key looks like success to an
agent, which then reports a setting as applied when it never was.

### 3. If the CLUSTER dials a caller-supplied host, guard it

```python
assert_egress_allowed(args["uploadHost"], field="uploadHost", tool=name)
```

Several tools make Couchbase open the connection, including one that uploads a full
diagnostic bundle from every node. `169.254.169.254` returns cloud IAM credentials, and
that denial cannot be configured away. For nested payloads use
`guard_nested_host_fields()`, which walks the whole structure — the previous
single-path version failed open on five different shapes.

### 4. `ok()` redacts. Do not bypass it

`ok_allow_secrets()` is the single sanctioned exception, for the one tool whose entire
purpose is returning a generated credential. Everything else goes through `ok()`.

### 5. The policy lives in `authz.py` — do not reimplement it

There are two dispatch paths into the handlers: `server.py`'s MCP dispatch and the
console's `POST /api/call`. The console re-implemented the confirmation and ceiling logic
and drifted twice — first letting a caller self-promote out of the gate with
`{"automation": true}`, then testing the hard ceiling only when automation was *on*, so
with it off a caller's own `confirm: true` satisfied it. Both callers now ask
`authz.evaluate()`.

### 6. Every decision path emits an audit record

Including refusals. In an unattended deployment the log is the only accountability, and a
path that acts without recording it defeats the entire model. The console emitted nothing
at all for a while, which made it the one way to act untraced.

### 7. New Capella paths need a primary source

Every path in `handlers/capella/spec.py` carries a provenance tag:

| Tag | Meaning |
|---|---|
| `[TF]` | Read from the Terraform provider's Go string literals |
| `[DOC]` | From Couchbase's published API reference / OpenAPI document |
| `[LIVE]` | Path confirmed against a real organization |
| `[LIVE+METHOD]` | Path and method both confirmed |
| `[PAT]` | Inferred from a confirmed sibling — **none currently remain** |

Then verify it:

```bash
export CB_CAPELLA_API_KEY='the-key-secret'
uv run python scripts/verify_capella_paths.py
```

Read-only by default: GETs run for real, writes are probed with `OPTIONS`. This is not
ceremony — it found that `GET .../clusters/{id}/appservices` does not exist (that path is
POST-only; App Services are listed organization-wide), which had made all 21 App Services
operations unreachable and was invisible from reading the code.

### 8. Adding a top-level module means updating the packaging

`Dockerfile` and `pyproject.toml`'s `force-include` both list the top-level modules
explicitly. They once omitted three, so the built image raised `ModuleNotFoundError` on
startup with none of the security controls present. `tests/test_packaging.py` derives the
requirement from `server.py`'s real imports and will fail if you forget.

### 9. The console has no build step, and no CDN

`gui/static/index.html` is JSX compiled in the browser by a **vendored** Babel under
`gui/static/vendor/`. Do not reintroduce a CDN `<script>`: the console has to work in an
air-gapped network, and an admin tool should not fetch its JavaScript from a third party at
request time. It was also served with no transpiler at all for a while, which meant the
page rendered blank and no test noticed.

---

## 🏗️ Project layout

```
couchbase-admin-mcp-server/
├── server.py                  # MCP entry point, tool dispatch, HTTP transport
├── authz.py                   # THE confirmation/ceiling policy — both dispatch paths
├── audit.py                   # Structured audit record, one per decision
├── profile_config.py          # workstation | enterprise, validated at startup
├── tls_config.py              # Transport encryption, both termination shapes
├── deployment.py              # Capella vs self-managed capability gating
├── logging_config.py          # Redaction, CR/LF flattening, private log files
├── auth/
│   ├── oidc.py                # Token validation, JWKS, refresh budget
│   ├── request_auth.py        # Claims resolved inside the dispatch task
│   ├── scope_gate.py          # Per-tool scope enforcement
│   └── session.py             # Signed cookie sessions for the console
├── handlers/
│   ├── shared.py              # HTTP client, ok()/err(), redaction, guards
│   ├── egress.py              # Cluster-egress allowlist
│   ├── capella/
│   │   ├── spec.py            # Declarative v4 op registry (61 ops)
│   │   ├── client.py          # v4 client, cursor pagination, retries
│   │   ├── guardrails.py      # Org pin, project allowlist, ceiling, TTL reaper
│   │   └── environment.py     # Composite ensure/park/resume/teardown/reap
│   └── *.py                   # ns_server tool groups (buckets, cluster, xdcr, ...)
├── gui/                       # Flask console + vendored frontend runtime
├── scripts/
│   ├── verify_capella_paths.py    # Probe v4 paths against a live organization
│   └── mutation_*.py              # Mutation harnesses (45 mutations)
└── tests/                     # 636 tests
```

---

## 🤝 Submitting changes

```bash
uv run ruff check . && uv run ruff format --check .
uv run pytest
uv run python scripts/mutation_rounds_1_3.py
uv run python scripts/mutation_round_4.py
```

Then open a PR describing:

- **What** the change does
- **Why** it is needed
- **How you tested it** — and for anything security-relevant, which mutation entry proves
  the test would fail if the control were removed

Commit messages in this repository tend to explain the *reasoning*, not just the change —
what was wrong, why it mattered, and what was considered and rejected. `git log` is the
best guide to the house style.

---

## 📖 Resources

- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Couchbase Management REST API](https://docs.couchbase.com/server/current/rest-api/rest-intro.html)
- [Capella Management API v4](https://docs.couchbase.com/cloud/management-api-reference/index.html)
- [Ruff](https://docs.astral.sh/ruff/)
- `CAPELLA_HANDOFF.md` — the full record of the security review, including the findings
  that produced the conventions above

## 🆘 Getting help

[Open an issue](https://github.com/Couchbase-Ecosystem/couchbase-admin-mcp-server/issues).
For a suspected security issue, please report it privately rather than in a public issue.
