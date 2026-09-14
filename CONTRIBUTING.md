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
git clone https://github.com/Couchbase-Ecosystem/couchbase_admin_mcp_server.git
cd couchbase-admin-mcp-server
uv sync --extra dev
```

External contributors do not have commit access. [Fork the
repository](https://github.com/Couchbase-Ecosystem/couchbase_admin_mcp_server/fork) and
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
uv run pytest                        # everything (~60s)
uv run pytest -m "not live"          # skip the 9 tests that bind a local port (~35s)
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

### 10. Read `Tool` metadata through `mcp_compat`, never by attribute

mcp 2.0 renamed `Tool.inputSchema` to `input_schema` and `annotations.readOnlyHint` to
`read_only_hint`. **Constructions are fine** — 2.x keeps the camelCase spellings as pydantic
aliases, so the several hundred `Tool(inputSchema=...)` calls need no change. Only attribute
**reads** break, and there were nineteen of them.

Use `mcp_compat.input_schema(tool)`, `is_read_only(tool)`, `is_destructive(tool)`,
`is_idempotent(tool)`. `tests/test_mcp_compat.py` parses every module and fails on a direct
read, so a twentieth cannot appear quietly.

The pin is `mcp>=1.10,<2.0` for a separate reason, documented in `pyproject.toml`: 2.x also
removed `Server`'s decorator registry and the `request_ctx` contextvar that
`auth/request_auth.py` uses to resolve claims inside the dispatch task.

### 11. Every handler group is tested by the shared contract harness

`tests/test_handler_contract.py` discovers every module in `handlers/` and every tool in its
`TOOLS`, then asserts the properties that are dangerous to get wrong and invisible when you
do: valid schema, `required` ⊆ `properties`, annotations present and non-contradictory,
globally unique namespaced names, every declared tool actually routed by `handle()`, no
handler raising instead of returning `err()`, and no data-mutating SQL++ embedded in source.

Two things to know before you touch it:

- Add a module to `handlers/` and `MODULE_NAMES` must grow with it. A test compares the two
  and fails if they diverge — otherwise a new group is silently skipped by ~140
  parametrisations that all still pass.
- The `no_cluster` fixture patches each seam **on every module that imported it**, including
  the derived version predicates (`is_8x`, `is_7x`), not just the primitives they call.
  Patching only `handlers.shared` is not enough: some suites reload that module, after which
  a handler's imported function still closes over the old module's globals. This surfaced as
  a failure in one module, in full-suite runs only.

---

## 🔑 Verifying Capella v4 paths (maintainer step, never CI)

The `capella-paths` CI job is **green when it verified nothing**, on purpose. A real
Capella API key is not held as a repository secret: this is a public repository in an org
that grants write access to several people, and anyone who can push a workflow change can
print a secret to a log. GitHub encrypts secrets and never exposes them to a fork's PR —
the exposure is the write access, not GitHub.

So path verification is a maintainer step, run locally, with a key that never leaves the
machine:

```bash
# A READ-ONLY organization API key SECRET (the secret, not the key id).
export CB_CAPELLA_API_KEY='...'          # PowerShell: $env:CB_CAPELLA_API_KEY = '...'

# Read-only sweep: GETs run for real, writes are probed with OPTIONS.
uv run python scripts/verify_capella_paths.py

# Machine-readable, for promoting parked operations out of spec_pending.py.
# --include-pending is the part that matters: WITHOUT it this script reads spec.py only,
# so it re-checks the 61 paths that are already verified and says nothing whatever about
# the 36 that need verifying.
# Use --out rather than a shell redirect. On Windows PowerShell `>` encodes output as
# UTF-16LE with a BOM, which no JSON reader will accept; --out writes UTF-8 itself.
uv run python scripts/verify_capella_paths.py --method-probe --include-pending \
    --out verify_capella_paths-$(date +%Y%m%d).json
```

### What the target organization needs

A parked operation reports SKIPPED when the object its path needs does not exist. That is
honest, and it is also a floor on how much one run can settle. To get a verdict on the
whole parked set, the organization wants:

| Parked group | Ops | What must exist |
| --- | --- | --- |
| `diagnostics` | 14 | audit logging enabled; at least one alert integration; at least one audit-log export job |
| `eventing` | 9 | a cluster running the Eventing service with at least one deployed function |
| `backup` | 5 | at least one completed managed backup on a bucket |
| `query_index` | 4 | any bucket carrying a GSI index |
| `replication` | 4 | at least one XDCR replication |

None of it needs to be large — one of each is enough, and a read-only key can see all of
it. Provision once and the same organization serves every future run.

What makes this safe to run against a real organization:

- GETs are real; every write is probed with `OPTIONS`, never executed.
- `--method-probe` deliberately does NOT send write bodies — it reads the 422 the API
  returns for an empty body, which names the required fields. That is how the disputed
  managed-backup restore path gets settled without performing a restore.
- The exit status is honest: non-zero when any path ERRORs, and non-zero when ZERO paths
  were VERIFIED. A 401 (which Capella returns before routing, so it says nothing about
  whether a route exists) and a 429 do not count as proof.

**Before sharing the JSON:** it records organization, project and cluster ids, so it is
gitignored (`verify_capella_paths-*.json`) and should be treated as internal. Nothing in
it is a credential.

Promoting a parked operation, once probed. The run's PROMOTION REPORT names the
candidates and the tag each has earned, so this is transcription rather than judgement:

1. Move the record from `handlers/capella/spec_pending.py` into `OPS` in `spec.py`, and
   **delete the parked copy** — a name left in both registries stops the next run with an
   error rather than probing it twice.
2. Retag its summary `[LIVE]` or `[LIVE+METHOD]`, as the promotion report says. The
   distinction is not cosmetic: an `OPTIONS` probe confirms the PATH and says nothing
   about whether the real method is accepted there, so only an operation whose own method
   was sent and rejected on its contents (400/422) earns `[LIVE+METHOD]`.
3. Record the observed status in `LIVE_VERIFIED`.
4. Run the suite — `test_every_operation_has_been_verified_against_a_live_organization`
   is what stops an unverified path shipping, and it exists because a commit message once
   claimed all paths were verified while ten were not.

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
│   │   ├── spec.py            # Declarative v4 op registry
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
- `RUNBOOK.md` — the operator guide: both deployment shapes, the environment lifecycle,
  a worked CI pipeline, troubleshooting
- `docs/ARCHITECTURE.md` and `docs/CB_Admin_MCP_Architecture.docx` — the control design and
  the verification state that produced the conventions above. Section 9 of the document
  records what has been measured and on what date
- `handlers/capella/spec_pending.py` — Capella v4 operations written but deliberately NOT
  shipped, each with the reason inline. Read this before adding a v4 path

## 🆘 Getting help

[Open an issue](https://github.com/Couchbase-Ecosystem/couchbase_admin_mcp_server/issues).
For a suspected security issue, please report it privately rather than in a public issue.
