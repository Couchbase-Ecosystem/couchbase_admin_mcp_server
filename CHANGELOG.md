# Changelog

All notable changes to the Couchbase Admin MCP Server are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The **build number** is the `pyproject.toml` version plus the short commit hash, for
example `1.0.0+e57765b` (decision Q2, `docs/questions.md`). A release entry names the
commit it was cut from.

This file starts on 2026-11-02. Earlier history is in `git log`. Nothing was
reconstructed from it here, so this file claims nothing about those changes.

## [Unreleased]

### Security

Fixes from the 2026-11 security review (static review plus executable probes). Each has a regression test in `tests/test_fix_*.py`.

- The HTTP clients no longer follow redirects, so the cluster admin credential (`admin_request`) and the Capella API key are never re-sent to another URL. A non-https `CAPELLA_BASE_URL` is refused unless it is loopback.
- `redact_text` now truncates before it masks, so nothing past the cap is returned unmasked. `quote_path` encodes `.` and `..` segments. An unrecognised `CB_ADMIN_READ_ONLY_MODE` value now means read-only, with a warning.
- Backup: the restore `target` and the repository `archive` are checked by the egress guard, host values with a path, query or backslash are refused, and eight more address ranges are always denied. `catalog_root` must resolve inside the configured catalogue root, and catalogue tools only touch files that carry the catalogue schema marker.
- Fixtures (both planes): manifest index definitions go through the index DDL guard, manifest file paths cannot leave the fixture directory, and keyspace, xattr and REST path names are escaped.
- Capella: `capella_backup_create` and `capella_cluster_audit_log_export_create` are guarded; a two-way replication also checks the source cluster; request bodies with case-colliding keys are refused; `CB_CAPELLA_ORG_ID` now pins the organization; alert webhook URLs go through the egress guard; open CIDRs (`0.0.0.0/0`) need `CAPELLA_ALLOW_OPEN_CIDR`.
- Server and console: a cancelled call writes an audit record; `next` on login accepts only a same-origin path; tracebacks are redacted and flattened in logs; server-wide `CB_ADMIN_DRY_RUN` now covers `capella_env_reap`; OIDC discovery requires https, checks the issuer, caps its size and expires its cache; the healthcheck probes https when the process terminates TLS.
- `admin_xdcr_conflict_log_query` clamps `limit`; `admin_user_create_temporary` checks the shape of `roles`; `admin_user_change_password` no longer turns group-derived roles into direct roles.
- Enterprise profile prints a warning at start when the hard ceiling, fixture root or catalogue root is not set.

Round 2 (re-scan of the fixed tree). Regression tests are in `tests/test_fix_capella_round2.py` and the existing `test_fix_*.py` files.

- Redaction: `redact_text` masks first, then chunks, so nothing is truncated and nothing past a window is unmasked; URI passwords with `/`, `?`, `#` are masked; more key names (cookie, api-key, client key) are masked; an exception that is a log argument is scrubbed in the message head.
- Capella: a caller description can no longer shadow the ownership marker (all markers are parsed, caller text containing `mcp-env:` is refused on create, a caller marker cannot replace the stored one); CIDRs wider than /8 (IPv4) or /16 (IPv6) are refused; `..` ids are encoded; non-canonical spellings of guarded body keys are refused; `capella_env_reap` treats only an explicit `dry_run: false` as a real reap; fixture export and verify now apply the project allowlist and protected-cluster list; the Data API client does not follow redirects, requires https and checks the host (`CB_CAPELLA_DATA_API_HOSTS` adds trusted hosts).
- SQL++: the statement lexer skips a closed `/*+ ... */` hint, so a quote inside it can no longer hide a `;`; index DDL is validated again after it is rewritten on import (both planes).
- Egress: `split_host` only treats a scheme at the start as a scheme and reads a backslash as a path separator; destination keys are matched after NFKC and casefold; a falsy `emailHost` no longer skips the check.
- Auth and console: one parser for `CB_ADMIN_HTTP_REQUIRE_AUTH`; `resource_access` roles count only for the audience client (or `CB_ADMIN_TRUSTED_CLIENTS`, `*` for all); OIDC discovery serves the last good document if a refresh fails and checks the endpoints it names are https; `/api/call` validates the body and arguments against the served schema and audits a refusal as `denied_invalid_arguments`; `/api/tools` lists only tools the caller's scopes allow.
- Fixtures: export honours server-wide preview mode, refuses cluster names containing a path separator, and quotes the bucket name in the scopes URL.
- Admin core: `admin_alerts_set` no longer double-wraps its refusal, sends recipients comma-separated and refuses a partial call that would clear the SMTP password; bucket create and update refuse undeclared keys; a wildcard bucket role is written as `role[*]` and an inner scope gap is refused; diagnostics `limit` and `sample_size` are capped; a tool-list path that does not exist is warned about.
- Capella fixture verify: zero rows from `system:indexes` is reported as "index state could not be checked" (a one-bucket `data_reader` sees no rows; measured live) instead of listing every recorded index as missing.
- Fixed `admin_user_change_password` for users holding wildcard, bucket or scope roles. Enterprise 8.0.1 reads an unnarrowed part back as `*` but rejects `data_reader[bucket:*:*]` on write, so the role rewrite failed with a 400. Trailing `*` parts are now dropped (`data_reader[bucket]`, `data_reader[*]`). Found by the live EE check.
- Round 3: `dry_run` on `admin_fixture_export` and `capella_fixture_export` is now honoured for a caller (the tools declare it, so the dispatch no longer strips it before the handler can preview); export `page_size` is bounded to 1..5000 and refused outside it; `cb_mcp_list_tools`, `cb_mcp_get_tool_info` and `cb_mcp_status` show only the tools the caller's token may use (a hidden tool looks like a missing one).
- Round 3: `CB_ADMIN_DRY_RUN=y` and `t` now turn preview mode on (they were read as off, unlike every other boolean control); audit records cap each string at 2048 characters and say how much was dropped, so one call cannot write an unbounded record.
- Round 3: the console's login-state cookie is a `__Host-` cookie over TLS (Secure, path `/`, no Domain), so a sibling subdomain or a service on the same host can no longer plant an attacker's state and log the victim in as the attacker. Plain http keeps the narrow path.
- Deploy: compose files default the scope names and pass through the hardening variables; `.dockerignore` secret patterns match at any depth.

Behaviour changes to expect from round 2: a cluster whose Data API host is outside `.cloud.couchbase.com` needs `CB_CAPELLA_DATA_API_HOSTS`; alert updates against an authenticated SMTP server must repeat `emailPass`; a token whose roles sit under a client other than the audience loses them unless `CB_ADMIN_TRUSTED_CLIENTS` names it.

Behaviour changes to expect: alert webhooks are refused until `CB_ADMIN_EGRESS_ALLOWED_HOSTS` or `CB_ADMIN_EGRESS_ALLOW_ANY` is set; a cluster that answers with a redirect is now an error; a restore target on loopback is always refused.

Not fixed (design decisions): the TLS 1.2 floor in `tls_config.py` (uvicorn builds its own context), a conflict-log-only restriction on the conflict query, and a role allow-list for temporary users.

### Added

- Full doc comments (what it does, the order of the steps, arguments, returns, what it raises, why, and the spec and design note) on five of the hardest functions: `assert_egress_allowed`, `profile_config.validate`, `_apply_guardrails`, `capella_request` and the backup catalogue `_matches` (D15). Documentation only. 29 more functions over the complexity limit remain; most already have long comments.
- Design note for the backup catalogue, `docs/design/backup-catalogue.md`, and `docs/spec.md` S9 re-read for it. Documentation only. It found three gaps, listed in the note.
- `scripts/mutation_round_7.py`, run in CI: 10 mutations of the backup catalogue.
- `scripts/mutation_round_6.py`, run in CI: 13 mutations of the Capella sandbox (guardrail policy, ownership of the cluster a call writes to, fixture import ownership). Two behaviour tests for the written-cluster rule in `tests/test_capella_guardrail_hardening.py`.
- The documentation gate, `tests/test_documentation_gate.py`, which lists every gap
  against the documentation standard (rules D1 to D15) on each test run.
- The handover set in `docs/`: `README.md`, `MODULE_MAP.md`, `BUILD_GUIDE.md`,
  `THREADING_MODEL.md`, `spec.md`, `questions.md` and `design-decisions.md`.
- `AGENTS.md`, the single copy of the working rules. `CLAUDE.md` now points at it.
- `tests/test_tool_group_examples.py`: one tested example for each of the 17 tool groups (D12).
- This changelog, shipped in the wheel and the container image.
- The documentation standard, in `CONTRIBUTING.md`.
- A header on every Python file, PowerShell script and the console page: component, spec section, main items, callers and callees (D1). Two gate rules check them: every Python header has the five fields, and its callers and callees match what the code imports. No behavior changed.
- A doc comment on every public function and class (D2). The gate now fails the build when one is missing.
- Design notes for the Capella client and guardrails, the egress allowlist, fixtures and the transports, in `docs/design/`. Documentation only. Writing them found one open question, Q-008 (the Capella fixture import does not check the target cluster's ownership).
- A gate rule, `scripts-preview`: every script previews, has an action flag, or is declared read-only with a reason. `scripts/README.md` has a new section listing which.

### Fixed

- `capella_fixture_import` now checks the target cluster. It fetches the live cluster and refuses one that lacks `CAPELLA_ENV_NAME_PREFIX` or is in `CAPELLA_PROTECTED_CLUSTERS`, before anything is written, and refuses when the cluster response is unusable. Before, an import could overwrite documents on a protected or hand-made cluster in an allowlisted project. Behavior change: an import into such a cluster is now refused (Q-008).
- The cached SDK cluster connection is now built under a lock. Two calls that arrived together before the first connection existed each built a cluster, and one was never closed (Q-001).

### Changed

- Backup catalogue entries are written atomically and writes are serialised. Before, a crash during a rewrite could truncate an entry, and two simultaneous updates to one entry could lose one change. No change to the tools or the entry format.
- `.env.example` now documents `CB_ADMIN_CATALOG_ROOT` and `CB_ADMIN_FIXTURE_ROOT`, which were described nowhere an operator would look.
- `.gitignore` lists `cb-data.tgz` and `reexport.json`, run artifacts that kept showing as untracked.
- `scripts/load_test_data.py` now previews by default and loads only with `--perform`. Before, it wrote about 2,200 documents as soon as it started. Anyone running it as before gets a plan and no data until they add `--perform`.
- The three mutation scripts take `--help` and `--list`. `--help` used to start a full round. With no option they run the round exactly as before.
- Eight PowerShell scripts take `-WhatIf` (`start-ee-cluster`, `ee-lab`, `seed-ee-bucket`, `add-local-services`, `probe-alternate-ports`, `run-docker-verification`, `commit-session`, `fetch-ee-backup`). It prints what they would change and changes nothing. Not run in CI, which has no PowerShell.
- The audit decision vocabulary is defined once, as `audit.DECISIONS`. The `build_record` docstring listed nine of the fourteen names; it and `docs/spec.md` S4 now list all of them, and a test fails when they disagree with the code (Q-003). The record format is unchanged.
- Customer names and internal ticket ids are removed from comments and documents, and the gate (D5) fails if a ticket id or a `@couchbase.com` address comes back (Q-007).
- `ee-lab.ps1` reads the lab password from `CB_LAB_PASSWORD` when `-Password` is not given (Q-006).
- Real Capella cluster ids and UUIDs in comments, documents and tests are replaced with stand-ins (D5).
- `seed-ee-bucket.ps1`, `probe-alternate-ports.ps1` and `probe_rest_paths.ps1` read the lab password from `CB_LAB_PASSWORD` instead of holding it as a literal. `ee-lab.ps1` documents the same variable.

- References to `CLAUDE.md` in code comments, tests and documents now name `AGENTS.md`.

## [1.0.0+e57765b] - 2026-10-09

Baseline for this file: the commit before the documentation work, "Verify index replica
counts on Capella from num_replica". On 2026-10-09 the test suite gave 4,666 passed and 2
skipped, at 90.2% coverage against an 89% floor (command: `uv run pytest -q -p no:randomly
--cov`, commit `89f817d`). Not re-run for `e57765b` itself: its CI result is not recorded
here.

### Fixed

- Index replica counts on Capella are read from the `num_replica` field that the live
  cluster returns. Not yet re-run against a live cluster.
