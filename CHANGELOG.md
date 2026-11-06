# Changelog

All notable changes to the Couchbase Admin MCP Server are recorded here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

The **build number** is the `pyproject.toml` version plus the short commit hash, for
example `1.0.0+e57765b` (decision Q2, `docs/questions.md`). A release entry names the
commit it was cut from.

This file starts on 2026-11-02. Earlier history is in `git log`. Nothing was
reconstructed from it here, so this file claims nothing about those changes.

## [Unreleased]

### Added

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
- A gate rule, `scripts-preview`: every script previews, has an action flag, or is declared read-only with a reason. `scripts/README.md` has a new section listing which.

### Fixed

- The cached SDK cluster connection is now built under a lock. Two calls that arrived together before the first connection existed each built a cluster, and one was never closed (Q-001).

### Changed

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
