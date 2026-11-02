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

### Changed

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
