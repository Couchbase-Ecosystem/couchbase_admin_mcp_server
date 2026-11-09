# Build guide

Written 2026-11-02. Commands come from `CONTRIBUTING.md`, `pyproject.toml`, the
`Dockerfile` and `.github/workflows/ci.yml`. They were not all re-run for this
document: the ones I ran on 2026-11-02 are marked "run".

## Requirements

- Python 3.10 to 3.14 (`requires-python = ">=3.10,<3.15"`).
- [`uv`](https://docs.astral.sh/uv/) for the environment.
- Docker, for the image build and the mutation rounds on Windows.
- A Couchbase cluster only for the live checks. The regression suite needs none.

## Set up

```bash
uv sync --extra dev        # run, 2026-11-02
uv run pre-commit install
```

## Run the server

`CB_ADMIN_PROFILE` has no default and the server refuses to start without it, because
the two profiles have opposite security postures (`profile_config.py`).

```bash
export CB_ADMIN_PROFILE=workstation
export CB_CONNECTION_STRING=couchbase://localhost
export CB_USERNAME=Administrator
export CB_PASSWORD=password      # set your own, never commit one
uv run python server.py
```

One container or process drives one control plane, never both. `deploy/` has the
Compose and Kubernetes files, and `docs/CONTAINER_DEPLOYMENT.md` explains them.

## Check your change

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -q -p no:randomly --cov      # the CI coverage command, with the floor
uv run pytest -q                           # random order, as CI also runs it
```

The suite is the gate. A run on 2026-11-02 of `uv run pytest -q -p no:randomly --no-cov`
gave 4,681 passed and 2 skipped. The coverage figure is dated in
`docs/design-decisions.md` and `CHANGELOG.md`, because counts move.

The documentation gate is part of the same run: `tests/test_documentation_gate.py`.
List only its findings with:

```bash
uv run pytest tests/test_documentation_gate.py -q -p no:randomly --no-cov -W default
```

Mutation rounds (a maintainer step, in a Linux container, because several mutations are
only caught by symlink tests):

```bash
uv run python scripts/mutation_rounds_1_3.py
uv run python scripts/mutation_round_4.py
uv run python scripts/mutation_round_5.py
uv run python scripts/mutation_round_6.py
uv run python scripts/mutation_round_7.py
```

Live verification against a Capella organization is a maintainer step and never runs in
CI. There is no API key in the repository. See `CONTRIBUTING.md` and `RUNBOOK.md`.

## Build the package and the image

```bash
uv build --wheel
python -m venv /tmp/fresh && /tmp/fresh/bin/pip install dist/*.whl
CB_ADMIN_PROFILE=workstation /tmp/fresh/bin/python -c "import server; print(len(server._TOOLS))"

docker build -t couchbase-admin-mcp:local .
docker run --rm -e CB_ADMIN_PROFILE=workstation couchbase-admin-mcp:local \
  python -c "import server; print(len(server._TOOLS))"
```

These are the packaging checks CI runs (`.github/workflows/ci.yml`, the wheel and image
job). Import from the installed copy, not the source tree, so a file left out of the
package shows up.

## Build number

The build number is the `pyproject.toml` version plus the short commit hash, for
example `1.0.0+51a8ce4` (decision Q2, `docs/questions.md`). `CHANGELOG.md` records
each release against its build number.

## Before you push

1. `ruff check`, `ruff format --check` and the test run above are clean.
2. Comments and documents that describe the changed behavior are updated in the same commit (D8).
3. `CHANGELOG.md` has a line under Unreleased.
4. A new design choice that someone could see is in `docs/questions.md` with options and a recommendation.
