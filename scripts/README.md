# scripts/

Maintainer tools. None of them runs in CI except the mutation rounds and, when a credential
exists, the Capella path check. None needs to be installed: run them from the repository
root with `uv run python scripts/<name>.py` (Python) or from Windows PowerShell 5.1
(`.ps1`).

Written 2026-11-02. Usage: every Python script prints its own usage with `--help`, which
is the reference. The one-line descriptions below come from each script's header.

## Safety conventions

- **Never put a secret in a script or on a command line.** Credentials come from the
  environment or an env file the operator keeps outside the repository.
- A script that changes a cluster or an organization takes `--perform`. Without it, it is
  meant to preview. Scripts aimed at an organization also take `--i-know-what-im-doing` for
  the writes that cannot be undone.
- **Every script previews, or says it changes nothing.** Decided by Chris Ahrendt on
  2026-11-06 (`docs/plans/script-dry-run-spec.md`). Python scripts that change something
  take `--perform` and preview without it. PowerShell scripts that change something take
  `-WhatIf`. The section "Preview before you change anything" below lists every script
  under one of those, an action flag, or "changes nothing", and
  `tests/test_documentation_gate.py` fails the build when a script is in none of them.

## Verify the server

| Script | What it does |
| --- | --- |
| `verify_mcp_surface.py` | Drives the server as a client does: start-up, gating, confirmation, dry-run interception, argument building, the audit record. Stops short of writes. Options: `--json`, `--out`, `--verbose`, `--timeout`, `--max-rounds` |
| `verify_capella_paths.py` | Confirms each Capella v4 path the server uses is real, against a live organization. A maintainer step. Options: `--project`, `--cluster`, `--json` |
| `idp_lab_assertions.py` | Drives the running server with tokens a real identity provider issued, over HTTP (`deploy/keycloak/`) |
| `dump_tool.py` | Calls one tool through a real client and prints the whole response |
| `run-mcp-evidence.ps1` | Captures a transcript of the server driven by a real client, for a ticket |
| `run-docker-verification.ps1` | Verifies the shipped container: the image builds, TLS from inside it, and the postures it must refuse |

## Mutation rounds (test quality)

| Script | What it does |
| --- | --- |
| `mutation_rounds_1_3.py`, `mutation_round_4.py`, `mutation_round_5.py`, `mutation_round_6.py` | Break one guard at a time and check the test suite notices. A surviving mutation means a control with no test. Run them in a Linux container (`CONTRIBUTING.md`, "Testing"). `--list` prints every mutation and runs nothing; `--help` prints usage |

## Exercise real operations (write to a cluster)

| Script | What it does |
| --- | --- |
| `backup_cycle_test.py` | A whole backup cycle on self-managed Enterprise Edition (`--perform`, `--archive`, `--plan`, `--bucket`, `--repository`) |
| `restore_cycle_test.py` | A restore through a real client. Previews by default, and `--perform` is required |
| `capella_backup_cycle.py` | A Capella managed-backup cycle |
| `capella_cross_cluster_restore.py` | Restore a Capella backup into a different cluster (`--target` is required) |
| `capella_xdcr_setup.py` | A one-way replication between two Capella clusters. `--from` and `--to` are both required, because direction is the safety property |
| `capella_populate_test_cluster.py`, `ee_populate_test_cluster.py` | Create the objects the surface check needs, through the tools themselves |
| `load_test_data.py` | Put sample data in the `mcptest` bucket so the tools have something to act on. Previews unless `--perform` is given. Options: `--bucket`, `--events`, `--assets`, `--capella`, `--timeout`, `--skip-indexes` |
| `fixture_round_trip.py` | Export, import elsewhere, export back, and compare (`--plane`, `--keyspace`, `--scratch`, `--work`) |
| `claim_env_marker.py` | Tag an existing cluster as a managed environment |

## Read-only checks and probes

| Script | What it does |
| --- | --- |
| `capella_backup_readiness.py` | What it would take to make Capella backup work end to end. Read-only |
| `probe_data_api.py`, `probe_data_api_kv.py` | Measure the Data API endpoints. `probe_data_api.py` can also enable or disable the Data API (`--enable`, `--disable`), which changes the cluster |
| `probe_access_control_function.py`, `probe_onoff_schedule.py` | Measure what body shape or response a Capella operation wants |
| `probe_local_sdk.py` | Find a connection string the SDK can use against a local cluster |
| `probe_backup_paths.ps1`, `probe_backup_repository.ps1`, `probe_rest_paths.ps1` | Measure REST paths and settings against a local cluster |
| `find-couchbase-clusters.ps1` | List every cluster manager answering on this host, so you name the right one |
| `measure-egress.ps1` | Probe what the network does to Capella, with the VPN state on every row |

## Lab set-up and housekeeping (PowerShell)

| Script | What it does |
| --- | --- |
| `probe-alternate-ports.ps1` | Ask a node which alternate-address port keys it accepts. It CHANGES the node's alternate-address map, so it is here and not under the read-only probes. Takes `-WhatIf` |
| `ee-lab.ps1` | Stand up or tear down a disposable Enterprise Edition lab, one primary and any number of peers |
| `start-ee-cluster.ps1`, `seed-ee-bucket.ps1`, `add-local-services.ps1` | Start and initialise a local cluster, load a sample bucket, add the Eventing and Backup services |
| `fetch-ee-backup.ps1` | Copy a backup archive out of its container (a script, not a tool, on purpose: see its header) |
| `commit-session.ps1` | Commit a session's work as a sequence of reviewable commits. Shows the plan unless `-Execute` is given |

## Preview before you change anything

Run these from the repository root (Python: `uv run python scripts/<name>.py`; PowerShell:
`.\scripts\<name>.ps1`). The first row of each group says how to preview.

**Python, `--perform` to act.** Without `--perform` the script prints what it would do and
changes nothing: `backup_cycle_test.py`, `restore_cycle_test.py`, `capella_backup_cycle.py`,
`capella_cross_cluster_restore.py`, `capella_xdcr_setup.py`, `capella_populate_test_cluster.py`,
`ee_populate_test_cluster.py`, `fixture_round_trip.py`, `claim_env_marker.py`, `dump_tool.py`,
`probe_access_control_function.py`, `probe_data_api_kv.py`, `probe_onoff_schedule.py`,
`load_test_data.py` (since 2026-11-06; it used to load at once).

**PowerShell, `-WhatIf` to preview.** It lists what the script would change and changes nothing:
`start-ee-cluster.ps1`, `ee-lab.ps1`, `seed-ee-bucket.ps1`, `add-local-services.ps1`,
`probe-alternate-ports.ps1`, `run-docker-verification.ps1`, `commit-session.ps1`,
`fetch-ee-backup.ps1`. `commit-session.ps1` already printed a plan unless `-Execute` was
given; `-WhatIf` gives the same plan and wins over `-Execute`. `-WhatIf` has been checked by
reading the scripts, not by running them in CI, which has no PowerShell: run it once by hand
on Windows after a change.

**An action flag instead.** Without it the script only reads: `probe_data_api.py` (`--enable`
or `--disable` change the Data API setting) and `verify_capella_paths.py` (`--write-probe` sends
writes; without it only GET and OPTIONS).

**Changes nothing outside itself.** No preview is needed:

- `capella_backup_readiness.py`, `probe_local_sdk.py`: read-only.
- `verify_mcp_surface.py`: drives the server over stdio and stops short of writes; the server's own
  dry run intercepts them.
- `idp_lab_assertions.py`: calls tools through the running server, so the server's gates apply.
- `mutation_rounds_1_3.py`, `mutation_round_4.py`, `mutation_round_5.py`, `mutation_round_6.py`:
  change only a temporary copy of the repository.
- `find-couchbase-clusters.ps1`, `measure-egress.ps1`, `probe_backup_paths.ps1`,
  `probe_backup_repository.ps1`, `probe_rest_paths.ps1`: send GET requests (the repository probe
  also sends OPTIONS).
- `run-mcp-evidence.ps1`: writes its own evidence files under the repository root; its write phase
  runs the server in dry-run.

## Lab password

The lab scripts (`ee-lab.ps1`, `seed-ee-bucket.ps1`, `probe-alternate-ports.ps1`, `probe_rest_paths.ps1`) take the lab
password from the `CB_LAB_PASSWORD` environment variable. Nothing is stored in the repository
(`docs/questions.md` Q-006, proposal (a), applied 2026-11-02 pending Chris's confirmation).

```powershell
$env:CB_LAB_PASSWORD = '<choose one>'
.\scripts\ee-lab.ps1 -Password $env:CB_LAB_PASSWORD -LoadSample
```
