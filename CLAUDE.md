# CLAUDE.md — CB Admin MCP

Read this before changing anything in this repository.

---

## 1. Verification mandate

**NEVER ASSUME. NEVER GUESS. ALWAYS VERIFY.** This outranks being fast and
outranks sounding certain. "I don't know yet, here is the one command that would
tell us" is a complete answer. A plausible cause stated as a finding is not.

### 1.1 Verify the write landed — by reading the content back

A tool reporting `written` is **not** evidence the file changed. On this setup
`device_commit_files` has returned `{"written": [...]}` for a write that did not
reach disk, twice in one session. Both times the next test run executed a stale
file and produced a failure that had already been fixed, which then cost a full
triage cycle to re-diagnose.

Size and mtime are not enough either — a partial or reverted write can carry a
fresh mtime. **Re-stage the file and grep it for the thing you changed.**

```
1. write        -> device_commit_files
2. read back    -> device_stage_files on the SAME path
3. prove        -> grep for the new symbol / string, and parse it
4. only then    -> tell Chris to run it
```

If step 3 fails, re-commit with `force: true` and repeat. Do not report a fix
as delivered until step 3 has passed.

### 1.2 Never invent a number

`assert len(OPS) > 100` was written into a test whose own docstring said "floors,
not exact counts". The registry holds 97. A floor that was not measured is a
guess with an assertion wrapped round it, and it fails for a reason unrelated to
the property under test — which trains the next person to edit the number rather
than read why it is there.

Assert the property that needs no magic number: non-emptiness, a relationship
between two measured values (`len(TOOLS) >= len(OPS)`), or equality against a
declared allowlist in the source.

### 1.3 Read the evidence before naming a cause

A hang was diagnosed as the VPN, then the VPN again after being told the tunnel
was down, then an absent local cluster, then a missing bucket. It was a
containerised cluster advertising `172.18.0.2` in its cluster map. Four confident
causes, zero tests run.

### 1.4 Say what would overturn it

Any claim worth making is worth stating alongside the observation that would
disprove it. If no such observation exists, it is not a finding.

### 1.5 Retractions are recorded, not quietly corrected

A wrong cause stays in the document with the reason it failed. See
`CAPELLA-CONNECTIVITY.md`, which keeps all three of its retracted diagnoses.

---

## 2. Both surfaces, always

The server drives two unrelated control planes:

| Surface | Prefix | Reached via |
|---|---|---|
| Capella | `capella_*` | v4 API at `cloudapi.cloud.couchbase.com`, org API key |
| Enterprise Edition | `admin_*` | ns_server on 8091/18091, cluster-admin credential |
| Neutral | `cb_*` | SDK / SQL++ diagnostics and the server's own status |

`deployment.detect_mode()` decides which halves load, and **it infers that
decision from the environment when `CB_DEPLOYMENT` is unset**:

- Capella host in `CB_CONNECTION_STRING` → `capella`
- `CAPELLA_API_KEY_SECRET` set, no connection string → `capella`
- both set → `both`
- otherwise → `self_managed`

### 2.1 HARD RULE: one container, one control plane

**A deployment drives exactly one surface. Never both.** An EE container and a
Capella container, separately configured and separately networked.

`both` is a mode the server supports and that **no deployment artifact
configures and no documentation demonstrates**. Do not add one, do not show a
customer how to reach it, and do not suggest it as a convenience. It switches
capability gating off, which removes the containment that per-surface
deployments exist to provide: in a `both` deployment a misconfiguration can act
on a cluster nobody meant it to reach; in a per-surface deployment there is no
route to reach it through.

The `both` code path is still TESTED — `tests/test_no_vacuous_coverage.py`
covers all three modes — because a supported-by-the-code path that nothing
exercises is how gating regressions ship. Tested is not the same as advertised.

`CB_ADMIN_REQUIRE_DEPLOYMENT` declares the surface and the server refuses to
start if the configuration resolves to anything else. Every artifact under
`deploy/` sets it, and `tests/test_one_container_one_surface.py` fails CI if a
shipped compose file ever gains the variable that would widen it.

### 2.2 The inference is the hazard

A developer with a Capella key and no connection string gets `capella`, which
unloads every `admin_*` tool. Any test that iterates the LOADED registry then
reports a clean run having exercised one surface. This has bitten three times:

- `test_gating_still_comes_first` skipped itself silently.
- Seven dispatch tests took `next(iter(server._HANDLERS))`, got
  `admin_bucket_list`, and failed on a refusal rather than the transport.
- The org-discovery tests in `test_verify_capella_paths.py` silently moved onto
  the wrong branch because `CB_CAPELLA_ORG_ID` was exported.

**Any test whose subject is the tool registry must pin `CB_DEPLOYMENT`
explicitly**, and pin it in a subprocess if `server` has to be re-imported —
`server` and `handlers.shared` snapshot their configuration at import, so
`importlib.reload` leaks into every test that runs afterwards.

`tests/test_no_vacuous_coverage.py` holds the mode matrix. The Capella-mode
`admin_*` set is asserted equal to `deployment.CAPELLA_REACHABLE_ADMIN_TOOLS`,
so an exception has to be declared in source, with a reason, to pass.

### 2.3 Service APIs need their ns_server proxy prefix

Search, Eventing and Backup are not served on the management port bare:

| Service | Prefix |
|---|---|
| Search / FTS | `/_p/fts` |
| Eventing | `/_p/event` |
| Backup | `/_p/backup` |

All nine Search tools shipped with bare `/api/index` and 404'd against every
cluster. `tests/test_service_proxy_paths.py` asserts the property by parsing the
handler source, not by pinning individual strings.

---

## 3. Tests may not pass vacuously

An empty `parametrize` is reported as a SKIP that sits in the list looking
exactly like "needs Developer Mode". A `for` loop over an empty collection is a
plain green tick.

`tests/test_no_vacuous_coverage.py` scans every test module and fails, naming
file, line and collection, if a test parametrises over or loops over something
nothing asserts is non-empty. `MAY_BE_EMPTY` is the escape hatch and it costs a
companion test proving emptiness is the success state.

Do not weaken that scan to make a new test pass. Add the guard.

---

## 4. Environment

Chris runs **Windows / PowerShell 5.1**. Use `$env:VAR = '...'`, never
`set VAR=`. Do not hand him POSIX paths in commands.

| Thing | Setting |
|---|---|
| uv on this network | `$env:UV_SYSTEM_CERTS = '1'` — the proxy re-signs TLS; without it `uv sync` fails with `invalid peer certificate: UnknownIssuer`, which reads like a broken index |
| npm on this network | `NODE_EXTRA_CA_CERTS` pointing at the exported corporate roots. **Never** `npm config set strict-ssl false` |
| Credentials | `C:\Work\Development\cbenv.bat` (uses `setx`, so a NEW window is needed) |
| `CAPELLA_API_KEY_SECRET` | the **secret**, used as the v4 Bearer token. `CAPELLA_ACCESS_KEY_ID` is the key id. Not interchangeable — and the 401 Capella returns for the wrong one blames the IP allowlist, which is a lie |
| Test order | `pytest-randomly` is active. A test that passes on statement ordering is a coin flip, not a pass |

Platform limits, probed in `tests/_platform.py` rather than inferred from
`os.name`: symlink creation needs Developer Mode or elevation; file permission
bits do not exist, so `logging_config._restrict_to_owner` deliberately does
nothing there rather than calling `os.chmod` and looking enforced.

---

## 5. Working style

- **Never paste code for Chris to copy in.** Edit the file, commit it, verify it
  per §1.1, then tell him what to run.
- Fix security bugs found in passing, in the same change.
- No Capella API key as a GitHub secret.
- Deleting GitHub workflow runs is permanently destructive and has never been
  approved.
- Research before contradicting him. "You can't change node services in place"
  was wrong; `POST /controller/rebalance` with `topology[<service>]` does exactly
  that. He was right and had done it before.

---

## 6. Known open

### Cross-cluster restore: DESIGNED IN, UNVERIFIED

`capella_backup_restore` takes `sourceClusterID` and `targetClusterID` as
SEPARATE required fields, which is a shape that only makes sense if they can
differ, and the field's own description says so. Documented constraints: same
organization, same cloud provider (Azure to Azure fine, Azure to AWS not).
Indexes come back DEFERRED, so a restored target is not performance-comparable
to its source until builds complete.

**It has never been executed.** The Field Engineering organization has ONE
cluster, so there is nowhere to restore into. This is not a code gap and not
something a test can close -- it needs a second Capella cluster on the same
provider to exist.

Do not describe cross-cluster restore to a customer as verified. The path is
confirmed (405 via OPTIONS, plus the published reference), the body is the
reference's rather than an observation, and the operation has never run.

- `admin_backup_*` — all four candidate paths 404 with the Backup service
  present. **Not guessed.** Unresolved and recorded as unresolved.
- `scripts/verify_mcp_surface.py` still reports SKIPPED for tools whose write
  bodies cannot be synthesised from the shipped schema. That is a limitation of
  the harness, not a defect in those tools, and must be reported as such — see
  §1.4. Reporting 41 already-live-verified operations as PROTOCOL FAILURES is
  the mistake to avoid.
