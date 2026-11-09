# The Capella client and its guardrails

**Source:** `handlers/capella/client.py` (the HTTP client), `handlers/capella/guardrails.py`
(the sandbox policy), `handlers/capella/__init__.py` (`_apply_guardrails`, `_handle_primitive`,
`handle`), `handlers/capella/environment.py` (the orchestrator that uses both).
**Spec:** `docs/spec.md` S8 (Capella operations) and S3 step 8 (`denied_guardrail`).
**Related:** `docs/design/authorization.md` (why `confirm: true` does not stop an unattended
delete, which is the reason this layer exists).

## What it decides

Two things, one after the other, for every Capella tool that changes something.

1. **Is this call inside the sandbox?** `guardrails.py` answers from configuration a human
   set at deploy time. Four independent limits: the organization is pinned
   (`CAPELLA_ORG_ID`), destructive work is confined to listed projects
   (`CAPELLA_ALLOWED_PROJECTS`), the live resource's name must carry a prefix
   (`CAPELLA_ENV_NAME_PREFIX`), and the number of environments has a ceiling
   (`CAPELLA_MAX_ENVIRONMENTS`, default 10). A refusal is a `GuardrailError`. Nothing was
   sent to Capella, and the tool answers "Refused by guardrail policy" with the policy.
2. **How is the call sent, and what happens when it fails?** `client.py` builds the path,
   adds the Bearer token, maps errors to a hint, retries only where a retry is safe, and
   pages list results up to a cap.

Order matters. `_apply_guardrails` runs its cheap local checks first (project), then makes one
read to fetch the live cluster and judge it by its own name and flags, then the call is made.

## Why it is built this way

**The sandbox is the only control that can say "delete freely, but only in here".** Read-only
mode is off for this workflow because it writes. `confirm: true` is skipped by design for an
automation principal. `CB_ADMIN_ALWAYS_CONFIRM` would stop teardown dead. None of the three
can express a boundary, so `guardrails.py` does, and it is read only from server
configuration. A tool argument, a token scope or an assertion by the model cannot widen it.

**It fails closed.** With no project allowlist, an unconfigured server can create but refuses
to delete (`Policy.destructive_allowed`). The escape hatch,
`CAPELLA_ALLOW_UNSCOPED_DESTRUCTIVE=true`, has a name chosen so that turning it on in a
customer organization is plainly deliberate, and `policy_warnings()` says out loud when a
control is present but inert (no prefix, unscoped ceiling, no pinned organization). A
control that reads as configured and does nothing is worse than none, and the file argues
this in several places.

**Ownership is judged on the live object.** `assert_managed` takes the cluster as Capella
returns it, not an id the caller supplies. An agent cannot claim a cluster is a test cluster.
The name on the object decides, and an id or a name in `CAPELLA_PROTECTED_CLUSTERS` refuses
the call with no override, compared without regard to case.

**The check covers every change, not only deletes.** Adding an allowlist entry, rewriting an
access-control function or flushing a bucket on an unmanaged cluster is as far out of scope
as deleting it. `_apply_guardrails` therefore fetches the cluster for any mutating tool whose
path names a cluster.

**Two tools write to a different cluster from the one in their path.**
`capella_backup_restore` (path is the source; it writes `body.targetClusterID`) and
`capella_replication_create` (path is the source; it writes `body.target.cluster`
continuously) are listed in `_WRITES_ELSEWHERE`. The ownership check runs on the cluster that
is written, not the one that is read. Checking the path cluster was wrong in both directions
at once: a protected source refused a safe outbound copy, and a protected target went
unchecked.

**The ownership marker is how a cluster stays collectable.** Capella has no tags, so the
orchestrator writes one line into the cluster's free-text description:
`mcp-env:{"env":...,"ttl_h":...,"created":...}`. The lister, the status tool and the reaper
read it. A cluster that loses its marker does not stop existing. It stops being counted and
reaped, and it bills until someone notices. So `capella_cluster_update` (whose `description`
Capella replaces, not merges) re-attaches a dropped marker (`_preserve_ownership_marker`),
and every parser here degrades to "pinned" or "not recognizably ours" and never to an error
that breaks a listing.

**Retries depend on the method.** A POST that creates a cluster can succeed and then lose its
response to a 502. Retrying it makes a second, billed cluster that the caller never hears
about. So a POST retries only on 408, 425 and 429, which prove it was not processed. GET,
HEAD, PUT and DELETE also retry on 500, 502, 503 and 504. The conservative choice is also
the recoverable one, because the orchestrator is a reconciler: its next pass lists what
exists and adopts anything that landed.

**The control plane cannot be weakened by a data-plane setting.** `_ssl_context` has no
insecure option. `CB_ADMIN_TLS_INSECURE` exists for self-signed self-managed clusters and
must not reach `cloudapi`.

**Credentials do not reach the model or the log.** An operation marked `sensitive_response`
passes through `redact_response` and carries a note on where the one sanctioned place to see
a new credential is. The API key secret never appears in an error.

## What went wrong before

- **A project allowlist was treated as enough.** `capella_bucket_flush` could be aimed at an
  unprefixed, hand-made cluster sitting in an allowlisted project, because only the cluster
  delete checked the name (finding F1 in `tests/test_capella_guardrail_hardening.py`). The
  ownership check was also wrapped in `isinstance(cluster, dict)`, so an odd response shape
  skipped it (F2), and `if project_id:` skipped the allowlist for an empty value (F3).
- **The spend ceiling covered only `capella_env_ensure`,** not the raw create primitive (F4).
  It also counted per project in unscoped mode, which `policy_warnings` now states (F20).
- **The ceiling's refusal memo was one global timestamp.** On the HTTP transport one process
  serves many callers, so one full project refused every other project's creates for 15
  seconds, and polling re-stamped it indefinitely. The memo is keyed by scope
  (`ceiling_scope_key`). Only a refusal is cached, because caching an allowance would fail
  open.
- **The protected list matched only ids, then only exact case.** Listing a cluster by name
  protected nothing while `capella_guardrails_status` reported it protected (F7). A
  case-different spelling did the same.
- **The marker parser failed open in two directions.** A non-greedy match stopped at a `}`
  inside a value, and a greedy anchored match failed when a human wrote a note after the
  marker. Both made the cluster "not ours". It now counts braces while tracking string state
  (`_extract_marker_json`). A huge or non-numeric `ttl_h` once broke the whole listing and
  both reap modes, so it now degrades to pinned, with a warning.
- **The first call on a new deployment was refused.** `capella_organizations_list` has no
  organization in its path, but the pin check ran for every tool and its own hint named that
  tool. The pin is now resolved only where the path uses it.
- **A raw-source body was sent as JSON.** Setting an access-control function takes the
  JavaScript itself as the body. Wrapping it in JSON produced an error that read like a verdict
  on the code and cost 43 measured attempts. `capella_request` takes a `content_type` for it.
- **A 404 was blamed on the ids when the server had given its reason,** such as an audit log
  export that produced no content. `_hint_for_status` now stays quiet when the body explains
  itself.

## Where it is tested

| Property | Test |
| --- | --- |
| Fails closed with no allowlist | `tests/test_capella.py::test_destructive_operations_fail_closed_without_an_allowlist` |
| A child-resource change is guarded | `tests/test_capella_guardrail_hardening.py` (F1 to F3) |
| Ceiling on the create primitive, across projects, memo | same file (F4, F16, F20, F21) |
| Protected list by name and by id | same file (F7) |
| The written cluster is checked, not the path cluster | `tests/test_guarded_write_target.py` |
| A missing or unusable cluster response refuses | `tests/test_capella_ownership_marker_guard.py` |
| The marker survives an update | same file |
| Marker parsing and expiry | `tests/test_guardrail_marker_parsing.py` |
| POST is not retried on a 5xx or a dropped connection; the secret is not in an error | `tests/test_capella_retry_safety.py` |
| Error codes come from the parsed body | `tests/test_capella_client_error_codes.py` |

## Before you change it

- A new tool that changes a cluster must set `guarded` in `spec.py`. If it writes to a
  cluster named only in its body, add it to `_WRITES_ELSEWHERE`.
  `tests/test_guarded_write_target.py` finds the known shapes and will name a new one.
- Do not read a limit from a tool argument. Do not add a retry for POST on a 5xx.
- A parser that reads the marker must fail toward "not recognizably ours" and warn. Do not
  let it raise from inside a list.
- GAP: the three mutation rounds (`scripts/mutation_*.py`) break 7 guards in `client.py` and
  5 in `environment.py`, but none in `guardrails.py` or `handlers/capella/__init__.py`, so
  the sandbox checks themselves are not mutation-checked (counted with `--list` on
  2026-11-09). When you change a guard, add a mutation for it to the next round.
- Record a new default in `docs/design-decisions.md`. Chris Ahrendt decides it.
