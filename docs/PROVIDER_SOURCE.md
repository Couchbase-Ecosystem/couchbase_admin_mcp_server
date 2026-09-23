# The Terraform provider as a source of truth

## Why this document exists

`CLAUDE.md` rule 1.5 says the Terraform provider's generated client outranks the
rendered documentation pages when establishing a v4 request shape. A rule that
names a source without saying *which checkout* is an instruction to go looking,
so this records it.

## What the source is

**`couchbasecloud/terraform-provider-couchbase-capella`.**

This used to read `couchbase/...`, which does not exist — a clone of it prompts
for credentials, which reads as "you need access" rather than "wrong path". The
organization is `couchbasecloud`.

The copy this repository's findings were read from was supplied as a zip archive
on 2026-09-14. It has **not** been vendored into this repository, deliberately:
it is a large Go codebase that this project does not build or link against, and
a stale vendored copy would be worse than none — the whole value of the source is
that it tracks Couchbase's own API document.

## The revision these findings were re-verified against

> **Open item CLOSED 2026-09-23.** The commit behind the 2026-09-14 zip was never
> recorded, and it cannot be recovered now. Rather than leave the findings
> unanchored, they were **re-checked against a fresh clone** and this revision
> records what was actually read:

| | |
|---|---|
| Repository | `https://github.com/couchbasecloud/terraform-provider-couchbase-capella.git` |
| Branch | `main` |
| Commit | `a3765c099bfe98d529c8c825a01fbfdc324cee78` |
| Authored | 2026-09-22 10:16:46 -0700 |
| Subject | `[AV-143946] Fix App Services OIDC Create (#795)` |
| Nearest release at the time | `v1.11.1`, tagged 2026-09-02 |
| Read on | 2026-09-23 |

Still **not vendored**, for the reason given above. Re-clone when you need it:

```bash
git clone https://github.com/couchbasecloud/terraform-provider-couchbase-capella.git
git -C terraform-provider-couchbase-capella checkout a3765c099bfe98d529c8c825a01fbfdc324cee78
```

**From here on, a finding that cites the provider cites the revision too.** A
claim attributed to "the provider" with no SHA is a claim nobody can re-check,
which is how the 2026-09-14 archive left this repository.

### What was re-verified at `a3765c0`, and how

Every finding below that could be checked by reading a file was checked. This is
not a claim that the findings are *still true of Capella* — only that the source
they were drawn from says what this document says it says, at a revision anyone
can fetch.

| Finding | Check at `a3765c0` | Result |
|---|---|---|
| `loadBalancerCidr` is hand-written only | present in `internal/api/appservice/appservice.go`; 0 occurrences in `openapi.gen.go` | **confirmed** |
| `capella_bucket_flush` is PUT expecting 200 | `internal/resources/flush_bucket.go:57` — `Method: http.MethodPut, SuccessStatus: http.StatusOK` | **confirmed** |
| The Data API base is read, not derived | `internal/api/data_api/data_api.go:30` declares `ConnectionString`, tagged to the JSON field `connectionString` — read from the response, not assembled | **confirmed** |
| Index definitions live at `.../queryService/indexes` | `openapi.gen.go:32321`, `:32430`, `:32487` | **confirmed** |
| Restore names both ends in one call | `internal/api/backup/backup.go:126-127` — `sourceClusterID`, `targetClusterID` | **confirmed** |

The `application/javascript` content-type finding and the 202-not-204 status
findings were not re-checked here; they are recorded in the registers with their
own evidence tags and a live control plane confirmed them, which is stronger than
a source read.

### One number to stop trusting

`docs/CAPELLA_SURFACE_TODO.md` opens with *"We cover 92 of the 289 v4 operations
the provider knows about."* Counting client methods in `openapi.gen.go` at
`a3765c0` gives **382**, from a 64,871-line file:

```bash
grep -c "^func (c \*Client) " internal/generated/api/openapi.gen.go
```

**That is not evidence the surface grew by 93 operations in eight days.** The 289
was counted by a method nobody wrote down, so the two numbers are not comparable
and the difference says nothing. The point is narrower: the denominator in that
sentence cannot be reproduced, so the coverage fraction should be re-derived —
with the counting method stated — before anyone quotes it again.

## The files that carry the answers

| Path | What it settles |
|---|---|
| `internal/generated/api/openapi.gen.go` | Generated from Couchbase's API document. Parameter names, required vs optional, content types, request and response shapes. **The strongest source.** |
| `internal/api/**` | Hand-written structs. Occasionally *ahead* of the generated client — see the exception below. |
| `internal/resources/*.go` | Expected status codes per operation, and the sequencing a real client uses. |

## Findings this source produced

Each of these was established from the provider and then confirmed against a live
control plane, or is recorded in the registers with its evidence tag.

- **`capella_app_endpoint_access_control_function_set` takes raw JavaScript with
  `Content-Type: application/javascript`.** Not JSON. This cost **43 measured
  probe attempts** and two retracted claims before the source was read. It is the
  reason rule 1.5 exists.
- **`bucket` is required in practice on the index endpoints**, from
  `ListIndexDefinitionsParams` / `IndexDefinitionParams` / `IndexBuildStatusParams`.
  It is optional in the schema; a call without it answers 400 with Capella code
  1000, whose message names neither the parameter nor the fact that it never
  arrived.
- **The index definition payload is at `GET .../clusters/{id}/queryService/indexes`**,
  not `/queryIndexes/definitions`, which does not exist.
- **Restore takes both `sourceClusterID` and `targetClusterID`** in one call, so
  cross-cluster restore is a single request with both ends named.
- **`capella_bucket_flush` is a PUT and expects 200** (`internal/resources/flush_bucket.go`).
  It is the only PUT in the provider that does not expect 204.
- **DELETE answers 202, not 204**, for cluster, App Service, App Endpoint and
  backup cycle. **POST answers 202** for cluster create, backup create, backup
  restore, audit log export create and all three activation toggles.
- **The Data API base is read, not derived.** `internal/api/data_api/data_api.go`
  reads `connectionString` from `GET .../dataAPI` rather than assembling a host
  from the cluster id. This repository had inferred
  `https://{clusterId}.data.cloud.couchbase.com` from two examples and that
  pattern was wrong: the id in the host is the short connection-string id, not
  the v4 UUID.

## The one documented exception

**`capella_app_service_create`'s `loadBalancerCidr` is in the hand-written struct
(`internal/api/appservice/appservice.go`) and NOT in the generated client.** Keep
it. This is the single place where "the generated client is the stronger source"
does not hold, and it is worth knowing the rule has an exception rather than
treating rule 1.5 as absolute.
