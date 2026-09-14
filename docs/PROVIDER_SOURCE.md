# The Terraform provider as a source of truth

## Why this document exists

`CLAUDE.md` rule 1.5 says the Terraform provider's generated client outranks the
rendered documentation pages when establishing a v4 request shape. A rule that
names a source without saying *which checkout* is an instruction to go looking,
so this records it.

## What the source is

**`couchbase/terraform-provider-couchbase-capella`.**

The copy this repository's findings were read from was supplied as a zip archive
on 2026-09-14. It has **not** been vendored into this repository, deliberately:
it is a large Go codebase that this project does not build or link against, and
a stale vendored copy would be worse than none — the whole value of the source is
that it tracks Couchbase's own API document.

> **Open item.** The exact upstream commit was not recorded when the archive was
> read. That is a gap: a finding attributed to "the provider" without a revision
> cannot be re-checked against the same bytes later. The next person to consult
> it should record the commit SHA here, and from then on every finding citing the
> provider should cite the revision too.

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
