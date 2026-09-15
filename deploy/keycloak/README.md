# Lab identity provider for the authorization model

`realm-cb-admin-mcp.json` is a Keycloak realm import. It exists because the
authorization model — scope gate, automation mode, hard ceiling, audit principal —
had never been watched working against a real IdP. `tests/test_http_transport_live.py`
mints its own tokens against a uvicorn it starts itself: it proves the code, not the
deployment, and it proves nothing about the claim shapes a real IdP emits.

The realm file carries no comments because it cannot. Keycloak's
`RealmRepresentation` rejects unrecognized fields outright — a `_comment` key does
not import and get ignored, it aborts startup with

    ERROR: Failed to run import
    ERROR: Unrecognized field "_comment_roles" (class ...RealmRepresentation),
           not marked as ignorable

MEASURED 2026-09-15. Hence this file. Anything explaining the realm goes here.

## Why realm ROLES and not client scopes

`auth/scope_gate.py` unions five top-level claims (`scope`, `scp`, `scopes`, `roles`,
`permissions`) with `realm_access.roles` and every `resource_access.<client>.roles`.
Keycloak puts a service account's realm roles in `realm_access.roles`, so this realm
exercises the NESTED path — the one that was missing until 2026-09-15 and the one an
Entra-shaped test never reaches.

The role names must match `CB_ADMIN_SCOPE_READ` / `_WRITE` / `_AUTOMATION` on the
server exactly. Name them explicitly in the compose environment rather than relying
on the defaults; a silent default is how the two drift.

## The four principals

| client | secret | grant | what it proves |
|---|---|---|---|
| `cb-admin-mcp-reader` | `reader-secret` | read | a read-only token cannot reach a write tool |
| `cb-admin-mcp-writer` | `writer-secret` | write | write works, and is still gated per call |
| `cb-admin-mcp-automation` | `automation-secret` | write + automation | the gate is skipped, and only with BOTH |
| `cb-admin-mcp-stranger` | `stranger-secret` | none, and no audience mapper | the required-claims check: no `aud` at all, refused with `MissingRequiredClaimError` before the scope gate |
| `cb-admin-mcp-otherapp` | `otherapp-secret` | write, audience `some-other-app` | the audience COMPARISON. Correct issuer, correct signature, a real `aud`, a real write grant — and still refused, because it was not minted for us. The realistic shared-tenant case, and the stronger of the two |

The first three carry an `oidc-audience-mapper` adding `cb-admin-mcp` to `aud`.
Without it Keycloak issues `aud: account` and every request fails at token
validation, before the scope gate — a 401 that reads like a scope problem and is not.

The last two are the negative cases, and they are deliberately different from each
other. `stranger` omits the mapper, so its token has no `aud` and is refused for a
MISSING claim. That was the first thing measured here, 2026-09-15, and it is not
enough on its own: a missing-claim refusal says nothing about whether the value is
ever compared. `otherapp` closes that — a well-formed token, right issuer, right
signature, carrying the write role and an `aud` of `some-other-app`. Everything
about it is valid except who it was minted for.

## Tier 1: loopback, no TLS, server on the host

`profile_config.py` refuses the enterprise profile when `OAUTH_ISSUER` is `http://`
at anything other than `localhost` / `127.0.0.1` / `::1`, because the JWKS fetched
from that origin is the only thing establishing that a token came from your IdP.
Loopback is exempt, so the cheap tier needs no certificate:

    docker run -d --name kc -p 127.0.0.1:8080:8080 `
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin `
      -v "${PWD}\deploy\keycloak\realm-cb-admin-mcp.json:/opt/keycloak/data/import/realm.json:ro" `
      quay.io/keycloak/keycloak:26.7.3 start-dev --import-realm

`--import-realm` reads the file on FIRST START ONLY. After editing the realm file,
`docker rm -f kc` and run again — restarting the existing container changes nothing.

Then `OAUTH_ISSUER=http://localhost:8080/realms/mcp`, `OAUTH_AUDIENCE=cb-admin-mcp`,
and run the server from the venv in the enterprise profile.

This does NOT cover the shipped image, the container-to-IdP TLS path, or issuer
identity across the docker network. Those are tier 2.

## Tier 2: the shipped image over the docker network

`../docker-compose.keycloak.yml` and `../docker-compose.ee.idp-lab.yml`. The MCP
container reaches Keycloak by container name, `keycloak` is not loopback, so the
https rule above applies and the lab IdP needs a certificate. Both files carry the
full reasoning, including the hosts-file entry that keeps the `iss` claim and
`OAUTH_ISSUER` byte-identical.

## What none of this proves

Disney's claim layout. Keycloak validates the plumbing, which is IdP-independent:
a real JWKS fetch, real `iss`/`aud` matching, the session wiring, the audit
principal. It does not establish where a different IdP puts the grant. That gap
closes with a decoded sample access token from the customer's own IdP, not with
another synthetic realm.
