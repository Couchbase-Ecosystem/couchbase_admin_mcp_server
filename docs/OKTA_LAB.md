# Verifying the authorization model against Okta

Couchbase uses Okta internally, so Okta is the provider this server will actually
be driven by here — and, unlike the Keycloak lab, the one where a claim-shape
surprise costs a real session rather than a test run.

> **The point of this document.** Keycloak proved the *plumbing*: JWKS fetch,
> issuer and audience matching, the scope gate, automation mode, the audit
> principal. It proved nothing about **where a given tenant puts the grant**, and
> that is the failure most likely to bite. Keycloak itself put the entire grant in
> `realm_access.roles` while the top-level `scope` claim carried only
> `profile email` — a server reading the obvious claims would have seen a fully
> authorized automation principal as holding nothing, and refused every write
> while reporting "needs confirmation".
>
> Okta is a second, differently-shaped answer to the same question. Running the
> assertions against it converts "we think this generalises" into a measurement.

---

## 1. Okta needs a CUSTOM authorization server. This is not optional.

Okta has two kinds:

| | Issuer | Custom scopes | Configurable `aud` |
|---|---|---|---|
| Org authorization server | `https://<org>.okta.com` | **No** | **No** |
| Custom authorization server | `https://<org>.okta.com/oauth2/<authServerId>` | Yes | Yes |

Okta's own documentation is explicit: *"You can't customize the org authorization
server's audience, claims, policies, or scopes."* The org server issues only
`okta.*` scopes for Okta's own APIs.

This server's whole authorization model is three custom scopes and an audience it
checks. **The org authorization server cannot express any of it.** Point the lab
at it and every call is denied for a reason that has nothing to do with the code —
which is why `scripts/idp_lab_assertions.py` refuses an issuer with no
`/oauth2/<id>` segment rather than letting you find out from a wall of 403s.

**Custom authorization servers require API Access Management**, an optional paid
add-on in production Okta. The Okta Integrator Free Plan includes it. That split
decides which of the two routes below you take.

---

## 2. Two routes, and they answer different questions

### Route A — an Okta Integrator Free Plan tenant (your own)

**Answers:** does this server work with Okta at all — issuer, JWKS, audience,
`scp`, the audit principal.
**Does not answer:** how *Couchbase's* tenant is configured.

You own the tenant, API Access Management is included, and it takes about fifteen
minutes. This is the Keycloak lab again with a different provider, and it is the
right first step because it is entirely within your control.

### Route B — Couchbase's corporate Okta

**Answers:** the question that actually matters here — what Couchbase's IdP
administrators put in a token, and whether this server reads it.
**Costs:** an IT request. Someone with Okta admin rights must create a custom
authorization server (or add scopes to an existing one) and a service app.

**Do Route A first.** If Route B then behaves differently, the difference is the
finding, and you will know immediately that it is configuration rather than code
because the same assertions passed against Route A an hour earlier.

> **The cheapest version of Route B is not a tenant at all.** A single decoded
> access token — claims only, `sub` redacted — from a service app in Couchbase's
> Okta answers the claim-shape question on its own, and costs an administrator
> five minutes. That is the same ask already outstanding with Disney, and for the
> same reason.

---

## 3. What to create

Three custom scopes on the authorization server. The names are the values of
`CB_ADMIN_SCOPE_READ`, `CB_ADMIN_SCOPE_WRITE` and `CB_ADMIN_SCOPE_AUTOMATION`,
which default to:

    couchbase-admin-mcp:read
    couchbase-admin-mcp:write
    couchbase-admin-mcp:automation

Set the authorization server's **Audience** to whatever you will set
`OAUTH_AUDIENCE` to. `api://couchbase-admin-mcp` matches the rest of this
repository's examples. The two must match byte for byte.

Then service apps — API Services / client credentials — one per principal the
assertions use:

| Principal | Scopes it may request | What it proves |
|---|---|---|
| `reader` | read | read executes; write denied; the tool listing is filtered |
| `writer` | write | write reaches the confirmation gate and stops there |
| `automation` | write + automation | unattended write executes |
| `stranger` | none | refused before the scope gate, for the missing grant |
| `otherapp` | write, **different audience** | the audience *comparison* |

`otherapp` is the one worth the extra effort. A token refused for a *missing*
`aud` proves the required-claims check; a well-formed token minted for another
application in the same tenant, holding the write scope, proves the server
compares the audience rather than merely requiring one. In a shared corporate
tenant every token has an `aud` — so that is the realistic attack, and it is the
shape Disney will have too. If a second audience is more trouble than it is worth
on a first pass, skip `otherapp` and say so in the result rather than reporting a
pass that did not test it.

**Okta grants only the scopes a token request ASKS FOR.** Keycloak attaches role
assignments whichever scopes are requested; Okta does not. The driver therefore
names each principal's scopes in the request — see `_okta_scopes()`.

---

## 4. Running it

```powershell
$env:IDP_LAB_PROVIDER    = 'okta'
$env:IDP_LAB_OKTA_ISSUER = 'https://<org>.okta.com/oauth2/<authServerId>'

$env:IDP_LAB_OKTA_READER_ID     = '0oa...'
$env:IDP_LAB_OKTA_READER_SECRET = '...'
# ...and WRITER, AUTOMATION, STRANGER, OTHERAPP

# The server, configured to trust that authorization server:
$env:OAUTH_ISSUER              = $env:IDP_LAB_OKTA_ISSUER
$env:OAUTH_AUDIENCE            = 'api://couchbase-admin-mcp'
$env:CB_ADMIN_HTTP_REQUIRE_AUTH = 'true'
```

**Start with `claims`, before any assertion.** It prints what the tenant actually
minted and what this server reads from it, and it is the whole Keycloak lesson in
one command:

```powershell
uv run python scripts\idp_lab_assertions.py --idp okta claims --principal automation
```

It exits non-zero and says so explicitly if the gate read no grants, or if the
audit record would name nobody. Either is a finding about the READER, not the
token.

Then the same assertions the Keycloak lab runs:

```powershell
uv run python scripts\idp_lab_assertions.py --idp okta tools --principal reader
uv run python scripts\idp_lab_assertions.py --idp okta call --principal reader --tool cb_mcp_status
uv run python scripts\idp_lab_assertions.py --idp okta audience
```

The assertions are identical across providers on purpose: a difference between
Keycloak and Okta must surface as a failing assertion about the **server**, not
as a second test that quietly tests something else.

---

## 5. What is already known about Okta's token shape

Read from Okta's published reference on 2026-09-16, **not** yet measured against a
live tenant. Each is a claim that would be overturned by one decoded token.

- **Scopes arrive in `scp`, as an array.** `auth/scope_gate.py` reads `scp` and
  `tests/test_scope_claim_shapes.py` pins that shape, so the gate should work
  unchanged.
- **`cid` carries the client id**, and a client-credentials token has no user —
  Okta's reference says `uid` *"isn't included in the access token if there is no
  user bound to it"*.

  **That second point was a defect here.** `principal_of()` read
  `sub`/`oid`/`client_id` and `client_id`/`azp`/`appid`, and **none of those is
  `cid`**. Against an Okta service principal the audit record would have named
  nobody — on a call that was authenticated, authorized and executed. Found
  2026-09-16 by reading the documented shape against this code, before a token
  had been minted; fixed the same day, with the provider table in
  `tests/test_scope_claim_shapes.py` extended to cover the audit principal and
  not only the grant.

  It is the same class of gap the Keycloak run found in the grant, one field over.

- **Unconfirmed, and the `claims` command settles it in one run:** whether Okta
  also sets `sub` on a client-credentials token. If it does, only the `client_id`
  field was empty; if it does not, both were. The fix covers both cases and does
  not depend on the answer — but the answer should be written down here once
  somebody has it.

---

## 6. After the run

Record the result the way the Keycloak run is recorded — in `README.md` under
**"Verified against a real identity provider"**, with the date, the provider
version, and the claim shape actually observed. A pass with no record of what was
in the token leaves the next person unable to tell which of the two providers a
future regression came from.
