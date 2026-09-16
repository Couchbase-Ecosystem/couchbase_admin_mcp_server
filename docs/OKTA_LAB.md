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

## 1a. MEASURED: `couchbase.okta.com` has no custom authorization server

Two unauthenticated requests, 2026-09-16, from a corporate laptop:

```powershell
# The CUSTOM authorization server named `default`
Invoke-RestMethod 'https://couchbase.okta.com/oauth2/default/.well-known/openid-configuration'

  {"errorCode":"E0000015",
   "errorSummary":"You do not have permission to access the feature you are requesting"}

# The ORG authorization server, which every Okta tenant has
Invoke-RestMethod 'https://couchbase.okta.com/.well-known/openid-configuration'

  issuer          https://couchbase.okta.com
  token_endpoint  https://couchbase.okta.com/oauth2/v1/token
```

The second is what makes the first mean something. The tenant answers
unauthenticated discovery normally, so the refusal is not TLS, not the URL, not
a network policy, and **not the caller's own permissions** — nobody was
authenticating. It is specific to the custom-authorization-server feature.

**Reading: API Access Management is not enabled on this org.** Stated as the
conclusion it is, not a certainty. **What would overturn it:** an Okta
administrator opening Security → API → Authorization Servers and finding one
listed. If a server exists under an id other than `default`, the feature is on
and only that name is absent.

### Why this is not a small problem

The org authorization server **cannot** carry custom scopes or a configurable
audience — Okta's own documentation says so, and it is not a setting anyone can
change. It issues `okta.*` scopes for Okta's own APIs and nothing else.

So as `couchbase.okta.com` stands today it cannot express this server's
authorization model at all. Not "needs configuring" — cannot express. The three
scopes and the audience check have nowhere to live.

Three ways out, honestly weighed:

1. **Enable API Access Management.** The clean answer, and the only one that
   keeps the IdP as the authority on who may do what. It is a paid add-on, so
   this is a procurement conversation rather than a configuration one. The ask
   is small once the feature exists: three scopes on an authorization server,
   and one API Services app per principal.
2. **Test against a tenant you own.** The Okta Integrator Free Plan includes API
   Access Management. This answers *does this server read an Okta-shaped token
   correctly*, which is the question that gates the CODE, and it needs nobody's
   approval. It does not answer how Couchbase's administrators configure claims.
3. **Map grants locally instead of reading them from the token.** Authenticate
   with Okta, then decide scopes from a server-side table keyed on `cid`.
   **Recorded because somebody will suggest it, not because it is recommended.**
   It moves the authorization decision out of the IdP and into this server's
   configuration, which is the property the whole model exists to avoid: the
   audit trail would then say what this server believed rather than what the
   identity provider granted, and revocation at the IdP would stop meaning
   anything. If it is ever taken, it should be a written decision with that
   trade named.

### And it is a signal about customers, not just about us

If Couchbase's own Okta does not have API Access Management, a customer's may
not either — and the deployment shape this server documents assumes custom
scopes on a custom authorization server. That is worth asking Disney directly,
alongside the sample-token request that is already outstanding:

> Does your Okta (or Entra) tenant have a custom authorization server we can be
> issued scopes on, or only the org one?

An answer of "only the org one" changes the integration before anybody writes
config, rather than during a working session.

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
**Costs:** more than an IT request, as of the measurement in section 1a. There is
no custom authorization server to add scopes to, so this route is blocked until
API Access Management is enabled on the org. Read section 1a before spending
time here.

**Do Route A first** — and as of 2026-09-16 it is the only one available. If
Route B later behaves differently, the difference is the finding, and you will
know immediately that it is configuration rather than code because the same
assertions passed against Route A.

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
