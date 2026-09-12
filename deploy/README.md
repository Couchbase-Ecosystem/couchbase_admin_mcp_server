# Deploying the Couchbase Admin MCP server

## The rule: one container, one control plane

This server can drive two unrelated control planes — Capella's v4 API, and
ns_server on a self-managed Enterprise Edition cluster. **A deployment drives
exactly one of them.** An EE container and a Capella container, separately
configured, separately networked, separately restartable.

The server also supports a `both` mode. **Nothing here configures it, and it is
not a supported deployment shape.** `both` switches capability gating off —
every tool for both control planes loads at once — which removes precisely the
containment that running one container per surface exists to provide. A
misconfiguration in a `both` deployment can act on a cluster nobody intended it
to reach; in a per-surface deployment there is no route to reach it through.

### The failure this prevents

`deployment.detect_mode()` **infers** the mode when `CB_DEPLOYMENT` is unset,
and the inference that matters is this one:

> a Capella API key **and** any non-Capella connection string → `both`

That is not a decision anyone makes. It is what happens when a container
inherits `CB_CONNECTION_STRING` from a shared env file, a copied compose stanza,
or a leftover line in `.env.example`. Nothing errors. The tool list silently
doubles. The first sign is a tool acting somewhere it should not have been able
to reach.

So every artifact here sets `CB_ADMIN_REQUIRE_DEPLOYMENT`, which **declares**
the surface. If what the container is actually given resolves to anything else,
the server refuses to start and names the variable to remove. A container that
stops is a container you fix; one that quietly widens is one you find out about
later.

`tests/test_one_container_one_surface.py` asserts this against these files, so a
connection string added to the Capella compose file fails CI rather than
shipping.

---

## Docker Compose

Two files, not two services in one file. Two services in one file share a
default network and come up together on a bare `docker compose up` — that is a
naming convention, not a separation.

### Enterprise Edition

```bash
cp deploy/env.ee.example deploy/.env.ee
# fill in CB_PASSWORD, COUCHBASE_NETWORK, CB_CONNECTION_STRING

docker compose --env-file deploy/.env.ee -f deploy/docker-compose.ee.yml up -d
```

`COUCHBASE_NETWORK` is the Docker network your Couchbase containers are already
on — `docker network ls` will show it.

Joining that network is the point. A containerised cluster advertises its
internal addresses (`172.x.x.x`) in its cluster map, which is unroutable from
the host; from a container on the same network those addresses are exactly
right. Reaching the same cluster from the host instead needs alternate addresses
configured on every node.

### Capella

```bash
cp deploy/env.capella.example deploy/.env.capella
# fill in CAPELLA_API_KEY_SECRET — the SECRET, not the access key id

docker compose --env-file deploy/.env.capella -f deploy/docker-compose.capella.yml up -d
```

This container is on an isolated bridge that this file alone creates. It has no
route to any cluster network, and that absence is the containment.

Both can run at once — different networks, different ports (8000 and 8001).
They remain two deployments that happen to be on one host.

---

## Kubernetes

`k8s/ee.yaml` and `k8s/capella.yaml`, each in **its own namespace** rather than
each being a Deployment in a shared one. The namespace is what makes the
NetworkPolicy boundary meaningful.

```bash
kubectl apply -f deploy/k8s/ee.yaml
kubectl apply -f deploy/k8s/capella.yaml
```

The Capella manifest carries a NetworkPolicy that denies egress by default and
re-opens only DNS and HTTPS, with RFC1918 space explicitly excluded. So that
workload cannot reach a cluster even if its ConfigMap is later edited to name
one — belt as well as braces, since the startup declaration would refuse that
configuration anyway.

Replace the `Secret` stringData before applying, and do not commit a filled-in
copy.

---

## Corporate TLS interception

**The most likely first failure, and it does not look like one.** It bites in
two separate places, and fixing one does nothing for the other.

### 1. At BUILD time — `pip` cannot reach PyPI

Observed on 2026-09-12, on the first attempt to build this image behind a
re-signing proxy:

```
certificate verify failed: self-signed certificate in certificate chain
Could not fetch URL https://pypi.org/simple/mcp/
ERROR: No matching distribution found for mcp<2.0,>=1.10
```

That reads as a broken package index. It is not: `python:3.12-slim` carries its
own CA set, the proxy presents a chain rooted in an authority the image has
never heard of, and pip refuses — correctly.

**Fix:** export your organization's roots into `deploy/ca/` as `.crt` files
before building. The Dockerfile installs everything found there into the image's
trust store and points `PIP_CERT` at it. `deploy/ca/README.md` has the export
command. The directory ships empty, so a network without interception needs
nothing.

**Do not** reach for `pip install --trusted-host`. It makes the error disappear
by turning the proxy into an unauthenticated man in the middle for every package
the image installs.

### 2. At RUN time — the server cannot reach Capella or the cluster

The image is `python:3.12-slim`. Python trusts its own bundled CA set, not the
host machine's certificate store. On a network where a proxy re-signs outbound
TLS, the re-signed certificate is untrusted inside the container — so calls to
`cloudapi.cloud.couchbase.com` fail in a way that reads as a Capella outage, and
calls to a cluster read as the cluster being down.

Export the roots the machine already trusts and mount them:

```powershell
$pem = "$env:USERPROFILE\corp-ca.pem"
Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA | ForEach-Object {
    "-----BEGIN CERTIFICATE-----"
    [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')
    "-----END CERTIFICATE-----"
} | Set-Content -Encoding ascii $pem
```

Then set `CORP_CA_FILE` to that path in your `.env`. Both compose files mount it
read-only and point `REQUESTS_CA_BUNDLE` and `SSL_CERT_FILE` at it.

Leave `CORP_CA_FILE` blank on a network with no interception.

The same class of problem affects `uv` (`UV_SYSTEM_CERTS=1`) and `npm`
(`NODE_EXTRA_CA_CERTS`). In all three cases the fix is to **add** the corporate
root to what the tool trusts. Never disable verification — `strict-ssl false`
and its equivalents turn the proxy into an unauthenticated man in the middle.

---

## Posture defaults

| Setting | Default here | Why |
|---|---|---|
| `CB_ADMIN_READ_ONLY_MODE` | `true` | Writes are a decision. Every write tool additionally requires `confirm: true`. |
| `CB_ADMIN_PROFILE` | `enterprise` | Refuses to start on an incoherent security posture rather than warning. |
| `CB_ADMIN_AUDIT_FILE` | set | An audit sink that was asked for and cannot be opened is **fatal** at startup — by design, since the alternative is a message in the log the operator was told they no longer needed. |
| `CB_ADMIN_HOST` | `0.0.0.0` | Inside a container, bound to the container's own namespace. Publish deliberately. |

A non-loopback HTTP bind with neither a certificate nor
`CB_ADMIN_TLS_TERMINATED_EXTERNALLY=true` is refused at startup: cleartext
bearer tokens defeat every other control at once, and the two situations are
indistinguishable from inside the process. Terminate TLS at your ingress and set
that variable, or give the container a certificate.

---

## Verifying a deployment

```powershell
.\scripts\run-docker-verification.ps1
```

Discovers the Couchbase network, builds both images, starts each container
separately, and drives every tool through a real MCP client from inside the
container — so what is verified is the thing that ships, not the thing that runs
on a developer's host.
