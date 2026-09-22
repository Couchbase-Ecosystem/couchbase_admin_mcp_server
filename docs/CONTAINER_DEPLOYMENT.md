# Deploying this server in a container

Docker on a laptop, AWS, and GCP. One document, three places, one rule that
does not bend in any of them.

> **Scope.** This is the deployment guide. `deploy/README.md` is the reference
> for the artifacts in this repository (the two compose files, the two
> Kubernetes manifests, the CA directory) and does not repeat what is here.
> `RUNBOOK.md` is what to do when a deployment misbehaves.

---

## 0. The rule, before anything else

**One container, one control plane.** A container talks to Capella's v4 control
plane, or to ns_server on a self-managed Enterprise Edition cluster. Never both.

Two containers, two configurations, two networks. If you need both surfaces, you
run two deployments.

This is not a style preference, and it is not about tidiness. The server infers
its mode when `CB_DEPLOYMENT` is unset, and one inference matters more than the
rest:

> a Capella API key **and** any non-Capella connection string → `both`

`both` switches capability gating off. Every tool for both control planes loads
at once, and nothing in the logs says so — the only outward sign is a longer
tool list. Nobody chooses that. It is what happens when a task definition is
copied, when a shared secret store hands a container one variable too many, or
when someone adds `CB_CONNECTION_STRING` to a Capella deployment believing they
are extending its reach. They are not extending its reach. They are removing its
gate.

So **every configuration in this document sets `CB_ADMIN_REQUIRE_DEPLOYMENT`.**
That variable *declares* the surface. If what the container is actually given
resolves to anything else, the server refuses to start and names the variable to
remove. A container that stops is a container you fix. A container that quietly
widens is one you find out about later, from the wrong side.

`tests/test_one_container_one_surface.py` asserts this against the shipped
artifacts, and `tests/test_container_deployment_guide.py` asserts it against
every configuration printed below — so a `both` example cannot reach a customer
through this file.

---

## 1. Decide two things first

Everything downstream follows from these.

### Which surface

| You are administering | Surface | Declare |
|---|---|---|
| Capella (cloud) | Capella v4 control plane | `CB_ADMIN_REQUIRE_DEPLOYMENT=capella` |
| A cluster you run yourself | ns_server on 8091/18091 | `CB_ADMIN_REQUIRE_DEPLOYMENT=self_managed` |

The consequence is network shape, not just credentials. A **Capella** container
needs outbound HTTPS to `cloudapi.cloud.couchbase.com` and **no route to any
cluster network at all** — that absence is the containment. An **Enterprise
Edition** container needs a route to the cluster's ports and no Capella
credential anywhere near it.

### Which transport

| Transport | Use it when | Shape |
|---|---|---|
| `stdio` (default) | A local MCP client launches the container per session — Claude Desktop, an IDE | `docker run -i --rm`, no ports |
| `http` | A long-running service other containers or agents connect to | Published port, `/mcp` endpoint |

**stdio cannot cross a container boundary.** If the client is not the thing
launching the container, you need `http`.

`http` is where the security requirements live, because an HTTP MCP endpoint
with no authentication is an admin API on a network interface. On the
`enterprise` profile the server refuses to start unless you have settled them —
see §4.

---

## 2. Build the image

There is no published image. You build it and push it to a registry you control
(ECR, Artifact Registry, Docker Hub, your own). That is deliberate: an admin
server reaching a production control plane should come from an artifact you
produced from source you can read.

```bash
git clone https://github.com/Couchbase-Ecosystem/couchbase_admin_mcp_server.git
cd couchbase_admin_mcp_server
docker build -t cb-admin-mcp:local .
```

The image is `python:3.12-slim`, multi-stage, and runs as a non-root user
(`mcp`, uid 1000). It carries no credentials and no `.env` — `.dockerignore`
keeps them out, and the `COPY` list in the `Dockerfile` is explicit rather than
`COPY . .` so that stays true.

### If the build stops with a certificate error

It will tell you, before pip runs, in these words:

```
BUILD STOPPED: this image does not trust your TLS proxy.
```

That is a preflight, not a failure to find a package. A proxy on your network
re-signs outbound TLS, and `python:3.12-slim` carries its own CA set that has
never heard of your organization's root. Export your roots into `deploy/ca/` as
`.crt` files and rebuild; the directory ships empty and is a no-op without
interception. `deploy/ca/README.md` has the export command.

**Do not use `--trusted-host`.** It makes the message go away by turning the
proxy into an unauthenticated man in the middle for every package the image
installs.

The same class of problem bites again at run time, for a different reason and
with a different fix — §6.

---

## 3. Local Docker

### 3a. Capella, stdio, for Claude Desktop

The frictionless path: the client launches the container, speaks over
stdin/stdout, and there is no port and no listener.

```ini
# CONFIGURATION: local-capella-stdio
CB_ADMIN_REQUIRE_DEPLOYMENT=capella
CB_DEPLOYMENT=capella
CB_ADMIN_PROFILE=workstation
CB_ADMIN_TRANSPORT=stdio
CB_ADMIN_READ_ONLY_MODE=true
```

`CAPELLA_API_KEY_SECRET` is passed separately and never written into a file that
lives beside the code — see §5 on secrets. It is the organization API key
**secret**, not `CAPELLA_ACCESS_KEY_ID`. They are different values, and the 401
Capella returns for the wrong one blames the IP allowlist, which sends you
debugging the network instead of the credential.

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "couchbase-capella": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "CB_ADMIN_REQUIRE_DEPLOYMENT=capella",
        "-e", "CB_DEPLOYMENT=capella",
        "-e", "CB_ADMIN_PROFILE=workstation",
        "-e", "CB_ADMIN_READ_ONLY_MODE=true",
        "-e", "CAPELLA_API_KEY_SECRET",
        "cb-admin-mcp:local"
      ]
    }
  }
}
```

`-e CAPELLA_API_KEY_SECRET` with no `=value` passes the variable through from
the environment that launched the client, so the secret is not in the config
file.

### 3b. Enterprise Edition, stdio

Same shape, different surface, and the network matters:

```ini
# CONFIGURATION: local-ee-stdio
CB_ADMIN_REQUIRE_DEPLOYMENT=self_managed
CB_DEPLOYMENT=self_managed
CB_ADMIN_PROFILE=workstation
CB_ADMIN_TRANSPORT=stdio
CB_ADMIN_READ_ONLY_MODE=true
CB_CONNECTION_STRING=couchbase://db1
CB_USERNAME=Administrator
```

Run it **on the cluster's Docker network**, and name the cluster by container
name:

```bash
docker network ls          # find the network your Couchbase containers are on
docker run -i --rm --network couchbase_default ... cb-admin-mcp:local
```

This is not a convenience. A containerised cluster advertises its *internal*
addresses (`172.x.x.x`) in its cluster map, which are unroutable from the host
but exactly right from a container on the same network. Reaching the same
cluster from the host instead needs alternate addresses configured on every
node — and if you configure an external alternate address, the Backup service
will pick it as its own endpoint and die in a restart loop. `CLAUDE.md` §4.1
records that diagnosis; do not re-derive it.

### 3c. Either surface, HTTP, via the shipped compose files

```bash
cp deploy/env.capella.example deploy/.env.capella      # fill in the secret
docker compose --env-file deploy/.env.capella -f deploy/docker-compose.capella.yml up -d
```

```bash
cp deploy/env.ee.example deploy/.env.ee                # fill in password + network
docker compose --env-file deploy/.env.ee -f deploy/docker-compose.ee.yml up -d
```

Two files, not two services in one file. Two services in one file share a
default network and come up together on a bare `docker compose up` — that is a
naming convention, not a separation.

Both can run at once on one host: different networks, different published ports
(8000 and 8001). They remain two deployments that happen to share a machine.

---

## 4. What a networked deployment has to settle

Everything from here — AWS, GCP, Kubernetes — is `http`, which means the
`enterprise` profile, which means the server will not start until these are
answered. That refusal is the point: each one was a real finding, and each is
asserted by `tests/test_documented_configurations_start.py`.

```ini
# CONFIGURATION: networked-capella
CB_ADMIN_REQUIRE_DEPLOYMENT=capella
CB_DEPLOYMENT=capella
CB_ADMIN_PROFILE=enterprise
CB_ADMIN_TRANSPORT=http
CB_ADMIN_HOST=0.0.0.0
CB_ADMIN_PORT=8000
CB_ADMIN_READ_ONLY_MODE=true
OAUTH_ISSUER=https://idp.example.com/realms/mcp
OAUTH_AUDIENCE=api://couchbase-admin-mcp
CB_ADMIN_HTTP_REQUIRE_AUTH=true
CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1
CB_ADMIN_AUDIT_FILE=/var/log/couchbase-admin-mcp/audit.log
```

```ini
# CONFIGURATION: networked-ee
CB_ADMIN_REQUIRE_DEPLOYMENT=self_managed
CB_DEPLOYMENT=self_managed
CB_ADMIN_PROFILE=enterprise
CB_ADMIN_TRANSPORT=http
CB_ADMIN_HOST=0.0.0.0
CB_ADMIN_PORT=8000
CB_ADMIN_READ_ONLY_MODE=true
CB_CONNECTION_STRING=couchbases://cluster.internal.example
CB_USERNAME=mcp-admin
OAUTH_ISSUER=https://idp.example.com/realms/mcp
OAUTH_AUDIENCE=api://couchbase-admin-mcp
CB_ADMIN_HTTP_REQUIRE_AUTH=true
CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1
CB_ADMIN_AUDIT_FILE=/var/log/couchbase-admin-mcp/audit.log
```

Line by line, because each of these is load-bearing and dropping any one of them
is fatal at startup:

- **`OAUTH_ISSUER`** — without an issuer there is no principal, so there is
  nobody to authorize. Scope enforcement has nothing to enforce against.
- **`OAUTH_AUDIENCE`** — without it, a token minted for a different application
  in the same identity provider is accepted here.
- **`CB_ADMIN_HTTP_REQUIRE_AUTH=true`** — off means no request authentication at
  all. An MCP endpoint that administers a database cluster, open to anything
  that can reach the port.
- **`CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1`** — this is an *assertion you are
  making*, not a switch that does something. You are telling the server that
  something in front of it terminates TLS. If that is false, every bearer token
  crosses the wire in cleartext and defeats the other three at once. Set it only
  when an ALB, an ingress, or Cloud Run's own front end really is doing that.
- **`CB_ADMIN_AUDIT_FILE`** — an audit sink that was asked for and cannot be
  opened is **fatal at startup**, by design. The alternative is a warning in a
  log, addressed to an operator who was told they no longer needed to read it.
  In a container this means the path must be writable by uid 1000, which matters
  on a read-only root filesystem: mount a writable volume at
  `/var/log/couchbase-admin-mcp`.
- **`CB_ADMIN_READ_ONLY_MODE=true`** — start here. Writes are a decision, and
  every write tool additionally requires `confirm: true` from the caller even
  once you turn this off.

The MCP endpoint is `POST /mcp` on `CB_ADMIN_PORT`. The image's `HEALTHCHECK`
probes it, and exits 0 without probing when the transport is not `http`.

---

## 5. Secrets: not in the repository, not in the image, not in the task definition

The credential this server holds is an organization API key or a cluster
administrator password. Treat it accordingly.

- **Never** commit it. `.gitignore` covers `.env.*`; the templates are
  `env.<surface>.example` with no leading dot precisely so they are not caught
  by that rule, and they ship empty.
- **Never** bake it into the image. `.dockerignore` excludes `.env`, and the
  `Dockerfile` copies an explicit file list rather than `COPY . .` so an
  accidental credential in the build context does not travel.
- **Never** put it in a task definition's `environment` block, which is
  plain text in the API response and in every console that renders it. Use the
  `secrets` mechanism, which resolves at container start.

AWS: Secrets Manager or SSM Parameter Store, referenced by ARN.
GCP: Secret Manager, referenced by resource name.
Both are shown below.

---

## 6. Corporate TLS interception at run time

Distinct from the build-time problem in §2, with a different fix, and fixing one
does nothing for the other.

The image is `python:3.12-slim`. Python trusts its own bundled CA set, not the
host machine's certificate store. On a network where a proxy re-signs outbound
TLS, the re-signed certificate is untrusted **inside** the container — so calls
to `cloudapi.cloud.couchbase.com` fail in a way that reads as a Capella outage,
and calls to a cluster read as the cluster being down.

Mount the roots the machine already trusts, and point Python at them:

```
REQUESTS_CA_BUNDLE=/etc/ssl/certs/corp-ca.pem
SSL_CERT_FILE=/etc/ssl/certs/corp-ca.pem
```

Both shipped compose files do this from `CORP_CA_FILE`. On AWS and GCP, bake the
roots into your own derived image or mount them from a secret — do not disable
verification.

---

## 7. AWS

### 7a. Capella on ECS Fargate

The natural fit: no cluster to reach, so the task needs outbound HTTPS and
nothing else. Put it in **private subnets with a NAT gateway**, not a public
subnet with a public IP.

Push the image:

```bash
aws ecr create-repository --repository-name cb-admin-mcp
aws ecr get-login-password --region us-east-1 \
  | docker login --username AWS --password-stdin <acct>.dkr.ecr.us-east-1.amazonaws.com
docker tag cb-admin-mcp:local <acct>.dkr.ecr.us-east-1.amazonaws.com/cb-admin-mcp:0.1.0
docker push <acct>.dkr.ecr.us-east-1.amazonaws.com/cb-admin-mcp:0.1.0
```

Store the secret:

```bash
aws secretsmanager create-secret \
  --name cb-admin-mcp/capella-api-key-secret \
  --secret-string 'PASTE-THE-SECRET-HERE'
```

Task definition — the environment is §4's `networked-capella`, and the
credential arrives through `secrets`, never `environment`:

```json
{
  "family": "cb-admin-mcp-capella",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::<acct>:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "mcp",
      "image": "<acct>.dkr.ecr.us-east-1.amazonaws.com/cb-admin-mcp:0.1.0",
      "essential": true,
      "readonlyRootFilesystem": true,
      "portMappings": [{ "containerPort": 8000, "protocol": "tcp" }],
      "environment": [
        { "name": "CB_ADMIN_REQUIRE_DEPLOYMENT", "value": "capella" },
        { "name": "CB_DEPLOYMENT", "value": "capella" },
        { "name": "CB_ADMIN_PROFILE", "value": "enterprise" },
        { "name": "CB_ADMIN_TRANSPORT", "value": "http" },
        { "name": "CB_ADMIN_HOST", "value": "0.0.0.0" },
        { "name": "CB_ADMIN_PORT", "value": "8000" },
        { "name": "CB_ADMIN_READ_ONLY_MODE", "value": "true" },
        { "name": "OAUTH_ISSUER", "value": "https://idp.example.com/realms/mcp" },
        { "name": "OAUTH_AUDIENCE", "value": "api://couchbase-admin-mcp" },
        { "name": "CB_ADMIN_HTTP_REQUIRE_AUTH", "value": "true" },
        { "name": "CB_ADMIN_TLS_TERMINATED_EXTERNALLY", "value": "1" },
        { "name": "CB_ADMIN_AUDIT_FILE", "value": "/var/log/couchbase-admin-mcp/audit.log" }
      ],
      "secrets": [
        {
          "name": "CAPELLA_API_KEY_SECRET",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:<acct>:secret:cb-admin-mcp/capella-api-key-secret"
        }
      ],
      "mountPoints": [
        { "sourceVolume": "audit", "containerPath": "/var/log/couchbase-admin-mcp" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/cb-admin-mcp",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "capella"
        }
      }
    }
  ],
  "volumes": [{ "name": "audit" }]
}
```

Three things in there are not decoration:

- **`readonlyRootFilesystem: true`** with a **writable volume mounted at
  `/var/log/couchbase-admin-mcp`**. Without the volume the audit sink cannot be
  opened and the task will not start — correctly, per §4. A task that boots and
  then cannot audit is the outcome being prevented.
- **`secrets`, not `environment`**, for the API key. `describe-task-definition`
  returns `environment` values verbatim to anyone with read access.
- **`readonlyRootFilesystem`** also means the image cannot be modified at run
  time by anything that reaches it.

In front of it: an **internal** Application Load Balancer with an ACM
certificate, target group on 8000, health check path `/mcp`. TLS terminates at
the ALB, which is what `CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1` asserts. The
task's security group should accept 8000 **only from the ALB's security group**.

Capella's own allowlist is the other half. If your Capella organization
restricts API access by source IP, allowlist the NAT gateway's Elastic IP —
otherwise every call returns a 401 that blames the allowlist, which for once is
telling the truth.

### 7b. Enterprise Edition on AWS

Same task definition shape with §4's `networked-ee` environment, `CB_PASSWORD`
from Secrets Manager, and **no Capella variables anywhere in it**.

The difference is placement. This task needs a route to the cluster's ports
(8091/18091 and the service ports), so it belongs in a subnet that already has
one — the cluster's VPC, or one peered to it. Its security group is the
narrowest thing you can make: egress to the cluster's security group on the
Couchbase ports, and nothing else.

If the cluster runs in Docker on an EC2 instance, the containerised-cluster
problem from §3b applies unchanged: run this container on the same Docker
network on the same host, not across the VPC to a published port.

**Never put the EE task and the Capella task in one task definition.** Two
containers in one task share a network namespace and a lifecycle — the ECS
equivalent of two services in one compose file, and it fails the same rule for
the same reason.

---

## 8. GCP

### 8a. Capella on Cloud Run

The best fit anywhere in this document: Cloud Run terminates TLS at its own
front end, requires no cluster route, and scales to zero.

```bash
gcloud artifacts repositories create cb-admin-mcp --repository-format=docker --location=us-central1
docker tag cb-admin-mcp:local us-central1-docker.pkg.dev/<project>/cb-admin-mcp/server:0.1.0
docker push us-central1-docker.pkg.dev/<project>/cb-admin-mcp/server:0.1.0

printf '%s' 'PASTE-THE-SECRET-HERE' \
  | gcloud secrets create capella-api-key-secret --data-file=-
```

```bash
gcloud run deploy cb-admin-mcp-capella \
  --image us-central1-docker.pkg.dev/<project>/cb-admin-mcp/server:0.1.0 \
  --region us-central1 \
  --port 8000 \
  --no-allow-unauthenticated \
  --service-account cb-admin-mcp@<project>.iam.gserviceaccount.com \
  --set-secrets CAPELLA_API_KEY_SECRET=capella-api-key-secret:latest \
  --set-env-vars CB_ADMIN_REQUIRE_DEPLOYMENT=capella,CB_DEPLOYMENT=capella,CB_ADMIN_PROFILE=enterprise,CB_ADMIN_TRANSPORT=http,CB_ADMIN_HOST=0.0.0.0,CB_ADMIN_PORT=8000,CB_ADMIN_READ_ONLY_MODE=true,CB_ADMIN_HTTP_REQUIRE_AUTH=true,CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1,OAUTH_ISSUER=https://idp.example.com/realms/mcp,OAUTH_AUDIENCE=api://couchbase-admin-mcp,CB_ADMIN_AUDIT_FILE=/var/log/couchbase-admin-mcp/audit.log
```

Two Cloud Run specifics worth knowing before you debug them:

- **`--no-allow-unauthenticated` is not a substitute for
  `CB_ADMIN_HTTP_REQUIRE_AUTH`.** Google's IAM check answers "may this identity
  reach this service"; the server's OAuth check answers "which tools may this
  principal call". They are different questions and you want both. Keep both.
- **`CB_ADMIN_TLS_TERMINATED_EXTERNALLY=1` is true here**, because Cloud Run's
  front end terminates TLS and speaks to the container over the sandbox
  boundary. This is one of the few places the assertion is unambiguously
  correct without you building anything.

Cloud Run's container filesystem is writable in-memory, so the audit file has a
place to live without a mounted volume — but it is **ephemeral and per-instance,
and it disappears when the instance does.** If the audit trail has to survive,
write it somewhere durable: a Cloud Storage FUSE mount, or ship stdout to Cloud
Logging with a sink. Decide which before you need the records, not after.

If your Capella organization allowlists API access by IP, Cloud Run's egress is
from a shared pool — attach a **Serverless VPC connector** with Cloud NAT and a
static address, and allowlist that.

### 8b. Enterprise Edition on GCP

Cloud Run *can* do it with a Serverless VPC connector and
`--vpc-egress private-ranges-only`, but **GKE or a Compute Engine instance in
the cluster's VPC is the better fit**, for the same reason as AWS: the
deployment needs a stable, narrow network path to a stateful cluster, and that
is what those give you.

For GKE, `deploy/k8s/ee.yaml` is the starting point. Use §4's `networked-ee`
environment, put `CB_PASSWORD` in a `Secret`, and keep the two surfaces in
**separate namespaces** — which is what makes the NetworkPolicy boundary in
those manifests mean anything. `deploy/k8s/capella.yaml` carries a policy that
denies egress by default and re-opens only DNS and HTTPS, with RFC1918 space
explicitly excluded, so that workload cannot reach a cluster even if its
ConfigMap is later edited to name one.

---

## 9. Verify the deployment, in this order

Each step fails differently, which is the point of doing them separately.

1. **It started.** `docker logs` / `aws logs tail` / `gcloud run services logs`.
   A refusal is loud and names the variable. Read the message rather than
   restarting.
2. **It declared the right surface.** The startup banner reports the mode. If it
   says `both`, `CB_ADMIN_REQUIRE_DEPLOYMENT` is missing — fix that before
   anything else in this list.
3. **The tool list is the right half.** A Capella deployment advertises
   `capella_*` and `cb_*` and no `admin_*`; an EE deployment the reverse. A list
   containing both is the failure this whole document is about.
4. **One read works.** `capella_organization_list` or `admin_bucket_list`. A 401
   here is a credential problem; a timeout is a network one; they look nothing
   alike in the logs and should not be conflated.
5. **The audit file is being written.** If it is empty after step 4, the sink is
   not where you think it is.

Locally, `scripts/run-docker-verification.ps1` does more than this: it discovers
the Couchbase network, builds both images, starts each container separately, and
drives every tool through a real MCP client **from inside the container** — so
what it verifies is the thing that ships rather than the thing that runs on a
developer's host.

---

## 10. What has actually been exercised

Stated plainly, because a deployment guide that does not distinguish between
"run many times" and "written carefully" is not telling you what you need to
know when it fails.

| Thing | Status |
|---|---|
| The image build, including the TLS preflight | Built and run repeatedly |
| `docker run` with stdio transport | Exercised; this is how the tool surface was verified |
| `deploy/docker-compose.ee.yml`, `deploy/docker-compose.ee.idp-lab.yml`, `deploy/docker-compose.keycloak.yml` | **Brought up 2026-09-15**, for the first time, by the real-IdP lab run recorded in `README.md` § "Verified against a real identity provider" |
| `deploy/docker-compose.capella.yml`, `deploy/docker-compose.ee.lab.yml` | **Never brought up.** The `docker run` probes exercise the image, not these files |
| `deploy/k8s/*.yaml` | **Written and asserted by tests, never applied to a cluster** |
| The HTTP transport | **Exercised end to end 2026-09-15** against a real Keycloak 26.7.3 with client-credentials tokens: authentication refusals before routing, audience validation, a scoped `tools/list`, the confirmation gate, an unattended automation write, and a per-decision audit record — on the host and then repeated inside `cb-admin-mcp:ee`. One provider only; see `README.md` for what that does and does not establish |
| The AWS and GCP shapes in §7 and §8 | **Not deployed by this project.** The environment configurations in them are asserted to start by `tests/test_container_deployment_guide.py`; the cloud resources around them are conventional and unverified |

The environment blocks above are not aspirational — they are run through the
server's real startup validation on every test run, so a configuration in this
document that would refuse to start fails CI. What is untested is the
infrastructure wrapped around them, and that is exactly where to be careful.

Last reviewed: 2026-09-22. The HTTP-transport and compose rows above were
corrected on that date: both were written on 2026-09-14 and the run that
settled them happened on 2026-09-15, after this section was last read.
