# Capella connectivity, and how we validate an MCP server against it

Two parts, because they keep coming up together.

**Part 1** is how to reach **Bride-of-Frankenstein**
(`cb.cpvbgft3fwgwy3eu.cloud.couchbase.com`) with the Couchbase SDK from this
laptop, and how to diagnose it when you cannot. It applies to the CRUD MCP PR
work, the CB Admin MCP, Frankenstein's loaders, and any quickstart sample.

**Part 2** is how we prove an MCP server actually works against a real cluster,
rather than assuming it does. Connecting is not the same as working, and the
worst bug in the CRUD PR work was invisible to every layer but one.

Written 2026-09-12 after losing most of a day to this, and revised three times the
same day as each successive explanation was tested and failed. The current
position is in the next section. **Two earlier versions of this file stated
diagnoses that were later disconfirmed**; both are recorded below rather than
deleted, because the pattern of asserting a plausible cause before running the
cheap test cost more than any of the causes did.

---

# Part 1. Connectivity

## Where this stands

### Settled: it is not allowlist granularity

The second version of this file said the VPN never blocked anything and the real
problem was a `/32` allowlist entry failing to track a rotating NAT pool. **That
was tested on 2026-09-12 and is wrong.**

The decisive observation is the sequence the allowlist passed through on
2026-09-11. With the VPN up, connections failed in three separate states:

1. with `198.51.100.45/32` alone listed,
2. with `198.51.100.146/32` also listed, after the portquiz probe named it,
3. **with the whole of `198.51.100.0/24` listed.**

State three covers every address the pool could hand out. If the failure were
about which pool address came up, that state would have connected. It did not.

This also makes an earlier open question moot. Whether `198.51.100.45` was a VPN
egress or a corporate-proxy egress no longer matters: the `/24` covers both cases
at once, and both failed.

### The allowlist as it actually stands

Read live on 2026-09-12, with the audit timestamps:

| CIDR | Status | Created | By | Comment |
|---|---|---|---|---|
| `198.51.100.45/32` | active | 2026-08-17T16:10:59 | Chris's user | (none) |
| `203.0.113.118/32` | active | 2026-09-12T17:11:35 | the API key | real egress to us-east-1 |

`.45` was active and listed throughout the 2026-09-11 failures, so an earlier
claim that it "is still the only `/32` on the cluster" was stale when written and
is only true now because the experimental entries (`.122/32`, `.146/32`, and the
`/24`) were removed afterwards.

`.45` is worth reviewing on its own account. It grants corporate reachability,
it is now demonstrated not to help, and it carries no comment saying who added it
or why. Removing it is a decision, not a step.

### Open: what the tunnel does to 11207 toward us-east-1

That is the remaining candidate and it is **unmeasured**. What is known:

- `portquiz.net:11207` connects, so 11207 is not filtered outbound in general.
  But portquiz is not AWS and not us-east-1.
- `cloudapi.cloud.couchbase.com:443` works with the tunnel up, so AWS is reachable
  on 443.
- The cluster's data port on `svc-d-node-001...:11207` does not answer with the
  tunnel up, in any allowlist state tried.

Nothing yet separates *port* from *destination* from *region*.
`scripts\measure-egress.ps1` now probes that matrix rather than sampling pool
addresses. See below.

### The one thing that would overturn the "three states" result

Allowlist changes are not instant; `allow-my-ip.ps1` itself says to allow a
minute. If the `/24` was added and tested inside that window, or while its
`status` was still `pending` rather than `active`, state three would have failed
for a reason that has nothing to do with the tunnel.

Nothing recorded says whether the `/24` was observed `active` before it was
tested. That is the single hole in an otherwise clean result, it is cheap to
close, and it should be closed before the tunnel hypothesis gets built on:
re-add the `/24`, confirm `status: active` in the listing, wait, *then* test.

### The `/24` decision: don't

Not on this evidence. It would not have fixed VPN-up, which is what state three
showed, so widening buys corporate-wide reachability to a cluster holding
`harvester` and `supportal` in exchange for nothing demonstrated.
`harvester.personal.*` sits on that cluster under a ruling that has not been made.

If the tunnel question is later answered and a `/24` turns out to be part of the
fix, this is a decision to take then, deliberately, and not as a debugging step.

### What to do today

**VPN off for anything that touches the data plane**: the SDK's 11207
connection, the Data API, the fixture tools, the quickstart samples. It is the
remedy that is known to work. It costs Supportal reachability in the same
session, which is the thing worth fixing once the tunnel question is settled.

**The VPN state does not matter for the admin MCP server's Capella tools.** Those
reach the v4 control plane at `cloudapi.cloud.couchbase.com` over 443 with the
organization API key, which is not gated by the per-cluster IP allowlist at all.
`scripts\verify_mcp_surface.py` runs fine with the tunnel up.

### Claims retracted, in order

Kept as a record because all three were asserted before the cheap test was run,
and that is the expensive habit here, not any one of the wrong answers.

1. **"Corporate egress filtering blocks 11207."** Disproved by
   `portquiz.net:11207` connecting.
2. **"`198.51.100.45/32` is still the only `/32` on the cluster."** A reading
   from a state file dated 17 August, presented as current. It was not.
3. **"The VPN never blocked anything; it is allowlist granularity."** Disproved
   by the three-states observation above. This one had reached the point of being
   written into this file, two PowerShell scripts and a runbook as a finding.

---

## Measuring the address that matters

This network routes by destination, not by port. Every IP-echo service reached
through the corporate proxy reports the proxy's address, which is not what the
Couchbase SDK's direct connection uses.

```powershell
$r = [System.Net.WebRequest]::Create('https://checkip.amazonaws.com')
$r.Proxy = $null
$r.Timeout = 20000
(New-Object System.IO.StreamReader($r.GetResponse().GetResponseStream())).ReadToEnd()
```

`Proxy = $null` is the part that matters. Without it you measure the proxy.

`mcp-crud-couchbase\allow-my-ip.ps1` runs that probe and adds the result as a
`/32` if it is missing. It is the right tool with the VPN **down**, where the
home address is stable and the entry it adds is the one that works.

With the VPN up it is a symptom-chaser, and now a demonstrated one: adding pool
addresses did not restore connectivity, and neither did listing the whole `/24`.
It also leaves entries behind. Two of the three experimental entries from
2026-09-11 had to be deleted by hand afterwards.

---

## Diagnosing a failure, in order

Capella **drops** packets from unlisted sources rather than refusing them, so a
wrong allowlist entry and a blocked port look identical: a hang, then a timeout.
That ambiguity is what makes this expensive to debug, and it is why the symptom
read as "the VPN breaks Capella" for a day. Work through it in this order and it
takes two minutes.

```powershell
# 1. Is the KV port reachable at all? (True = allowlist and route are fine)
Test-NetConnection svc-d-node-001.cpvbgft3fwgwy3eu.cloud.couchbase.com -Port 11207 -InformationLevel Quiet

# 2. Is the port blocked generally, or only to this destination?
Test-NetConnection portquiz.net -Port 11207 -InformationLevel Quiet   # True = port is open

# 3. What address does an AWS host actually see? (see the snippet above)

# 4. What is currently allowlisted?
$H = @{ Authorization = "Bearer $env:CAPELLA_API_KEY_SECRET"; 'Content-Type' = 'application/json' }
$U = 'https://cloudapi.cloud.couchbase.com/v4/organizations/cb89726a-f6c5-452e-b92c-2c72ff292d6d/projects/715ca1af-7a2f-4d12-8eab-262f93fe8c2d/clusters/322df7dd-650e-4b12-b77c-4df1ba792100/allowedcidrs'
(Invoke-RestMethod -Uri "$U`?perPage=100" -Headers $H).data | Select-Object cidr, status, comment
```

If step 1 fails and step 2 succeeds, the port is open and the destination is not
answering. With the VPN **down** that is the allowlist, and step 3 gives you the
address to add. With the VPN **up** it is not the allowlist. A full `/24` was
listed on 2026-09-11 and it still failed, so do not spend the afternoon adding
entries. Turn the tunnel off, or run `measure-egress.ps1` and settle the open
question.

Add an entry:

```powershell
Invoke-RestMethod -Method POST -Uri $U -Headers $H -Body (@{cidr='x.x.x.x/32'; comment='why'} | ConvertTo-Json)
```

Delete one (get the id from the listing with `Select-Object cidr, id`):

```powershell
Invoke-RestMethod -Method DELETE -Uri "$U/<id>" -Headers $H
```

---

## What is not the problem

Ruled out by measurement, so don't spend time on them again. All of these were
investigated because the failure was read as a connectivity problem, and none of
them was ever the cause.

- **Outbound port filtering.** `portquiz.net:11207` connects fine.
- **The connection string.** `couchbases://cb.cpvbgft3fwgwy3eu.cloud.couchbase.com`
  is what the Capella console gives. Never add a port; the SDK resolves
  `_couchbases._tcp` SRV to `svc-d-node-001/002/003` on 11207 itself.
- **Private endpoints or VPC peering.** `privateEndpointService` is disabled and
  `networkPeers` is empty. Plain public cluster.
- **A `.dp.` hostname variant.** Appears in Couchbase docs as a placeholder.
  `cb.cpvbgft3fwgwy3eu.dp.cloud.couchbase.com` does not resolve.
- **The Data API.** Enabled, but it is a separate HTTPS interface. The SDK does
  not use it, so it cannot substitute for an SDK connection.
- **The VPN.** *Not* ruled out, and now the leading candidate. See the top of
  this file. What is ruled out is the explanation that the allowlist was merely
  too narrow.

---

## Credentials

`C:\Work\Development\cbenv.bat` sets the environment once (`setx`, so new shells
inherit it). Two things it gets right that are easy to get wrong:

- `CAPELLA_API_KEY_SECRET` is the **secret**, used as the Bearer token for the
  v4 control-plane API. `CAPELLA_ACCESS_KEY_ID` is the key id. They are not
  interchangeable.
- `CB_USERNAME` / `CB_PASSWORD` in that file are the **local** cluster's
  credentials, not Capella's. Capella database users are separate objects, and
  their passwords cannot be read back after creation. If you need one, create a
  new credential via the API or the console.

For the CRUD PR testing, `mcp-crud-couchbase\setup-capella-test.ps1` creates a
`mcpcrudtest` credential scoped to `travel-sample` only, so the test run cannot
touch `harvester` or `supportal`. It writes the password to `capella-env.ps1`.

---

## Verifying end to end

Two levels, and they answer different questions.

**Is the SDK path good?** `mcp-crud-couchbase\capella-sample-test.py` is the
Capella console's own quickstart with the credentials filled in. It connects,
inserts, gets, replaces and removes, printing a CAS for each. Fifteen-second
timeout, so it fails fast.

```powershell
cd C:\Work\Development\mcp-crud-couchbase\upstream-work
. ..\capella-env.ps1
uv run python ..\capella-sample-test.py
```

**Can a client actually call the admin tools?** That is a different question, and
a working SDK connection does not answer it. The admin server's Capella surface
goes to the v4 control plane over HTTPS, not through the SDK at all.
`CB-Admin-MCP\scripts\verify_mcp_surface.py` drives the server over stdio with a
real MCP client and reports which tools answered.

```powershell
cd C:\Work\Development\CB-Admin-MCP
uv run python scripts\verify_mcp_surface.py --out evidence-mcp-read.txt
```

If the first works and the second does not, the problem is in the server or the
control-plane credentials, not the network.


---

# Part 2. How we validate an MCP server

Four layers, cheapest first. Each catches something the one before it cannot.
The CRUD PR work runs all four. The same structure applies to the Admin MCP,
with `verify_mcp_surface.py` standing in for layer 3.

## 1. Unit tests, the logic with no cluster

`uv run pytest tests/unit -q`. Seconds. Mocks the SDK, so it proves option
construction, validation and error mapping without a network.

What it catches that nothing else does: that an option is built the way the SDK
actually reads it. Take the clearest example. The SDK's `*Options` classes are
unvalidated `dict` subclasses, so passing `durability_level=` is *accepted and
silently dropped*. The write succeeds, the caller is told it succeeded, and the
guarantee was never requested. A unit test asserting `durability_level` is
absent from the options object is the only cheap way to catch that.

What it cannot catch: whether the server registers the tool at all.

## 2. Integration tests, a real server against a real cluster

`uv run pytest tests/integration/ -v`. Each test spawns the MCP server as a
subprocess over stdio, connects as an MCP client, and calls tools by name
against a live cluster.

This is the layer that matters most, because it exercises the whole path: tool
registration, the JSON schema the client sees, argument marshalling, the SDK
call, the cluster's response, and the response shape sent back.

It is also the layer that caught the worst bug in the CRUD work. A patch applied
its tests but not its source. Every unit test passed, and the server quietly
advertised 37 tools instead of 38. Only the integration run surfaced it, as
`Unknown tool: 'get_documents_by_ids'`. **If an MCP server is only unit-tested,
a missing tool registration is invisible.**

Read-only mode deserves its own tests here. Start a session with
`CB_MCP_READ_ONLY_MODE=true` and assert that write tools are absent from the
listing *and* that a read tool still works under it. Asserting only the listing
proves nothing about runtime behaviour.

## 3. Manual verification through an MCP client

`mcp-crud-couchbase\manual-check.py` connects as an MCP client over stdio, lists
the advertised tools, and calls each new capability with real arguments,
printing every request and response. `CB-Admin-MCP\scripts\verify_mcp_surface.py`
does the same job for the admin surface at much larger scale, walking every
advertised tool and reporting which answered.

Why bother when layer 2 already uses an MCP client: the transcript is readable
by a person. It shows the tool names, the exact arguments, and the exact JSON
returned, which is what a reviewer or a support engineer actually wants to see,
and what upstream's CONTRIBUTING asks for as evidence.

MCP Inspector does the same thing through a GUI if Node is available
(`npx @modelcontextprotocol/inspector ...`). This machine has no Node, hence the
scripts.

## 4. Both deployments

Every change gets run against **both** Capella and self-managed Couchbase
Server, because they differ in ways that matter: TLS is mandatory on Capella,
durability needs enough replicas, and some endpoints (the query service's
`/admin/settings`, for one) simply are not exposed on Capella. A tool that works
on local Docker and fails on Capella is a tool that fails for most users.

- Self-managed: `mcp-crud-couchbase\setup-test-cluster-2node.ps1` builds a
  throwaway two-node cluster on non-default ports (9091/21210, 9191/21211) so it
  cannot disturb anything else running locally. Two nodes matter, because a
  single-node cluster cannot satisfy `MAJORITY` durability, so those tests would
  skip and prove nothing.
- Capella: `mcp-crud-couchbase\setup-capella-test.ps1` loads `travel-sample` and
  creates a credential scoped to that bucket only, so a test run cannot touch
  live data in `harvester` or `supportal`.

## Capturing evidence: not with Start-Transcript

This cost a full day of rework, so it is written down.

**`Start-Transcript` does not capture test results on Windows PowerShell 5.1.**
It records PowerShell's own output streams. `uv` and `pytest` are native console
executables that write straight to the console handle, so their output never
reaches the transcript. Eight evidence files were produced this way, each one
containing the commands and none of the results, and nobody noticed because the
correct results had scrolled past on screen during the run. The screen is not
the file.

What works, as implemented in `mcp-crud-couchbase\capture-selfmanaged.ps1`,
`capture-capella.ps1` and `capture-baseline.ps1`:

- Pipe every native command with `2>&1` into a helper that both `Write-Host`s the
  line and appends it to the file. Forcing PowerShell to read the stream is what
  captures it.
- Write everything through `Out-File -Encoding utf8`. Do **not** use
  `Tee-Object`: in 5.1 it takes no `-Encoding` and writes UTF-16, so a file that
  mixes it with `Out-File` alternates encodings block by block and cannot be read
  as either.
- Do not leave `$ErrorActionPreference = 'Stop'` set while piping with `2>&1`. A
  harmless warning on native stderr becomes a terminating error and kills the run
  mid-loop. Set it to `Continue` and check `$LASTEXITCODE` yourself instead.
- Add `--junitxml`. A machine-readable result cannot be lost to a console quirk,
  and `failures="0" errors="0" skipped="0"` is a single line a reviewer can check.
- Print a header first: branch, **full commit SHA**, cluster and version, bucket,
  timestamp. Without the SHA a transcript cannot be tied to the code it tested.
  Two Capella transcripts recorded a commit that an amend had already replaced,
  and both runs had to be repeated.
- Measure the cluster, do not assert it. The self-managed header reads node count
  and version from `/pools/default` at run time, and refuses to run on fewer than
  two nodes, because `MAJORITY` durability on one node would make those tests
  meaningless.

And then read the file. Verify evidence by opening what landed on disk, not by
watching the console or trusting that a write reported success. Every one of the
failures above was visible in the file and invisible on the screen.
