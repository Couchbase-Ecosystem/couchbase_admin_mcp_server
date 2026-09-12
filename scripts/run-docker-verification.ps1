<#
  run-docker-verification.ps1

  Verify the SHIPPED CONTAINER, not the developer's host.

  deploy/ has compose files, Kubernetes manifests and CI assertions that they are
  well formed. None of that is evidence the server RUNS in a container, reaches
  a cluster from one, or refuses the posture it is supposed to refuse. This
  executes the image.

  WHAT IT CHECKS, and why each one is here
  ----------------------------------------
    1. the image builds
    2. TLS from INSIDE the container to cloudapi.cloud.couchbase.com.
       The prediction: python:3.12-slim trusts its own bundled CA set, not the
       machine's. Where a proxy re-signs outbound TLS -- which this network does,
       which is why uv needs UV_SYSTEM_CERTS -- the re-signed certificate is
       untrusted inside the container and Capella looks like an outage. If that
       happens here it will happen to Disney, on their proxy.
    3. the EE container resolving the cluster BY CONTAINER NAME on the shared
       Docker network. This is the whole reason to run there: a containerised
       cluster advertises internal addresses in its cluster map, unroutable from
       the host, correct from a container beside it.
    4. CB_ADMIN_REQUIRE_DEPLOYMENT actually REFUSING a drifted posture. A guard
       that fails open is worse than no guard, and this is the only way to see it
       do its job -- handed a Capella key AND a connection string, which resolve
       to 'both', while declaring 'capella'.
    5. which tools each declared mode loads.

  READ-ONLY against your clusters. Containers are started with --rm and a probe
  command instead of the server, so nothing is left running and no tool is
  called.
#>

[CmdletBinding()]
param(
    [string]$Image = 'cb-admin-mcp:verify',
    [switch]$SkipBuild,
    # Point these at a cluster the EE container should reach. Discovered from
    # the running containers when omitted.
    [string]$ClusterContainer,
    [string]$Network,
    [string]$CorpCaFile = $env:CORP_CA_FILE,

    # Used only to count buckets when choosing between several Couchbase
    # containers. Never passed into the image under test.
    [string]$Username = $env:CB_USERNAME,
    [string]$Password = $env:CB_PASSWORD
)

$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

$script:Failures = @()
function Check {
    param([bool]$Ok, [string]$Label, [string]$Detail = '')
    Write-Host ("   {0}  {1}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Label) `
        -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
    if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
    if (-not $Ok) { $script:Failures += $Label }
}

# -- 0. Docker, and which cluster ---------------------------------------------

Write-Host ''
Write-Host '== 0. environment ==' -ForegroundColor Cyan

$dockerOk = $null -ne (Get-Command docker -ErrorAction SilentlyContinue)
Check $dockerOk 'docker is available'
if (-not $dockerOk) { exit 1 }

if (-not $ClusterContainer) {
    # A Couchbase container is one whose image name mentions couchbase.
    $candidates = @(docker ps --format '{{.Names}}\t{{.Image}}' | ForEach-Object {
        $parts = $_ -split "`t"
        if ($parts[1] -match 'couchbase') { $parts[0] }
    })
    Write-Host ("   couchbase containers: " + ($candidates -join ', '))

    # NOT the first one. Several Couchbase containers can be running and they
    # are not interchangeable -- picking by list order chose a node of an idle
    # two-node test cluster over the single-node cluster holding every bucket,
    # the Backup service and the test data. The check would then have passed
    # while proving something about a cluster nobody was asking about.
    #
    # Choose by what ANSWERS: a container running a cluster manager with
    # buckets on it. That is a property, not a guess about naming.
    $best = $null
    $bestBuckets = -1
    foreach ($name in $candidates) {
        $probe = docker exec $name curl -s -m 5 -o /dev/null -w '%{http_code}' `
            http://127.0.0.1:8091/pools/default 2>$null
        if ("$probe" -notmatch '^(200|401)$') {
            Write-Host ("     {0,-42} no cluster manager on 8091" -f $name) -ForegroundColor DarkGray
            continue
        }
        # WITH CREDENTIALS. /buckets is authenticated, so an unauthenticated
        # probe answers 401 and parses as zero buckets -- which made every
        # candidate tie at 0 and handed the choice back to list order, the exact
        # thing this block exists to avoid.
        $raw = docker exec $name curl -s -m 5 -u "${Username}:${Password}" `
            http://127.0.0.1:8091/pools/default/buckets 2>$null
        $count = 0
        if ($raw) { try { $count = @(($raw | ConvertFrom-Json)).Count } catch { $count = 0 } }
        Write-Host ("     {0,-42} cluster manager, {1} bucket(s)" -f $name, $count)
        if ($count -gt $bestBuckets) { $bestBuckets = $count; $best = $name }
    }
    $ClusterContainer = $best

    if ($candidates.Count -gt 1) {
        Write-Host ''
        Write-Host ("   choosing {0} ({1} buckets). Override with -ClusterContainer." -f $ClusterContainer, $bestBuckets) -ForegroundColor Yellow
    }
}
Check ([bool]$ClusterContainer) 'a Couchbase container was found' $ClusterContainer

if ($ClusterContainer -and -not $Network) {
    # Read the network off the container rather than assuming a compose default.
    $json = docker inspect $ClusterContainer | ConvertFrom-Json
    $Network = ($json[0].NetworkSettings.Networks | Get-Member -MemberType NoteProperty |
                Select-Object -First 1).Name
}
Check ([bool]$Network) 'its Docker network was discovered' $Network

# -- 1. Build ------------------------------------------------------------------

Write-Host ''
Write-Host '== 1. the image builds ==' -ForegroundColor Cyan
if ($SkipBuild) {
    Write-Host '   skipped by request'
} else {
    # STREAM IT. The first version piped this through Select-Object -Last 6,
    # which buffers the entire build and prints nothing until it finishes -- so a
    # build that was working looked hung, and the only way to tell a slow build
    # from a stuck one was to wait it out. A run that shows nothing cannot
    # distinguish working from stopped; that is the same defect as a harness
    # that names a tool only once it has finished with it.
    Write-Host '   Streaming build output. The FIRST build pulls python:3.12-slim'
    Write-Host '   and installs dependencies, which takes minutes on a slow network.'
    Write-Host '   If it stalls on a pip step, that is the corporate TLS proxy:'
    Write-Host '   pip inside the build has the same untrusted-CA problem as check 2.'
    Write-Host ''

    $started = Get-Date
    docker build --progress=plain -t $Image -f Dockerfile .
    $buildExit = $LASTEXITCODE
    $elapsed = [int]((Get-Date) - $started).TotalSeconds

    Write-Host ''
    Check ($buildExit -eq 0) "docker build succeeded (${elapsed}s)"
    if ($buildExit -ne 0) {
        Write-Host '   A build that failed on a pip/TLS step needs the corporate roots'
        Write-Host '   INSIDE the build, which is a Dockerfile change rather than a'
        Write-Host '   runtime mount -- the CA file check below only fixes the RUNNING'
        Write-Host '   container. Say so rather than assuming the image is broken.'
        exit 1
    }
}

# A probe runs Python INSIDE the image. --entrypoint overrides the server, so
# nothing serves and no tool is called.
#
# THE PROGRAM GOES IN ON STDIN, not as a `-c` argument. PowerShell parses the
# argument list before docker sees it and strips the quoting, so
#     url = "https://cloudapi.cloud.couchbase.com/..."
# arrived inside the container as
#     url = https://cloudapi.cloud.couchbase.com/...
# and every probe died with SyntaxError -- reported as "the container could not
# complete a TLS handshake", which is a conclusion about the network drawn from
# a quoting bug. `python -` reads the program from stdin, where there is no
# argument parser to get through.
function Probe {
    param([string]$Code, [string[]]$DockerArgs = @())
    $arguments = @('run', '--rm', '-i', '--entrypoint', 'python') + $DockerArgs + @($Image, '-')
    $out = $Code | docker @arguments 2>&1
    return ($out -join "`n")
}

# -- 2. TLS from inside the container -----------------------------------------

Write-Host ''
Write-Host '== 2. TLS to the Capella control plane, from inside ==' -ForegroundColor Cyan

$tlsProbe = @'
import urllib.request, urllib.error, ssl, sys
url = "https://cloudapi.cloud.couchbase.com/v4/organizations"
try:
    urllib.request.urlopen(url, timeout=25)
    print("REACHED 200")
except urllib.error.HTTPError as e:
    # 401 is a SUCCESS for this probe: the TLS handshake completed and the
    # server answered. We sent no credentials on purpose.
    print(f"REACHED {e.code}")
except urllib.error.URLError as e:
    reason = getattr(e, "reason", e)
    if isinstance(reason, ssl.SSLError) or "CERTIFICATE" in str(reason).upper():
        print(f"TLS_FAILED {reason}")
    else:
        print(f"NETWORK_FAILED {reason}")
except Exception as e:
    print(f"OTHER {type(e).__name__}: {e}")
'@

$caArgs = @()
if ($CorpCaFile -and (Test-Path $CorpCaFile)) {
    $full = (Resolve-Path $CorpCaFile).Path
    $caArgs = @('-v', "${full}:/etc/ssl/certs/corp-ca.pem:ro",
                '-e', 'REQUESTS_CA_BUNDLE=/etc/ssl/certs/corp-ca.pem',
                '-e', 'SSL_CERT_FILE=/etc/ssl/certs/corp-ca.pem')
    Write-Host "   mounting corporate CA: $full"
} else {
    Write-Host '   no CORP_CA_FILE mounted - testing the trust the IMAGE carries,'
    Write-Host '   which now includes anything found in deploy/ca/ at build time.'
}

$tls = Probe $tlsProbe $caArgs
Write-Host "   $tls"
$tlsOk = $tls -match 'REACHED'
Check $tlsOk 'the container completed a TLS handshake with cloudapi'
if (-not $tlsOk -and $tls -match 'TLS_FAILED') {
    Write-Host '   THIS IS THE PREDICTED FAILURE.' -ForegroundColor Yellow
    Write-Host '   python:3.12-slim trusts its bundled CA set, not the machine store.'
    Write-Host '   Export the corporate roots and re-run with -CorpCaFile:'
    Write-Host '     $pem = "$env:USERPROFILE\corp-ca.pem"'
    Write-Host '     Get-ChildItem Cert:\LocalMachine\Root, Cert:\LocalMachine\CA | ForEach-Object {'
    Write-Host '         "-----BEGIN CERTIFICATE-----"'
    Write-Host '         [Convert]::ToBase64String($_.RawData, "InsertLineBreaks")'
    Write-Host '         "-----END CERTIFICATE-----" } | Set-Content -Encoding ascii $pem'
    Write-Host '     .\scripts\run-docker-verification.ps1 -SkipBuild -CorpCaFile $pem'
}

# -- 3. The cluster, by container name on the shared network -------------------

Write-Host ''
Write-Host '== 3. the EE container reaching the cluster ==' -ForegroundColor Cyan

if ($Network -and $ClusterContainer) {
    $clusterProbe = @"
import urllib.request, urllib.error, json
url = "http://${ClusterContainer}:8091/pools"
try:
    body = urllib.request.urlopen(url, timeout=20).read().decode()
    print("REACHED " + json.loads(body).get("implementationVersion", "?"))
except urllib.error.HTTPError as e:
    print(f"REACHED (auth {e.code})")
except Exception as e:
    print(f"FAILED {type(e).__name__}: {e}")
"@
    $cluster = Probe $clusterProbe @('--network', $Network)
    Write-Host "   $cluster"
    Check ($cluster -match 'REACHED') `
        "the cluster answers at ${ClusterContainer}:8091 from inside the network" `
        'this is the address the cluster map advertises, unroutable from the host'
} else {
    Check $false 'cluster reachability could not be tested' 'no container or network'
}

# -- 4. The deployment guard, doing its job ------------------------------------

Write-Host ''
Write-Host '== 4. CB_ADMIN_REQUIRE_DEPLOYMENT refuses a drifted posture ==' -ForegroundColor Cyan
Write-Host '   Declaring capella while handing it BOTH a Capella key and a'
Write-Host '   connection string - which detect_mode() resolves to `both`, the'
Write-Host '   posture that switches capability gating off.'

$drift = docker run --rm `
    -e CB_ADMIN_REQUIRE_DEPLOYMENT=capella `
    -e CAPELLA_API_KEY_SECRET=not-a-real-key `
    -e CB_CONNECTION_STRING=couchbase://somewhere `
    -e CB_USERNAME=u -e CB_PASSWORD=p `
    -e CB_ADMIN_PROFILE=workstation `
    -e CB_ADMIN_TRANSPORT=stdio `
    $Image 2>&1
$driftText = ($drift -join "`n")
$refused = $driftText -match 'REFUSING TO START' -or $driftText -match 'REQUIRE_DEPLOYMENT'
Write-Host ("   " + (($driftText -split "`n") | Select-Object -First 6 | Out-String).Trim())
Check $refused 'the server refused to start' 'a guard that fails open is worse than none'

Write-Host ''
Write-Host '   And the same posture WITHOUT the declaration must still start:'
$nodecl = docker run --rm `
    -e CAPELLA_API_KEY_SECRET=not-a-real-key `
    -e CB_CONNECTION_STRING=couchbase://somewhere `
    -e CB_USERNAME=u -e CB_PASSWORD=p `
    -e CB_ADMIN_PROFILE=workstation `
    -e CB_ADMIN_TRANSPORT=stdio `
    --entrypoint python $Image -c "import server; print('LOADED', len(server._TOOLS))" 2>&1
$nodeclText = ($nodecl -join "`n")
Write-Host "   $(($nodeclText -split "`n" | Select-Object -Last 3) -join ' ')"
Check ($nodeclText -match 'LOADED') 'undeclared posture is unchanged' `
    'the guard is opt-in; inference must behave exactly as before'

# -- 5. What each declared mode loads ------------------------------------------

Write-Host ''
Write-Host '== 5. tools loaded per declared mode ==' -ForegroundColor Cyan

$countProbe = @'
import server
names = [getattr(t, "name", "") for t in server._TOOLS]
print("COUNTS capella=%d admin=%d total=%d" % (
    sum(1 for n in names if n.startswith("capella_")),
    sum(1 for n in names if n.startswith("admin_")),
    len(names)))
'@

foreach ($mode in @('capella', 'self_managed')) {
    $env_args = @('-e', "CB_DEPLOYMENT=$mode",
                  '-e', "CB_ADMIN_REQUIRE_DEPLOYMENT=$mode",
                  '-e', 'CB_ADMIN_PROFILE=workstation',
                  '-e', 'CB_ADMIN_TRANSPORT=stdio')
    if ($mode -eq 'capella') { $env_args += @('-e', 'CAPELLA_API_KEY_SECRET=not-a-real-key') }
    else { $env_args += @('-e', 'CB_CONNECTION_STRING=couchbase://somewhere', '-e', 'CB_USERNAME=u', '-e', 'CB_PASSWORD=p') }

    $out = Probe $countProbe $env_args
    $line = ($out -split "`n" | Where-Object { $_ -match 'COUNTS' }) -join ''
    Write-Host ("   {0,-13} {1}" -f $mode, $(if ($line) { $line } else { ($out -split "`n" | Select-Object -Last 1) }))
    Check ([bool]$line) "$mode starts and loads a tool list"
}

# -- 6. Real MCP tool calls, from inside the container -------------------------
#
# THE CHECK THE OTHERS ARE NOT.
#
# Checks 2 and 3 are raw urllib calls: they prove TLS and routing, not that a
# tool works. Check 5 imports `server` and counts _TOOLS: that is the registry
# being BUILT, not a tool being CALLED. Passing all of those while every tool
# returned an error is a perfectly consistent outcome -- which is the same
# "individually green, collectively unusable" shape the backup family had.
#
# So: start the server over stdio from inside the container, through the real
# MCP client, and call a read tool against each control plane.

Write-Host ''
Write-Host '== 6. real MCP tool calls from inside the container ==' -ForegroundColor Cyan

$toolProbe = @'
import asyncio, json, os, sys

TOOL = os.environ["PROBE_TOOL"]
ARGS = json.loads(os.environ.get("PROBE_ARGS") or "{}")

async def main():
    from mcp import ClientSession, StdioServerParameters, stdio_client
    params = StdioServerParameters(
        command=sys.executable, args=["/app/server.py"], env=dict(os.environ)
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=60)
            listed = await session.list_tools()
            names = [t.name for t in listed.tools]
            if TOOL not in names:
                print(f"TOOL_ABSENT {TOOL} not among {len(names)} advertised tools")
                return
            result = await asyncio.wait_for(
                session.call_tool(TOOL, ARGS), timeout=90
            )
            text = ""
            for block in getattr(result, "content", None) or []:
                if getattr(block, "text", None):
                    text = block.text
                    break
            try:
                body = json.loads(text)
            except Exception:
                print(f"UNPARSEABLE {text[:200]}")
                return
            if isinstance(body, dict) and body.get("_is_error"):
                print(f"TOOL_ERROR {json.dumps(body)[:300]}")
            else:
                size = len(json.dumps(body))
                print(f"TOOL_OK {TOOL} advertised={len(names)} payload_bytes={size}")

asyncio.run(main())
'@

# -- 6a. Capella, from a container with no route to any cluster ----------------
if ($env:CAPELLA_API_KEY_SECRET) {
    # Forward the organization id if the shell has one. A container given only
    # an API key SHOULD still be able to list organizations -- that is the
    # bootstrap case and it is now fixed -- but a deployment normally pins the
    # org, and testing the pinned path is testing what people run.
    $capellaArgs = @(
        '-e', "CAPELLA_API_KEY_SECRET=$($env:CAPELLA_API_KEY_SECRET)",
        '-e', 'CB_DEPLOYMENT=capella',
        '-e', 'CB_ADMIN_REQUIRE_DEPLOYMENT=capella',
        '-e', 'CB_ADMIN_PROFILE=workstation',
        '-e', 'CB_ADMIN_TRANSPORT=stdio',
        '-e', 'CB_ADMIN_READ_ONLY_MODE=true',
        '-e', 'PROBE_TOOL=capella_organizations_list'
    )
    foreach ($name in @('CAPELLA_ORG_ID', 'CB_CAPELLA_ORG_ID')) {
        $value = [Environment]::GetEnvironmentVariable($name)
        if ($value) { $capellaArgs += @('-e', "${name}=${value}") }
    }
    $out = Probe $toolProbe $capellaArgs
    $line = ($out -split "`n" | Where-Object { $_ -match '^(TOOL_OK|TOOL_ERROR|TOOL_ABSENT|UNPARSEABLE)' }) -join ''
    Write-Host "   capella      $line"
    Check ($line -match '^TOOL_OK') 'a Capella tool ANSWERED from inside the container' `
        'not a urllib probe - the MCP client called the tool and got a payload'
} else {
    Check $false 'Capella tool call skipped' 'CAPELLA_API_KEY_SECRET is not set in this shell'
}

# -- 6a-bis. The bootstrap case: an API key and nothing else -------------------
#
# A container holding only a key must be able to ask which organizations that
# key can see. It could not: every primitive resolved an organization id, and
# capella_organizations_list has none in its path, so it was refused with a hint
# naming itself. Found by running this probe, not by reading the code.
if ($env:CAPELLA_API_KEY_SECRET) {
    $bootstrapArgs = @(
        '-e', "CAPELLA_API_KEY_SECRET=$($env:CAPELLA_API_KEY_SECRET)",
        '-e', 'CB_DEPLOYMENT=capella',
        '-e', 'CB_ADMIN_REQUIRE_DEPLOYMENT=capella',
        '-e', 'CB_ADMIN_PROFILE=workstation',
        '-e', 'CB_ADMIN_TRANSPORT=stdio',
        '-e', 'CB_ADMIN_READ_ONLY_MODE=true',
        '-e', 'PROBE_TOOL=capella_organizations_list'
    )
    $out = Probe $toolProbe $bootstrapArgs
    $line = ($out -split "`n" | Where-Object { $_ -match '^(TOOL_OK|TOOL_ERROR|TOOL_ABSENT|UNPARSEABLE)' }) -join ''
    Write-Host "   bootstrap    $line"
    Check ($line -match '^TOOL_OK') 'an API key alone can list organizations' `
        'the first call on a new deployment must not need the answer it returns'
}

# -- 6b. Enterprise Edition, on the cluster network ----------------------------
if ($ClusterContainer -and $Network -and $Username -and $Password) {
    $eeArgs = @(
        '--network', $Network,
        '-e', "CB_CONNECTION_STRING=couchbase://$ClusterContainer",
        '-e', "CB_MGMT_HOST=$ClusterContainer",
        '-e', "CB_USERNAME=$Username",
        '-e', "CB_PASSWORD=$Password",
        '-e', 'CB_DEPLOYMENT=self_managed',
        '-e', 'CB_ADMIN_REQUIRE_DEPLOYMENT=self_managed',
        '-e', 'CB_ADMIN_PROFILE=workstation',
        '-e', 'CB_ADMIN_TRANSPORT=stdio',
        '-e', 'CB_ADMIN_READ_ONLY_MODE=true',
        '-e', 'PROBE_TOOL=admin_bucket_list'
    )
    $out = Probe $toolProbe $eeArgs
    $line = ($out -split "`n" | Where-Object { $_ -match '^(TOOL_OK|TOOL_ERROR|TOOL_ABSENT|UNPARSEABLE)' }) -join ''
    Write-Host "   self_managed $line"
    Check ($line -match '^TOOL_OK') 'an Enterprise Edition tool ANSWERED from inside the container' `
        "against $ClusterContainer on $Network, by container name"
    if ($line -match 'TOOL_ERROR') {
        Write-Host '   The tool was reached and refused. Read the message: a cluster-map'
        Write-Host '   or credential problem is a DIFFERENT finding from a broken tool.'
    }
} else {
    Check $false 'EE tool call skipped' 'need a cluster container, a network, and CB_USERNAME/CB_PASSWORD'
}

# -- Summary -------------------------------------------------------------------

Write-Host ''
if ($script:Failures.Count -eq 0) {
    Write-Host 'CONTAINER VERIFICATION PASSED' -ForegroundColor Green
    Write-Host '  The image builds, refuses a posture that drifted to `both`, and'
    Write-Host '  ANSWERED A REAL TOOL CALL against each control plane from inside a'
    Write-Host '  container -- driven by an MCP client, not a urllib probe.'
    exit 0
}
Write-Host ("{0} check(s) failed:" -f $script:Failures.Count) -ForegroundColor Red
foreach ($f in $script:Failures) { Write-Host "  * $f" -ForegroundColor Red }
exit 1
