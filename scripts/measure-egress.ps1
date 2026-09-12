<#
  measure-egress.ps1

  Probe what the network actually does to Capella, with the VPN state recorded on
  every row.

  WHAT QUESTION THIS ANSWERS, AND WHY IT CHANGED
  ----------------------------------------------
  This script was first written to sample the corporate NAT pool, on the theory
  that Capella failures with the tunnel up were a /32 allowlist entry failing to
  track a rotating address. That theory was tested on 2026-09-12 and is wrong:
  on 2026-09-11, with the VPN up, connections failed in three allowlist states --
  with 163.116.250.45/32 alone, with .146/32 added, and with the whole
  163.116.250.0/24 listed. The /24 covers every address the pool can hand out.
  Granularity does not explain it.

  What is left unmeasured is what the tunnel does to port 11207 toward AWS
  us-east-1 specifically. Nothing so far separates PORT from DESTINATION from
  REGION:

      portquiz.net:11207                    connects  -- 11207 not filtered in general,
                                                         but not AWS and not us-east-1
      cloudapi.cloud.couchbase.com:443      works     -- AWS reachable on 443
      svc-d-node-001...:11207               fails     -- the one that matters

  So this now probes a matrix rather than sampling addresses. Each sample records
  the egress address, DNS resolution, and reachability of four targets chosen to
  isolate one variable each.

  IT NEVER CHANGES THE ALLOWLIST. It will READ the allowlist, if a Capella API key
  is in the environment, for one reason: "11207 failed" is only evidence about the
  tunnel if the address in play was listed and active at the time. Without that
  check the run cannot tell the two explanations apart, which is the mistake this
  script exists downstream of.

  WHY -VpnState IS MANDATORY
  --------------------------
  The table in CAPELLA-CONNECTIVITY.md did not record the tunnel state per row,
  and that single omission is why a day went into the wrong explanation: readings
  taken under different tunnel states were compared as though they were
  comparable. A row without its VPN state is not a weak data point, it is an
  unusable one. The parameter has no default because being asked is the point.

  USAGE
  -----
      powershell -File scripts\measure-egress.ps1 -VpnState Up
      powershell -File scripts\measure-egress.ps1 -VpnState Down -Samples 1

  One sample is enough to read the matrix. Repeat over time only if you are
  chasing something intermittent.
#>

[CmdletBinding()]
param(
    # No default, deliberately. See the note above.
    [Parameter(Mandatory = $true)]
    [ValidateSet('Up', 'Down')]
    [string]$VpnState,

    [int]$Samples = 1,
    [int]$IntervalSeconds = 300,

    [string]$Csv = 'egress-samples.csv',

    [string]$ClusterId = 'cpvbgft3fwgwy3eu',
    [string]$OrgId = '42730eb3-53ab-451a-b5eb-8eeb9a92084c',
    [string]$ProjectId = 'be388b87-43cb-4e9b-a3f1-0f837609c4af',
    [string]$ClusterUuid = '85298b32-c01f-417d-8485-44ceb543af4f'
)

$ErrorActionPreference = 'Stop'

# ── The matrix ───────────────────────────────────────────────────────────────
#
# Four targets, each isolating one variable against the one that matters. The
# point is not any single result but which combination comes back.

$Targets = @(
    @{ Key = 'kv';      Host = "svc-d-node-001.$ClusterId.cloud.couchbase.com"; Port = 11207
       Means = 'the operation that fails: AWS us-east-1, port 11207' }
    @{ Key = 'mgmt';    Host = "cb.$ClusterId.cloud.couchbase.com";             Port = 18091
       Means = 'same host family and region, DIFFERENT port -- isolates the port' }
    @{ Key = 'control'; Host = 'cloudapi.cloud.couchbase.com';                  Port = 443
       Means = 'AWS on 443 -- the control plane, known good, the control case' }
    @{ Key = 'port';    Host = 'portquiz.net';                                  Port = 11207
       Means = 'port 11207 to a NON-AWS host -- isolates the port from the destination' }
)

function Get-DirectEgressAddress {
    <#
      The proxy-free probe. `Proxy = $null` is the whole point: without it this
      measures the corporate proxy, which is not the address a direct SDK
      connection leaves from. checkip.amazonaws.com is in us-east-1, the cluster's
      own region, so this is an AWS destination reached directly.
    #>
    param([int]$TimeoutMs = 20000)

    $request = [System.Net.WebRequest]::Create('https://checkip.amazonaws.com')
    $request.Proxy = $null
    $request.Timeout = $TimeoutMs
    $reader = New-Object System.IO.StreamReader($request.GetResponse().GetResponseStream())
    try { return $reader.ReadToEnd().Trim() } finally { $reader.Dispose() }
}

function Test-AddressInBlock {
    param([string]$Address, [string]$Cidr)

    $parts = $Cidr.Split('/')
    if ($parts.Count -ne 2) { return $false }
    $prefix = [int]$parts[1]

    try {
        $addressBytes = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
        $blockBytes = ([System.Net.IPAddress]::Parse($parts[0])).GetAddressBytes()
    } catch { return $false }
    if ($addressBytes.Length -ne $blockBytes.Length) { return $false }

    # Whole bytes then the partial byte. Written out rather than done with a
    # UInt32 conversion because PowerShell's byte order on that conversion is
    # platform-dependent, and the resulting bug would be a silent wrong answer in
    # the one place this script exists to be right.
    $fullBytes = [math]::Floor($prefix / 8)
    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($addressBytes[$i] -ne $blockBytes[$i]) { return $false }
    }
    $remaining = $prefix % 8
    if ($remaining -gt 0) {
        $mask = [byte](0xFF -shl (8 - $remaining))
        if (($addressBytes[$fullBytes] -band $mask) -ne ($blockBytes[$fullBytes] -band $mask)) {
            return $false
        }
    }
    return $true
}

function Get-AllowlistCoverage {
    <#
      READ ONLY. Returns whether the measured address is covered by an ACTIVE
      allowlist entry, and by which one.

      `status` is checked, not just presence. An entry that is listed but still
      pending has not taken effect, and a reachability failure measured in that
      window says nothing about the tunnel -- which is the one hole in the
      evidence this script is trying to close.
    #>
    param([string]$Address)

    if (-not $env:CAPELLA_API_KEY_SECRET) {
        return @{ Known = $false; Reason = 'CAPELLA_API_KEY_SECRET not set' }
    }
    $uri = "https://cloudapi.cloud.couchbase.com/v4/organizations/$OrgId/projects/$ProjectId/clusters/$ClusterUuid/allowedcidrs?perPage=100"
    try {
        $entries = (Invoke-RestMethod -Uri $uri -Headers @{
            Authorization = "Bearer $env:CAPELLA_API_KEY_SECRET"
        }).data
    } catch {
        return @{ Known = $false; Reason = $_.Exception.Message }
    }

    foreach ($entry in $entries) {
        if (Test-AddressInBlock -Address $Address -Cidr $entry.cidr) {
            return @{
                Known  = $true
                Cidr   = $entry.cidr
                Status = $entry.status
                Active = ($entry.status -eq 'active')
            }
        }
    }
    return @{ Known = $true; Cidr = $null; Status = 'not listed'; Active = $false }
}

Write-Host ''
Write-Host "  probing Capella with the VPN $($VpnState.ToUpper())" -ForegroundColor Cyan
Write-Host "  samples : $Samples"
Write-Host "  csv     : $Csv"
Write-Host '  this script never changes the allowlist.'
Write-Host ''

$lastRow = $null

for ($n = 1; $n -le $Samples; $n++) {
    $timestamp = (Get-Date).ToString('o')

    $address = $null
    $probeError = ''
    try { $address = Get-DirectEgressAddress } catch { $probeError = $_.Exception.Message }

    $coverage = if ($address) { Get-AllowlistCoverage -Address $address } else { @{ Known = $false; Reason = 'no address' } }

    # DNS first. Split-tunnel name resolution is a live candidate for the
    # remaining question, and a host that does not resolve is a different failure
    # from one that resolves and does not answer.
    $srv = $null
    try {
        $srv = (Resolve-DnsName -Name "_couchbases._tcp.cb.$ClusterId.cloud.couchbase.com" -Type SRV -ErrorAction Stop |
                Where-Object { $_.Type -eq 'SRV' } | Select-Object -First 1).NameTarget
    } catch { $srv = '(no SRV answer)' }

    $row = [ordered]@{
        timestamp = $timestamp
        vpn       = $VpnState
        address   = $address
        allowlist = if ($coverage.Known) {
                        if ($coverage.Cidr) { "$($coverage.Cidr) [$($coverage.Status)]" } else { 'not listed' }
                    } else { "unknown ($($coverage.Reason))" }
        srv       = $srv
    }

    Write-Host ("  sample {0}/{1}  {2}" -f $n, $Samples, $timestamp)
    Write-Host ("    egress    : {0}" -f $(if ($address) { $address } else { "probe failed: $probeError" }))
    Write-Host ("    allowlist : {0}" -f $row.allowlist)
    Write-Host ("    SRV       : {0}" -f $srv)

    foreach ($target in $Targets) {
        $ok = (Test-NetConnection $target.Host -Port $target.Port -WarningAction SilentlyContinue).TcpTestSucceeded
        $row["$($target.Key)_reachable"] = $ok
        Write-Host ("    {0,-9} : {1,-5}  {2}:{3}" -f $target.Key, $ok, $target.Host, $target.Port)
    }

    [pscustomobject]$row | Export-Csv -Path $Csv -NoTypeInformation -Append
    $lastRow = $row
    Write-Host ''

    if ($n -lt $Samples) { Start-Sleep -Seconds $IntervalSeconds }
}

# ── Reading the matrix ───────────────────────────────────────────────────────
#
# Stated as what each combination RULES OUT, not as a conclusion. Every wrong
# answer in this investigation came from a plausible cause asserted before the
# distinguishing test was run.

Write-Host '  ── what this run rules out ──' -ForegroundColor Cyan

if (-not $lastRow) { Write-Host '  nothing measured.'; exit 1 }

$kv = $lastRow.kv_reachable
$mgmt = $lastRow.mgmt_reachable
$control = $lastRow.control_reachable
$port = $lastRow.port_reachable

if ($kv) {
    Write-Host "  kv:11207 ANSWERED with the VPN $VpnState. Nothing is broken in this state." -ForegroundColor Green
    Write-Host '  If this is VPN Up, that contradicts 2026-09-11 and the allowlist entry'
    Write-Host '  under test is the difference. Record it.'
} else {
    Write-Host "  kv:11207 did not answer with the VPN $VpnState." -ForegroundColor Yellow

    if ($lastRow.allowlist -like '*not listed*') {
        Write-Host '  BUT the measured address is not in the allowlist, so this sample says'
        Write-Host '  nothing about the tunnel. Add the address, wait for status=active, re-run.'
    } elseif ($lastRow.allowlist -notlike '*[active]*') {
        Write-Host '  BUT the covering entry is not active yet. An entry that has not taken'
        Write-Host '  effect and a blocked path are the same timeout. Wait and re-run --'
        Write-Host '  this is exactly the hole in the 2026-09-11 evidence.'
    } else {
        Write-Host '  The address IS covered by an active entry, so this is not the allowlist.'
        if ($port) {
            Write-Host '  11207 reaches a non-AWS host, so the port is not filtered in general.'
        } else {
            Write-Host '  11207 also fails to a non-AWS host: the port is blocked outright here,'
            Write-Host '  which is a simpler explanation than anything AWS-specific.'
        }
        if ($mgmt) {
            Write-Host '  18091 to the same cluster ANSWERS: the destination and region are'
            Write-Host '  reachable and the problem is specific to port 11207 on that path.'
        } elseif ($control) {
            Write-Host '  18091 fails but cloudapi:443 works: AWS is reachable, the cluster'
            Write-Host '  hostnames are not. Look at split-tunnel routing or DNS for'
            Write-Host "  *.$ClusterId.cloud.couchbase.com rather than at ports."
        } else {
            Write-Host '  Even cloudapi:443 fails. This is broader than Capella -- check the'
            Write-Host '  tunnel itself before drawing any conclusion about 11207.'
        }
    }
}

Write-Host ''
Write-Host '  The /24 widening is NOT indicated by any result here. It was tested on'
Write-Host '  2026-09-11 and did not restore connectivity with the tunnel up.'
Write-Host ''
