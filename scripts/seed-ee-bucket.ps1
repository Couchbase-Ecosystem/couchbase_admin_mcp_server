# Create a bucket and load travel-sample using the tools inside the container.
#
# WHY NOT /sampleBuckets/install
# ------------------------------
# It is synchronous: it withholds its response until the load finishes, so a
# client either blocks for minutes or times out, and a Ctrl+C aborts the request
# before the server commits to the work. Two runs of start-ee-cluster.ps1 and
# one probe run all looked hung at that step for this reason, and the bucket was
# never created.
#
# cbimport runs INSIDE the container against 127.0.0.1, so nothing depends on
# port mapping, alternate addresses, or this host's networking. It also prints
# progress, so a slow load looks slow rather than looking stuck.
#
# The bucket is the point. Every bucket-shaped admin_* tool skips for want of a
# bucket_name, and any bucket resolves it -- travel-sample is preferred only
# because its scopes, collections and indexes reach further tools.
$ErrorActionPreference = 'Continue'
$Container = 'cb-mcp-ee'
$User      = 'Administrator'
$Pass      = 'reticuli'
$Bucket    = 'travel-sample'

function Step($t) { Write-Host "`n== $t" -ForegroundColor Cyan }

Step "what samples ship in this image"
docker exec $Container ls -1 /opt/couchbase/samples/

Step "create the bucket"
docker exec $Container couchbase-cli bucket-create `
    -c 127.0.0.1 -u $User -p $Pass `
    --bucket $Bucket --bucket-type couchbase --bucket-ramsize 256 `
    --enable-flush 1 --wait
if ($LASTEXITCODE -ne 0) {
    Write-Host "   (a non-zero here is fine if it already exists)" -ForegroundColor DarkGray
}

Step "load the sample data"
# --format sample takes the shipped zip. If the flag names differ on this build
# cbimport prints its usage, which is the answer rather than a dead end.
# ?network=default IS LOAD-BEARING.
#
# The first attempt failed with "dial tcp 127.0.0.1:38091: connection refused"
# from INSIDE the container. The SDK auto-selects the external network when its
# bootstrap host matches an alternate address -- and 127.0.0.1 does, because
# that is exactly what we configured the external map to say. So an in-container
# client followed the map meant for host clients and dialled a port that only
# exists out here.
#
# Two things worth taking from that. The alternate map is live and honoured,
# which is the confirmation we wanted. And any tool running INSIDE the network
# must pin network=default, or it will be routed out through the host.
docker exec $Container cbimport json `
    -c "couchbase://127.0.0.1?network=default" -u $User -p $Pass `
    -b $Bucket -d file:///opt/couchbase/samples/travel-sample.zip `
    --format sample --generate-key "%id%"

Step "what is there now"
docker exec $Container couchbase-cli bucket-list -c 127.0.0.1 -u $User -p $Pass
