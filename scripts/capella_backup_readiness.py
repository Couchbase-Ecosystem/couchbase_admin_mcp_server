"""What would it take to make Capella backup work end to end?

READ-ONLY. Nothing here creates, deletes or restores anything. It answers the
questions that decide whether the write path CAN be tested, before anyone tries
and misreads a plan restriction as a broken tool.

WHAT IS ALREADY KNOWN, AND HOW
==============================
`handlers/capella/spec.py` carries LIVE_VERIFIED statuses recorded against a real
organization:

    capella_backups_list        200   answered
    capella_backup_get          200   answered
    capella_backup_create       405   route matched, method never sent
    capella_backup_cycle_delete 405   route matched, method never sent
    capella_backup_restore      405   route matched, method never sent

405 comes from an OPTIONS probe of a MATCHED route -- a wrong path answers 404 --
so the paths are confirmed and the BODIES are not. The reads are demonstrated.
The writes are unverified, which is not the same as broken.

WHAT THIS SCRIPT ESTABLISHES
============================
  1. Which clusters exist, and their support plan. Managed backup is not
     available on every tier, and a plan restriction returns a 4xx that looks
     exactly like a malformed body.
  2. Which buckets exist per cluster, with the base64 bucket_id the v4 backup
     endpoints take -- v4 uses bucket_id, keyspaces use NAMES, and ns_server uses
     bucket_name. Three vocabularies for one object.
  3. Whether any backup ALREADY EXISTS. Restore cannot be tested without one,
     and a backup takes time to complete, so this decides the sequencing.
  4. Whether the four parked backupSchedule paths match a real route, by OPTIONS.
     They were transcribed from the reference and never probed.
  5. Which project is safe to write in. It reports what each project HOLDS, so
     the choice is made from data rather than from whichever id was in scope.

USAGE
-----
    uv run python scripts/capella_backup_readiness.py

Needs CAPELLA_API_KEY_SECRET (the SECRET, not the access key id). The VPN does
not matter: this is the v4 control plane on 443, which the per-cluster IP
allowlist does not gate. See CAPELLA-CONNECTIVITY.md.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("CB_CAPELLA_API_URL", "https://cloudapi.cloud.couchbase.com").rstrip("/")
TIMEOUT = 30


def call(path: str, method: str = "GET") -> tuple[int, object]:
    """Return (status, parsed-body-or-text). Never raises on an HTTP error.

    The status is the finding here, so a 403 must come back as 403 rather than
    as an exception that gets summarised as "failed".
    """
    token = os.environ.get("CAPELLA_API_KEY_SECRET", "").strip()
    request = urllib.request.Request(
        f"{BASE}{path}",
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            raw = response.read().decode("utf-8", "replace")
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw
    except Exception as exc:  # noqa: BLE001
        return 0, f"{type(exc).__name__}: {exc}"


def rows(payload: object) -> list:
    """v4 list envelopes are NOT uniform.

    Observed shapes: {"data":[...]}, {"data":{"data":[...]}}, and a bare list.
    Guessing one of them is how a populated response reads as empty.
    """
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("data"), list):
            return data["data"]
    return []


def main() -> int:
    if not os.environ.get("CAPELLA_API_KEY_SECRET"):
        print("CAPELLA_API_KEY_SECRET is not set. Run cbenv.bat, then a NEW window.")
        print("It must be the SECRET, not CAPELLA_ACCESS_KEY_ID -- and the 401")
        print("Capella returns for the wrong one blames the IP allowlist, which")
        print("sends you debugging the network instead of the credential.")
        return 1

    status, payload = call("/v4/organizations")
    if status != 200:
        print(f"GET /v4/organizations -> {status}")
        print(json.dumps(payload, indent=2)[:800] if not isinstance(payload, str) else payload[:800])
        return 1

    organizations = rows(payload)
    print(f"\norganizations visible: {len(organizations)}")

    findings: list[str] = []
    backup_capable: list[str] = []

    for org in organizations:
        org_id = org.get("id")
        print(f"\n=== org {org.get('name')} ({org_id}) ===")

        status, payload = call(f"/v4/organizations/{org_id}/projects?perPage=100")
        projects = rows(payload)
        print(f"  projects: {len(projects)} (list status {status})")

        for project in projects:
            project_id = project.get("id")
            status, payload = call(
                f"/v4/organizations/{org_id}/projects/{project_id}/clusters?perPage=100"
            )
            clusters = rows(payload)
            print(f"\n  -- project {project.get('name')} ({project_id}): "
                  f"{len(clusters)} cluster(s)")

            for cluster in clusters:
                cluster_id = cluster.get("id")
                plan = (cluster.get("support") or {}).get("plan", "?")
                tier = (cluster.get("support") or {}).get("timezone", "")
                state = cluster.get("currentState", "?")
                print(f"     cluster {cluster.get('name')} ({cluster_id})")
                print(f"        state={state}  support.plan={plan} {tier}")

                # Buckets, with the id the backup endpoints actually take.
                status, payload = call(
                    f"/v4/organizations/{org_id}/projects/{project_id}"
                    f"/clusters/{cluster_id}/buckets?perPage=100"
                )
                buckets = rows(payload)
                for bucket in buckets:
                    name = bucket.get("name")
                    bucket_id = bucket.get("id") or base64.b64encode(
                        (name or "").encode()
                    ).decode()
                    print(f"        bucket {name!r}  bucket_id={bucket_id}")

                # Does a backup already exist? Restore cannot be tested without one.
                status, payload = call(
                    f"/v4/organizations/{org_id}/projects/{project_id}"
                    f"/clusters/{cluster_id}/backups?perPage=100"
                )
                existing = rows(payload)
                print(f"        backups: {len(existing)} (list status {status})")
                for backup in existing[:10]:
                    # What is already there decides whether RESTORE can be
                    # tested at all: it needs a completed backup, and a backup
                    # takes time, so an existing one removes a wait and a write.
                    print(
                        "          backup {id}  bucket={bucket}  "
                        "state={state}  cycle={cycle}".format(
                            id=backup.get("id", "?"),
                            bucket=backup.get("bucketName") or backup.get("bucket", "?"),
                            state=backup.get("status") or backup.get("state", "?"),
                            cycle=backup.get("cycleId", "?"),
                        )
                    )
                if status == 200:
                    backup_capable.append(f"{cluster.get('name')} ({cluster_id})")
                elif status in (402, 403):
                    findings.append(
                        f"{cluster.get('name')}: backups list -> {status}. That is a "
                        "PLAN or PERMISSION refusal, not a broken path -- managed "
                        "backup is not on every tier."
                    )
                elif status == 404:
                    findings.append(
                        f"{cluster.get('name')}: backups list -> 404, which would "
                        "mean the shipped path is wrong. It is recorded as LIVE "
                        "200 in spec.py, so this is a real regression."
                    )

                # ── The backup SCHEDULE route, by sweep ──────────────────
                #
                # The path transcribed from the reference returned Go's default
                # "404 page not found" -- the response an HTTP mux gives when
                # NOTHING matched -- and a deliberately impossible path returned
                # the identical body. So that path is not a route, and the
                # transcription was wrong.
                #
                # That same fact is the discriminator that makes a sweep sound:
                #
                #   plain "404 page not found"  -> no route of that shape exists
                #   a JSON body with a code     -> route matched, object missing
                #
                # A known-good route with a bogus id is probed first to prove the
                # discriminator actually distinguishes, rather than assuming it.
                if buckets:
                    first = buckets[0]
                    bid = first.get("id") or base64.b64encode(
                        (first.get("name") or "").encode()
                    ).decode()
                    cluster_base = (
                        f"/v4/organizations/{org_id}/projects/{project_id}"
                        f"/clusters/{cluster_id}"
                    )

                    print("        -- backup schedule route sweep --")

                    # Control 1: a REAL route, missing object. Establishes what a
                    # matched-route 404 looks like on this API.
                    bogus = "00000000-0000-0000-0000-000000000000"
                    ctl_status, ctl_body = call(f"{cluster_base}/backups/{bogus}")
                    ctl_text = (
                        json.dumps(ctl_body) if not isinstance(ctl_body, str) else ctl_body
                    )
                    matched_shape = ctl_text.strip().startswith("{")
                    print(f"          control  real route + bogus id -> {ctl_status}: "
                          f"{ctl_text[:120]}")
                    if not matched_shape:
                        findings.append(
                            "the matched-route control did not return a JSON body, so "
                            "plain-text 404 cannot be used to tell a missing route from "
                            "a missing object. The sweep below is inconclusive."
                        )

                    # The per-bucket backupSchedule spellings are kept as a
                    # REGRESSION check: all seven were disconfirmed on
                    # 2026-09-12, and if one ever starts answering that is a new
                    # API surface worth knowing about, not a quiet win.
                    snapshot = f"{cluster_base}/cloudsnapshotbackups"
                    candidates = [
                        ("buckets/{bid}/backupSchedule", f"{cluster_base}/buckets/{bid}/backupSchedule"),
                        ("buckets/{bid}/backupschedule", f"{cluster_base}/buckets/{bid}/backupschedule"),
                        ("buckets/{bid}/backup-schedule", f"{cluster_base}/buckets/{bid}/backup-schedule"),
                        ("buckets/{bid}/backup/schedule", f"{cluster_base}/buckets/{bid}/backup/schedule"),
                        ("buckets/{bid}/backups/schedule", f"{cluster_base}/buckets/{bid}/backups/schedule"),
                        ("backupSchedule (cluster level)", f"{cluster_base}/backupSchedule"),
                        ("backupschedule (cluster level)", f"{cluster_base}/backupschedule"),

                        # ── The cloud snapshot subsystem ─────────────────────
                        # Confirmed live: the list answers 200 and the schedule
                        # answers 204. The rest of the family is transcribed from
                        # the Terraform provider's client as listed in
                        # spec_pending.py, and has never been probed. This is the
                        # probe.
                        ("cloudsnapshotbackupschedule", f"{cluster_base}/cloudsnapshotbackupschedule"),
                        ("cloudsnapshotbackups", snapshot),
                        ("cloudsnapshotbackups/regions", f"{snapshot}/regions"),
                        ("cloudsnapshotbackups/restores", f"{snapshot}/restores"),
                        # A bogus id, so a matched route answers with the JSON
                        # not-found shape rather than a mux 404. That tells the
                        # by-id route apart from an absent one.
                        ("cloudsnapshotbackups/{id}", f"{snapshot}/{bogus}"),
                        ("cloudsnapshotbackups/{id}/restore", f"{snapshot}/{bogus}/restore"),
                    ]

                    matched = []
                    for label, candidate in candidates:
                        status, body = call(candidate)
                        text = json.dumps(body) if not isinstance(body, str) else body
                        is_json = text.strip().startswith(("{", "["))
                        routed = status != 404 or is_json
                        verdict = "ROUTE MATCHED" if routed else "no such route"
                        print(f"          {label:34} {status:<4} {verdict}")
                        if routed:
                            matched.append((label, candidate, status, text[:200]))

                    # What does the snapshot subsystem actually HOLD? A route
                    # that exists and an object that exists are different claims,
                    # and only the second decides whether restore is testable.
                    snap_status, snap_body = call(f"{snapshot}?perPage=100")
                    if snap_status == 200:
                        snaps = rows(snap_body)
                        print(f"          cloud snapshots present: {len(snaps)}")
                        for snap in snaps[:10]:
                            print("            snapshot {id}  state={state}  "
                                  "created={created}".format(
                                      id=snap.get("id", "?"),
                                      state=snap.get("status") or snap.get("state", "?"),
                                      created=snap.get("createdAt")
                                      or snap.get("created", "?"),
                                  ))
                        if not snaps:
                            findings.append(
                                "the cloud snapshot subsystem is reachable but holds no "
                                "snapshots, so its restore path cannot be exercised "
                                "without creating one."
                            )

                    if matched:
                        print("\n          ROUTES THAT EXIST:")
                        for label, candidate, status, text in matched:
                            print(f"            {label}  ({status})")
                            print(f"              {candidate}")
                            print(f"              {text}")
                        findings.append(
                            "backup schedule / snapshot routes that DO exist: "
                            + ", ".join(label for label, *_ in matched)
                            + ". The four parked ops in spec_pending.py must be "
                            "retargeted to whichever of these is right, or deleted."
                        )
                    else:
                        findings.append(
                            "NO candidate backup-schedule path matched a route on this "
                            "API. The four parked ops in spec_pending.py are based on a "
                            "path that does not exist and must not be promoted. Either "
                            "the endpoint is absent from this API version, or it is "
                            "gated by the support plan (basic), or it lives under a noun "
                            "not tried here."
                        )

    print("\n" + "=" * 70)
    print("WHAT THIS SETTLES")
    print("=" * 70)
    if backup_capable:
        print("\nClusters whose backups endpoint ANSWERED (reads confirmed live):")
        for entry in backup_capable:
            print(f"  * {entry}")
        print("\nThe remaining unknown is the WRITE body, which only a real")
        print("create can settle. Pick a cluster above whose project holds")
        print("nothing you care about, then run the Level 3 plan in")
        print("docs/LIVE_WRITE_TEST_PLAN.md against it.")
    else:
        print("\nNo cluster's backups endpoint answered. Read the statuses above:")
        print("  402/403 -> plan or permission, NOT a broken tool")
        print("  404     -> the shipped path is wrong, which contradicts")
        print("             LIVE_VERIFIED in spec.py and is a real finding")

    if findings:
        print("\nNEEDS A DECISION OR A LOOK:")
        for finding in findings:
            print(f"  * {finding}")

    print("\nNOT ANSWERED HERE, and not guessable:")
    print("  * the backupSchedule request BODY. The reference documents that")
    print("    page for the console and never names the JSON fields, which is")
    print("    why the four parked ops declare no body. The empty-body 422 from")
    print("    --method-probe names them; a guessed schema would look")
    print("    authoritative while being invented.")
    print("  * whether managed backup is the right primitive at all. See the")
    print("    cloudsnapshotbackups note in handlers/capella/spec_pending.py:")
    print("    managed backups cannot be user-named and their bytes come via an")
    print("    emailed console URL, which may not suit an automated restore.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
