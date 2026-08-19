"""handlers/cluster.py — Cluster info, nodes, rebalance, failover, auto-failover, server groups.

Changes from upstream:
- Phase 1: ToolAnnotations. Failover, rebalance, node remove, internal/memory
  settings marked destructive.
- Phase 2: Structured err() returns.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .egress import assert_egress_allowed
from .shared import (
    admin_request,
    arg_truthy,
    err,
    form_data,
    form_data_declared,
    ok,
    quote_path,
    refuse_undeclared,
)

#: Keys /settings/alerts accepts. Mass assignment on a settings endpoint lets a
#: confused or injected agent set fields nobody reviewed, so the payload is built
#: from this list rather than from whatever the caller sent.
_ALERTS_KEYS: frozenset[str] = frozenset(
    {
        "enabled",
        "recipients",
        "sender",
        "emailUser",
        "emailPass",
        "emailHost",
        "emailPort",
        "emailEncrypt",
        "alerts",
        "pop_up_alerts",
    }
)


TOOLS: list[Tool] = [
    # ── Cluster info ────────────────────────────────────────────────────
    Tool(
        name="admin_cluster_info",
        description="Get high-level cluster information (name, nodes, memory quotas, etc.).",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_cluster_details",
        description="Get detailed cluster info including node services and storage.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_cluster_tasks",
        description="List all ongoing cluster tasks (rebalance, compaction, index, etc.).",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_cluster_name_set",
        description="Rename the cluster.",
        inputSchema={
            "type": "object",
            "properties": {"clusterName": {"type": "string"}},
            "required": ["clusterName"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_cluster_memory_set",
        description=(
            "Set memory quotas for services (dataMemoryQuota, indexMemoryQuota, "
            "ftsMemoryQuota, cbasMemoryQuota, eventingMemoryQuota). "
            "Misconfiguration can crash services. Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "dataMemoryQuota": {"type": "integer", "description": "MB"},
                "indexMemoryQuota": {"type": "integer", "description": "MB"},
                "ftsMemoryQuota": {"type": "integer", "description": "MB"},
                "cbasMemoryQuota": {"type": "integer", "description": "MB"},
                "eventingMemoryQuota": {"type": "integer", "description": "MB"},
                "confirm": {"type": "boolean"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=True
        ),
    ),
    # ── Nodes ────────────────────────────────────────────────────────────
    Tool(
        name="admin_node_list",
        description="List all nodes in the cluster with status and services.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_node_services_list",
        description="List services running on each node.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_node_add",
        description="Add a node to the cluster.",
        inputSchema={
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "IP or hostname of the new node",
                },
                "user": {
                    "type": "string",
                    "description": "Admin username on the new node",
                },
                "password": {"type": "string"},
                "services": {
                    "type": "string",
                    "description": "Comma-separated: kv,n1ql,index,fts,cbas,eventing",
                },
            },
            "required": ["hostname", "user", "password"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False
        ),
    ),
    Tool(
        name="admin_node_remove",
        description="Eject (remove) a node from the cluster. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "otpNode": {
                    "type": "string",
                    "description": "OTP node string, e.g. ns_1@hostname",
                },
                "confirm": {"type": "boolean"},
            },
            "required": ["otpNode"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=True
        ),
    ),
    # ── Rebalance ────────────────────────────────────────────────────────
    Tool(
        name="admin_rebalance_start",
        description=(
            "Start a rebalance operation. Provide ejectedNodes and/or knownNodes "
            "OTP strings. Rebalance moves data and can stress the cluster. "
            "Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "ejectedNodes": {
                    "type": "string",
                    "description": "Comma-separated OTP nodes to eject",
                },
                "knownNodes": {
                    "type": "string",
                    "description": "Comma-separated OTP nodes known in cluster",
                },
                "confirm": {"type": "boolean"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False
        ),
    ),
    Tool(
        name="admin_rebalance_progress",
        description="Get the current rebalance progress.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_rebalance_stop",
        description="Stop an in-progress rebalance. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {"confirm": {"type": "boolean"}},
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=True
        ),
    ),
    # ── Failover ─────────────────────────────────────────────────────────
    Tool(
        name="admin_failover_hard",
        description=(
            "Perform a hard failover on a node. This forcibly removes the node "
            "from the cluster and may cause data loss for unreplicated documents. "
            "Requires confirm:true."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "otpNode": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["otpNode"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False
        ),
    ),
    Tool(
        name="admin_failover_graceful",
        description="Start a graceful failover on a node. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "otpNode": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["otpNode"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False
        ),
    ),
    Tool(
        name="admin_recovery_type_set",
        description="Set the recovery type for a failed-over node (full or delta).",
        inputSchema={
            "type": "object",
            "properties": {
                "otpNode": {"type": "string"},
                "recoveryType": {"type": "string", "enum": ["full", "delta"]},
            },
            "required": ["otpNode", "recoveryType"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
        ),
    ),
    # ── Auto-Failover ─────────────────────────────────────────────────────
    Tool(
        name="admin_autofailover_get",
        description="Get auto-failover settings.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_autofailover_set",
        description=(
            "Configure auto-failover. `failoverOnDataDiskIssues` and "
            "`canAbortRebalance` are now declared and forwarded -- the description "
            "advertised them while the handler silently dropped them and reported "
            "success, so an operator was told disk-issue failover was configured when "
            "it was not."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "timeout": {
                    "type": "integer",
                    "description": "Seconds before failover",
                },
                "maxCount": {"type": "integer"},
                "failoverOnDataDiskIssues[enabled]": {
                    "type": "boolean",
                    "description": "Fail a node over when its data disk reports errors.",
                },
                "failoverOnDataDiskIssues[timePeriod]": {
                    "type": "integer",
                    "description": "Seconds of sustained disk errors before failover (5-3600).",
                },
                "canAbortRebalance": {
                    "type": "boolean",
                    "description": "Allow auto-failover to abort a running rebalance.",
                },
            },
            "required": ["enabled"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_autofailover_reset",
        description="Reset the auto-failover counter.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
        ),
    ),
    # ── Server groups ─────────────────────────────────────────────────────
    Tool(
        name="admin_server_groups_get",
        description="List all server groups (rack-zone awareness).",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_server_group_create",
        description="Create a new server group.",
        inputSchema={
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=False
        ),
    ),
    Tool(
        name="admin_server_group_delete",
        description="Delete an empty server group by UUID. Requires confirm:true.",
        inputSchema={
            "type": "object",
            "properties": {
                "uuid": {"type": "string"},
                "confirm": {"type": "boolean"},
            },
            "required": ["uuid"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_server_group_rename",
        description="Rename a server group.",
        inputSchema={
            "type": "object",
            "properties": {
                "uuid": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["uuid", "name"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
        ),
    ),
    # ── Logging ───────────────────────────────────────────────────────────
    Tool(
        name="admin_logs_collect_start",
        description="Start collecting logs across the cluster.",
        inputSchema={
            "type": "object",
            "properties": {
                "nodes": {
                    "type": "string",
                    "description": "Comma-separated OTP node list, or 'all'",
                },
                "uploadHost": {
                    "type": "string",
                    "description": "Optional upload target hostname",
                },
                "customer": {"type": "string"},
                "ticket": {"type": "string"},
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=True, idempotentHint=False
        ),
    ),
    Tool(
        name="admin_logs_collect_cancel",
        description="Cancel an in-progress log collection.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
        ),
    ),
    # ── Auto-compaction ───────────────────────────────────────────────────
    Tool(
        name="admin_autocompaction_get",
        description="Get global auto-compaction settings.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_autocompaction_set",
        description=(
            "Set global auto-compaction settings. Key fields: "
            "databaseFragmentationThreshold[percentage|size], "
            "viewFragmentationThreshold[percentage|size], "
            "parallelDBAndViewCompaction, allowedTimePeriod[fromHour,fromMinute,"
            "toHour,toMinute,abortOutside]."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "databaseFragmentationThreshold[percentage]": {"type": "integer"},
                "databaseFragmentationThreshold[size]": {"type": "integer"},
                # Declared, because the description advertises them and
                # refuse_undeclared was rejecting them -- so the documented view
                # compaction and time-window settings were unreachable through the
                # tool that documents them.
                "viewFragmentationThreshold[percentage]": {"type": "integer"},
                "viewFragmentationThreshold[size]": {"type": "integer"},
                "allowedTimePeriod[fromHour]": {"type": "integer"},
                "allowedTimePeriod[fromMinute]": {"type": "integer"},
                "allowedTimePeriod[toHour]": {"type": "integer"},
                "allowedTimePeriod[toMinute]": {"type": "integer"},
                "allowedTimePeriod[abortOutside]": {"type": "boolean"},
                "parallelDBAndViewCompaction": {"type": "boolean"},
            },
            # /controller/setAutoCompaction REQUIRES this one, so a minimal call
            # without it 400s. Declaring it required makes that a schema error the
            # model can see rather than a cluster round-trip.
            "required": ["parallelDBAndViewCompaction"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
        ),
    ),
    # ── Alerts & email ─────────────────────────────────────────────────────
    Tool(
        name="admin_alerts_get",
        description="Get email alert configuration.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=True, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_alerts_set",
        description=(
            "Configure email alerts. NOTE: /settings/alerts is a full REPLACE, so any "
            "key omitted reverts to the endpoint's default. This tool reads the "
            "current settings first and merges, so a partial call changes only what "
            "you name. `alerts` is the list of alert TYPES that fire — omitting it "
            "used to disable all of them while reporting success."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "sender": {"type": "string"},
                "recipients": {
                    "type": "string",
                    "description": "Comma-separated emails",
                },
                # `emailHost`, not `emailServer`: the description advertised the
                # latter, which is the sub-document name in the GET response, and it
                # was silently dropped on the way in.
                "emailHost": {"type": "string"},
                "emailPort": {"type": "integer"},
                "emailEncrypt": {"type": "boolean"},
                "emailUser": {"type": "string"},
                "emailPass": {"type": "string"},
                "alerts": {
                    "type": "string",
                    "description": (
                        "Comma-separated alert types to enable, e.g. "
                        "auto_failover_node,disk_usage_analyzer_failed,ip_address_changed. "
                        "Omit to preserve the cluster's current list."
                    ),
                },
                "pop_up_alerts": {
                    "type": "string",
                    "description": (
                        "Comma-separated alert types shown in the UI. Omit to "
                        "preserve the current list."
                    ),
                },
            },
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
        ),
    ),
    Tool(
        name="admin_alerts_test_email",
        description="Send a test email using current alert configuration.",
        inputSchema={"type": "object", "properties": {}},
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=False
        ),
    ),
]


def handle(name: str, args: dict) -> list[TextContent]:
    try:
        if name == "admin_cluster_info":
            return ok(admin_request("GET", "/pools"))

        if name == "admin_cluster_details":
            return ok(admin_request("GET", "/pools/default"))

        if name == "admin_cluster_tasks":
            return ok(admin_request("GET", "/pools/default/tasks"))

        if name == "admin_cluster_name_set":
            return ok(
                admin_request(
                    "POST", "/pools/default", data={"clusterName": args["clusterName"]}
                )
            )

        if name == "admin_cluster_memory_set":
            # /pools/default accepts far more than this tool declares (including
            # clusterName and node-provisioning fields), so an undeclared key here was
            # a real cluster-wide configuration change.
            refusal = refuse_undeclared(args, name, TOOLS, endpoint="/pools/default")
            if refusal is not None:
                return refusal
            data = form_data_declared(args, name, TOOLS)
            # ns_server's POST /pools/default names the DATA service quota
            # `memoryQuota`; there is no `dataMemoryQuota` parameter, so the quota was
            # silently never applied (or 400d, depending on build). The friendly name
            # stays in the schema -- it reads unambiguously next to indexMemoryQuota
            # and ftsMemoryQuota -- but it must be translated on the way out.
            if "dataMemoryQuota" in data:
                data["memoryQuota"] = data.pop("dataMemoryQuota")
            return ok(admin_request("POST", "/pools/default", data=data))

        if name == "admin_node_list":
            return ok(admin_request("GET", "/pools/nodes"))

        if name == "admin_node_services_list":
            return ok(admin_request("GET", "/pools/default/nodeServices"))

        if name == "admin_node_add":
            # The cluster dials out to this host, and a node that joins receives
            # replica data.
            assert_egress_allowed(args["hostname"], field="hostname", tool=name)
            data = {
                "hostname": args["hostname"],
                "user": args["user"],
                "password": args["password"],
                "services": args.get("services", "kv"),
            }
            return ok(admin_request("POST", "/controller/addNode", data=data))

        if name == "admin_node_remove":
            return ok(
                admin_request(
                    "POST",
                    "/controller/ejectNode",
                    data={"otpNode": args["otpNode"]},
                )
            )

        if name == "admin_rebalance_start":
            data: dict = {}
            if args.get("ejectedNodes"):
                data["ejectedNodes"] = args["ejectedNodes"]
            if args.get("knownNodes"):
                data["knownNodes"] = args["knownNodes"]
            return ok(admin_request("POST", "/controller/rebalance", data=data))

        if name == "admin_rebalance_progress":
            return ok(admin_request("GET", "/pools/default/rebalanceProgress"))

        if name == "admin_rebalance_stop":
            return ok(admin_request("POST", "/controller/stopRebalance"))

        if name == "admin_failover_hard":
            return ok(
                admin_request(
                    "POST", "/controller/failOver", data={"otpNode": args["otpNode"]}
                )
            )

        if name == "admin_failover_graceful":
            return ok(
                admin_request(
                    "POST",
                    "/controller/startGracefulFailover",
                    data={"otpNode": args["otpNode"]},
                )
            )

        if name == "admin_recovery_type_set":
            return ok(
                admin_request(
                    "POST",
                    "/controller/setRecoveryType",
                    data={
                        "otpNode": args["otpNode"],
                        "recoveryType": args["recoveryType"],
                    },
                )
            )

        if name == "admin_autofailover_get":
            return ok(admin_request("GET", "/settings/autoFailover"))

        if name == "admin_autofailover_set":
            # arg_truthy, not raw truthiness. The schema declares enabled as a
            # boolean and nothing enforced that, so the string "false" -- non-empty,
            # therefore truthy -- ENABLED auto-failover on a destructiveHint tool.
            #
            # `is not None`, not truthiness, on the two numerics: `if
            # args.get("timeout")` silently dropped timeout=0 and maxCount=0 while
            # still returning success, so the caller was told a value had been set
            # that was never sent. 0 is out of ns_server's accepted range and it will
            # say so -- an explicit rejection the caller can act on, which is better
            # than a false success.
            data = {"enabled": "true" if arg_truthy(args["enabled"]) else "false"}
            # The disk-issue and abort-rebalance parameters, which the description has
            # always advertised. They were neither declared nor forwarded, and with no
            # refuse_undeclared they were dropped in silence.
            for flag in ("failoverOnDataDiskIssues[enabled]", "canAbortRebalance"):
                if args.get(flag) is not None:
                    data[flag] = "true" if arg_truthy(args[flag]) else "false"
            if args.get("failoverOnDataDiskIssues[timePeriod]") is not None:
                data["failoverOnDataDiskIssues[timePeriod]"] = str(
                    args["failoverOnDataDiskIssues[timePeriod]"]
                )
            if args.get("timeout") is not None:
                data["timeout"] = str(args["timeout"])
            if args.get("maxCount") is not None:
                data["maxCount"] = str(args["maxCount"])
            return ok(admin_request("POST", "/settings/autoFailover", data=data))

        if name == "admin_autofailover_reset":
            return ok(admin_request("POST", "/settings/autoFailover/resetCount"))

        if name == "admin_server_groups_get":
            return ok(admin_request("GET", "/pools/default/serverGroups"))

        if name == "admin_server_group_create":
            return ok(
                admin_request(
                    "POST", "/pools/default/serverGroups", data={"name": args["name"]}
                )
            )

        if name == "admin_server_group_delete":
            sg = quote_path(args["uuid"])
            return ok(admin_request("DELETE", f"/pools/default/serverGroups/{sg}"))

        if name == "admin_server_group_rename":
            sg = quote_path(args["uuid"])
            return ok(
                admin_request(
                    "PUT",
                    f"/pools/default/serverGroups/{sg}",
                    data={"name": args["name"]},
                )
            )

        if name == "admin_logs_collect_start":
            data = {}
            # uploadHost receives a full diagnostic bundle from every node —
            # query text, document keys, configuration, sometimes credentials.
            if args.get("uploadHost"):
                assert_egress_allowed(args["uploadHost"], field="uploadHost", tool=name)
            for k in ("nodes", "uploadHost", "customer", "ticket"):
                if args.get(k):
                    data[k] = args[k]
            return ok(
                admin_request("POST", "/controller/startLogsCollection", data=data)
            )

        if name == "admin_logs_collect_cancel":
            return ok(admin_request("POST", "/controller/cancelLogsCollection"))

        if name == "admin_autocompaction_get":
            return ok(admin_request("GET", "/settings/autoCompaction"))

        if name == "admin_autocompaction_set":
            refusal = refuse_undeclared(
                args, name, TOOLS, endpoint="/controller/setAutoCompaction"
            )
            if refusal is not None:
                return refusal
            data = form_data_declared(args, name, TOOLS)
            return ok(admin_request("POST", "/controller/setAutoCompaction", data=data))

        if name == "admin_alerts_get":
            return ok(admin_request("GET", "/settings/alerts"))

        if name == "admin_alerts_set":
            if args.get("emailHost"):
                assert_egress_allowed(args["emailHost"], field="emailHost", tool=name)
            # Per-tool key allow-list. This used to forward EVERY caller-supplied
            # key to /settings/alerts, so a model could invent fields and have
            # them applied to a settings endpoint verbatim.
            unknown = refuse_undeclared(args, name, TOOLS)
            if unknown:
                return err(unknown, tool=name)
            # READ-MODIFY-WRITE. POST /settings/alerts is a full replace, so a call
            # that named only `recipients` reset everything else -- most damagingly
            # `alerts`, the list of TYPES that fire, which the schema did not even
            # declare. The result was `"alerts": []`: the tool reported alerting
            # "enabled" and the cluster silently stopped emailing on auto-failover,
            # disk-full and OOM. Merging means a partial call changes only what it
            # names.
            supplied = {k: v for k, v in args.items() if k in _ALERTS_KEYS}
            merged: dict = {}
            current = admin_request("GET", "/settings/alerts")
            # REFUSE on an unexpected shape rather than merging against nothing.
            #
            # `if isinstance(current, dict)` alone let an empty body ({"status":"ok"}),
            # a text/plain body, or a list skip the merge entirely -- and because this
            # endpoint is a full replace, proceeding with an empty base wiped enabled,
            # sender, alerts and emailServer and reported success. That is precisely
            # the defect the merge was added to prevent, reachable whenever the GET
            # answers with something unexpected.
            if not isinstance(current, dict) or not (
                set(current) & (_ALERTS_KEYS | {"emailServer", "pop_up_alerts"})
            ):
                return err(
                    "Could not read the current alert settings, so the change was not "
                    "attempted.",
                    tool=name,
                    hint=(
                        "POST /settings/alerts REPLACES the whole document, so a "
                        "partial update must be merged onto the current values. "
                        "Without a readable GET this call would silently clear every "
                        "alert type. Check the cluster with admin_alerts_get."
                    ),
                )
            if isinstance(current, dict):
                for key in _ALERTS_KEYS:
                    if key in supplied:
                        continue
                    if key in current and current[key] not in (None, ""):
                        merged[key] = current[key]
                    elif key in ("alerts", "pop_up_alerts") and isinstance(
                        current.get(key), list
                    ):
                        merged[key] = ",".join(str(a) for a in current[key])
                # The SMTP host/port/user live in an `emailServer` sub-document on the
                # way out but are flat parameters on the way in.
                server = current.get("emailServer")
                if isinstance(server, dict):
                    for out_key, in_key in (
                        ("host", "emailHost"),
                        ("port", "emailPort"),
                        ("encrypt", "emailEncrypt"),
                        ("user", "emailUser"),
                    ):
                        if in_key not in supplied and server.get(out_key) not in (
                            None,
                            "",
                        ):
                            merged[in_key] = server[out_key]
            merged.update(supplied)
            # Comma-separated, not JSON. form_value JSON-encodes a list, and
            # /settings/alerts parses these two as comma-separated tokens -- a JSON
            # array is unparseable, which on this endpoint means "no alert types".
            for key in ("alerts", "pop_up_alerts"):
                if isinstance(merged.get(key), (list, tuple)):
                    merged[key] = ",".join(str(a) for a in merged[key])
            data = form_data(merged, exclude=("confirm",))
            return ok(admin_request("POST", "/settings/alerts", data=data))

        if name == "admin_alerts_test_email":
            return ok(admin_request("POST", "/settings/alerts/sendTestEmail"))

        return err(f"Unknown cluster tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
