"""handlers/cluster.py — Cluster info, nodes, rebalance, failover, auto-failover, server groups.

Changes from upstream:
- Phase 1: ToolAnnotations. Failover, rebalance, node remove, internal/memory
  settings marked destructive.
- Phase 2: Structured err() returns.
"""

from __future__ import annotations

from mcp.types import TextContent, Tool, ToolAnnotations

from .shared import admin_request, err, form_data, ok, quote_path

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
            readOnlyHint=False, destructiveHint=False, idempotentHint=False
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
        description="Configure auto-failover (enabled, timeout, maxCount, failoverOnDataDiskIssues).",
        inputSchema={
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "timeout": {
                    "type": "integer",
                    "description": "Seconds before failover",
                },
                "maxCount": {"type": "integer"},
            },
            "required": ["enabled"],
        },
        annotations=ToolAnnotations(
            readOnlyHint=False, destructiveHint=False, idempotentHint=True
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
            readOnlyHint=False, destructiveHint=False, idempotentHint=False
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
                "parallelDBAndViewCompaction": {"type": "boolean"},
            },
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
        description="Configure email alerts (enabled, emailServer, recipients, alerts list, etc.).",
        inputSchema={
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "sender": {"type": "string"},
                "recipients": {
                    "type": "string",
                    "description": "Comma-separated emails",
                },
                "emailHost": {"type": "string"},
                "emailPort": {"type": "integer"},
                "emailEncrypt": {"type": "boolean"},
                "emailUser": {"type": "string"},
                "emailPass": {"type": "string"},
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
            data = form_data(args)
            return ok(admin_request("POST", "/pools/default", data=data))

        if name == "admin_node_list":
            return ok(admin_request("GET", "/pools/nodes"))

        if name == "admin_node_services_list":
            return ok(admin_request("GET", "/pools/default/nodeServices"))

        if name == "admin_node_add":
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
            data = {"enabled": "true" if args["enabled"] else "false"}
            if args.get("timeout"):
                data["timeout"] = str(args["timeout"])
            if args.get("maxCount"):
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
            data = form_data(args)
            return ok(admin_request("POST", "/controller/setAutoCompaction", data=data))

        if name == "admin_alerts_get":
            return ok(admin_request("GET", "/settings/alerts"))

        if name == "admin_alerts_set":
            data = {}
            for k, v in args.items():
                if v is not None:
                    data[k] = "true" if v is True else "false" if v is False else str(v)
            return ok(admin_request("POST", "/settings/alerts", data=data))

        if name == "admin_alerts_test_email":
            return ok(admin_request("POST", "/settings/alerts/sendTestEmail"))

        return err(f"Unknown cluster tool: {name}", tool=name)

    except Exception as exc:
        return err(f"{type(exc).__name__}: {exc}", tool=name, args=args)
