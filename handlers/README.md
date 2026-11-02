# handlers/

One module per tool group. The server builds its tool list from each module's `TOOLS` and
routes a call to its `handle(name, arguments)`. Handlers are synchronous and run on worker
threads (`docs/THREADING_MODEL.md`), so they may block but must not assume they are alone.

The map of every module is `docs/MODULE_MAP.md`. The short version:

- `shared.py` is the base: HTTP admin client with retries, SDK connection, response helpers,
  redaction and the confirmation primitives.
- `capella/` is the Capella v4 control plane (declarative registry, HTTP client, guardrails,
  test environments, fixtures through the Data API).
- `fixture.py` and `fixture_core.py` are fixtures on self-managed Enterprise Edition and the
  mechanics shared with Capella.
- `backup_catalog.py` is deliberately outside `capella/`: it annotates backups on both planes.
- `egress.py` is the allowlist for destinations the cluster is asked to contact.
- The rest are the self-managed tool groups: buckets, collections, security, cluster, xdcr,
  indexes, search_admin, stats, diagnostics, eight_x, backup, eventing, encryption, mcp_status.

## Adding a tool group

1. Create the module with `TOOLS` and `handle`. Annotate every tool honestly: the read-only
   catalog and the confirmation gate are built from those flags.
2. Register it in `server.py` (both the `_RAW_TOOLS` list and `_HANDLERS`) and in
   `MODULE_NAMES` in `tests/test_handler_contract.py`. A discovery test fails if the two
   disagree.
3. Add it to `tests/test_tool_group_examples.py` (one tested example per group, decision Q5).
4. Give the module a header and a doc comment on each public item, and update
   `docs/MODULE_MAP.md` in the same commit.
