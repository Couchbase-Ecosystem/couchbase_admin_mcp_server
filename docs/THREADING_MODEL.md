# Threading model

Written 2026-11-02, read from the code at the commit named in `CHANGELOG.md`. Each
statement names the file it comes from. Nothing here was measured under load: where a
behavior is read from the code and not tested, it says so.

## 1. One event loop, worker threads for everything that blocks

`server.py` runs one asyncio event loop (`asyncio.run` in `main()`). The MCP
transport (stdio or streamable HTTP) lives on that loop. Every handler is
**synchronous and blocking** (it makes HTTP calls with retries, or SDK calls), so the
dispatch never runs a handler on the loop:

| Step in `call_tool` (`server.py`) | Where it runs | Why |
| --- | --- | --- |
| Resolve the caller (`current_claims`) | A worker thread, via `asyncio.to_thread` | Validating a token can make an outbound HTTPS call to the identity provider. On the loop, one slow provider would stall every client |
| Gates: scope, ceiling, confirmation, dry run | The loop | Pure in-memory decisions, no I/O |
| The handler (`handler.handle`) | A worker thread, via `loop.run_in_executor(None, ...)` | Handlers block |
| Audit record | The thread that made the decision | `audit.emit_tool_call` writes through the logging module |

Two different thread hops are used on purpose, and they are not interchangeable:

- `asyncio.to_thread` copies the current context into the worker. The caller
  resolution needs that, because `request_ctx` (set by the MCP library for this
  request) must be visible there. `server.py` says so beside the call.
- `run_in_executor` does **not** copy the context. The handler wrapper therefore
  re-establishes what it needs inside the worker: `authz.caller_context` sets whether
  a human is present for this call, held as an attribute on the current thread
  (`authz.py`, not as a module-level thread-local, because the test suite reloads
  modules and two copies of a thread-local made the console and the guard disagree).

## 2. State shared between threads

| State | File | Protection | Notes |
| --- | --- | --- | --- |
| Cached SDK cluster connection `_cluster` | `handlers/shared.py` `get_sdk_cluster` | `_cluster_lock` (a `threading.Lock`), taken around the whole build (double-checked) | Two threads that both call it first build one cluster, not two. The code publishes only after `wait_until_ready` succeeds, so a half-built cluster is never cached, and a failed build releases the lock and leaves the cache empty. Decided in [Q-001 in questions.md](questions.md) on 2026-11-05. Held by `tests/test_cluster_cache_lock.py` |
| OIDC discovery cache, unknown-key-id memo, JWKS refresh budget | `auth/oidc.py` | `_throttle_lock` (a `threading.Lock`) for the throttle structures. `_discovery_cache` has no lock found | The lock exists because validation runs on worker threads from two places (the edge middleware and the dispatch). An unlocked dict raised "dictionary changed size during iteration", which turned into denials of legitimate tokens |
| Audit sink handle | `audit.py` | Module globals set at start-up | Not checked for concurrent first use. Not measured |
| Logging configuration | `logging_config.py` | Module global `_resolved_config` | Set once at start-up |
| Capella cooldown timestamps | `handlers/capella/guardrails.py` | Keyed by scope, not process-global | Reason recorded beside the code: one global timestamp let one scope starve another |
| Console sessions | `auth/session.py` | Not checked | Used by the Flask console only |

## 3. Parallel work inside one tool call

`handlers/capella/fixture.py` imports documents with a `ThreadPoolExecutor` of
`_IMPORT_CONCURRENCY` (8) workers. The importer reads the file one line at a time,
collects a batch of that size, and waits for the batch with `pool.map` before reading
more, so memory stays bounded and the cluster sees at most 8 writes in flight. Results
are tallied on the calling thread only, so the counters need no lock.

## 4. The console is a separate process

`gui/gui_server.py` is a Flask application. It is started separately (`python
gui/gui_server.py` or `gunicorn "gui.gui_server:create_app()"`). It imports the same
handlers and asks the same `authz` module for the decision, but its request threads are
managed by its own server, not by the MCP event loop. [VERIFY] The number of worker
threads under gunicorn is set by the operator's gunicorn options. The repository does not
set it.

## 5. Rules for new code

1. A handler must not assume it runs on the event loop. It runs on a worker thread, and
   several handlers can run at once.
2. Shared mutable state needs a lock, or a comment that says why none is needed.
3. Anything that must see the request context must be reached through `asyncio.to_thread`,
   not `run_in_executor`.
4. A new background thread or pool needs an entry in section 2 or 3 in the same commit (D8).
