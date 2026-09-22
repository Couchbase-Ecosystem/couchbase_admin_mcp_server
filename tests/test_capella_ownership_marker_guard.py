"""The ownership marker's survival across an update, and the fail-closed fetch.

The marker is what makes a cluster VISIBLE to `capella_env_list`, `capella_env_status`
and the reaper. A cluster that loses it does not stop existing -- it stops being
collectable, and it goes on billing indefinitely with nothing pointing at it. The
module records the measurement: six live clusters against a ceiling of two.

`capella_cluster_update` is the specific risk. It takes a free-text `description`
that a caller legitimately edits, it is annotated destructive=False, so an
automation principal reaches it with no confirmation -- and Capella replaces the
stored value rather than merging it. So an ordinary "tidy up the description" call
silently orphans the cluster.

The rule the code follows, and that these pin:

  * A caller who KEPT a valid marker is left exactly as written. The server does
    not rewrite text it does not need to touch.
  * A caller who dropped one has it re-attached under their prose.
  * A cluster that never had one gains nothing -- this preserves, it does not
    claim ownership of somebody else's cluster.

And underneath it, `_fetch_cluster` fails CLOSED. An earlier version wrapped the
ownership check in `if isinstance(cluster, dict)`, so an unexpected response shape
SKIPPED the check and let the operation proceed. A guard that disappears when the
world looks strange is not a guard.
"""

from __future__ import annotations

import json

import pytest

from handlers import capella
from handlers.capella import guardrails

CREATED = "2026-09-14T00:00:00Z"
MARKER = {"created": CREATED, "ttl_h": 4, "env": "fx"}


def _marker_text() -> str:
    return guardrails.ENV_MARKER_PREFIX + json.dumps(
        MARKER, separators=(",", ":"), sort_keys=True
    )


@pytest.fixture
def cluster(monkeypatch):
    """The live cluster the guard fetches, swappable per test."""
    state = {"response": {"name": "mcp-fx", "description": _marker_text()}}

    def request(method, path, *args, **kwargs):
        if isinstance(state["response"], Exception):
            raise state["response"]
        return state["response"]

    monkeypatch.setattr(capella, "capella_request", request)
    return state


ARGS = {"organization_id": "o", "project_id": "p", "cluster_id": "c"}


# ── _fetch_cluster fails closed ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "response",
    [
        None,
        "a string",
        ["a", "list"],
        {},
        {"id": "c"},  # a dict, but with no name to decide ownership from
    ],
)
def test_an_unusable_cluster_response_refuses_rather_than_skipping_the_check(
    cluster, response
):
    """A guard that disappears when the world looks strange is not a guard."""
    cluster["response"] = response
    with pytest.raises(guardrails.GuardrailError) as caught:
        capella._fetch_cluster(ARGS)
    message = str(caught.value)
    assert "Could not establish ownership" in message
    assert "capella_clusters_list" in caught.value.hint


def test_a_usable_cluster_is_returned(cluster):
    assert capella._fetch_cluster(ARGS)["name"] == "mcp-fx"


# ── the marker survives an update ────────────────────────────────────────────


def test_a_caller_who_dropped_the_marker_has_it_reattached(cluster):
    """Without it the cluster becomes invisible to the environment tooling and
    goes on billing with nothing pointing at it."""
    body = {"description": "tidied up the notes"}
    capella._preserve_ownership_marker("capella_cluster_update", ARGS, body)
    assert body["description"].startswith("tidied up the notes\n")
    assert guardrails.parse_marker(body["description"]) == MARKER


def test_a_caller_who_kept_a_valid_marker_is_left_exactly_as_written(cluster):
    """The server does not rewrite text it does not need to touch."""
    written = f"my own prose\n{_marker_text()}"
    body = {"description": written}
    capella._preserve_ownership_marker("capella_cluster_update", ARGS, body)
    assert body["description"] == written


def test_an_empty_description_becomes_the_marker_alone(cluster):
    body = {"description": ""}
    capella._preserve_ownership_marker("capella_cluster_update", ARGS, body)
    assert guardrails.parse_marker(body["description"]) == MARKER
    assert not body["description"].startswith("\n")


def test_a_cluster_that_never_had_a_marker_gains_nothing(cluster):
    """This PRESERVES ownership; it does not claim it. Stamping a marker onto
    somebody else's cluster would bring it inside the reaper's scope."""
    cluster["response"] = {"name": "not-ours", "description": "someone else's"}
    body = {"description": "new text"}
    capella._preserve_ownership_marker("capella_cluster_update", ARGS, body)
    assert body["description"] == "new text"


def test_an_update_that_does_not_touch_the_description_is_untouched(cluster):
    """No description in the body means Capella leaves the stored value alone,
    so there is nothing to preserve."""
    body = {"name": "renamed"}
    capella._preserve_ownership_marker("capella_cluster_update", ARGS, body)
    assert body == {"name": "renamed"}


def test_a_guardrail_error_while_fetching_propagates(cluster):
    """The marker cannot be preserved without reading the cluster, and guessing
    would either orphan it or stamp the wrong owner."""
    cluster["response"] = guardrails.GuardrailError("cannot read", hint="")
    with pytest.raises(guardrails.GuardrailError):
        capella._preserve_ownership_marker(
            "capella_cluster_update", ARGS, {"description": "x"}
        )


def test_only_the_update_primitive_preserves_markers():
    """The set is deliberately narrow: it names the one operation that replaces a
    free-text field a caller edits."""
    assert frozenset({"capella_cluster_update"}) == capella._MARKER_PRESERVING_UPDATES
