"""Regression tests for the Capella guardrail fixes of the round-2 audit.

Component: regression suite; see tests/README.md.
Spec: docs/spec.md S3 step 8, S8.
Main items: tests for marker shadowing, the CIDR floor, dot-segment ids, the Data API
    host and redirect checks, the read-side project policy and the reap dry-run parse.
Callers: none; collected by pytest
Callees: `handlers.capella.client`, `handlers.capella.environment`,
    `handlers.capella.fixture`, `handlers.capella.guardrails`, `handlers.fixture_core`,
    `handlers.shared`

Each test fails on the code before the fix.
"""

import urllib.error
import urllib.request

import pytest

from handlers.capella import client, fixture
from handlers.capella import guardrails as g

CREATED = "2026-11-01T00:00:00Z"


def test_an_empty_marker_does_not_shadow_the_real_one():
    desc = f'mcp-env:{{}} note mcp-env:{{"env": "e1", "created": "{CREATED}"}}'
    assert g.parse_marker(desc)["env"] == "e1"


def test_an_unbalanced_marker_does_not_shadow_the_real_one():
    desc = f'mcp-env:{{ x\nmcp-env:{{"env": "e2", "created": "{CREATED}"}}'
    assert g.parse_marker(desc)["env"] == "e2"


@pytest.mark.parametrize(
    "cidr", ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0", "::/8"]
)
def test_a_very_wide_cidr_is_refused(cidr):
    with pytest.raises(g.GuardrailError):
        g.assert_cidr_not_open(cidr)


@pytest.mark.parametrize("cidr", ["10.0.0.0/8", "203.0.113.7/32", "2001:db8::/32"])
def test_an_ordinary_cidr_is_allowed(cidr):
    g.assert_cidr_not_open(cidr)


def test_dot_segments_are_encoded():
    assert client.quote_segment("..") == "%2E%2E"
    assert client.quote_segment(".") == "%2E"


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://abc.data.cloud.couchbase.com", True),
        ("http://abc.data.cloud.couchbase.com", False),
        ("https://evil.example.net", False),
        ("https://u:p@abc.data.cloud.couchbase.com", False),
        ("http://localhost:8093", True),
    ],
)
def test_data_api_host_check(url, ok):
    assert (fixture._data_api_host_problem(url) == "") is ok


def test_an_operator_can_add_a_data_api_host(monkeypatch):
    monkeypatch.setenv("CB_CAPELLA_DATA_API_HOSTS", ".corp.example")
    assert fixture._data_api_host_problem("https://a.corp.example") == ""


def test_the_data_api_does_not_follow_redirects(monkeypatch):
    seen = []

    class _Boom(urllib.request.BaseHandler):
        def http_open(self, req):
            seen.append(req.full_url)
            raise urllib.error.HTTPError(
                req.full_url, 302, "Found", {"Location": "http://other.invalid/"}, None
            )

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: _opener(handlers),
    )

    def _opener(handlers):
        director = urllib.request.OpenerDirector()
        for handler in handlers:
            director.add_handler(handler() if isinstance(handler, type) else handler)
        director.add_handler(_Boom())
        return director

    request = urllib.request.Request("http://abc.invalid/x")
    with pytest.raises(urllib.error.HTTPError) as caught:
        fixture._open_data_api(request, 1)
    assert caught.value.code == 302
    assert seen == ["http://abc.invalid/x"]


def test_read_side_policy_refuses_a_protected_cluster(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "p")
    monkeypatch.setenv("CAPELLA_PROTECTED_CLUSTERS", "prod-db")
    with pytest.raises(g.GuardrailError):
        g.assert_not_protected({"id": "c1", "name": "prod-db"}, "p")
    g.assert_not_protected({"id": "c2", "name": "scratch"}, "p")


def test_read_side_policy_fails_closed_on_a_bad_cluster_response(monkeypatch):
    from handlers.capella import environment as env

    monkeypatch.setattr(env, "_invoke", lambda *a, **k: "not a dict")
    problem = fixture._read_side_problem({"cluster_id": "c"}, "p", None, "export from")
    assert "usable cluster" in problem


def test_read_side_policy_allows_an_ordinary_cluster(monkeypatch):
    from handlers.capella import environment as env

    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "p")
    monkeypatch.delenv("CAPELLA_PROTECTED_CLUSTERS", raising=False)
    monkeypatch.setattr(env, "_invoke", lambda *a, **k: {"id": "c", "name": "scratch"})
    assert (
        fixture._read_side_problem({"cluster_id": "c"}, "p", None, "export from") == ""
    )


def test_a_rewritten_index_statement_is_guarded_again(monkeypatch):
    """A nodes clause that flips quote parity must not smuggle a second statement."""
    from handlers import fixture_core, shared

    evil = 'CREATE INDEX i ON `b`(x) WITH {"nodes": ["a"]}; DROP SCOPE `b`.`p`'
    rewritten, _ = fixture_core.strip_index_nodes(evil)
    assert shared.assert_index_create_ddl(rewritten) is not None
