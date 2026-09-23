"""A cluster-level query must not require a bucket to exist.

MEASURED 2026-09-23 against the EE container. With `CB_BUCKET` unset,
`admin_index_list` -- a query against `system:indexes`, which is answered by a
query node and never touches a bucket -- returned:

    BucketNotFoundException: BucketNotFoundException(<ec=10, ...
    message=Failed to open_bucket, ...>)

The message names no bucket, so the operator cannot tell which bucket was
wanted, that the name came from an environment variable, or that the tool never
needed one. `RUNBOOK.md` carried it as an environment-variable gotcha for over a
week; it was not. `get_sdk_connection` opened `CB_BUCKET` (defaulting to
`default`, which most clusters do not have) in the same try block that readied
the cluster, so the bucket's failure became the tool's failure.

All seven call sites discarded the bucket and the collection, and nothing in the
repository read the cached `_bucket` or `_collection` -- the fixture importer
opens its own bucket per keyspace. The open was serving nobody and breaking
every cluster-level tool.

`get_sdk_cluster()` now returns a readied Cluster and opens no bucket.
`get_sdk_connection()` is unchanged for anyone who genuinely wants one.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import types
from typing import ClassVar

import pytest

from handlers import shared

REPO = pathlib.Path(__file__).resolve().parent.parent


class _Cluster:
    instances: ClassVar[list] = []

    def __init__(self, connection_string, options):
        self.connection_string = connection_string
        self.options = options
        self.bucket_calls: list[str] = []
        _Cluster.instances.append(self)

    def wait_until_ready(self, timeout):
        return None

    def bucket(self, name):
        self.bucket_calls.append(name)
        raise RuntimeError(f"Failed to open_bucket {name}")

    def close(self):
        return None


class _Options:
    def __init__(self, authenticator):
        self.authenticator = authenticator

    def apply_profile(self, name):
        return None


@pytest.fixture
def sdk(monkeypatch):
    """A stubbed `couchbase` whose every bucket open FAILS.

    That is the whole point: it stands in for a cluster on which the bucket
    named by CB_BUCKET does not exist.
    """
    package = types.ModuleType("couchbase")
    auth_module = types.ModuleType("couchbase.auth")
    cluster_module = types.ModuleType("couchbase.cluster")
    options_module = types.ModuleType("couchbase.options")

    auth_module.CertificateAuthenticator = lambda **kw: ("cert", kw)
    auth_module.PasswordAuthenticator = lambda *a, **kw: ("password", a, kw)
    cluster_module.Cluster = _Cluster
    options_module.ClusterOptions = _Options

    for name, module in (
        ("couchbase", package),
        ("couchbase.auth", auth_module),
        ("couchbase.cluster", cluster_module),
        ("couchbase.options", options_module),
    ):
        monkeypatch.setitem(sys.modules, name, module)

    _Cluster.instances.clear()
    monkeypatch.setattr(shared, "_cluster", None, raising=False)
    monkeypatch.setattr(shared, "_bucket", None, raising=False)
    monkeypatch.setattr(shared, "_collection", None, raising=False)

    monkeypatch.setenv("CB_CONNECTION_STRING", "couchbase://cb.example.com")
    monkeypatch.setenv("CB_USERNAME", "Administrator")
    monkeypatch.setenv("CB_PASSWORD", "password")
    for key in ("CB_CLIENT_CERT_PATH", "CB_CLIENT_KEY_PATH", "CB_CA_CERT_PATH"):
        monkeypatch.delenv(key, raising=False)
    for key in ("CB_BUCKET", "CB_SCOPE", "CB_COLLECTION"):
        monkeypatch.delenv(key, raising=False)
    return shared


def test_a_cluster_is_returned_without_opening_any_bucket(sdk):
    """THE regression. Every bucket open in this stub raises; this must not."""
    cluster = sdk.get_sdk_cluster()
    assert cluster.connection_string == "couchbase://cb.example.com"
    assert cluster.bucket_calls == []


def test_the_cluster_is_cached(sdk):
    assert sdk.get_sdk_cluster() is sdk.get_sdk_cluster()
    assert len(_Cluster.instances) == 1


def test_a_caller_that_wants_a_bucket_still_gets_the_failure(sdk):
    """NEGATIVE CONTROL.

    If this passed too, the test above would prove nothing -- it would mean the
    stub is not actually failing bucket opens.
    """
    with pytest.raises(RuntimeError):
        sdk.get_sdk_connection()


def test_the_bucket_failure_names_the_bucket_and_where_it_came_from(sdk):
    """The SDK's own message names neither, which is what made a missing
    environment variable read as a defect in the tool."""
    with pytest.raises(RuntimeError) as caught:
        sdk.get_sdk_connection()
    message = str(caught.value)
    assert "default" in message
    assert "CB_BUCKET" in message


def test_one_cluster_serves_both_entry_points(sdk):
    """`get_sdk_connection` must reuse the cluster `get_sdk_cluster` opened,
    not construct a second connection pool."""
    cluster = sdk.get_sdk_cluster()
    with pytest.raises(RuntimeError):
        sdk.get_sdk_connection()
    assert len(_Cluster.instances) == 1
    assert _Cluster.instances[0] is cluster


def test_no_handler_asks_for_a_bucket_it_discards():
    """STRUCTURAL GUARD, so this cannot come back.

    `cluster, _, _ = get_sdk_connection()` is the shape of the defect: it makes
    a cluster-level tool depend on a bucket it never uses. A handler that truly
    needs a bucket must bind it to a real name.
    """
    offenders: list[str] = []
    for path in sorted((REPO / "handlers").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            call = node.value
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Name)
                and call.func.id == "get_sdk_connection"
            ):
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Tuple):
                continue
            names = [e.id for e in target.elts if isinstance(e, ast.Name)]
            discarded = [n for n in names[1:] if n.startswith("_")]
            if discarded:
                offenders.append(
                    f"{path.relative_to(REPO)}:{node.lineno} discards {discarded} "
                    f"-- call get_sdk_cluster() instead"
                )
    assert not offenders, "\n".join(offenders)
