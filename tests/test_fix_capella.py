"""Regression tests for the Capella client and guardrail fixes of 2026-11."""

import http.server
import json
import threading

import pytest

from handlers import capella
from handlers.capella import client, guardrails
from tests.test_capella_guardrail_hardening import Recorder


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("CAPELLA_ORG_ID", "org-1")
    monkeypatch.setenv("CAPELLA_ALLOWED_PROJECTS", "test-proj")
    monkeypatch.setenv("CAPELLA_ENV_NAME_PREFIX", "mcptest-")
    monkeypatch.delenv("CAPELLA_PROTECTED_CLUSTERS", raising=False)
    monkeypatch.delenv("CAPELLA_ALLOW_OPEN_CIDR", raising=False)
    monkeypatch.delenv("CB_CAPELLA_ORG_ID", raising=False)
    monkeypatch.setenv("CB_ADMIN_EGRESS_SKIP_DNS", "true")


class ByIdRecorder(Recorder):
    def __init__(self, clusters_by_id):
        super().__init__(None)
        self.by_id = clusters_by_id

    def request(
        self, method, path, *, params=None, body=None, content_type="application/json"
    ):
        self.requests.append((method, path))
        if method == "GET" and "/clusters/" in path:
            return self.by_id[path.split("/clusters/")[1].split("/")[0]]
        return {"status": "ok"}


def _wire(monkeypatch, clusters):
    rec = ByIdRecorder(clusters)
    monkeypatch.setattr(capella, "capella_request", rec.request)
    monkeypatch.setattr(capella, "capella_list", rec.listing)
    return rec


def _call(tool, **args):
    return json.loads(capella.handle(tool, args)[0].text)


PROD = {"id": "prod-1", "name": "acme-prod"}
TEST = {"id": "test-1", "name": "mcptest-x"}


def _posts(rec):
    return [r for r in rec.requests if r[0] != "GET"]


# 1. redirects and base URL


def test_redirect_is_not_followed_and_key_is_not_forwarded(monkeypatch):
    got = {}

    class A(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got["auth"] = self.headers.get("Authorization")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    att = http.server.HTTPServer(("127.0.0.1", 0), A)

    class C(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{att.server_port}/x")
            self.end_headers()

        def log_message(self, *a):
            pass

    cl = http.server.HTTPServer(("127.0.0.1", 0), C)
    for s in (att, cl):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    monkeypatch.setenv("CAPELLA_BASE_URL", f"http://127.0.0.1:{cl.server_port}")
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "capsecret")
    with pytest.raises(client.CapellaError):
        client.capella_request("GET", "/v4/organizations")
    att.shutdown()
    cl.shutdown()
    assert "auth" not in got


def test_non_https_remote_base_url_is_refused(monkeypatch):
    monkeypatch.setenv("CAPELLA_BASE_URL", "http://capella.example.com")
    monkeypatch.setenv("CAPELLA_API_KEY_SECRET", "capsecret")
    with pytest.raises(client.CapellaError, match="https"):
        client.capella_request("GET", "/v4/organizations")


# 2. backup and audit export are guarded


def test_backup_create_outside_allowlist_is_refused(monkeypatch):
    rec = _wire(monkeypatch, {"prod-1": PROD})
    out = _call(
        "capella_backup_create",
        project_id="other-proj",
        cluster_id="prod-1",
        bucket_id="b1",
    )
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


def test_backup_create_on_unmanaged_cluster_is_refused(monkeypatch):
    rec = _wire(monkeypatch, {"prod-1": PROD})
    out = _call(
        "capella_backup_create",
        project_id="test-proj",
        cluster_id="prod-1",
        bucket_id="b1",
    )
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


def test_backup_create_on_managed_cluster_is_sent(monkeypatch):
    rec = _wire(monkeypatch, {"test-1": TEST})
    out = _call(
        "capella_backup_create",
        project_id="test-proj",
        cluster_id="test-1",
        bucket_id="b1",
    )
    assert out.get("guardrail") is not True, out
    assert len(_posts(rec)) == 1


def test_audit_log_export_create_is_guarded(monkeypatch):
    rec = _wire(monkeypatch, {"prod-1": PROD})
    out = _call(
        "capella_cluster_audit_log_export_create",
        project_id="test-proj",
        cluster_id="prod-1",
        body={"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
    )
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


# 3. replication direction


def _repl(monkeypatch, direction):
    rec = _wire(monkeypatch, {"prod-1": PROD, "test-1": TEST})
    body = {"sourceBucket": "b", "target": {"cluster": "test-1", "bucket": "b"}}
    if direction is not None:
        body["direction"] = direction
    return rec, _call(
        "capella_replication_create",
        project_id="test-proj",
        cluster_id="prod-1",
        body=body,
    )


@pytest.mark.parametrize("direction", ["twoWay", "TWOWAY", "twoway"])
def test_two_way_replication_into_unmanaged_source_is_refused(monkeypatch, direction):
    rec, out = _repl(monkeypatch, direction)
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


def test_one_way_replication_out_of_unmanaged_source_still_allowed(monkeypatch):
    rec, out = _repl(monkeypatch, "oneWay")
    assert out.get("guardrail") is not True, out
    assert len(_posts(rec)) == 1


def test_unknown_replication_direction_is_refused(monkeypatch):
    rec, out = _repl(monkeypatch, "sideways")
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


# 4. case-colliding keys


def test_case_colliding_body_keys_are_refused(monkeypatch):
    rec = _wire(monkeypatch, {"test-1": TEST})
    out = _call(
        "capella_bucket_create",
        project_id="test-proj",
        cluster_id="test-1",
        body={"name": "mcptest-ok", "Name": "evil"},
    )
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


# 5. org alias


def test_cb_capella_org_id_alias_pins_the_org(monkeypatch):
    monkeypatch.delenv("CAPELLA_ORG_ID", raising=False)
    monkeypatch.setenv("CB_CAPELLA_ORG_ID", "org-alias")
    assert guardrails.load_policy().organization_id == "org-alias"


def test_capella_org_id_wins_over_alias(monkeypatch):
    monkeypatch.setenv("CB_CAPELLA_ORG_ID", "org-alias")
    assert guardrails.load_policy().organization_id == "org-1"


def test_deploy_templates_no_longer_claim_discovery_from_the_key():
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "deploy"
    for rel in (
        "env.capella.example",
        "docker-compose.capella.yml",
        "k8s/capella.yaml",
    ):
        assert "Discovered from the key" not in (root / rel).read_text()


# 6. webhook egress


def _alert(monkeypatch, url):
    rec = _wire(monkeypatch, {})
    out = _call(
        "capella_alert_integration_create",
        project_id="test-proj",
        body={
            "name": "n",
            "kind": "webhook",
            "config": {"webhook": {"url": url, "method": "POST", "token": "t"}},
        },
    )
    return rec, out


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/x",
        "https://169.254.169.254/latest",
        "https://127.0.0.1/x",
        "https://10.0.0.5/x",
    ],
)
def test_unsafe_webhook_urls_are_refused(monkeypatch, url):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOW_ANY", "true")
    rec, out = _alert(monkeypatch, url)
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


def test_public_https_webhook_on_the_allowlist_is_sent(monkeypatch):
    monkeypatch.setenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", "hooks.slack.com")
    rec, out = _alert(monkeypatch, "https://hooks.slack.com/services/T/B/X")
    assert out.get("guardrail") is not True, out
    assert len(_posts(rec)) == 1


def test_webhook_is_refused_when_no_egress_policy_is_configured(monkeypatch):
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOWED_HOSTS", raising=False)
    monkeypatch.delenv("CB_ADMIN_EGRESS_ALLOW_ANY", raising=False)
    rec, out = _alert(monkeypatch, "https://hooks.slack.com/services/T/B/X")
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


# 7. open CIDR


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
def test_open_cidr_is_refused_on_primitive(monkeypatch, cidr):
    rec = _wire(monkeypatch, {"test-1": TEST})
    out = _call(
        "capella_allowed_cidr_create",
        project_id="test-proj",
        cluster_id="test-1",
        body={"cidr": cidr},
    )
    assert out.get("guardrail") is True, out
    assert _posts(rec) == []


def test_open_cidr_allowed_with_operator_setting(monkeypatch):
    monkeypatch.setenv("CAPELLA_ALLOW_OPEN_CIDR", "true")
    _wire(monkeypatch, {"test-1": TEST})
    out = _call(
        "capella_allowed_cidr_create",
        project_id="test-proj",
        cluster_id="test-1",
        body={"cidr": "0.0.0.0/0"},
    )
    assert out.get("guardrail") is not True, out


def test_narrow_cidr_is_sent(monkeypatch):
    _wire(monkeypatch, {"test-1": TEST})
    out = _call(
        "capella_allowed_cidr_create",
        project_id="test-proj",
        cluster_id="test-1",
        body={"cidr": "203.0.113.4/32"},
    )
    assert out.get("guardrail") is not True, out


@pytest.mark.parametrize("key", ["allowed_cidrs", "app_service_cidrs"])
def test_env_ensure_refuses_open_cidr_before_any_request(monkeypatch, key):
    from handlers.capella import environment

    sent = []
    monkeypatch.setattr(
        environment, "capella_request", lambda *a, **k: sent.append(a) or {}
    )
    monkeypatch.setattr(
        environment, "capella_list", lambda *a, **k: sent.append(a) or {"data": []}
    )
    out = json.loads(
        environment.handle(
            "capella_env_ensure",
            {"env_name": "e1", "project_id": "test-proj", key: ["0.0.0.0/0"]},
        )[0].text
    )
    assert out.get("guardrail") is True, out
    assert sent == []


# 8. reap sweep survives a composite refusal


def test_reap_reports_a_composite_refusal_per_environment(monkeypatch):
    from handlers.capella import environment

    entries = [
        {"environment": "a", "cluster_id": "c1", "project_id": "test-proj"},
        {"environment": "b", "cluster_id": "c2", "project_id": "test-proj"},
    ]
    monkeypatch.setattr(
        environment,
        "_list_envs",
        lambda a: {"managed": [{**e, "expired": True} for e in entries]},
    )
    monkeypatch.setattr(environment, "_classify_expired", lambda e: (entries, []))

    def teardown(a):
        if a["env_name"] == "a":
            raise environment.CompositeRefusedError("disabled")
        return {"result": "deleting"}

    monkeypatch.setattr(environment, "_teardown", teardown)
    out = environment._reap({"dry_run": False})
    assert [r["environment"] for r in out["reaped"]] == ["b"]
    assert [r["environment"] for r in out["refused"]] == ["a"]
