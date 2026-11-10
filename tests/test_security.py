"""Access controls: Host check, operator login, password lockout, and input checks before the forensic log."""
import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import QuietRequestHandler, create_app
from app_settings import AppSettings
from falcon_client import FalconClient, FalconError
from forensic_log import ForensicLog
from security import RateLimiter, Throttle, host_allowed, host_name, parse_allowed_hosts

HEADERS = {"X-Requested-By": "ngsiem-logtester"}


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def basic(user, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


@pytest.fixture
def forensic_path(tmp_path):
    return tmp_path / "forensic.jsonl"


def make(tmp_path, forensic_path, connection_exists=True, client_out=None, **kwargs):
    client = FalconClient("id", "secret", "http://127.0.0.1:1", timeout=1)

    def get_connection(connection_id, log):
        if not connection_exists:
            raise FalconError(f"Could not read data connector {connection_id}: connection not found")
        return {"id": connection_id, "name": "x", "parser_name": "json", "source_type": "Push", "status": "Active"}

    client.get_connection = get_connection
    client.calls = []

    def list_connections(log):
        client.calls.append("list")
        return [{"id": "c1"}, {"id": "nope"}] if connection_exists else [{"id": "c1"}]

    client.list_connections = list_connections
    settings = AppSettings(tmp_path / "app_settings.json", tmp_path / "branding")
    kwargs.setdefault("admin_password", "")
    kwargs.setdefault("access_password", "")
    kwargs.setdefault("allowed_hosts", "")
    if client_out is not None:
        client_out.append(client)
    return create_app(client, forensic=ForensicLog(forensic_path), app_settings=settings, **kwargs).test_client()


# Host names

@pytest.mark.parametrize("header,name", [("localhost:5000", "localhost"), ("127.0.0.1", "127.0.0.1"),
                                         ("[::1]:5000", "::1"), ("Server.Example:80", "server.example")])
def test_host_name(header, name):
    assert host_name(header) == name


def test_host_allowed():
    allowed = parse_allowed_hosts("10.0.0.5, logtester.corp.example")
    assert host_allowed("localhost:5000", set())
    assert host_allowed("10.0.0.5:5000", allowed)
    assert host_allowed("LOGTESTER.corp.example", allowed)
    assert not host_allowed("attacker.example", allowed)
    assert host_allowed("anything", {"*"})


def test_unknown_host_is_refused(tmp_path, forensic_path):
    web = make(tmp_path, forensic_path)
    response = web.get("/api/connectors", headers={"Host": "attacker.example:5000"})
    assert response.status_code == 421
    assert web.get("/api/connectors", headers={"Host": "localhost:5000"}).status_code == 200


def test_configured_host_is_accepted(tmp_path, forensic_path):
    web = make(tmp_path, forensic_path, allowed_hosts="10.0.0.5")
    assert web.get("/api/connectors", headers={"Host": "10.0.0.5:5000"}).status_code == 200


# Operator login

def test_login_required_when_access_password_set(tmp_path, forensic_path):
    web = make(tmp_path, forensic_path, access_password="op-pass")
    response = web.get("/")
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Basic")
    assert web.get("/api/connectors", headers=basic("alice", "wrong")).status_code == 401
    assert web.get("/", headers=basic("alice", "op-pass")).status_code == 200


def test_no_login_on_localhost_by_default(tmp_path, forensic_path):
    assert make(tmp_path, forensic_path).get("/").status_code == 200


def test_operator_login_is_recorded(tmp_path, forensic_path):
    web = make(tmp_path, forensic_path, access_password="op-pass")
    web.post("/api/submit", json={"connector_id": "c1", "log": '{"a": 1}'}, headers=basic("alice", "op-pass"))
    first = json.loads(forensic_path.read_text(encoding="utf-8").splitlines()[0])
    assert first["operator_login"] == "alice"


def test_wrong_operator_passwords_lock_the_address_out(tmp_path, forensic_path):
    clock = Clock()
    web = make(tmp_path, forensic_path, access_password="op-pass", throttle=Throttle(clock=clock))
    for _ in range(5):
        assert web.get("/api/connectors", headers=basic("x", "guess")).status_code == 401
    locked = web.get("/api/connectors", headers=basic("x", "op-pass"))
    assert locked.status_code == 429 and int(locked.headers["Retry-After"]) > 0
    clock.now += 301
    assert web.get("/api/connectors", headers=basic("x", "op-pass")).status_code == 200


def test_requests_without_credentials_dont_count_as_failures(tmp_path, forensic_path):
    web = make(tmp_path, forensic_path, access_password="op-pass")
    for _ in range(10):
        assert web.get("/").status_code == 401
    assert web.get("/", headers=basic("x", "op-pass")).status_code == 200


def test_wrong_admin_passwords_lock_the_address_out(tmp_path, forensic_path):
    clock = Clock()
    web = make(tmp_path, forensic_path, admin_password="admin-pass", throttle=Throttle(clock=clock))
    for _ in range(5):
        response = web.post("/api/settings", json={"title": "x"}, headers={**HEADERS, "X-Admin-Password": "guess"})
        assert response.status_code == 403
    response = web.post("/api/settings", json={"title": "x"}, headers={**HEADERS, "X-Admin-Password": "admin-pass"})
    assert response.status_code == 429
    clock.now += 301
    response = web.post("/api/settings", json={"title": "x"}, headers={**HEADERS, "X-Admin-Password": "admin-pass"})
    assert response.status_code == 200


def test_success_resets_the_failure_count():
    clock = Clock()
    throttle = Throttle(clock=clock)
    for _ in range(4):
        throttle.failed("k")
    throttle.succeeded("k")
    for _ in range(4):
        throttle.failed("k")
    assert throttle.retry_after("k") == 0


# Security headers

def test_security_headers(tmp_path, forensic_path):
    response = make(tmp_path, forensic_path).get("/")
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"


# Input checked before the forensic log is written

@pytest.mark.parametrize("body", [
    {"connector_id": "", "log": '{"a": 1}'},
    {"connector_id": ["c1"], "log": '{"a": 1}'},
    {"connector_id": "c" * 201, "log": '{"a": 1}'},
    {"connector_id": "c1", "log": "   "},
    {"connector_id": "c1", "log": '{"a": 1}', "mode": {"x": 1}},
    {"connector_id": "c1", "log": '{"a": 1}', "mode": "other"},
])
def test_bad_submissions_write_nothing(tmp_path, forensic_path, body):
    response = make(tmp_path, forensic_path).post("/api/submit", json=body)
    assert response.status_code == 400
    assert not response.get_json()["success"]
    assert not forensic_path.exists()


def test_unknown_connector_writes_nothing(tmp_path, forensic_path):
    result = make(tmp_path, forensic_path, connection_exists=False).post(
        "/api/submit", json={"connector_id": "nope", "log": '{"a": 1}'}).get_json()
    assert not result["success"] and "Unknown data connector" in result["message"]
    assert not forensic_path.exists()


def test_wrong_typed_fields_dont_crash_evaluate(tmp_path, forensic_path):
    response = make(tmp_path, forensic_path).post(
        "/api/evaluate", json={"log": "{}", "mode": {"x": 1}, "connector_id": ["a"], "sample_id": 5})
    assert response.status_code == 200


# Content-Security-Policy and Server header

def test_page_has_a_nonce_csp(tmp_path, forensic_path):
    web = make(tmp_path, forensic_path)
    first, second = web.get("/"), web.get("/")
    policy = first.headers["Content-Security-Policy"]
    nonce = policy.split("'nonce-")[1].split("'")[0]
    assert f'<script nonce="{nonce}">' in first.get_data(as_text=True)
    assert f'<style nonce="{nonce}">' in first.get_data(as_text=True)
    assert "unsafe-inline" not in policy and "frame-ancestors 'none'" in policy
    assert nonce not in second.headers["Content-Security-Policy"]


def test_json_responses_have_a_locked_down_csp(tmp_path, forensic_path):
    response = make(tmp_path, forensic_path).get("/api/settings")
    assert response.headers["Content-Security-Policy"] == "default-src 'none'; frame-ancestors 'none'"


def test_server_header_hides_versions():
    assert QuietRequestHandler.version_string(None) == "NGSIEM-LogTester"


# Falcon API call limits

def test_unknown_connector_ids_dont_reach_falcon(tmp_path, forensic_path):
    clients, clock = [], Clock()
    web = make(tmp_path, forensic_path, client_out=clients, clock=clock)
    client = clients[0]
    reads = []
    original = client.get_connection
    client.get_connection = lambda cid, log: reads.append(cid) or original(cid, log)
    for i in range(20):
        assert web.get(f"/api/connectors/bogus-{i}/parser").status_code == 404
    assert reads == [] and client.calls == ["list"]   # one listing, then cached for 30 seconds
    clock.now += 31
    web.get("/api/connectors/bogus-x/parser")
    assert client.calls == ["list", "list"]
    assert web.get("/api/connectors/c1/parser").status_code == 200 and reads == ["c1"]


def test_evaluate_doesnt_read_unknown_connectors(tmp_path, forensic_path):
    clients = []
    web = make(tmp_path, forensic_path, client_out=clients)
    for i in range(10):
        web.post("/api/evaluate", json={"log": "{}", "connector_id": f"bogus-{i}"})
    assert clients[0].calls == ["list"]


def test_falcon_routes_are_rate_limited(tmp_path, forensic_path):
    clock = Clock()
    web = make(tmp_path, forensic_path, rate_limiter=RateLimiter(3, clock=clock))
    codes = [web.get("/api/connectors").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert web.get("/api/sample-events").status_code == 200   # no Falcon call, not limited
    assert web.post("/api/evaluate", json={"log": "{}"}).status_code == 200
    clock.now += 61
    assert web.get("/api/connectors").status_code == 200


def test_rate_limiter_retry_after():
    clock = Clock()
    limiter = RateLimiter(2, window=60, clock=clock)
    assert limiter.retry_after("a") == 0 and limiter.retry_after("a") == 0
    clock.now += 10
    assert limiter.retry_after("a") == 51
    assert limiter.retry_after("b") == 0
