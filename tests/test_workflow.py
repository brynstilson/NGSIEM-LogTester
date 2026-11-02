import hashlib
import json
import sys
import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import forensic_log as forensic_log_module
from app import create_app
from falcon_client import ActivityLog, DeleteRefused, FalconClient, FalconError
from forensic_log import DEFAULT_PATH, ForensicLog
from mock_falcon import MockFalcon
from workflow import Settings, build_ingest_url, delete_clone, parse_log, resolve_connector

LOG = '{"event": "login", "user": "alice"}'
CLIENT_SECRET = "SECRET-CLIENT-VALUE"


@pytest.fixture
def mock():
    # The mock's ingest URL includes its port, which isn't known until the server has bound.
    server = make_server("127.0.0.1", 0, MockFalcon().app, threaded=True)
    falcon = MockFalcon(port=server.server_port)
    server.app = falcon.app
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield falcon
    server.shutdown()


@pytest.fixture
def forensic_path(tmp_path):
    return tmp_path / "logs" / "forensic.jsonl"


def fast_settings():
    return Settings(token_wait_seconds=1, token_poll_seconds=0.01, ingest_retry_seconds=0.01, cleanup_retry_seconds=0.01)


@pytest.fixture
def web(mock, forensic_path):
    client = FalconClient("id", CLIENT_SECRET, f"http://127.0.0.1:{mock.port}")
    return create_app(client, fast_settings(), ForensicLog(forensic_path)).test_client()


def records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def submit(web, connector_id="conn-okta", log=LOG, mode="event"):
    response = web.post("/api/submit", json={"connector_id": connector_id, "log": log, "mode": mode})
    return response.get_json()


def assert_no_secrets(result, mock):
    text = json.dumps(result)
    assert mock.TOKEN not in text
    assert CLIENT_SECRET not in text
    assert "mock-access-token" not in text


def test_lists_every_connector_sorted_and_marks_pull(web):
    data = web.get("/api/connectors").get_json()
    assert data["success"]
    assert [c["name"] for c in data["connectors"]] == ["App logs", "Okta prod", "S3 access logs"]
    assert {c["name"]: c["can_ingest"] for c in data["connectors"]}["S3 access logs"] is False


def test_lists_across_pages(web, mock):
    mock.page_size_override = 1
    assert len(web.get("/api/connectors").get_json()["connectors"]) == 3


def test_selecting_a_connector_returns_its_parser(web):
    data = web.get("/api/connectors/conn-okta/parser").get_json()
    assert data["success"]
    assert data["connector"]["parser"] == "okta-sso"


def test_stored_parser_is_used_at_submit(web, mock):
    web.get("/api/connectors/conn-okta/parser")
    mock.calls.clear()
    assert submit(web)["success"]
    # The source isn't read again. The one read is the delete limiter checking the clone.
    assert mock.calls.count(("GET", "/ngsiem/entities/connections/v1")) == 1
    assert mock.created[0]["parser"] == "okta-sso"


def test_full_flow_clones_and_posts_wrapped_event(web, mock):
    result = submit(web)
    assert result["success"], result
    created = mock.created[0]
    assert created["connector_id"] == "cat-okta"
    assert created["parser"] == "okta-sso"
    assert created["name"].startswith("Okta prod-clone-")
    assert created["enable_host_enrichment"] is True
    # An `event` field in the raw log must not be mistaken for an HEC envelope.
    assert json.loads(mock.ingested[0]["body"]) == {"event": json.loads(LOG)}
    assert mock.ingested[0]["path"] == "/services/collector"
    assert_no_secrets(result, mock)


def test_source_connector_is_not_modified(web, mock):
    before = json.dumps(mock.connections[0])
    submit(web)
    assert json.dumps(mock.connections[0]) == before


def test_raw_mode_sends_exact_bytes_to_raw_path(web, mock):
    assert submit(web, mode="raw")["success"]
    assert mock.ingested[0]["path"] == "/services/collector/raw"
    assert mock.ingested[0]["body"] == LOG


def test_array_becomes_one_event_each(web, mock):
    assert submit(web, log='[{"a": 1}, {"a": 2}]')["success"]
    lines = mock.ingested[0]["body"].splitlines()
    assert [json.loads(line) for line in lines] == [{"event": {"a": 1}}, {"event": {"a": 2}}]


@pytest.mark.parametrize("bad", ["", "  ", "{not json", "42", '"text"', "[]", "[1, 2]", "NaN"])
def test_invalid_logs_fail_before_cloning(web, mock, bad):
    result = submit(web, log=bad)
    assert not result["success"]
    assert mock.created == []
    assert result["log"]


def test_pull_connector_is_refused_without_cloning(web, mock):
    result = submit(web, connector_id="conn-s3")
    assert not result["success"]
    assert "pull" in result["message"]
    assert mock.created == []


def test_token_read_waits_through_provisioning(web, mock):
    mock.not_ready_polls = 3
    result = submit(web)
    assert result["success"], result
    assert mock.calls.count(("GET", "/ngsiem/entities/connections/token/v1")) == 4


def test_provisioning_timeout_fails_and_names_the_clone(web, mock):
    mock.not_ready_polls = 10**6
    result = submit(web)
    assert not result["success"]
    assert "provisioning" in result["message"]
    assert "clone-1" in result["message"]
    assert mock.ingested == []


def test_token_read_failure_falls_back_to_regenerate(web, mock):
    mock.token_get_status = 404
    mock.not_ready_polls = 0
    result = submit(web)
    assert result["success"], result
    assert ("POST", "/ngsiem/entities/connections/token/v1") in mock.calls
    assert_no_secrets(result, mock)


def test_create_failure_is_reported_with_api_message(web, mock):
    mock.create_status = 403
    result = submit(web)
    assert not result["success"]
    assert "create rejected" in result["message"]
    assert mock.ingested == []


def test_ingest_retries_transient_rejection(web, mock):
    mock.ingest_statuses = [401, 503]
    result = submit(web)
    assert result["success"], result
    assert len(mock.ingested) == 3


def test_ingest_failure_after_retries_reports_clone_and_scrubs_echoed_token(web, mock):
    mock.ingest_statuses = [503, 503, 503]
    result = submit(web)
    assert not result["success"]
    assert "HTTP 503" in result["message"]
    assert "clone-1" in result["message"]
    assert_no_secrets(result, mock)


def test_permanent_ingest_rejection_is_not_retried(web, mock):
    mock.ingest_statuses = [400]
    assert not submit(web)["success"]
    assert len(mock.ingested) == 1


def test_ingest_error_in_a_200_body_is_a_failure(web, mock):
    mock.ingest_body = {"#error": True, "@error_msg": "Input too big. Event truncated at 1048576"}
    result = submit(web)
    assert not result["success"]
    assert "Input too big" in result["message"]


def test_bad_credentials_are_reported(mock):
    client = FalconClient("", "", f"http://127.0.0.1:{mock.port}")
    data = create_app(client, Settings()).test_client().get("/api/connectors").get_json()
    assert not data["success"]
    assert "FALCON_CLIENT_ID" in data["message"]


def test_unreachable_falcon_is_reported():
    client = FalconClient("id", CLIENT_SECRET, "http://127.0.0.1:1", timeout=1)
    data = create_app(client, Settings()).test_client().get("/api/connectors").get_json()
    assert not data["success"]
    assert "Could not reach" in data["message"]


def test_submit_requires_json_content_type(web, mock):
    response = web.post("/api/submit", data="connector_id=conn-okta", content_type="application/x-www-form-urlencoded")
    assert response.status_code == 415
    assert mock.created == []


def clone_ids(mock):
    return [c["id"] for c in mock.connections if c["id"].startswith("clone-")]


DELETE_CALL = ("DELETE", "/ngsiem/entities/connections/v1")


@pytest.fixture
def client(mock):
    return FalconClient("id", CLIENT_SECRET, f"http://127.0.0.1:{mock.port}")


def create_clone(client, name="my-clone"):
    return client.create_connection(
        {"connector_id": "cat-okta", "name": name, "parser": "okta-sso"}, ActivityLog()
    )


@pytest.mark.parametrize("connection_id", ["conn-okta", "conn-app", "conn-s3", "does-not-exist"])
def test_limiter_refuses_anything_this_client_did_not_create(client, mock, connection_id):
    before = list(mock.connections)
    with pytest.raises(DeleteRefused):
        client.delete_connection(connection_id, ActivityLog())
    assert DELETE_CALL not in mock.calls
    assert mock.connections == before


def test_limiter_refuses_a_source_connector_even_with_a_clone_on_the_list(client, mock):
    create_clone(client)
    with pytest.raises(DeleteRefused):
        client.delete_connection("conn-okta", ActivityLog())
    assert DELETE_CALL not in mock.calls


def test_limiter_allows_a_clone_this_client_created(client, mock):
    clone_id = create_clone(client)
    client.delete_connection(clone_id, ActivityLog())
    assert clone_ids(mock) == []


def test_limiter_allows_each_clone_to_be_deleted_only_once(client, mock):
    clone_id = create_clone(client)
    client.delete_connection(clone_id, ActivityLog())
    with pytest.raises(DeleteRefused):
        client.delete_connection(clone_id, ActivityLog())
    assert mock.calls.count(DELETE_CALL) == 1


def test_limiter_refuses_a_clone_from_before_a_restart(client, mock):
    clone_id = create_clone(client)
    restarted = FalconClient("id", CLIENT_SECRET, client.base_url)
    with pytest.raises(DeleteRefused):
        restarted.delete_connection(clone_id, ActivityLog())
    assert clone_ids(mock) == [clone_id]


def test_limiter_refuses_a_clone_whose_name_no_longer_matches(client, mock):
    clone_id = create_clone(client)
    mock.connections[-1]["name"] = "Someone reused this connector"
    with pytest.raises(DeleteRefused, match="Someone reused this connector"):
        client.delete_connection(clone_id, ActivityLog())
    assert DELETE_CALL not in mock.calls


def test_limiter_does_not_delete_when_the_clone_cannot_be_read(client, mock):
    clone_id = create_clone(client)
    mock.hide_clones_on_read = True
    with pytest.raises(FalconError):
        client.delete_connection(clone_id, ActivityLog())
    assert DELETE_CALL not in mock.calls
    assert clone_ids(mock) == [clone_id]


def test_wrong_id_reaching_cleanup_is_refused_once_and_recorded(client, mock):
    events = []
    error = delete_clone(
        client, {"id": "conn-okta", "name": "Okta prod"}, fast_settings(), ActivityLog(),
        lambda event, **fields: events.append((event, fields)),
    )
    assert "Refused" in error
    assert [event for event, _ in events] == ["clone_delete_refused"]
    assert ("GET", "/ngsiem/entities/connections/v1") not in mock.calls
    assert DELETE_CALL not in mock.calls


def test_refused_delete_is_reported_and_in_the_forensic_log(web, mock, forensic_path):
    mock.rename_clones = True
    result = submit(web)
    assert not result["success"]
    assert "Refused to delete clone-1" in result["message"]
    assert "remove it manually" in result["message"]
    assert DELETE_CALL not in mock.calls
    assert clone_ids(mock) == ["clone-1"]
    rows = records(forensic_path)
    refused = [r for r in rows if r["event"] == "clone_delete_refused"]
    assert len(refused) == 1
    assert refused[0]["clone"]["id"] == "clone-1"
    assert "Refused" in refused[0]["reason"]
    assert rows[-1]["success"] is False


def test_unreadable_clone_fails_after_retries_without_deleting(web, mock, forensic_path):
    mock.hide_clones_on_read = True
    result = submit(web)
    assert not result["success"]
    assert "remove it manually" in result["message"]
    assert DELETE_CALL not in mock.calls
    assert clone_ids(mock) == ["clone-1"]
    assert "clone_delete_failed" in [r["event"] for r in records(forensic_path)]


def test_clone_is_deleted_after_the_log_is_sent(web, mock):
    result = submit(web)
    assert result["success"], result
    assert "deleted" in result["message"]
    assert clone_ids(mock) == []
    methods = [call for call in mock.calls if call[1].startswith("/services") or call[0] == "DELETE"]
    assert [method for method, _ in methods] == ["POST", "DELETE"]


def test_only_the_clone_is_deleted(web, mock):
    submit(web)
    assert {c["id"] for c in mock.connections} == {"conn-okta", "conn-app", "conn-s3"}


def test_clone_is_deleted_when_ingest_fails(web, mock):
    mock.ingest_statuses = [400]
    result = submit(web)
    assert not result["success"]
    assert "HTTP 400" in result["message"]
    assert "was deleted" in result["message"]
    assert clone_ids(mock) == []


def test_clone_is_deleted_when_token_never_arrives(web, mock):
    mock.not_ready_polls = 10**6
    assert not submit(web)["success"]
    assert clone_ids(mock) == []


def test_clone_is_deleted_after_an_unexpected_error(web, mock):
    mock.token_get_non_json = True
    result = submit(web)
    assert not result["success"]
    assert "Unexpected" in result["message"]
    assert clone_ids(mock) == []


def test_delete_is_retried(web, mock):
    mock.delete_statuses = [409, 500]
    assert submit(web)["success"]
    assert mock.calls.count(("DELETE", "/ngsiem/entities/connections/v1")) == 3
    assert clone_ids(mock) == []


def test_delete_failure_fails_the_submission_and_names_the_clone(web, mock, forensic_path):
    mock.delete_statuses = [500, 500, 500]
    result = submit(web)
    assert not result["success"]
    assert "The log was accepted" in result["message"]
    assert "clone-1" in result["message"]
    assert "remove it manually" in result["message"]
    assert len(mock.ingested) == 1
    assert "clone_delete_failed" in [r["event"] for r in records(forensic_path)]


def test_delete_error_in_a_200_body_is_a_failure(web, mock):
    mock.delete_error_in_body = True
    result = submit(web)
    assert not result["success"]
    assert "remove it manually" in result["message"]


def test_ingest_and_delete_failure_are_both_reported(web, mock):
    mock.ingest_statuses = [400]
    mock.delete_statuses = [500, 500, 500]
    result = submit(web)
    assert "HTTP 400" in result["message"]
    assert "remove it manually" in result["message"]


def test_nothing_is_deleted_when_no_clone_was_made(web, mock):
    mock.create_status = 403
    submit(web)
    submit(web, connector_id="conn-s3")
    submit(web, log="{bad")
    assert ("DELETE", "/ngsiem/entities/connections/v1") not in mock.calls


def test_forensic_log_records_the_whole_submission(web, mock, forensic_path):
    result = submit(web)
    rows = records(forensic_path)
    assert [r["event"] for r in rows] == [
        "submission_started", "clone_created", "clone_deleted", "submission_finished",
    ]
    assert {r["submission_id"] for r in rows} == {result["submission_id"]}
    started, finished = rows[0], rows[-1]
    assert started["submitted_log"] == LOG
    assert started["log_sha256"] == hashlib.sha256(LOG.encode()).hexdigest()
    assert started["operator"]
    assert started["api_client_id"] == "id"
    assert finished["success"] is True
    assert finished["source_connector"]["parser"] == "okta-sso"
    assert finished["clone"]["id"] == "clone-1"
    assert any("/services/collector" in entry["title"] for entry in finished["activity"])


def test_forensic_log_never_contains_secrets(web, mock, forensic_path):
    mock.ingest_statuses = [503, 503, 503]  # This response echoes the token.
    submit(web)
    text = forensic_path.read_text(encoding="utf-8")
    assert mock.TOKEN not in text
    assert CLIENT_SECRET not in text
    assert "mock-access-token" not in text


def test_forensic_log_records_failures_and_rejected_input(web, forensic_path):
    submit(web, log="{bad")
    rows = records(forensic_path)
    assert rows[0]["submitted_log"] == "{bad"
    assert rows[-1]["event"] == "submission_finished"
    assert rows[-1]["success"] is False
    assert "not valid JSON" in rows[-1]["message"]


def test_forensic_log_appends_across_restarts(mock, forensic_path):
    client = FalconClient("id", CLIENT_SECRET, f"http://127.0.0.1:{mock.port}")
    for _ in range(2):
        submit(create_app(client, fast_settings(), ForensicLog(forensic_path)).test_client())
    assert [r["event"] for r in records(forensic_path)].count("submission_started") == 2


def test_unwritable_forensic_log_blocks_before_any_tenant_change(mock, tmp_path):
    client = FalconClient("id", CLIENT_SECRET, f"http://127.0.0.1:{mock.port}")
    # The parent "directory" is a file, so the log can't be created.
    (tmp_path / "blocked").write_text("x")
    forensic = ForensicLog(tmp_path / "blocked" / "forensic.jsonl")
    result = submit(create_app(client, fast_settings(), forensic).test_client())
    assert not result["success"]
    assert "forensic log" in result["message"]
    assert mock.created == []


def test_forensic_log_defaults_to_the_application_directory():
    assert DEFAULT_PATH.parent.parent == Path(forensic_log_module.__file__).resolve().parent


def push(id_, name, parsers, vendor="V", product="P"):
    return {"id": id_, "name": name, "type": "PUSH", "parsers": parsers, "vendor_name": vendor, "vendor_product_name": product}


def connection(parser="p1", vendor="V", product="P"):
    return {"name": "src", "parser_name": parser, "vendor_name": vendor, "vendor_product_name": product}


def test_resolve_prefers_vendor_and_parser_match():
    catalog = [push("a", "A", ["p1"]), push("b", "B", ["p2"])]
    assert resolve_connector(connection(), catalog, ActivityLog())["id"] == "a"


def test_resolve_accepts_vendor_match_with_custom_parser():
    catalog = [push("a", "A", ["other"])]
    assert resolve_connector(connection(parser="custom"), catalog, ActivityLog())["id"] == "a"


def test_resolve_refuses_ambiguous_vendor_match():
    catalog = [push("a", "A", ["p1"]), push("b", "B", ["p1"]), push("h", "HEC", ["x"], "G", "H")]
    with pytest.raises(FalconError, match="Could not determine"):
        resolve_connector(connection(), catalog, ActivityLog())


def test_resolve_falls_back_to_only_connector_with_parser():
    catalog = [push("a", "A", ["p1"], "X", "Y"), push("b", "B", ["p2"], "X", "Y")]
    assert resolve_connector(connection(), catalog, ActivityLog())["id"] == "a"


def test_resolve_falls_back_to_generic_hec():
    catalog = [push("h", "HEC / HTTP Event Connector", ["json"], "G", "H"), push("o", "Other", ["z"], "X", "Y")]
    assert resolve_connector(connection(parser="custom"), catalog, ActivityLog())["id"] == "h"


def test_resolve_ignores_pull_connectors():
    catalog = [{**push("a", "A", ["p1"]), "type": "PULL"}]
    with pytest.raises(FalconError):
        resolve_connector(connection(), catalog, ActivityLog())


@pytest.mark.parametrize("url,mode,expected", [
    ("https://x.ingest.crowdstrike.com/services/collector", "event", "https://x.ingest.crowdstrike.com/services/collector"),
    ("https://x.ingest.crowdstrike.com/services/collector/", "raw", "https://x.ingest.crowdstrike.com/services/collector/raw"),
    ("https://x.ingest.crowdstrike.com", "event", "https://x.ingest.crowdstrike.com/services/collector"),
    ("https://x.ingest.crowdstrike.com/services/collector/raw", "raw", "https://x.ingest.crowdstrike.com/services/collector/raw"),
])
def test_build_ingest_url(url, mode, expected):
    assert build_ingest_url(url, mode) == expected


def test_parse_log_wraps_a_single_object():
    assert parse_log('{"a": 1}') == [{"a": 1}]
