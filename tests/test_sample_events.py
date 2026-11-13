import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import create_app
from falcon_client import FalconClient
from forensic_log import ForensicLog
from sample_events import MARKER, SAMPLE_IDS, SAMPLES, list_samples, render_sample
from workflow import Settings, parse_log

REQUESTED_SOURCES = [
    "Proofpoint TAP log", "Proofpoint TAP click log", "Microsoft Windows system event log", "Microsoft Entra log", "Cisco UCS log",
    "Cisco Firepower log", "VMware vSphere log", "AWS CloudTrail log", "AWS SecurityHub log",
    "Abnormal Security email log", "Checkpoint NGFW log", "Claroty xDome log", "Cloudflare log",
    "Epic Systems EHR log", "Fortinet firewall log", "Google Workspace log", "Netskope log", "Okta log",
    "Palo Alto NGFW log", "Palo Alto Prisma log", "Snowflake log",
]
RESERVED_NETWORKS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "10.0.0.0/8")]
ALL_IDS = sorted(SAMPLE_IDS)


def test_every_requested_source_is_listed_in_order():
    assert [sample["label"] for sample in list_samples()] == REQUESTED_SOURCES


def test_ids_are_unique():
    assert len(SAMPLE_IDS) == len(SAMPLES)


def test_listing_leaves_out_the_events():
    assert all("event" not in sample for sample in list_samples())


JSON_IDS = sorted(s["id"] for s in SAMPLES if "event" in s)
TEXT_IDS = sorted(s["id"] for s in SAMPLES if "text" in s)


def test_syslog_sources_are_plain_text():
    assert TEXT_IDS == ["cisco-firepower", "cisco-ucs", "epic-ehr", "fortinet-firewall", "paloalto-ngfw",
                        "vmware-vsphere", "windows-system"]
    assert {s["id"] for s in list_samples() if s["format"] == "text"} == set(TEXT_IDS)


@pytest.mark.parametrize("sample_id", JSON_IDS)
def test_json_sample_is_a_single_valid_event(sample_id):
    assert len(parse_log(render_sample(sample_id))) == 1


@pytest.mark.parametrize("sample_id", TEXT_IDS)
def test_text_sample_is_one_bare_line_and_not_json(sample_id):
    text = render_sample(sample_id)
    assert "\n" not in text
    with pytest.raises(ValueError):
        json.loads(text)


@pytest.mark.parametrize("sample_id", ALL_IDS)
def test_sample_can_be_found_and_has_no_unfilled_tokens(sample_id):
    text = render_sample(sample_id)
    assert MARKER in text
    assert "{{" not in text and "}}" not in text


@pytest.mark.parametrize("sample_id", ALL_IDS)
def test_sample_uses_only_reserved_addresses(sample_id):
    text = render_sample(sample_id)
    for found in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", text):
        try:
            address = ipaddress.ip_address(found)
        except ValueError:
            continue  # Version strings such as 3.14.0.1 aren't addresses.
        assert any(address in network for network in RESERVED_NETWORKS), found
    for domain in re.findall(r"[\w.+-]+@([\w.-]+)", text):
        assert domain.lower().split("\\")[0] == "example.com" or domain[0].isdigit(), domain


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: s["id"])
def test_sample_says_how_far_to_trust_it(sample):
    assert sample["accuracy"] in {"documented", "partial", "approximate"}
    assert sample["note"]
    assert sample["source"].startswith("https://")


@pytest.mark.parametrize("sample_id", ALL_IDS)
def test_timestamps_are_filled_with_the_current_time(sample_id):
    when = datetime(2031, 2, 3, 4, 5, 6, tzinfo=timezone.utc)
    text = render_sample(sample_id, now=when)
    assert any(piece in text for piece in ("2031-02-03", "2031/02/03", "Feb 03 04:05:06", str(int(when.timestamp()))))


def test_timestamps_change_between_loads():
    first = render_sample("okta", now=datetime(2031, 1, 1, tzinfo=timezone.utc))
    second = render_sample("okta", now=datetime(2031, 1, 1, tzinfo=timezone.utc) + timedelta(days=1))
    assert first != second


def test_unknown_sample_returns_nothing():
    assert render_sample("not-a-sample") is None


def test_filling_doesnt_change_the_library():
    before = json.dumps(SAMPLES)
    render_sample("okta")
    assert json.dumps(SAMPLES) == before


@pytest.fixture
def web(tmp_path):
    settings = Settings(
        token_wait_seconds=1, token_poll_seconds=0.01, ingest_retry_seconds=0.01,
        ingest_ready_wait_seconds=0.01, cleanup_retry_seconds=0.01,
    )
    client = FalconClient("id", "secret", "http://127.0.0.1:1", timeout=1)
    # The connector must exist before anything is recorded; sending to it still fails, which is fine here.
    client.get_connection = lambda connection_id, log: {"id": connection_id, "name": "x", "parser_name": "json",
                                                         "source_type": "Push", "status": "Active"}
    client.list_connections = lambda log: [{"id": "x"}]
    return create_app(client, settings, ForensicLog(tmp_path / "forensic.jsonl")), tmp_path / "forensic.jsonl"


def test_routes_list_and_render_samples(web):
    client = web[0].test_client()
    listing = client.get("/api/sample-events").get_json()
    assert listing["success"] and len(listing["samples"]) == 21
    loaded = client.get("/api/sample-events/okta").get_json()
    assert loaded["success"]
    assert json.loads(loaded["log"])["eventType"] == "user.session.start"


def test_unknown_sample_route_is_a_404(web):
    response = web[0].test_client().get("/api/sample-events/not-a-sample")
    assert response.status_code == 404
    assert not response.get_json()["success"]


@pytest.mark.parametrize("sent,recorded", [("okta", "okta"), ("not-a-sample", None), (["okta"], None), (None, None)])
def test_forensic_log_records_only_real_sample_ids(web, sent, recorded):
    app, path = web
    app.test_client().post("/api/submit", json={"connector_id": "x", "log": "{bad", "sample_id": sent})
    first = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert first["event"] == "submission_started"
    assert first["sample_event_id"] == recorded
