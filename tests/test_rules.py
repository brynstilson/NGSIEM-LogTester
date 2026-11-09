import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cql import FALSE, TRUE, UNKNOWN, Evaluator, parse_rule, tokenize
from field_model import EventView, text_fields
from mock_falcon import CONFIGURED_RULES, RULE_TEMPLATES, _connection
from rules import build_template, events_of, evaluate, judge, latest_configured, normalize, rule_templates, template_entry
from sample_events import render_sample
from test_workflow import fast_settings, records, submit  # noqa: F401  (fixtures are shared below)
from test_workflow import client, forensic_path, mock, web  # noqa: F401


def check(query, event, parser=None):
    rule = parse_rule(query)
    evaluator = Evaluator(EventView(event, parser))
    states = [evaluator.run(node) for kind, node in rule.stages if kind == "filter"]
    if FALSE in states:
        return FALSE
    return UNKNOWN if UNKNOWN in states else TRUE


def rule(query, name="Rule", source="configured", status="active", rule_id="r1"):
    return normalize({"rule_id": rule_id, "name": name, "status": status, "search": {"filter": query}}, source)


OKTA = json.loads(render_sample("okta"))


# ---------------------------------------------------------------- reading queries

def test_tokenizer_handles_strings_regexes_and_comments():
    tokens = tokenize('a="x y" // comment\n| b=/fo+/i c!=3')
    assert ("string", "x y") in tokens
    assert ("regex", ("fo+", "i")) in tokens
    assert ("op", "!=") in tokens
    assert all("comment" not in str(value) for _, value in tokens)


def test_a_slash_in_a_bare_value_is_not_a_regex():
    assert check("Vendor.debugContext.debugData.requestUri=/api/v1/authn", OKTA, "okta-sso") is TRUE


@pytest.mark.parametrize("query,threshold", [
    ("x=1 | groupBy([user.name], function=count(as=failures)) | failures >= 5", 5),
    ("x=1 | groupBy([a]) | _count > 3", 4),
    ("x=1 | count(as=n) | n = 2", 2),
    ("x=1", 1),
])
def test_thresholds_after_an_aggregation(query, threshold):
    assert parse_rule(query).threshold == threshold


def test_distinct_counts_are_noted():
    rule_ = parse_rule("x=1 | groupBy([a], function=count(user.name, distinct=true, as=users)) | users >= 3")
    assert rule_.threshold == 3
    assert rule_.distinct_field == "user.name"


@pytest.mark.parametrize("query", ["#event_simpleName=ProcessRollup2", '#repo="base_sensor" x=1'])
def test_endpoint_rules_are_flagged(query):
    assert parse_rule(query).endpoint_only


def test_unsupported_functions_are_listed_not_guessed():
    assert "correlate" in parse_rule("#Vendor=okta | correlate(a: {x=1})").unsupported


# ---------------------------------------------------------------- evaluating one event

@pytest.mark.parametrize("query,expected", [
    ('Vendor.eventType="user.session.start"', TRUE),
    ('Vendor.eventType="user.session.end"', FALSE),
    ("Vendor.eventType=user.session.*", TRUE),
    ("Vendor.eventType=/SESSION/i", TRUE),
    ("Vendor.eventType=/SESSION/", FALSE),
    ('Vendor.eventType!="user.session.start"', FALSE),
    ("Vendor.securityContext.asNumber > 100", TRUE),
    ("Vendor.securityContext.asNumber < 100", FALSE),
    ('in(field=Vendor.eventType, values=["a", "user.session.start"])', TRUE),
    ('in(Vendor.eventType, values=["a", "b"])', FALSE),
    ('Vendor.client.ipAddress=* | cidr(Vendor.client.ipAddress, subnet="203.0.113.0/24")', TRUE),
    ('!cidr(Vendor.client.ipAddress, subnet=["10.0.0.0/8"])', TRUE),
    ('Vendor.eventType="nope" OR Vendor.severity="INFO"', TRUE),
    ('Vendor.severity="INFO" AND NOT Vendor.eventType="user.session.start"', FALSE),
    ('(Vendor.severity="WARN" or Vendor.severity="INFO") Vendor.outcome.result="SUCCESS"', TRUE),
    ('Vendor.eventType=~wildcard("USER.SESSION.*", ignoreCase=true)', TRUE),
    ('"User login to Okta"', TRUE),
    ("Vendor.target[0].id=x", FALSE),
])
def test_conditions_on_raw_vendor_fields(query, expected):
    assert check(query, OKTA, "okta-sso") is expected


def test_parser_tags_come_from_the_selected_parser():
    assert check('#Vendor="okta" #event.module="sso"', OKTA, "okta-sso") is TRUE
    assert check('#Vendor="aws"', OKTA, "okta-sso") is FALSE
    assert check('#Vendor="okta"', OKTA, None) is UNKNOWN


def test_mapped_ecs_fields_use_approximate_mappings():
    assert check('event.action="user.session.start" #event.outcome="success"', OKTA, "okta-sso") is TRUE
    assert check('source.ip="203.0.113.130"', OKTA, "okta-sso") is TRUE


def test_unknown_parser_fields_are_unknown_not_false():
    assert check('event.category="authentication"', OKTA, "okta-sso") is UNKNOWN


def test_plain_text_lines_expose_key_values():
    line = render_sample("cisco-firepower")
    fields = text_fields(line)
    assert fields["SrcIP"] == "192.0.2.30"
    assert check('AccessControlRuleAction="Allow" "430003"', line, "cisco-firepower") is TRUE


# ---------------------------------------------------------------- judging submissions and templates

def test_suggestions_name_the_raw_field_to_change():
    result = judge(rule('#Vendor="okta" Vendor.eventType="user.account.lock"'), [OKTA], "okta-sso")
    assert result["verdict"] == "unlikely"
    assert any('"eventType"' in s and "user.account.lock" in s for s in result["suggestions"])


def test_suggestions_catch_case_and_near_miss_field_names():
    event = dict(OKTA, eventtype="x")
    del event["eventType"]
    result = judge(rule('Vendor.eventType="user.session.start" Vendor.severity="info"'), [event], "okta-sso")
    text = " ".join(result["suggestions"])
    assert 'Did you mean "eventtype"' in text
    assert "case-sensitive" in text


def test_a_threshold_rule_needs_enough_matching_events():
    brute = rule('#Vendor="okta" Vendor.eventType="user.session.start" | groupBy([user.name]) | _count >= 3')
    assert judge(brute, [OKTA], "okta-sso")["verdict"] == "needs_more_events"
    assert judge(brute, [OKTA] * 3, "okta-sso")["verdict"] == "likely"


def test_only_enabled_configured_rules_will_fire():
    query = '#Vendor="okta" Vendor.eventType="user.session.start"'
    rules = [
        rule(query, rule_id="on"),
        rule(query, status="inactive", rule_id="off"),
        rule(query, source="template", rule_id="tpl"),
    ]
    firing = evaluate(rules, json.dumps(OKTA), "event", "okta-sso")["will_fire"]
    assert [r["key"] for r in firing] == ["configured:on"]


def test_latest_published_version_is_used():
    chosen = latest_configured(CONFIGURED_RULES)
    assert {r["id"] for r in chosen} == {"ver-1", "ver-2", "ver-3"}


@pytest.mark.parametrize("raw", CONFIGURED_RULES[:1] + CONFIGURED_RULES[2:] + RULE_TEMPLATES[:3], ids=lambda r: r["name"])
def test_every_generated_template_is_judged_likely(raw):
    normalized = normalize(raw, "configured" if raw.get("rule_id") else "template")
    log, note = build_template(normalized)
    is_text = isinstance(log, str)
    text = log if is_text else json.dumps(log)
    assert "NGSIEM-LogTester-TEST" in text
    events = events_of(text, "raw" if is_text else "event")
    assert judge(normalized, events, normalized["parser"])["verdict"] == "likely", note


def test_threshold_templates_hold_enough_events():
    brute = normalize(CONFIGURED_RULES[0], "configured")
    log, _ = build_template(brute)
    assert isinstance(log, list) and len(log) == 5


def test_endpoint_rules_get_no_template():
    entries = rule_templates([normalize(RULE_TEMPLATES[3], "template")])
    assert entries == []


def test_templates_are_grouped_by_vendor_and_product():
    entries = rule_templates([normalize(r, "template") for r in RULE_TEMPLATES])
    assert {e["group"] for e in entries} == {"Proofpoint / TAP", "Fortinet / FortiGate", "Okta / Okta SSO"}


# ---------------------------------------------------------------- the app

def test_rules_route_reports_counts(web):
    data = web.get("/api/rules?templates=1").get_json()
    assert data["success"]
    assert (data["configured"], data["enabled"], data["templates"]) == (3, 2, 4)
    assert all("_rule" not in r for r in data["rules"])


def test_missing_scope_is_reported_and_doesnt_block_submitting(web, mock):
    mock.rules_status = 403
    data = web.get("/api/rules").get_json()
    assert not data["success"]
    assert "scope" in data["message"]
    assert submit(web)["success"]


def test_rule_templates_route_lists_grouped_entries(web):
    templates = web.get("/api/rule-templates?templates=1").get_json()["templates"]
    assert {"AWS / CloudTrail", "Okta / Okta SSO", "Proofpoint / TAP"} <= {t["group"] for t in templates}
    assert all("log" not in t for t in templates)
    entry = next(t for t in templates if t["label"].startswith("AWS"))
    loaded = web.get(f"/api/sample-events/{entry['id']}").get_json()
    assert loaded["success"] and json.loads(loaded["log"])["eventName"] == "ConsoleLogin"


def test_evaluate_route_groups_results(web):
    log = web.get("/api/sample-events/" + next(
        t["id"] for t in web.get("/api/rule-templates?templates=1").get_json()["templates"] if t["label"].startswith("AWS")
    )).get_json()["log"]
    data = web.post("/api/evaluate", json={"log": log, "mode": "event", "include_templates": True}).get_json()
    assert data["success"] and data["rule_count"] == 7
    assert [g["group"] for g in data["will_fire"]] == ["AWS / CloudTrail"]


def aws_template(web):
    entry = next(t for t in web.get("/api/rule-templates").get_json()["templates"] if t["label"].startswith("AWS"))
    return web.get(f"/api/sample-events/{entry['id']}").get_json()["log"]


@pytest.fixture
def aws_connector(mock):
    mock.connections.append(_connection("conn-aws", "CloudTrail prod", "aws-cloudtrail", "Push", "AWS", "CloudTrail"))
    return "conn-aws"


def test_the_connectors_parser_decides_whether_a_rule_fires(web, mock):
    # The same AWS log through the Okta connector gets #Vendor="okta", so the AWS rule can't fire.
    response = web.post("/api/submit", json={"connector_id": "conn-okta", "log": aws_template(web), "mode": "event"}).get_json()
    assert response["success"], response


def test_submission_that_would_fire_needs_acknowledgement_first(web, mock, forensic_path, aws_connector):
    response = web.post("/api/submit", json={"connector_id": aws_connector, "log": aws_template(web), "mode": "event"}).get_json()
    assert response["needs_acknowledgement"]
    assert [r["name"] for g in response["will_fire"] for r in g["rules"]] == ["AWS - Console login without MFA"]
    assert mock.created == []
    assert not forensic_path.exists()


def test_acknowledged_submission_proceeds_and_is_recorded(web, mock, forensic_path, aws_connector):
    first = web.post("/api/submit", json={"connector_id": aws_connector, "log": aws_template(web), "mode": "event"}).get_json()
    keys = [r["key"] for g in first["will_fire"] for r in g["rules"]]
    result = web.post("/api/submit", json={
        "connector_id": aws_connector, "log": aws_template(web), "mode": "event", "acknowledged_rules": keys,
    }).get_json()
    assert result["success"], result
    started = records(forensic_path)[0]
    assert started["correlation_rule_check"]["status"] == "checked"
    assert [r["name"] for r in started["correlation_rule_check"]["acknowledged"]] == ["AWS - Console login without MFA"]


def test_acknowledging_only_some_rules_is_not_enough(web, mock, aws_connector):
    response = web.post("/api/submit", json={
        "connector_id": aws_connector, "log": aws_template(web), "mode": "event", "acknowledged_rules": ["configured:other"],
    }).get_json()
    assert response["needs_acknowledgement"]
    assert mock.created == []


def test_rules_that_arent_enabled_dont_need_acknowledgement(web, mock, aws_connector):
    mock.rules = [dict(r, status="inactive") for r in mock.rules]
    web.get("/api/rules?refresh=1")
    response = web.post("/api/submit", json={"connector_id": aws_connector, "log": aws_template(web), "mode": "event"}).get_json()
    assert response["success"], response


# ---------------------------------------------------------------- shapes found in the live tenant's rules

TAP_RULE = (
    '#Vendor="proofpoint" #event.module="tap" #repo!="xdr*"\n'
    '| #event.kind="event"\n'
    '| array:contains(array="event.category[]", value="email")\n'
    '| case {\n'
    '    event.action="messages-delivered";\n'
    '    event.action="delivered" Vendor.eventType="messagesDelivered";\n'
    '}\n'
    '| Vendor.spamScore>70'
)


def tap_message(score, event_type="messagesDelivered"):
    return dict(json.loads(render_sample("proofpoint-tap")), spamScore=score, eventType=event_type)


def test_repo_not_equal_xdr_is_not_an_endpoint_rule():
    assert not parse_rule(TAP_RULE).endpoint_only
    assert parse_rule('#repo="base_sensor" x=1').endpoint_only


def test_case_branches_are_an_or():
    tap = rule(TAP_RULE)
    assert judge(tap, [tap_message(90)], "proofpoint-tap")["verdict"] == "likely"
    assert judge(tap, [tap_message(90, "messagesBlocked")], "proofpoint-tap")["verdict"] == "unlikely"


def test_proofpoint_event_action_comes_from_event_type_like_the_parser():
    for event_type, action in [("messagesDelivered", "messages-delivered"), ("messagesBlocked", "messages-blocked"),
                               ("clicksPermitted", "clicks-permitted"), ("clicksBlocked", "clicks-blocked")]:
        assert check(f'event.action="{action}"', tap_message(1, event_type), "proofpoint-tap") is TRUE
    assert check('event.action="messages-delivered"', tap_message(1, "somethingElse"), "proofpoint-tap") is not TRUE


def test_a_message_without_event_type_is_told_to_add_it():
    message = tap_message(90)
    del message["eventType"]
    result = judge(rule(TAP_RULE), [message], "proofpoint-tap")
    assert result["verdict"] != "likely"
    assert any('"eventType"' in s and "messagesDelivered" in s for s in result["suggestions"])


def test_a_batch_envelope_is_not_treated_as_events():
    # The parser reads one message per event, so a {"messagesDelivered": [...]} wrapper isn't split.
    result = judge(rule(TAP_RULE), [{"messagesDelivered": [tap_message(90)]}], "proofpoint-tap")
    assert result["verdict"] != "likely"


def test_no_suggestions_once_a_rule_matches():
    result = judge(rule(TAP_RULE), [tap_message(90)], "proofpoint-tap")
    assert result["suggestions"] == []


def test_array_contains_uses_the_parsers_categories_and_raw_arrays():
    assert check('array:contains(array="event.category[]", value="email")', tap_message(1), "proofpoint-tap") is TRUE
    assert check('array:contains(array="Vendor.toAddresses[]", value="recipient@example.com")', tap_message(1), "proofpoint-tap") is TRUE
    assert check('array:contains(array="event.type[]", value="x")', tap_message(1), "proofpoint-tap") is UNKNOWN


def test_assignment_inside_a_function_doesnt_hide_it():
    query = '#repo!="xdr*" | #event.kind="event" | correlate(a: { #Vendor="okta" | _k := user.name }, b: {x=1})'
    assert "correlate" in parse_rule(query).unsupported


def test_matching_only_parser_tags_is_not_called_likely():
    result = judge(rule('#Vendor="okta" #event.kind="event"'), [OKTA], "okta-sso")
    assert result["verdict"] == "uncertain"


def test_backslashes_in_strings_are_literal():
    tokens = tokenize(r'Vendor.path="C:\Users\test\file.exe" x="a\"b"')
    assert ("string", r"C:\Users\test\file.exe") in tokens
    assert ("string", 'a"b') in tokens


def test_a_comparison_with_a_computed_value_is_unknown():
    assert check("Vendor.eventType=lower(Vendor.severity)", OKTA, "okta-sso") is UNKNOWN


def test_one_unreadable_rule_doesnt_stop_the_others(web, mock):
    mock.templates.append({"id": "tpl-bad", "name": "Broken", "search": {"filter": None}, "vendors": ["X"]})
    mock.templates.append({"id": "tpl-odd", "name": "Odd", "search": {"filter": '"unterminated'}})
    data = web.get("/api/rules?refresh=1&templates=1").get_json()
    assert data["templates"] >= 4


def test_templates_use_the_vendors_list_for_grouping():
    multi = normalize({"id": "m", "name": "Multi", "vendors": ["Apache", "F5"], "search": {"filter": "x=1"}}, "template")
    assert (multi["vendor"], multi["product"]) == ("Apache, F5", "Multiple sources")


def test_a_template_used_by_a_configured_rule_is_listed_once(web, mock):
    mock.rules[0]["template_id"] = "tpl-okta-admin"
    rules = web.get("/api/rules?refresh=1&templates=1").get_json()["rules"]
    assert "Okta - Admin role granted" not in [r["name"] for r in rules]


def test_tap_template_is_one_message_with_its_event_type():
    tap = rule(TAP_RULE)
    tap["parser"] = "proofpoint-tap"
    log, _ = build_template(tap)
    assert log["eventType"] == "messagesDelivered"
    assert "messagesDelivered" not in log
    assert judge(tap, [log], "proofpoint-tap")["verdict"] == "likely"


def test_suggestions_follow_the_branch_closest_to_passing():
    low = tap_message(10)
    suggestions = judge(rule(TAP_RULE), [low], "proofpoint-tap")["suggestions"]
    assert any("spamScore" in s for s in suggestions)
    assert not any("messages-delivered" in s for s in suggestions)


def test_vendor_comes_from_an_unmapped_parsers_name():
    assert check('#Vendor="vmware"', OKTA, "vmware-esxi") is TRUE
    assert check('#Vendor="okta"', OKTA, "vmware-esxi") is FALSE


# ---------------------------------------------------------------- configured rules by default, templates on request

TEMPLATE_CALLS = ("GET", "/correlation-rules/queries/templates/v1")


def test_only_configured_rules_load_by_default(web, mock):
    data = web.get("/api/rules").get_json()
    assert (data["configured"], data["templates"]) == (3, 0)
    entries = web.get("/api/rule-templates").get_json()
    assert {t["rule_source"] for t in entries["templates"]} == {"configured"}
    assert entries["templates_loaded"] is False
    assert TEMPLATE_CALLS not in mock.calls


def test_templates_load_only_when_asked(web, mock):
    entries = web.get("/api/rule-templates?templates=1").get_json()
    assert "template" in {t["rule_source"] for t in entries["templates"]}
    assert entries["templates_loaded"] is True
    assert mock.calls.count(TEMPLATE_CALLS) == 1
    web.get("/api/rule-templates?templates=1")
    assert mock.calls.count(TEMPLATE_CALLS) == 1  # Cached.


def test_live_check_includes_templates_only_when_asked(web, mock):
    log = render_sample("okta")
    without = web.post("/api/evaluate", json={"log": log, "mode": "event"}).get_json()
    assert without["rule_count"] == 3
    assert TEMPLATE_CALLS not in mock.calls
    with_templates = web.post("/api/evaluate", json={"log": log, "mode": "event", "include_templates": True}).get_json()
    assert with_templates["rule_count"] == 7


def test_submitting_never_loads_templates(web, mock):
    assert submit(web)["success"]
    assert TEMPLATE_CALLS not in mock.calls


def test_a_template_sample_loads_once_templates_are_loaded(web):
    entries = web.get("/api/rule-templates?templates=1").get_json()["templates"]
    template = next(t for t in entries if t["rule_source"] == "template")
    loaded = web.get(f"/api/sample-events/{template['id']}").get_json()
    assert loaded["success"] and loaded["log"]
    if template["format"] == "json":
        assert json.loads(loaded["log"])


def test_a_configured_rule_sample_loads_without_templates(web, mock):
    entries = web.get("/api/rule-templates").get_json()["templates"]
    loaded = web.get(f"/api/sample-events/{entries[0]['id']}").get_json()
    assert loaded["success"]
    assert TEMPLATE_CALLS not in mock.calls


# ---------------------------------------------------------------- parser-aligned readers and mappings

from field_model import EventView as View, read_text, PROFILES as PARSER_PROFILES


def test_windows_xml_is_read_like_the_parser():
    view = View(render_sample("windows-system"), "microsoft-windows")
    assert view.raw["Event.System.EventID"] == "7036"
    assert view.raw["Event.System.Channel"] == "System"
    assert view.raw["Event.System.Provider._Name"] == "Service Control Manager"
    assert view.raw["Event.EventData.param2"] == "running"
    assert check('Vendor.Event.System.EventID="7036" event.code="7036"', render_sample("windows-system"), "microsoft-windows") is TRUE


def test_vcenter_event_lines_are_read_like_the_parser():
    view = View(render_sample("vmware-vsphere"), "vmware-vcenter")
    assert view.raw["appname"] == "vpxd"
    assert view.raw["eventType"] == "vim.event.UserLoginSessionEvent"
    assert check("Vendor.eventType=/UserLogin/", render_sample("vmware-vsphere"), "vmware-vcenter") is TRUE


def test_epic_xml_and_mnemonics_are_read_like_the_parser():
    text = render_sample("epic-ehr")
    view = View(text, "epic-ehr")
    assert view.raw["EventLog.E1Mid"] == "LOGIN"
    assert view.raw["Mnemonics.IP"] == "192.0.2.90"
    assert check('event.action="LOGIN" Vendor.Mnemonics.SUCCESS="Yes"', text, "epic-ehr") is TRUE


def test_paloalto_csv_is_read_by_column_like_the_parser():
    text = render_sample("paloalto-ngfw")
    view = View(text, "paloalto-ngfw")
    assert view.raw["Type"] == "TRAFFIC"
    assert view.raw["Action"] == "allow"
    assert view.raw["SourceAddress"] == "192.0.2.140"
    assert check('event.action="allow" source.ip="192.0.2.140" Vendor.RuleName=*rule', text, "paloalto-ngfw") is TRUE


def test_paloalto_csv_after_a_syslog_header():
    text = "<14>Nov 09 18:00:00 fw01 " + render_sample("paloalto-ngfw")
    assert View(text, "paloalto-ngfw").raw["Action"] == "allow"


def test_fortinet_key_values_after_the_priority():
    view = View(render_sample("fortinet-firewall"), "fortinet-fortigate")
    assert view.raw["date"] and view.raw["action"] == "accept"


def test_fortinet_event_action_only_for_utm_blocks():
    text = render_sample("fortinet-firewall")
    assert check('event.action="accept"', text, "fortinet-fortigate") is not TRUE
    assert check('event.action="block"', text + " utmaction=block", "fortinet-fortigate") is TRUE


def test_entra_action_and_outcome_follow_the_parser():
    entra = json.loads(render_sample("microsoft-entra"))
    assert check('event.action="sign-in-activity" #event.outcome="success"', entra, "microsoft-entra-id") is TRUE
    entra["properties"]["status"]["errorCode"] = 50126
    assert check('#event.outcome="failure"', entra, "microsoft-entra-id") is TRUE


def test_cloudflare_action_and_prisma_names_follow_the_parsers():
    assert check('event.action="block"', json.loads(render_sample("cloudflare")), "cloudflare-waf") is TRUE
    prisma = json.loads(render_sample("paloalto-prisma"))
    assert check('event.action="gateway-connected" user.name="test.user@example.com"', prisma, "paloalto-prisma-access") is TRUE


def test_a_reader_falls_back_to_key_values_for_other_text():
    assert read_text("not xml at all key=value", PARSER_PROFILES["microsoft-windows"]) == {"key": "value"}


def test_every_sample_names_its_parser_and_has_a_profile():
    from sample_events import SAMPLES
    for sample in SAMPLES:
        if sample["id"] == "cisco-ucs":
            assert sample["parser"] is None
            continue
        assert sample["parser"] in PARSER_PROFILES, sample["id"]
        assert PARSER_PROFILES[sample["parser"]]["sample"] == sample["id"]


def test_text_samples_keep_their_format_in_templates():
    windows = rule('#Vendor="microsoft" #event.module="windows" Vendor.Event.System.EventID="4624"')
    windows["parser"] = "microsoft-windows"
    log, note = build_template(windows)
    assert log.startswith("<Event")
    assert "4624" in note
    entry = template_entry(windows)
    assert entry["format"] == "text"


def test_fortinet_templates_edit_the_key_value_line():
    fortinet = rule('#Vendor=fortinet Vendor.action="deny" Vendor.dstcountry="Testland"')
    fortinet["parser"] = "fortinet-fortigate"
    log, _ = build_template(fortinet)
    assert isinstance(log, str) and log.startswith("<189>")
    assert "action=deny" in log or 'action="deny"' in log
    assert "dstcountry=Testland" in log
    assert judge(fortinet, [log], "fortinet-fortigate")["verdict"] == "likely"
