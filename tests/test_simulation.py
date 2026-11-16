"""Parser simulation, lineage, regex samples, generation, rule refresh and verification."""
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from falcon_client import FalconError  # noqa: E402
from lineage import Lineage  # noqa: E402
from parser_sim import SimError, parse_script, simulate  # noqa: E402
from regex_sample import sample, substitute  # noqa: E402
from rules import RuleBook, evaluate, normalize, refresh_minutes_from, template_entry  # noqa: E402
from simulation import Simulation  # noqa: E402
import verify as verify_module  # noqa: E402

# A parser in the style of CrowdStrike's: JSON with a Vendor. prefix, tags, case and match blocks.
JSON_PARSER = r'''
// comment at the start
parseJson(prefix="Vendor.", excludeEmpty=true, handleNull=discard)
| Vendor := "acme"
| event.module := "mail"
| event.kind := "event"
| event.reason := Vendor.classification
| array:append("event.category[]", values="email")
| case {
    Vendor.eventType = /clicks?Permitted/ | Vendor.eventType := "clicksPermitted";
    *;
}
| Vendor.eventType match {
    "clicksPermitted" => event.action := "clicks-permitted" | event.outcome := "success";
    "messagesDelivered" => event.action := "messages-delivered";
    * => *;
}
| event.dataset := format("mail.%s", field=[Vendor.kind])
| source.ip := lower(Vendor.senderIP)
'''

SYSLOG_PARSER = r'''
case {
    @rawstring = /^(?<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<host.name>\S+)\s+(?<log.syslog.appname>[\w-]+)(\[(?<log.syslog.procid>\d+)\])?:\s+(?<message>.*)/;
}
| Vendor := "acme"
| event.module := "box"
| log.syslog.appname =~ regex("(?<_app>[a-z]+)", strict=false)
| format(format="box.%s", field=[_app], as="event.dataset")
'''

TAGS = ["Vendor", "event.module", "event.kind", "event.dataset", "event.outcome"]


# ---- simulator

def test_simulates_json_parser_with_case_and_match():
    raw = json.dumps({"eventType": "clickPermitted", "classification": "phish", "senderIP": "192.0.2.10", "kind": "click"})
    result = simulate(JSON_PARSER, raw, TAGS)
    assert not result.dropped and not result.error
    assert result.fields["Vendor.eventType"] == "clicksPermitted"
    assert result.fields["event.action"] == "clicks-permitted"
    assert result.fields["event.reason"] == "phish"
    assert result.fields["event.category[0]"] == "email"
    assert result.fields["event.dataset"] == "mail.click"
    assert result.tags()["#Vendor"] == "acme"


def test_missing_source_leaves_field_unset():
    result = simulate(JSON_PARSER, json.dumps({"eventType": "messagesDelivered"}), TAGS)
    assert "event.reason" not in result.fields
    assert result.fields["event.action"] == "messages-delivered"


def test_case_without_match_drops_the_event():
    result = simulate(SYSLOG_PARSER, "not a syslog line", TAGS)
    assert result.dropped


def test_regex_extraction_with_dotted_group_names():
    result = simulate(SYSLOG_PARSER, "Nov 13 10:00:00 host1 vobd[42]: something happened", TAGS)
    assert result.fields["log.syslog.appname"] == "vobd"
    assert result.fields["host.name"] == "host1"
    assert result.fields["event.dataset"] == "box.vobd"


def test_unknown_functions_are_reported_not_guessed():
    result = simulate('parseJson() | x := mysteryFunction(field=a) | match(file="lookup.csv", field=a, include=[b])',
                      json.dumps({"a": "1"}))
    assert "mysteryfunction()" in result.unsupported
    assert "match(file=...)" in result.unsupported
    assert {"x", "b"} <= result.unknown
    assert result.approximate


def test_kvparse_and_cef():
    result = simulate('kvParse(as="Vendor")', 'date=2026-01-01 action="accept now" srcip=192.0.2.1')
    assert result.fields["Vendor.action"] == "accept now"
    cef = simulate('parseCEF(prefix="Vendor.", headerprefix="Vendor.")', "CEF:0|Acme|Box|1.0|100|Test|5|src=192.0.2.1 act=blocked")
    assert cef.fields["Vendor.device.vendor"] == "Acme" and cef.fields["Vendor.act"] == "blocked"


def test_comments_after_semicolons_are_not_regexes():
    script = "case {\n  a = 1 | b := \"x\"; // a comment\n  *;\n} // trailing\n| c := \"y\""
    parse_script(script)


def test_syntax_errors_raise():
    with pytest.raises(SimError):
        parse_script("case { a = 1 ")


# ---- lineage

def test_lineage_traces_fields_to_raw_fields_and_conditions():
    lineage = Lineage(JSON_PARSER)
    assert lineage.format == "json"
    assert lineage.raw_source("event.reason") == "classification"
    assert "classification" in lineage.hint("event.reason", "phish")
    assert 'Vendor.eventType is "clicksPermitted"' in lineage.hint("event.action", "clicks-permitted")


def test_lineage_finds_syslog_gates():
    lineage = Lineage(SYSLOG_PARSER)
    assert lineage.format is None
    assert lineage.gates and lineage.gates[0]


# ---- regex samples

def test_regex_sample_with_overrides():
    pattern = r"^(?<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?<host.name>\S+)\s+(?<log.syslog.appname>[\w-]+):\s+(?<message>.*)"
    line = sample(pattern, "", {"log.syslog.appname": "vobd", "message": "hello world"})
    assert line and "vobd: hello world" in line
    assert sample(r"PHP Fatal error:\s+Allowed memory size of \d+ bytes", "") == "PHP Fatal error: Allowed memory size of 1 bytes"


def test_regex_substitute_keeps_the_rest():
    assert substitute(r"(^|\.)(?<svc>\S+?)\.", "", "signin.amazonaws.com", {"svc": "bedrock"}) == "bedrock.amazonaws.com"


# ---- generation with a simulation

class FakeStore:
    def __init__(self, parsers):
        self.parsers = parsers

    def index(self):
        return {name: {"Name": name, "ID": f"x:{1}", "vendor": "acme", "product": [name]} for name in self.parsers}

    def resolve(self, name):
        return name if name in self.parsers else None

    def get(self, name):
        if name not in self.parsers:
            return None
        return {"name": name, "version": "1", "script": self.parsers[name], "tag_fields": TAGS, "vendor": "acme", "product": [name]}


def rule(query, name="Acme rule", source="template"):
    return normalize({"id": "r1", "name": name, "search": {"filter": query}, "status": "active"}, source)


def test_generator_builds_a_log_the_parser_turns_into_a_match():
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="acme" #event.module="mail" | event.reason=/phish/i | event.action="clicks-permitted"')
    entry = template_entry(r, sim)
    assert entry and entry["simulated"] and entry["verdict"] == "likely", entry
    log = json.loads(entry["log"])
    assert log["classification"].lower().startswith("phish")
    assert log["eventType"] == "clicksPermitted"


def test_generator_builds_syslog_lines():
    sim = Simulation(FakeStore({"acme-box": SYSLOG_PARSER}))
    r = rule('#Vendor="acme" #event.dataset="box.vobd" | log.syslog.appname="vobd" | message=/changed to disabled/i')
    entry = template_entry(r, sim)
    assert entry["verdict"] == "likely", entry
    assert "vobd" in entry["log"] and "changed to disabled" in entry["log"]


def test_incomplete_samples_say_why():
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="acme" #event.module="mail" | correlate(a: {x=1}, b: {y=2}, sequence=false, within=1h)')
    entry = template_entry(r, sim)
    assert entry["incomplete"] and entry["note"]


def test_rule_check_uses_the_simulation_and_explains_uncertainty():
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="acme" | event.reason="phish"', source="configured")
    r["enabled"] = True
    raw = json.dumps({"eventType": "clicksPermitted", "classification": "phish"})
    checked = evaluate([r], raw, "event", "acme-mail", sim)
    assert checked["results"][0]["verdict"] == "likely" and checked["results"][0]["simulated"]
    lookup = rule('#Vendor="acme" | b="1"', source="configured")
    unknown_parser = 'parseJson(prefix="Vendor.") | Vendor := "acme" | match(file="l.csv", field=Vendor.a, include=[b])'
    sim2 = Simulation(FakeStore({"acme-lookup": unknown_parser}))
    result = evaluate([lookup], json.dumps({"a": "1"}), "event", "acme-lookup", sim2)["results"][0]
    assert result["verdict"] == "uncertain"
    assert any("lookup" in reason for reason in result["reasons"])


# ---- rule refresh (P7, P8)

def test_refresh_minutes_setting():
    assert refresh_minutes_from(None) == 15
    assert refresh_minutes_from("") == 15
    assert refresh_minutes_from("0") == 0
    assert refresh_minutes_from(" 30 ") == 30
    for bad in ("1.5", "-1", "ten"):
        with pytest.raises(ValueError):
            refresh_minutes_from(bad)


class RuleClient:
    def __init__(self):
        self.calls = 0
        self.rules = [{"id": "a", "rule_id": "a", "name": "A", "status": "active", "search": {"filter": '#Vendor="x"'}}]

    def list_correlation_rules(self, log):
        self.calls += 1
        return list(self.rules)


def test_version_changes_only_when_rules_change():
    client = RuleClient()
    book = RuleBook(client, refresh_minutes=15)
    book.load(None)
    first = book.status()["version"]
    book.load(None, refresh=True)
    assert book.status()["version"] == first
    client.rules.append({"id": "b", "rule_id": "b", "name": "B", "status": "active", "search": {"filter": '#Vendor="y"'}})
    book.load(None, refresh=True)
    assert book.status()["version"] == first + 1


def test_max_age_forces_a_fresh_read():
    client = RuleClient()
    book = RuleBook(client, refresh_minutes=15)
    book.load(None)
    book.load(None)
    assert client.calls == 1
    book._cache["configured"] = (book._cache["configured"][0], None, book._cache["configured"][2] - 120)
    book.load(None, max_age=60)
    assert client.calls == 2


def test_failed_refresh_keeps_known_rules():
    client = RuleClient()
    book = RuleBook(client, refresh_minutes=15)
    rules, _ = book.load(None)
    client.list_correlation_rules = lambda log: (_ for _ in ()).throw(FalconError("down"))
    again, error = book.load(None, refresh=True)
    assert len(again) == len(rules) == 1 and error


def test_refresher_off_when_zero():
    assert RuleBook(RuleClient(), refresh_minutes=0).start_refresher(lambda: None) is None


# ---- verification (P5)

class SearchClient:
    def __init__(self, events):
        self.events, self.queries = events, []

    def start_search(self, repo, query, start, log, end="now"):
        self.queries.append(query)
        return "job1"

    def get_search(self, repo, job_id, log):
        return {"done": True, "events": self.events}


class Log:
    def info(self, *a):
        pass


def test_verify_compares_real_parsing_and_checks_rules():
    raw = json.dumps({"eventType": "clicksPermitted", "classification": "phish", "id": "NGSIEM-LogTester-TEST-CLICK-1"})
    real = {"@rawstring": raw, "#Vendor": "acme", "event.reason": "phish", "event.action": "clicks-permitted"}
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="acme" | event.reason="phish"')
    submission = {"time": datetime.now(timezone.utc) - timedelta(minutes=3), "text": raw, "parser": "acme-mail"}
    from rules import judge
    client = SearchClient([real])
    out = verify_module.verify(client, submission, [r], sim, judge, Log())
    assert out["found"] == 1 and "NGSIEM-LogTester-TEST-CLICK-1" in client.queries[0]
    assert out["events"][0]["rules"][0]["verdict"] == "likely"
    assert out["events"][0]["comparison"]["matching_fields"] >= 2


def test_verify_reports_nothing_found_yet():
    sim = Simulation(None)
    submission = {"time": datetime.now(timezone.utc), "text": '{"a": "NGSIEM-LogTester-TEST"}', "parser": None}
    from rules import judge
    out = verify_module.verify(SearchClient([]), submission, [], sim, judge, Log())
    assert out["found"] == 0 and "few minutes" in out["message"]


# ---- accepting a suggestion

from suggest import apply_suggestion, want_from_condition  # noqa: E402


def test_want_from_condition():
    assert want_from_condition({"op": "=", "expected": "/phish/i"}) == ("regex", ("phish", "i"))
    assert want_from_condition({"op": "=", "expected": "*"}) == ("exists",)
    assert want_from_condition({"op": "in", "expected": "a, b"}) == ("in", ["a", "b"])
    assert want_from_condition({"op": ">", "expected": "70"}) == ("num", ">", "70")


def test_suggestion_is_applied_through_the_parser():
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="acme" | event.reason=/phish/i | event.action="clicks-permitted"')
    text = json.dumps({"eventType": "messagesDelivered", "senderIP": "192.0.2.10"})
    from rules import judge
    check = judge(r, [json.loads(text)], "acme-mail", sim)
    fixes = [f for f in check["fixes"] if f["kind"] == "field"]
    assert len(fixes) == 2
    first = apply_suggestion(r, text, "event", "acme-mail", sim, fixes[0])
    assert first["success"] and first["verdict"] != "likely"
    both = apply_suggestion(r, text, "event", "acme-mail", sim, {"kind": "all"})
    assert both["success"] and both["verdict"] == "likely", both
    fixed = json.loads(both["log"])
    assert fixed["eventType"] == "clicksPermitted" and "phish" in fixed["classification"].lower()
    assert fixed["senderIP"] == "192.0.2.10"  # the rest of the log is kept


def test_suggestions_about_the_connector_have_no_apply():
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="other" | event.reason="phish"')
    from rules import judge
    check = judge(r, [{"classification": "spam"}], "acme-mail", sim)
    vendor_fix = next(f for f in check["fixes"] if "connector" in f["text"].lower() or "#Vendor" in f["text"])
    assert vendor_fix["kind"] is None


def test_repeat_suggestion_makes_enough_events():
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="acme" | event.reason="phish" | groupBy([source.ip], function=count(as=n)) | n >= 3')
    text = json.dumps({"classification": "phish", "senderIP": "192.0.2.10"})
    out = apply_suggestion(r, text, "event", "acme-mail", sim, {"kind": "repeat"})
    assert out["success"] and len(json.loads(out["log"])) == 3


def test_suggestion_without_simulation_uses_mappings():
    r = normalize({"id": "o1", "name": "Okta rule", "search": {"filter": '#Vendor="okta" | event.action="user.session.start"'}}, "template")
    text = json.dumps({"eventType": "user.account.lock"})
    out = apply_suggestion(r, text, "event", "okta-sso", Simulation(None), {"kind": "all"})
    assert out["success"] and json.loads(out["log"])["eventType"] == "user.session.start"


def test_apply_suggestion_route(tmp_path):
    from app import create_app
    from app_settings import AppSettings
    from falcon_client import FalconClient
    from forensic_log import ForensicLog
    client = FalconClient("id", "secret", "http://127.0.0.1:1", timeout=1)
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    web = create_app(client, forensic=ForensicLog(tmp_path / "f.jsonl"), app_settings=AppSettings(tmp_path / "s.json", tmp_path / "b"),
                     admin_password="", access_password="", allowed_hosts="", rule_refresh_minutes=0, simulation=sim)
    book = web.extensions["rulebook"]
    r = rule('#Vendor="acme" | event.reason="phish"', source="configured")
    import time as _t
    book._cache["configured"] = ([r], None, _t.time())
    tc = web.test_client()
    body = {"log": json.dumps({"classification": "spam"}), "mode": "event", "rule_key": r["key"],
            "fix": {"kind": "all"}, "sample_id": None}
    # No connector or sample is selected, so name the parser through the rule's own sample entry.
    r["parser"] = "acme-mail"
    out = tc.post("/api/apply-suggestion", json=body).get_json()
    assert out["success"] and json.loads(out["log"])["classification"] == "phish", out
    missing = tc.post("/api/apply-suggestion", json={**body, "rule_key": "configured:nope"})
    assert missing.status_code == 404


# ---- timestamps, conditional evaluation, the field catalog and the audit

from catalog import audit_event, catalog_parser  # noqa: E402
from parser_sim import check_timestamp  # noqa: E402
from timestamps import format_timestamp  # noqa: E402

CLICK_PARSER = r'''
parseJson(prefix="Vendor.", excludeEmpty=true, handleNull=discard)
| case {
    Vendor.messageTime=* | @timestamp := parseTimestamp("yyyy-MM-dd'T'HH:mm:ss.SSSX", field=Vendor.messageTime);
    Vendor.threatTime=* AND Vendor.clickTime=* | parseTimestamp("yyyy-MM-dd'T'HH:mm:ss.SSSX", field=Vendor.clickTime);
    * | parseTimestamp("yyyy-MM-dd'T'HH:mm:ss.SSSX", field=Vendor.clickTime);
}
| Vendor := "acme"
| event.module := "mail"
| destination.ip := Vendor.clickIP
| Vendor.eventType match {
    "clicksPermitted" => url.original := Vendor.url;
    * => *;
}
'''


@pytest.mark.parametrize("fmt", ["yyyy-MM-dd'T'HH:mm:ss.SSSX", "yyyy-MM-dd'T'HH:mm:ss[.SSSSSSSSS]XXXXX", "MMM [ ]d[d] HH:mm:ss",
                                 "dd/MMM/yyyy:HH:mm:ss Z", "yyyy/MM/dd HH:mm:ss[.SSSSSS]", "seconds", "millis",
                                 "EEE MMM dd HH:mm:ss[.SSSSSS] yyyy", "MMM dd yyyy HH:mm:ss z"])
def test_formatted_timestamps_parse_with_their_own_format(fmt):
    assert check_timestamp(format_timestamp(fmt), fmt) == (True, "")


def test_timestamp_checks_follow_the_documented_rules():
    iso = "yyyy-MM-dd'T'HH:mm:ss[.SSSSSSSSS]XXXXX"
    assert check_timestamp("2018-09-08T17:51:04.777Z", iso)[0]          # default format, 3-digit fraction
    assert check_timestamp("2018-09-08T17:51:04.777777777Z", iso)[0]    # up to 9 digits
    assert check_timestamp("1690480444.589", "seconds")[0]              # seconds with milliseconds
    assert not check_timestamp("2026-01-01 10:00:00", "yyyy-MM-dd'T'HH:mm:ss.SSSX")[0]
    assert not check_timestamp(None, iso)[0]


def test_a_bad_timestamp_adds_error_but_keeps_the_event():
    result = simulate(CLICK_PARSER, json.dumps({"messageTime": "not a time"}), TAGS)
    assert not result.dropped and result.fields.get("@error") == "true"
    assert result.timestamps[0]["ok"] is False


def test_match_guards_and_fall_through_follow_the_documentation():
    assert simulate('parseJson() | a match { ** => b := "e"; * => b := "any" }', json.dumps({"a": "1"})).fields["b"] == "e"
    assert simulate('parseJson() | a match { ** => b := "e"; * => b := "any" }', json.dumps({})).fields["b"] == "any"
    assert simulate('parseJson() | a match { true => b := "t" }', json.dumps({})).fields["b"] == "t"
    fell = simulate('parseJson() | a match { "1" => x = 2 | b := "first"; * => b := "next" }', json.dumps({"a": "1"}))
    assert fell.fields["b"] == "next"


def test_catalog_lists_fields_timestamps_and_conditions():
    entry = catalog_parser({"name": "acme-mail", "version": "1", "script": CLICK_PARSER, "tag_fields": TAGS})
    stamps = {(t["field"], t["format"]) for t in entry["timestamps"]}
    assert ("Vendor.messageTime", "yyyy-MM-dd'T'HH:mm:ss.SSSX") in stamps
    assert ("Vendor.clickTime", "yyyy-MM-dd'T'HH:mm:ss.SSSX") in stamps
    assert entry["fields"]["destination.ip"][0]["raw_field"] == "clickIP"
    assert entry["fields"]["url.original"][0]["when"] == ['Vendor.eventType is "clicksPermitted"']
    assert "clickIP" in entry["raw_inputs"] and entry["format"] == "json"


def test_audit_reports_missing_inputs_on_the_logs_branch():
    doc = {"name": "acme-mail", "script": CLICK_PARSER, "tag_fields": TAGS}
    click = {"eventType": "clicksPermitted", "clickTime": "2026-01-01T00:00:00.000Z", "threatTime": "2026-01-01T00:00:00.000Z"}
    report = audit_event(doc, json.dumps(click), set(click))
    missing = {m["field"]: m for m in report["missing_inputs"]}
    assert missing["url.original"]["raw_field"] == "url" and missing["url.original"]["when"]
    assert missing["destination.ip"]["raw_field"] == "clickIP"
    message = {"eventType": "messagesDelivered", "messageTime": "2026-01-01T00:00:00.000Z"}
    assert "url.original" not in {m["field"] for m in audit_event(doc, json.dumps(message), set(message))["missing_inputs"]}
    bad = audit_event(doc, json.dumps({"eventType": "clicksPermitted"}), {"eventType"})
    assert bad["timestamps"] and bad["timestamps"][0]["field"] == "Vendor.clickTime"


def test_generated_samples_carry_parseable_timestamps():
    sim = Simulation(FakeStore({"acme-mail": CLICK_PARSER}))
    r = rule('#Vendor="acme" #event.module="mail" | url.original="https://example.com/x"')
    entry = template_entry(r, sim)
    log = json.loads(entry["log"])
    result = sim.run("acme-mail", json.dumps(log))
    assert result.timestamps and all(t["ok"] for t in result.timestamps), result.timestamps
    assert entry["verdict"] == "likely"


# ---- recent timestamps and timezones

from timestamps import has_zone, moment_for, system_zone_label  # noqa: E402

ZONE_FIELD_PARSER = r'''
case {
    @rawstring = /^(?<_ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?<event.timezone>\S+) (?<host.name>\S+): (?<message>.*)/;
}
| parseTimestamp(format="MMM [ ]d[d] HH:mm:ss", field=_ts, timezoneField=event.timezone)
| Vendor := "acme"
| event.module := "wlc"
'''


def test_zone_rules():
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert moment_for("yyyy-MM-dd'T'HH:mm:ssXXX", now).utcoffset() == now.astimezone().utcoffset()  # system zone, stated
    assert moment_for("yyyy-MM-dd HH:mm:ss", now, tz="Asia/Tokyo").utcoffset() == timedelta(hours=9)
    assert moment_for("yyyy-MM-dd HH:mm:ss", now).utcoffset() == timedelta(0)  # zone-less: NG-SIEM assumes UTC
    assert has_zone("dd/MMM/yyyy:HH:mm:ss Z") and not has_zone("yyyy/MM/dd HH:mm:ss")


def test_fortigate_sample_states_the_system_zone():
    from sample_events import render_sample
    from timestamps import offset_text
    text = render_sample("fortinet-firewall")
    assert f'tz="{offset_text(datetime.now().astimezone(), colon=False)}"' in text
    local_date = datetime.now().astimezone().strftime("%Y-%m-%d")
    assert f"date={local_date}" in text


def test_zone_field_gets_the_system_zone():
    sim = Simulation(FakeStore({"acme-wlc": ZONE_FIELD_PARSER}))
    r = rule('#Vendor="acme" #event.module="wlc" | message=/link down/i')
    entry = template_entry(r, sim)
    assert entry["verdict"] == "likely", entry
    assert system_zone_label() in entry["log"]
    result = sim.run("acme-wlc", entry["log"])
    assert all(t["ok"] for t in result.timestamps)


def test_selected_rule_samples_have_current_timestamps(tmp_path):
    from app import create_app
    from app_settings import AppSettings
    from falcon_client import FalconClient
    from forensic_log import ForensicLog
    import time as _t
    client = FalconClient("id", "secret", "http://127.0.0.1:1", timeout=1)
    sim = Simulation(FakeStore({"acme-mail": CLICK_PARSER}))
    web = create_app(client, forensic=ForensicLog(tmp_path / "f.jsonl"), app_settings=AppSettings(tmp_path / "s.json", tmp_path / "b"),
                     admin_password="", access_password="", allowed_hosts="", rule_refresh_minutes=0, simulation=sim)
    r = rule('#Vendor="acme" #event.module="mail" | url.original="https://example.com/x"', source="configured")
    web.extensions["rulebook"]._cache["configured"] = ([r], None, _t.time())
    tc = web.test_client()
    first = json.loads(tc.get(f"/api/sample-events/rule:{r['key']}").get_json()["log"])
    stamp = first.get("clickTime") or first.get("messageTime")
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - parsed).total_seconds()) < 60


# ---- missing data and the build version

import missing  # noqa: E402

CORRELATE_RULE = '''#repo!="xdr*"
| correlate(
  Mail: {
    #Vendor="acme" #event.module="mail"
    | objectArray:exists(array="Vendor.threatsInfoMap[]", condition={Vendor.threatsInfoMap.classification="phish"})
    | split(Vendor.threatsInfoMap)
  } include:[Vendor.threatsInfoMap.threat],
  Box: {
    #Vendor="acme" #event.module="box"
    | message=/download/i
    | message <=> Mail.Vendor.threatsInfoMap.threat
  } include:[message],
  sequence=true,
  within=30m  // TUNING
)'''

MAIL_PARSER = r'''
parseJson(prefix="Vendor.", excludeEmpty=true, handleNull=discard)
| Vendor := "acme"
| event.module := "mail"
'''


def test_correlate_is_split_into_its_sources():
    parsed = missing.parse_correlate(CORRELATE_RULE)
    assert [s["name"] for s in parsed["subs"]] == ["Mail", "Box"]
    assert parsed["sequence"] and parsed["within"] == "30m"
    assert parsed["joins"] == [{"sub": "Box", "field": "message", "other": "Mail", "other_field": "Vendor.threatsInfoMap.threat"}]
    query, splits = missing.sub_query(parsed, "Mail")
    assert 'Vendor.threatsInfoMap[0].classification="phish"' in query and "split" not in query and "<=>" not in query


def test_missing_data_builds_a_companion_with_the_shared_value():
    sim = Simulation(FakeStore({"acme-mail": MAIL_PARSER, "acme-box": SYSLOG_PARSER.replace('"box"', '"box"')}))
    r = rule(CORRELATE_RULE)
    entry = template_entry(r, sim)
    assert entry["verdict"] == "needs_more_events" and "Box" in entry["note"]
    analysis = missing.analyze(r, entry["log"], "event", entry["parser"], sim)
    join = next(i for i in analysis["items"] if i["kind"] == "join")
    assert join["field"] == "Vendor.threatsInfoMap[0].threat" and len(join["examples"]) == 3
    chosen = join["examples"][1]
    out = missing.fill(r, entry["log"], "event", entry["parser"], sim, {join["id"]: chosen})
    assert json.loads(out["log"])["threatsInfoMap"][0]["threat"] == chosen
    companion = out["companions"][0]
    assert companion["name"] == "Box" and chosen in companion["log"] and "order" in out["message"]


def test_ioc_and_lookup_and_threshold_items():
    class Intel:
        def search_indicators(self, ioc_type, confidences, log, limit=3):
            assert ioc_type == "ip_address" and confidences == ["high"]
            return [{"indicator": "203.0.113.200"}, {"indicator": "203.0.113.201"}]
    sim = Simulation(FakeStore({"acme-mail": JSON_PARSER}))
    r = rule('#Vendor="acme" | ioc:lookup(source.ip, type="ip_address", confidenceThreshold="high", strict="true")'
             ' | match(file="blocklist.csv", field=[user.name], strict=true)'
             ' | groupBy([source.ip], function=[count(as=hits), sum(Vendor.bytes, as=total)]) | hits >= 5 | total > 1000')
    analysis = missing.analyze(r, json.dumps({"senderIP": "192.0.2.1"}), "event", "acme-mail", sim, Intel())
    kinds = {i["kind"]: i for i in analysis["items"]}
    assert kinds["ioc"]["examples"] == ["203.0.113.200", "203.0.113.201"]
    assert kinds["lookup"]["file"] == "blocklist.csv" and kinds["lookup"]["examples"] == []
    assert kinds["events"]["examples"][0] == "5" and kinds["sum"]["examples"][0] == "1001"
    out = missing.fill(r, json.dumps({"senderIP": "192.0.2.1", "bytes": 1}), "event", "acme-mail", sim,
                       {kinds["ioc"]["id"]: "203.0.113.200", kinds["events"]["id"]: "5", kinds["sum"]["id"]: "1001"})
    events = json.loads(out["log"])
    assert len(events) == 5 and all(e["senderIP"] == "203.0.113.200" for e in events)
    assert sum(int(e["bytes"]) for e in events) >= 1001


def test_examples_follow_the_field():
    assert missing.examples_for("source.ip")[0].startswith(("192.0.2.", "198.51.100.", "203.0.113."))
    assert missing.examples_for("Vendor.properties.FileOriginUrl")[0].startswith("https://")
    assert missing.examples_for("process.name", ("regex", (r"(cmd|powershell)\.exe", ""))) == ["cmd.exe", "powershell.exe"]


def test_version_is_in_the_footer(tmp_path):
    from app import APP_VERSION, create_app
    from app_settings import AppSettings
    from falcon_client import FalconClient
    from forensic_log import ForensicLog
    assert re.fullmatch(r"\d+\.\d+\.\d+", APP_VERSION)
    assert APP_VERSION == (Path(__file__).resolve().parent.parent / "VERSION").read_text(encoding="utf-8").strip()
    web = create_app(FalconClient("id", "s", "http://127.0.0.1:1", timeout=1), forensic=ForensicLog(tmp_path / "f.jsonl"),
                     app_settings=AppSettings(tmp_path / "s.json", tmp_path / "b"), admin_password="", access_password="",
                     allowed_hosts="", rule_refresh_minutes=0, simulation=Simulation(None))
    assert f"NG-SIEM Log Tester v{APP_VERSION}" in web.test_client().get("/").get_data(as_text=True)
