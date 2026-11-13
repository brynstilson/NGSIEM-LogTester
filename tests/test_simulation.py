"""Parser simulation, lineage, regex samples, generation, rule refresh and verification."""
import json
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
