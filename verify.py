"""Verify a submission in NG-SIEM: find the parsed events, compare them with the simulation, and
check the correlation rules against what NG-SIEM actually produced.

Needs the NGSIEM: Write scope, which covers starting searches. Searches are read-only.
"""
import re
import time
from datetime import datetime, timedelta, timezone

from falcon_client import ActivityLog, FalconError
from parser_sim import Result
from sample_events import MARKER

REPOSITORY = "search-all"
POLL_SECONDS = 1.5
TIMEOUT_SECONDS = 45
MAX_EVENTS = 20


def search_token(text):
    """A distinctive piece of the submitted log to search for."""
    if MARKER in text:
        ids = re.findall(re.escape(MARKER) + r"[\w.-]*", text)
        return max(ids, key=len) if ids else MARKER
    words = sorted(set(re.findall(r"[A-Za-z0-9][A-Za-z0-9._@-]{9,}", text)), key=len, reverse=True)
    return words[0] if words else None


def _quote(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def run_search(client, query, start, log, timeout=TIMEOUT_SECONDS, sleep=time.sleep):
    job_id = client.start_search(REPOSITORY, query, start, log)
    deadline = time.monotonic() + timeout
    while True:
        page = client.get_search(REPOSITORY, job_id, ActivityLog())  # results stay out of the verbose log
        if page.get("done"):
            return page.get("events") or []
        if time.monotonic() > deadline:
            raise FalconError("The NG-SIEM search didn't finish in time. Try again in a minute.")
        sleep(POLL_SECONDS)


def as_result(event):
    """An NG-SIEM event as a parser Result, so the rule check can read it like a simulation."""
    fields = {k[1:] if k.startswith("#") else k: str(v) for k, v in event.items() if v is not None}
    tags = [k[1:] for k in event if k.startswith("#")]
    return Result(fields=fields, tag_fields=tags)


class RealParse:
    """Stands in for the Simulation in the rule check: returns NG-SIEM's own parsed event."""

    active = True

    def __init__(self, result, parser):
        self.result, self.name = result, parser

    def run(self, name, rawstring):
        return self.result

    def lineage(self, name):
        return None

    def parser(self, name):
        return {"name": self.name}


def compare(real, simulated):
    """Differences between NG-SIEM's parsed fields and the simulation's, ignoring raw and time fields."""
    skip = ("@", "Vendor.", "Parser.", "ecs.", "Cps.")
    real_fields = {k: v for k, v in real.fields.items() if not k.startswith(skip)}
    sim_fields = {k: v for k, v in (simulated.fields if simulated else {}).items() if not k.startswith(skip)}
    differ = {k: {"ngsiem": real_fields[k], "simulated": sim_fields[k]}
              for k in real_fields if k in sim_fields and real_fields[k] != sim_fields[k]}
    only_real = sorted(k for k in real_fields if k not in sim_fields)
    only_sim = sorted(k for k in sim_fields if k not in real_fields and k not in (simulated.unknown if simulated else set()))
    matched = sum(1 for k in real_fields if k in sim_fields and real_fields[k] == sim_fields[k])
    return {"matching_fields": matched, "different": differ, "only_in_ngsiem": only_real[:50],
            "only_in_simulation": only_sim[:50]}


def verify(client, submission, rules, simulation, judge, log, now=None):
    """Search NG-SIEM for a submission's events and check them. Returns a JSON-ready dict."""
    token = search_token(submission["text"])
    if not token:
        return {"success": False, "message": "The log has no distinctive text to search for, so it can't be found in NG-SIEM."}
    started = submission["time"] - timedelta(minutes=2)
    query = f"{_quote(token)} | tail({MAX_EVENTS})"
    log.info(f"Searching NG-SIEM ({REPOSITORY}) from {started.isoformat()} for {token}")
    events = run_search(client, query, started.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), log)
    if not events:
        waited = int(((now or datetime.now(timezone.utc)) - submission["time"]).total_seconds())
        return {"success": True, "found": 0, "token": token,
                "message": f"No events found yet ({waited} seconds after sending). NG-SIEM can take a few minutes "
                           "to make new events searchable. Try again shortly."}
    parser = submission.get("parser")
    checked = []
    for event in events[:5]:
        real = as_result(event)
        raw = event.get("@rawstring", "")
        simulated = simulation.run(parser, raw) if simulation is not None and parser and raw else None
        verdicts = []
        for rule in rules:
            result = judge(rule, [raw], parser, RealParse(real, parser))
            verdicts.append({"name": rule["name"], "key": rule["key"], "verdict": result["verdict"],
                             "summary": result["summary"], "conditions": result["conditions"]})
        tags = {f"#{k}": real.fields[k] for k in real.tag_fields if k in real.fields}
        checked.append({"tags": tags, "fields": {k: v for k, v in sorted(real.fields.items()) if k != "@rawstring"},
                        "comparison": compare(real, simulated) if simulated else None, "rules": verdicts})
    return {"success": True, "found": len(events), "token": token, "events": checked}
