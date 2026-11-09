"""Correlation rules and templates: loading, judging a submission, and building matching logs."""
import copy
import ipaddress
import json
import re
import threading
import time

from cql import FALSE, TRUE, UNKNOWN, Evaluator, parse_rule, tokenize
from falcon_client import FalconError
from field_model import (PREFIX, PROFILES, EventView, example_value, expand_envelopes, profile_for_parser,
                         profile_for_rule, raw_value_for)
from sample_events import MARKER, render_sample

LIKELY, UNCERTAIN, UNLIKELY, NEEDS_EVENTS, NOT_APPLICABLE = (
    "likely", "uncertain", "unlikely", "needs_more_events", "not_applicable",
)
CACHE_SECONDS = 900  # Rules change rarely, and loading 1,600 templates takes a while.


def _query_of(raw):
    search = raw.get("search") if isinstance(raw.get("search"), dict) else {}
    for value in (search.get("filter"), search.get("query"), raw.get("filter"), raw.get("query"),
                  raw.get("search") if isinstance(raw.get("search"), str) else None):
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _tag(tokens, *names):
    for i, (kind, value) in enumerate(tokens):
        if kind in ("word", "string") and value in names and i + 2 < len(tokens) and tokens[i + 1] in (("op", "="), ("op", "==")):
            return str(tokens[i + 2][1])
    return None


def normalize(raw, source):
    """One rule or template in the shape the app uses, whatever the API returned."""
    query = _query_of(raw)
    tokens = tokenize(query)
    vendor_tag = raw.get("vendor") or _tag(tokens, "#Vendor", "Vendor")
    module = raw.get("product") or _tag(tokens, "#event.module", "event.module")
    sourcetype = _tag(tokens, "@sourcetype")
    if isinstance(vendor_tag, list):
        vendor_tag = None
    parser_key, profile = profile_for_rule(vendor_tag, module, sourcetype)
    listed = [str(v) for v in raw.get("vendors") or [] if v]
    if len(listed) > 1:
        vendor, product = ", ".join(listed), "Multiple sources"
    elif profile:
        vendor, product = profile["display"]
    else:
        vendor = listed[0] if listed else (vendor_tag or "Other").title()
        product = (module or sourcetype or "General").replace("-", " ").title()
    status = str(raw.get("status") or "").lower()
    rule = parse_rule(query)
    return {
        "key": f"{source}:{raw.get('rule_id') or raw.get('id')}",
        "id": raw.get("rule_id") or raw.get("id"),
        "name": raw.get("name") or "Unnamed rule",
        "description": raw.get("description") or "",
        "source": source,
        "enabled": source == "configured" and status in ("active", "enabled"),
        "status": raw.get("status") or ("template" if source == "template" else "unknown"),
        "severity": raw.get("severity"),
        "template_id": raw.get("template_id") if source == "configured" else raw.get("id"),
        "type": raw.get("type") or "",
        "tactic": raw.get("tactic") or "",
        "technique": raw.get("technique") or "",
        "query": query,
        "vendor": vendor,
        "product": product,
        "parser": parser_key,
        "threshold": rule.threshold,
        "endpoint_only": rule.endpoint_only,
        "_rule": rule,
    }


def latest_configured(resources):
    """One entry per rule: the published version, or else the highest version."""
    best = {}
    for raw in resources:
        rule_id = raw.get("rule_id") or raw.get("id")
        rank = (str(raw.get("state") or "").lower() == "published", raw.get("version") or 0)
        if rule_id not in best or rank > best[rule_id][0]:
            best[rule_id] = (rank, raw)
    return [raw for _, raw in best.values()]


class RuleBook:
    """Configured rules and CrowdStrike templates, cached separately.

    Configured rules take one API call. The templates run to well over 1,000 and take many calls,
    so they're only fetched when the operator asks for them.
    """

    def __init__(self, client):
        self.client = client
        self._cache = {"configured": ([], None, 0), "template": ([], None, 0)}
        self._lock = threading.Lock()

    def _fetch(self, source, log):
        rules, unreadable = [], []
        fetch = (lambda: latest_configured(self.client.list_correlation_rules(log))) if source == "configured" \
            else (lambda: self.client.list_correlation_rule_templates(log))
        label = "Configured rules" if source == "configured" else "Rule templates"
        try:
            for raw in fetch():
                try:
                    rule = normalize(raw, source)
                except Exception as exc:  # One odd rule mustn't hide all the others.
                    unreadable.append(raw.get("name") or raw.get("id"))
                    log.error(f"Couldn't read {source} rule {raw.get('name') or raw.get('id')}", repr(exc))
                    continue
                if rule["query"]:
                    rules.append(rule)
        except FalconError as exc:
            return [], f"{label}: {exc}"
        error = f"{label}: {len(unreadable)} couldn't be read, such as {unreadable[0]}." if unreadable else None
        return rules, error

    def _get(self, source, log, refresh):
        with self._lock:
            rules, error, loaded_at = self._cache[source]
            if refresh or not loaded_at or time.time() - loaded_at >= CACHE_SECONDS:
                rules, error = self._fetch(source, log)
                self._cache[source] = (rules, error, time.time())
            return rules, error

    def templates_loaded(self):
        return bool(self._cache["template"][2])

    def load(self, log, refresh=False, include_templates=False):
        """Configured rules, plus the templates if asked. Returns (rules, error message or None)."""
        configured, error = self._get("configured", log, refresh)
        if not include_templates:
            return list(configured), error
        templates, template_error = self._get("template", log, refresh)
        # A template that a configured rule was created from is shown once, as the configured rule.
        in_use = {r["template_id"] for r in configured if r["template_id"]}
        rules = list(configured) + [t for t in templates if t["template_id"] not in in_use]
        return rules, " ".join(e for e in (error, template_error) if e) or None

    def find(self, key):
        source = "configured" if key.startswith("configured:") else "template"
        return next((rule for rule in self._cache[source][0] if rule["key"] == key), None)


# ---------------------------------------------------------------- judging a submission

def events_of(text, mode):
    """The events a submission would produce, as objects or plain text lines."""
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return [text.strip()] if mode == "raw" and (text or "").strip() else []
    if isinstance(parsed, dict):
        return [parsed]
    if isinstance(parsed, list) and parsed and all(isinstance(item, dict) for item in parsed):
        return parsed
    return [text.strip()] if mode == "raw" else []


def _evaluate_event(rule, event, parser, derived=None):
    view = EventView(event, parser, derived)
    computed = [name for kind, name in rule.stages if kind == "assign"]
    evaluator = Evaluator(view, computed)
    states = [evaluator.run(node) for kind, node in rule.stages if kind == "filter"]
    if FALSE in states:
        state = FALSE
    elif UNKNOWN in states:
        state = UNKNOWN
    else:
        state = TRUE
    return state, evaluator


def judge(rule_info, events, parser):
    """Whether a submission is likely to satisfy one rule, with the conditions behind it."""
    rule = rule_info["_rule"]
    base = {"key": rule_info["key"], "name": rule_info["name"], "vendor": rule_info["vendor"],
            "product": rule_info["product"], "source": rule_info["source"], "enabled": rule_info["enabled"],
            "severity": rule_info["severity"], "threshold": rule.threshold}
    if rule.endpoint_only:
        return {**base, "verdict": NOT_APPLICABLE, "summary": "Runs on Falcon sensor data, not third-party logs.",
                "conditions": [], "suggestions": [], "matching_events": 0}
    if not events:
        return {**base, "verdict": UNLIKELY, "summary": "There's no event to check.", "conditions": [],
                "suggestions": [], "matching_events": 0}
    expanded = [pair for event in events for pair in expand_envelopes(event, parser)]
    outcomes = [_evaluate_event(rule, event, parser, derived) for event, derived in expanded]
    matching = sum(1 for state, _ in outcomes if state is TRUE)
    unknown = sum(1 for state, _ in outcomes if state is UNKNOWN)
    if not outcomes:
        return {**base, "verdict": UNLIKELY, "summary": "The batch array has no events.", "conditions": [],
                "suggestions": [], "matching_events": 0}
    shown = next((ev for state, ev in outcomes if state is TRUE), None) or outcomes[0][1]
    unsupported = sorted(set(rule.unsupported) | set(shown.unsupported))
    # Tags such as #Vendor come from the parser, so a match on those alone says nothing about the log.
    content_checked = any(c.state is TRUE and not c.basis.startswith(("set by", "parser name", "assumed"))
                          for c in shown.conditions)
    if matching and matching >= rule.threshold and not content_checked:
        unsupported = unsupported or ["no condition on the log's own fields"]
    if matching and matching >= rule.threshold:
        verdict = UNCERTAIN if unsupported else LIKELY
        summary = f"{matching} of {len(events)} event(s) satisfy the rule's filter."
    elif matching:
        verdict = NEEDS_EVENTS if not unsupported else UNCERTAIN
        summary = (f"The rule needs at least {rule.threshold} matching events in its lookback window, "
                   f"and this submission has {matching}.")
    elif unknown:
        verdict = UNCERTAIN
        summary = "Some conditions depend on what the parser produces, so they can't be checked here."
    else:
        verdict = UNLIKELY
        summary = "At least one of the rule's conditions isn't met."
    if unsupported:
        summary += f" Parts of the query can't be evaluated here: {', '.join(unsupported)}."
    conditions = [
        {"field": c.field, "op": c.op, "expected": c.expected, "actual": c.actual,
         "met": {TRUE: "yes", FALSE: "no", UNKNOWN: "unknown"}[c.state], "basis": c.basis}
        for c in shown.conditions
    ]
    suggestions = []
    for condition in (shown.conditions if verdict != LIKELY else []):
        if condition.state is not TRUE and condition.suggestion and condition.suggestion not in suggestions:
            suggestions.append(condition.suggestion)
    if rule.threshold > 1 and matching < rule.threshold:
        suggestions.append(f"Send at least {rule.threshold} matching events as a JSON array.")
    envelopes = (profile_for_parser(parser)[1] or {}).get("envelopes")
    if envelopes and verdict != LIKELY and all(not derived for _, derived in expanded):
        names = ", ".join(envelopes)
        suggestions.append(f"This parser expects events inside a batch array ({names}). "
                           f'For example: {{"{next(iter(envelopes))}": [ <your event> ]}}.')
    return {**base, "verdict": verdict, "summary": summary, "conditions": conditions,
            "suggestions": suggestions, "matching_events": matching}


def evaluate(rules, text, mode, parser):
    events = events_of(text, mode)
    results = []
    for rule in rules:
        parser_for_rule = parser or rule["parser"]
        try:
            results.append(judge(rule, events, parser_for_rule))
        except Exception as exc:  # One rule the reader can't handle mustn't hide the rest.
            results.append({
                "key": rule["key"], "name": rule["name"], "vendor": rule["vendor"], "product": rule["product"],
                "source": rule["source"], "enabled": rule["enabled"], "severity": rule["severity"],
                "threshold": rule["threshold"], "verdict": UNCERTAIN, "conditions": [], "suggestions": [],
                "matching_events": 0, "summary": f"This rule's query couldn't be checked ({type(exc).__name__}).",
            })
    firing = [r for r in results if r["verdict"] == LIKELY and r["source"] == "configured" and r["enabled"]]
    return {"events": len(events), "results": results, "will_fire": firing}


def group(results):
    """Rules grouped by vendor and product, for display."""
    groups = {}
    for result in results:
        groups.setdefault(f"{result['vendor']} / {result['product']}", []).append(result)
    return [{"group": name, "rules": items} for name, items in sorted(groups.items())]


# ---------------------------------------------------------------- building a matching log

def _set_path(event, path, value):
    parts = re.findall(r"[^.\[\]]+|\[\d+\]", path)
    node = event
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        following = parts[i + 1] if not last else None
        if part.startswith("["):
            index = int(part[1:-1])
            while len(node) <= index:
                node.append({} if following and not following.startswith("[") else [])
            if last:
                node[index] = value
            else:
                if not isinstance(node[index], (dict, list)):
                    node[index] = [] if following.startswith("[") else {}
                node = node[index]
        else:
            if last:
                node[part] = value
            else:
                if not isinstance(node.get(part), (dict, list)):
                    node[part] = [] if following.startswith("[") else {}
                node = node[part]


def _requirements(node, negate=False):
    """Conditions an event must meet for the filter to pass, taking the first branch of each or."""
    kind = node[0]
    if kind == "and":
        return [req for child in node[1] for req in _requirements(child, negate)]
    if kind == "or":
        return _requirements(node[1][0], negate) if not negate else [r for c in node[1] for r in _requirements(c, True)]
    if kind == "not":
        return _requirements(node[1], not negate)
    if kind == "cmp":
        op = node[2]
        if negate:
            op = {"=": "!=", "!=": "=", "<": ">=", ">": "<=", "<=": ">", ">=": "<"}[op]
        return [("cmp", node[1], op, node[3])]
    if kind == "call" and node[1] in ("in", "cidr"):
        return [(node[1] if not negate else f"!{node[1]}", node)]
    if kind == "text" and not negate:
        return [("text", node[1])]
    return []


def _raw_path(view, name):
    if name.startswith(PREFIX):
        return name[len(PREFIX):], None
    alias = (view.profile or {}).get("aliases", {}).get(name)
    if alias:
        return alias
    if name.startswith("#") or name.startswith("@") or "." in name:
        return None, None
    return name, None




def build_template(rule_info):
    """A synthetic log that should satisfy one rule, starting from its vendor's sample."""
    rule = rule_info["_rule"]
    parser = rule_info["parser"]
    if rule.endpoint_only:
        return None, "This rule runs on Falcon sensor data, so no third-party log can trigger it."
    base_id = PROFILES.get(parser, {}).get("sample")
    base = None
    if base_id:
        rendered = render_sample(base_id)
        try:
            base = json.loads(rendered)
        except ValueError:
            base = None  # Text samples can't take structured fields, so start from JSON instead.
    event = base if isinstance(base, dict) else {"message": f"{MARKER} correlation rule test"}
    view = EventView(event, parser)
    unmet = []
    for kind, node in rule.stages:
        if kind != "filter":
            continue
        for requirement in _requirements(node):
            if requirement[0] == "text":
                event["message"] = f"{event.get('message', '')} {requirement[1]}".strip()
                continue
            if requirement[0] in ("in", "!in", "cidr", "!cidr"):
                call = requirement[1]
                target = call[3].get("field") or (call[2][0] if call[2] else None)
                values = call[3].get("values") or call[3].get("subnet")
                path, transform = _raw_path(view, str(target[1])) if target else (None, None)
                if not path or not values:
                    continue
                options = [str(v) for v in values[1]] if values[0] == "list" else [str(values[1])]
                if requirement[0] == "in":
                    _set_path(event, path, raw_value_for(transform, options[0].replace("*", "test")))
                elif requirement[0] == "cidr":
                    network = ipaddress.ip_network(options[0], strict=False)
                    _set_path(event, path, str(network.network_address + 1))
                elif requirement[0] == "!in":
                    _set_path(event, path, f"{MARKER}-value")
                continue
            _, name, op, value = requirement
            if len(value) != 2 or value[0] not in ("string", "word", "regex"):
                unmet.append(f"{name} must equal a computed value")
                continue
            value_kind, expected = value
            path, transform = _raw_path(view, name)
            if not path:
                continue
            if op == "!=":
                current = EventView(event, parser).lookup(name, "=", None).value
                if current is not None and current == str(expected):
                    _set_path(event, path, f"{MARKER}-value")
                continue
            if op in ("<", ">", "<=", ">="):
                number = float(expected)
                wanted = number + 1 if op == ">" else number - 1 if op == "<" else number
                _set_path(event, path, int(wanted) if wanted.is_integer() else wanted)
                continue
            example = example_value(value_kind, expected)
            if example is None:
                unmet.append(f"{name} must match /{expected[0]}/")
                continue
            _set_path(event, path, raw_value_for(transform, example))
    events = [event]
    if rule.threshold > 1:
        events = []
        for index in range(rule.threshold):
            copy_event = copy.deepcopy(event)
            if rule.distinct_field:
                path, _ = _raw_path(view, rule.distinct_field)
                if path:
                    current = EventView(copy_event, parser).lookup(rule.distinct_field, "=", None).value or "value"
                    _set_path(copy_event, path, f"{current}-{index + 1}")
            events.append(copy_event)
    note = ""
    if unmet:
        note = "Edit before sending: " + "; ".join(unmet) + "."
    log = events[0] if len(events) == 1 else events
    envelopes = PROFILES.get(parser, {}).get("envelopes")
    if envelopes:
        candidates = [{key: events} for key in envelopes]
        for candidate in candidates:
            if judge(rule_info, [candidate], parser)["verdict"] == LIKELY:
                return candidate, note
        return candidates[0], note
    return log, note


def template_entry(rule):
    """One dropdown entry: a generated log for a rule, or None if no third-party log fits it."""
    if rule["endpoint_only"]:
        return None
    try:
        log, note = build_template(rule)
        if log is None:
            return None
        text = json.dumps(log, indent=2)
        check = judge(rule, events_of(text, "event"), rule["parser"])
    except Exception:  # Leave out a rule whose query can't be turned into a log.
        return None
    return {
        "id": f"rule:{rule['key']}",
        "label": rule["name"],
        "group": f"{rule['vendor']} / {rule['product']}",
        "rule_key": rule["key"],
        "rule_source": rule["source"],
        "enabled": rule["enabled"],
        "verdict": check["verdict"],
        "note": note,
        "log": text,
    }


def rule_templates(rules):
    """Dropdown entries: one generated log per rule that a third-party log could trigger."""
    entries = [entry for entry in (template_entry(rule) for rule in rules) if entry]
    return sorted(entries, key=lambda e: (e["group"], e["label"].lower()))
