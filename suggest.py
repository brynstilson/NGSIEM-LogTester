"""Applies a rule check suggestion to the operator's log, on their behalf.

A suggestion points at one failing condition of one rule. The change is worked out the same way the
sample generator does it: back through the connector's parser (from the simulation's lineage) to the
raw field that produces the value, or, without a simulation, through the approximate field mappings.
The result is checked again, so the operator sees whether the rule now matches.
"""
import copy
import json

from generator import Solver, _apply, _flat_base, concrete
from rules import EventView, LIKELY, _raw_path, _set_path, events_of, judge
from field_model import raw_value_for


def want_from_condition(condition):
    """The requirement a displayed condition stands for, in the generator's terms."""
    op, expected = condition["op"], str(condition["expected"])
    if op in ("=", "!=") and len(expected) > 1 and expected.startswith("/"):
        body, _, flags = expected[1:].rpartition("/")
        return ("regex", (body, flags)) if op == "=" else ("ne", None)
    if op == "=":
        return ("exists",) if expected == "*" else ("eq", expected)
    if op == "!=":
        return ("ne", expected)
    if op in ("<", ">", "<=", ">="):
        return ("num", op, expected)
    if op == "in":
        return ("in", [v.strip() for v in expected.split(",") if v.strip()])
    if op == "cidr":
        return ("cidr", [v.strip() for v in expected.split(",") if v.strip()])
    if op == "contains":
        return ("contains", expected)
    if op in ("matches", "regex"):
        return ("regex", (expected.strip("/"), ""))
    if op == "wildcard":
        return ("eq", expected)
    return None


def _render(original_text, events, is_text):
    if is_text:
        return events[0]
    payload = events[0] if len(events) == 1 else events
    return json.dumps(payload, indent=2)


def _fix_event(event, condition, parser, simulation):
    """event with the condition met, or None if no change to the log can be worked out."""
    want = want_from_condition(condition)
    if want is None:
        return None
    field = condition["field"]
    lineage = simulation.lineage(parser) if simulation is not None and parser else None
    if lineage is not None:
        solver = Solver(lineage, _flat_base(event))
        if not solver.resolve(field, want):
            return None
        return _apply(event, solver.edits, lineage.format, solver.raw_overrides, False, solver.raw_text)
    # No simulation: the approximate mapping from rule field to raw field.
    if isinstance(event, str):
        return None
    view = EventView(event, parser)
    path, transform = _raw_path(view, field)
    value = concrete(want, None)
    if not path or value is None:
        return None
    fixed = copy.deepcopy(event)
    _set_path(fixed, path, raw_value_for(transform, value))
    return fixed


def apply_suggestion(rule, text, mode, parser, simulation, fix):
    """Apply one suggestion ({"kind": "field", "condition": i}, {"kind": "repeat"} or {"kind": "all"}).

    Returns {"success", "log", "message", "verdict"}.
    """
    events = events_of(text, mode)
    if not events:
        return {"success": False, "message": "The log couldn't be read, so the suggestion wasn't applied."}
    is_text = isinstance(events[0], str)
    before = judge(rule, events, parser, simulation)
    kind = fix.get("kind")
    if kind == "repeat":
        if is_text:
            return {"success": False, "message": f"Plain-text logs can't be repeated here: send the line {rule['threshold']} times."}
        needed = max(rule["threshold"], 1)
        events = (events * needed)[:max(needed, len(events))]
        changed = True
    else:
        if kind == "all":
            targets = [i for i, f in enumerate(before.get("fixes", [])) if f.get("kind") == "field"]
            indexes = [before["fixes"][i]["condition"] for i in targets]
        elif kind == "field" and isinstance(fix.get("condition"), int):
            indexes = [fix["condition"]]
        else:
            return {"success": False, "message": "That suggestion can't be applied automatically."}
        changed = False
        for index in indexes:
            current = judge(rule, events, parser, simulation)
            conditions = current["conditions"]
            if index >= len(conditions) or conditions[index]["met"] == "yes":
                # The conditions shown may have shifted after an earlier change; match by field and wanted value.
                wanted = before["conditions"][index] if index < len(before["conditions"]) else None
                match = next((i for i, c in enumerate(conditions) if wanted and c["field"] == wanted["field"]
                              and c["expected"] == wanted["expected"] and c["met"] == "no"), None)
                if match is None:
                    continue
                index = match
            condition = conditions[index]
            new_events = []
            for event in events:
                fixed = _fix_event(event, condition, parser, simulation)
                new_events.append(fixed if fixed is not None else event)
            if new_events != events:
                events, changed = new_events, True
        if not changed:
            return {"success": False, "message": "No change to the log could be worked out for that suggestion. "
                                                 "It may depend on the connector's parser rather than the log."}
    after = judge(rule, events, parser, simulation)
    new_text = _render(text, events, is_text)
    if after["verdict"] == LIKELY:
        message = "Applied. The check now expects this log to match the rule."
    elif after["verdict"] == before["verdict"]:
        message = "Applied, but the rule still doesn't match: see the remaining suggestions."
    else:
        message = "Applied. The rule's verdict changed."
    return {"success": True, "log": new_text, "message": message, "verdict": after["verdict"],
            "previous_verdict": before["verdict"]}
