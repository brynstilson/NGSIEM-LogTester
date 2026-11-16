"""Data a rule needs that one generated log can't supply, and the operator's way to supply it.

analyze() lists what's missing for a rule, each with 2-3 example values to choose from (or a box for the
operator's own):
- correlate(): the rule joins events from several sources (Proofpoint and Defender XDR, say) on a shared
  value. The operator picks the shared value; the app writes it into this log and generates the
  companion event for each other source, to send through a connector with that source's parser.
- ioc:lookup(): a field must hold an indicator that is in CrowdStrike's threat intelligence. Synthetic
  values can't match, so the examples are real indicators from the tenant's Falcon Intelligence.
- match(file=...): a field must hold a value from one of the tenant's lookup files.
- aggregation thresholds: count(), count(distinct=true) or sum() over several events.
- any other condition the log doesn't meet.
fill() applies the chosen values and returns the new log and any companion events.
"""
import copy
import hashlib
import json
import math
import re

from sample_events import MARKER

SYNTHETIC = {
    "url": [f"https://login-verify.example.com/{MARKER}/phishing-test",
            f"https://invoice-portal.example.net/{MARKER}/download.php",
            f"https://shared-docs.example.org/{MARKER}/view?id=1"],
    "domain": ["login-verify.example.com", "invoice-portal.example.net", "shared-docs.example.org"],
    "ip": ["192.0.2.10", "198.51.100.23", "203.0.113.45"],
    "email": ["test.user@example.com", "finance.test@example.com", "it.admin.test@example.com"],
    "user": ["test.user", "finance.test", "it.admin.test"],
    "host": [f"{MARKER}-WS01", f"{MARKER}-SRV02", f"{MARKER}-LAPTOP03"],
    "file": [f"{MARKER}-invoice.pdf.exe", f"{MARKER}-update.ps1", f"{MARKER}-payload.dll"],
    "path": [f"C:\\Users\\test.user\\Downloads\\{MARKER}-invoice.pdf.exe",
             f"C:\\ProgramData\\{MARKER}\\update.ps1", f"/tmp/{MARKER}/payload.sh"],
    "process": ["powershell.exe", "cmd.exe", "rundll32.exe"],
    "command": [f"powershell.exe -NoProfile -EncodedCommand {MARKER}", f"cmd.exe /c whoami && echo {MARKER}",
                f"rundll32.exe {MARKER}-payload.dll,Start"],
    "sha256": [hashlib.sha256(f"{MARKER} sample {i}".encode()).hexdigest() for i in (1, 2, 3)],
    "md5": [hashlib.md5(f"{MARKER} sample {i}".encode()).hexdigest() for i in (1, 2, 3)],
    "port": ["443", "4444", "8080"],
    "id": [f"{MARKER}-ID-0001", f"{MARKER}-ID-0002", f"{MARKER}-ID-0003"],
    "other": [f"{MARKER}-VALUE-1", f"{MARKER}-VALUE-2", f"{MARKER}-VALUE-3"],
}

_KIND_HINTS = [  # (pattern on the field name, kind), first match wins
    (r"url|uri|link|origin|threat$|threat\.|referr", "url"), (r"sha256|sha_256", "sha256"), (r"md5", "md5"),
    (r"(^|\.)(ip|ipaddress|ip_address|clientip|clickip|senderip)$|\.ip\b|_ip$|ip\[", "ip"),
    (r"email|recipient|sender|mail", "email"), (r"domain|fqdn", "domain"),
    (r"command_line|commandline|cmdline|command", "command"), (r"process|image|executable", "process"),
    (r"file\.path|filepath|folder|directory|path", "path"), (r"file\.name|filename|file_name", "file"),
    (r"host|device|computer|machine|workstation", "host"), (r"user|account|login|principal", "user"),
    (r"port", "port"), (r"(^|\.)id$|_id$|uid$|guid", "id"),
]


def field_kind(*names):
    for name in names:
        low = str(name or "").lower()
        for pattern, kind in _KIND_HINTS:
            if re.search(pattern, low):
                return kind
    return "other"


def examples_for(field, want=None, other_field=None):
    """2-3 synthetic example values for a field, meeting want where there is one."""
    from regex_sample import variants
    if want:
        kind = want[0]
        if kind == "in":
            return [v.replace("*", "test") for v in want[1][:3]]
        if kind == "eq":
            return [want[1].replace("*", "test")]
        if kind == "regex":
            found = variants(want[1][0], want[1][1])
            if found:
                return found
        if kind == "num":
            n = float(want[2])
            values = [n + 1, n * 2 + 1, n + 10] if want[1] in (">", ">=") else [max(n - 1, 0), 0]
            return [str(int(v)) if float(v).is_integer() else str(v) for v in values][:3]
        if kind == "cidr":
            import ipaddress
            try:
                net = ipaddress.ip_network(want[1][0], strict=False)
                return [str(net.network_address + i) for i in (1, 2, 3)]
            except (ValueError, IndexError):
                pass
    return list(SYNTHETIC[field_kind(field, other_field)])


# ---------------------------------------------------------------- correlate()

def _strip_comments(text):
    out = []
    for line in text.splitlines():
        quote = False
        for i, ch in enumerate(line):
            if ch == '"' and (i == 0 or line[i - 1] != "\\"):
                quote = not quote
            if not quote and line.startswith("//", i) and (i == 0 or line[i - 1] in " \t,|{(["):
                line = line[:i]
                break
        out.append(line)
    return "\n".join(out)


def _balanced(text, start):
    """(inner text, index after the closing bracket) for the bracket at text[start]."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    opening = text[start]
    closing = pairs[opening]
    depth, i, quote = 0, start, False
    while i < len(text):
        ch = text[i]
        if ch == '"' and text[i - 1] != "\\":
            quote = not quote
        elif not quote:
            if ch == opening:
                depth += 1
            elif ch == closing:
                depth -= 1
                if depth == 0:
                    return text[start + 1:i], i + 1
        i += 1
    return text[start + 1:], len(text)


_JOIN = re.compile(r"([\w.@#\[\]]+)\s*<=>\s*(\w+)\.([\w.@#\[\]]+)")


def parse_correlate(query):
    """The parts of a correlate() query, or None if it has none."""
    text = _strip_comments(query or "")
    m = re.search(r"\bcorrelate\s*\(", text)
    if not m:
        return None
    outer = text[:m.start()].strip()
    outer = outer[:-1].strip() if outer.endswith("|") else outer
    body, _ = _balanced(text, m.end() - 1)
    subs, i = [], 0
    while True:
        sm = re.compile(r"(\w+)\s*:\s*\{").search(body, i)
        if not sm:
            break
        inner, end = _balanced(body, sm.end() - 1)
        include = []
        im = re.match(r"\s*include\s*:\s*\[", body[end:])
        if im:
            fields, end2 = _balanced(body, end + im.end() - 1)
            include = [f.strip() for f in fields.split(",") if f.strip()]
            end = end2
        subs.append({"name": sm.group(1), "query": inner.strip(), "include": include})
        i = end
    if len(subs) < 2:
        return None
    joins = []
    for sub in subs:
        for jm in _JOIN.finditer(sub["query"]):
            joins.append({"sub": sub["name"], "field": jm.group(1), "other": jm.group(2), "other_field": jm.group(3)})
    sequence = re.search(r"sequence\s*=\s*(true|false)", body)
    within = re.search(r"within\s*=\s*([\w.]+)", body)
    return {"outer": outer, "subs": subs, "joins": joins,
            "sequence": bool(sequence and sequence.group(1) == "true"), "within": within.group(1) if within else None}


def _splits(query):
    return [m.group(1).strip().strip('"') for m in re.finditer(r"\bsplit\(\s*(?:field\s*=\s*)?\"?([\w.@#]+)\"?[^)]*\)", query)]


def _flatten_field(field, splits):
    """split(X) turns X's elements into separate events; address the first element instead."""
    for array in sorted(splits, key=len, reverse=True):
        if field.startswith(array + "["):
            return field  # already addresses an element
        if field == array:
            return f"{array}[0]"
        if field.startswith(array + "."):
            return f"{array}[0]{field[len(array):]}"
    return field


def sub_query(parsed, name):
    """One correlate() sub-search as a standalone query: shared filters, without split() or joins.

    objectArray:exists(array="X[]", condition={...}) becomes the condition on X's first element, which
    is what split() leaves behind.
    """
    sub = next(s for s in parsed["subs"] if s["name"] == name)
    body = sub["query"]
    splits = _splits(body)
    stages = [st.strip() for st in re.split(r"\n\s*\|", "\n" + body) if st.strip()]
    kept = []
    for stage in stages:
        stage = stage.lstrip("|").strip()
        if not stage or re.match(r"split\s*\(", stage) or "<=>" in stage:
            continue
        om = re.match(r'objectArray:exists\(\s*array\s*=\s*"([^"]+)\[\]"\s*,\s*condition\s*=\s*\{(.*)\}\s*\)\s*$', stage, re.S)
        if om:
            array, condition = om.group(1), om.group(2)
            stage = re.sub(re.escape(array) + r"\.", f"{array}[0].", condition)
        kept.append(stage)
    rewritten = []
    for stage in kept:
        rewritten.append(re.sub(r"(?<![\w.\[])([A-Za-z#@][\w.]*)",
                                lambda m: m.group(1) if m.string[m.end():m.end() + 1] == "["
                                else _flatten_field(m.group(1), splits), stage))
    parts = ([parsed["outer"]] if parsed["outer"] else []) + rewritten
    return "\n| ".join(parts), splits


def pseudo_rules(rule):
    """One standalone rule per correlate() sub-search, keyed by sub-search name."""
    from rules import normalize
    parsed = parse_correlate(rule.get("query"))
    if not parsed:
        return None, {}
    out = {}
    for sub in parsed["subs"]:
        query, splits = sub_query(parsed, sub["name"])
        pseudo = normalize({"id": f"{rule['id']}:{sub['name']}", "name": f"{rule['name']}: {sub['name']}",
                            "search": {"filter": query}, "status": "active"}, rule["source"])
        pseudo["_splits"] = splits
        out[sub["name"]] = pseudo
    return parsed, out


def source_label(pseudo):
    """Vendor and product as the sub-search names them (#Vendor and #event.module), for display."""
    vendor = str(pseudo.get("vendor_tag") or pseudo.get("vendor") or "").strip('"')
    module = str(pseudo.get("module_tag") or pseudo.get("product") or "").strip('"')
    return {"vendor": vendor.title() if vendor.islower() else vendor, "product": module}


def _join_field(join, side, subs):
    """The flattened field a join reads on one side ('sub' or 'other')."""
    name = join["sub"] if side == "sub" else join["other"]
    field = join["field"] if side == "sub" else join["other_field"]
    return _flatten_field(field, subs[name].get("_splits") or [])


# ---------------------------------------------------------------- what's missing

_IOC = re.compile(r"ioc:lookup\(\s*(?:field\s*=\s*)?\[?\"?([\w.@#\[\]]+)\"?\]?(.*?)\)", re.S)
_MATCH = re.compile(r"\bmatch\(\s*file\s*=\s*\"([^\"]+)\"(.*?)\)", re.S)
_AGG_ALIAS = re.compile(r"(?:(\w+)\s*:=\s*)?\b(count|sum|max|min|avg)\(\s*([^()]*?)\)")
CONFIDENCE = {"high": ["high"], "medium": ["high", "medium"], "low": ["high", "medium", "low"]}


def _arg(text, name):
    m = re.search(name + r"\s*=\s*\"?([\w.\-]+)\"?", text)
    return m.group(1) if m else None


def aggregations(query):
    """Aggregate outputs a rule filters on after grouping: [(alias, function, field, op, number)]."""
    text = _strip_comments(query or "")
    grouping = re.search(r"\b(groupBy|stats|timeChart|bucket|count|sum)\s*\(", text)
    if not grouping:
        return []
    aliases = {}
    for m in _AGG_ALIAS.finditer(text):
        assigned, function, args = m.group(1), m.group(2), m.group(3)
        alias = assigned or _arg(args, "as") or f"_{function}"
        field = None
        first = args.split(",")[0].strip() if args.strip() else ""
        if first and "=" not in first:
            field = first.strip('"')
        elif _arg(args, "field"):
            field = _arg(args, "field")
        if function == "count" and re.search(r"distinct\s*=\s*true", args):
            function = "distinct"
        aliases[alias] = (function, field)
    out = []
    for m in re.finditer(r"\|\s*([\w]+)\s*(>=|>|==|=)\s*(\d+(?:\.\d+)?)", text[grouping.start():]):
        alias = m.group(1)
        if alias in aliases:
            function, field = aliases[alias]
            out.append((alias, function, field, m.group(2), float(m.group(3))))
    return out


def _needed(op, number):
    return int(math.floor(number)) + 1 if op == ">" else int(math.ceil(number))


def analyze(rule, text, mode, parser, simulation, client=None, log=None):
    """{"items": [...], "correlate": {...} or None} for a rule and the operator's current log."""
    from falcon_client import ActivityLog, FalconError
    from generator import requirements
    from rules import NOT_FIXABLE_IN_LOG, events_of, judge
    items = []
    parsed, pseudos = pseudo_rules(rule)
    correlate_info = None
    if parsed:
        correlate_info = {"sources": [{"name": s["name"], **source_label(pseudos[s["name"]])} for s in parsed["subs"]],
                          "sequence": parsed["sequence"], "within": parsed["within"]}
        primary = _primary(parsed, pseudos, parser)
        correlate_info["this_log"] = primary
        for index, join in enumerate(parsed["joins"]):
            # "field" is the side this log belongs to; "other_field" is the companion event's side.
            if join["other"] == primary:
                mine, theirs = _join_field(join, "other", pseudos), _join_field(join, "sub", pseudos)
                my_name, their_name = join["other"], join["sub"]
            else:
                mine, theirs = _join_field(join, "sub", pseudos), _join_field(join, "other", pseudos)
                my_name, their_name = join["sub"], join["other"]
            items.append({
                "id": f"join:{index}", "kind": "join", "field": mine, "other_field": theirs,
                "label": f"Shared value: {my_name} {mine} = {their_name} {theirs}",
                "help": (f"The rule matches the {my_name} event (this log) and the {their_name} event only when these "
                         f"fields are equal. The value goes into both."),
                "examples": examples_for(mine, other_field=theirs), "required": True})
    source_query = rule.get("query") or ""
    for index, m in enumerate(_IOC.finditer(_strip_comments(source_query))):
        field, args = m.group(1), m.group(2)
        ioc_type = _arg(args, "type") or "ip_address"
        confidence = (_arg(args, "confidenceThreshold") or "low").lower()
        examples, note = [], ""
        if client is not None:
            try:
                found = client.search_indicators(ioc_type, CONFIDENCE.get(confidence, ["high"]), log or ActivityLog())
                examples = [r["indicator"] for r in found][:3]
                note = " Examples are real indicators from your Falcon Intelligence, used only in this test log."
            except FalconError as exc:
                note = f" {exc}"
        items.append({
            "id": f"ioc:{index}", "kind": "ioc", "field": field, "ioc_type": ioc_type, "confidence": confidence,
            "label": f"{field}: an indicator in CrowdStrike threat intelligence ({ioc_type}, {confidence} confidence or above)",
            "help": ("ioc:lookup() only matches indicators that are in CrowdStrike's live intelligence, so a synthetic value "
                     "can never match. Enter an indicator you know is in your Falcon Intelligence." + note),
            "examples": examples, "required": True})
    for index, m in enumerate(_MATCH.finditer(_strip_comments(source_query))):
        file, args = m.group(1), m.group(2)
        fm = re.search(r"field\s*=\s*\[?([^\],)]+)", args)
        field = fm.group(1).strip().strip('"') if fm else None
        if not field:
            continue
        items.append({
            "id": f"lookup:{index}", "kind": "lookup", "field": field, "file": file,
            "label": f"{field}: a value listed in the lookup file {file}",
            "help": (f"The rule looks {field} up in the tenant lookup file \"{file}\" and only matches values listed "
                     "there. Enter one of its values."), "examples": [], "required": True})
    for index, (alias, function, field, op, number) in enumerate(aggregations(source_query if not parsed else "")):
        needed = _needed(op, number)
        if function in ("count", "distinct"):
            items.append({
                "id": f"agg:{index}", "kind": "events", "field": field, "function": function,
                "label": f"Number of events ({alias} {op} {number:g}" + (f", each with a different {field}" if function == "distinct" else "") + ")",
                "help": "The rule counts matching events. This many copies of the event are sent, as a JSON array.",
                "examples": [str(needed), str(needed + 5), str(needed * 2)], "required": True})
        elif function == "sum" and field:
            items.append({
                "id": f"agg:{index}", "kind": "sum", "field": field, "threshold": needed,
                "label": f"Total of {field} across events ({alias} {op} {number:g})",
                "help": f"The rule adds up {field}. The total is split evenly across the events sent.",
                "examples": [str(needed), str(needed * 2), str(needed * 10)], "required": True})
    # Conditions this log doesn't meet that a value can fix.
    target_rule = rule
    if parsed and pseudos:
        target_rule = next(iter(pseudos.values()))
    events = events_of(text, mode)
    covered = {i["field"] for i in items}
    wants = {f: w for f, w, _ in requirements(target_rule["_rule"]) if w is not None}
    if events:
        check = judge(target_rule, events, parser, simulation)
        for c in check["conditions"]:
            if c["met"] != "no" or c["field"] in NOT_FIXABLE_IN_LOG or c["field"] in covered:
                continue
            from suggest import want_from_condition
            want = wants.get(c["field"]) or want_from_condition(c)
            items.append({
                "id": f"field:{c['field']}", "kind": "field", "field": c["field"], "op": c["op"], "expected": c["expected"],
                "label": f"{c['field']} {c['op']} {c['expected']}",
                "help": f"This log has {c['actual']!r} for {c['field']}." if c["actual"] is not None else f"This log has no {c['field']}.",
                "examples": examples_for(c["field"], want), "required": False})
            covered.add(c["field"])
    for word, text_ in (("defineTable", "builds a table from other events already in NG-SIEM (for example a baseline or "
                                         "first-seen list), so it depends on the tenant's history."),
                        ("selfJoinFilter", "compares several events of the same kind, so it needs more than one event.")):
        if re.search(word, source_query):
            items.append({"id": f"info:{word}", "kind": "info", "label": f"Uses {word}()",
                          "help": f"The rule {text_} No value in this log can supply that.", "examples": []})
    return {"items": items, "correlate": correlate_info}


# ---------------------------------------------------------------- applying values

def _set(event, field, value, parser, simulation):
    from suggest import _fix_event
    fixed = _fix_event(event, {"field": field, "op": "=", "expected": str(value)}, parser, simulation)
    return fixed if fixed is not None else event


def _has_value(event, field, parser, simulation):
    """Whether the parsed event (simulated) already has field."""
    from rules import raw_of
    if simulation is None or not parser:
        return False
    result = simulation.run(parser, raw_of(event))
    name = field[1:] if field.startswith("#") else field
    return bool(result and name in result.fields)


def fill(rule, text, mode, parser, simulation, values, client=None):
    """Apply the operator's values. Returns {"success", "log", "companions", "message", "verdict"}."""
    from generator import _repeat, generate
    from rules import events_of, judge, template_entry
    analysis = analyze(rule, text, mode, parser, simulation)
    items = {i["id"]: i for i in analysis["items"]}
    events = events_of(text, mode)
    if not events:
        return {"success": False, "message": "The log couldn't be read."}
    is_text = isinstance(events[0], str)
    applied = []
    parsed, pseudos = pseudo_rules(rule)
    join_values = {}
    count_override, sum_items = None, []
    for item_id, value in (values or {}).items():
        item = items.get(item_id)
        value = str(value).strip()
        if item is None or not value or item["kind"] == "info":
            continue
        if item["kind"] in ("field", "ioc", "lookup"):
            events = [_set(e, item["field"], value, parser, simulation) for e in events]
            applied.append(item["field"])
        elif item["kind"] == "join":
            join_values[item_id] = value
            events = [_set(e, item["field"], value, parser, simulation) for e in events]
            applied.append(item["field"])
        elif item["kind"] == "events":
            try:
                count_override = max(int(float(value)), 1)
            except ValueError:
                continue
            if item.get("function") == "distinct" and item.get("field"):
                sum_items.append(("distinct", item["field"], None))
        elif item["kind"] == "sum":
            try:
                sum_items.append(("sum", item["field"], float(value)))
            except ValueError:
                continue
    if count_override or sum_items:
        if is_text:
            return {"success": False, "message": "Plain-text logs can't be repeated here: send the line several times."}
        n = count_override or len(events)
        base = events[0]
        events = [copy.deepcopy(base) for _ in range(n)]
        for kind, field, total in sum_items:
            for i, event in enumerate(events):
                value = f"{MARKER}-{i + 1}" if kind == "distinct" else str(int(math.ceil(total / n)))
                events[i] = _set(event, field, value, parser, simulation)
        applied.append(f"{n} events")
    companions = []
    if parsed:
        primary = _primary(parsed, pseudos, parser)
        for sub in parsed["subs"]:
            if sub["name"] == primary:
                continue
            pseudo = pseudos[sub["name"]]
            entry = generate(pseudo, simulation) if simulation is not None and simulation.active else None
            if entry is None:
                fallback = template_entry(pseudo, simulation)
                if not fallback:
                    companions.append({"name": sub["name"], **source_label(pseudo),
                                       "parser": pseudo["parser"], "log": None,
                                       "note": "No sample could be built for this source."})
                    continue
                log, comp_parser, verdict = fallback["log"], fallback["parser"], fallback["verdict"]
                comp_events = events_of(log, "raw" if fallback["format"] == "text" else "event")
            else:
                comp_parser, verdict = entry["parser"], entry["verdict"]
                comp_events = entry["log"] if isinstance(entry["log"], list) else [entry["log"]]
            for index, join in enumerate(parsed["joins"]):
                value = join_values.get(f"join:{index}") or (items.get(f"join:{index}") or {}).get("examples", [None])[0]
                if value is None:
                    continue
                if join["sub"] == sub["name"]:
                    field = _join_field(join, "sub", pseudos)
                elif join["other"] == sub["name"]:
                    field = _join_field(join, "other", pseudos)
                else:
                    continue
                comp_events = [_set(e, field, value, comp_parser, simulation) for e in comp_events]
            # Fields the rule reports for this source (its include: list) get synthetic values too, so the
            # companion reads like a real event, as long as that doesn't change its part of the rule.
            sub_includes = next((x["include"] for x in parsed["subs"] if x["name"] == sub["name"]), [])
            before = judge(pseudo, comp_events, comp_parser, simulation)["verdict"]
            for field in sub_includes:
                field = _flatten_field(field, pseudo.get("_splits") or [])
                if _has_value(comp_events[0], field, comp_parser, simulation):
                    continue  # already set, such as the shared value
                trial = [_set(e, field, examples_for(field)[0], comp_parser, simulation) for e in comp_events]
                if trial != comp_events and judge(pseudo, trial, comp_parser, simulation)["verdict"] == before:
                    comp_events = trial
            check = judge(pseudo, comp_events, comp_parser, simulation)
            comp_text = comp_events[0] if isinstance(comp_events[0], str) else json.dumps(
                comp_events[0] if len(comp_events) == 1 else comp_events, indent=2)
            companions.append({"name": sub["name"], **source_label(pseudo),
                               "parser": comp_parser, "log": comp_text, "verdict": check["verdict"],
                               "format": "text" if isinstance(comp_events[0], str) else "json"})
    target = next(iter(pseudos.values())) if parsed else rule
    if parsed:
        target = pseudos[_primary(parsed, pseudos, parser)]
    check = judge(target, events, parser, simulation)
    new_text = events[0] if is_text else json.dumps(events[0] if len(events) == 1 else events, indent=2)
    order = ""
    if parsed:
        names = [s["name"] for s in parsed["subs"]]
        order = (f" Send the events in this order: {', '.join(names)}" if parsed["sequence"] else
                 f" Send all {len(names)} events") + (f", within {parsed['within']}." if parsed["within"] else ".")
    message = (f"Applied: {', '.join(applied)}." if applied else "No values were applied.") + order
    return {"success": True, "log": new_text, "companions": companions, "message": message,
            "verdict": check["verdict"]}


def _primary(parsed, pseudos, parser):
    """The sub-search this log belongs to: the one whose parser matches, else the first."""
    for sub in parsed["subs"]:
        if parser and pseudos[sub["name"]].get("parser") and str(parser).startswith(pseudos[sub["name"]]["parser"]):
            return sub["name"]
    for sub in parsed["subs"]:
        vendor = str(pseudos[sub["name"]].get("vendor_tag") or "").lower()
        if parser and vendor and str(parser).lower().startswith(vendor):
            return sub["name"]
    return parsed["subs"][0]["name"]
