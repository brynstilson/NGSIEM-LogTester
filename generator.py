"""Builds a raw log that the connector's real parser turns into an event matching a correlation rule.

It works backwards from the rule's conditions through the parser's lineage (which raw field, case
branch or match arm produces each parsed field), writes those raw fields into a base log, then runs
the parser simulation and the rule check to confirm the result. Several base logs are tried, such
as a vendor's message and click events, and the best is kept. Any condition it couldn't place is
listed, so a sample is never silently incomplete.
"""
import copy
import ipaddress
import json

from field_model import example_value
from sample_events import MARKER, SAMPLES, render_sample

LIKELY, NEEDS_EVENTS, UNCERTAIN, UNLIKELY = "likely", "needs_more_events", "uncertain", "unlikely"
RANK = {LIKELY: 0, NEEDS_EVENTS: 1, UNCERTAIN: 2, UNLIKELY: 3}
MAX_DEPTH = 6
MARKER_FIELD = "ngsiem_logtester_marker"
NESTED = ""  # separates a field holding JSON text from the path inside that JSON


# ---------------------------------------------------------------- wants: what a field must look like

def want_from_cmp(op, value):
    kind, expected = value
    if kind == "regex":
        return ("regex", expected) if op == "=" else ("ne", None)
    if op == "=":
        return ("eq", str(expected))
    if op == "!=":
        return ("ne", str(expected))
    return ("num", op, str(expected))


def concrete(want, current=None):
    kind = want[0]
    if kind == "eq":
        return want[1].replace("*", "test") if "*" in want[1] else want[1]
    if kind == "regex":
        return example_value("regex", want[1])
    if kind == "num":
        try:
            n = float(want[2])
        except ValueError:
            return None
        v = n + 1 if want[1] == ">" else n - 1 if want[1] == "<" else n
        return int(v) if float(v).is_integer() else v
    if kind == "exists":
        return current if current not in (None, "") else f"{MARKER}-value"
    if kind == "in":
        return want[1][0].replace("*", "test") if want[1] else None
    if kind == "cidr":
        try:
            return str(ipaddress.ip_network(want[1][0], strict=False).network_address + 1)
        except (ValueError, IndexError):
            return None
    if kind == "ne":
        return f"{MARKER}-value"
    if kind == "contains":
        return want[1]
    return None


def merge(existing, want, base_value=None):
    """A value meeting want that keeps an earlier requirement on the same field, or None.

    Two regex conditions on one field (message=/a/ and message=/b/) are met by joining examples.
    """
    if existing is None:
        return concrete(want, base_value)
    if satisfies(want, existing):
        return existing
    addition = concrete(want)
    if addition is None:
        return None
    combined = f"{existing} {addition}"
    return combined if satisfies(want, combined) else None


def satisfies(want, value):
    import fnmatch
    import re
    if value is None:
        return want[0] == "ne"
    value = str(value)
    kind = want[0]
    if kind == "eq":
        return fnmatch.fnmatchcase(value, want[1]) if "*" in want[1] else value == want[1]
    if kind == "ne":
        return want[1] is None or value != want[1]
    if kind == "regex":
        body, flags = want[1]
        try:
            return re.search(body, value, re.I if "i" in flags else 0) is not None
        except re.error:
            return False
    if kind == "in":
        return any(fnmatch.fnmatchcase(value, v) for v in want[1])
    if kind in ("exists", "contains"):
        return True if kind == "exists" else value == want[1]
    if kind == "num":
        try:
            a, b = float(value), float(want[2])
        except ValueError:
            return False
        return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[want[1]]
    return False


# ---------------------------------------------------------------- solving against the lineage

class Solver:
    def __init__(self, lineage, base_fields):
        self.lineage = lineage
        self.decoder = lineage.main_decoder() if lineage else None
        self.base = base_fields
        self.edits = {}
        self.raw_overrides = {}   # (pattern, flags) -> {group field: value}, for text logs
        self.raw_text = []        # text the rule expects somewhere in the raw log
        self.unplaced = []

    def raw_path(self, field):
        # Any decoder reading the raw log itself, such as the usual parseJson(prefix="Vendor.") branch
        # beside a special no-prefix branch.
        raw_decoders = [x for x in (self.lineage.decoders if self.lineage else [])
                        if x.source == "@rawstring" and x.kind in ("json", "kv") and x.prefix and field.startswith(x.prefix)]
        if raw_decoders:
            prefix = max((x.prefix for x in raw_decoders), key=len)
            return field[len(prefix):]
        nested = [x for x in (self.lineage.decoders if self.lineage else [])
                  if x.kind == "json" and x.source != "@rawstring" and x.prefix and field.startswith(x.prefix)]
        if nested:
            decoder = max(nested, key=lambda x: len(x.prefix))
            outer = self.raw_path(decoder.source) if decoder.source != field else None
            if outer is None and self.lineage:
                outer = self.lineage.raw_source(decoder.source)
            if outer:
                return f"{outer}{NESTED}{field[len(decoder.prefix):]}"
        xml = [x for x in (self.lineage.decoders if self.lineage else []) if x.kind == "xml" and x.prefix and field.startswith(x.prefix)]
        if xml:
            prefix = min((x.prefix for x in xml), key=len)
            return field[len(prefix):]
        return None

    def current(self, field):
        """The base log's value for a parsed field, where it can be traced to a raw field."""
        path = self.raw_path(field)
        if path is None and self.lineage:
            path = self.lineage.raw_source(field)
        return self.base.get(path) if path else None

    def snapshot(self):
        return dict(self.edits), {k: dict(v) for k, v in self.raw_overrides.items()}, list(self.raw_text)

    def restore(self, state):
        self.edits, self.raw_overrides, self.raw_text = state[0], state[1], state[2]

    def resolve(self, field, want, depth=0, seen=frozenset()):
        field = field[1:] if field.startswith("#") else field
        if depth > MAX_DEPTH or (field, want[0]) in seen:
            return False
        if field == "@rawstring":
            # Text the rule looks for anywhere in the log: added as a marker field or to the line.
            value = concrete(want) if want[0] != "text" else want[1]
            if value is None:
                return False
            self.raw_text.append(str(value))
            return True
        seen = seen | {(field, want[0])}
        path = self.raw_path(field)
        if path is not None:
            existing = self.edits.get(path)
            value = merge(existing, want, self.base.get(path))
            if value is None:
                return False
            self.edits[path] = value
            return True
        producers = (self.lineage.producers.get(field, []) if self.lineage else [])
        if want[0] == "contains":
            producers = self.lineage.producers.get(field.rstrip("[]"), []) if self.lineage else []
        used = set(self.raw_overrides)
        ordered = sorted(producers, key=lambda p: (not (p.kind == "extract" and p.value in used), len(p.conditions), p.kind != "copy"))
        for producer in ordered:
            state = self.snapshot()
            if self._producer(producer, want, depth, seen):
                return True
            self.restore(state)
        return False

    def _producer(self, p, want, depth, seen):
        if p.kind == "copy" and p.source:
            inner = want
            if p.transform == "lower" and want[0] == "eq":
                inner = ("eq", want[1])
            ok = self.resolve(p.source, inner, depth + 1, seen)
            return ok and self.conditions(p.conditions, depth, seen)
        if p.kind == "const":
            return satisfies(want, p.value) and self.conditions(p.conditions, depth, seen)
        if p.kind == "append":
            return want[0] in ("contains", "eq") and satisfies(("eq", want[1]), p.value) and self.conditions(p.conditions, depth, seen)
        if p.kind == "append-copy" and p.source:
            return self.resolve(p.source, ("eq", want[1]), depth + 1, seen) and self.conditions(p.conditions, depth, seen)
        if p.kind == "format" and p.source:
            before, after = p.value
            value = concrete(want)
            if value is None:
                return False
            value = str(value)
            if not (value.startswith(before) and value.endswith(after)) or len(value) < len(before) + len(after):
                return False
            inner = value[len(before):len(value) - len(after) if after else None]
            return self.resolve(p.source, ("eq", inner), depth + 1, seen) and self.conditions(p.conditions, depth, seen)
        if p.kind == "extract" and p.source:
            from regex_sample import sample, substitute
            value = concrete(want)
            if value is None:
                return False
            body, flags = p.value
            if p.source == "@rawstring":
                if self.raw_overrides and (body, flags) not in self.raw_overrides:
                    return False  # One raw line: keep every value in the same pattern.
                group = self.raw_overrides.setdefault((body, flags), {})
                merged = merge(group.get(p.target), want)
                if merged is None:
                    return False
                group[p.target] = str(merged)
                return self.conditions(p.conditions, depth, seen)
            current = self.current(p.source)
            new = substitute(body, flags, current, {p.target: value}) if current else None
            new = new or sample(body, flags, {p.target: value})
            if new is None:
                return False
            return self.resolve(p.source, ("eq", new), depth + 1, seen) and self.conditions(p.conditions, depth, seen)
        return False

    def conditions(self, conds, depth, seen):
        for cond in conds:
            if not self.condition(cond, depth, seen):
                return False
        return True

    def condition(self, cond, depth, seen):
        kind = cond[0]
        if kind == "arm":
            _, field, pattern = cond
            pk = pattern[0]
            if pk == "any":
                return True
            if pk in ("string", "word", "number"):
                return self.resolve(field, ("eq", str(pattern[1])), depth + 1, seen)
            if pk == "regex":
                return self.resolve(field, ("regex", pattern[1]), depth + 1, seen)
            if pk == "call" and pattern[1][0] == "in":
                values = pattern[1][2].get("values")
                items = [str(v[1]) for v in (values[1] if values and values[0] == "list" else []) if v[0] == "lit"]
                return bool(items) and self.resolve(field, ("in", items), depth + 1, seen)
            return True
        if kind == "cmp":
            _, field, op, value = cond
            if field == "@rawstring":
                return True  # The base log's format decides this, not a field we can set.
            if value[0] == "any":
                return self.resolve(field, ("exists",), depth + 1, seen) if op == "=" else True
            return self.resolve(field, want_from_cmp(op, value), depth + 1, seen)
        if kind == "and":
            return all(self.condition(c, depth, seen) for c in cond[1])
        if kind == "or":
            for c in cond[1]:
                state = self.snapshot()
                if self.condition(c, depth, seen):
                    return True
                self.restore(state)
            return False
        if kind == "call" and cond[1][0] == "in":
            fname, positional, named = cond[1]
            field = named.get("field") or (positional[0] if positional else None)
            values = named.get("values")
            items = [str(v[1]) for v in (values[1] if values and values[0] == "list" else []) if v[0] == "lit"]
            if field and items:
                return self.resolve(str(field[1]), ("in", items), depth + 1, seen)
        if kind == "apply":
            # field =~ in(values=[...]), field =~ cidr(...), field =~ wildcard(...), field =~ regex(...)
            _, field, (fname, positional, named) = cond
            values = named.get("values") or named.get("subnet") or named.get("pattern") or named.get("regex") \
                or (positional[0] if positional else None)
            items = [str(v[1]) for v in (values[1] if values and values[0] == "list" else [values] if values else [])
                     if v and v[0] in ("lit", "ref")]
            if not items:
                return True
            want = {"in": ("in", items), "cidr": ("cidr", items), "wildcard": ("in", items),
                    "regex": ("regex", (items[0], ""))}.get(fname)
            return self.resolve(field, want, depth + 1, seen) if want else True
        return True  # not(...), text and other conditions don't block a branch here


# ---------------------------------------------------------------- the generator

def requirements(rule):
    """(field, want, label) for each condition of the rule's first matching path."""
    from rules import _requirements
    out = []
    for kind, node in rule.stages:
        if kind != "filter":
            continue
        for req in _requirements(node):
            if req[0] == "cmp":
                _, name, op, value = req
                if len(value) != 2 or value[0] not in ("string", "word", "regex", "number"):
                    out.append((name, None, f"{name} must equal a computed value"))
                    continue
                vkind = "word" if value[0] == "number" else value[0]
                out.append((name, want_from_cmp(op, (vkind, value[1])), f"{name} {op} {value[1] if vkind != 'regex' else '/' + value[1][0] + '/'}"))
            elif req[0] in ("in", "!in", "cidr", "!cidr"):
                call = req[1]
                target = call[3].get("field") or (call[2][0] if call[2] else None)
                values = call[3].get("values") or call[3].get("subnet")
                if not target or not values:
                    continue
                items = [str(v) for v in values[1]] if values[0] == "list" else [str(values[1])]
                kind = {"in": "in", "cidr": "cidr", "!in": "ne", "!cidr": "ne"}[req[0]]
                out.append((str(target[1]), (kind, items if kind != "ne" else None), f"{target[1]} {req[0]} {', '.join(items)}"))
            elif req[0] == "contains":
                out.append((req[1], ("contains", req[2]), f"{req[1]} contains {req[2]}"))
            elif req[0] == "text":
                out.append(("@rawstring", ("text", req[1]), f'text "{req[1]}"'))
    return out


def base_logs(parser, lineage, simulation):
    """Candidate starting logs for a parser: its built-in samples, else a skeleton in its format."""
    bases = []
    for sample in SAMPLES:
        if sample.get("parser") == parser or parser in (sample.get("parsers") or []):
            text = render_sample(sample["id"])
            try:
                bases.append((sample["id"], json.loads(text)))
            except ValueError:
                bases.append((sample["id"], text))
    fmt = lineage.format if lineage else None
    if not bases:
        if fmt == "json":
            bases.append(("skeleton", {MARKER_FIELD: MARKER}))
        elif fmt == "kv":
            bases.append(("skeleton", f"{MARKER_FIELD}={MARKER}"))
        elif fmt == "cef":
            doc = simulation.parser(parser) or {}
            vendor = str(doc.get("vendor") or "Vendor").title()
            product = str((doc.get("product") or ["Product"])[0]).title()
            bases.append(("skeleton", f"CEF:0|{vendor}|{product}|1.0|100|{MARKER} test event|5|{MARKER_FIELD}={MARKER}"))
        # Text formats: a line built from each pattern the parser reads the raw log with.
        for body, flags in raw_patterns(lineage)[:4]:
            from regex_sample import sample
            line = sample(body, flags, {"message": f"{MARKER} synthetic event"}) or sample(body, flags)
            if line:
                bases.append(("skeleton", line))
    return bases


def raw_patterns(lineage):
    """Distinct regexes the parser applies to @rawstring, in script order."""
    seen, out = set(), []
    for producers in (lineage.producers.values() if lineage else []):
        for p in producers:
            if p.kind == "extract" and p.source == "@rawstring" and p.value not in seen:
                seen.add(p.value)
                out.append(p.value)
    return out


def _apply_xml(text, edits):
    """Set fields in an XML log by text editing, so namespaces and layout stay as they were."""
    import re as _re
    from xml.sax.saxutils import escape
    for path, value in edits.items():
        parts = path.split(".")
        leaf = parts[-1]
        value = escape(str(value))
        if leaf.startswith("_"):
            continue  # attributes are left as they are
        if len(parts) >= 2 and parts[-2] == "EventData":
            data = _re.compile(r"(<Data\s+Name=[\"']" + _re.escape(leaf) + r"[\"']\s*>)(.*?)(</Data>)", _re.S)
            if data.search(text):
                text = data.sub(lambda m: m.group(1) + value + m.group(3), text, count=1)
            elif "</EventData>" in text:
                text = text.replace("</EventData>", f'<Data Name="{leaf}">{value}</Data></EventData>', 1)
            continue
        element = _re.compile(r"(<" + _re.escape(leaf) + r"(?:\s[^>]*)?>)(.*?)(</" + _re.escape(leaf) + r">)", _re.S)
        if element.search(text):
            text = element.sub(lambda m: m.group(1) + value + m.group(3), text, count=1)
    return text


def _apply_text_overrides(text, overrides, skeleton):
    from regex_sample import sample, substitute
    for (body, flags), groups in overrides.items():
        changed = substitute(body, flags, text, groups)
        if changed is None and skeleton:
            changed = sample(body, flags, groups)
        if changed is not None:
            text = changed
    return text


def _apply(base, edits, fmt, overrides=None, skeleton=False, raw_text=()):
    from rules import _apply_kv, _set_path
    if raw_text:
        if isinstance(base, dict):
            edits = {**edits, MARKER_FIELD + "_text": " ".join(raw_text)}
        elif isinstance(base, str):
            base = base.rstrip() + " " + " ".join(raw_text)
    if isinstance(base, str) and base.lstrip().startswith("<") and edits:
        base = _apply_xml(base, edits)
        edits = {}
    if isinstance(base, str) and overrides:
        base = _apply_text_overrides(base, overrides, skeleton)
    # Values inside a field that holds JSON text are gathered and written as that text.
    nested = {}
    for path in [p for p in edits if NESTED in p]:
        outer, inner = path.split(NESTED, 1)
        nested.setdefault(outer, {})[inner] = edits.pop(path) if False else edits[path]
    edits = {p: v for p, v in edits.items() if NESTED not in p}
    for outer, inner_edits in nested.items():
        holder = {}
        if isinstance(base, dict):
            current = base
            for part in outer.split("."):
                current = current.get(part) if isinstance(current, dict) else None
            if isinstance(current, str):
                try:
                    holder = json.loads(current)
                except ValueError:
                    holder = {}
        for inner, value in inner_edits.items():
            try:
                _set_path(holder, inner, value)
            except (TypeError, AttributeError, IndexError, ValueError):
                pass
        edits[outer] = json.dumps(holder)
    if isinstance(base, dict):
        event = copy.deepcopy(base)
        for path, value in edits.items():
            try:
                _set_path(event, path, value)
            except (TypeError, AttributeError, IndexError, ValueError):
                pass
        return event
    if isinstance(base, str) and fmt in ("kv", "cef") and edits:
        return _apply_kv(base, {k: v for k, v in edits.items()})
    return base


def _flat_base(base):
    from field_model import flatten, text_fields
    if isinstance(base, dict):
        return dict(flatten(base))
    return text_fields(base) if isinstance(base, str) else {}


def generate(rule_info, simulation):
    """(log, note, verdict, parser) or None if the simulation can't help with this rule."""
    from rules import judge, events_of
    rule = rule_info["_rule"]
    if rule.endpoint_only or not simulation or not simulation.active:
        return None
    reqs = requirements(rule)
    parsers = candidate_parsers(rule_info, reqs, simulation)
    best = None
    for parser in parsers[:3]:
        lineage = simulation.lineage(parser)
        if lineage is None:
            continue
        for label, base in base_logs(parser, lineage, simulation):
            solver = Solver(lineage, _flat_base(base))
            unplaced = []
            # Satisfy what the parser needs just to keep the log (top-level filters, case blocks
            # with no catch-all), unless the base log already passes.
            probe = simulation.run(parser, base if isinstance(base, str) else json.dumps(base))
            if probe is None or probe.dropped:
                for options in lineage.gates:
                    for option in options:
                        state = solver.snapshot()
                        if solver.conditions(option, 0, frozenset()):
                            break
                        solver.restore(state)
            for field, want, text in reqs:
                if field == "#repo":
                    continue  # Set at ingest: third-party data never lands in Falcon's own repositories.
                if want is None:
                    unplaced.append(text)
                    continue
                if not solver.resolve(field, want):
                    unplaced.append(text)
            build = lambda sv: _build(base, sv, lineage, rule, label)  # noqa: E731
            log, events, text_log = build(solver)
            check = judge(rule_info, events_of(text_log, "raw" if isinstance(log, str) else "event"), parser, simulation)
            if check["verdict"] != LIKELY:
                solver, check, unplaced = _search(rule_info, parser, lineage, solver, reqs, simulation, build, check, unplaced)
                log, events, text_log = build(solver)
            sim_result = simulation.run(parser, events[0] if isinstance(events[0], str) else json.dumps(events[0]))
            dropped = bool(sim_result and sim_result.dropped)
            score = (RANK.get(check["verdict"], 4) + (5 if dropped else 0), parsers.index(parser), len(unplaced), label == "skeleton")
            candidate = {"log": log if len(events) == 1 else events, "text": text_log, "verdict": check["verdict"],
                         "unplaced": unplaced, "parser": parser, "check": check, "base": label, "score": score}
            if best is None or score < best["score"]:
                best = candidate
            if check["verdict"] == LIKELY:
                break
        if best and best["verdict"] == LIKELY:
            break
    if best is None:
        return None
    notes = []
    if best["unplaced"]:
        notes.append("Couldn't place: " + "; ".join(best["unplaced"]) + ".")
    if best["verdict"] != LIKELY:
        reasons = best["check"].get("reasons") or []
        if reasons:
            notes.append("Why it may not fire: " + " ".join(reasons[:4]))
    if isinstance(best["log"], str) and rule.threshold > 1:
        notes.append(f"The rule needs {rule.threshold} matching events, so send this line {rule.threshold} times.")
    best["note"] = " ".join(notes)
    return best


TAG_FIELDS = {"#event.module", "event.module", "#event.dataset", "event.dataset", "#event.kind", "event.kind",
              "#Vendor", "Vendor", "#observer.type", "#event.outcome"}


def candidate_parsers(rule_info, reqs, simulation):
    """Parsers that could produce this rule's tags, best first.

    Every parser of the rule's vendor is scored on whether its constants can give the tag values the
    rule filters on (#event.module, #event.dataset and so on); parsers with a built-in sample win ties.
    """
    names = set(simulation.parsers_for_rule(rule_info.get("vendor_tag"), None, rule_info.get("sourcetype")))
    if rule_info.get("parser") and simulation.parser(rule_info["parser"]):
        names.add(simulation.store.resolve(rule_info["parser"]))
    with_samples = {s.get("parser") for s in SAMPLES}
    tag_wants = [(f, w) for f, w, _ in reqs if f in TAG_FIELDS and w is not None]
    scored = []
    for name in names:
        lineage = simulation.lineage(name)
        if lineage is None:
            continue
        score = 0
        for field, want in tag_wants:
            target = field.lstrip("#")
            producers = lineage.producers.get(target, [])
            if any(p.kind == "const" and satisfies(want, p.value) for p in producers):
                score += 3
            elif any(p.kind == "format" and _format_fits(p.value, want) for p in producers):
                score += 3
            elif producers and all(p.kind in ("const", "format") for p in producers):
                score -= 2
            elif any(p.kind in ("format", "copy", "derived", "extract") for p in producers):
                score += 1
            elif producers:
                score -= 2
            else:
                score -= 1
        scored.append((-score, name not in with_samples, name))
    return [name for _, _, name in sorted(scored)]


def _repeat(log, rule, lineage, solver):
    if isinstance(log, str):
        return [log]
    events = []
    for index in range(rule.threshold):
        item = copy.deepcopy(log)
        if rule.distinct_field:
            path = solver.raw_path(rule.distinct_field[1:] if rule.distinct_field.startswith("#") else rule.distinct_field)
            if path is None and lineage:
                src = lineage.raw_source(rule.distinct_field)
                path = src
            if path:
                from rules import _set_path
                current = item
                for part in path.split("."):
                    current = current.get(part) if isinstance(current, dict) else None
                _set_path(item, path, f"{current or 'value'}-{index + 1}")
        events.append(item)
    return events


def _format_fits(parts, want):
    """Whether a format("before%safter") producer can give a value satisfying want."""
    before, after = parts
    value = concrete(want)
    if value is None:
        return False
    value = str(value)
    return value.startswith(before) and value.endswith(after) and len(value) > len(before) + len(after)



def _build(base, solver, lineage, rule, label):
    log = _apply(base, solver.edits, lineage.format, solver.raw_overrides, label == "skeleton", solver.raw_text)
    events = [log]
    if rule.threshold > 1:
        events = _repeat(log, rule, lineage, solver)
    text_log = log if isinstance(log, str) else json.dumps(events[0] if len(events) == 1 else events, indent=2)
    return log, events, text_log


def _met(check):
    return (RANK.get(check["verdict"], 4) * -10) + sum(1 for c in check["conditions"] if c["met"] == "yes")


def _variants(value):
    """Raw spellings a parser might turn into value: computed fields are often lower-cased or slugged."""
    text = str(value)
    words = text.replace("-", " ").replace("_", " ")
    out = [text, words, words.capitalize(), words.title(), words.title().replace(" ", ""), text.replace("-", "_"),
           text.upper(), words.upper(), text.replace(" ", "-")]
    return list(dict.fromkeys(v for v in out if v))


def _search(rule_info, parser, lineage, solver, reqs, simulation, build, check, unplaced, rounds=4):
    """Hill-climb with the simulation: for each failing condition, try each producer of the field on
    its own, then spelling variants for the raw field behind a computed one, keeping what helps."""
    from rules import judge, events_of
    best_score = _met(check)
    wants = {}
    for field, want, _ in reqs:
        if want is not None:
            wants.setdefault(field, []).append(want)
    for _ in range(rounds):
        failing = [c["field"] for c in check["conditions"] if c["met"] == "no" and c["field"] in wants]
        if not failing:
            break
        improved = False
        for field in dict.fromkeys(failing):
            target = field[1:] if field.startswith("#") else field
            trials = []
            for producer in lineage.producers.get(target, []):
                trial = copy.copy(solver)
                trial.edits, trial.raw_overrides, trial.raw_text = solver.snapshot()
                saved = lineage.producers[target]
                lineage.producers[target] = [producer]
                try:
                    if all(trial.resolve(field, w) for w in wants[field]):
                        trials.append(trial)
                finally:
                    lineage.producers[target] = saved
                if producer.kind in ("derived", "copy", "format") and producer.source:
                    path = trial.raw_path(producer.source) or lineage.raw_source(producer.source)
                    value = concrete(wants[field][0])
                    if path and value is not None:
                        for variant in _variants(value):
                            t2 = copy.copy(solver)
                            t2.edits, t2.raw_overrides, t2.raw_text = solver.snapshot()
                            t2.edits[path] = variant
                            trials.append(t2)
            for trial in trials[:24]:
                log, events, text_log = build(trial)
                result = judge(rule_info, events_of(text_log, "raw" if isinstance(log, str) else "event"), parser, simulation)
                score = _met(result)
                if score > best_score:
                    solver, check, best_score, improved = trial, result, score, True
                    unplaced = [u for u in unplaced if not u.startswith(field)]
                    if result["verdict"] == LIKELY:
                        return solver, check, unplaced
                    break
        if not improved:
            break
    return solver, check, unplaced
