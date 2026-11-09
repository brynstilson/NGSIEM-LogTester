"""A small CQL reader for estimating whether one submission would satisfy a correlation rule.

NG-SIEM evaluates a rule against events *after* a parser has normalized them. This module only
sees the raw log, so it works from an approximation of the parser (see field_model.py) and
reports how sure it is. It understands the filter part of a query (comparisons, regexes,
wildcards, in(), cidr(), and/or/not), and count thresholds after an aggregation. Anything else
is reported as "can't evaluate" rather than guessed.
"""
import difflib
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field

TRUE, FALSE, UNKNOWN = True, False, None

# Functions that only shape output for a single event, so they don't change whether it matches.
PASSTHROUGH = {
    "table", "select", "sort", "head", "tail", "fieldset", "drop", "rename", "format", "eval",
    "lower", "upper", "replace", "split", "splitstring", "parsejson", "parsetimestamp", "concat",
    "default", "iplocation", "asn", "length", "round", "formattime", "now", "unit",
}
AGGREGATES = {
    "groupby", "count", "stats", "top", "timechart", "bucket", "series", "sum", "avg", "max", "min",
    "collect", "session", "window", "selectlast", "selectfrommax", "selectfrommin", "tail",
}
UNSUPPORTED = {
    "correlate", "join", "definetable", "match", "lookup", "sequence", "selfjoin",
    "selfjoinfilter", "readfile", "ioc:lookup", "neighbor", "slidingwindow", "test",
}
ENDPOINT_TAGS = {"#event_simpleName", "event_simpleName", "#repo"}


@dataclass
class Condition:
    field: str
    op: str
    expected: str
    state: object = UNKNOWN
    actual: object = None
    basis: str = ""
    suggestion: str = ""


@dataclass
class Evaluation:
    """How one event fares against one rule's filter."""
    state: object
    conditions: list = field(default_factory=list)
    unsupported: list = field(default_factory=list)


@dataclass
class Rule:
    stages: list
    threshold: int = 1
    distinct_field: str = ""
    unsupported: list = field(default_factory=list)
    endpoint_only: bool = False


# ---------------------------------------------------------------- tokenizing

_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_REGEX = re.compile(r"/(?:\\.|[^/\\\n])+/[a-zA-Z]*")
_OPS = [":=", "!=", "<=", ">=", "=~", "==", "=", "<", ">", "!", "(", ")", "[", "]", "{", "}", ",", "|", ";"]
_WORD = re.compile(r'[^\s"=!<>(),|;\[\]{}]+(?:\[\d*\][^\s"=!<>(),|;\[\]{}]*)*')


def tokenize(query):
    tokens, i, text = [], 0, query or ""
    while i < len(text):
        char = text[i]
        if char.isspace():
            i += 1
            continue
        if text.startswith("//", i):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = len(text) if end < 0 else end + 2
            continue
        if char == '"':
            match = _STRING.match(text, i)
            if not match:
                tokens.append(("string", text[i + 1:]))
                break
            # Only \" and \\ are escapes. Other backslashes, as in Windows paths, are literal.
            tokens.append(("string", re.sub(r'\\(["\\])', r"\1", match.group()[1:-1])))
            i = match.end()
            continue
        previous = tokens[-1][1] if tokens else "|"
        if char == "/" and previous in {"=", "!=", "(", ",", "|", "and", "or", "not", "!", "=~"}:
            match = _REGEX.match(text, i)
            if match:
                body, _, flags = match.group()[1:].rpartition("/")
                tokens.append(("regex", (body, flags)))
                i = match.end()
                continue
        op = next((o for o in _OPS if text.startswith(o, i)), None)
        if op:
            tokens.append(("op", op))
            i += len(op)
            continue
        match = _WORD.match(text, i)
        if not match:
            tokens.append(("word", char))
            i += 1
            continue
        word = match.group()
        tokens.append(("keyword" if word.lower() in {"and", "or", "not"} else "word", word))
        i = match.end()
    return tokens


def split_stages(tokens):
    stages, current, depth = [], [], 0
    for token in tokens:
        if token == ("op", "(") or token == ("op", "[") or token == ("op", "{"):
            depth += 1
        elif token in (("op", ")"), ("op", "]"), ("op", "}")):
            depth -= 1
        if token == ("op", "|") and depth == 0:
            stages.append(current)
            current = []
        else:
            current.append(token)
    stages.append(current)
    return [stage for stage in stages if stage]


# ---------------------------------------------------------------- parsing filter expressions

class _Parser:
    def __init__(self, tokens):
        self.tokens, self.i = tokens, 0

    def peek(self, offset=0):
        index = self.i + offset
        return self.tokens[index] if index < len(self.tokens) else (None, None)

    def take(self):
        token = self.peek()
        self.i += 1
        return token

    def parse(self):
        node = self.parse_or()
        if self.i < len(self.tokens):
            return ("and", [node, ("unsupported", " ".join(str(t[1]) for t in self.tokens[self.i:]))])
        return node

    def parse_or(self):
        items = [self.parse_and()]
        while self.peek() == ("keyword", "or") or (self.peek()[0] == "keyword" and str(self.peek()[1]).lower() == "or"):
            self.take()
            items.append(self.parse_and())
        return items[0] if len(items) == 1 else ("or", items)

    def parse_and(self):
        items = [self.parse_unary()]
        while self.i < len(self.tokens):
            kind, value = self.peek()
            if kind == "keyword" and value.lower() == "and":
                self.take()
            elif kind == "keyword" and value.lower() == "or" or value == ")":
                break
            items.append(self.parse_unary())
        return items[0] if len(items) == 1 else ("and", items)

    def parse_unary(self):
        kind, value = self.peek()
        if (kind == "keyword" and value.lower() == "not") or (kind, value) == ("op", "!"):
            self.take()
            return ("not", self.parse_unary())
        return self.parse_primary()

    def parse_value(self):
        if self.peek()[0] == "word" and self.peek(1) == ("op", "("):
            return self.parse_call(self.take()[1])
        kind, value = self.take()
        if kind == "op" and value == "[":
            values = []
            while self.peek()[0] is not None and self.peek()[1] != "]":
                item_kind, item = self.take()
                if item != ",":
                    values.append(item)
            self.take()
            return ("list", values)
        return (kind, value)

    def parse_call(self, name):
        self.take()  # (
        positional, named = [], {}
        while self.peek()[0] is not None and self.peek()[1] != ")":
            if self.peek()[0] == "word" and self.peek(1) == ("op", "="):
                key = self.take()[1]
                self.take()
                named[key.lower()] = self.parse_value()
            elif self.peek() == ("op", ","):
                self.take()
            else:
                positional.append(self.parse_value())
        self.take()  # )
        return ("call", name.lower(), positional, named)

    def parse_primary(self):
        kind, value = self.peek()
        if (kind, value) == ("op", "("):
            self.take()
            node = self.parse_or()
            if self.peek() == ("op", ")"):
                self.take()
            return node
        if kind == "word" and self.peek(1) == ("op", "("):
            self.take()
            return self.parse_call(value)
        if kind in ("word", "string") and self.peek(1)[0] == "op" and self.peek(1)[1] in {"=", "!=", "<", ">", "<=", ">=", "==", "=~"}:
            self.take()
            op = self.take()[1]
            if op == "=~":
                name_kind, name = self.peek()
                if name_kind == "word" and self.peek(1) == ("op", "("):
                    self.take()
                    return ("matchcall", value, self.parse_call(name))
                return ("unsupported", f"{value} =~ {name}")
            return ("cmp", value, "=" if op == "==" else op, self.parse_value())
        self.take()
        if kind in ("string", "word"):
            return ("text", value)
        if kind == "regex":
            return ("textregex", value)
        return ("unsupported", str(value))


# ---------------------------------------------------------------- reading a whole rule

def _stage_head(stage):
    kind, value = stage[0]
    if kind == "word" and len(stage) > 1 and stage[1] == ("op", "("):
        return value.lower()
    return None


def _is_assignment(stage):
    """A stage like `name := value`, not one with := somewhere inside a function's arguments."""
    return len(stage) > 1 and stage[1] == ("op", ":=")


def _call_args(stage):
    node = _Parser(stage).parse_primary()
    return node if node[0] == "call" else None


def _parse_case(stage, rule):
    """A case statement passes an event if any branch does, so it is an or of its branches."""
    inner = stage[2:-1] if stage[-1] == ("op", "}") else stage[2:]
    branches, current, depth = [], [], 0
    for token in inner:
        if token in (("op", "("), ("op", "["), ("op", "{")):
            depth += 1
        elif token in (("op", ")"), ("op", "]"), ("op", "}")):
            depth -= 1
        if token == ("op", ";") and depth == 0:
            branches.append(current)
            current = []
        else:
            current.append(token)
    branches.append(current)
    nodes = []
    for branch in branches:
        if not branch:
            continue
        if branch == [("word", "*")]:
            nodes.append(("true",))
            continue
        parts = []
        for sub in split_stages(branch):
            head = _stage_head(sub)
            if sub[0] == ("word", "case") and len(sub) > 1 and sub[1] == ("op", "{"):
                parts.append(_parse_case(sub, rule))
            elif _is_assignment(sub):
                rule.stages.append(("assign", sub[0][1]))
            elif head in UNSUPPORTED:
                parts.append(("unsupported", head))
            elif head in AGGREGATES or head in PASSTHROUGH:
                continue
            else:
                parts.append(_Parser(sub).parse())
        nodes.append(("and", parts) if parts else ("true",))
    return ("or", nodes) if nodes else ("true",)


def parse_rule(query):
    """Read a rule's query into filter stages and an event-count threshold."""
    rule = Rule(stages=[])
    tokens = tokenize(query)
    # Rules over Falcon sensor telemetry can't be triggered by a third-party log.
    for i, (kind, value) in enumerate(tokens):
        if kind == "word" and value in {"#event_simpleName", "event_simpleName"}:
            rule.endpoint_only = True
        if (kind == "word" and value == "#repo" and i + 2 < len(tokens) and tokens[i + 1] == ("op", "=")
                and tokens[i + 2][1] in {"base_sensor", "detections"}):
            rule.endpoint_only = True

    aggregated, outputs = False, {"_count"}
    for stage in split_stages(tokens):
        head = _stage_head(stage)
        if stage[0] == ("word", "case") and len(stage) > 1 and stage[1] == ("op", "{"):
            if aggregated:
                rule.unsupported.append("case after aggregation")
            else:
                rule.stages.append(("filter", _parse_case(stage, rule)))
            continue
        if _is_assignment(stage) and head not in UNSUPPORTED:
            target = stage[0][1]
            if not aggregated:
                rule.stages.append(("assign", target))
            continue
        if head in UNSUPPORTED:
            rule.unsupported.append(head)
            continue
        if head in AGGREGATES:
            aggregated = True
            call = _call_args(stage)
            if call:
                _, name, positional, named = call
                function = named.get("function")
                inner = function if function and function[0] == "call" else call
                inner_named = inner[3] if inner and inner[0] == "call" else named
                alias = inner_named.get("as")
                if alias:
                    outputs.add(str(alias[1]))
                if (inner_named.get("distinct") or ("", ""))[1] == "true" and inner[2]:
                    rule.distinct_field = str(inner[2][0][1])
            continue
        if head in PASSTHROUGH:
            continue
        node = _Parser(stage).parse()
        if aggregated:
            threshold = _threshold(node, outputs)
            if threshold:
                rule.threshold = max(rule.threshold, threshold)
            else:
                rule.unsupported.append("filter after aggregation")
            continue
        rule.stages.append(("filter", node))
    return rule


def _threshold(node, outputs):
    if node[0] != "cmp" or node[1] not in outputs:
        return None
    try:
        number = float(node[3][1])
    except (TypeError, ValueError):
        return None
    op = node[2]
    if op == ">":
        return int(number) + 1
    if op in (">=", "="):
        return int(number)
    return None


# ---------------------------------------------------------------- evaluating against one event

def _glob(pattern, value):
    return fnmatch.fnmatchcase(value, pattern)


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compare(op, actual, expected_kind, expected):
    if expected_kind == "regex":
        body, flags = expected
        re_flags = (re.I if "i" in flags else 0) | (re.M if "m" in flags else 0) | (re.S if "s" in flags else 0)
        try:
            found = re.search(body, actual, re_flags) is not None
        except re.error:
            return UNKNOWN
        return found if op == "=" else not found
    if op in ("<", ">", "<=", ">="):
        a, e = _number(actual), _number(expected)
        if a is None or e is None:
            return UNKNOWN
        return {"<": a < e, ">": a > e, "<=": a <= e, ">=": a >= e}[op]
    equal = _glob(str(expected), actual) if "*" in str(expected) else actual == str(expected)
    return equal if op == "=" else not equal


class Evaluator:
    def __init__(self, view, computed=()):
        self.view = view
        self.computed = set(computed)
        self.conditions = []
        self.unsupported = []

    def run(self, node):
        kind = node[0]
        if kind == "true":
            return TRUE
        if kind == "and":
            results = [self.run(child) for child in node[1]]
            if FALSE in results:
                return FALSE
            return UNKNOWN if UNKNOWN in results else TRUE
        if kind == "or":
            # Keep only the conditions of the branch closest to passing, so suggestions don't
            # ask for changes to a branch that isn't needed.
            results, branches = [], []
            for child in node[1]:
                before = len(self.conditions)
                results.append(self.run(child))
                branches.append(self.conditions[before:])
                del self.conditions[before:]
            rank = lambda i: (results[i] is not TRUE, results[i] is FALSE,
                              sum(c.state is FALSE for c in branches[i]), sum(c.state is UNKNOWN for c in branches[i]))
            self.conditions.extend(branches[min(range(len(results)), key=rank)] if results else [])
            if TRUE in results:
                return TRUE
            return UNKNOWN if UNKNOWN in results else FALSE
        if kind == "not":
            result = self.run(node[1])
            return UNKNOWN if result is UNKNOWN else not result
        if kind == "cmp":
            return self.compare(node[1], node[2], node[3])
        if kind == "call":
            return self.call(node)
        if kind == "matchcall":
            return self.match_call(node[1], node[2])
        if kind == "text":
            found = str(node[1]).lower() in self.view.rawstring.lower() if "*" not in str(node[1]) else _glob(f"*{node[1]}*", self.view.rawstring)
            self.conditions.append(Condition("@rawstring", "contains", str(node[1]), found, None, "raw text",
                                             "" if found else f'Include the text "{node[1]}" in the log.'))
            return found
        if kind == "textregex":
            body, flags = node[1]
            result = _compare("=", self.view.rawstring, "regex", node[1])
            self.conditions.append(Condition("@rawstring", "matches", f"/{body}/{flags}", result, None, "raw text",
                                             "" if result else f"Include text matching /{body}/{flags} in the log."))
            return result
        self.unsupported.append(str(node[1]))
        return UNKNOWN

    def record(self, name, op, expected_text, state, actual, basis, suggestion=""):
        self.conditions.append(Condition(name, op, expected_text, state, actual, basis, suggestion))
        return state

    def compare(self, name, op, value):
        if len(value) != 2:
            return self.record(name, op, "a computed value", UNKNOWN, None, "computed by the rule")
        value_kind, expected = value
        expected_text = f"/{expected[0]}/{expected[1]}" if value_kind == "regex" else str(expected)
        if name in self.computed:
            return self.record(name, op, expected_text, UNKNOWN, None, "computed by the rule")
        found = self.view.lookup(name, op, expected if value_kind != "regex" else None)
        if found.state is not None:
            return self.record(name, op, expected_text, found.state, found.value, found.basis, found.note)
        if found.value is None:
            state = UNKNOWN if found.basis == "unmapped" else FALSE
            if op == "!=" and found.basis != "unmapped":
                state = TRUE
            suggestion = "" if state is TRUE else self.view.suggest_missing(name, op, value_kind, expected, found.basis)
            return self.record(name, op, expected_text, state, None, found.basis or "missing", suggestion)
        result = _compare(op, found.value, value_kind, expected)
        suggestion = "" if result is not FALSE else self.view.suggest_value(name, op, value_kind, expected, found)
        return self.record(name, op, expected_text, result, found.value, found.basis, suggestion)

    def _values(self, arg):
        if arg is None:
            return []
        kind, value = arg
        return [str(v) for v in value] if kind == "list" else [str(value)]

    def call(self, node):
        _, name, positional, named = node
        target = named.get("field") or (positional[0] if positional else None)
        field_name = str(target[1]) if target else ""
        if name == "in":
            values = self._values(named.get("values"))
            found = self.view.lookup(field_name, "=", values[0] if values else None)
            ignore = (named.get("ignorecase") or ("", ""))[1] == "true"
            if found.value is None:
                return self.record(field_name, "in", ", ".join(values), FALSE if found.basis != "unmapped" else UNKNOWN,
                                   None, found.basis or "missing",
                                   self.view.suggest_missing(field_name, "=", "string", values[0] if values else "", found.basis))
            actual = found.value.lower() if ignore else found.value
            result = any(_glob(v.lower() if ignore else v, actual) for v in values)
            return self.record(field_name, "in", ", ".join(values), result, found.value, found.basis,
                               "" if result else f'Set {self.view.raw_name(field_name)} to one of: {", ".join(values)}.')
        if name == "cidr":
            subnets = self._values(named.get("subnet"))
            found = self.view.lookup(field_name, "=", None)
            if found.value is None:
                return self.record(field_name, "cidr", ", ".join(subnets), UNKNOWN if found.basis == "unmapped" else FALSE,
                                   None, found.basis or "missing")
            try:
                address = ipaddress.ip_address(found.value)
                result = any(address in ipaddress.ip_network(s, strict=False) for s in subnets)
            except ValueError:
                result = UNKNOWN
            return self.record(field_name, "cidr", ", ".join(subnets), result, found.value, found.basis)
        if name == "regex":
            pattern = positional[0][1] if positional else (named.get("regex") or ("", ""))[1]
            found = self.view.lookup(field_name or "@rawstring", "=", None)
            if found.value is None:
                return self.record(field_name or "@rawstring", "regex", str(pattern), UNKNOWN, None, found.basis)
            flags = (named.get("flags") or ("", ""))[1]
            result = _compare("=", found.value, "regex", (str(pattern), str(flags)))
            return self.record(field_name or "@rawstring", "regex", str(pattern), result, found.value, found.basis)
        if name == "array:contains":
            array = str((named.get("array") or ("", ""))[1])
            wanted = str((named.get("value") or ("", ""))[1])
            values, basis = self.view.array_values(array)
            if values is None:
                return self.record(array, "contains", wanted, UNKNOWN, None, basis or "set by the parser")
            found = wanted in values
            return self.record(array, "contains", wanted, found, ", ".join(values), basis,
                               "" if found else f'The parser would need to put "{wanted}" in {array}.')
        self.unsupported.append(f"{name}()")
        return UNKNOWN

    def match_call(self, name, call):
        _, function, positional, named = call
        if function == "wildcard":
            pattern = str((named.get("pattern") or (positional[0] if positional else ("", "")))[1])
            ignore = (named.get("ignorecase") or ("", ""))[1] == "true"
            found = self.view.lookup(name, "=", None)
            if found.value is None:
                return self.record(name, "wildcard", pattern, FALSE if found.basis != "unmapped" else UNKNOWN, None, found.basis or "missing")
            actual, wanted = (found.value.lower(), pattern.lower()) if ignore else (found.value, pattern)
            return self.record(name, "wildcard", pattern, _glob(wanted, actual), found.value, found.basis)
        if function == "in":
            return self.call(("call", "in", [("word", name)], named))
        self.unsupported.append(f"{name} =~ {function}()")
        return UNKNOWN


def closest(name, candidates):
    match = difflib.get_close_matches(name, candidates, n=1, cutoff=0.8)
    return match[0] if match else None
