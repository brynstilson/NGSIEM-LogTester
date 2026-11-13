"""Simulates an NG-SIEM parser: runs its script on a raw log to predict the parsed event.

It interprets the parts of the CrowdStrike Query Language that parsers use: case and match blocks,
filters, := assignments and the common functions (parseJson, kvParse, parseCEF, parseCsv, parseXml,
replace, regex, lower, coalesce, format, splitString, array and objectArray functions, and more).

Anything it can't reproduce, such as lookup files or an unknown function, is recorded, and the
fields it would have set are marked unknown rather than guessed. A filter that depends on an
unknown value is treated as passing, and the result is flagged as approximate.
"""
import base64
import csv
import fnmatch
import hashlib
import io
import ipaddress
import json
import math
import re
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field as dc_field

import regex as rx

UNKNOWN = object()          # A value the simulator can't know.
REGEX_TIMEOUT = 0.25        # seconds; a runaway pattern is treated as unknown.
MAX_STEPS = 20000           # Guards against pathological scripts.


class SimError(Exception):
    pass


# ---------------------------------------------------------------- tokenizer

_OPS = ["=>", ":=", "!=", "<=", ">=", "==", "=~", "&&", "||", "=", "<", ">", "!", "(", ")", "[", "]",
        "{", "}", ",", "|", ";", "+", "-", "*", "/", "%"]
_WORD = re.compile(r"[A-Za-z_@#$*](?:[\w.@#$*]|:(?![=\s]))*(?:\[\d*\](?:[\w.@#$*]|:(?![=\s]))*)*|\d[\w.]*")
_REGEX_AFTER_OPS = {"=", "!=", "==", "(", ",", "|", ";", "{", "[", "!", "=~", "=>", "&&", "||"}
_KEYWORDS = {"and", "or", "not"}


@dataclass
class Tok:
    kind: str     # op, word, string, regex, number
    value: object
    pos: int = 0


def tokenize(text):
    tokens, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c in " \t\r\n":
            i += 1
            continue
        if text.startswith("//", i):  # An empty regex is never used, so // always starts a comment.
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in "\"'":
            j, buf = i + 1, []
            while j < n and text[j] != c:
                if text[j] == "\\" and j + 1 < n:
                    nxt = text[j + 1]
                    buf.append(nxt if nxt in "\"'\\" else "\\" + nxt)
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            tokens.append(Tok("string", "".join(buf), i))
            i = j + 1
            continue
        if c == "/" and _regex_allowed(tokens):
            j, in_class = i + 1, False
            while j < n:
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                elif ch == "\n":
                    break
                j += 1
            body = text[i + 1:j]
            k = j + 1
            while k < n and text[k].isalpha():
                k += 1
            tokens.append(Tok("regex", (body, text[j + 1:k]), i))
            i = k
            continue
        if c == "*" and i + 1 < n and (text[i + 1].isalnum() or text[i + 1] in "_.@") and _regex_allowed(tokens):
            m = _WORD.match(text, i)
            tokens.append(Tok("word", m.group(0), i))
            i = m.end()
            continue
        m = _WORD.match(text, i) if (c.isalnum() or c in "_@#$") else None
        if m:
            word = m.group(0)
            kind = "number" if re.fullmatch(r"-?\d+(\.\d+)?", word) else "word"
            tokens.append(Tok(kind, word, i))
            i = m.end()
            continue
        for op in _OPS:
            if text.startswith(op, i):
                tokens.append(Tok("op", op, i))
                i += len(op)
                break
        else:
            i += 1  # Skip a character the language doesn't use.
    return tokens


def _regex_allowed(tokens):
    if not tokens:
        return True
    last = tokens[-1]
    if last.kind == "op":
        return last.value in _REGEX_AFTER_OPS
    if last.kind == "word" and last.value.lower() in _KEYWORDS:
        return True
    return False


# ---------------------------------------------------------------- parser (to tuples)

class _Parser:
    def __init__(self, tokens):
        self.t, self.i = tokens, 0

    def peek(self, k=0):
        j = self.i + k
        return self.t[j] if j < len(self.t) else Tok("eof", None)

    def is_op(self, value, k=0):
        tok = self.peek(k)
        return tok.kind == "op" and tok.value == value

    def is_word(self, value=None, k=0):
        tok = self.peek(k)
        return tok.kind == "word" and (value is None or tok.value.lower() == value)

    def take(self):
        tok = self.peek()
        self.i += 1
        return tok

    def expect(self, value):
        tok = self.take()
        if not (tok.kind == "op" and tok.value == value):
            raise SimError(f"expected {value!r} at {tok.pos}, found {tok.value!r}")
        return tok

    # pipeline: stage ('|' stage)*, ending at ';', '}' or end of input
    def pipeline(self):
        stages = []
        while True:
            while self.is_op("|"):
                self.take()
            tok = self.peek()
            if tok.kind == "eof" or (tok.kind == "op" and tok.value in (";", "}", ")")):
                return stages
            stages.append(self.stage())
            if not (self.is_op("|") or self.peek().kind == "eof" or self.is_op(";") or self.is_op("}") or self.is_op(")")):
                # Two stages without a pipe, as the language allows for filters on one line.
                continue

    def stage(self):
        if self.is_word("case") and self.is_op("{", 1):
            self.take()
            return self.case_block()
        if self.peek().kind in ("word", "string") and self.is_word("match", 1) and self.is_op("{", 2):
            name = self.take().value
            self.take()
            return self.match_block(name)
        if self.peek().kind == "word" and self.is_op(":=", 1):
            target = self.take().value
            self.take()
            return ("assign", target, self.expr())
        if self.peek().kind == "word" and self.is_op("=~", 1) and self.peek(2).kind == "word" and self.is_op("(", 3):
            name = self.take().value
            self.take()
            call = self.call(self.take().value)
            return ("apply", name, call)
        return ("filter", self.filter_or())

    def case_block(self):
        self.expect("{")
        branches = []
        while not self.is_op("}"):
            if self.peek().kind == "eof":
                raise SimError("unclosed case")
            branches.append(self.pipeline())
            if self.is_op(";"):
                self.take()
        self.expect("}")
        return ("case", branches)

    def match_block(self, name):
        self.expect("{")
        arms = []
        while not self.is_op("}"):
            if self.peek().kind == "eof":
                raise SimError("unclosed match")
            negate = False
            if self.is_op("!"):
                self.take()
                negate = True
            tok = self.peek()
            if tok.kind == "word" and self.is_op("(", 1):
                pattern = ("call", self.call(self.take().value))
            elif tok.kind == "op" and tok.value == "*":
                self.take()
                pattern = ("any",)
            else:
                self.take()
                pattern = (tok.kind, tok.value)
            if negate:
                pattern = ("not", pattern)
            self.expect("=>")
            if self.is_op("*") and (self.is_op(";", 1) or self.is_op("}", 1)):
                self.take()
                body = []
            else:
                body = self.pipeline()
            arms.append((pattern, body))
            if self.is_op(";"):
                self.take()
        self.expect("}")
        return ("match", name, arms)

    # filters
    def filter_or(self):
        node = self.filter_and()
        parts = [node]
        while self.is_word("or") or self.is_op("||"):
            self.take()
            parts.append(self.filter_and())
        return parts[0] if len(parts) == 1 else ("or", parts)

    def _filter_continues(self):
        tok = self.peek()
        if tok.kind == "eof":
            return False
        if tok.kind == "op" and tok.value in ("|", ";", "}", ")", "=>", "]", ","):
            return False
        if tok.kind == "word" and tok.value.lower() == "or":
            return False
        if tok.kind == "op" and tok.value == "||":
            return False
        return True

    def filter_and(self):
        parts = [self.filter_unary()]
        while self._filter_continues():
            if self.is_word("and") or self.is_op("&&"):
                self.take()
            parts.append(self.filter_unary())
        return parts[0] if len(parts) == 1 else ("and", parts)

    def filter_unary(self):
        if self.is_word("not") or self.is_op("!"):
            self.take()
            return ("not", self.filter_unary())
        if self.is_op("("):
            self.take()
            node = self.filter_or()
            self.expect(")")
            return node
        tok = self.peek()
        if tok.kind == "op" and tok.value == "*":
            self.take()
            return ("true",)
        if tok.kind == "regex":
            self.take()
            return ("cmp", "@rawstring", "=", ("regex", tok.value))
        if tok.kind == "string":
            nxt = self.peek(1)
            if nxt.kind == "op" and nxt.value in ("=", "!=", "<", ">", "<=", ">=", "=="):
                self.take()
                op = self.take().value
                return ("cmp", tok.value, "=" if op == "==" else op, self.filter_value())
            self.take()
            return ("text", tok.value)
        if tok.kind in ("word", "number"):
            if self.is_op("(", 1) and tok.kind == "word":
                self.take()
                return ("call", self.call(tok.value))
            nxt = self.peek(1)
            if nxt.kind == "op" and nxt.value in ("=", "!=", "<", ">", "<=", ">=", "=="):
                self.take()
                op = self.take().value
                op = "=" if op == "==" else op
                return ("cmp", tok.value, op, self.filter_value())
            if nxt.kind == "op" and nxt.value == "=~":
                self.take()
                self.take()
                if self.peek().kind == "regex":
                    return ("cmp", tok.value, "=", ("regex", self.take().value))
                negate = self.is_op("!")
                if negate:
                    self.take()
                name = self.take().value
                node = ("apply", tok.value, self.call(name))
                return ("not", node) if negate else node
            self.take()
            return ("text", tok.value)
        raise SimError(f"unexpected {tok.value!r} at {tok.pos}")

    def filter_value(self):
        tok = self.take()
        if tok.kind == "op" and tok.value == "*":
            return ("any",)
        if tok.kind == "op" and tok.value == "-" and self.peek().kind == "number":
            return ("number", "-" + self.take().value)
        if tok.kind in ("word", "number"):
            text, end = str(tok.value), tok.pos + len(str(tok.value))
            # Unquoted values such as asm-botdefense arrive as several tokens with no space between.
            while self.is_op("-") and self.peek().pos == end and self.peek(1).kind in ("word", "number") and self.peek(1).pos == end + 1:
                self.take()
                part = self.take()
                text += "-" + str(part.value)
                end = part.pos + len(str(part.value))
            return ("word", text)
        if tok.kind in ("string", "regex"):
            return (tok.kind, tok.value)
        raise SimError(f"bad value {tok.value!r} at {tok.pos}")

    # function calls and expressions
    def call(self, name):
        self.expect("(")
        positional, named = [], {}
        while not self.is_op(")"):
            if self.peek().kind == "eof":
                raise SimError(f"unclosed call {name}")
            if self.peek().kind == "word" and self.is_op("=", 1) and not self.is_op("=", 2):
                key = self.take().value.lower()
                self.take()
                named[key] = self.arg_value()
            else:
                positional.append(self.arg_value())
            if self.is_op(","):
                self.take()
        self.expect(")")
        return (name.lower(), positional, named)

    def arg_value(self):
        if self.is_op("{"):
            self.take()
            body = self.pipeline()
            self.expect("}")
            return ("block", body)
        if self.is_op("*") and (self.is_op(",", 1) or self.is_op(")", 1)):
            self.take()
            return ("any",)
        return self.expr()

    def expr(self):
        return self.expr_or()

    def expr_or(self):
        node = self.expr_and()
        while self.is_op("||") or self.is_word("or"):
            self.take()
            node = ("bool", "or", node, self.expr_and())
        return node

    def expr_and(self):
        node = self.expr_cmp()
        while self.is_op("&&") or self.is_word("and"):
            self.take()
            node = ("bool", "and", node, self.expr_cmp())
        return node

    def expr_cmp(self):
        node = self.expr_add()
        while self.peek().kind == "op" and self.peek().value in ("==", "!=", "<", ">", "<=", ">=", "="):
            op = self.take().value
            if self.is_op("*") and (self.is_op(",", 1) or self.is_op(")", 1)):
                self.take()
                node = ("exists", node, op)
                continue
            node = ("compare", "==" if op == "=" else op, node, self.expr_add())
        return node

    def expr_add(self):
        node = self.expr_mul()
        while self.is_op("+") or self.is_op("-"):
            op = self.take().value
            node = ("arith", op, node, self.expr_mul())
        return node

    def expr_mul(self):
        node = self.expr_unary()
        while (self.is_op("*") or self.is_op("/") or self.is_op("%")) and not (self.is_op(",", 1) or self.is_op(")", 1)):
            op = self.take().value
            node = ("arith", op, node, self.expr_unary())
        return node

    def expr_unary(self):
        if self.is_op("!") or self.is_word("not"):
            self.take()
            return ("neg", self.expr_unary())
        if self.is_op("-"):
            self.take()
            return ("arith", "-", ("lit", "0"), self.expr_unary())
        return self.expr_primary()

    def expr_primary(self):
        tok = self.peek()
        if tok.kind == "op" and tok.value == "(":
            self.take()
            node = self.expr()
            self.expect(")")
            return node
        if tok.kind == "op" and tok.value == "[":
            self.take()
            items = []
            while not self.is_op("]"):
                if self.peek().kind == "eof":
                    raise SimError("unclosed list")
                if self.is_op("["):
                    items.append(self.expr_primary())
                else:
                    items.append(self.expr())
                if self.is_op(","):
                    self.take()
            self.expect("]")
            return ("list", items)
        if tok.kind == "op" and tok.value == "*":
            self.take()
            return ("any",)
        self.take()
        if tok.kind == "string":
            return ("lit", tok.value)
        if tok.kind == "number":
            return ("lit", tok.value)
        if tok.kind == "regex":
            return ("regexlit", tok.value)
        if tok.kind == "word":
            if self.is_op("("):
                return ("callx", self.call(tok.value))
            if tok.value.lower() in ("true", "false"):
                return ("lit", tok.value.lower())
            return ("ref", tok.value)
        raise SimError(f"unexpected {tok.value!r} at {tok.pos}")


def parse_script(text):
    """The parser script as a list of stages. Raises SimError on syntax it can't read."""
    parser = _Parser(tokenize(text))
    stages = parser.pipeline()
    if parser.peek().kind != "eof":
        raise SimError(f"unexpected {parser.peek().value!r} at {parser.peek().pos}")
    return stages


# ---------------------------------------------------------------- regular expressions

_GROUP = re.compile(r"\(\?<(?![=!])([^>]+)>")
_regex_cache = {}


def compile_regex(body, flags=""):
    """Compile a LogScale (Java-style) pattern. Returns (compiled, {python group: field name})."""
    key = (body, flags)
    if key in _regex_cache:
        return _regex_cache[key]
    names = {}

    def rename(match):
        alias = f"g{len(names)}"
        names[alias] = match.group(1)
        return f"(?P<{alias}>"

    pattern = _GROUP.sub(rename, body)
    pattern = re.sub(r"\\Q(.*?)(\\E|$)", lambda m: re.escape(m.group(1)), pattern)
    pattern = pattern.replace("\\h", "[ \\t]")
    f = rx.V0
    if "i" in flags:
        f |= rx.IGNORECASE
    if "m" in flags:
        f |= rx.MULTILINE
    if "s" in flags:
        f |= rx.DOTALL
    try:
        compiled = rx.compile(pattern, f)
    except Exception:
        compiled = None
    _regex_cache[key] = (compiled, names)
    return compiled, names


def regex_search(body, flags, text):
    """(matched, {field: value}) or (UNKNOWN, {}) if the pattern can't be run."""
    compiled, names = compile_regex(body, flags)
    if compiled is None:
        return UNKNOWN, {}
    try:
        m = compiled.search(text, timeout=REGEX_TIMEOUT)
    except TimeoutError:
        return UNKNOWN, {}
    if not m:
        return False, {}
    return True, {names[k]: v for k, v in m.groupdict().items() if v is not None and k in names}


def java_replacement(text):
    text = re.sub(r"\$\{(\w+)\}", r"\\g<\1>", text)
    text = re.sub(r"\$(\d+)", r"\\g<\1>", text)
    return text


# ---------------------------------------------------------------- the simulated event

@dataclass
class Result:
    fields: dict
    dropped: bool = False
    unknown: set = dc_field(default_factory=set)        # fields whose values can't be known
    unsupported: list = dc_field(default_factory=list)  # functions or syntax that weren't simulated
    uncertain: list = dc_field(default_factory=list)    # filters decided on unknown values
    error: str = ""
    tag_fields: list = dc_field(default_factory=list)

    @property
    def approximate(self):
        return bool(self.unknown or self.unsupported or self.uncertain or self.error)

    def tags(self):
        return {f"#{name}": self.fields[name] for name in self.tag_fields if name in self.fields}


class _Event:
    def __init__(self, fields, unknown=None, notes=None):
        self.fields = fields
        self.unknown = unknown if unknown is not None else set()
        self.notes = notes if notes is not None else {"unsupported": [], "uncertain": []}
        self.scope = {}

    def copy(self):
        clone = _Event(dict(self.fields), set(self.unknown), self.notes)
        clone.scope = dict(self.scope)
        return clone

    def get(self, name):
        name = _field(name)
        bound = self._scoped(name)
        if bound is not None:
            return bound
        if name in self.unknown:
            return UNKNOWN
        return self.fields.get(name)

    def _scoped(self, name):
        for var, (array, index) in self.scope.items():
            if name == var:
                if array is None:
                    return index  # a bound scalar value
                return self.fields.get(f"{array}[{index}]")
            if name.startswith(var + "."):
                if array is None:
                    return None
                return self.fields.get(f"{array}[{index}].{name[len(var) + 1:]}")
        return None

    def set(self, name, value):
        name = _field(name)
        if value is UNKNOWN:
            self.fields.pop(name, None)
            self.unknown.add(name)
            return
        self.unknown.discard(name)
        if value is None:
            return
        if isinstance(value, list):
            base = name[:-2] if name.endswith("[]") else name
            self.drop_array(base)
            for i, item in enumerate(value):
                self.set(f"{base}[{i}]", item)
            return
        self.fields[name] = str(value)

    def drop(self, name):
        name = _field(name)
        if name.endswith("[]"):
            self.drop_array(name[:-2])
            return
        self.fields.pop(name, None)
        self.unknown.discard(name)
        prefix = name + "."
        for key in [k for k in self.fields if k.startswith(prefix)]:
            del self.fields[key]

    def array(self, base):
        """Scalar elements of base[] in order."""
        base = _field(base)
        base = base[:-2] if base.endswith("[]") else base
        items = []
        i = 0
        while f"{base}[{i}]" in self.fields:
            items.append(self.fields[f"{base}[{i}]"])
            i += 1
        return items

    def array_length(self, base):
        base = _field(base)
        base = base[:-2] if base.endswith("[]") else base
        pattern = re.compile(re.escape(base) + r"\[(\d+)\]")
        indexes = [int(m.group(1)) for k in self.fields for m in [pattern.match(k)] if m]
        return max(indexes) + 1 if indexes else 0

    def drop_array(self, base):
        pattern = re.compile(re.escape(base) + r"\[\d+\]")
        for key in [k for k in self.fields if pattern.match(k)]:
            del self.fields[key]


def _field(name):
    name = str(name)
    return name[1:] if name.startswith("#") else name


def _glob(pattern, value, ignore_case=False):
    if ignore_case:
        pattern, value = pattern.lower(), value.lower()
    return fnmatch.fnmatchcase(value, pattern)


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _str(value):
    if value is None or value is UNKNOWN:
        return value
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


# ---------------------------------------------------------------- interpreter

class Simulator:
    def __init__(self, script):
        self.stages = parse_script(script)
        self.steps = 0

    def run(self, rawstring, tag_fields=()):
        event = _Event({"@rawstring": rawstring})
        result = Result(fields={}, tag_fields=list(tag_fields))
        self.steps = 0
        try:
            out = self.pipeline(self.stages, event)
        except SimError as exc:
            result.error = str(exc)
            out = event
        result.dropped = out is None
        final = out or event
        result.fields = dict(final.fields)
        result.unknown = set(final.unknown)
        result.unsupported = sorted(set(event.notes["unsupported"]))
        result.uncertain = sorted(set(event.notes["uncertain"]))
        return result

    def tick(self):
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise SimError("too many steps")

    def note(self, ev, kind, text):
        ev.notes[kind].append(text)

    # A pipeline returns the event, or None if it was dropped.
    def pipeline(self, stages, ev):
        for stage in stages:
            self.tick()
            ev = self.stage(stage, ev)
            if ev is None:
                return None
        return ev

    def stage(self, stage, ev):
        kind = stage[0]
        if kind == "assign":
            ev.set(stage[1], self.value(stage[2], ev, target=stage[1]))
            return ev
        if kind == "apply":
            name, call = stage[1], stage[2]
            fname, positional, named = call
            named = dict(named)
            named.setdefault("field", ("ref", name))
            if fname in ("in", "cidr", "wildcard", "regex"):
                result = self.filter(("call", (fname, positional, named)), ev)
                return self._filtered(result, ev, f"{name} =~ {fname}()")
            return self.call_stage((fname, positional, named), ev)
        if kind == "case":
            for branch in stage[1]:
                out = self.pipeline(branch, ev.copy())
                if out is not None:
                    return out
            return None
        if kind == "match":
            return self.match(stage, ev)
        if kind == "filter":
            node = stage[1]
            if node[0] == "call":
                return self.call_stage(node[1], ev)
            return self._filtered(self.filter(node, ev), ev, "a filter")
        raise SimError(f"unknown stage {kind}")

    def _filtered(self, result, ev, what):
        if result is UNKNOWN:
            self.note(ev, "uncertain", what)
            return ev
        return ev if result else None

    def match(self, stage, ev):
        _, name, arms = stage
        value = ev.get(name)
        for pattern, body in arms:
            kind = pattern[0]
            if kind == "any":
                hit = True
            elif value is None:
                hit = False
            elif value is UNKNOWN:
                self.note(ev, "uncertain", f"{name} match")
                hit = True
            elif kind == "string" or kind == "word" or kind == "number":
                text = str(pattern[1])
                hit = _glob(text, value) if "*" in text else value == text
            elif kind == "regex":
                hit, captured = regex_search(pattern[1][0], pattern[1][1], value)
                if hit is UNKNOWN:
                    self.note(ev, "uncertain", f"{name} match regex")
                    hit = True
                elif hit:
                    for k, v in captured.items():
                        ev.set(k, v)
            elif kind == "not":
                inner = self.match(("match", name, [(pattern[1], [])]), ev.copy())
                hit = inner is None
            elif kind == "call":
                fname, positional, named = pattern[1]
                named = dict(named)
                named.setdefault("field", ("ref", name))
                hit = self.filter(("call", (fname, positional, named)), ev)
                if hit is UNKNOWN:
                    hit = True
            else:
                hit = False
            if hit:
                return self.pipeline(body, ev)
        return None

    # ---- filters: True, False or UNKNOWN
    def filter(self, node, ev):
        kind = node[0]
        if kind == "true":
            return True
        if kind == "and":
            results = [self.filter(child, ev) for child in node[1]]
            if False in results:
                return False
            return UNKNOWN if UNKNOWN in results else True
        if kind == "or":
            results = []
            for child in node[1]:
                r = self.filter(child, ev)
                if r is True:
                    return True
                results.append(r)
            return UNKNOWN if UNKNOWN in results else False
        if kind == "not":
            r = self.filter(node[1], ev)
            return UNKNOWN if r is UNKNOWN else not r
        if kind == "text":
            raw = ev.get("@rawstring") or ""
            text = str(node[1])
            return _glob(f"*{text}*", raw, True) if "*" in text else text.lower() in raw.lower()
        if kind == "cmp":
            return self.compare(node[1], node[2], node[3], ev)
        if kind == "apply":
            return self.filter(("call", (node[2][0], node[2][1], {**node[2][2], "field": ("ref", node[1])})), ev)
        if kind == "call":
            fname, positional, named = node[1]
            if fname in FILTER_FUNCS:
                return FILTER_FUNCS[fname](self, ev, positional, named)
            out = self.call_stage(node[1], ev)
            return out is not None
        raise SimError(f"unknown filter {kind}")

    def compare(self, name, op, value, ev):
        actual = ev.get(name)
        vkind = value[0]
        if actual is UNKNOWN:
            return UNKNOWN
        if vkind == "any":
            exists = actual is not None
            return exists if op == "=" else not exists
        if actual is None:
            return op == "!="
        if vkind == "regex":
            hit, captured = regex_search(value[1][0], value[1][1], actual)
            if hit is UNKNOWN:
                return UNKNOWN
            if hit and op == "=":
                for k, v in captured.items():
                    ev.set(k, v)
            return hit if op == "=" else not hit
        expected = str(value[1])
        if op in ("<", ">", "<=", ">="):
            a, e = _number(actual), _number(expected)
            if a is None or e is None:
                return False
            return {"<": a < e, ">": a > e, "<=": a <= e, ">=": a >= e}[op]
        equal = _glob(expected, actual) if "*" in expected else actual == expected
        return equal if op == "=" else not equal

    # ---- expressions: a string, a list of strings, None (no value) or UNKNOWN
    def value(self, node, ev, target=None):
        kind = node[0]
        if kind == "lit":
            return node[1]
        if kind == "ref":
            return ev.get(node[1])
        if kind == "any":
            return None
        if kind == "list":
            return [self.value(item, ev) for item in node[1]]
        if kind == "regexlit":
            return node[1][0]
        if kind == "callx":
            return self.call_value(node[1], ev, target)
        if kind == "neg":
            r = self.truth(node[1], ev)
            return UNKNOWN if r is UNKNOWN else ("false" if r else "true")
        if kind in ("compare", "bool", "exists"):
            r = self.truth(node, ev)
            return UNKNOWN if r is UNKNOWN else ("true" if r else "false")
        if kind == "arith":
            a, b = self.value(node[2], ev), self.value(node[3], ev)
            if a is UNKNOWN or b is UNKNOWN:
                return UNKNOWN
            x, y = _number(a), _number(b)
            if x is None or y is None:
                return None
            try:
                return _str({"+": x + y, "-": x - y, "*": x * y, "/": x / y, "%": x % y}[node[1]])
            except ZeroDivisionError:
                return None
        if kind == "block":
            return None
        raise SimError(f"unknown expression {kind}")

    def truth(self, node, ev):
        kind = node[0]
        if kind == "bool":
            a = self.truth(node[2], ev)
            if node[1] == "and":
                if a is False:
                    return False
                b = self.truth(node[3], ev)
                if b is False:
                    return False
                return UNKNOWN if UNKNOWN in (a, b) else True
            if a is True:
                return True
            b = self.truth(node[3], ev)
            if b is True:
                return True
            return UNKNOWN if UNKNOWN in (a, b) else False
        if kind == "neg":
            r = self.truth(node[1], ev)
            return UNKNOWN if r is UNKNOWN else not r
        if kind == "exists":
            v = self.value(node[1], ev)
            if v is UNKNOWN:
                return UNKNOWN
            return (v is not None) if node[2] in ("=", "==") else (v is None)
        if kind == "compare":
            op = node[1]
            a, b = self.value(node[2], ev), self.value(node[3], ev)
            if a is UNKNOWN or b is UNKNOWN:
                return UNKNOWN
            if a is None or b is None:
                return op == "!=" and not (a is None and b is None)
            if op in ("<", ">", "<=", ">="):
                x, y = _number(a), _number(b)
                if x is None or y is None:
                    x, y = str(a), str(b)
                return {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]
            x, y = _number(a), _number(b)
            equal = (x == y) if x is not None and y is not None else str(a) == str(b)
            return equal if op == "==" else not equal
        if kind == "callx":
            fname, positional, named = node[1]
            if fname in FILTER_FUNCS:
                return FILTER_FUNCS[fname](self, ev, positional, named)
        v = self.value(node, ev)
        if v is UNKNOWN:
            return UNKNOWN
        return v not in (None, "", "false", "0")

    # ---- function arguments
    def arg(self, positional, named, key, index=None, default=None):
        if key in named:
            return named[key]
        if index is not None and len(positional) > index:
            return positional[index]
        return default

    def name_of(self, node, default=None):
        """A field name given as a word or a string."""
        if node is None:
            return default
        if node[0] in ("ref", "lit"):
            return str(node[1])
        return default

    def names_of(self, node):
        if node is None:
            return []
        if node[0] == "list":
            out = []
            for item in node[1]:
                out.extend(self.names_of(item))
            return out
        name = self.name_of(node)
        return [name] if name else []

    def text_arg(self, node, ev, default=None):
        if node is None:
            return default
        if node[0] == "lit":
            return str(node[1])
        if node[0] == "ref":
            return str(node[1])
        v = self.value(node, ev)
        return default if v is None or v is UNKNOWN else str(v)

    def bool_arg(self, node, default=False):
        if node is None:
            return default
        return str(node[1]).lower() == "true" if node[0] in ("lit", "ref") else default

    # ---- functions used as stages
    def call_stage(self, call, ev):
        fname = call[0]
        handler = STAGE_FUNCS.get(fname)
        if handler:
            return handler(self, ev, call[1], call[2])
        if fname in FILTER_FUNCS:
            return self._filtered(FILTER_FUNCS[fname](self, ev, call[1], call[2]), ev, f"{fname}()")
        if fname in VALUE_FUNCS:
            out = self.arg(call[1], call[2], "as")
            target = self.name_of(out, f"_{fname.split(':')[-1]}")
            ev.set(target, self.call_value(call, ev, target))
            return ev
        if fname in NOOP_FUNCS:
            return ev
        self.note(ev, "unsupported", f"{fname}()")
        for out in ("as", "asarray", "include"):
            for name in self.names_of(call[2].get(out)):
                ev.set(name, UNKNOWN)
        return ev

    def call_value(self, call, ev, target=None):
        fname, positional, named = call
        handler = VALUE_FUNCS.get(fname)
        if handler:
            return handler(self, ev, positional, named)
        if fname in FILTER_FUNCS:
            r = FILTER_FUNCS[fname](self, ev, positional, named)
            return UNKNOWN if r is UNKNOWN else ("true" if r else "false")
        self.note(ev, "unsupported", f"{fname}()")
        return UNKNOWN

    def run_block(self, block, ev):
        if block is None or block[0] != "block":
            return ev
        return self.pipeline(block[1], ev)


# ---------------------------------------------------------------- function implementations

def _prefix(text):
    if not text:
        return ""
    return text if text.endswith(".") else text + "."


def _flatten_json(value, path, out, exclude_empty, handle_null):
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten_json(v, f"{path}.{k}" if path else str(k), out, exclude_empty, handle_null)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _flatten_json(v, f"{path}[{i}]", out, exclude_empty, handle_null)
    elif value is None:
        if handle_null == "discard":
            return
        out[path] = "" if handle_null == "empty" else "null"
    else:
        text = json.dumps(value) if isinstance(value, bool) else str(value)
        if exclude_empty and text == "":
            return
        out[path] = text


def f_parsejson(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "@rawstring")
    raw = ev.get(source)
    if raw is UNKNOWN:
        sim.note(ev, "uncertain", "parseJson on an unknown field")
        return ev
    if not raw:
        return ev
    try:
        data = json.loads(raw)
    except ValueError:
        ev.set("@error", "true")
        return ev
    prefix = sim.text_arg(sim.arg(p, n, "prefix"), ev, "")
    out = {}
    _flatten_json(data, "", out, sim.bool_arg(n.get("excludeempty")),
                  (sim.text_arg(n.get("handlenull"), ev, "keep") or "keep").lower())
    removes = sim.value(n["removeprefixes"], ev) if "removeprefixes" in n else []
    removes = [str(x) for x in (removes if isinstance(removes, list) else [removes]) if x not in (None, UNKNOWN)]
    for key, val in out.items():
        for r in removes:
            if key.startswith(r):
                key = key[len(r):]
                break
        ev.set(f"{prefix}{key}", val)
    return ev


_KV_PAIR = re.compile(r'([^\s=,;"\']+)\s*=\s*("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^\s,;]*)')


def f_kvparse(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "@rawstring")
    raw = ev.get(source)
    if raw is UNKNOWN:
        sim.note(ev, "uncertain", "kvParse on an unknown field")
        return ev
    if not raw:
        return ev
    prefix = _prefix(sim.text_arg(n.get("as") or n.get("prefix"), ev, ""))
    override = sim.bool_arg(n.get("override"))
    exclude_empty = sim.bool_arg(n.get("excludeempty"))
    separator = sim.text_arg(n.get("separator"), ev, "=")
    pattern = _KV_PAIR if separator == "=" else re.compile(
        r'([^\s' + re.escape(separator) + r',;"\']+)\s*' + re.escape(separator) + r'\s*("(?:[^"\\]|\\.)*"|[^\s,;]*)')
    for key, val in pattern.findall(raw):
        if val[:1] in "\"'" and val[-1:] == val[:1] and len(val) >= 2:
            val = val[1:-1].replace('\\"', '"')
        if exclude_empty and val == "":
            continue
        name = f"{prefix}{key}"
        if not override and ev.get(name) not in (None, UNKNOWN):
            continue
        ev.set(name, val)
    return ev


def f_parsecef(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "@rawstring")
    raw = ev.get(source)
    if not raw or raw is UNKNOWN:
        return ev
    start = raw.find("CEF:")
    if start < 0:
        return ev
    parts, buf, i, text = [], [], 0, raw[start + 4:]
    while i < len(text) and len(parts) < 7:
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            buf.append(text[i + 1])
            i += 2
            continue
        if ch == "|":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    extension = text[i:] if len(parts) == 7 else "".join(buf)
    header = _prefix(sim.text_arg(n.get("headerprefix"), ev, "cef."))
    prefix = _prefix(sim.text_arg(n.get("prefix"), ev, "cef."))
    label_prefix = _prefix(sim.text_arg(n.get("labelprefix"), ev, "cef.label."))
    names = ["version", "device.vendor", "device.product", "device.version", "event_class_id", "name", "severity"]
    for name, val in zip(names, parts):
        ev.set(f"{header}{name}", val)
    pairs = list(re.finditer(r"(\w[\w.\-]*)=", extension))
    values = {}
    for j, m in enumerate(pairs):
        end = pairs[j + 1].start() if j + 1 < len(pairs) else len(extension)
        values[m.group(1)] = extension[m.end():end].strip().replace("\\=", "=")
    labels = {k[:-5]: v for k, v in values.items() if k.endswith("Label")}
    for key, val in values.items():
        if key.endswith("Label"):
            continue
        ev.set(f"{prefix}{key}", val)
        if key in labels:
            ev.set(f"{label_prefix}{labels[key]}", val)
    return ev


def f_parsecsv(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "@rawstring")
    raw = ev.get(source)
    if not raw or raw is UNKNOWN:
        return ev
    columns = sim.names_of(n.get("columns"))
    delimiter = sim.text_arg(n.get("delimiter"), ev, ",") or ","
    try:
        row = next(csv.reader(io.StringIO(raw), delimiter=delimiter[0]))
    except (StopIteration, csv.Error):
        return ev
    exclude_empty = sim.bool_arg(n.get("excludeempty"))
    for name, val in zip(columns, row):
        if exclude_empty and val == "":
            continue
        ev.set(name, val)
    return ev


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _xml_flatten(element, path, out):
    here = f"{path}.{_local(element.tag)}" if path else _local(element.tag)
    for attribute, val in element.attrib.items():
        out[f"{here}._{_local(attribute)}"] = val
    children = list(element)
    if element.text and element.text.strip() and not children:
        out[here] = element.text.strip()
    counts = {}
    for child in children:
        counts[_local(child.tag)] = counts.get(_local(child.tag), 0) + 1
    seen = {}
    for child in children:
        tag = _local(child.tag)
        if counts[tag] > 1:
            index = seen.get(tag, 0)
            seen[tag] = index + 1
            sub = {}
            _xml_flatten(child, "", sub)
            for k, v in sub.items():
                rest = k[len(tag):]
                out[f"{here}.{tag}[{index}]{rest}"] = v
        else:
            _xml_flatten(child, here, out)


def f_parsexml(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "@rawstring")
    raw = ev.get(source)
    if not raw or raw is UNKNOWN:
        return ev
    prefix = _prefix(sim.text_arg(n.get("prefix"), ev, ""))
    try:
        root = ET.fromstring(raw.strip())
    except ET.ParseError:
        ev.set("@error", "true")
        return ev
    out = {}
    _xml_flatten(root, "", out)
    for key, val in out.items():
        ev.set(f"{prefix}{key}", val)
    return ev


def f_parseurl(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "url")
    raw = ev.get(source)
    if not raw or raw is UNKNOWN:
        return ev
    prefix = _prefix(sim.text_arg(n.get("as") or n.get("prefix"), ev, source))
    try:
        parts = urllib.parse.urlsplit(raw if "://" in raw else "//" + raw)
        values = {"scheme": parts.scheme, "host": parts.hostname, "port": parts.port, "path": parts.path,
                  "query": parts.query, "fragment": parts.fragment, "username": parts.username, "password": parts.password}
    except ValueError:
        return ev
    for key, val in values.items():
        if val not in (None, ""):
            ev.set(f"{prefix}{key}", val)
    return ev


def f_timestamp(sim, ev, p, n):
    target = sim.name_of(n.get("as"), "@timestamp")
    source = sim.name_of(sim.arg(p, n, "field", 1 if p and p[0][0] == "lit" and len(p) > 1 else None), "@timestamp")
    if ev.get(source) is not None or source == "@timestamp":
        ev.set(target, "(parsed timestamp)")
    return ev


def f_replace(sim, ev, p, n):
    source = sim.name_of(n.get("field"), "@rawstring")
    target = sim.name_of(n.get("as"), source)
    value = _replace(sim, ev, p, n, source)
    if value is not None:
        ev.set(target, value)
    return ev


def _replace(sim, ev, p, n, source):
    raw = ev.get(source)
    if raw is None:
        return None
    if raw is UNKNOWN:
        return UNKNOWN
    pattern_node = n.get("regex") if "regex" in n else (p[0] if p else None)
    if pattern_node is None:
        return None
    pattern = pattern_node[1][0] if pattern_node[0] == "regexlit" else sim.text_arg(pattern_node, ev, "")
    flags = sim.text_arg(n.get("flags"), ev, "") or ""
    replacement = java_replacement(sim.text_arg(n.get("with"), ev, "") or "")
    compiled, names = compile_regex(pattern, flags)
    if compiled is None:
        return UNKNOWN
    replacement = re.sub(r"\\g<([^>]+)>", lambda m: "\\g<" + next((k for k, v in names.items() if v == m.group(1)), m.group(1)) + ">", replacement)
    try:
        return compiled.sub(replacement.replace("\\_", "_"), raw, timeout=REGEX_TIMEOUT)
    except (TimeoutError, Exception):
        return UNKNOWN


def v_replace(sim, ev, p, n):
    return _replace(sim, ev, p, n, sim.name_of(n.get("field"), "@rawstring"))


def _case_value(sim, ev, p, n, fn):
    source = sim.name_of(sim.arg(p, n, "field", 0))
    raw = ev.get(source) if source else None
    if raw is None or raw is UNKNOWN:
        return raw
    return fn(raw)


def f_case(fn):
    def stage(sim, ev, p, n):
        fields = sim.names_of(sim.arg(p, n, "field", 0))
        target = sim.name_of(n.get("as"))
        for name in fields:
            raw = ev.get(name)
            if raw is None:
                continue
            ev.set(target or name, UNKNOWN if raw is UNKNOWN else fn(raw))
        return ev
    return stage


def f_lowercase(sim, ev, p, n):
    fields = sim.names_of(sim.arg(p, n, "field", 0)) or ["*"]
    include = (sim.text_arg(n.get("include"), ev, "values") or "values").lower()
    names = list(ev.fields) if fields == ["*"] else fields
    for name in names:
        if name == "@rawstring" or name not in ev.fields:
            continue
        val = ev.fields[name]
        new_name = name.lower() if include in ("field", "both") else name
        new_val = val.lower() if include in ("values", "both") else val
        if new_name != name:
            del ev.fields[name]
        ev.fields[new_name] = new_val
    return ev


def f_drop(sim, ev, p, n):
    names = sim.names_of(sim.arg(p, n, "fields", 0))
    for name in names:
        ev.drop(name)
    return ev


def f_rename(sim, ev, p, n):
    source = sim.arg(p, n, "field", 0)
    if source is not None and source[0] == "list":
        pairs = [sim.names_of(item) for item in source[1]]
    else:
        pairs = [[sim.name_of(source), sim.name_of(sim.arg(p, n, "as", 1))]]
    for pair in pairs:
        if len(pair) != 2 or not pair[0] or not pair[1]:
            continue
        old, new = pair
        moved = {k: v for k, v in ev.fields.items() if k == old or k.startswith(old + ".") or k.startswith(old + "[")}
        for k, v in moved.items():
            del ev.fields[k]
            ev.fields[new + k[len(old):]] = v
        if old in ev.unknown:
            ev.unknown.discard(old)
            ev.unknown.add(new)
    return ev


def v_splitstring(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "@rawstring")
    raw = ev.get(source)
    if raw is None or raw is UNKNOWN:
        return raw
    by = sim.text_arg(n.get("by"), ev, ",")
    compiled, _ = compile_regex(by, "")
    try:
        parts = compiled.split(raw, timeout=REGEX_TIMEOUT) if compiled is not None else raw.split(by)
    except TimeoutError:
        return UNKNOWN
    index = n.get("index")
    if index is not None:
        i = _number(sim.text_arg(index, ev))
        if i is None:
            return None
        i = int(i)
        return parts[i] if -len(parts) <= i < len(parts) else None
    return parts


def f_splitstring(sim, ev, p, n):
    source = sim.name_of(sim.arg(p, n, "field", 0), "@rawstring")
    target = sim.name_of(n.get("as"), "_splitstring" if source == "@rawstring" else source)
    value = v_splitstring(sim, ev, p, n)
    if value is not None:
        ev.set(target if not isinstance(value, list) or target.endswith("[]") else target + "[]", value)
    return ev


def v_concatarray(sim, ev, p, n):
    base = sim.name_of(sim.arg(p, n, "field", 0))
    if not base:
        return None
    items = ev.array(base)
    lo = _number(sim.text_arg(n.get("from"), ev, "0")) or 0
    hi = _number(sim.text_arg(n.get("to"), ev))
    items = items[int(lo): int(hi) + 1 if hi is not None else None]
    if not items:
        return None
    sep = sim.text_arg(n.get("separator"), ev, "") or ""
    return sim.text_arg(n.get("prefix"), ev, "") + sep.join(items) + sim.text_arg(n.get("suffix"), ev, "")


def v_concat(sim, ev, p, n):
    names = sim.arg(p, n, "field", 0)
    parts = []
    for item in (names[1] if names and names[0] == "list" else [names] if names else []):
        v = sim.value(item, ev)
        if v is UNKNOWN:
            return UNKNOWN
        if v is not None:
            parts.append(str(v))
    return "".join(parts)


def v_format(sim, ev, p, n):
    fmt = sim.text_arg(sim.arg(p, n, "format", 0), ev, "")
    fields = sim.arg(p, n, "field", 1)
    items = fields[1] if fields and fields[0] == "list" else [fields] if fields else []
    values = []
    for item in items:
        v = sim.value(item, ev)
        if v is UNKNOWN:
            return UNKNOWN
        values.append("" if v is None else str(v))
    out, k = [], 0

    def sub(m):
        nonlocal k
        spec = m.group(0)
        if spec == "%%":
            return "%"
        if spec in ("%n",):
            return "\n"
        v = values[k] if k < len(values) else ""
        k += 1
        conv = spec[-1]
        if conv in "dfx":
            num = _number(v)
            if num is None:
                return v
            try:
                return ("%" + spec[1:-1].replace(",", "") + conv) % (int(num) if conv in "dx" else num)
            except (TypeError, ValueError):
                return v
        return ("%" + spec[1:-1].replace(",", "") + "s") % v if conv in "sS" else v

    return re.sub(r"%%|%n|%[-#+ 0,(]*\d*(?:\.\d+)?[sSdfx]", sub, fmt)


def v_coalesce(sim, ev, p, n):
    items = sim.arg(p, n, "expressions", 0)
    ignore_empty = sim.bool_arg(n.get("ignoreempty"), True)
    unknown = False
    for item in (items[1] if items and items[0] == "list" else [items] if items else []):
        v = sim.value(item, ev)
        if v is UNKNOWN:
            unknown = True
            continue
        if v is None or (ignore_empty and v == ""):
            continue
        return v
    return UNKNOWN if unknown else None


def v_getfield(sim, ev, p, n):
    source = sim.arg(p, n, "source", 0)
    name = sim.value(source, ev) if source and source[0] != "ref" else sim.value(source, ev)
    if name is UNKNOWN:
        return UNKNOWN
    if name is None and source is not None and source[0] == "ref":
        name = None
    return ev.get(name) if name else None


def f_default(sim, ev, p, n):
    fields = sim.names_of(sim.arg(p, n, "field", 0))
    value = sim.value(n["value"], ev) if "value" in n else ""
    replace_empty = sim.bool_arg(n.get("replaceempty"))
    for name in fields:
        current = ev.get(name)
        if current is None or (replace_empty and current == ""):
            ev.set(name, value)
    return ev


def f_array_append(sim, ev, p, n):
    base = sim.name_of(sim.arg(p, n, "array", 0))
    if not base:
        return ev
    base = base[:-2] if base.endswith("[]") else base
    values = sim.value(n["values"], ev) if "values" in n else []
    values = values if isinstance(values, list) else [values]
    start = ev.array_length(base)
    for i, v in enumerate(x for x in values if x is not None and x is not UNKNOWN):
        ev.set(f"{base}[{start + i}]", v)
    return ev


def f_array_dedup(sim, ev, p, n):
    base = sim.name_of(sim.arg(p, n, "array", 0))
    if not base:
        return ev
    items, seen = [], set()
    for v in ev.array(base):
        if v not in seen:
            seen.add(v)
            items.append(v)
    base = base[:-2] if base.endswith("[]") else base
    ev.set(base + "[]", items)
    return ev


def f_array_drop(sim, ev, p, n):
    base = sim.name_of(sim.arg(p, n, "array", 0))
    if base:
        ev.drop_array(base[:-2] if base.endswith("[]") else base)
    return ev


def f_array_length(sim, ev, p, n):
    base = sim.name_of(sim.arg(p, n, "array", 0))
    ev.set(sim.name_of(n.get("as"), "_length"), ev.array_length(base) if base else 0)
    return ev


def _bind_eval(sim, ev, base, var, block, out_base, objects):
    """Run block once per element with var bound, collecting out_base from each run."""
    base = base[:-2] if base.endswith("[]") else base
    results = []
    for i in range(ev.array_length(base)):
        scoped = ev.copy()
        scoped.scope[var] = (base, i) if objects else (None, ev.fields.get(f"{base}[{i}]"))
        out = sim.run_block(block, scoped)
        if out is None:
            continue
        if out_base:
            results.append(out.get(out_base) if out_base not in out.unknown else UNKNOWN)
    return results


def f_array_eval(objects):
    def stage(sim, ev, p, n):
        base = sim.name_of(n.get("array"))
        var = sim.name_of(n.get("var"), "x")
        out = sim.name_of(n.get("asarray"))
        if not base:
            return ev
        out_base = out[:-2] if out and out.endswith("[]") else out
        values = _bind_eval(sim, ev, base, var, n.get("function"), out_base, objects)
        if out_base:
            if any(v is UNKNOWN for v in values):
                ev.set(out_base, UNKNOWN)
            ev.set(out_base + "[]", [v for v in values if v not in (None, UNKNOWN)])
        return ev
    return stage


def f_array_filter(sim, ev, p, n):
    base = sim.name_of(n.get("array"))
    var = sim.name_of(n.get("var"), "x")
    out = sim.name_of(n.get("asarray"), base)
    if not base:
        return ev
    b = base[:-2] if base.endswith("[]") else base
    kept = []
    for i, v in enumerate(ev.array(b)):
        scoped = ev.copy()
        scoped.scope[var] = (None, v)
        if sim.run_block(n.get("function"), scoped) is not None:
            kept.append(v)
    o = out[:-2] if out.endswith("[]") else out
    ev.set(o + "[]", kept)
    return ev


def flt_objectarray_exists(sim, ev, p, n):
    base = sim.name_of(n.get("array"))
    var = sim.name_of(n.get("var"), "x")
    if not base:
        return False
    b = base[:-2] if base.endswith("[]") else base
    unknown = False
    for i in range(ev.array_length(b)):
        scoped = ev.copy()
        scoped.scope[var] = (b, i)
        cond = n.get("condition")
        out = sim.run_block(cond, scoped)
        if out is not None:
            return True
    return UNKNOWN if unknown else False


def flt_array_contains(sim, ev, p, n):
    base = sim.name_of(sim.arg(p, n, "array", 0))
    value = sim.text_arg(n.get("value"), ev)
    return value in ev.array(base) if base else False


def flt_array_regex(sim, ev, p, n):
    base = sim.name_of(sim.arg(p, n, "array", 0))
    pattern = sim.text_arg(n.get("regex"), ev, "")
    flags = sim.text_arg(n.get("flags"), ev, "") or ""
    results = [regex_search(pattern, flags, v)[0] for v in (ev.array(base) if base else [])]
    if True in results:
        return True
    return UNKNOWN if UNKNOWN in results else False


def flt_in(sim, ev, p, n):
    name = sim.name_of(sim.arg(p, n, "field", 0))
    actual = ev.get(name) if name else None
    if actual is UNKNOWN:
        return UNKNOWN
    if actual is None:
        return False
    values = sim.value(n["values"], ev) if "values" in n else []
    values = values if isinstance(values, list) else [values]
    ignore = sim.bool_arg(n.get("ignorecase"))
    return any(_glob(str(v), actual, ignore) if "*" in str(v) else (actual.lower() == str(v).lower() if ignore else actual == str(v))
               for v in values if v is not None and v is not UNKNOWN)


def flt_cidr(sim, ev, p, n):
    name = sim.name_of(sim.arg(p, n, "field", 0))
    actual = ev.get(name) if name else None
    if actual is UNKNOWN:
        return UNKNOWN
    negate = sim.bool_arg(n.get("negate"))
    subnets = sim.value(n["subnet"], ev) if "subnet" in n else (sim.value(p[1], ev) if len(p) > 1 else [])
    subnets = subnets if isinstance(subnets, list) else [subnets]
    if actual is None:
        return negate and False
    try:
        address = ipaddress.ip_address(actual.strip())
        hit = any(address in ipaddress.ip_network(str(s), strict=False) for s in subnets if s)
    except ValueError:
        hit = False
    return (not hit) if negate else hit


def flt_regex(sim, ev, p, n):
    pattern_node = n.get("regex") if "regex" in n else (p[0] if p else None)
    if pattern_node is None:
        return True
    pattern = pattern_node[1][0] if pattern_node[0] == "regexlit" else sim.text_arg(pattern_node, ev, "")
    source = sim.name_of(n.get("field"), "@rawstring")
    strict = sim.bool_arg(n.get("strict"), True)
    raw = ev.get(source)
    if raw is UNKNOWN:
        return UNKNOWN if strict else True
    if raw is None:
        return not strict
    hit, captured = regex_search(pattern, sim.text_arg(n.get("flags"), ev, "") or "", raw)
    if hit is UNKNOWN:
        return UNKNOWN if strict else True
    for k, v in captured.items():
        ev.set(k, v)
    return hit or not strict


def flt_test(sim, ev, p, n):
    node = p[0] if p else None
    return sim.truth(node, ev) if node else True


def flt_wildcard(sim, ev, p, n):
    name = sim.name_of(n.get("field"), "@rawstring")
    pattern = sim.text_arg(sim.arg(p, n, "pattern", 0), ev, "*")
    actual = ev.get(name)
    if actual is UNKNOWN:
        return UNKNOWN
    if actual is None:
        return False
    return _glob(pattern if name != "@rawstring" else f"*{pattern}*", actual, sim.bool_arg(n.get("ignorecase")))


def v_if(sim, ev, p, n):
    cond = p[0] if p else None
    r = sim.truth(cond, ev) if cond else False
    if r is UNKNOWN:
        return UNKNOWN
    branch = n.get("then") if r else n.get("else")
    return sim.value(branch, ev) if branch is not None else None


def v_simple(fn, arg="field"):
    def value(sim, ev, p, n):
        node = sim.arg(p, n, arg, 0)
        v = sim.value(node, ev) if node is not None and node[0] != "lit" else (node[1] if node else None)
        if node is not None and node[0] == "lit" and arg == "field":
            v = ev.get(node[1])
        if v is None or v is UNKNOWN:
            return v
        try:
            return fn(str(v))
        except Exception:
            return None
    return value


def _b64(text):
    return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace")


def f_match_file(sim, ev, p, n):
    sim.note(ev, "unsupported", "match(file=...)")
    # A lookup adds the columns it finds. Fields already set keep their value; others become unknown.
    for name in sim.names_of(n.get("include")):
        if ev.get(name) is None:
            ev.set(name, UNKNOWN)
    target = sim.name_of(n.get("column"))
    if target and not n.get("include"):
        ev.set(target, UNKNOWN)
    return ev


def f_drop_event(sim, ev, p, n):
    return None


def f_set_field(sim, ev, p, n):
    target = sim.value(n.get("target"), ev) if n.get("target") else None
    if target and target is not UNKNOWN:
        ev.set(target, sim.value(n.get("value"), ev) if n.get("value") else None)
    return ev


def f_eval(sim, ev, p, n):
    return ev


def f_split(sim, ev, p, n):
    sim.note(ev, "unsupported", "split() (one event per array element)")
    return ev


def f_write_json(sim, ev, p, n):
    names = sim.names_of(sim.arg(p, n, "field", 0))
    target = sim.name_of(n.get("as"), "_json")
    data = {}
    for name in names:
        if name.endswith("*"):
            data.update({k: v for k, v in ev.fields.items() if k.startswith(name[:-1])})
        elif ev.get(name) not in (None, UNKNOWN):
            data[name] = ev.get(name)
    ev.set(target, json.dumps(data))
    return ev


def f_unknown_output(default_as):
    def stage(sim, ev, p, n):
        target = sim.name_of(n.get("as"), default_as)
        ev.set(target, UNKNOWN)
        return ev
    return stage


FILTER_FUNCS = {
    "in": flt_in, "cidr": flt_cidr, "regex": flt_regex, "test": flt_test, "wildcard": flt_wildcard,
    "array:contains": flt_array_contains, "objectarray:exists": flt_objectarray_exists,
    "array:regex": lambda sim, ev, p, n: flt_array_regex(sim, ev, p, n),
}

STAGE_FUNCS = {
    "parsejson": f_parsejson, "kvparse": f_kvparse, "parsecef": f_parsecef, "parsecsv": f_parsecsv,
    "parsexml": f_parsexml, "parseurl": f_parseurl, "parseuri": f_parseurl,
    "parsetimestamp": f_timestamp, "findtimestamp": f_timestamp, "parsetime": f_timestamp,
    "replace": f_replace, "lower": f_case(str.lower), "upper": f_case(str.upper),
    "lowercase": f_lowercase, "drop": f_drop, "rename": f_rename, "splitstring": f_splitstring,
    "default": f_default, "array:append": f_array_append, "array:dedup": f_array_dedup,
    "array:drop": f_array_drop, "array:length": f_array_length, "array:eval": f_array_eval(False),
    "objectarray:eval": f_array_eval(True), "array:filter": f_array_filter, "match": f_match_file,
    "dropevent": f_drop_event, "setfield": f_set_field, "eval": f_eval, "split": f_split,
    "writejson": f_write_json, "communityid": f_unknown_output("network.community_id"),
    "iplocation": f_unknown_output("_iplocation"), "asn": f_unknown_output("_asn"),
}

VALUE_FUNCS = {
    "replace": v_replace, "lower": v_simple(str.lower), "upper": v_simple(str.upper),
    "splitstring": v_splitstring, "concatarray": v_concatarray, "concat": v_concat, "format": v_format,
    "coalesce": v_coalesce, "getfield": v_getfield, "if": v_if,
    "parsetimestamp": lambda sim, ev, p, n: "(parsed timestamp)",
    "findtimestamp": lambda sim, ev, p, n: "(parsed timestamp)",
    "rename": lambda sim, ev, p, n: sim.value(sim.arg(p, n, "field", 0), ev),
    "length": v_simple(lambda s: str(len(s))), "text:length": v_simple(lambda s: str(len(s))),
    "crypto:sha256": v_simple(lambda s: hashlib.sha256(s.encode()).hexdigest()),
    "crypto:sha1": v_simple(lambda s: hashlib.sha1(s.encode()).hexdigest()),
    "crypto:md5": v_simple(lambda s: hashlib.md5(s.encode()).hexdigest()),
    "math:floor": v_simple(lambda s: _str(math.floor(float(s)))),
    "math:ceil": v_simple(lambda s: _str(math.ceil(float(s)))),
    "math:abs": v_simple(lambda s: _str(abs(float(s)))),
    "round": v_simple(lambda s: _str(round(float(s)))),
    "urldecode": v_simple(urllib.parse.unquote), "base64decode": v_simple(_b64),
    "tostring": v_simple(str), "parseint": v_simple(lambda s: _str(int(float(s)))),
    "text:trim": v_simple(str.strip),
}

NOOP_FUNCS = {"select", "table", "fields", "sort", "head", "tail", "sortedby", "fieldset", "unit",
              "array:sort", "formattime", "now", "count"}


# ---------------------------------------------------------------- public helpers

_compiled = {}


def simulator_for(script):
    """A cached Simulator for a script, or raises SimError if it can't be read."""
    if script not in _compiled:
        try:
            _compiled[script] = Simulator(script)
        except SimError as exc:
            _compiled[script] = exc
    value = _compiled[script]
    if isinstance(value, SimError):
        raise value
    return value


def simulate(script, rawstring, tag_fields=()):
    """Run a parser script on one raw event. Returns a Result."""
    try:
        sim = simulator_for(script)
    except SimError as exc:
        return Result(fields={"@rawstring": rawstring}, error=f"Couldn't read the parser: {exc}", tag_fields=list(tag_fields))
    return sim.run(rawstring, tag_fields)
