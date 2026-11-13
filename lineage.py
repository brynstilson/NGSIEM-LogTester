"""Static analysis of a parser script: where each parsed field comes from, and the log's format.

For every field a parser sets, it records each way it can be set: copied from another field
(possibly lower-cased), set to a constant, appended to an array, or extracted by a regex, along
with the case-branch and match-arm conditions that must hold. Sample generation works backwards
from a rule's requirements through these producers to the raw fields a log must carry.
"""
from dataclasses import dataclass, field as dc_field

from parser_sim import SimError, parse_script

COPY_FUNCS = {"lower": "lower", "upper": "upper", "rename": None, "tostring": None, "text:trim": None}
DECODERS = {"parsejson": "json", "kvparse": "kv", "parsecef": "cef", "parsecsv": "csv", "parsexml": "xml"}


@dataclass
class Producer:
    target: str
    kind: str                      # copy, const, append, extract, derived
    source: str = None
    transform: str = None
    value: object = None
    conditions: list = dc_field(default_factory=list)   # filter nodes, match arms


@dataclass
class Decoder:
    kind: str                      # json, kv, cef, csv, xml
    source: str
    prefix: str = ""
    columns: list = dc_field(default_factory=list)
    conditions: list = dc_field(default_factory=list)


def _name(node):
    if node is None:
        return None
    if node[0] in ("ref", "lit"):
        return str(node[1])
    return None


def _names(node):
    if node is None:
        return []
    if node[0] == "list":
        out = []
        for item in node[1]:
            out.extend(_names(item))
        return out
    n = _name(node)
    return [n] if n else []


FILTER_APPLY = {"in", "cidr", "wildcard", "regex"}


def _branch_filter(stage):
    """The condition a stage at the start of a case branch stands for, or None if it isn't one.

    Plain filters count, and so does `field =~ in(...)` (or cidr, wildcard, regex), which the
    parser reads as a stage of its own.
    """
    if stage[0] == "filter" and stage[1][0] not in ("call",):
        return stage[1]
    if stage[0] == "apply" and stage[2][0] in FILTER_APPLY:
        return ("apply", stage[1], stage[2])
    return None


def _prefix(text):
    if not text:
        return ""
    return text if text.endswith(".") else text + "."


def _target(name):
    name = name[1:] if name.startswith("#") else name
    return name


class Lineage:
    def __init__(self, script):
        self.stages = parse_script(script)
        self.producers = {}
        self.decoders = []
        self.raw_fields = set()     # fields read straight from the raw log by a decoder
        self._walk(self.stages, [])
        self.gates = self._gates(self.stages)

    def _gates(self, stages):
        """What every log must satisfy to survive the top level of the script, in order.

        A top-level filter is one requirement. A case block without a catch-all branch, or a match
        block without a * arm, drops logs that fit none of its options, so it becomes a list of
        alternatives (the leading filters of each branch, or each arm's pattern).
        """
        gates = []
        for stage in stages:
            kind = stage[0]
            if kind == "filter" and stage[1][0] not in ("call",):
                gates.append([[stage[1]]])
            elif kind == "case":
                options = []
                for branch in stage[1]:
                    leading = []
                    for st in branch:
                        if _branch_filter(st) is not None:
                            leading.append(_branch_filter(st))
                        else:
                            break
                    if not leading or any(node[0] == "true" for node in leading):
                        options = None  # a catch-all branch: nothing is required
                        break
                    options.append(leading)
                if options:
                    gates.append(options)
            elif kind == "match":
                _, name, arms = stage
                if not any(pattern[0] == "any" for pattern, _ in arms):
                    gates.append([[("arm", _target(name), pattern)] for pattern, _ in arms])
        return gates

    # ---- building
    def _add(self, producer):
        self.producers.setdefault(producer.target, []).append(producer)

    def _walk(self, stages, conds):
        for stage in stages:
            kind = stage[0]
            if kind == "assign":
                self._assign(_target(stage[1]), stage[2], conds)
            elif kind == "case":
                for branch in stage[1]:
                    leading, rest = [], list(branch)
                    while rest and _branch_filter(rest[0]) is not None:
                        leading.append(_branch_filter(rest.pop(0)))
                    # Regex filters at the start of a branch also extract fields.
                    for node in leading:
                        self._extract(node, conds)
                    self._walk(rest, conds + leading)
            elif kind == "match":
                _, name, arms = stage
                for pattern, body in arms:
                    self._walk(body, conds + [("arm", _target(name), pattern)])
            elif kind == "filter":
                node = stage[1]
                if node[0] == "call":
                    self._call(node[1], conds)
                else:
                    self._extract(node, conds)
            elif kind == "apply":
                fname, positional, named = stage[2]
                self._call((fname, positional, {**named, "field": named.get("field", ("ref", stage[1]))}), conds)

    def _assign(self, target, expr, conds):
        kind = expr[0]
        if kind == "ref":
            self._add(Producer(target, "copy", source=_target(expr[1]), conditions=conds))
        elif kind == "lit":
            self._add(Producer(target, "const", value=str(expr[1]), conditions=conds))
        elif kind == "callx":
            fname, positional, named = expr[1]
            if fname in COPY_FUNCS:
                source = _name(named.get("field") or (positional[0] if positional else None))
                if source:
                    self._add(Producer(target, "copy", source=_target(source), transform=COPY_FUNCS[fname], conditions=conds))
                    return
            if fname == "coalesce":
                items = positional[0] if positional else named.get("expressions")
                for item in (items[1] if items and items[0] == "list" else []):
                    self._assign(target, item, conds)
                return
            if fname == "if":
                for branch in ("then", "else"):
                    if named.get(branch) is not None and named[branch][0] != "any":
                        self._assign(target, named[branch], conds)
                return
            if fname == "format":
                fmt = named.get("format") or (positional[0] if positional else None)
                fields = named.get("field") or (positional[1] if len(positional) > 1 else None)
                refs = _names(fields)
                if fmt and fmt[0] == "lit" and str(fmt[1]).count("%s") == 1 and len(refs) == 1:
                    before, after = str(fmt[1]).split("%s")
                    self._add(Producer(target, "format", source=_target(refs[0]), value=(before, after), conditions=conds))
                    return
            if fname == "splitstring":
                source = _name(named.get("field") or (positional[0] if positional else None))
                if source:
                    self._add(Producer(target, "derived", source=_target(source), transform="split", conditions=conds))
                return
            sources = [s for s in self._refs(expr) if s]
            self._add(Producer(target, "derived", source=sources[0] if sources else None, conditions=conds))

    def _refs(self, node):
        if isinstance(node, tuple):
            if node and node[0] == "ref":
                return [_target(node[1])]
            out = []
            for item in node[1:]:
                out.extend(self._refs(item))
            return out
        if isinstance(node, list):
            out = []
            for item in node:
                out.extend(self._refs(item))
            return out
        return []

    def _extract(self, node, conds):
        if node[0] == "cmp" and node[3][0] == "regex":
            import re
            for group in re.findall(r"\(\?<(?![=!])([^>]+)>", node[3][1][0]):
                self._add(Producer(_target(group), "extract", source=_target(node[1]), value=node[3][1], conditions=conds))
        elif node[0] in ("and", "or"):
            for child in node[1]:
                self._extract(child, conds)

    def _call(self, call, conds):
        fname, positional, named = call
        first = positional[0] if positional else None
        if fname in DECODERS:
            source = _name(named.get("field") or (first if first and first[0] in ("ref", "lit") else None)) or "@rawstring"
            prefix = named.get("prefix") or named.get("as")
            decoder = Decoder(DECODERS[fname], _target(source), _prefix(_name(prefix) or ""), _names(named.get("columns")), conds)
            if fname == "parsecef":
                decoder.prefix = _prefix(_name(named.get("prefix")) or "cef.")
            self.decoders.append(decoder)
            for col in decoder.columns:
                self._add(Producer(_target(col), "column", source=decoder.source, value=decoder.columns.index(col), conditions=conds))
        elif fname == "array:append":
            target = _name(named.get("array") or first)
            values = named.get("values")
            items = values[1] if values and values[0] == "list" else [values] if values else []
            for item in items:
                if item and item[0] == "lit":
                    self._add(Producer(_target(target).rstrip("[]"), "append", value=str(item[1]), conditions=conds))
                elif item and item[0] == "ref":
                    self._add(Producer(_target(target).rstrip("[]"), "append-copy", source=_target(item[1]), conditions=conds))
        elif fname in ("lower", "upper"):
            for source in _names(named.get("field") or first):
                target = _name(named.get("as")) or source
                if target != source:
                    self._add(Producer(_target(target), "copy", source=_target(source), transform=fname, conditions=conds))
        elif fname == "rename":
            source, target = _name(named.get("field") or first), _name(named.get("as"))
            if source and target:
                self._add(Producer(_target(target), "copy", source=_target(source), conditions=conds))
        elif fname == "regex":
            pattern = named.get("regex") or first
            source = _name(named.get("field")) or "@rawstring"
            if pattern and pattern[0] in ("lit", "regexlit"):
                body = pattern[1] if pattern[0] == "lit" else pattern[1][0]
                self._extract(("cmp", source, "=", ("regex", (body, ""))), conds)
        elif fname in ("objectarray:eval", "array:eval"):
            out = _name(named.get("asarray"))
            array = _name(named.get("array"))
            var = _name(named.get("var")) or "x"
            block = named.get("function")
            if out and array and block and block[0] == "block":
                for stage in block[1]:
                    if stage[0] == "assign" and stage[2][0] in ("ref", "callx"):
                        refs = self._refs(stage[2])
                        ref = refs[0] if refs else None
                        if ref and (ref == var or ref.startswith(var + ".")):
                            element = array.rstrip("[]") + "[0]" + ref[len(var):]
                            self._add(Producer(out.rstrip("[]") + "[0]", "copy", source=element, conditions=conds))
        elif fname == "format":
            target = _name(named.get("as"))
            if target:
                self._assign(_target(target), ("callx", call), conds)
        elif fname == "default":
            for target in _names(named.get("field") or first):
                value = named.get("value")
                if value and value[0] == "lit":
                    self._add(Producer(_target(target), "const", value=str(value[1]), conditions=conds))
        elif fname == "case":
            pass

    # ---- questions
    @property
    def format(self):
        """The raw format: the first decoder that reads the raw log (directly or via an extracted field)."""
        for d in self.decoders:
            if d.source == "@rawstring":
                return d.kind
        return None  # The raw log is text that regexes take apart first.

    def main_decoder(self):
        raw = [d for d in self.decoders if d.source == "@rawstring"]
        for d in raw:
            if d.prefix:
                return d
        for d in raw:
            return d
        return self.decoders[0] if self.decoders else None

    def constants(self, field):
        return [p.value for p in self.producers.get(field, []) if p.kind == "const"]

    def raw_source(self, field, depth=0):
        """The raw field name (as the vendor sends it) that a parsed field is read from, if known."""
        if depth > 6:
            return None
        matching = [d for d in self.decoders if d.prefix and field.startswith(d.prefix) and d.kind in ("json", "kv", "cef", "xml")]
        if matching:
            # The broadest decoder (shortest prefix) reads the raw log; longer prefixes re-parse nested text.
            decoder = min(matching, key=lambda d: (d.source != "@rawstring", len(d.prefix)))
            return field[len(decoder.prefix):]
        for producer in self.producers.get(field, []):
            if producer.kind == "copy" and producer.source:
                found = self.raw_source(producer.source, depth + 1)
                if found:
                    return found
        return None

    def hint(self, field, example):
        """A sentence saying how to make the parser produce field = example, or None."""
        raw = self.raw_source(field)
        if raw and raw != field:
            return f'The parser sets {field} from the raw field "{raw}": give "{raw}" the value "{example}".'
        consts = [p for p in self.producers.get(field, []) if p.kind == "const" and p.value == str(example)]
        if consts and consts[0].conditions:
            cond = describe_condition(consts[0].conditions[-1])
            if cond:
                return f'The parser sets {field} = "{example}" when {cond}.'
        return None


def describe_condition(cond):
    if cond[0] == "arm":
        _, field, pattern = cond
        if pattern[0] in ("string", "word", "number"):
            return f'{field} is "{pattern[1]}"'
        if pattern[0] == "regex":
            return f"{field} matches /{pattern[1][0]}/"
        return None
    if cond[0] == "cmp":
        _, field, op, value = cond
        if value[0] == "any":
            return f"{field} is present" if op == "=" else f"{field} is absent"
        if value[0] == "regex":
            return f"{field} matches /{value[1][0]}/"
        return f'{field} {op} "{value[1]}"'
    return None


_cache = {}


def lineage_for(script):
    if script not in _cache:
        try:
            _cache[script] = Lineage(script)
        except SimError:
            _cache[script] = None
    return _cache[script]
