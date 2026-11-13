"""Builds a string that matches a regular expression, optionally with chosen text for named groups.

Used to write sample values for rule conditions such as process.command_line=/-enc\\s+\\S+/i, and to
synthesize syslog lines that a parser's extraction regex accepts, with the captured fields set to
the values a rule needs. The result is always checked against the pattern; None means no match
could be built.
"""
import re

try:
    import re._parser as sre  # Python 3.11+
    from re import _constants as C
except ImportError:  # pragma: no cover
    import sre_parse as sre
    import sre_constants as C

from parser_sim import compile_regex

MAX_LEN = 4000


class _Builder:
    def __init__(self, overrides, names):
        self.overrides = overrides        # field name -> text
        self.names = names                # python group alias -> field name
        self.groups = {}

    def build(self, parsed):
        return "".join(self.node(op, av) for op, av in parsed)

    def node(self, op, av):
        name = getattr(op, "name", str(op))
        if name == "LITERAL":
            return chr(av)
        if name == "NOT_LITERAL":
            return "a" if chr(av) != "a" else "b"
        if name == "ANY":
            return "x"
        if name == "IN":
            return self.pick(av)
        if name == "BRANCH":
            return self.build(av[1][0])
        if name == "SUBPATTERN":
            group, _, _, sub = av
            alias = next((a for a, i in self.group_ids.items() if i == group), None) if group else None
            field = self.names.get(alias) if alias else None
            if field and field in self.overrides:
                text = str(self.overrides[field])
            else:
                text = self.build(sub)
            if group:
                self.groups[group] = text
            return text
        if name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            lo, hi, sub = av
            count = lo if lo > 0 else (1 if self._wants_one(sub) else 0)
            if hi != C.MAXREPEAT:
                count = min(count, hi)
            return "".join(self.build(sub) for _ in range(count))
        if name == "ATOMIC_GROUP":
            return self.build(av)
        if name == "GROUPREF":
            return self.groups.get(av, "")
        if name in ("AT", "ASSERT", "ASSERT_NOT"):
            return ""
        if name == "CATEGORY":
            return self.category(av)
        if name == "GROUPREF_EXISTS":
            return self.build(av[1])
        return ""

    def _wants_one(self, sub):
        """Optional parts that hold a named field are kept, so the line reads unambiguously."""
        named = set(self.group_ids.values())
        if len(sub) == 1 and self.node(*sub[0]) == " ":
            return True  # an optional space between fields reads better kept
        stack = list(sub)
        while stack:
            op, av = stack.pop()
            name = getattr(op, "name", str(op))
            if name == "SUBPATTERN":
                if av[0] in named:
                    return True
                stack.extend(av[3])
            elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                stack.extend(av[2])
            elif name == "BRANCH":
                for alt in av[1]:
                    stack.extend(alt)
            elif name == "ATOMIC_GROUP":
                stack.extend(av)
        return False

    def category(self, av):
        name = getattr(av, "name", str(av))
        return {"CATEGORY_DIGIT": "1", "CATEGORY_NOT_DIGIT": "a", "CATEGORY_SPACE": " ", "CATEGORY_NOT_SPACE": "a",
                "CATEGORY_WORD": "a", "CATEGORY_NOT_WORD": "-"}.get(name, "a")

    def pick(self, items):
        negate = any(getattr(op, "name", "") == "NEGATE" for op, _ in items)
        if not negate:
            for op, av in items:
                name = getattr(op, "name", "")
                if name == "LITERAL":
                    return chr(av)
                if name == "RANGE":
                    lo, hi = av
                    for preferred in ("a", "A", "1", "0"):
                        if lo <= ord(preferred) <= hi:
                            return preferred
                    return chr(lo)
                if name == "CATEGORY":
                    return self.category(av)
            return "a"
        excluded = set()
        for op, av in items:
            name = getattr(op, "name", "")
            if name == "LITERAL":
                excluded.add(chr(av))
            elif name == "RANGE":
                excluded.update(chr(c) for c in range(av[0], min(av[1], av[0] + 300) + 1))
        for candidate in "aZ1x-_ ":
            if candidate not in excluded:
                return candidate
        return "q"


def _defaults(names):
    """Readable values for common syslog groups, tried before the bare minimum the pattern allows."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    choices = {}
    for field in names.values():
        low = field.lower()
        if low.endswith(("priority", "pri")):
            choices[field] = ["14"]
        elif low in ("ts", "_ts", "timestamp", "time", "@timestamp", "date", "_timestamp") or low.endswith((".ts", "timestamp")):
            choices[field] = [now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
                              now.strftime("%b %d %H:%M:%S").replace(" 0", "  "), now.strftime("%Y-%m-%d %H:%M:%S"),
                              now.strftime("%b %d %H:%M:%S")]
        elif low.endswith(("hostname", "host.name", "host")):
            choices[field] = ["ngsiem-logtester-test-host"]
        elif low.endswith("procid") or low.endswith("pid"):
            choices[field] = ["4321"]
        elif low.endswith(".ip") or low.endswith("_ip") or low == "ip":
            choices[field] = ["192.0.2.10"]
    return choices


def sample(pattern, flags="", overrides=None):
    """A string matching the LogScale pattern, with named groups set from overrides, or None.

    Common syslog groups (priority, timestamp, host, process ID, IP) get realistic values when the
    pattern accepts them; otherwise the shortest text the pattern allows is used.
    """
    overrides = overrides or {}
    compiled, names = compile_regex(pattern, flags)
    if compiled is None:
        return None
    chosen = dict(overrides)
    for field, values in _defaults(names).items():
        if field in chosen:
            continue
        for value in values:
            if _sample({**chosen, field: value}, pattern, flags) is not None:
                chosen[field] = value
                break
    return _sample(chosen, pattern, flags) or _sample(overrides, pattern, flags)


def _sample(overrides, pattern, flags):
    compiled, names = compile_regex(pattern, flags)
    if compiled is None:
        return None
    try:
        py_pattern = re.sub(r"\(\?<(?![=!])([^>]+)>", lambda m, it=iter(list(names)): f"(?P<{next(it)}>", pattern)
        parsed = sre.parse(py_pattern, re.I if "i" in flags else 0)
    except Exception:
        return None
    builder = _Builder(overrides, names)
    builder.group_ids = dict(parsed.state.groupdict)
    try:
        text = builder.build(parsed)
    except RecursionError:
        return None
    if len(text) > MAX_LEN:
        return None
    try:
        m = compiled.search(text, timeout=0.25)
    except TimeoutError:
        return None
    if not m:
        return None
    for alias, field in names.items():
        if field in overrides and m.group(alias) != str(overrides[field]):
            return None
    return text


def substitute(pattern, flags, text, overrides):
    """Rewrite named groups in text (which must already match) to the override values, or None."""
    compiled, names = compile_regex(pattern, flags)
    if compiled is None or text is None:
        return None
    try:
        m = compiled.search(text, timeout=0.25)
    except TimeoutError:
        return None
    if not m:
        return None
    spans = []
    for alias, field in names.items():
        if field in overrides and m.start(alias) >= 0:
            spans.append((m.start(alias), m.end(alias), str(overrides[field])))
    if not spans:
        return None
    out = text
    for start, end, value in sorted(spans, reverse=True):
        out = out[:start] + value + out[end:]
    try:
        check = compiled.search(out, timeout=0.25)
    except TimeoutError:
        return None
    if not check:
        return None
    for alias, field in names.items():
        if field in overrides and check.group(alias) != str(overrides[field]):
            return None
    return out
