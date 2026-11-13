"""Ties the parser store, simulator and lineage together, with caching, for the rule check and generator."""
import threading
from collections import OrderedDict

from field_model import PROFILES
from lineage import lineage_for
from parser_sim import Result, simulate, simulator_for, SimError

RESULT_CACHE = 4000


class Simulation:
    """Runs a connector's real parser on raw events. Inactive (returns None) without a parser store."""

    def __init__(self, store=None):
        self.store = store
        self._results = OrderedDict()
        self._lock = threading.Lock()

    @property
    def active(self):
        return self.store is not None

    def parser(self, name):
        """The parser definition, or None if it isn't available."""
        if not self.store or not name:
            return None
        try:
            return self.store.get(name)
        except Exception:  # A store problem must never break the rule check.
            return None

    def lineage(self, name):
        doc = self.parser(name)
        return lineage_for(doc["script"]) if doc else None

    def run(self, name, rawstring):
        """A Result for rawstring parsed by the named parser, or None if that parser isn't available."""
        doc = self.parser(name)
        if not doc:
            return None
        key = (doc["name"], doc["version"], rawstring)
        with self._lock:
            if key in self._results:
                self._results.move_to_end(key)
                return self._results[key]
        result = simulate(doc["script"], rawstring, doc["tag_fields"])
        with self._lock:
            self._results[key] = result
            while len(self._results) > RESULT_CACHE:
                self._results.popitem(last=False)
        return result

    def parsers_for_rule(self, vendor, module=None, sourcetype=None):
        """Parser names that set #Vendor (and #event.module, if given) to these values, best first."""
        if not self.store:
            return []
        try:
            index = self.store.index()
        except Exception:
            return []
        if sourcetype:
            resolved = self.store.resolve(sourcetype)
            if resolved:
                return [resolved]
        vendor = (vendor or "").lower()
        module = (module or "").lower()
        listed = [n for n, e in index.items() if str(e.get("vendor") or "").lower() == vendor] if vendor else []
        if not listed:
            return []
        if not module:
            return sorted(listed, key=lambda n: (n not in PROFILES, n))
        matched = []
        for name in listed:
            lineage = self.lineage(name)
            modules = {str(v).lower() for v in (lineage.constants("event.module") if lineage else [])}
            products = {str(p).lower() for p in (index[name].get("product") or [])}
            if module in modules or module in products or module in name:
                matched.append(name)
        return sorted(matched, key=lambda n: (n not in PROFILES, n)) or []
