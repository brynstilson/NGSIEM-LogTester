"""NG-SIEM parser definitions, read live from the tenant and cached on disk.

Needs the NGSIEM Parsers: Read scope. Definitions are cached under cache/parsers (git-ignored) by
name and version, so each version is downloaded once, and a cached copy is used if the API fails.
"""
import json
import os
import re
import threading
import time
from pathlib import Path

import yaml

from falcon_client import ActivityLog, FalconError

APP_DIR = Path(__file__).resolve().parent
INDEX_SECONDS = 3600  # How long the list of parsers is trusted before it's read again.


def _safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


class ParserStore:
    def __init__(self, client, cache_dir=None, index_seconds=INDEX_SECONDS, clock=time.time):
        self.client = client
        self.cache_dir = Path(cache_dir or os.environ.get("PARSER_CACHE_DIR") or APP_DIR / "cache" / "parsers").resolve()
        self.index_seconds, self.clock = index_seconds, clock
        self._index, self._index_at, self._index_error = {}, 0, None
        self._docs = {}
        self._lock = threading.Lock()

    # The API's activity is kept out of operators' verbose logs: parser bodies are large.
    def _log(self):
        return ActivityLog()

    def index(self):
        """{parser name: listing entry}. Falls back to the copy on disk if the API can't be reached."""
        with self._lock:
            if self._index and self.clock() - self._index_at < self.index_seconds:
                return self._index
            path = self.cache_dir / "index.json"
            try:
                entries = self.client.list_parsers(self._log())
                self._index = {e.get("Name"): e for e in entries if e.get("Name") and e.get("ID")}
                self._index_error = None
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(self._index), encoding="utf-8")
            except (FalconError, OSError) as exc:
                self._index_error = str(exc)
                if not self._index and path.exists():
                    self._index = json.loads(path.read_text(encoding="utf-8"))
            self._index_at = self.clock()
            return self._index

    @property
    def error(self):
        return self._index_error

    def resolve(self, name):
        """The parser name as listed, matching exact names first, then the closest prefix."""
        if not name:
            return None
        index = self.index()
        if name in index:
            return name
        candidates = sorted(n for n in index if n.startswith(name) or name.startswith(n))
        return candidates[0] if candidates else None

    def get(self, name):
        """{"name", "version", "script", "tag_fields"} for a parser, or None if it isn't available."""
        name = self.resolve(name)
        if not name:
            return None
        entry = self.index().get(name) or {}
        parser_id = entry.get("ID", "")
        version = parser_id.split(":", 1)[1] if ":" in parser_id else "unknown"
        key = f"{name}@{version}"
        with self._lock:
            if key in self._docs:
                return self._docs[key]
        path = self.cache_dir / f"{_safe(key)}.yaml"
        text = None
        if path.exists():
            text = path.read_text(encoding="utf-8")
        else:
            try:
                text = self.client.get_parser_template(parser_id, self._log())["yaml_template"]
                self.cache_dir.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            except (FalconError, OSError):
                older = sorted(self.cache_dir.glob(f"{_safe(name)}@*.yaml")) if self.cache_dir.exists() else []
                text = older[-1].read_text(encoding="utf-8") if older else None
        if not text:
            return None
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            return None
        parsed = {"name": name, "version": version, "script": doc.get("script") or "",
                  "tag_fields": doc.get("tagFields") or [], "vendor": entry.get("vendor"),
                  "product": entry.get("product") or []}
        with self._lock:
            self._docs[key] = parsed
        return parsed
