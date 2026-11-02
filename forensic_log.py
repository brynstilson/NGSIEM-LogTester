"""Permanent, append-only record of every log submission, one JSON object per line."""
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parent / "logs" / "forensic.jsonl"


class ForensicLog:
    """The app only ever appends to this file. It never rotates, truncates or deletes it."""

    def __init__(self, path=None):
        self.path = Path(path or os.environ.get("FORENSIC_LOG_PATH") or DEFAULT_PATH).resolve()
        self._lock = threading.Lock()

    def write(self, event, submission_id, **fields):
        """Append a record and flush it to disk. Raises OSError if that isn't possible."""
        record = {
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            "submission_id": submission_id,
            **fields,
        }
        line = json.dumps(record)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as file:
                file.write(line + "\n")
                file.flush()
                os.fsync(file.fileno())
