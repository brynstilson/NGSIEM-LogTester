"""Access controls: the allowed Host names, the operator login, and lockout after failed passwords."""
import hmac
import threading
import time

LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}
MAX_FAILURES = 5          # wrong passwords from one address...
FAILURE_WINDOW = 300      # ...within this many seconds...
LOCKOUT_SECONDS = 300     # ...lock that address out for this long.


def host_name(host_header):
    """The host part of a Host header, lower case and without the port."""
    host = (host_header or "").strip().lower()
    if host.startswith("["):  # [::1]:5000
        return host[1:host.find("]")] if "]" in host else host
    if host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host


def parse_allowed_hosts(value):
    """APP_ALLOWED_HOSTS: comma-separated host names or IP addresses, or * for any."""
    return {host_name(item) for item in (value or "").split(",") if item.strip()}


def host_allowed(host_header, allowed):
    """Rejecting unknown Host names stops DNS rebinding: a hostile page can't pose as this app."""
    return "*" in allowed or host_name(host_header) in LOOPBACK_NAMES | allowed


def password_matches(given, expected):
    return hmac.compare_digest((given or "").encode(), expected.encode())


class RateLimiter:
    """Allows each client address a fixed number of requests per window (a sliding log)."""

    def __init__(self, limit, window=60, clock=time.monotonic):
        self.limit, self.window, self.clock = limit, window, clock
        self._hits = {}
        self._lock = threading.Lock()

    def retry_after(self, key):
        """Record a request and return 0 if it's allowed, or the seconds to wait if it isn't."""
        with self._lock:
            now = self.clock()
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                return int(self.window - (now - hits[0])) + 1
            hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 10000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self.window}
            return 0


class Throttle:
    """Counts wrong passwords per client address and locks the address out after too many."""

    def __init__(self, max_failures=MAX_FAILURES, window=FAILURE_WINDOW, lockout=LOCKOUT_SECONDS, clock=time.monotonic):
        self.max_failures, self.window, self.lockout, self.clock = max_failures, window, lockout, clock
        self._failures = {}
        self._locked_until = {}
        self._lock = threading.Lock()

    def retry_after(self, key):
        """Seconds until this key may try again, or 0 if it isn't locked out."""
        with self._lock:
            remaining = self._locked_until.get(key, 0) - self.clock()
            if remaining <= 0:
                self._locked_until.pop(key, None)
                return 0
            return int(remaining) + 1

    def failed(self, key):
        with self._lock:
            now = self.clock()
            recent = [t for t in self._failures.get(key, []) if now - t < self.window] + [now]
            if len(recent) >= self.max_failures:
                self._locked_until[key] = now + self.lockout
                recent = []
            self._failures[key] = recent
            # Forget stale addresses so the table can't grow without limit.
            if len(self._failures) > 10000:
                self._failures = {k: v for k, v in self._failures.items() if v and now - v[-1] < self.window}

    def succeeded(self, key):
        with self._lock:
            self._failures.pop(key, None)
