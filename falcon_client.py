"""Thin CrowdStrike Falcon API client plus the verbose activity log shown to operators."""
import json
import threading
import time
from datetime import datetime, timezone

import requests

SENSITIVE_KEYS = {"token", "access_token", "client_secret", "authorization", "api_key"}
MAX_LOGGED_CHARS = 20000
REDACTED = "***REDACTED***"
PAGE_SIZE = 100


class FalconError(Exception):
    """A failure that should be reported to the operator."""


class DeleteRefused(FalconError):
    """The delete limiter stopped a delete before it reached Falcon."""


def redact(value):
    """Return a copy of a JSON value with sensitive keys masked."""
    if isinstance(value, dict):
        return {k: REDACTED if k.lower() in SENSITIVE_KEYS else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


class ActivityLog:
    """Timestamped steps for one operation. Secrets never survive into an entry."""

    def __init__(self):
        self.entries = []
        self._secrets = set()

    def add_secret(self, secret):
        if secret:
            self._secrets.add(secret)

    def _scrub(self, text):
        for secret in self._secrets:
            text = text.replace(secret, REDACTED)
        if len(text) > MAX_LOGGED_CHARS:
            text = f"{text[:MAX_LOGGED_CHARS]}\n... truncated ({len(text)} chars total)"
        return text

    def add(self, level, title, detail=None):
        self.entries.append({
            "time": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": level,
            "title": self._scrub(title),
            "detail": self._scrub(detail) if detail else None,
        })

    def info(self, title, detail=None):
        self.add("info", title, detail)

    def error(self, title, detail=None):
        self.add("error", title, detail)

    def http(self, method, url, response=None, request_body=None, request_headers=None, error=None):
        """Record one HTTP exchange. Response bodies that aren't JSON are logged after scrubbing."""
        lines = [f"{method} {url}"]
        for name, value in (request_headers or {}).items():
            lines.append(f"> {name}: {value}")
        if request_body is not None:
            lines.append(f"> body:\n{request_body}")
        if error is not None:
            self.error(f"{method} {url} failed", "\n".join(lines + [f"< error: {error}"]))
            return
        trace_id = response.headers.get("X-Cs-TraceId")
        lines.append(f"< HTTP {response.status_code} {response.reason}")
        if trace_id:
            lines.append(f"< X-Cs-TraceId: {trace_id}")
        try:
            body = json.dumps(redact(response.json()), indent=2)
        except ValueError:
            body = response.text
        if body:
            lines.append(f"< body:\n{body}")
        level = "info" if response.ok else "error"
        self.add(level, f"{method} {url} -> HTTP {response.status_code}", "\n".join(lines))


def api_errors(response):
    """Pull a readable message out of a Falcon error response."""
    try:
        errors = response.json().get("errors") or []
        messages = [e.get("message", str(e)) if isinstance(e, dict) else str(e) for e in errors]
    except (ValueError, AttributeError):
        messages = []
    return "; ".join(messages) or f"HTTP {response.status_code}"


def first_resource(payload):
    """Return the single resource from a Falcon envelope.

    `resources` is a list on most endpoints but a bare object on the token endpoints.
    """
    resources = (payload or {}).get("resources")
    if isinstance(resources, list):
        return resources[0] if resources else None
    return resources


class FalconClient:
    def __init__(self, client_id, client_secret, base_url, timeout=30):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._access_token = None
        self._expires_at = 0
        self._lock = threading.Lock()
        self._created_clones = {}  # ID -> name. The only connections this client may delete.

    def _authenticate(self, log):
        if not self.client_id or not self.client_secret:
            raise FalconError("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are not set. See README.md.")
        url = f"{self.base_url}/oauth2/token"
        try:
            response = requests.post(
                url,
                data={"client_id": self.client_id, "client_secret": self.client_secret},
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            log.http("POST", url, error=exc)
            raise FalconError(f"Could not reach {self.base_url}. See the verbose log for details.") from exc
        log.http("POST", url, response)
        if not response.ok:
            raise FalconError(f"Falcon authentication failed: {api_errors(response)}")
        payload = response.json()
        self._access_token = payload["access_token"]
        # Refresh a minute early so a token can't expire mid-workflow.
        self._expires_at = time.time() + payload.get("expires_in", 1799) - 60

    def _token(self, log, force=False):
        with self._lock:
            if force or not self._access_token or time.time() >= self._expires_at:
                self._authenticate(log)
            return self._access_token

    def request(self, method, path, log, params=None, body=None):
        """Call a Falcon API route, re-authenticating once on a 401."""
        url = f"{self.base_url}{path}"
        logged_body = json.dumps(redact(body), indent=2) if body is not None else None
        logged_url = requests.Request(method, url, params=params).prepare().url
        response = None
        for attempt in (1, 2):
            headers = {"Authorization": f"Bearer {self._token(log, force=attempt == 2)}"}
            try:
                response = requests.request(
                    method, url, params=params, json=body, headers=headers, timeout=self.timeout
                )
            except requests.RequestException as exc:
                log.http(method, logged_url, request_body=logged_body, error=exc)
                raise FalconError(f"Could not reach {self.base_url}. See the verbose log for details.") from exc
            log.http(method, logged_url, response, request_body=logged_body)
            if response.status_code != 401:
                break
        return response

    def _list_all(self, path, log):
        items, offset = [], 0
        while True:
            response = self.request("GET", path, log, params={"limit": PAGE_SIZE, "offset": offset})
            if not response.ok:
                raise FalconError(f"GET {path} failed: {api_errors(response)}")
            payload = response.json()
            page = payload.get("resources") or []
            items.extend(page)
            offset += len(page)
            total = ((payload.get("meta") or {}).get("pagination") or {}).get("total")
            if not page or (total is not None and offset >= total) or (total is None and len(page) < PAGE_SIZE):
                return items

    def list_connections(self, log):
        """Data connections configured in this tenant (the console's data connectors list)."""
        return self._list_all("/ngsiem/combined/connections/v1", log)

    def list_connector_catalog(self, log):
        """Connector types available to instantiate a connection from."""
        return self._list_all("/ngsiem/combined/connectors/v1", log)

    def get_connection(self, connection_id, log):
        response = self.request("GET", "/ngsiem/entities/connections/v1", log, params={"ids": connection_id})
        if not response.ok:
            raise FalconError(f"Could not read data connector {connection_id}: {api_errors(response)}")
        connection = first_resource(response.json())
        if not connection:
            raise FalconError(f"Data connector {connection_id} was not found.")
        return connection

    def create_connection(self, body, log):
        response = self.request("POST", "/ngsiem/entities/connections/v1", log, body=body)
        if not response.ok:
            raise FalconError(f"Could not create the cloned connector: {api_errors(response)}")
        created = first_resource(response.json())
        if not created or not created.get("id"):
            raise FalconError("Falcon did not return an ID for the cloned connector.")
        with self._lock:
            self._created_clones[created["id"]] = body["name"]
        return created["id"]

    def delete_connection(self, connection_id, log):
        """Delete a clone this client created, and nothing else.

        Raises DeleteRefused for any other connection. This is the app's only delete call, so
        every delete passes the limiter. An ID can be deleted once, and the list of IDs is
        held in memory, so a clone left behind by a restart has to be removed by hand.
        """
        with self._lock:
            expected_name = self._created_clones.get(connection_id)
        if expected_name is None:
            raise DeleteRefused(f"Refused to delete {connection_id}: this submission didn't create it.")
        # A failed read raises here, so a connector that can't be checked is never deleted.
        actual_name = self.get_connection(connection_id, log).get("name")
        if actual_name != expected_name:
            raise DeleteRefused(
                f"Refused to delete {connection_id}: its name is '{actual_name}', not the "
                f"expected '{expected_name}'."
            )
        response = self.request("DELETE", "/ngsiem/entities/connections/v1", log, params={"ids": connection_id})
        try:
            has_errors = bool(response.json().get("errors"))
        except (ValueError, AttributeError):
            has_errors = False
        if response.status_code != 404 and (not response.ok or has_errors):
            raise FalconError(api_errors(response))
        with self._lock:
            del self._created_clones[connection_id]

    def list_correlation_rules(self, log):
        """Every configured correlation rule version. Needs the Correlation Rules: Read scope."""
        items, offset = [], 0
        while True:
            response = self.request("GET", "/correlation-rules/combined/rules/v1", log,
                                    params={"limit": 500, "offset": offset})
            if not response.ok:
                raise FalconError(f"Could not read correlation rules: {api_errors(response)}")
            payload = response.json()
            page = payload.get("resources") or []
            items.extend(page)
            offset += len(page)
            total = ((payload.get("meta") or {}).get("pagination") or {}).get("total")
            if not page or (total is not None and offset >= total) or (total is None and len(page) < 500):
                return items

    def list_correlation_rule_templates(self, log):
        """CrowdStrike's built-in correlation rule templates."""
        ids, offset = [], 0
        while True:
            response = self.request("GET", "/correlation-rules/queries/templates/v1", log,
                                    params={"limit": 100, "offset": offset})
            if not response.ok:
                raise FalconError(f"Could not list correlation rule templates: {api_errors(response)}")
            payload = response.json()
            page = payload.get("resources") or []
            ids.extend(page)
            offset += len(page)
            total = ((payload.get("meta") or {}).get("pagination") or {}).get("total")
            if not page or (total is not None and offset >= total) or (total is None and len(page) < 100):
                break
        templates = []
        for start in range(0, len(ids), 100):
            response = self.request("GET", "/correlation-rules/entities/templates/v1", log,
                                    params={"ids": ids[start:start + 100]})
            if not response.ok:
                raise FalconError(f"Could not read correlation rule templates: {api_errors(response)}")
            templates.extend(response.json().get("resources") or [])
        return templates

    def list_parsers(self, log, repository="parsers-repository"):
        """Every NG-SIEM parser: name, ID with version, vendor and product. Needs NGSIEM Parsers: Read."""
        items, offset = [], 0
        while True:
            response = self.request("GET", "/ngsiem-content/queries/parsers/v1", log,
                                    params={"limit": 100, "offset": offset, "repository": repository})
            if not response.ok:
                raise FalconError(f"Could not list parsers: {api_errors(response)}")
            payload = response.json()
            page = payload.get("resources") or []
            items.extend(page)
            offset += len(page)
            total = ((payload.get("meta") or {}).get("pagination") or {}).get("total")
            if not page or (total is not None and offset >= total) or (total is None and len(page) < 100):
                return items

    def get_parser_template(self, parser_id, log, repository="parsers-repository"):
        """One parser's definition as YAML text. parser_id is the full ID:version form."""
        response = self.request("GET", "/ngsiem-content/entities/parsers-template/v1", log,
                                params={"ids": [parser_id], "repository": repository})
        if not response.ok:
            raise FalconError(f"Could not read parser {parser_id}: {api_errors(response)}")
        resource = first_resource(response.json())
        if not isinstance(resource, dict) or not resource.get("yaml_template"):
            raise FalconError(f"Parser {parser_id} has no definition.")
        return resource

    def start_search(self, repository, query, start, log, end="now"):
        """Start an NG-SIEM search job and return its ID. Needs the NGSIEM: Write scope."""
        response = self.request("POST", f"/humio/api/v1/repositories/{repository}/queryjobs", log,
                                body={"queryString": query, "start": start, "end": end, "isLive": False})
        if response.status_code == 403:
            raise FalconError("NG-SIEM search isn't allowed for this API client. Add the NGSIEM: Write scope "
                              "(it covers starting searches) to verify submissions.")
        if not response.ok:
            raise FalconError(f"Could not start an NG-SIEM search: {api_errors(response)}")
        job = response.json()
        job_id = job.get("id") or (first_resource(job) or {}).get("id")
        if not job_id:
            raise FalconError("NG-SIEM didn't return a search job ID.")
        return job_id

    def get_search(self, repository, job_id, log):
        """One poll of an NG-SIEM search job: {"done": bool, "events": [...]}."""
        response = self.request("GET", f"/humio/api/v1/repositories/{repository}/queryjobs/{job_id}", log)
        if not response.ok:
            raise FalconError(f"Could not read NG-SIEM search results: {api_errors(response)}")
        return response.json()

    def get_ingest_token(self, connection_id, log):
        return self.request("GET", "/ngsiem/entities/connections/token/v1", log, params={"ids": connection_id})

    def regenerate_ingest_token(self, connection_id, log):
        return self.request("POST", "/ngsiem/entities/connections/token/v1", log, params={"ids": connection_id})
