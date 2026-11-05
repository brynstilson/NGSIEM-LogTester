"""The clone-and-ingest workflow: validate log, clone connector, get credentials, POST."""
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from falcon_client import REDACTED, DeleteRefused, FalconError, api_errors, first_resource

MODE_EVENT = "event"
MODE_RAW = "raw"
COLLECTOR_PATH = "/services/collector"
MAX_CONNECTION_NAME = 50
RETRYABLE_INGEST_STATUSES = {401, 403, 404, 429}  # A new token can take a moment to become valid.
GENERIC_HEC_NAME = re.compile(r"\bhec\b|http event", re.IGNORECASE)


@dataclass
class Settings:
    token_wait_seconds: float = 120
    token_poll_seconds: float = 5
    ingest_attempts: int = 6  # In live testing, some new tokens were still rejected after 15 seconds.
    ingest_retry_seconds: float = 5
    ingest_ready_wait_seconds: float = 5
    cleanup_attempts: int = 3
    cleanup_retry_seconds: float = 5
    request_timeout: float = 30
    enable_enrichment: bool = True


def _norm(value):
    return (value or "").strip().lower()


def is_pull(connection):
    return _norm(connection.get("source_type")) == "pull"


def connector_section(connection):
    """Which dropdown section a connection belongs in."""
    source_type = _norm(connection.get("source_type"))
    return source_type if source_type in ("push", "pull") else "other"


def parse_log(text):
    """Parse the operator's JSON into a list of event objects."""
    def reject_constant(name):
        raise ValueError(f"{name} is not valid JSON")

    if not (text or "").strip():
        raise FalconError("No JSON log was provided.")
    try:
        parsed = json.loads(text, parse_constant=reject_constant)
    except ValueError as exc:
        raise FalconError(f"The log is not valid JSON: {exc}. To send plain text, use Raw mode.") from exc
    events = parsed if isinstance(parsed, list) else [parsed]
    if not events or not all(isinstance(event, dict) for event in events):
        raise FalconError("The log must be a JSON object or a non-empty array of objects.")
    return events


def build_payload(text, events, mode):
    """Return (body, content type) for the ingest POST.

    Event mode wraps each log in the HEC envelope, always, because `event` is also a common
    field name in raw logs. Raw mode sends a single log byte for byte, and arrays as one
    compact JSON object per line.
    """
    if mode == MODE_RAW:
        body = text.strip() if len(events) == 1 else "\n".join(json.dumps(e) for e in events)
        return body, "text/plain; charset=utf-8"
    return "\n".join(json.dumps({"event": e}) for e in events), "application/json"


def prepare_log(text, mode, log):
    """Validate the operator's log and return (body, content type) for the ingest POST.

    Event mode needs JSON, because the HEC envelope wraps an object. Raw mode also takes anything
    else unchanged, such as a syslog line, so a parser can receive a log in its native format.
    """
    if mode == MODE_RAW:
        if not (text or "").strip():
            raise FalconError("No log was provided.")
        try:
            events = parse_log(text)
        except FalconError:
            log.info(f"Not a JSON event, so sending it as plain text: {len(text.strip())} characters, raw mode.")
            return text.strip(), "text/plain; charset=utf-8"
    else:
        events = parse_log(text)
    body, content_type = build_payload(text, events, mode)
    log.info(f"Validated log: {len(events)} event(s), {len(body)} characters, {mode} mode.")
    return body, content_type


def build_ingest_url(ingest_url, mode):
    """Target the HEC collector path, and its /raw variant in raw mode."""
    url = ingest_url.rstrip("/")
    if not urlsplit(url).path:
        url += COLLECTOR_PATH
    if mode == MODE_RAW and not url.endswith("/raw"):
        url += "/raw"
    return url


def resolve_connector(connection, catalog, log):
    """Find the catalog connector a connection was built from.

    The API does not return connector_id when reading a connection, so it has to be inferred.
    Refuses to guess when more than one connector fits.
    """
    parser = connection.get("parser_name")
    push = [c for c in catalog if _norm(c.get("type")) == "push"]
    has_parser = lambda c: parser in (c.get("parsers") or [])

    vendor = _norm(connection.get("vendor_name"))
    product = _norm(connection.get("vendor_product_name"))
    by_vendor = [
        c for c in push
        if vendor and _norm(c.get("vendor_name")) == vendor and _norm(c.get("vendor_product_name")) == product
    ]
    by_vendor_and_parser = [c for c in by_vendor if has_parser(c)]
    by_parser = [c for c in push if has_parser(c)]
    generic_hec = [c for c in push if GENERIC_HEC_NAME.search(c.get("name") or "")]

    candidates = by_vendor_and_parser or by_vendor
    for rule, matches in (
        ("same vendor and product", candidates),
        (f"only push connector supporting parser '{parser}'", by_parser),
        ("generic HEC connector", generic_hec),
    ):
        if len(matches) == 1:
            log.info(f"Resolved source connector: {matches[0].get('name')}", f"Matched on: {rule}\nconnector_id: {matches[0].get('id')}")
            return matches[0]
        if matches and matches is candidates:
            break

    names = ", ".join(f"{c.get('name')} ({c.get('id')})" for c in (candidates or by_parser or generic_hec)) or "none"
    raise FalconError(
        f"Could not determine which connector '{connection.get('name')}' was built from, so nothing "
        f"was cloned. Candidates: {names}"
    )


def resolve_hec_connector(catalog, parser, log):
    """Find the generic HEC connector that stands in for a pull connector.

    A pull connector can't receive a POST, so its clone is always built from this connector.
    Refuses to guess when more than one connector fits.
    """
    matches = [
        c for c in catalog
        if _norm(c.get("type")) == "push" and GENERIC_HEC_NAME.search(c.get("name") or "")
    ]
    if len(matches) != 1:
        names = ", ".join(f"{c.get('name')} ({c.get('id')})" for c in matches) or "none"
        raise FalconError(f"Could not identify one generic HEC connector, so nothing was cloned. Candidates: {names}")
    connector = matches[0]
    log.info(f"Resolved HEC connector for the clone: {connector.get('name')}", f"connector_id: {connector.get('id')}")
    if parser not in (connector.get("parsers") or []):
        log.info(f"Parser '{parser}' isn't in the HEC connector's listed parsers. Applying it anyway.")
    return connector


def verify_clone_parser(client, clone, parser, log):
    """Confirm Falcon applied the source's exact parser before any log is sent."""
    actual = client.get_connection(clone["id"], log).get("parser_name")
    if actual != parser:
        raise FalconError(f"The clone's parser is '{actual}', not the source's '{parser}', so the log wasn't sent.")
    log.info(f"Confirmed the clone uses parser '{parser}'.")


def clone_connection(client, connection, connector, settings, log):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    kind = "HEC clone" if is_pull(connection) else "Clone"
    suffix = f"-clone-{stamp}"
    # Falcon silently cuts longer names, and the delete limiter would then refuse the clone.
    source_name = (connection.get("name") or "")[:MAX_CONNECTION_NAME - len(suffix)].rstrip()
    body = {
        "connector_id": connector["id"],
        "name": f"{source_name}{suffix}",
        "parser": connection.get("parser_name"),
        "description": f"{kind} of {connection.get('name')} ({connection.get('id')}) for log testing.",
        # The API never returns these for the source, so they can't be copied from it.
        "enable_host_enrichment": settings.enable_enrichment,
        "enable_user_enrichment": settings.enable_enrichment,
        "log_sources": [],
    }
    for field in ("vendor_name", "vendor_product_name"):
        if connection.get(field):
            body[field] = connection[field]
    clone_id = client.create_connection(body, log)
    log.info(f"Created cloned connector {body['name']}", f"id: {clone_id}\nparser: {body['parser']}")
    return clone_id, body["name"]


def _poll_token(fetch, settings, log):
    """Call a token endpoint until it stops answering 202 ConnectionNotReady."""
    deadline = time.monotonic() + settings.token_wait_seconds
    while True:
        response = fetch()
        if response.status_code != 202:
            return response
        if time.monotonic() >= deadline:
            raise FalconError(
                f"The cloned connector was still provisioning after {settings.token_wait_seconds:g} seconds."
            )
        log.info(f"Connector still provisioning. Retrying in {settings.token_poll_seconds:g}s.")
        time.sleep(settings.token_poll_seconds)


def get_ingest_credentials(client, clone_id, settings, log):
    """Return (token, ingest URL) for a new connector.

    Falcon only reveals a token once, so a GET that comes back without one falls through to
    regenerating, which is safe here because nothing else has used this clone's token.
    """
    response = _poll_token(lambda: client.get_ingest_token(clone_id, log), settings, log)
    resource = first_resource(response.json()) if response.ok else None
    if not resource or not resource.get("token"):
        log.info("No token from the read call. Generating one instead.")
        response = _poll_token(lambda: client.regenerate_ingest_token(clone_id, log), settings, log)
        if not response.ok:
            raise FalconError(f"Could not get the ingest token: {api_errors(response)}")
        resource = first_resource(response.json())
        if not resource or not resource.get("token"):
            raise FalconError("Falcon did not return an ingest token for the cloned connector.")

    token = resource["token"]
    log.add_secret(token)
    log.info("Retrieved ingest token (not stored or displayed).")
    ingest_url = resource.get("ingest_url") or resource.get("url")
    if not ingest_url:
        ingest_url = client.get_connection(clone_id, log).get("ingest_url")
    if not ingest_url:
        raise FalconError("Falcon did not return an ingest URL for the cloned connector.")
    log.info(f"Retrieved ingest URL: {ingest_url}")
    return token, ingest_url


def post_log(url, token, body, content_type, settings, log):
    """POST to the ingest URL, retrying what a just-created connector may briefly reject."""
    # In live testing, a new token got a 401 on an immediate POST and was accepted 5 seconds later.
    log.info(f"Waiting {settings.ingest_ready_wait_seconds:g}s for the new ingest token to become active.")
    time.sleep(settings.ingest_ready_wait_seconds)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": content_type}
    logged_headers = {"Authorization": f"Bearer {REDACTED}", "Content-Type": content_type}
    failure = None
    for attempt in range(1, settings.ingest_attempts + 1):
        try:
            response = requests.post(url, data=body.encode("utf-8"), headers=headers, timeout=settings.request_timeout)
        except requests.RequestException as exc:
            log.http("POST", url, request_headers=logged_headers, request_body=body, error=exc)
            failure = "Could not reach the ingest URL. See the verbose log for details."
        else:
            log.http("POST", url, response, request_headers=logged_headers, request_body=body)
            if response.ok:
                return check_ingest_response(response)
            failure = f"The ingest URL returned HTTP {response.status_code}."
            if response.status_code not in RETRYABLE_INGEST_STATUSES and response.status_code < 500:
                raise FalconError(failure)
        if attempt < settings.ingest_attempts:
            log.info(f"Ingest attempt {attempt} of {settings.ingest_attempts} failed. Retrying in {settings.ingest_retry_seconds:g}s.")
            time.sleep(settings.ingest_retry_seconds)
    raise FalconError(failure)


def check_ingest_response(response):
    """A 2xx can still report a rejected or truncated event in its body."""
    try:
        payload = response.json()
    except ValueError:
        return
    if not isinstance(payload, dict):
        return
    if payload.get("#error") in (True, "true"):
        raise FalconError(f"Ingest reported an error: {payload.get('@error_msg') or 'unknown error'}")
    if payload.get("code") not in (None, 0):
        raise FalconError(f"Ingest reported an error: {payload.get('text') or payload.get('code')}")


def delete_clone(client, clone, settings, log, record=lambda event, **fields: None):
    """Delete the clone, retrying because one still provisioning may refuse. Returns any error."""
    failure = None
    for attempt in range(1, settings.cleanup_attempts + 1):
        try:
            client.delete_connection(clone["id"], log)
        except DeleteRefused as exc:  # Retrying can't change a refusal.
            log.error(str(exc))
            record("clone_delete_refused", clone=clone, reason=str(exc))
            return str(exc)
        except FalconError as exc:
            failure = str(exc)
        else:
            log.info(f"Deleted cloned connector {clone['name']}", f"id: {clone['id']}")
            return None
        if attempt < settings.cleanup_attempts:
            log.info(f"Delete attempt {attempt} of {settings.cleanup_attempts} failed. Retrying in {settings.cleanup_retry_seconds:g}s.")
            time.sleep(settings.cleanup_retry_seconds)
    log.error(f"Could not delete cloned connector {clone['name']}", f"id: {clone['id']}\nerror: {failure}")
    return failure


def submit_log(client, connection, text, mode, settings, log, record=lambda event, **fields: None):
    """Run the whole workflow. Returns the clone's details, or raises FalconError.

    `record` receives forensic events as they happen, so a clone stays traceable even if the
    process dies before the workflow finishes.
    """
    body, content_type = prepare_log(text, mode, log)

    parser = connection.get("parser_name")
    pull = is_pull(connection)
    if pull and not parser:
        raise FalconError(f"Pull connector '{connection.get('name')}' has no parser assigned. Nothing was cloned.")
    log.info(
        f"Source connector: {connection.get('name')}",
        f"id: {connection.get('id')}\ntype: {connection.get('source_type')}\nparser: {parser}",
    )
    catalog = client.list_connector_catalog(log)
    if pull:
        record("source_parser_stored", source_connector_id=connection.get("id"), parser=parser)
        connector = resolve_hec_connector(catalog, parser, log)
    else:
        connector = resolve_connector(connection, catalog, log)

    clone_id, clone_name = clone_connection(client, connection, connector, settings, log)
    clone = {
        "id": clone_id,
        "name": clone_name,
        "parser": parser,
        "built_from_connector_id": connector["id"],
        "source_type": connection.get("source_type"),
    }
    record("clone_created", clone=clone)

    error = None
    try:
        token, ingest_url = get_ingest_credentials(client, clone_id, settings, log)
        if pull:
            verify_clone_parser(client, clone, parser, log)
        post_log(build_ingest_url(ingest_url, mode), token, body, content_type, settings, log)
    except FalconError as exc:
        error = str(exc)
    except Exception as exc:  # Whatever went wrong, the clone still has to be cleaned up.
        log.error(f"Unexpected {type(exc).__name__}", str(exc))
        error = f"Unexpected {type(exc).__name__}. See the verbose log for details."

    cleanup_error = delete_clone(client, clone, settings, log, record)
    label = f"{clone_name} ({clone_id})"
    if cleanup_error:
        record("clone_delete_failed", clone=clone, error=cleanup_error)
        leftover = f"Cloned connector {label} could not be deleted, so remove it manually: {cleanup_error}"
        raise FalconError(f"{error} {leftover}" if error else f"The log was accepted. {leftover}")
    record("clone_deleted", clone=clone)
    if error:
        raise FalconError(f"{error} Cloned connector {label} was deleted.")
    return clone
