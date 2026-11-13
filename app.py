"""Operator web app for testing a raw JSON log against a clone of an NG-SIEM data connector."""
import getpass
import hashlib
import os
import secrets
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request, send_file
from werkzeug.serving import WSGIRequestHandler

from app_settings import AppSettings, SettingsError
from security import LOOPBACK_NAMES, RateLimiter, Throttle, host_allowed, parse_allowed_hosts, password_matches

from falcon_client import ActivityLog, FalconClient, FalconError
from forensic_log import ForensicLog
from field_model import PROFILES
from parsers import ParserStore
from rules import RuleBook, evaluate, events_of, group, judge, raw_of, refresh_minutes_from, rule_templates, template_entry
from simulation import Simulation
from suggest import apply_suggestion
from verify import verify
from sample_events import SAMPLE_IDS, list_samples, render_sample
from workflow import MODE_EVENT, MODE_RAW, Settings, connector_section, is_pull, submit_log


def _summary(connection):
    return {
        "id": connection.get("id"),
        "name": connection.get("name"),
        "parser": connection.get("parser_name"),
        "status": connection.get("status"),
        "source_type": connection.get("source_type"),
        "vendor_name": connection.get("vendor_name"),
        "vendor_product_name": connection.get("vendor_product_name"),
        "section": connector_section(connection),
    }


MAX_CONNECTOR_ID = 200
SUBMIT_RULES_MAX_AGE = 60        # seconds: configured rules older than this are re-read at submit
FALCON_REQUESTS_PER_MINUTE = 30   # per client address, for the routes that call the Falcon API
CONNECTOR_LIST_MIN_AGE = 30       # seconds before an unknown connector ID may trigger a new listing

# Routes that call the Falcon API. /api/evaluate isn't here: it only uses cached rules and connectors.
FALCON_ROUTES = {"list_connectors", "select_connector", "list_rules", "list_rule_templates", "submit", "verify_submission"}
RECENT_SUBMISSIONS = 50  # kept in memory so they can be verified in NG-SIEM afterwards


def create_app(client=None, settings=None, forensic=None, app_settings=None, admin_password=None,
               access_password=None, allowed_hosts=None, throttle=None, rate_limiter=None, clock=time.monotonic,
               rule_refresh_minutes=None, simulation=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
    app_settings = app_settings or AppSettings()
    # Optional. When set, only someone with the password can change the settings.
    admin_password = os.environ.get("APP_ADMIN_PASSWORD") if admin_password is None else admin_password
    # Optional on localhost, required when other machines can connect: the password for every page.
    access_password = os.environ.get("APP_ACCESS_PASSWORD") if access_password is None else access_password
    allowed_hosts = parse_allowed_hosts(os.environ.get("APP_ALLOWED_HOSTS") if allowed_hosts is None else allowed_hosts)
    throttle = throttle or Throttle()
    rate_limiter = rate_limiter or RateLimiter(FALCON_REQUESTS_PER_MINUTE)
    # Connector IDs from the latest listing. Only these are ever read from Falcon or cached.
    known = {"ids": set(), "listed_at": None}
    known_lock = threading.Lock()
    settings = settings or Settings()
    forensic = forensic or ForensicLog()
    client = client or FalconClient(
        os.environ.get("FALCON_CLIENT_ID"),
        os.environ.get("FALCON_CLIENT_SECRET"),
        os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    selected = {}  # connection ID -> details read when the operator selected it
    if rule_refresh_minutes is None:
        rule_refresh_minutes = refresh_minutes_from(os.environ.get("RULE_REFRESH_MINUTES"))
    rulebook = RuleBook(client, rule_refresh_minutes)
    app.extensions["rulebook"] = rulebook
    # Runs each connector's real parser (read live with NGSIEM Parsers: Read) to predict the parsed
    # event. Without that scope or with PARSER_SIMULATION=off, the approximate field mappings are used.
    if simulation is None:
        off = str(os.environ.get("PARSER_SIMULATION", "on")).lower() in ("off", "0", "false", "no")
        simulation = Simulation(None if off else ParserStore(client))
    app.extensions["simulation"] = simulation
    template_cache = {}
    submissions = OrderedDict()  # submission ID -> what's needed to verify it later

    def entry_for(rule):
        """The generated sample for one rule, built once per rule version."""
        key = (rule["key"], rule["query"], rule["enabled"])
        if key not in template_cache:
            template_cache[key] = template_entry(rule, simulation)
        return template_cache[key]

    def public(rule):
        return {key: value for key, value in rule.items() if not key.startswith("_")}

    def locked_out(key):
        wait = throttle.retry_after(f"{key}:{request.remote_addr}")
        if not wait:
            return None
        response = jsonify(success=False, message=f"Too many wrong passwords. Try again in {wait} seconds.", log=[])
        response.status_code = 429
        response.headers["Retry-After"] = str(wait)
        return response

    def remember_connectors(connections):
        """Record the IDs from a listing, and drop cached details for connectors that no longer exist."""
        ids = {c.get("id") for c in connections if c.get("id")}
        with known_lock:
            known["ids"], known["listed_at"] = ids, clock()
            for stale in [cid for cid in selected if cid not in ids]:
                selected.pop(stale, None)

    def connector_known(connection_id, log):
        """Whether an ID came from a connector listing. An unknown ID triggers at most one new listing
        every CONNECTOR_LIST_MIN_AGE seconds, so made-up IDs can't drive unlimited Falcon API calls."""
        if not isinstance(connection_id, str) or not connection_id or len(connection_id) > MAX_CONNECTOR_ID:
            return False
        with known_lock:
            if connection_id in known["ids"]:
                return True
            fresh = known["listed_at"] is not None and clock() - known["listed_at"] < CONNECTOR_LIST_MIN_AGE
        if fresh:
            return False
        try:
            remember_connectors(client.list_connections(log))
        except FalconError as exc:
            log.error(str(exc))
            with known_lock:
                known["listed_at"] = clock()  # A failed listing also waits before it's retried.
            return False
        with known_lock:
            return connection_id in known["ids"]

    def unknown_connector(connection_id, log):
        message = f"Unknown data connector: {str(connection_id)[:MAX_CONNECTOR_ID]}. Click Refresh and choose it again."
        log.error(message)
        return jsonify(success=False, message=message, log=log.entries), 404

    @app.before_request
    def guard():
        g.csp_nonce = secrets.token_urlsafe(16)
        if not host_allowed(request.host, allowed_hosts):
            return jsonify(success=False, message="Unknown host name. Add it to APP_ALLOWED_HOSTS.", log=[]), 421
        g.operator_login = None
        if access_password:
            refusal = locked_out("access")
            if refusal:
                return refusal
            auth = request.authorization
            if auth and auth.type == "basic" and password_matches(auth.password, access_password):
                throttle.succeeded(f"access:{request.remote_addr}")
                g.operator_login = (auth.username or "")[:80] or None
            else:
                if auth:
                    throttle.failed(f"access:{request.remote_addr}")
                response = jsonify(success=False, message="Sign in with the operator password.", log=[])
                response.status_code = 401
                response.headers["WWW-Authenticate"] = 'Basic realm="NG-SIEM Log Tester", charset="UTF-8"'
                return response
        if request.endpoint in FALCON_ROUTES:
            wait = rate_limiter.retry_after(request.remote_addr)
            if wait:
                response = jsonify(success=False, log=[],
                                   message=f"Too many requests that call the Falcon API. Try again in {wait} seconds.")
                response.status_code = 429
                response.headers["Retry-After"] = str(wait)
                return response
        return None

    @app.after_request
    def security_headers(response):
        if response.mimetype == "text/html":
            nonce = g.get("csp_nonce", "")
            policy = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                      "img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        else:
            policy = "default-src 'none'; frame-ancestors 'none'"
        response.headers.setdefault("Content-Security-Policy", policy)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    def parser_for(connection_id, log):
        """The selected connector's parser, which decides what a rule would see."""
        connection = selected.get(connection_id) if isinstance(connection_id, str) else None
        if connection is None:
            if not connector_known(connection_id, log):
                return None
            try:
                connection = selected[connection_id] = client.get_connection(connection_id, log)
            except FalconError:
                return None
        return connection.get("parser_name")

    def sample_parser(sample_id):
        """The parser a selected sample or rule template was written for."""
        if not isinstance(sample_id, str):
            return None
        if sample_id.startswith("rule:"):
            rule = rulebook.find(sample_id[len("rule:"):])
            entry = entry_for(rule) if rule else None
            return (entry or {}).get("parser") or (rule["parser"] if rule else None)
        return next((key for key, profile in PROFILES.items() if profile.get("sample") == sample_id), None)

    def rule_check(text, mode, connection_id, log, sample_id=None, include_templates=False, max_age=None):
        """Judge a submission against configured rules, and templates too if the operator loaded them."""
        rules, error = rulebook.load(log, include_templates=include_templates, max_age=max_age)
        parser = parser_for(connection_id, log) or sample_parser(sample_id)
        checked = evaluate(rules, text, mode, parser, simulation)
        checked["parser"] = parser
        return rules, checked, error

    def simulation_summary(text, mode, parser):
        """The simulated parsed event(s) for the page's information icon, or None."""
        if not parser or not simulation.active:
            return None
        doc = simulation.parser(parser)
        if not doc:
            return {"available": False, "parser": parser,
                    "message": "The parser couldn't be read, so field names are approximate. "
                               "Check that the API client has the NGSIEM Parsers: Read scope."}
        events = []
        for event in events_of(text, mode)[:5]:
            result = simulation.run(parser, raw_of(event))
            if result is None:
                continue
            fields = {k: v for k, v in sorted(result.fields.items()) if k != "@rawstring"}
            tags = {f"#{t}": result.fields[t] for t in result.tag_fields if t in result.fields}
            events.append({"dropped": result.dropped, "tags": tags, "fields": dict(list(fields.items())[:400]),
                           "unknown": sorted(result.unknown), "unsupported": result.unsupported,
                           "error": result.error, "approximate": result.approximate})
        return {"available": True, "parser": doc["name"], "version": doc["version"], "events": events}

    def wants_templates():
        return request.args.get("templates") == "1"

    @app.get("/")
    def index():
        # The saved title goes in the first paint, so the default never flashes up.
        return render_template("index.html", title=app_settings.read()["title"], csp_nonce=g.csp_nonce,
                               rule_refresh_minutes=rulebook.refresh_minutes)

    @app.get("/api/rules/status")
    def rules_status():
        # Cheap: no Falcon call. The page polls this and reloads its rule samples when the version changes.
        return jsonify(success=True, **rulebook.status())

    def settings_payload():
        values = app_settings.read()
        return {**values, "logo_url": "/branding/logo" if values["logo"] else None,
                "password_required": bool(admin_password)}

    def admin_refusal():
        """Why a settings change is refused, or None. Also blocks cross-site form posts."""
        # A custom header can't be sent by another site's form or image without a CORS preflight.
        if request.headers.get("X-Requested-By") != "ngsiem-logtester":
            return jsonify(success=False, message="Missing request header."), 400
        if admin_password:
            refusal = locked_out("admin")
            if refusal:
                return refusal
            if not password_matches(request.headers.get("X-Admin-Password"), admin_password):
                throttle.failed(f"admin:{request.remote_addr}")
                return jsonify(success=False, message="The administrator password is incorrect."), 403
            throttle.succeeded(f"admin:{request.remote_addr}")
        return None

    def record_settings_change(changes):
        try:
            forensic.write("settings_changed", str(uuid.uuid4()), operator=getpass.getuser(),
                           operator_login=g.get("operator_login"), remote_addr=request.remote_addr, changes=changes)
            return None
        except OSError as exc:
            return f"The change was saved, but the forensic log couldn't be written: {exc}"

    @app.get("/api/settings")
    def get_settings():
        return jsonify(success=True, settings=settings_payload())

    @app.post("/api/settings")
    def save_settings():
        refusal = admin_refusal()
        if refusal:
            return refusal
        data = request.get_json(silent=True)
        if not request.is_json or not isinstance(data, dict):
            return jsonify(success=False, message="Expected a JSON request."), 415
        try:
            changed = app_settings.update({k: v for k, v in data.items() if k != "remove_logo"})
        except SettingsError as exc:
            return jsonify(success=False, message=str(exc)), 400
        if data.get("remove_logo") is True and app_settings.read()["logo"]:
            app_settings.remove_logo()
            changed["logo"] = "removed"
        warning = record_settings_change(changed) if changed else None
        return jsonify(success=True, settings=settings_payload(), changed=sorted(changed), message=warning)

    @app.post("/api/settings/logo")
    def upload_logo():
        refusal = admin_refusal()
        if refusal:
            return refusal
        upload = request.files.get("logo")
        if upload is None:
            return jsonify(success=False, message="Choose an image file."), 400
        data = upload.read()
        try:
            name = app_settings.set_logo(data)
        except SettingsError as exc:
            return jsonify(success=False, message=str(exc)), 400
        warning = record_settings_change({"logo": {"file": name, "bytes": len(data),
                                                   "sha256": hashlib.sha256(data).hexdigest()}})
        return jsonify(success=True, settings=settings_payload(), message=warning)

    @app.get("/branding/logo")
    def logo():
        name = app_settings.read()["logo"]
        path = app_settings.logo_path(name)
        if not path:
            return jsonify(success=False, message="No logo is set."), 404
        response = send_file(path, mimetype=app_settings.content_type(name), max_age=0)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    @app.get("/api/connectors")
    def list_connectors():
        log = ActivityLog()
        try:
            connections = client.list_connections(log)
        except FalconError as exc:
            log.error(str(exc))
            return jsonify(success=False, message=str(exc), log=log.entries)
        remember_connectors(connections)
        connectors = sorted((_summary(c) for c in connections), key=lambda c: (c["name"] or "").lower())
        return jsonify(success=True, connectors=connectors, log=log.entries)

    @app.get("/api/connectors/<connection_id>/parser")
    def select_connector(connection_id):
        log = ActivityLog()
        if not connector_known(connection_id, log):
            return unknown_connector(connection_id, log)
        try:
            connection = client.get_connection(connection_id, log)
        except FalconError as exc:
            log.error(str(exc))
            return jsonify(success=False, message=str(exc), log=log.entries)
        selected[connection_id] = connection
        return jsonify(success=True, connector=_summary(connection), log=log.entries)

    @app.get("/api/sample-events")
    def sample_events():
        return jsonify(success=True, samples=list_samples())

    @app.get("/api/rules")
    def list_rules():
        log = ActivityLog()
        rules, error = rulebook.load(log, refresh=request.args.get("refresh") == "1", include_templates=wants_templates())
        return jsonify(
            success=error is None,
            message=error,
            rules=[public(rule) for rule in rules],
            configured=sum(1 for rule in rules if rule["source"] == "configured"),
            enabled=sum(1 for rule in rules if rule["enabled"]),
            templates=sum(1 for rule in rules if rule["source"] == "template"),
            log=log.entries,
        )

    @app.get("/api/rule-templates")
    def list_rule_templates():
        log = ActivityLog()
        rules, error = rulebook.load(log, refresh=request.args.get("refresh") == "1", include_templates=wants_templates())
        entries = rule_templates(rules, simulation, template_cache)
        return jsonify(success=error is None, message=error, templates_loaded=rulebook.templates_loaded(),
                       templates=[{k: v for k, v in entry.items() if k != "log"} for entry in entries])

    @app.post("/api/evaluate")
    def evaluate_log():
        data = request.get_json(silent=True)
        if not request.is_json or not isinstance(data, dict):
            return jsonify(success=False, message="Expected a JSON request."), 415
        log = ActivityLog()
        text = data.get("log") if isinstance(data.get("log"), str) else ""
        rules, checked, error = rule_check(text, data.get("mode", MODE_EVENT), data.get("connector_id"), log,
                                           data.get("sample_id"), data.get("include_templates") is True)
        return jsonify(
            success=True,
            rules_available=error is None,
            message=error,
            rule_count=len(rules),
            events=checked["events"],
            groups=group(checked["results"]),
            will_fire=group(checked["will_fire"]),
            simulation=simulation_summary(text, data.get("mode", MODE_EVENT), checked.get("parser")),
        )

    @app.post("/api/apply-suggestion")
    def apply_suggestion_route():
        """Make a rule check suggestion's change to the operator's log. Nothing is sent anywhere."""
        data = request.get_json(silent=True)
        if not request.is_json or not isinstance(data, dict):
            return jsonify(success=False, message="Expected a JSON request."), 415
        text = data.get("log") if isinstance(data.get("log"), str) else ""
        mode = data.get("mode") if data.get("mode") in (MODE_EVENT, MODE_RAW) else MODE_EVENT
        fix = data.get("fix") if isinstance(data.get("fix"), dict) else {}
        rule_key = data.get("rule_key")
        rule = rulebook.find(rule_key) if isinstance(rule_key, str) else None
        if rule is None:
            return jsonify(success=False, message="That rule isn't loaded. Reload rules and try again."), 404
        log = ActivityLog()
        # The same parser the rule check used: the connector's, the sample's, or the rule's own.
        parser = (parser_for(data.get("connector_id"), log) or sample_parser(data.get("sample_id"))
                  or (entry_for(rule) or {}).get("parser") or rule.get("parser"))
        try:
            outcome = apply_suggestion(rule, text, mode, parser, simulation, fix)
        except Exception as exc:  # A suggestion that can't be applied must not break the page.
            outcome = {"success": False, "message": f"The suggestion couldn't be applied ({type(exc).__name__})."}
        return jsonify(**outcome)

    @app.get("/api/sample-events/<sample_id>")
    def sample_event(sample_id):
        if sample_id.startswith("rule:"):
            rule = rulebook.find(sample_id[len("rule:"):])
            entry = entry_for(rule) if rule else None
            if entry is None:
                return jsonify(success=False, message=f"Unknown rule template: {sample_id}"), 404
            return jsonify(success=True, log=entry["log"], note=entry["note"], verdict=entry["verdict"],
                           parser=entry.get("parser"), reasons=entry.get("reasons", []),
                           incomplete=entry.get("incomplete", False), simulated=entry.get("simulated", False))
        text = render_sample(sample_id)
        if text is None:
            return jsonify(success=False, message=f"Unknown sample event: {sample_id}"), 404
        return jsonify(success=True, log=text)

    @app.post("/api/submit")
    def submit():
        # Requiring a JSON body means another site can't trigger this without a CORS preflight.
        data = request.get_json(silent=True)
        if not request.is_json or not isinstance(data, dict):
            return jsonify(success=False, message="Expected a JSON request.", log=[]), 415
        log = ActivityLog()
        connection_id = data.get("connector_id")
        mode = data.get("mode", MODE_EVENT)
        text = data.get("log") if isinstance(data.get("log"), str) else ""
        # Refuse bad input before anything is written, so failed requests can't fill the forensic log.
        problem = None
        if not isinstance(connection_id, str) or not connection_id.strip() or len(connection_id) > MAX_CONNECTOR_ID:
            problem = "Select a data connector first."
        elif not isinstance(mode, str) or mode not in (MODE_EVENT, MODE_RAW):
            problem = "Unknown send mode."
        elif not text.strip():
            problem = "The log is empty. Paste a log or choose a sample first."
        if problem:
            log.error(problem)
            return jsonify(success=False, message=problem, log=log.entries), 400
        submission_id = str(uuid.uuid4())
        sample_id = data.get("sample_id")
        sample_id = sample_id if isinstance(sample_id, str) and (sample_id in SAMPLE_IDS or sample_id.startswith("rule:")) else None

        # Configured rules this submission would probably fire must be acknowledged first. Templates
        # never fire, so they aren't loaded for this.
        # Rules are re-read if the stored copy is over a minute old, so a rule just enabled in Falcon is checked.
        rules, checked, rule_error = rule_check(text, mode, connection_id, log, max_age=SUBMIT_RULES_MAX_AGE)
        firing = checked["will_fire"]
        acknowledged = data.get("acknowledged_rules") if isinstance(data.get("acknowledged_rules"), list) else []
        unacknowledged = [rule for rule in firing if rule["key"] not in acknowledged]
        if unacknowledged:
            return jsonify(
                success=False,
                needs_acknowledgement=True,
                message="This submission will probably trigger correlation rules in the tenant.",
                will_fire=group(firing),
                log=log.entries,
            )
        rule_summary = {
            "status": "unavailable" if rule_error else "checked",
            "error": rule_error,
            "rules_checked": len(rules),
            "acknowledged": [{"key": r["key"], "name": r["name"], "vendor": r["vendor"], "product": r["product"]} for r in firing],
        }

        # Confirm the connector exists before writing anything. Reading it changes nothing in the tenant.
        # A pull connector is read again here, so its clone gets the parser assigned right now.
        connection = selected.get(connection_id)
        if connection is None and not connector_known(connection_id, log):
            return unknown_connector(connection_id, log)
        if connection is None or is_pull(connection):
            try:
                connection = selected[connection_id] = client.get_connection(connection_id, log)
            except FalconError as exc:
                log.error(str(exc))
                return jsonify(success=False, message=str(exc), log=log.entries)

        # No forensic record means no tenant change, so this write has to succeed first.
        try:
            forensic.write(
                "submission_started",
                submission_id,
                operator=getpass.getuser(),
                operator_login=g.get("operator_login"),
                remote_addr=request.remote_addr,
                api_client_id=client.client_id,
                falcon_base_url=client.base_url,
                connector_id=connection_id,
                mode=mode,
                sample_event_id=sample_id,
                correlation_rule_check=rule_summary,
                log_sha256=hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest(),
                submitted_log=text,
            )
        except OSError as exc:
            message = f"Nothing was sent or cloned, because the forensic log can't be written: {exc}"
            log.error(message)
            return jsonify(success=False, message=message, log=log.entries)
        log.info(f"Forensic record {submission_id} opened in {forensic.path.name}")
        if rule_error:
            log.error("Correlation rules couldn't be checked, so this submission wasn't screened for them.", rule_error)
        elif firing:
            log.info(f"Operator acknowledged {len(firing)} correlation rule(s) that will probably fire: "
                     + ", ".join(rule["name"] for rule in firing))

        unwritten = []

        def record(event, **fields):
            try:
                forensic.write(event, submission_id, **fields)
            except OSError as exc:
                unwritten.append(event)
                log.error(f"Could not write forensic record {event}", str(exc))

        clone = None
        try:
            clone = submit_log(client, connection, text, mode, settings, log, record)
            success = True
            message = f"Log accepted by cloned connector {clone['name']}, and the clone was deleted."
            log.info(message)
        except FalconError as exc:
            success = False
            message = str(exc)
            log.error(message)
        except Exception as exc:  # The forensic record must still be closed.
            success = False
            message = f"Unexpected {type(exc).__name__}. See the verbose log for details."
            log.error(message, str(exc))

        record(
            "submission_finished",
            success=success,
            message=message,
            source_connector=_summary(connection) if connection else None,
            clone=clone,
            activity=log.entries,
        )
        if unwritten:
            message += f" WARNING: the forensic log is incomplete, missing: {', '.join(unwritten)}."
        if success:
            flagged = [r["key"] for r in checked["results"] if r["verdict"] in ("likely", "uncertain", "needs_more_events")]
            if sample_id and sample_id.startswith("rule:"):
                flagged.append(sample_id[len("rule:"):])
            submissions[submission_id] = {"time": datetime.now(timezone.utc), "text": text, "mode": mode,
                                          "parser": (connection or {}).get("parser_name"), "rule_keys": list(dict.fromkeys(flagged))}
            while len(submissions) > RECENT_SUBMISSIONS:
                submissions.popitem(last=False)
        return jsonify(success=success, message=message, submission_id=submission_id, clone=clone, log=log.entries,
                       verifiable=success)

    @app.post("/api/verify")
    def verify_submission():
        """Find a submission's events in NG-SIEM and check the rules against NG-SIEM's own parsing."""
        data = request.get_json(silent=True)
        if not request.is_json or not isinstance(data, dict):
            return jsonify(success=False, message="Expected a JSON request."), 415
        submission_id = data.get("submission_id")
        submission = submissions.get(submission_id) if isinstance(submission_id, str) else None
        if submission is None:
            return jsonify(success=False, message="That submission isn't available to verify. Only recent submissions "
                                                  "made since the app started can be verified."), 404
        log = ActivityLog()
        rules, _ = rulebook.load(log, include_templates=rulebook.templates_loaded())
        wanted = [r for r in rules if r["key"] in submission["rule_keys"]]
        try:
            outcome = verify(client, submission, wanted, simulation, judge, log)
        except FalconError as exc:
            outcome = {"success": False, "message": str(exc)}
        try:
            forensic.write("submission_verified", submission_id, operator=getpass.getuser(),
                           operator_login=g.get("operator_login"), remote_addr=request.remote_addr,
                           found=outcome.get("found"), token=outcome.get("token"), message=outcome.get("message"),
                           rules=[{"key": r["key"], "verdict": r["verdict"]} for e in outcome.get("events", [])[:1] for r in e["rules"]])
        except OSError:
            pass
        return jsonify(**outcome, log=log.entries)

    return app


LOOPBACK_HOSTS = LOOPBACK_NAMES


class QuietRequestHandler(WSGIRequestHandler):
    """Sends a plain Server header, without the Werkzeug and Python versions."""

    def version_string(self):
        return "NGSIEM-LogTester"


def listen_address(environ=os.environ):
    """Return (host, port, warnings, errors) from HOST, PORT and the access settings.

    The default is localhost only, because the app acts with the API client's rights. HOST=0.0.0.0
    accepts connections from other machines, which is refused unless an operator password, an
    administrator password and the allowed host names are all set.
    """
    host = (environ.get("HOST") or "127.0.0.1").strip()
    port = int(environ.get("PORT") or 5000)
    warnings, errors = [], []
    if host.strip("[]") in LOOPBACK_HOSTS:
        return host, port, warnings, errors
    for name, why in (("APP_ACCESS_PASSWORD", "the password operators sign in with"),
                      ("APP_ADMIN_PASSWORD", "the password for changing the settings"),
                      ("APP_ALLOWED_HOSTS", "the host names or IP addresses people browse to, comma-separated")):
        if not (environ.get(name) or "").strip():
            errors.append(f"HOST={host} lets other machines connect, so {name} must be set: {why}.")
    access = environ.get("APP_ACCESS_PASSWORD") or ""
    if access and access == environ.get("APP_ADMIN_PASSWORD"):
        errors.append("APP_ACCESS_PASSWORD and APP_ADMIN_PASSWORD must be different.")
    if not errors:
        warnings.append(
            f"WARNING: listening on {host}:{port}, so other machines can reach this app. Traffic is plain "
            "HTTP, so passwords cross the network unencrypted. Use it only on a trusted network, limit the "
            "port with a firewall rule, or put an HTTPS reverse proxy in front of it.")
        if "*" in parse_allowed_hosts(environ.get("APP_ALLOWED_HOSTS")):
            warnings.append("WARNING: APP_ALLOWED_HOSTS=* accepts any host name, which weakens the protection "
                            "against DNS rebinding.")
    return host, port, warnings, errors


if __name__ == "__main__":
    import sys

    load_dotenv()
    bind_host, bind_port, bind_warnings, bind_errors = listen_address()
    for error in bind_errors:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
    if bind_errors:
        sys.exit(1)
    for warning in bind_warnings:
        print(warning, flush=True)
    try:
        refresh_minutes_from(os.environ.get("RULE_REFRESH_MINUTES"))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        sys.exit(1)
    application = create_app()
    application.extensions["rulebook"].start_refresher(ActivityLog)
    application.run(host=bind_host, port=bind_port, threaded=True, request_handler=QuietRequestHandler)
