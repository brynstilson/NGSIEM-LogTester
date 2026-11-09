"""Operator web app for testing a raw JSON log against a clone of an NG-SIEM data connector."""
import getpass
import hashlib
import os
import uuid

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

from falcon_client import ActivityLog, FalconClient, FalconError
from forensic_log import ForensicLog
from field_model import PROFILES
from rules import RuleBook, evaluate, group, rule_templates
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


def create_app(client=None, settings=None, forensic=None):
    app = Flask(__name__)
    settings = settings or Settings()
    forensic = forensic or ForensicLog()
    client = client or FalconClient(
        os.environ.get("FALCON_CLIENT_ID"),
        os.environ.get("FALCON_CLIENT_SECRET"),
        os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
    )
    selected = {}  # connection ID -> details read when the operator selected it
    rulebook = RuleBook(client)

    def public(rule):
        return {key: value for key, value in rule.items() if not key.startswith("_")}

    def parser_for(connection_id, log):
        """The selected connector's parser, which decides what a rule would see."""
        if not connection_id:
            return None
        connection = selected.get(connection_id)
        if connection is None:
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
            return rule["parser"] if rule else None
        return next((key for key, profile in PROFILES.items() if profile.get("sample") == sample_id), None)

    def rule_check(text, mode, connection_id, log, sample_id=None):
        rules = rulebook.load(log)
        parser = parser_for(connection_id, log) or sample_parser(sample_id)
        checked = evaluate(rules, text, mode, parser)
        return rules, checked

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/connectors")
    def list_connectors():
        log = ActivityLog()
        try:
            connections = client.list_connections(log)
        except FalconError as exc:
            log.error(str(exc))
            return jsonify(success=False, message=str(exc), log=log.entries)
        connectors = sorted((_summary(c) for c in connections), key=lambda c: (c["name"] or "").lower())
        return jsonify(success=True, connectors=connectors, log=log.entries)

    @app.get("/api/connectors/<connection_id>/parser")
    def select_connector(connection_id):
        log = ActivityLog()
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
        rules = rulebook.load(log, refresh=request.args.get("refresh") == "1")
        return jsonify(
            success=rulebook.error is None,
            message=rulebook.error,
            rules=[public(rule) for rule in rules],
            configured=sum(1 for rule in rules if rule["source"] == "configured"),
            enabled=sum(1 for rule in rules if rule["enabled"]),
            templates=sum(1 for rule in rules if rule["source"] == "template"),
            log=log.entries,
        )

    @app.get("/api/rule-templates")
    def list_rule_templates():
        log = ActivityLog()
        entries = rule_templates(rulebook.load(log, refresh=request.args.get("refresh") == "1"))
        return jsonify(success=rulebook.error is None, message=rulebook.error,
                       templates=[{k: v for k, v in entry.items() if k != "log"} for entry in entries])

    @app.post("/api/evaluate")
    def evaluate_log():
        data = request.get_json(silent=True)
        if not request.is_json or not isinstance(data, dict):
            return jsonify(success=False, message="Expected a JSON request."), 415
        log = ActivityLog()
        text = data.get("log") if isinstance(data.get("log"), str) else ""
        rules, checked = rule_check(text, data.get("mode", MODE_EVENT), data.get("connector_id"), log,
                                    data.get("sample_id"))
        return jsonify(
            success=True,
            rules_available=rulebook.error is None,
            message=rulebook.error,
            rule_count=len(rules),
            events=checked["events"],
            groups=group(checked["results"]),
            will_fire=group(checked["will_fire"]),
        )

    @app.get("/api/sample-events/<sample_id>")
    def sample_event(sample_id):
        if sample_id.startswith("rule:"):
            entry = next((e for e in rule_templates(rulebook.load(ActivityLog())) if e["id"] == sample_id), None)
            if entry is None:
                return jsonify(success=False, message=f"Unknown rule template: {sample_id}"), 404
            return jsonify(success=True, log=entry["log"], note=entry["note"], verdict=entry["verdict"])
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
        submission_id = str(uuid.uuid4())
        sample_id = data.get("sample_id")
        sample_id = sample_id if isinstance(sample_id, str) and (sample_id in SAMPLE_IDS or sample_id.startswith("rule:")) else None

        # Configured rules this submission would probably fire must be acknowledged first.
        rules, checked = rule_check(text, mode, connection_id, log)
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
            "status": "unavailable" if rulebook.error else "checked",
            "error": rulebook.error,
            "rules_checked": len(rules),
            "acknowledged": [{"key": r["key"], "name": r["name"], "vendor": r["vendor"], "product": r["product"]} for r in firing],
        }

        # No forensic record means no tenant change, so this write has to succeed first.
        try:
            forensic.write(
                "submission_started",
                submission_id,
                operator=getpass.getuser(),
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
        if rulebook.error:
            log.error("Correlation rules couldn't be checked, so this submission wasn't screened for them.", rulebook.error)
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

        connection = selected.get(connection_id)
        clone = None
        try:
            if mode not in (MODE_EVENT, MODE_RAW):
                raise FalconError(f"Unknown send mode: {mode}")
            # A pull connector is read again here, so its clone gets the parser assigned right now.
            if connection is None or is_pull(connection):
                if not connection_id:
                    raise FalconError("Select a data connector first.")
                connection = selected[connection_id] = client.get_connection(connection_id, log)
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
        return jsonify(success=success, message=message, submission_id=submission_id, clone=clone, log=log.entries)

    return app


if __name__ == "__main__":
    load_dotenv()
    # Bound to localhost only: the app has no login, and it acts with the API client's rights.
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), threaded=True)
